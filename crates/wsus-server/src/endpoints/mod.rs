//! MS-WUSP server endpoints as a framework-neutral handler.
//!
//! [`WsusServer::handle`] maps an [`HttpRequestParts`] to an [`HttpResponseParts`]. It
//! decodes SOAP with `wsus-protocol`, validates the session cookie before touching any
//! repository, dispatches on the body element, and renders every failure as a protocol SOAP
//! fault (never a framework error body).
//!
//! Blocking boundary: the repositories are synchronous (SQLite plus file I/O), so `handle`
//! blocks. It is the single entry point; async callers must run it on a blocking thread
//! (the `http` feature does this with `spawn_blocking`). No repository call happens
//! anywhere else.
//!
//! Routes (case-insensitive, matching WSUS):
//! * `POST /ClientWebService/client.asmx`: GetConfig, GetCookie, RegisterComputer,
//!   StartCategoryScan, SyncUpdates, RefreshCache, GetExtendedUpdateInfo, GetExtendedUpdateInfo2,
//!   GetFileLocations
//! * `POST /SimpleAuthWebService/SimpleAuth.asmx`: GetAuthorizationCookie
//! * `POST /ReportingWebService/ReportingWebService.asmx`: ReportEventBatch
//! * `GET|HEAD /Content/{xx}/{sha1}[.ext]`
//!
//! Nothing here has been validated against a native Windows Update client.
mod client;
mod content;
mod encoding;
mod fault;
pub mod message;
mod report;
mod scope;
pub mod time;
pub mod wsusss;

#[cfg(feature = "http")]
pub mod http;

use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use wsus_protocol::soap::{
    Body, Envelope, Limits, SoapMessage, SoapRequest, SoapVersion, action_from_content_type,
    decode_payload, encode_response, validate_action,
};
use wsus_protocol::wusp::{self, CLIENT_NS, REPORTING_NS, SIMPLE_AUTH_NS};

use crate::catalog::Catalog;
use crate::computers::Computers;
use crate::content::ContentStore;
use crate::policy::Policy;
use crate::reporting::{EventKind, Reporting};
use crate::session::SessionManager;
use crate::storage::hex_encode;

pub use message::{HttpRequestParts, HttpResponseParts, ResponseBody};

use fault::{ApiError, invalid};

const CLIENT_PATH: &str = "/clientwebservice/client.asmx";
const AUTH_PATH: &str = "/simpleauthwebservice/simpleauth.asmx";
const REPORTING_PATH: &str = "/reportingwebservice/reportingwebservice.asmx";

/// Partial URL advertised in `GetConfig.AuthInfo`.
pub(crate) const AUTH_SERVICE_URL: &str = "SimpleAuthWebService/SimpleAuth.asmx";
pub(crate) const AUTH_PLUGIN_ID: &str = "SimpleTargeting";

/// How `SyncUpdates` chooses what to deliver.
///
/// Neither mode has been verified against a native Windows Update Agent
/// (`docs/wsus-validation.md`, ledger row "native WUA against our server").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncDelivery {
    /// Real-WSUS-like staged delivery (default). The server reads `InstalledNonLeafUpdateIDs`
    /// and delivers only revisions whose prerequisite clauses are all satisfied by it, so
    /// the client evaluates metadata in dependency order and reports what is installed
    /// (inventory sections 5.3 and 9.3). Advertises `ProtocolVersion` 3.2 and answers
    /// `StartCategoryScan`.
    #[default]
    Staged,
    /// The earlier behaviour: the whole approved closure is delivered at once, ignoring the
    /// installed list (cached ids only suppress re-delivery). Advertises `ProtocolVersion`
    /// 3.0. A native client evaluates only the entities whose prerequisites it already knows
    /// to be installed, so it never reaches the leaves behind unevaluated non-leaf updates
    /// (a known limitation, kept for comparison and for clients that evaluate by themselves).
    Closure,
}

impl SyncDelivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Closure => "closure",
        }
    }
}

impl std::str::FromStr for SyncDelivery {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "staged" => Ok(Self::Staged),
            "closure" => Ok(Self::Closure),
            other => Err(format!(
                "unknown sync_delivery {other:?}, expected \"staged\" or \"closure\""
            )),
        }
    }
}

/// Which updates a computer is offered by `SyncUpdates` (and may fetch extended metadata for).
///
/// Orthogonal to [`SyncDelivery`]: the delivery mode decides the order and paging, this decides
/// the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliveryScope {
    /// Default. An update is offered only when it is approved for one of the computer's groups
    /// or is a prerequisite, category or bundle member of an approved update. Updates that are
    /// in scope only as metadata carry `Action` `Evaluate` (or `Bundle` for bundle members);
    /// `PreDeploymentCheck` is never emitted.
    #[default]
    Approved,
    /// What a real WSUS does (Observed 2026-10-05, inventory 12.19): every non-declined update
    /// of the active generation is offered, approved or not, so the client evaluates it and
    /// reports installed or needed state. Unapproved software that is not a bundle member carries
    /// `PreDeploymentCheck`, bundle members `Bundle`, approved software the approval's action,
    /// everything else `Evaluate`. Bundle members whose bundles are all declined are not offered.
    /// Staged delivery still applies the prerequisite rule.
    AllNonDeclined,
}

impl DeliveryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::AllNonDeclined => "all_non_declined",
        }
    }
}

impl std::str::FromStr for DeliveryScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "approved" => Ok(Self::Approved),
            "all_non_declined" => Ok(Self::AllNonDeclined),
            other => Err(format!(
                "unknown delivery_scope {other:?}, expected \"approved\" or \"all_non_declined\""
            )),
        }
    }
}

/// Request limits and wire-visible configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Catalog source whose active generation is served.
    pub source_name: String,
    /// Largest accepted request body.
    pub max_request_bytes: usize,
    /// Largest array in any request (cached ids, digests, events, ...).
    pub max_array_len: usize,
    /// Deepest accepted XML nesting.
    pub max_xml_depth: usize,
    /// Most XML elements in one request.
    pub max_xml_elements: usize,
    /// `NewUpdates` per `SyncUpdates` response before `Truncated` is set. Default 30, what the
    /// real WSUS (WS2025 10.0.26100) was observed to return (inventory 9.1); the earlier
    /// default of 200 was unsourced. [`ServerConfig::closure`] keeps 200.
    pub max_sync_new_updates: usize,
    /// Delivery algorithm of `SyncUpdates`.
    pub sync_delivery: SyncDelivery,
    /// Which updates are offered (approved scope or every non-declined update).
    pub delivery_scope: DeliveryScope,
    /// `ProtocolVersion` advertised by `GetConfig`. `None` derives it from `sync_delivery`
    /// (3.2 staged, 3.0 closure). Advertise 3.2 only when serving what 3.2 clients expect.
    pub protocol_version: Option<String>,
    /// Hard cap on `InstalledNonLeafUpdateIDs` (Observed on the real WSUS: 400 accepted, 401
    /// rejected with `InvalidParameters`). 0 disables the check. Staged delivery only.
    pub max_installed_non_leaf_ids: usize,
    /// Staged delivery: answer cached revisions whose prerequisites are not all satisfied by
    /// `InstalledNonLeafUpdateIDs` in `OutOfScopeRevisionIDs` (a lab observation recorded in
    /// the inventory, raw exchange not retained). Default on.
    pub out_of_scope_unsatisfied: bool,
    /// Advertised and enforced `MaxExtendedUpdatesPerRequest`.
    pub max_extended_updates_per_request: usize,
    /// Most digests in one `GetFileLocations`.
    pub max_file_digests_per_request: usize,
    /// Most events in one `ReportEventBatch`.
    pub max_events_per_batch: usize,
    /// Origin used to build file URLs, for example `http://wsus.example:8530`. When
    /// `None`, the request `Host` header is used.
    pub content_base_url: Option<String>,
    /// `Config.AllowedEventIds`. Empty by default: the event id table is unverified
    /// against a native client, so none is invented.
    pub allowed_event_ids: Vec<i32>,
    /// Classification of reported `EventID`s into derived status; unmapped events are stored raw
    /// and do not change derived status. The default maps event `182` (installation failure) to
    /// `InstallFailed` and event `156` (client status) to `ClientStatus`: the real WSUS (inventory
    /// 9.10) set the computer's status of the update to Failed when it received a native `182`,
    /// left it unchanged for `181`, `161`, `167`, `162` and `201`, and took Installed and
    /// NotInstalled from the `U` and `V` lists of `156`, which is derived here.
    pub event_kinds: BTreeMap<i16, EventKind>,
    /// Answer SOAP requests that send `Accept-Encoding: xpress` with
    /// `Content-Encoding: xpress` bodies (default on). Content file responses
    /// are never compressed. Request bodies with `Content-Encoding: xpress`
    /// are accepted regardless of this switch (bounded by `max_request_bytes`).
    pub xpress_responses: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            source_name: "upstream".into(),
            max_request_bytes: 4 * 1024 * 1024,
            max_array_len: 50_000,
            max_xml_depth: 64,
            max_xml_elements: 500_000,
            max_sync_new_updates: 30,
            sync_delivery: SyncDelivery::Staged,
            delivery_scope: DeliveryScope::Approved,
            protocol_version: None,
            max_installed_non_leaf_ids: 400,
            out_of_scope_unsatisfied: true,
            max_extended_updates_per_request: 50,
            max_file_digests_per_request: 100,
            max_events_per_batch: 500,
            content_base_url: None,
            allowed_event_ids: Vec::new(),
            event_kinds: BTreeMap::from([
                (156, EventKind::ClientStatus),
                (182, EventKind::InstallFailed),
            ]),
            xpress_responses: true,
        }
    }
}

impl ServerConfig {
    /// Configuration for the `closure` delivery mode: 200 updates per page and `ProtocolVersion`
    /// 3.0, as before staged delivery existed.
    pub fn closure() -> Self {
        Self {
            sync_delivery: SyncDelivery::Closure,
            max_sync_new_updates: 200,
            ..Self::default()
        }
    }

    /// The `ProtocolVersion` property `GetConfig` reports.
    pub fn effective_protocol_version(&self) -> &str {
        match (&self.protocol_version, self.sync_delivery) {
            (Some(v), _) => v,
            (None, SyncDelivery::Staged) => "3.2",
            (None, SyncDelivery::Closure) => "3.0",
        }
    }

    /// Digest of the settings clients can observe through `GetConfig`; pass it to
    /// [`SessionManager::open`] so a change advances the configuration generation.
    pub fn fingerprint(&self) -> String {
        let mut text = format!(
            "v2|{}|{:?}|{AUTH_PLUGIN_ID}|{AUTH_SERVICE_URL}|{}",
            self.max_extended_updates_per_request,
            self.allowed_event_ids,
            self.effective_protocol_version()
        );
        // Only a non-default scope is mixed in, so existing servers keep their fingerprint.
        if self.delivery_scope != DeliveryScope::Approved {
            text.push_str("|scope=");
            text.push_str(self.delivery_scope.as_str());
        }
        hex_encode(&Sha256::digest(text.as_bytes()))
    }

    fn xml_limits(&self) -> Limits {
        Limits {
            max_body_bytes: self.max_request_bytes,
            max_depth: self.max_xml_depth,
            max_array_len: self.max_array_len,
            max_elements: self.max_xml_elements,
            ..Limits::default()
        }
    }
}

/// Repositories and session manager the handlers use.
#[derive(Debug, Clone)]
pub struct Services {
    pub catalog: Catalog,
    pub policy: Policy,
    pub computers: Computers,
    pub reporting: Reporting,
    pub content: ContentStore,
    pub sessions: Arc<SessionManager>,
}

/// Per-request context handed to operations.
pub(crate) struct Ctx<'a> {
    pub inner: &'a Inner,
    /// Origin for file URLs, resolved from configuration or the `Host` header.
    pub base_url: Option<String>,
}

pub(crate) struct Inner {
    pub svc: Services,
    pub config: ServerConfig,
    pub limits: Limits,
    /// Prerequisite clauses per (generation, local revision id); see `scope::clauses`.
    pub clauses: scope::ClauseCache,
    /// Per-generation index of the `all_non_declined` scope; see `scope::AllIndexCache`.
    pub all_index: scope::AllIndexCache,
}

/// The MS-WUSP server. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct WsusServer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for WsusServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsusServer").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Client,
    Auth,
    Reporting,
}

impl WsusServer {
    pub fn new(services: Services, config: ServerConfig) -> Self {
        let limits = config.xml_limits();
        Self {
            inner: Arc::new(Inner {
                svc: services,
                config,
                limits,
                clauses: Default::default(),
                all_index: Default::default(),
            }),
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.inner.config
    }

    pub fn services(&self) -> &Services {
        &self.inner.svc
    }

    /// Handle one request. **Blocking**: see the module documentation.
    pub fn handle(&self, req: HttpRequestParts) -> HttpResponseParts {
        let path = req.path.to_ascii_lowercase();
        let route = match path.as_str() {
            CLIENT_PATH => Some(Route::Client),
            AUTH_PATH => Some(Route::Auth),
            REPORTING_PATH => Some(Route::Reporting),
            _ => None,
        };
        if let Some(route) = route {
            let accepts = self.inner.config.xpress_responses && encoding::accepts_xpress(&req);
            let mut resp = self.handle_soap(route, &req);
            if self.inner.config.xpress_responses {
                encoding::encode_response(&mut resp, accepts);
            }
            return resp;
        }
        if path.starts_with(content::CONTENT_PREFIX) {
            return content::serve(
                &self.inner.svc.catalog.database().clone(),
                &self.inner.svc.content,
                &req,
            );
        }
        ApiError::Http(404, "no such service").render(SoapVersion::V11, None)
    }

    /// Response for a request whose body exceeded `max_request_bytes` before it could be
    /// buffered (transport adapters call this instead of [`Self::handle`]).
    pub fn too_large(&self, req: &HttpRequestParts) -> HttpResponseParts {
        ApiError::Http(413, "request too large").render(guess_version(req), None)
    }

    /// Response for an unexpected failure outside the handler (for example a panicked
    /// blocking task).
    pub fn internal_error(&self) -> HttpResponseParts {
        ApiError::Internal.render(SoapVersion::V11, None)
    }

    fn handle_soap(&self, route: Route, req: &HttpRequestParts) -> HttpResponseParts {
        let guess = guess_version(req);
        if req.method != "POST" {
            return ApiError::Http(405, "SOAP services accept POST only")
                .render(guess, None)
                .with("Allow", "POST");
        }
        let ctype = req
            .header("Content-Type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !(ctype.starts_with("text/xml") || ctype.starts_with("application/soap+xml")) {
            return ApiError::Http(415, "unsupported media type").render(guess, None);
        }
        if req.body.len() > self.inner.config.max_request_bytes {
            return ApiError::Http(413, "request too large").render(guess, None);
        }
        let body = match encoding::decode_request_body(req, self.inner.config.max_request_bytes) {
            encoding::RequestEncoding::Ok(body) => body,
            encoding::RequestEncoding::Unsupported => {
                return ApiError::Http(415, "unsupported content encoding").render(guess, None);
            }
            encoding::RequestEncoding::Malformed => {
                return ApiError::Client("malformed xpress request body".into())
                    .render(guess, None);
            }
        };
        let env = match Envelope::decode(&body, &self.inner.limits) {
            Ok(e) => e,
            Err(_) => return ApiError::Client("malformed SOAP request".into()).render(guess, None),
        };
        let version = env.version;
        let action = match version {
            SoapVersion::V11 => req.header("SOAPAction").map(str::to_owned),
            SoapVersion::V12 => req
                .header("Content-Type")
                .and_then(action_from_content_type),
        };
        let method = action.as_deref();
        if !env.must_understand_headers().is_empty() {
            return ApiError::MustUnderstand.render(version, method);
        }
        let payload = match env.body {
            Body::Payload(p) => p,
            Body::Fault(_) => {
                return ApiError::Client("request body is a fault".into()).render(version, method);
            }
        };
        if validate_action(action.as_deref(), &payload.name).is_err() {
            return ApiError::Client("SOAPAction does not match the body element".into())
                .render(version, method);
        }
        let ns = payload.name.ns.as_deref().unwrap_or("");
        let name = payload.name.local.as_str();
        let inner = &*self.inner;
        let cx = Ctx {
            inner,
            base_url: base_url(&inner.config, req),
        };
        let cx = &cx;
        let out = match (route, ns, name) {
            (Route::Client, CLIENT_NS, "GetConfig") => {
                call::<wusp::GetConfig>(cx, version, &payload, client::get_config)
            }
            (Route::Client, CLIENT_NS, "GetCookie") => {
                call::<wusp::GetCookie>(cx, version, &payload, client::get_cookie)
            }
            (Route::Client, CLIENT_NS, "RegisterComputer") => {
                call::<wusp::RegisterComputer>(cx, version, &payload, client::register_computer)
            }
            (Route::Client, CLIENT_NS, "StartCategoryScan") => {
                call::<wusp::StartCategoryScan>(cx, version, &payload, client::start_category_scan)
            }
            (Route::Client, CLIENT_NS, "SyncUpdates") => {
                call::<wusp::SyncUpdates>(cx, version, &payload, client::sync_updates)
            }
            (Route::Client, CLIENT_NS, "RefreshCache") => {
                call::<wusp::RefreshCache>(cx, version, &payload, client::refresh_cache)
            }
            (Route::Client, CLIENT_NS, "GetExtendedUpdateInfo") => {
                call::<wusp::GetExtendedUpdateInfo>(cx, version, &payload, client::extended_info)
            }
            (Route::Client, CLIENT_NS, "GetExtendedUpdateInfo2") => {
                call::<wusp::GetExtendedUpdateInfo2>(cx, version, &payload, client::extended_info2)
            }
            (Route::Client, CLIENT_NS, "GetFileLocations") => {
                call::<wusp::GetFileLocations>(cx, version, &payload, client::file_locations)
            }
            (Route::Auth, SIMPLE_AUTH_NS, "GetAuthorizationCookie") => {
                call::<wusp::GetAuthorizationCookie>(
                    cx,
                    version,
                    &payload,
                    client::authorization_cookie,
                )
            }
            (Route::Reporting, REPORTING_NS, "ReportEventBatch") => {
                call::<wusp::ReportEventBatch>(cx, version, &payload, report::report_event_batch)
            }
            _ => Err(ApiError::Client(format!("unsupported operation {name}"))),
        };
        match out {
            Ok(enc) => HttpResponseParts::bytes(200, &enc.0, enc.1),
            Err(e) => e.render(version, method),
        }
    }
}

fn guess_version(req: &HttpRequestParts) -> SoapVersion {
    match req.header("Content-Type") {
        Some(c) if c.to_ascii_lowercase().starts_with("application/soap+xml") => SoapVersion::V12,
        _ => SoapVersion::V11,
    }
}

/// Decode a typed request, run the operation, encode the typed response.
fn call<R: SoapRequest>(
    cx: &Ctx<'_>,
    version: SoapVersion,
    payload: &wsus_protocol::soap::Element,
    op: impl FnOnce(&Ctx<'_>, R) -> Result<R::Response, ApiError>,
) -> Result<(String, Vec<u8>), ApiError>
where
    R::Response: SoapMessage,
{
    let request = decode_payload::<R>(payload, &cx.inner.limits)
        .map_err(|_| invalid("the request does not match the operation schema"))?;
    let response = op(cx, request)?;
    let enc = encode_response(version, &response);
    Ok((enc.content_type, enc.body))
}

/// Origin for file URLs: configured, else `http://` plus a sanity-checked `Host` header.
fn base_url(config: &ServerConfig, req: &HttpRequestParts) -> Option<String> {
    if let Some(b) = &config.content_base_url {
        return Some(b.clone());
    }
    let host = req.header("Host")?.trim();
    let ok = !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        });
    ok.then(|| format!("http://{host}"))
}
