//! MS-WSUSSS upstream server (USS) as a framework-neutral handler.
//!
//! [`UpstreamServer`] serves the active catalog generation of one source to downstream
//! WSUS servers. Like [`super::WsusServer`] it maps an [`HttpRequestParts`] to an
//! [`HttpResponseParts`], validates the cookie before touching any repository, and renders
//! every failure as a protocol SOAP fault. The handler is **blocking** (SQLite plus file
//! I/O); the `http` feature runs it on blocking threads.
//!
//! # Routes (case-insensitive; inventory section 3.2)
//!
//! * `POST /ServerSyncWebService/ServerSyncWebService.asmx` (also the WSDL spelling
//!   `ServerSyncProxy.asmx`): `GetAuthConfig`, `GetCookie`, `GetConfigData`,
//!   `GetRevisionIdList`, `GetUpdateData`, `DownloadFiles`
//! * `POST /DssAuthWebService/DssAuthWebService.asmx`: `GetAuthorizationCookie`
//! * `GET|HEAD /Content/<folder>/<file>`: the existing content route; `<folder>` is the
//!   last two hex digits of the SHA-1 and `<file>` its 40 hex digits, optionally with an
//!   extension. The specification contradicts itself on the folder rule (inventory section 8
//!   item 1), so this is the reading shared with the MS-WUSP server and with
//!   `WsusssClient::convention_location`; it is **Unverified**.
//!
//! Ports: the web services and the content directory may listen on different ports.
//! [`server_server_content_port`] implements the specified rule (HTTP services: content
//! on 80; HTTPS 443: 80; HTTPS N: N-1) and [`UpstreamServerConfig::with_ports`] applies it.
//! The handler itself serves either surface on any port; [`Surface`] lets a binding
//! restrict a listener to one of them.
//!
//! # What is served
//!
//! Everything in the active generation that is a whole update document (what the
//! downstream importer stores) is offered to every authorized downstream server, with no
//! per-downstream policy: replica groups, deployments and target groups are **not
//! implemented** (`GetDeployments` is refused as unsupported), as are reporting rollup,
//! driver operations and `GetUpdateDecryptionData`. Revisions stored in WUSP form (a Core
//! fragment sequence) cannot be turned back into a well-formed document without
//! synthesizing, so they are not enumerated; the count is reported by
//! [`UpstreamServer::summary`]. Withdrawn revisions are enumerated with their stored
//! document (which carries the withdrawal); tombstones cannot be expressed on the wire and are
//! omitted.
//!
//! # Anchors, generations and restarts
//!
//! `GetRevisionIdList` anchors map to immutable catalog generations (see [`anchors`]) and
//! persist in the database, so they stay valid across restarts and catalog refreshes until
//! the generation is pruned; an anchor that cannot be resolved yields `ServerChanged`. A
//! delta is computed between the anchor's generation and the generation active at call
//! time. `GetUpdateData` finds a requested revision in the active generation and, failing
//! that, in recent superseded ones, so a refresh in the middle of a downstream
//! synchronization never strands the revisions it already listed. Revision identity on this
//! protocol is the (UpdateID, RevisionNumber) pair; no local revision id or row id is ever
//! sent.
//!
//! # Limits
//!
//! `GetUpdateData` accepts at most the advertised `MaxNumberOfUpdatesPerRequest`, which is
//! the configured count limit reduced so that the largest metadata blob of the active
//! generation times the count stays within the response limit (2,000,000 bytes, the Windows
//! figure); a request whose actual response would exceed the limit is refused unless it is
//! a single update that cannot be split. `DownloadFiles` accepts at most 100 digests.
//!
//! # Compression
//!
//! `XmlUpdateBlobCompressed` is never sent. Its format is unverified (inventory section 8
//! item 11), so metadata goes out uncompressed in `XmlUpdateBlob`. Windows sends compressed
//! blobs above 5,120 bytes; whether a Windows downstream accepts uncompressed ones is
//! **Unverified**.
//!
//! # Evidence status
//!
//! Exercised only against this project's own downstream client. That proves
//! self-consistency, NOT interoperability with a real downstream WSUS, which the plan
//! (section 12) requires before this can be called working.
mod accounts;
pub mod anchors;
mod ops;
mod summary;

#[cfg(feature = "http")]
pub mod http;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};

use rusqlite::OptionalExtension;
use sha2::Digest as _;
use uuid::Uuid;
use wsus_protocol::soap::{
    Body, Envelope, ErrorCode, Limits, SoapFault, SoapMessage, SoapRequest, SoapVersion,
    action_from_content_type, decode_payload, encode_fault, encode_response, validate_action,
};
use wsus_protocol::wsusss::{self as ws, DSS_AUTH_NS, SERVER_SYNC_NS};

pub use accounts::{AccountState, DownstreamAccess, DownstreamAccount, Downstreams};
pub use anchors::{Anchor, Anchors, Resolved};

use super::fault::ApiError;
use super::message::{HttpRequestParts, HttpResponseParts};
use crate::catalog::{Catalog, SourceId};
use crate::content::ContentStore;
use crate::session::SessionManager;
use crate::storage::{self, Database, hex_encode};

const SYNC_PATH: &str = "/serversyncwebservice/serversyncwebservice.asmx";
const SYNC_PATH_WSDL: &str = "/serversyncwebservice/serversyncproxy.asmx";
const AUTH_PATH: &str = "/dssauthwebservice/dssauthwebservice.asmx";
const REPORTING_PATH: &str = "/reportingwebservice/reportingwebservice.asmx";

/// Partial URL advertised in `GetAuthConfig.AuthInfo` (the specification's `ServiceUrl`).
pub(crate) const AUTH_SERVICE_URL: &str = "DssAuthWebService/DssAuthWebService.asmx";
pub(crate) const AUTH_PLUGIN_ID: &str = "DssTargeting";

/// Windows limit of one `GetUpdateData` response (inventory section 6.2).
pub const WINDOWS_MAX_UPDATE_RESPONSE_BYTES: usize = 2_000_000;
/// `DownloadFiles` digest limit.
pub const MAX_DOWNLOAD_FILES_DIGESTS: usize = 100;

const META_CFG_FP: &str = "uss_config_fingerprint";
const META_CFG_GEN: &str = "uss_config_generation";
const META_CFG_AT: &str = "uss_config_last_change";

/// Port that serves content when the web services listen on `services_port`
/// (Specified, WSUSSS 2.1, inventory section 3.2): HTTP services use port 80 for content;
/// HTTPS on 443 uses 80; HTTPS on any other port N uses N-1.
pub fn server_server_content_port(services_port: u16, tls: bool) -> Option<u16> {
    match (tls, services_port) {
        (false, _) | (true, 443) => Some(80),
        (true, 0 | 1) => None,
        (true, n) => Some(n - 1),
    }
}

/// Which part of the server a listener exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// SOAP services only.
    Services,
    /// `/Content/` only.
    Content,
    /// Both (one port for everything).
    All,
}

/// Limits and wire-visible configuration.
#[derive(Debug, Clone)]
pub struct UpstreamServerConfig {
    /// Catalog source whose active generation is served.
    pub source_name: String,
    pub max_request_bytes: usize,
    pub max_array_len: usize,
    pub max_xml_depth: usize,
    pub max_xml_elements: usize,
    /// Configured `MaxNumberOfUpdatesPerRequest` before the response-size reduction.
    pub max_updates_per_request: usize,
    /// Largest `GetUpdateData` response metadata, in bytes.
    pub max_update_response_bytes: usize,
    /// Advertise `CatalogOnlySync`: downstream servers then use Microsoft Update for
    /// content and never ask this server for files.
    pub catalog_only_sync: bool,
    /// `ProtocolVersion` in `GetConfigData`. Unverified which value Windows expects.
    pub protocol_version: String,
    /// Origin used to build `UssUrl`, for example `http://uss.example:80`. When `None` it
    /// is the request's `Host` name plus `content_port`.
    pub content_base_url: Option<String>,
    /// Port of the content directory, used when `content_base_url` is `None`.
    pub content_port: Option<u16>,
    pub access: DownstreamAccess,
}

impl Default for UpstreamServerConfig {
    fn default() -> Self {
        Self {
            source_name: "upstream".into(),
            max_request_bytes: 1024 * 1024,
            max_array_len: 10_000,
            max_xml_depth: 64,
            max_xml_elements: 200_000,
            max_updates_per_request: 100,
            max_update_response_bytes: WINDOWS_MAX_UPDATE_RESPONSE_BYTES,
            catalog_only_sync: false,
            protocol_version: "1.20".into(),
            content_base_url: None,
            content_port: Some(80),
            access: DownstreamAccess::Open,
        }
    }
}

impl UpstreamServerConfig {
    /// Apply the specified content-port rule for web services on `services_port`.
    pub fn with_ports(mut self, services_port: u16, tls: bool) -> Self {
        self.content_port = server_server_content_port(services_port, tls);
        self
    }

    /// Digest of the settings downstream servers can observe through `GetConfigData`; a
    /// change advances the configuration anchor.
    pub fn fingerprint(&self) -> String {
        let text = format!(
            "v1|{}|{}|{}|{}",
            self.max_updates_per_request,
            self.max_update_response_bytes,
            self.catalog_only_sync,
            self.protocol_version
        );
        hex_encode(&sha2::Sha256::digest(text.as_bytes()))
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

/// Repositories and the session manager the handlers use. The session manager is shared
/// with the MS-WUSP server (one signing key, one server identity); downstream cookies have
/// their own kinds and never validate on the MS-WUSP endpoints.
#[derive(Debug, Clone)]
pub struct UpstreamServices {
    pub catalog: Catalog,
    pub content: ContentStore,
    pub sessions: Arc<SessionManager>,
}

/// Counters describing what is offered, for administration and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferSummary {
    pub generation: crate::catalog::GenerationId,
    /// Update GUIDs offered (highest revision each).
    pub offered: usize,
    /// Of those, categories/classifications/detectoids.
    pub offered_config: usize,
    /// Records not offered: tombstones, lower revisions and WUSP-form records.
    pub not_offered: usize,
    pub max_blob_bytes: u64,
    /// `MaxNumberOfUpdatesPerRequest` that is advertised right now.
    pub advertised_batch_limit: usize,
}

pub(crate) struct Inner {
    pub svc: UpstreamServices,
    pub config: UpstreamServerConfig,
    pub limits: Limits,
    pub downstreams: Downstreams,
    pub anchors: Anchors,
    pub summaries: Mutex<summary::Cache>,
    pub requested_downloads: Mutex<BTreeSet<Vec<u8>>>,
    pub config_state: RwLock<ConfigState>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConfigState {
    pub generation: i64,
    pub last_change: i64,
}

pub(crate) struct Ctx<'a> {
    pub inner: &'a Inner,
    /// Host name (without port) from the request, when well formed.
    pub host: Option<String>,
}

/// The MS-WSUSSS upstream server. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct UpstreamServer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for UpstreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamServer").finish_non_exhaustive()
    }
}

/// Fault with a `Message` detail (`FileDigestsMissing`) or an ordinary [`ApiError`].
pub(crate) enum UssError {
    Api(ApiError),
    Message(ErrorCode, &'static str, String),
}

impl From<ApiError> for UssError {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

impl From<storage::Error> for UssError {
    fn from(e: storage::Error) -> Self {
        Self::Api(e.into())
    }
}

impl UssError {
    pub(crate) fn code(code: ErrorCode, reason: &'static str) -> Self {
        Self::Api(ApiError::Code(code, reason))
    }

    fn render(self, version: SoapVersion, method: Option<&str>) -> HttpResponseParts {
        match self {
            Self::Api(e) => e.render(version, method),
            Self::Message(code, reason, message) => {
                let fault = SoapFault::application(
                    version,
                    code,
                    reason,
                    Some(&message),
                    Some(Uuid::new_v4()),
                    method,
                );
                let status = match version {
                    SoapVersion::V11 => 500,
                    SoapVersion::V12 => 400,
                };
                let enc = encode_fault(&fault);
                HttpResponseParts::bytes(status, &enc.content_type, enc.body)
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Sync,
    Auth,
}

impl UpstreamServer {
    /// Open over `services`, loading or advancing the configuration anchor state.
    pub fn open(
        services: UpstreamServices,
        config: UpstreamServerConfig,
    ) -> Result<Self, storage::Error> {
        let db = services.catalog.database().clone();
        let state = load_config_state(&db, &config.fingerprint(), services.sessions.now())?;
        let limits = config.xml_limits();
        Ok(Self {
            inner: Arc::new(Inner {
                downstreams: Downstreams::new(db.clone()),
                anchors: Anchors::new(db),
                svc: services,
                config,
                limits,
                summaries: Mutex::default(),
                requested_downloads: Mutex::default(),
                config_state: RwLock::new(state),
            }),
        })
    }

    pub fn config(&self) -> &UpstreamServerConfig {
        &self.inner.config
    }

    pub fn services(&self) -> &UpstreamServices {
        &self.inner.svc
    }

    /// Downstream account administration.
    pub fn downstreams(&self) -> &Downstreams {
        &self.inner.downstreams
    }

    pub fn anchors(&self) -> &Anchors {
        &self.inner.anchors
    }

    /// Digests downstream servers asked for through `DownloadFiles` that are known but have
    /// no verified content here, in digest order. The caller (content acquisition) is
    /// expected to fetch them; the queue is in memory and is emptied by this call.
    pub fn drain_download_requests(&self) -> Vec<Vec<u8>> {
        let mut q = self
            .inner
            .requested_downloads
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *q).into_iter().collect()
    }

    /// What the active generation offers to downstream servers; `None` without an active
    /// generation.
    pub fn summary(&self) -> Result<Option<OfferSummary>, storage::Error> {
        let Some((_, generation)) = ops::active(&self.inner)? else {
            return Ok(None);
        };
        let s = summary::Cache::get_or_load(
            &self.inner.summaries,
            self.inner.svc.catalog.database(),
            generation,
        )?;
        Ok(Some(OfferSummary {
            generation,
            offered: s.newest.len(),
            offered_config: s.newest.values().filter(|e| e.is_config()).count(),
            not_offered: s.excluded,
            max_blob_bytes: s.max_blob,
            advertised_batch_limit: ops::batch_limit(&self.inner.config, s.max_blob),
        }))
    }

    /// Whether `path` belongs to a SOAP service of this server (for a binding that shares
    /// a listener with the MS-WUSP server).
    pub fn owns_path(&self, path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        matches!(
            p.as_str(),
            SYNC_PATH | SYNC_PATH_WSDL | AUTH_PATH | REPORTING_PATH
        )
    }

    /// Handle one request on every surface. **Blocking.**
    pub fn handle(&self, req: HttpRequestParts) -> HttpResponseParts {
        self.handle_on(Surface::All, req)
    }

    /// Handle one request, answering only paths of `surface`.
    pub fn handle_on(&self, surface: Surface, req: HttpRequestParts) -> HttpResponseParts {
        let path = req.path.to_ascii_lowercase();
        let route = match path.as_str() {
            SYNC_PATH | SYNC_PATH_WSDL => Some(Route::Sync),
            AUTH_PATH => Some(Route::Auth),
            _ => None,
        };
        if let Some(route) = route
            && surface != Surface::Content
        {
            return self.handle_soap(route, &req);
        }
        if path == REPORTING_PATH && surface != Surface::Content {
            return ApiError::Http(404, "reporting is not implemented")
                .render(guess_version(&req), None);
        }
        if path.starts_with(super::content::CONTENT_PREFIX) && surface != Surface::Services {
            return super::content::serve(
                self.inner.svc.catalog.database(),
                &self.inner.svc.content,
                &req,
            );
        }
        ApiError::Http(404, "no such service").render(SoapVersion::V11, None)
    }

    pub fn too_large(&self, req: &HttpRequestParts) -> HttpResponseParts {
        ApiError::Http(413, "request too large").render(guess_version(req), None)
    }

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
        let env = match Envelope::decode(&req.body, &self.inner.limits) {
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
        let cx = Ctx {
            inner: &self.inner,
            host: host_of(req),
        };
        let cx = &cx;
        let out = match (route, ns, name) {
            (Route::Sync, SERVER_SYNC_NS, "GetAuthConfig") => {
                call::<ws::GetAuthConfig>(cx, version, &payload, ops::get_auth_config)
            }
            (Route::Auth, DSS_AUTH_NS, "GetAuthorizationCookie") => {
                call::<ws::GetAuthorizationCookie>(cx, version, &payload, ops::authorization_cookie)
            }
            (Route::Sync, SERVER_SYNC_NS, "GetCookie") => {
                call::<ws::GetCookie>(cx, version, &payload, ops::get_cookie)
            }
            (Route::Sync, SERVER_SYNC_NS, "GetConfigData") => {
                call::<ws::GetConfigData>(cx, version, &payload, ops::get_config_data)
            }
            (Route::Sync, SERVER_SYNC_NS, "GetRevisionIdList") => {
                call::<ws::GetRevisionIdList>(cx, version, &payload, ops::get_revision_id_list)
            }
            (Route::Sync, SERVER_SYNC_NS, "GetUpdateData") => {
                call::<ws::GetUpdateData>(cx, version, &payload, ops::get_update_data)
            }
            (Route::Sync, SERVER_SYNC_NS, "DownloadFiles") => {
                call::<ws::DownloadFiles>(cx, version, &payload, ops::download_files)
            }
            _ => Err(UssError::Api(ApiError::Client(format!(
                "unsupported operation {name}"
            )))),
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

fn call<R: SoapRequest>(
    cx: &Ctx<'_>,
    version: SoapVersion,
    payload: &wsus_protocol::soap::Element,
    op: impl FnOnce(&Ctx<'_>, R) -> Result<R::Response, UssError>,
) -> Result<(String, Vec<u8>), UssError>
where
    R::Response: SoapMessage,
{
    let request = decode_payload::<R>(payload, &cx.inner.limits).map_err(|_| {
        UssError::code(
            ErrorCode::InvalidParameters,
            "the request does not match the operation schema",
        )
    })?;
    let response = op(cx, request)?;
    let enc = encode_response(version, &response);
    Ok((enc.content_type, enc.body))
}

/// Host name from the `Host` header, port removed, when it looks sane.
fn host_of(req: &HttpRequestParts) -> Option<String> {
    let host = req.header("Host")?.trim();
    let name = match host.strip_prefix('[') {
        Some(rest) => format!("[{}", rest.split_once(']')?.0) + "]",
        None => host.split(':').next()?.to_owned(),
    };
    let ok = !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'[' | b']' | b':')
        });
    ok.then_some(name)
}

fn load_config_state(
    db: &Database,
    fingerprint: &str,
    now: i64,
) -> Result<ConfigState, storage::Error> {
    db.transaction(|tx| {
        let get = |k: &str| -> Result<Option<String>, storage::Error> {
            Ok(tx
                .query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
                .optional()?)
        };
        let put = |k: &str, v: &str| -> Result<(), storage::Error> {
            tx.execute(
                "INSERT INTO meta(key,value) VALUES(?1,?2) \
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                rusqlite::params![k, v],
            )?;
            Ok(())
        };
        let fp = get(META_CFG_FP)?;
        let generation = get(META_CFG_GEN)?.and_then(|v| v.parse::<i64>().ok());
        let last = get(META_CFG_AT)?.and_then(|v| v.parse::<i64>().ok());
        let state = match (fp.as_deref() == Some(fingerprint), generation, last) {
            (true, Some(g), Some(l)) => ConfigState {
                generation: g,
                last_change: l,
            },
            (_, g, l) => {
                let state = ConfigState {
                    generation: g.unwrap_or(0) + 1,
                    last_change: now.max(l.unwrap_or(0) + 1),
                };
                put(META_CFG_FP, fingerprint)?;
                put(META_CFG_GEN, &state.generation.to_string())?;
                put(META_CFG_AT, &state.last_change.to_string())?;
                state
            }
        };
        Ok(state)
    })
}

/// Source id by name.
pub(crate) fn source_id(inner: &Inner) -> Result<Option<SourceId>, storage::Error> {
    Ok(inner
        .svc
        .catalog
        .source_by_name(&inner.config.source_name)?
        .map(|s| s.id))
}
