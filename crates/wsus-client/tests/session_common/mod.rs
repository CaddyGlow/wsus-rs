//! In-process fake MS-WUSP server and harness shared by the session and sync
//! tests. Responses are produced with the wsus-protocol encoders from the
//! MS-WUSP 38.0 message shapes. NOTHING here is a capture from, or has been
//! validated against, a real WSUS server.
#![allow(dead_code)]

use base64::Engine as _;
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use uuid::Uuid;
use wsus_client::{
    session::{Clock, ManualClock, SessionConfig, WuspSession, unix_to_xs},
    state::StateStore,
    sync::{RevisionStore, SyncEngine},
    transport::{
        HttpRequest, HttpResponse, ImmediateTimer, Method, RetryPolicy, TransportError,
        mock::{MockStep, MockTransport},
    },
};
use wsus_protocol::{
    common::{AuthPlugInInfo, AuthorizationCookie, Cookie},
    identity::{Revision, UpdateId, UpdateRevision},
    soap::{
        ErrorCode, Limits, Presence, Scalar, SoapFault, SoapVersion, XsDateTime, decode_request,
        encode_fault, encode_response,
    },
    wusp::*,
};

pub const T0: i64 = 1_700_000_000;
pub const BASE: &str = "http://wsus.test:8530";

pub fn rev(n: u128, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(Uuid::from_u128(n)),
        revision: Revision(r),
    }
}

pub fn sha1_of(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

#[derive(Clone)]
pub struct ServerRevision {
    pub local_id: i32,
    pub identity: UpdateRevision,
    pub leaf: bool,
    pub bundled: Vec<UpdateRevision>,
    pub prerequisites: Vec<UpdateId>,
    pub file: Option<(String, Vec<u8>)>,
    pub action: String,
    pub retired: bool,
    /// Serve spec-style fragments: no root, stripped namespaces, b./m./d.
    /// dotted names (MS-WUSP 3.1.1.1); not well-formed XML.
    pub lenient: bool,
}

impl ServerRevision {
    fn core_xml(&self) -> String {
        let mut rel = String::new();
        if !self.bundled.is_empty() {
            rel.push_str("<BundledUpdates>");
            for b in &self.bundled {
                rel.push_str(&format!(
                    "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"{}\"/>",
                    b.id, b.revision.0
                ));
            }
            rel.push_str("</BundledUpdates>");
        }
        if !self.prerequisites.is_empty() {
            rel.push_str("<Prerequisites>");
            for p in &self.prerequisites {
                rel.push_str(&format!("<UpdateIdentity UpdateID=\"{p}\"/>"));
            }
            rel.push_str("</Prerequisites>");
        }
        if self.lenient {
            return format!(
                "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"{}\"/><Properties UpdateType=\"Software\"/><Relationships>{rel}</Relationships><ApplicabilityRules><b.WindowsVersion Major=\"10\"/><m.MsiProductInstalled ProductCode=\"x\"/><d.Driver x:y=\"1\"/></ApplicabilityRules>",
                self.identity.id, self.identity.revision.0
            );
        }
        format!(
            "<Update><UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"{}\"/><Properties UpdateType=\"Software\"/><Relationships>{rel}</Relationships></Update>",
            self.identity.id, self.identity.revision.0
        )
    }

    fn extended_xml(&self) -> String {
        let files = match &self.file {
            Some((name, data)) => format!(
                "<Files><File FileName=\"{name}\" Size=\"{}\" Digest=\"{}\" DigestAlgorithm=\"SHA1\"/></Files>",
                data.len(),
                base64::engine::general_purpose::STANDARD.encode(sha1_of(data))
            ),
            None => "<Files/>".into(),
        };
        if self.lenient {
            return format!(
                "<Properties MaxDownloadSize=\"1234\"/>{files}<HandlerSpecificData type=\"x\"><d.Thing/></HandlerSpecificData>"
            );
        }
        format!("<Update><Properties/>{files}</Update>")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReportMode {
    Normal,
    /// Process the batch, then lose the response (transport failure).
    LoseResponseOnce,
}

pub struct Fake {
    pub clock: ManualClock,
    pub last_change: String,
    pub registration_required: bool,
    pub registered: bool,
    pub cookie_ttl: i64,
    /// Cookies are valid only for this epoch; bump to answer InvalidCookie /
    /// ServerChanged.
    pub cookie_epoch: u32,
    pub server_changed_fault: bool,
    pub revisions: Vec<ServerRevision>,
    pub page_size: usize,
    pub max_extended: i32,
    pub allowed_events: Vec<i32>,
    pub location_generation: u32,
    pub calls: Vec<String>,
    pub sent_counts: BTreeMap<i32, u32>,
    pub old_cookies_seen: Vec<bool>,
    pub faults: VecDeque<(String, ErrorCode)>,
    pub always_fault: BTreeMap<String, ErrorCode>,
    pub transport_failures: VecDeque<String>,
    pub report_mode: ReportMode,
    pub reported: Vec<Uuid>,
    /// Every reported event as received (wire shape).
    pub reported_events: Vec<wsus_protocol::wusp::ReportingEvent>,
    pub issued: u32,
    pub extended_batches: Vec<usize>,
    pub content_corruption: bool,
    pub gets: u32,
    pub changed_next: BTreeSet<i32>,
    /// Number of GetFileLocations answers that hand out an already rotated
    /// (expired) location.
    pub stale_location_responses: u32,
    /// `SyncUpdates` answers `InvalidParameters` when
    /// `InstalledNonLeafUpdateIDs` is longer than this (lab WSUS: 400).
    pub max_installed_non_leaf: Option<usize>,
    /// (installed non-leaf, other cached) list lengths of every `SyncUpdates`.
    pub list_sizes: Vec<(usize, usize)>,
    /// Staged rule of the lab WSUS (inventory 9.3): a revision is delivered only when every
    /// prerequisite is the update of an id in `InstalledNonLeafUpdateIDs`, and a cached
    /// revision with an unlisted prerequisite is answered as out of scope.
    pub enforce_prerequisites: bool,
}

impl Fake {
    pub fn new(clock: ManualClock) -> Self {
        Self {
            clock,
            last_change: "2024-01-01T00:00:00Z".into(),
            registration_required: false,
            registered: false,
            cookie_ttl: 3600,
            cookie_epoch: 1,
            server_changed_fault: false,
            revisions: Vec::new(),
            page_size: 100,
            max_extended: 50,
            allowed_events: vec![],
            location_generation: 1,
            calls: Vec::new(),
            sent_counts: BTreeMap::new(),
            old_cookies_seen: Vec::new(),
            faults: VecDeque::new(),
            always_fault: BTreeMap::new(),
            transport_failures: VecDeque::new(),
            report_mode: ReportMode::Normal,
            reported: Vec::new(),
            reported_events: Vec::new(),
            issued: 0,
            extended_batches: Vec::new(),
            content_corruption: false,
            gets: 0,
            changed_next: BTreeSet::new(),
            stale_location_responses: 0,
            max_installed_non_leaf: None,
            list_sizes: Vec::new(),
            enforce_prerequisites: false,
        }
    }

    pub fn add(&mut self, n: u128, r: u32, leaf: bool) -> &mut ServerRevision {
        let local_id = 100 + self.revisions.len() as i32;
        self.revisions.push(ServerRevision {
            local_id,
            identity: rev(n, r),
            leaf,
            bundled: vec![],
            prerequisites: vec![],
            file: None,
            action: "Install".into(),
            retired: false,
            lenient: false,
        });
        self.revisions.last_mut().unwrap()
    }

    pub fn count(&self, op: &str) -> usize {
        self.calls.iter().filter(|c| *c == op).count()
    }

    fn url_for(&self, sha1: &[u8]) -> String {
        self.url_for_gen(sha1, self.location_generation)
    }

    fn url_for_gen(&self, sha1: &[u8], generation: u32) -> String {
        let hex: String = sha1.iter().map(|b| format!("{b:02x}")).collect();
        format!("http://content.test/g{generation}/{hex}?sig=SECRET{generation}")
    }

    fn cookie_data(&self) -> Vec<u8> {
        format!(
            "cookie-e{}-c{}-n{}",
            self.cookie_epoch, self.last_change, self.issued
        )
        .into_bytes()
    }

    fn check_cookie(&self, cookie: &Presence<Cookie>) -> Result<(), ErrorCode> {
        let Some(c) = cookie.value() else {
            return Err(ErrorCode::InvalidCookie);
        };
        let data =
            String::from_utf8_lossy(c.encrypted_data.value().map_or(&[][..], |v| v.as_slice()))
                .into_owned();
        if self.server_changed_fault
            && !data.starts_with(&format!("cookie-e{}-", self.cookie_epoch))
        {
            return Err(ErrorCode::ServerChanged);
        }
        if !data.starts_with(&format!("cookie-e{}-", self.cookie_epoch)) {
            return Err(ErrorCode::InvalidCookie);
        }
        if !data.contains(&format!("-c{}-", self.last_change)) {
            return Err(ErrorCode::ConfigChanged);
        }
        let exp = wsus_client::session::xs_to_unix(&c.expiration).unwrap_or(0);
        if exp <= self.clock.now_unix() {
            return Err(ErrorCode::CookieExpired);
        }
        Ok(())
    }
}

fn fault_response(code: ErrorCode, method: &str) -> MockStep {
    let fault = SoapFault::application(
        SoapVersion::V11,
        code,
        "fake fault",
        None,
        None,
        Some(method),
    );
    let enc = encode_fault(&fault);
    MockStep::Respond(HttpResponse::new(500, enc.body))
}

fn ok<M: wsus_protocol::soap::SoapMessage>(m: &M) -> MockStep {
    MockStep::Respond(HttpResponse::new(
        200,
        encode_response(SoapVersion::V11, m).body,
    ))
}

fn deployment(rev: &ServerRevision) -> Deployment {
    Deployment {
        id: rev.local_id,
        action: DeploymentAction::parse(&rev.action).unwrap(),
        deadline: Presence::Absent,
        is_assigned: true,
        last_change_time: "2024-01-01T00:00:00Z".into(),
        download_priority: Presence::Absent,
        hardware_ids: Presence::Absent,
        auto_select: Presence::Absent,
        auto_download: Presence::Absent,
        supersedence_behavior: Presence::Absent,
        flag_bitmask: Presence::Absent,
        client_behaviors: Presence::Absent,
    }
}

fn update_info(r: &ServerRevision) -> UpdateInfo {
    UpdateInfo {
        id: r.local_id,
        deployment: Presence::Value(deployment(r)),
        is_leaf: r.leaf,
        xml: Presence::Value(r.core_xml()),
    }
}

fn handle(shared: &Mutex<Fake>, req: &HttpRequest) -> MockStep {
    let mut f = shared.lock().unwrap();
    if req.method == Method::Get {
        return serve_content(&mut f, req);
    }
    let action = req
        .headers
        .get("soapaction")
        .unwrap_or("")
        .trim_matches('"')
        .to_owned();
    let op = action.rsplit('/').next().unwrap_or("").to_owned();
    let limits = Limits::default();
    f.calls.push(op.clone());
    if let Some(pos) = f.transport_failures.iter().position(|o| *o == op) {
        f.transport_failures.remove(pos);
        return MockStep::Fail(TransportError::io("connection reset"));
    }
    if let Some(code) = f.always_fault.get(&op).cloned() {
        return fault_response(code, &op);
    }
    if let Some(pos) = f.faults.iter().position(|(o, _)| *o == op) {
        let (_, code) = f.faults.remove(pos).unwrap();
        return fault_response(code, &op);
    }
    macro_rules! decode {
        ($t:ty) => {
            decode_request::<$t>(Some(&action), &req.body, &limits)
                .expect("request decodes")
                .1
        };
    }
    let now = f.clock.now_unix();
    match op.as_str() {
        "GetConfig" => {
            let _ = decode!(GetConfig);
            let config = Config {
                last_change: XsDateTime::new(&f.last_change).unwrap(),
                is_registration_required: f.registration_required,
                auth_info: Presence::Value(vec![AuthPlugInInfo {
                    plug_in_id: Presence::Value("SimpleTargeting".into()),
                    service_url: Presence::Value("SimpleAuthWebService/SimpleAuth.asmx".into()),
                    parameter: Presence::Absent,
                }]),
                allowed_event_ids: Presence::Value(f.allowed_events.clone()),
                properties: Presence::Value(vec![ConfigurationProperty {
                    name: Presence::Value("MaxExtendedUpdatesPerRequest".into()),
                    value: Presence::Value(f.max_extended.to_string()),
                }]),
            };
            ok(&GetConfigResponse {
                result: Presence::Value(config),
            })
        }
        "GetAuthorizationCookie" => {
            let _ = decode!(GetAuthorizationCookie);
            ok(&GetAuthorizationCookieResponse {
                result: Presence::Value(AuthorizationCookie {
                    plug_in_id: Presence::Value("SimpleTargeting".into()),
                    cookie_data: Presence::Value(b"auth".to_vec()),
                }),
            })
        }
        "GetCookie" => {
            let r = decode!(GetCookie);
            f.old_cookies_seen.push(r.old_cookie.value().is_some());
            if r.last_change.as_str() != f.last_change {
                return fault_response(ErrorCode::ConfigChanged, &op);
            }
            f.issued += 1;
            let cookie = Cookie {
                expiration: unix_to_xs(now + f.cookie_ttl),
                encrypted_data: Presence::Value(f.cookie_data()),
            };
            ok(&GetCookieResponse {
                result: Presence::Value(cookie),
            })
        }
        "RegisterComputer" => {
            let r = decode!(RegisterComputer);
            if let Err(c) = f.check_cookie(&r.cookie) {
                return fault_response(c, &op);
            }
            f.registered = true;
            ok(&RegisterComputerResponse {})
        }
        "RefreshCache" => {
            let r = decode!(RefreshCache);
            if let Err(c) = f.check_cookie(&r.cookie) {
                return fault_response(c, &op);
            }
            let results = r
                .global_ids
                .value()
                .into_iter()
                .flatten()
                .filter_map(|g| f.revisions.iter().find(|s| s.identity == *g))
                .map(|s| RefreshCacheResult {
                    revision_id: s.local_id,
                    global_id: Presence::Value(s.identity),
                    is_leaf: s.leaf,
                    deployment: Presence::Value(deployment(s)),
                })
                .collect();
            ok(&RefreshCacheResponse {
                result: Presence::Value(results),
            })
        }
        "SyncUpdates" => {
            let r = decode!(SyncUpdates);
            if let Err(c) = f.check_cookie(&r.cookie) {
                return fault_response(c, &op);
            }
            if f.registration_required && !f.registered {
                return fault_response(ErrorCode::RegistrationRequired, &op);
            }
            let p = r.parameters.value().unwrap();
            let installed_len = p
                .installed_non_leaf_update_ids
                .value()
                .map_or(0, |v| v.len());
            let other_len = p.other_cached_update_ids.value().map_or(0, |v| v.len());
            f.list_sizes.push((installed_len, other_len));
            if f.max_installed_non_leaf.is_some_and(|m| installed_len > m) {
                return fault_response(ErrorCode::InvalidParameters, &op);
            }
            let cached: BTreeSet<i32> = p
                .installed_non_leaf_update_ids
                .value()
                .into_iter()
                .flatten()
                .chain(p.other_cached_update_ids.value().into_iter().flatten())
                .chain(p.cached_driver_ids.value().into_iter().flatten())
                .copied()
                .collect();
            let installed_updates: BTreeSet<UpdateId> = p
                .installed_non_leaf_update_ids
                .value()
                .into_iter()
                .flatten()
                .filter_map(|id| f.revisions.iter().find(|s| s.local_id == *id))
                .map(|s| s.identity.id)
                .collect();
            let satisfied = |s: &ServerRevision| {
                !f.enforce_prerequisites
                    || s.prerequisites
                        .iter()
                        .all(|p| installed_updates.contains(p))
            };
            let oos: Vec<i32> = f
                .revisions
                .iter()
                .filter(|s| (s.retired || !satisfied(s)) && cached.contains(&s.local_id))
                .map(|s| s.local_id)
                .collect();
            let changed_ids: Vec<i32> = f
                .changed_next
                .iter()
                .copied()
                .filter(|i| cached.contains(i))
                .collect();
            let fresh: Vec<ServerRevision> = f
                .revisions
                .iter()
                .filter(|s| !s.retired && !cached.contains(&s.local_id) && satisfied(s))
                .cloned()
                .collect();
            let page: Vec<ServerRevision> = fresh.iter().take(f.page_size).cloned().collect();
            let truncated = fresh.len() > page.len();
            for s in &page {
                *f.sent_counts.entry(s.local_id).or_default() += 1;
            }
            let changed: Vec<UpdateInfo> = f
                .revisions
                .iter()
                .filter(|s| changed_ids.contains(&s.local_id))
                .map(|s| {
                    let mut u = update_info(s);
                    u.xml = Presence::Absent;
                    u
                })
                .collect();
            for i in &changed_ids {
                f.changed_next.remove(i);
            }
            ok(&SyncUpdatesResponse {
                result: Presence::Value(SyncInfo {
                    new_updates: Presence::Value(page.iter().map(update_info).collect()),
                    out_of_scope_revision_ids: Presence::Value(oos),
                    changed_updates: Presence::Value(changed),
                    truncated,
                    new_cookie: Presence::Absent,
                    deployed_out_of_scope_revision_ids: Presence::Absent,
                    driver_sync_not_needed: Presence::Absent,
                }),
            })
        }
        "GetExtendedUpdateInfo" | "GetExtendedUpdateInfo2" => {
            let (cookie, ids, types, locales): (
                _,
                Vec<i32>,
                Vec<XmlUpdateFragmentType>,
                Vec<String>,
            ) = if op == "GetExtendedUpdateInfo" {
                let r = decode!(GetExtendedUpdateInfo);
                (
                    r.cookie.clone(),
                    r.revision_ids.value().cloned().unwrap_or_default(),
                    r.info_types.value().cloned().unwrap_or_default(),
                    r.locales.value().cloned().unwrap_or_default(),
                )
            } else {
                let r = decode!(GetExtendedUpdateInfo2);
                let ids = r
                    .update_ids
                    .value()
                    .into_iter()
                    .flatten()
                    .filter_map(|u| f.revisions.iter().find(|s| s.identity == *u))
                    .map(|s| s.local_id)
                    .collect();
                (
                    r.cookie.clone(),
                    ids,
                    r.info_types.value().cloned().unwrap_or_default(),
                    r.locales.value().cloned().unwrap_or_default(),
                )
            };
            if let Err(c) = f.check_cookie(&cookie) {
                return fault_response(c, &op);
            }
            f.extended_batches.push(ids.len());
            let mut updates = Vec::new();
            let mut locations = Vec::new();
            let mut oos = Vec::new();
            for id in &ids {
                let Some(s) = f.revisions.iter().find(|s| s.local_id == *id) else {
                    oos.push(*id);
                    continue;
                };
                for t in &types {
                    match t {
                        XmlUpdateFragmentType::Extended => updates.push(UpdateData {
                            id: *id,
                            xml: Presence::Value(s.extended_xml()),
                        }),
                        XmlUpdateFragmentType::LocalizedProperties => {
                            for l in &locales {
                                updates.push(UpdateData {
                                    id: *id,
                                    xml: Presence::Value(format!(
                                        "<LocalizedProperties><Language>{l}</Language><Title>Title {l}</Title><Description>Desc {l}</Description></LocalizedProperties>"
                                    )),
                                });
                            }
                        }
                        XmlUpdateFragmentType::FileUrl => {
                            if let Some((_, data)) = &s.file {
                                let sha = sha1_of(data);
                                locations.push(FileLocation {
                                    file_digest: Presence::Value(sha.clone()),
                                    url: Presence::Value(f.url_for(&sha)),
                                    pieces_hash_url: Presence::Absent,
                                    block_map_url: Presence::Absent,
                                    decryption_information: Presence::Absent,
                                    file_digest_algorithm: Presence::Absent,
                                    encrypted_file_digest: Presence::Absent,
                                    encrypted_file_digest_algorithm: Presence::Absent,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            if op == "GetExtendedUpdateInfo" {
                ok(&GetExtendedUpdateInfoResponse {
                    result: Presence::Value(ExtendedUpdateInfo {
                        updates: Presence::Value(updates),
                        file_locations: Presence::Value(locations),
                        out_of_scope_revision_ids: Presence::Value(oos),
                    }),
                })
            } else {
                ok(&GetExtendedUpdateInfo2Response {
                    result: Presence::Value(ExtendedUpdateInfo2 {
                        updates: Presence::Value(updates),
                        file_locations: Presence::Value(locations),
                        file_decryption_data: Presence::Absent,
                        file_decryption_data2: Presence::Absent,
                        update_encryption_details: Presence::Absent,
                    }),
                })
            }
        }
        "GetFileLocations" => {
            let r = decode!(GetFileLocations);
            if let Err(c) = f.check_cookie(&r.cookie) {
                return fault_response(c, &op);
            }
            let mut out = Vec::new();
            let stale = f.stale_location_responses > 0;
            if stale {
                f.stale_location_responses -= 1;
            }
            let generation = f.location_generation - u32::from(stale);
            for d in r.file_digests.value().into_iter().flatten() {
                if f.revisions
                    .iter()
                    .any(|s| s.file.as_ref().is_some_and(|(_, data)| sha1_of(data) == *d))
                {
                    out.push(FileLocation {
                        file_digest: Presence::Value(d.clone()),
                        url: Presence::Value(f.url_for_gen(d, generation)),
                        pieces_hash_url: Presence::Absent,
                        block_map_url: Presence::Absent,
                        decryption_information: Presence::Absent,
                        file_digest_algorithm: Presence::Absent,
                        encrypted_file_digest: Presence::Absent,
                        encrypted_file_digest_algorithm: Presence::Absent,
                    });
                }
            }
            ok(&GetFileLocationsResponse {
                result: Presence::Value(GetFileLocationsResults {
                    file_locations: Presence::Value(out),
                    new_cookie: Presence::Absent,
                }),
            })
        }
        "ReportEventBatch" => {
            let r = decode!(ReportEventBatch);
            if let Err(c) = f.check_cookie(&r.cookie) {
                return fault_response(c, &op);
            }
            for e in r.event_batch.value().into_iter().flatten() {
                if let Some(b) = e.basic_data.value() {
                    f.reported.push(b.event_instance_id);
                }
                f.reported_events.push(e.clone());
            }
            if f.report_mode == ReportMode::LoseResponseOnce {
                f.report_mode = ReportMode::Normal;
                return MockStep::Fail(TransportError::io("connection reset"));
            }
            ok(&ReportEventBatchResponse { result: true })
        }
        other => panic!("fake server: unexpected operation {other}"),
    }
}

fn serve_content(f: &mut Fake, req: &HttpRequest) -> MockStep {
    f.gets += 1;
    let url = req.url.expose().to_owned();
    let Some(path) = url.strip_prefix("http://content.test/g") else {
        return MockStep::Respond(HttpResponse::new(404, vec![]));
    };
    let (gen_part, rest) = path.split_once('/').unwrap_or(("", ""));
    if gen_part != f.location_generation.to_string() {
        return MockStep::Respond(HttpResponse::new(403, b"expired".to_vec()));
    }
    let hex = rest.split('?').next().unwrap_or("");
    let Some(data) = f.revisions.iter().find_map(|s| {
        s.file.as_ref().and_then(|(_, d)| {
            let h: String = sha1_of(d).iter().map(|b| format!("{b:02x}")).collect();
            (h == hex).then(|| d.clone())
        })
    }) else {
        return MockStep::Respond(HttpResponse::new(404, vec![]));
    };
    let mut body = data;
    if f.content_corruption {
        body[0] ^= 0xff;
    }
    let mut response = HttpResponse::new(200, body.clone());
    response
        .headers
        .set("Content-Length", body.len().to_string());
    MockStep::Respond(response)
}

pub type Session = WuspSession<MockTransport, ImmediateTimer, ManualClock>;
pub type Engine = SyncEngine<MockTransport, ImmediateTimer, ManualClock>;

pub struct Harness {
    pub fake: Arc<Mutex<Fake>>,
    pub clock: ManualClock,
    pub dir: TempDir,
    pub transport: MockTransport,
}

pub fn computer_info() -> ComputerInfo {
    ComputerInfo {
        dns_name: Presence::Absent,
        os_major_version: 10,
        os_minor_version: 0,
        os_build_number: 26100,
        os_service_pack_major_number: 0,
        os_service_pack_minor_number: 0,
        os_locale: Presence::Value("en-US".into()),
        computer_manufacturer: Presence::Absent,
        computer_model: Presence::Absent,
        bios_version: Presence::Absent,
        bios_name: Presence::Absent,
        bios_release_date: XsDateTime::new("2024-01-01T00:00:00Z").unwrap(),
        processor_architecture: Presence::Absent,
        suite_mask: 0,
        old_product_type: 1,
        new_product_type: 48,
        system_metrics: 0,
        client_version_major_number: 10,
        client_version_minor_number: 0,
        client_version_build_number: 26100,
        client_version_qfe_number: 0,
        os_description: Presence::Absent,
        oem: Presence::Absent,
        device_type: Presence::Absent,
        firmware_version: Presence::Absent,
        mobile_operator: Presence::Absent,
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Like [`Harness::new`], but every response is post-processed by
    /// `encode` when the request sent `Accept-Encoding: xpress`.
    pub fn with_response_encoding(
        encode: impl Fn(HttpResponse) -> HttpResponse + Send + Sync + 'static,
    ) -> Self {
        Self::build(Some(Box::new(encode)))
    }

    fn build(encode: Option<Box<dyn Fn(HttpResponse) -> HttpResponse + Send + Sync>>) -> Self {
        let clock = ManualClock::new(T0);
        let fake = Arc::new(Mutex::new(Fake::new(clock.clone())));
        let shared = fake.clone();
        let transport = MockTransport::with_handler(move |req| {
            let step = handle(&shared, req);
            match (&encode, step) {
                (Some(encode), MockStep::Respond(resp))
                    if req
                        .headers
                        .get("accept-encoding")
                        .is_some_and(|v| v.contains("xpress")) =>
                {
                    MockStep::Respond(encode(resp))
                }
                (_, step) => step,
            }
        });
        Self {
            fake,
            clock,
            dir: TempDir::new().unwrap(),
            transport,
        }
    }

    pub fn fake(&self) -> std::sync::MutexGuard<'_, Fake> {
        self.fake.lock().unwrap()
    }

    pub fn state_path(&self) -> PathBuf {
        self.dir.path().join("state").join("state.json")
    }

    pub fn config(&self) -> SessionConfig {
        let mut c = SessionConfig::new(BASE, "client.test");
        c.computer_info = Some(computer_info());
        c.retry = RetryPolicy::none();
        c
    }

    pub fn session_with(&self, config: SessionConfig) -> Session {
        let store = StateStore::open(self.state_path()).unwrap();
        WuspSession::new(
            self.transport.clone(),
            ImmediateTimer,
            self.clock.clone(),
            config,
            store,
        )
        .unwrap()
    }

    pub fn session(&self) -> Session {
        self.session_with(self.config())
    }

    pub fn engine_with(&self, config: SessionConfig) -> Engine {
        let store = RevisionStore::open(self.dir.path().join("meta")).unwrap();
        SyncEngine::new(self.session_with(config), store)
    }

    pub fn engine(&self) -> Engine {
        self.engine_with(self.config())
    }

    pub fn ops(&self) -> Vec<String> {
        self.fake().calls.clone()
    }
}
