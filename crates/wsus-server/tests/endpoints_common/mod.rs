#![allow(dead_code)]
//! Shared in-process harness: temp database, content store, server, and a tiny client.
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use sha1::Sha1;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wsus_protocol::common::{AuthorizationCookie, Cookie};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest, Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{
    Envelope, ErrorCode, Limits, Presence, SoapFault, SoapRequest, SoapVersion, XsDateTime,
    decode_response, encode_request,
};
use wsus_protocol::wusp::*;
use wsus_server::catalog::*;
use wsus_server::computers::Computers;
use wsus_server::content::{ContentDescriptor, ContentStore};
use wsus_server::endpoints::{
    HttpRequestParts, HttpResponseParts, ServerConfig, Services, SyncDelivery, WsusServer,
};
use wsus_server::policy::{ALL_COMPUTERS, DeploymentAction as PolicyAction, Policy};
use wsus_server::reporting::Reporting;
use wsus_server::session::{SessionConfig, SessionManager};
use wsus_server::storage::{Database, now_unix};

pub const CLIENT_PATH: &str = "/ClientWebService/client.asmx";
pub const AUTH_PATH: &str = "/SimpleAuthWebService/SimpleAuth.asmx";
pub const REPORTING_PATH: &str = "/ReportingWebService/ReportingWebService.asmx";

pub fn uid(n: u128) -> UpdateId {
    UpdateId(Uuid::from_u128(n))
}

pub fn rev(n: u128, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: uid(n),
        revision: Revision(r),
    }
}

pub fn digests(data: &[u8]) -> Vec<FileDigest> {
    vec![
        FileDigest {
            algorithm: DigestAlgorithm::Sha1,
            bytes: Sha1::digest(data).to_vec(),
        },
        FileDigest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: Sha256::digest(data).to_vec(),
        },
    ]
}

pub fn sha1_of(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

pub fn descriptor(name: &str, data: &[u8]) -> FileDescriptor {
    FileDescriptor {
        file_name: name.into(),
        size: data.len() as u64,
        digests: digests(data),
    }
}

pub fn frag(n: u128) -> FragmentImport {
    let mut f = FragmentImport::new(
        rev(n, 1),
        "Software",
        format!("<Update n=\"{n}\"/>").as_bytes(),
    );
    f.extended_xml = Some(format!("<Extended n=\"{n}\"/>").into_bytes());
    f
}

pub fn with_prereq(mut f: FragmentImport, target: u128) -> FragmentImport {
    f.relationships.push(RelationshipImport {
        kind: RelationshipKind::Prerequisite,
        target: uid(target),
        revision: None,
    });
    f
}

pub fn with_file(mut f: FragmentImport, name: &str, data: &[u8]) -> FragmentImport {
    f.files.push(descriptor(name, data));
    f
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub db: Database,
    pub catalog: Catalog,
    pub policy: Policy,
    pub computers: Computers,
    pub reporting: Reporting,
    pub content: ContentStore,
    pub sessions: Arc<SessionManager>,
    pub server: WsusServer,
    pub clock: Arc<AtomicI64>,
    pub source: SourceId,
}

pub fn default_config() -> ServerConfig {
    ServerConfig {
        source_name: "upstream".into(),
        content_base_url: Some("http://wsus.test:8530".into()),
        ..ServerConfig::default()
    }
}

/// Both `SyncUpdates` delivery modes; shared tests loop over this.
pub const MODES: [SyncDelivery; 2] = [SyncDelivery::Staged, SyncDelivery::Closure];

/// Test configuration for a delivery mode (page size and advertised version follow the mode).
pub fn config_for(mode: SyncDelivery) -> ServerConfig {
    let base = match mode {
        SyncDelivery::Staged => ServerConfig::default(),
        SyncDelivery::Closure => ServerConfig::closure(),
    };
    ServerConfig {
        source_name: "upstream".into(),
        content_base_url: Some("http://wsus.test:8530".into()),
        ..base
    }
}

pub fn setup_mode(mode: SyncDelivery) -> Env {
    setup_with(config_for(mode))
}

pub fn setup() -> Env {
    setup_with(default_config())
}

pub fn setup_with(config: ServerConfig) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("db.sqlite")).unwrap();
    build(dir, db, config)
}

pub fn build(dir: tempfile::TempDir, db: Database, config: ServerConfig) -> Env {
    let clock = Arc::new(AtomicI64::new(now_unix()));
    let c = clock.clone();
    let sessions = Arc::new(
        SessionManager::open_with_clock(
            db.clone(),
            SessionConfig::default(),
            &config.fingerprint(),
            Arc::new(move || c.load(Ordering::SeqCst)),
        )
        .unwrap(),
    );
    let catalog = Catalog::new(db.clone());
    let source = match catalog.source_by_name("upstream").unwrap() {
        Some(s) => s.id,
        None => catalog
            .add_source("upstream", SourceKind::Upstream, "")
            .unwrap(),
    };
    let content = ContentStore::open(db.clone(), &dir.path().join("content")).unwrap();
    let policy = Policy::new(db.clone());
    let computers = Computers::new(db.clone());
    let reporting = Reporting::new(db.clone());
    let server = WsusServer::new(
        Services {
            catalog: catalog.clone(),
            policy: policy.clone(),
            computers: computers.clone(),
            reporting: reporting.clone(),
            content: content.clone(),
            sessions: sessions.clone(),
        },
        config,
    );
    Env {
        dir,
        db,
        catalog,
        policy,
        computers,
        reporting,
        content,
        sessions,
        server,
        clock,
        source,
    }
}

impl Env {
    /// Import, validate and activate one generation.
    pub fn publish(&self, frags: &[FragmentImport]) -> GenerationId {
        let g = self.catalog.begin_generation(self.source, None).unwrap();
        self.catalog.import_fragments(g, frags).unwrap();
        match self.catalog.activate(g).unwrap() {
            ActivateOutcome::Activated { .. } => g,
            other => panic!("activation rejected: {other:?}"),
        }
    }

    pub fn approve(&self, n: u128) {
        self.policy
            .approve(uid(n), ALL_COMPUTERS, PolicyAction::Install, None)
            .unwrap();
    }

    pub fn advance(&self, secs: i64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn post(
        &self,
        path: &str,
        version: SoapVersion,
        body: Vec<u8>,
        ctype: &str,
        action: Option<&str>,
    ) -> HttpResponseParts {
        let _ = version;
        let mut r = HttpRequestParts::new("POST", path)
            .with_header("Content-Type", ctype)
            .with_body(body);
        if let Some(a) = action {
            r = r.with_header("SOAPAction", a);
        }
        self.server.handle(r)
    }

    pub fn raw<R: SoapRequest>(&self, version: SoapVersion, req: &R) -> HttpResponseParts {
        let enc = encode_request(version, req);
        let path = match R::NAMESPACE {
            wsus_protocol::wusp::SIMPLE_AUTH_NS => AUTH_PATH,
            wsus_protocol::wusp::REPORTING_NS => REPORTING_PATH,
            _ => CLIENT_PATH,
        };
        self.post(
            path,
            version,
            enc.body,
            &enc.content_type,
            enc.soap_action.as_deref(),
        )
    }

    /// Typed call. `Err` carries the HTTP status and the decoded fault.
    pub fn call<R: SoapRequest>(&self, req: &R) -> Result<R::Response, (u16, Box<SoapFault>)> {
        let resp = self.raw(SoapVersion::V11, req);
        let status = resp.status;
        let body = resp.into_bytes().unwrap();
        match decode_response::<R::Response>(&body, &Limits::default()) {
            Ok(r) => {
                assert_eq!(status, 200);
                Ok(r)
            }
            Err(wsus_protocol::ProtocolError::Fault(f)) => Err((status, f)),
            Err(e) => panic!(
                "undecodable response (status {status}): {e}\n{}",
                String::from_utf8_lossy(&body)
            ),
        }
    }

    pub fn fault_code<R: SoapRequest>(&self, req: &R) -> ErrorCode {
        let (status, f) = self.call(req).err().expect("expected a fault");
        assert_eq!(status, 500, "SOAP 1.1 faults are HTTP 500");
        f.wsus.expect("WSUS fault detail").error_code
    }

    pub fn get(&self, path: &str) -> HttpResponseParts {
        self.server.handle(HttpRequestParts::new("GET", path))
    }
}

pub fn xs(s: &str) -> XsDateTime {
    XsDateTime::new(s).unwrap()
}

pub struct Client {
    pub id: Uuid,
    pub cookie: Cookie,
}

pub fn get_config(env: &Env) -> Config {
    env.call(&GetConfig {
        protocol_version: Presence::Value("1.8".into()),
    })
    .unwrap()
    .result
    .into_value()
    .unwrap()
}

pub fn auth_cookie(env: &Env, id: Uuid, group: Option<&str>) -> AuthorizationCookie {
    env.call(&GetAuthorizationCookie {
        client_id: Presence::Value(id.to_string()),
        target_group_name: group.map_or(Presence::Absent, |g| Presence::Value(g.into())),
        dns_name: Presence::Value("pc1.example".into()),
    })
    .unwrap()
    .result
    .into_value()
    .unwrap()
}

pub fn get_cookie_req(env: &Env, auth: AuthorizationCookie, old: Option<Cookie>) -> GetCookie {
    GetCookie {
        auth_cookies: Presence::Value(vec![auth]),
        old_cookie: old.map_or(Presence::Absent, Presence::Value),
        last_change: get_config(env).last_change,
        current_time: xs("2026-10-04T00:00:00Z"),
        protocol_version: Presence::Value("1.8".into()),
    }
}

pub fn computer_info() -> ComputerInfo {
    ComputerInfo {
        dns_name: Presence::Value("pc1.example".into()),
        os_major_version: 10,
        os_minor_version: 0,
        os_build_number: 26100,
        os_service_pack_major_number: 0,
        os_service_pack_minor_number: 0,
        os_locale: Presence::Value("en-US".into()),
        computer_manufacturer: Presence::Value("Acme".into()),
        computer_model: Presence::Value("Box".into()),
        bios_version: Presence::Absent,
        bios_name: Presence::Absent,
        bios_release_date: xs("2024-01-01T00:00:00Z"),
        processor_architecture: Presence::Value("9".into()),
        suite_mask: 0,
        old_product_type: 1,
        new_product_type: 48,
        system_metrics: 0,
        client_version_major_number: 10,
        client_version_minor_number: 0,
        client_version_build_number: 26100,
        client_version_qfe_number: 1,
        os_description: Presence::Absent,
        oem: Presence::Absent,
        device_type: Presence::Absent,
        firmware_version: Presence::Absent,
        mobile_operator: Presence::Absent,
    }
}

pub fn register_req(cookie: &Cookie) -> RegisterComputer {
    RegisterComputer {
        cookie: Presence::Value(cookie.clone()),
        computer_info: Presence::Value(computer_info()),
    }
}

/// GetConfig, GetAuthorizationCookie, GetCookie. Not registered yet.
pub fn handshake(env: &Env, id: Uuid, group: Option<&str>) -> Client {
    let auth = auth_cookie(env, id, group);
    let cookie = env
        .call(&get_cookie_req(env, auth, None))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    Client { id, cookie }
}

/// Full handshake including RegisterComputer.
pub fn registered(env: &Env, n: u128) -> Client {
    let c = handshake(env, Uuid::from_u128(n), None);
    env.call(&register_req(&c.cookie)).unwrap();
    c
}

pub fn sync_req(cookie: &Cookie, installed: &[i32], other: &[i32]) -> SyncUpdates {
    SyncUpdates {
        cookie: Presence::Value(cookie.clone()),
        parameters: Presence::Value(SyncUpdateParameters {
            express_query: false,
            installed_non_leaf_update_ids: Presence::Value(installed.to_vec()),
            other_cached_update_ids: Presence::Value(other.to_vec()),
            system_spec: Presence::Absent,
            cached_driver_ids: Presence::Absent,
            skip_software_sync: false,
            filter_category_ids: Presence::Absent,
            need_two_group_out_of_scope_updates: Presence::Absent,
            computer_spec: Presence::Absent,
            feature_score_matching_key: Presence::Absent,
        }),
    }
}

/// One SyncUpdates call; returns the info and updates the client's cookie.
pub fn sync(env: &Env, c: &mut Client, installed: &[i32], other: &[i32]) -> SyncInfo {
    let info = env
        .call(&sync_req(&c.cookie, installed, other))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    if let Some(n) = info.new_cookie.value() {
        c.cookie = n.clone();
    }
    info
}

pub fn new_ids(info: &SyncInfo) -> Vec<i32> {
    info.new_updates
        .value()
        .map(|v| v.iter().map(|u| u.id).collect())
        .unwrap_or_default()
}

/// A client loop that behaves like the native agent for metadata whose rules always evaluate
/// as installed: non-leaf revisions go to `InstalledNonLeafUpdateIDs`, leaves to
/// `OtherCachedUpdateIDs`, and it calls again after a truncated response or after a response
/// that delivered a non-leaf update (MS-WUSP 3.1.5.7). Returns every response's updates.
pub fn sync_rounds(env: &Env, c: &mut Client) -> Vec<Vec<UpdateInfo>> {
    let mut rounds = Vec::new();
    let (mut installed, mut other): (Vec<i32>, Vec<i32>) = (Vec::new(), Vec::new());
    loop {
        let info = sync(env, c, &installed, &other);
        let ups: Vec<UpdateInfo> = info.new_updates.value().cloned().unwrap_or_default();
        for u in &ups {
            if u.is_leaf {
                other.push(u.id);
            } else {
                installed.push(u.id);
            }
        }
        let non_leaf = ups.iter().any(|u| !u.is_leaf);
        let again = info.truncated || non_leaf;
        if !ups.is_empty() {
            rounds.push(ups);
        }
        assert!(rounds.len() < 200, "sync did not converge");
        if !again {
            break;
        }
        assert!(
            !ups_is_empty_and_truncated(&info),
            "truncated response without updates"
        );
    }
    rounds
}

fn ups_is_empty_and_truncated(info: &SyncInfo) -> bool {
    info.truncated && new_ids(info).is_empty()
}

/// Ids received per call, see [`sync_rounds`].
pub fn sync_all(env: &Env, c: &mut Client) -> Vec<Vec<i32>> {
    sync_rounds(env, c)
        .into_iter()
        .map(|r| r.into_iter().map(|u| u.id).collect())
        .collect()
}

pub fn local(env: &Env, n: u128) -> i32 {
    env.catalog.find_local_id(rev(n, 1)).unwrap().unwrap().id
}

pub fn put_content(env: &Env, name: &str, data: &[u8]) {
    env.content
        .put_bytes(
            &ContentDescriptor {
                file_name: name.into(),
                size: data.len() as u64,
                digests: digests(data),
            },
            data,
        )
        .unwrap();
}

pub fn fault_of(resp: HttpResponseParts) -> (u16, SoapFault) {
    let status = resp.status;
    let body = resp.into_bytes().unwrap();
    match Envelope::decode(&body, &Limits::default()).expect("fault envelope") {
        Envelope {
            body: wsus_protocol::soap::Body::Fault(f),
            ..
        } => (status, f),
        other => panic!("expected a fault, got {other:?}"),
    }
}
