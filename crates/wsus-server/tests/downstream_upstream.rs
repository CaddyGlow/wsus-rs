//! Upstream orchestration tests against a fake upstream written here.
//!
//! Nothing here is validated against a real WSUS server: the fake implements
//! this project's reading of MS-WSUSSS, so passing proves internal consistency
//! (staging, resume, activation, checkpointing), not interoperability.
use base64::Engine as _;
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    future::Future,
    pin::pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    thread::{self, Thread},
};
use uuid::Uuid;
use wsus_client::{
    download::{DownloadLimits, DownloadOptions, Downloader},
    transport::{
        HttpRequest, HttpResponse, ImmediateTimer, Method, RetryPolicy, TransportError,
        mock::{MockStep, MockTransport},
    },
    wsusss::{WsusssClient, WsusssConfig},
};
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{
    Body, Envelope, ErrorCode, Limits, Presence, SoapFault, SoapMessage, SoapVersion,
    decode_payload, encode_fault, encode_response,
};
use wsus_protocol::wsusss::*;
use wsus_server::catalog::{Catalog, FragmentState, GenerationState};
use wsus_server::content::ContentStore;
use wsus_server::storage::Database;
use wsus_server::upstream::{
    CategoryFilter, ContentSelection, ResetReason, StageOutcome, SyncOutcome, UpstreamConfig,
    UpstreamError, UpstreamSync,
};

fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => thread::park(),
        }
    }
}

fn uid(n: u128) -> UpdateId {
    UpdateId(Uuid::from_u128(n))
}

fn rev(n: u128, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: uid(n),
        revision: Revision(r),
    }
}

const PRODUCT: u128 = 0x100;
const OTHER_PRODUCT: u128 = 0x101;
const CLASSIFICATION: u128 = 0x200;
const DETECTOID: u128 = 0x300;

struct Spec {
    id: u128,
    rev: u32,
    kind: &'static str,
    categories: Vec<u128>,
    prerequisites: Vec<u128>,
    files: Vec<(String, Vec<u8>)>,
    expired: bool,
}

impl Spec {
    fn software(id: u128, rev: u32) -> Self {
        Self {
            id,
            rev,
            kind: "Software",
            categories: vec![PRODUCT, CLASSIFICATION],
            prerequisites: vec![DETECTOID],
            files: Vec::new(),
            expired: false,
        }
    }

    fn config(id: u128, kind: &'static str) -> Self {
        Self {
            id,
            rev: 1,
            kind,
            categories: Vec::new(),
            prerequisites: Vec::new(),
            files: Vec::new(),
            expired: false,
        }
    }

    fn xml(&self) -> String {
        let mut rel = String::new();
        for c in &self.categories {
            rel += &format!(
                "<AtLeastOne IsCategory=\"true\"><UpdateIdentity UpdateID=\"{}\"/></AtLeastOne>",
                Uuid::from_u128(*c).hyphenated()
            );
        }
        for p in &self.prerequisites {
            rel += &format!(
                "<UpdateIdentity UpdateID=\"{}\"/>",
                Uuid::from_u128(*p).hyphenated()
            );
        }
        let mut files = String::new();
        for (name, data) in &self.files {
            files += &format!(
                "<File FileName=\"{name}\" Size=\"{}\" Digest=\"{}\" DigestAlgorithm=\"SHA1\"/>",
                data.len(),
                base64::engine::general_purpose::STANDARD.encode(Sha1::digest(data))
            );
        }
        format!(
            "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
             <UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"{}\"/>\
             <Properties UpdateType=\"{}\" PublicationState=\"{}\"/>\
             <Relationships><Prerequisites>{rel}</Prerequisites></Relationships>\
             <Files>{files}</Files></Update>",
            Uuid::from_u128(self.id).hyphenated(),
            self.rev,
            self.kind,
            if self.expired { "Expired" } else { "Published" }
        )
    }
}

struct Entry {
    seq: u64,
    identity: UpdateRevision,
    xml: String,
    config: bool,
    files: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct UpState {
    epoch: u32,
    seq: u64,
    entries: Vec<Entry>,
    ops: Vec<String>,
    update_data_calls: Vec<Vec<UpdateRevision>>,
    /// Answer GetUpdateData with a connection failure once this many calls
    /// have been served (counted from the start of the fake's life).
    fail_update_data_from: Option<usize>,
    cookie_gen: u8,
    faults: VecDeque<(String, ErrorCode)>,
    content_available: HashSet<String>,
    content: BTreeMap<String, Vec<u8>>,
    make_available_on_download_files: bool,
    catalog_only: bool,
}

struct Upstream {
    state: Mutex<UpState>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Upstream {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(UpState {
                epoch: 1,
                cookie_gen: 1,
                ..UpState::default()
            }),
        })
    }

    fn publish(&self, spec: Spec) {
        let mut st = self.state.lock().unwrap();
        st.seq += 1;
        let seq = st.seq;
        let config = matches!(spec.kind, "Category" | "Detectoid");
        for (_, data) in &spec.files {
            st.content.insert(hex(&Sha1::digest(data)), data.clone());
        }
        st.entries.push(Entry {
            seq,
            identity: rev(spec.id, spec.rev),
            xml: spec.xml(),
            config,
            files: spec.files.clone(),
        });
    }

    fn remove(&self, id: u128) {
        self.state
            .lock()
            .unwrap()
            .entries
            .retain(|e| e.identity.id != uid(id));
    }

    fn new_epoch(&self) {
        self.state.lock().unwrap().epoch += 1;
    }

    fn invalidate_cookies(&self) {
        self.state.lock().unwrap().cookie_gen += 1;
    }

    fn fail_update_data_from(&self, n: Option<usize>) {
        self.state.lock().unwrap().fail_update_data_from = n;
    }

    fn count(&self, op: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .ops
            .iter()
            .filter(|o| *o == op)
            .count()
    }

    fn requested_ids(&self) -> Vec<UpdateRevision> {
        self.state
            .lock()
            .unwrap()
            .update_data_calls
            .iter()
            .flatten()
            .copied()
            .collect()
    }

    fn respond<M: SoapMessage>(m: &M) -> MockStep {
        MockStep::Respond(HttpResponse::new(
            200,
            encode_response(SoapVersion::V11, m).body,
        ))
    }

    fn fault(code: ErrorCode, op: &str) -> MockStep {
        let f = SoapFault::application(SoapVersion::V11, code, "fault", None, None, Some(op));
        MockStep::Respond(HttpResponse::new(500, encode_fault(&f).body))
    }

    fn handle(&self, req: &HttpRequest) -> MockStep {
        if req.method == Method::Get {
            return self.content(req);
        }
        let limits = Limits::default();
        let env = Envelope::decode(&req.body, &limits).expect("envelope");
        let Body::Payload(p) = env.body else {
            panic!("fault request")
        };
        let op = p.name.local.clone();
        let mut st = self.state.lock().unwrap();
        st.ops.push(op.clone());
        if let Some(pos) = st.faults.iter().position(|(o, _)| *o == op) {
            let (_, code) = st.faults.remove(pos).unwrap();
            return Self::fault(code, &op);
        }
        let cookie_ok = |c: &Presence<Cookie>, st: &UpState| {
            c.value()
                .and_then(|c| c.encrypted_data.value())
                .is_some_and(|d| d == &vec![st.cookie_gen])
        };
        let expiry = wsus_protocol::soap::XsDateTime::new("2999-01-01T00:00:00Z").unwrap();
        match op.as_str() {
            "GetAuthConfig" => Self::respond(&GetAuthConfigResponse {
                result: Presence::Value(ServerAuthConfig {
                    last_change: expiry,
                    auth_info: Presence::Value(vec![AuthPlugInInfo {
                        plug_in_id: "DssTargeting".into(),
                        service_url: "DssAuthWebService/DssAuthWebService.asmx".into(),
                        parameter: Presence::Absent,
                    }]),
                    allowed_event_ids: Presence::Absent,
                }),
            }),
            "GetAuthorizationCookie" => Self::respond(&GetAuthorizationCookieResponse {
                result: Presence::Value(AuthorizationCookie {
                    plug_in_id: "DssTargeting".into(),
                    cookie_data: Presence::Value(vec![st.cookie_gen]),
                }),
            }),
            "GetCookie" => {
                let r = decode_payload::<GetCookie>(&p, &limits).unwrap();
                let auth_gen = r.auth_cookies.value().unwrap()[0]
                    .cookie_data
                    .value()
                    .unwrap()[0];
                if auth_gen != st.cookie_gen {
                    return Self::fault(ErrorCode::InvalidAuthorizationCookie, &op);
                }
                Self::respond(&GetCookieResponse {
                    result: Presence::Value(Cookie {
                        expiration: expiry,
                        encrypted_data: Presence::Value(vec![st.cookie_gen]),
                    }),
                })
            }
            "GetConfigData" => {
                let r = decode_payload::<GetConfigData>(&p, &limits).unwrap();
                if !cookie_ok(&r.cookie, &st) {
                    return Self::fault(ErrorCode::InvalidCookie, &op);
                }
                if let Some(a) = r.config_anchor.value()
                    && *a != format!("cfg:{}", st.epoch)
                {
                    return Self::fault(ErrorCode::ServerChanged, &op);
                }
                Self::respond(&GetConfigDataResponse {
                    result: Presence::Value(ServerSyncConfigData {
                        catalog_only_sync: st.catalog_only,
                        lazy_sync: false,
                        server_hosts_psf_files: false,
                        max_number_of_computer_ids_in_request: 1,
                        max_number_of_driver_sets_per_request: 1,
                        max_number_of_pnp_hardware_ids_in_request: 1,
                        max_number_of_updates_per_request: 100,
                        new_config_anchor: format!("cfg:{}", st.epoch).into(),
                        protocol_version: "1.20".into(),
                        language_update_list: Presence::Absent,
                        max_updates_per_request_in_get_update_decryption_data: 1,
                    }),
                })
            }
            "GetRevisionIdList" => {
                let r = decode_payload::<GetRevisionIdList>(&p, &limits).unwrap();
                if !cookie_ok(&r.cookie, &st) {
                    return Self::fault(ErrorCode::InvalidCookie, &op);
                }
                let filter = r.filter.value().unwrap();
                let after = match filter.anchor.value() {
                    None => 0,
                    Some(a) => {
                        let (e, s) = a.split_once(':').unwrap();
                        if e.parse::<u32>().unwrap() != st.epoch {
                            return Self::fault(ErrorCode::ServerChanged, &op);
                        }
                        s.parse::<u64>().unwrap()
                    }
                };
                let mut latest: BTreeMap<UpdateId, &Entry> = BTreeMap::new();
                for e in st.entries.iter().filter(|e| e.config == filter.get_config) {
                    let slot = latest.entry(e.identity.id).or_insert(e);
                    if e.identity.revision > slot.identity.revision {
                        *slot = e;
                    }
                }
                let revisions: Vec<UpdateRevision> = latest
                    .values()
                    .filter(|e| e.seq > after)
                    .map(|e| e.identity)
                    .collect();
                let max = st.entries.iter().map(|e| e.seq).max().unwrap_or(0);
                Self::respond(&GetRevisionIdListResponse {
                    result: Presence::Value(RevisionIdList {
                        anchor: format!("{}:{max}", st.epoch).into(),
                        new_revisions: Presence::Value(revisions),
                    }),
                })
            }
            "GetUpdateData" => {
                let r = decode_payload::<GetUpdateData>(&p, &limits).unwrap();
                if !cookie_ok(&r.cookie, &st) {
                    return Self::fault(ErrorCode::InvalidCookie, &op);
                }
                if st
                    .fail_update_data_from
                    .is_some_and(|n| st.update_data_calls.len() >= n)
                {
                    return MockStep::Fail(TransportError::connect("upstream went away"));
                }
                let ids = r.update_ids.value().unwrap().clone();
                st.update_data_calls.push(ids.clone());
                let mut updates = Vec::new();
                let mut urls = Vec::new();
                for id in &ids {
                    let e = st
                        .entries
                        .iter()
                        .find(|e| e.identity == *id)
                        .expect("known revision");
                    updates.push(ServerSyncUpdateData {
                        id: Presence::Value(*id),
                        xml_update_blob: e.xml.clone().into(),
                        file_digest_list: Presence::Absent,
                        xml_update_blob_compressed: Presence::Absent,
                    });
                    for (_, data) in &e.files {
                        let d = Sha1::digest(data);
                        urls.push(ServerSyncUrlData {
                            file_digest: Presence::Value(d.to_vec()),
                            mu_url: Presence::Absent,
                            uss_url: format!(
                                "http://upstream.test:8530/Content/{}/{}?sig=SECRETSIG",
                                hex(&d[19..]),
                                hex(&d)
                            )
                            .into(),
                            decryption_key: Presence::Absent,
                        });
                    }
                }
                Self::respond(&GetUpdateDataResponse {
                    result: Presence::Value(ServerUpdateData {
                        updates: Presence::Value(updates),
                        file_urls: Presence::Value(urls),
                    }),
                })
            }
            "DownloadFiles" => {
                if st.make_available_on_download_files {
                    let all: Vec<String> = st.content.keys().cloned().collect();
                    st.content_available.extend(all);
                }
                Self::respond(&DownloadFilesResponse {})
            }
            other => panic!("unexpected operation {other}"),
        }
    }

    fn content(&self, req: &HttpRequest) -> MockStep {
        let st = self.state.lock().unwrap();
        let url = req.url.expose();
        let name = url
            .split('?')
            .next()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        match st.content.get(&name) {
            Some(b) if st.content_available.contains(&name) => {
                MockStep::Respond(HttpResponse::new(200, b.clone()))
            }
            _ => MockStep::Respond(HttpResponse::new(404, Vec::new())),
        }
    }
}

type Orchestrator = UpstreamSync<MockTransport, ImmediateTimer>;

fn orchestrator(
    up: &Arc<Upstream>,
    catalog: &Catalog,
    batch: usize,
    endpoint: &str,
) -> Orchestrator {
    orchestrator_with(
        up,
        catalog,
        batch,
        UpstreamConfig::new("upstream", endpoint),
    )
}

fn orchestrator_with(
    up: &Arc<Upstream>,
    catalog: &Catalog,
    batch: usize,
    config: UpstreamConfig,
) -> Orchestrator {
    let u = Arc::clone(up);
    let transport = MockTransport::with_handler(move |r| u.handle(r));
    let mut c = WsusssConfig::new(
        "http://upstream.test:8530",
        "DOMAIN\\dss$",
        "6e8d0c3a-3f1e-4b66-9d3e-0a1b2c3d4e5f",
    );
    c.retry = RetryPolicy::none();
    c.update_batch_size = batch;
    c.busy_delay = std::time::Duration::ZERO;
    c.download_files_wait = std::time::Duration::ZERO;
    let client = WsusssClient::new(c, transport, ImmediateTimer);
    UpstreamSync::new(catalog.clone(), client, config).unwrap()
}

fn seed(up: &Upstream, software: u128) {
    up.publish(Spec::config(PRODUCT, "Category"));
    up.publish(Spec::config(OTHER_PRODUCT, "Category"));
    up.publish(Spec::config(CLASSIFICATION, "Category"));
    up.publish(Spec::config(DETECTOID, "Detectoid"));
    for n in 1..=software {
        up.publish(Spec::software(n, 1));
    }
}

fn catalog() -> Catalog {
    Catalog::new(Database::open_in_memory().unwrap())
}

fn present(c: &Catalog, o: &Orchestrator) -> BTreeSet<UpdateRevision> {
    let snap = c.snapshot(o.source()).unwrap().expect("active generation");
    snap.list(None, 10_000, false)
        .unwrap()
        .items
        .into_iter()
        .map(|f| f.identity)
        .collect()
}

#[test]
fn initial_sync_stages_validates_activates_and_commits_the_checkpoint() {
    let up = Upstream::new();
    seed(&up, 3);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    assert_eq!(o.committed_checkpoint().unwrap(), None);
    let report = block_on(o.run()).unwrap();
    let SyncOutcome::Activated {
        generation,
        fragments,
        checkpoint,
    } = report.outcome
    else {
        panic!("expected activation")
    };
    assert_eq!(fragments, 7);
    assert_eq!(report.stats.reset, Some(ResetReason::Initial));
    assert_eq!(report.stats.fetched, 7);
    assert_eq!(cat.active_generation(o.source()).unwrap(), Some(generation));
    assert_eq!(o.committed_checkpoint().unwrap(), Some(checkpoint.clone()));
    assert_eq!(checkpoint.update_anchor.as_deref(), Some("1:7"));
    assert_eq!(checkpoint.config_anchor.as_deref(), Some("cfg:1"));
    assert_eq!(present(&cat, &o).len(), 7);
    // Revision mappings resolve through local_id for every staged revision.
    let snap = cat.snapshot(o.source()).unwrap().unwrap();
    let rec = snap.get(rev(2, 1)).unwrap().unwrap();
    assert_eq!(cat.local_id(rev(2, 1)).unwrap(), rec.local);
    assert_eq!(cat.lookup_local(rec.local).unwrap(), Some(rev(2, 1)));
    assert_eq!(rec.kind, "Software");
}

#[test]
fn no_change_sync_fetches_nothing_and_keeps_the_generation() {
    let up = Upstream::new();
    seed(&up, 2);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    block_on(o.run()).unwrap();
    let active = cat.active_generation(o.source()).unwrap();
    let calls = up.requested_ids().len();
    let report = block_on(o.run()).unwrap();
    assert_eq!(report.outcome, SyncOutcome::NoChange);
    assert_eq!(up.requested_ids().len(), calls);
    assert_eq!(cat.active_generation(o.source()).unwrap(), active);
}

#[test]
fn new_revisions_fetch_only_the_delta_and_keep_old_revisions() {
    let up = Upstream::new();
    seed(&up, 3);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    block_on(o.run()).unwrap();
    let first = cat.active_generation(o.source()).unwrap().unwrap();
    let before = up.requested_ids().len();
    up.publish(Spec::software(1, 2));
    up.publish(Spec::software(4, 1));
    let report = block_on(o.run()).unwrap();
    assert_eq!(report.stats.reset, None);
    assert_eq!(report.stats.fetched, 2);
    assert_eq!(report.stats.carried, 7);
    let fetched: Vec<_> = up.requested_ids()[before..].to_vec();
    assert_eq!(fetched.len(), 2);
    assert!(fetched.contains(&rev(1, 2)) && fetched.contains(&rev(4, 1)));
    let now = present(&cat, &o);
    assert_eq!(now.len(), 9);
    assert!(now.contains(&rev(1, 1)) && now.contains(&rev(1, 2)));
    let second = cat.active_generation(o.source()).unwrap().unwrap();
    assert_ne!(first, second);
    assert_eq!(
        cat.generation(first).unwrap().state,
        GenerationState::Superseded
    );
}

#[test]
fn withdrawn_revisions_are_marked_and_not_offered() {
    let up = Upstream::new();
    seed(&up, 2);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    block_on(o.run()).unwrap();
    let mut gone = Spec::software(2, 2);
    gone.expired = true;
    up.publish(gone);
    let report = block_on(o.run()).unwrap();
    assert_eq!(report.stats.withdrawn, 1);
    let snap = cat.snapshot(o.source()).unwrap().unwrap();
    assert_eq!(
        snap.get(rev(2, 2)).unwrap().unwrap().state,
        FragmentState::Withdrawn
    );
    assert!(!present(&cat, &o).contains(&rev(2, 2)));
    assert!(present(&cat, &o).contains(&rev(2, 1)));
}

#[test]
fn upstream_server_change_resets_anchors_and_tombstones_vanished_revisions() {
    let up = Upstream::new();
    seed(&up, 3);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    block_on(o.run()).unwrap();
    up.new_epoch();
    up.remove(3);
    let report = block_on(o.run()).unwrap();
    assert_eq!(report.stats.reset, Some(ResetReason::ServerChanged));
    assert_eq!(
        report.stats.fetched, 6,
        "full resync of what the new server lists"
    );
    assert_eq!(report.stats.tombstoned, 1);
    let snap = cat.snapshot(o.source()).unwrap().unwrap();
    assert_eq!(
        snap.get(rev(3, 1)).unwrap().unwrap().state,
        FragmentState::Deleted
    );
    assert_eq!(
        o.committed_checkpoint()
            .unwrap()
            .unwrap()
            .update_anchor
            .as_deref(),
        Some("2:6")
    );

    // A configured endpoint change forces the same reset without any fault.
    let mut other = orchestrator(&up, &cat, 100, "up-b");
    let report = block_on(other.run()).unwrap();
    assert_eq!(report.stats.reset, Some(ResetReason::EndpointChanged));
}

#[test]
fn expired_authorization_is_renewed_during_a_sync() {
    let up = Upstream::new();
    seed(&up, 2);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    block_on(o.run()).unwrap();
    up.invalidate_cookies();
    up.publish(Spec::software(9, 1));
    let report = block_on(o.run()).unwrap();
    assert_eq!(report.stats.fetched, 1);
    assert_eq!(up.count("GetAuthorizationCookie"), 2);
    assert!(present(&cat, &o).contains(&rev(9, 1)));
}

fn staging_count(cat: &Catalog, o: &Orchestrator) -> usize {
    cat.database()
        .with_conn(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM generations WHERE source_id=?1 AND state='staging'",
                [o.source().0],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap() as usize
}

#[test]
fn interruption_during_fetch_resumes_without_refetching_staged_work() {
    let up = Upstream::new();
    seed(&up, 6);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 2, "up-a");
    // Two batches succeed, then the upstream disappears.
    up.fail_update_data_from(Some(2));
    let err = block_on(o.run()).unwrap_err();
    assert!(matches!(err, UpstreamError::Wsusss(_)), "{err}");
    assert!(
        cat.snapshot(o.source()).unwrap().is_none(),
        "nothing visible"
    );
    assert_eq!(o.committed_checkpoint().unwrap(), None);
    assert_eq!(staging_count(&cat, &o), 1);
    let staged_before: BTreeSet<_> = up.requested_ids().into_iter().collect();
    assert_eq!(staged_before.len(), 4);

    up.fail_update_data_from(None);
    // A fresh process: new orchestrator, new client, same database.
    let mut again = orchestrator(&up, &cat, 2, "up-a");
    let report = block_on(again.run()).unwrap();
    assert!(report.stats.resumed);
    assert_eq!(report.stats.fetched, 10 - 4);
    let all = up.requested_ids();
    let unique: BTreeSet<_> = all.iter().copied().collect();
    assert_eq!(all.len(), unique.len(), "no revision fetched twice");
    assert_eq!(present(&cat, &again).len(), 10);
    assert_eq!(staging_count(&cat, &again), 0);
}

#[test]
fn interruption_during_activation_resumes_with_no_refetch() {
    let up = Upstream::new();
    seed(&up, 3);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    let StageOutcome::Staged(staged) = block_on(o.stage()).unwrap() else {
        panic!("expected staging")
    };
    let calls = up.requested_ids().len();
    // The process dies before activation: nothing is visible and no
    // checkpoint was committed.
    drop(o);
    assert!(cat.snapshot(staged_source(&cat)).unwrap().is_none());

    let mut again = orchestrator(&up, &cat, 100, "up-a");
    assert_eq!(again.committed_checkpoint().unwrap(), None);
    let report = block_on(again.run()).unwrap();
    assert!(report.stats.resumed);
    assert_eq!(report.stats.fetched, 0);
    assert_eq!(up.requested_ids().len(), calls, "nothing fetched again");
    let SyncOutcome::Activated { generation, .. } = report.outcome else {
        panic!("expected activation")
    };
    assert_eq!(
        generation, staged.generation,
        "same generation, activated once"
    );
    assert_eq!(present(&cat, &again).len(), 7);
}

fn staged_source(cat: &Catalog) -> wsus_server::catalog::SourceId {
    cat.source_by_name("upstream").unwrap().unwrap().id
}

#[test]
fn repeated_resume_converges_with_each_revision_fetched_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    let up = Upstream::new();
    seed(&up, 8);
    let mut cutoff = 1;
    let mut attempts = 0;
    loop {
        // Reopen the database each time, as a restarted process would.
        let cat = Catalog::new(Database::open(&path).unwrap());
        let mut o = orchestrator(&up, &cat, 2, "up-a");
        let served = up.state.lock().unwrap().update_data_calls.len();
        up.fail_update_data_from(Some(served + cutoff));
        attempts += 1;
        match block_on(o.run()) {
            Ok(report) => {
                assert!(
                    attempts >= 3,
                    "expected several interruptions, got {attempts}"
                );
                assert!(matches!(report.outcome, SyncOutcome::Activated { .. }));
                assert_eq!(present(&cat, &o).len(), 12);
                break;
            }
            Err(UpstreamError::Wsusss(_)) => {
                assert!(cat.snapshot(o.source()).unwrap().is_none());
                cutoff = 1;
            }
            Err(e) => panic!("{e}"),
        }
        assert!(attempts < 20);
    }
    let all = up.requested_ids();
    let unique: BTreeSet<_> = all.iter().copied().collect();
    assert_eq!(all.len(), unique.len());
}

#[test]
fn a_stale_pending_checkpoint_is_not_resumed_and_is_kept_as_evidence() {
    let up = Upstream::new();
    seed(&up, 4);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 2, "up-a");
    up.fail_update_data_from(Some(1));
    block_on(o.run()).unwrap_err();
    let stale = cat
        .database()
        .with_conn(|c| {
            Ok(c.query_row(
                "SELECT id FROM generations WHERE state='staging'",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap();
    up.fail_update_data_from(None);
    up.publish(Spec::software(5, 1)); // the upstream moved on: new anchor
    let mut again = orchestrator(&up, &cat, 2, "up-a");
    let report = block_on(again.run()).unwrap();
    assert!(!report.stats.resumed);
    let info = cat
        .generation(wsus_server::catalog::GenerationId(stale))
        .unwrap();
    assert_eq!(info.state, GenerationState::Failed);
    assert!(info.evidence.unwrap().contains("stale"));
    assert_eq!(present(&cat, &again).len(), 4 + 5);
}

#[test]
fn rejected_validation_leaves_catalog_and_checkpoint_untouched() {
    let up = Upstream::new();
    seed(&up, 2);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    block_on(o.run()).unwrap();
    let good = o.committed_checkpoint().unwrap();
    // The new update needs a detectoid that was never published.
    let mut broken = Spec::software(7, 1);
    broken.prerequisites = vec![0xdead];
    up.publish(broken);
    let err = block_on(o.run()).unwrap_err();
    let UpstreamError::Rejected { generation, report } = err else {
        panic!("expected rejection")
    };
    assert_eq!(report.issues.len(), 1);
    assert_eq!(
        cat.generation(generation).unwrap().state,
        GenerationState::Failed
    );
    assert_eq!(
        o.committed_checkpoint().unwrap(),
        good,
        "checkpoint not advanced"
    );
    assert_eq!(present(&cat, &o).len(), 6);
}

#[test]
fn category_filter_excludes_but_pulls_in_required_prerequisites() {
    let up = Upstream::new();
    seed(&up, 0);
    let mut keep = Spec::software(1, 1);
    keep.prerequisites = vec![DETECTOID, 2];
    up.publish(keep);
    let mut needed = Spec::software(2, 1);
    needed.categories = vec![OTHER_PRODUCT, CLASSIFICATION];
    up.publish(needed);
    let mut unrelated = Spec::software(3, 1);
    unrelated.categories = vec![OTHER_PRODUCT, CLASSIFICATION];
    up.publish(unrelated);
    let cat = catalog();
    let mut config = UpstreamConfig::new("upstream", "up-a");
    config.filter = CategoryFilter {
        products: vec![uid(PRODUCT)],
        classifications: vec![uid(CLASSIFICATION)],
    };
    let mut o = orchestrator_with(&up, &cat, 100, config);
    let report = block_on(o.run()).unwrap();
    assert_eq!(report.stats.excluded_by_filter, 2);
    assert_eq!(report.stats.pulled_by_dependency, 1);
    let now = present(&cat, &o);
    assert!(now.contains(&rev(1, 1)) && now.contains(&rev(2, 1)));
    assert!(!now.contains(&rev(3, 1)));

    // Changing the filter forces a full resynchronization.
    let mut wider = UpstreamConfig::new("upstream", "up-a");
    wider.filter = CategoryFilter::default();
    let mut o2 = orchestrator_with(&up, &cat, 100, wider);
    let report = block_on(o2.run()).unwrap();
    assert_eq!(report.stats.reset, Some(ResetReason::FilterChanged));
    assert!(present(&cat, &o2).contains(&rev(3, 1)));
}

#[test]
fn unusable_metadata_fails_the_sync_without_activation() {
    let up = Upstream::new();
    seed(&up, 1);
    {
        let mut st = up.state.lock().unwrap();
        st.entries.last_mut().unwrap().xml = "<Update><nope/></Update>".into();
    }
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    let err = block_on(o.run()).unwrap_err();
    assert!(matches!(err, UpstreamError::Metadata { .. }), "{err}");
    assert!(cat.snapshot(o.source()).unwrap().is_none());
}

#[test]
fn discovery_lists_categories_without_staging_anything() {
    let up = Upstream::new();
    seed(&up, 1);
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    let found = block_on(o.discover_categories()).unwrap();
    assert_eq!(found.categories.len(), 3);
    assert_eq!(found.detectoids, 1);
    assert_eq!(staging_count(&cat, &o), 0);
    assert!(cat.snapshot(o.source()).unwrap().is_none());
}

#[test]
fn file_acquisition_is_reported_separately_from_metadata_success() {
    let up = Upstream::new();
    seed(&up, 0);
    let mut a = Spec::software(1, 1);
    a.files = vec![("a.cab".into(), vec![1u8; 3000])];
    let mut b = Spec::software(2, 1);
    b.files = vec![("b.cab".into(), vec![2u8; 4000])];
    up.publish(a);
    up.publish(b);
    {
        let mut st = up.state.lock().unwrap();
        // a.cab is on the upstream; b.cab is not until DownloadFiles runs.
        let ha = hex(&Sha1::digest(vec![1u8; 3000]));
        st.content_available.insert(ha);
    }
    let cat = catalog();
    let mut o = orchestrator(&up, &cat, 100, "up-a");
    let sync = block_on(o.run()).unwrap();
    assert!(matches!(sync.outcome, SyncOutcome::Activated { .. }));

    let dir = tempfile::tempdir().unwrap();
    let store = ContentStore::open(cat.database().clone(), &dir.path().join("store")).unwrap();
    let downloader = Downloader::open(dir.path().join("dl"), DownloadLimits::default()).unwrap();
    let options = DownloadOptions {
        retry: RetryPolicy::none(),
        ..DownloadOptions::default()
    };

    // The upstream cannot supply b.cab: the file fails, metadata stays active.
    let report =
        block_on(o.acquire_content(&store, &downloader, &ContentSelection::All, &options)).unwrap();
    assert_eq!(report.acquired, 1);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].file_name, "b.cab");
    assert!(
        !report.failed[0].reason.contains("SECRETSIG"),
        "signed URL leaked: {}",
        report.failed[0].reason
    );
    assert!(cat.snapshot(o.source()).unwrap().is_some());
    assert_eq!(
        up.count("DownloadFiles"),
        1,
        "asked the upstream to fetch the file"
    );

    // After the upstream has fetched it, the next call completes the set.
    up.state.lock().unwrap().make_available_on_download_files = true;
    let report = block_on(o.acquire_content(
        &store,
        &downloader,
        &ContentSelection::Updates(BTreeSet::from([uid(2)])),
        &options,
    ))
    .unwrap();
    assert_eq!(report.acquired, 1);
    assert!(report.failed.is_empty());
    let report =
        block_on(o.acquire_content(&store, &downloader, &ContentSelection::All, &options)).unwrap();
    assert_eq!(report.already_present, 2);
    assert_eq!(report.acquired, 0);

    // Catalog-only upstreams host no content.
    up.state.lock().unwrap().catalog_only = true;
    let mut fresh = orchestrator(&up, &cat, 100, "up-a");
    let report =
        block_on(fresh.acquire_content(&store, &downloader, &ContentSelection::All, &options))
            .unwrap();
    assert!(report.catalog_only);
}
