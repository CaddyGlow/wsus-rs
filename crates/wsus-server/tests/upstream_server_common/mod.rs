#![allow(dead_code)]
//! Shared harness for the MS-WSUSSS upstream server tests.
//!
//! The upstream server is exercised in process, through the neutral handler, either with raw
//! SOAP calls or through this project's own downstream client (`WsusssClient`) over a mock
//! transport that forwards to the handler. That is a self-consistency check only: it proves
//! the two halves of this project agree with each other, not that a real downstream WSUS
//! would accept the server.
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use base64::Engine as _;
use sha1::{Digest as _, Sha1};
use uuid::Uuid;
use wsus_client::transport::{
    HttpRequest, HttpResponse, ImmediateTimer, Method, RetryPolicy,
    mock::{MockStep, MockTransport},
};
use wsus_client::wsusss::{WsusssClient, WsusssConfig};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest, Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{
    Envelope, ErrorCode, Limits, Presence, SoapFault, SoapRequest, SoapVersion, decode_response,
    encode_request,
};
use wsus_protocol::wsusss::*;
use wsus_server::catalog::*;
use wsus_server::content::{ContentDescriptor, ContentStore};
use wsus_server::endpoints::wsusss::{UpstreamServer, UpstreamServerConfig, UpstreamServices};
use wsus_server::endpoints::{HttpRequestParts, HttpResponseParts};
use wsus_server::session::{SessionConfig, SessionManager};
use wsus_server::storage::{Database, now_unix};

pub const SYNC_PATH: &str = "/ServerSyncWebService/ServerSyncWebService.asmx";
pub const AUTH_PATH: &str = "/DssAuthWebService/DssAuthWebService.asmx";
pub const ACCOUNT: &str = "DOMAIN\\dss1$";
pub const ACCOUNT_GUID: &str = "6e8d0c3a-3f1e-4b66-9d3e-0a1b2c3d4e5f";

pub const PRODUCT: u128 = 0x100;
pub const CLASSIFICATION: u128 = 0x200;
pub const DETECTOID: u128 = 0x300;

pub fn block_on<F: Future>(future: F) -> F::Output {
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

pub fn uid(n: u128) -> UpdateId {
    UpdateId(Uuid::from_u128(n))
}

pub fn rev(n: u128, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: uid(n),
        revision: Revision(r),
    }
}

/// A whole update document as the downstream importer stores it.
pub struct Doc {
    pub id: u128,
    pub rev: u32,
    pub kind: &'static str,
    pub categories: Vec<u128>,
    pub prerequisites: Vec<u128>,
    pub files: Vec<(String, Vec<u8>)>,
    pub padding: usize,
    pub expired: bool,
}

impl Doc {
    pub fn software(id: u128, rev: u32) -> Self {
        Self {
            id,
            rev,
            kind: "Software",
            categories: vec![PRODUCT, CLASSIFICATION],
            prerequisites: vec![DETECTOID],
            files: Vec::new(),
            padding: 0,
            expired: false,
        }
    }

    /// A software update with no category or prerequisite relationships, so a generation can
    /// hold it without the standard categories.
    pub fn bare(id: u128, rev: u32) -> Self {
        Self {
            categories: Vec::new(),
            prerequisites: Vec::new(),
            ..Self::software(id, rev)
        }
    }

    pub fn config(id: u128, kind: &'static str) -> Self {
        Self {
            id,
            rev: 1,
            kind,
            categories: Vec::new(),
            prerequisites: Vec::new(),
            files: Vec::new(),
            padding: 0,
            expired: false,
        }
    }

    pub fn with_file(mut self, name: &str, data: &[u8]) -> Self {
        self.files.push((name.into(), data.to_vec()));
        self
    }

    pub fn padded(mut self, bytes: usize) -> Self {
        self.padding = bytes;
        self
    }

    pub fn xml(&self) -> String {
        let g = |n: u128| Uuid::from_u128(n).hyphenated();
        let mut rel = String::new();
        for c in &self.categories {
            rel += &format!(
                "<AtLeastOne IsCategory=\"true\"><UpdateIdentity UpdateID=\"{}\"/></AtLeastOne>",
                g(*c)
            );
        }
        for p in &self.prerequisites {
            rel += &format!("<UpdateIdentity UpdateID=\"{}\"/>", g(*p));
        }
        let mut files = String::new();
        for (name, data) in &self.files {
            files += &format!(
                "<File FileName=\"{name}\" Size=\"{}\" Digest=\"{}\" DigestAlgorithm=\"SHA1\"/>",
                data.len(),
                base64::engine::general_purpose::STANDARD.encode(Sha1::digest(data))
            );
        }
        let pad = if self.padding > 0 {
            format!("<Padding>{}</Padding>", "x".repeat(self.padding))
        } else {
            String::new()
        };
        format!(
            "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
             <UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"{}\"/>\
             <Properties UpdateType=\"{}\" PublicationState=\"{}\"/>\
             <Relationships><Prerequisites>{rel}</Prerequisites></Relationships>\
             <Files>{files}</Files>{pad}</Update>",
            g(self.id),
            self.rev,
            self.kind,
            if self.expired { "Expired" } else { "Published" }
        )
    }

    /// The catalog record, with relationships and file descriptors as the importer stores.
    pub fn record(&self) -> FragmentImport {
        let mut f = FragmentImport::new(rev(self.id, self.rev), self.kind, self.xml().as_bytes());
        if self.expired {
            f.state = FragmentState::Withdrawn;
        }
        for c in &self.categories {
            f.relationships.push(RelationshipImport {
                kind: RelationshipKind::Category,
                target: uid(*c),
                revision: None,
            });
        }
        for p in &self.prerequisites {
            f.relationships.push(RelationshipImport {
                kind: RelationshipKind::Prerequisite,
                target: uid(*p),
                revision: None,
            });
        }
        for (name, data) in &self.files {
            f.files.push(FileDescriptor {
                file_name: name.clone(),
                size: data.len() as u64,
                digests: vec![
                    FileDigest {
                        algorithm: DigestAlgorithm::Sha1,
                        bytes: Sha1::digest(data).to_vec(),
                    },
                    FileDigest {
                        algorithm: DigestAlgorithm::Sha256,
                        bytes: sha2::Sha256::digest(data).to_vec(),
                    },
                ],
            });
        }
        f
    }
}

pub fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub db_path: PathBuf,
    pub catalog: Catalog,
    pub content: ContentStore,
    pub sessions: Arc<SessionManager>,
    pub server: UpstreamServer,
    pub clock: Arc<AtomicI64>,
    pub source: SourceId,
}

pub fn config() -> UpstreamServerConfig {
    UpstreamServerConfig {
        source_name: "serving".into(),
        content_base_url: Some("http://uss.test:80".into()),
        ..UpstreamServerConfig::default()
    }
}

pub fn fixture() -> Fixture {
    fixture_with(config())
}

pub fn fixture_with(config: UpstreamServerConfig) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite");
    open_at(dir, db_path, config, Arc::new(AtomicI64::new(now_unix())))
}

fn open_at(
    dir: tempfile::TempDir,
    db_path: PathBuf,
    config: UpstreamServerConfig,
    clock: Arc<AtomicI64>,
) -> Fixture {
    let db = Database::open(&db_path).unwrap();
    let c = clock.clone();
    let sessions = Arc::new(
        SessionManager::open_with_clock(
            db.clone(),
            SessionConfig::default(),
            "uss-tests",
            Arc::new(move || c.load(Ordering::SeqCst)),
        )
        .unwrap(),
    );
    let catalog = Catalog::new(db.clone());
    let source = match catalog.source_by_name("serving").unwrap() {
        Some(s) => s.id,
        None => catalog
            .add_source("serving", SourceKind::Import, "")
            .unwrap(),
    };
    let content = ContentStore::open(db, &dir.path().join("content")).unwrap();
    let server = UpstreamServer::open(
        UpstreamServices {
            catalog: catalog.clone(),
            content: content.clone(),
            sessions: sessions.clone(),
        },
        config,
    )
    .unwrap();
    Fixture {
        dir,
        db_path,
        catalog,
        content,
        sessions,
        server,
        clock,
        source,
    }
}

impl Fixture {
    /// Close everything and reopen over the same database file and content directory: a
    /// process restart. The clock keeps running.
    pub fn restart(self) -> Fixture {
        self.restart_with(config())
    }

    pub fn restart_with(self, cfg: UpstreamServerConfig) -> Fixture {
        let Fixture {
            dir,
            db_path,
            clock,
            catalog,
            content,
            sessions,
            server,
            ..
        } = self;
        drop((catalog, content, sessions, server));
        open_at(dir, db_path, cfg, clock)
    }

    pub fn advance(&self, secs: i64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    /// Activate a new generation holding exactly `docs`.
    pub fn publish(&self, docs: &[Doc]) -> GenerationId {
        let records: Vec<FragmentImport> = docs.iter().map(Doc::record).collect();
        self.activate(&records)
    }

    pub fn activate(&self, records: &[FragmentImport]) -> GenerationId {
        let g = self.catalog.begin_generation(self.source, None).unwrap();
        self.catalog.import_fragments(g, records).unwrap();
        match self.catalog.activate(g).unwrap() {
            ActivateOutcome::Activated { .. } => g,
            other => panic!("activation rejected: {other:?}"),
        }
    }

    /// New generation = everything of the active one plus `docs` (replacing equal
    /// identities), as a catalog refresh would produce.
    pub fn refresh(&self, docs: &[Doc]) -> GenerationId {
        let mut records: Vec<FragmentImport> = Vec::new();
        if let Some(snap) = self.catalog.snapshot(self.source).unwrap() {
            let mut after = None;
            loop {
                let page = snap.list(after, 500, true).unwrap();
                for r in page.items {
                    if docs.iter().any(|d| rev(d.id, d.rev) == r.identity) {
                        continue;
                    }
                    let mut f = FragmentImport::new(r.identity, &r.kind, &r.core_xml);
                    f.state = r.state;
                    f.relationships = snap
                        .relationships(r.local)
                        .unwrap()
                        .into_iter()
                        .map(|x| RelationshipImport {
                            kind: x.kind,
                            target: x.target,
                            revision: x.revision,
                        })
                        .collect();
                    f.files = snap.files(r.local).unwrap();
                    records.push(f);
                }
                match page.next {
                    Some(n) => after = Some(n),
                    None => break,
                }
            }
        }
        records.extend(docs.iter().map(Doc::record));
        self.activate(&records)
    }

    /// Standard categories plus `n` software updates.
    pub fn seed(&self, n: u128) {
        let mut docs = vec![
            Doc::config(PRODUCT, "Category"),
            Doc::config(CLASSIFICATION, "Category"),
            Doc::config(DETECTOID, "Detectoid"),
        ];
        docs.extend((1..=n).map(|i| Doc::software(i, 1)));
        self.publish(&docs);
    }

    pub fn put_content(&self, name: &str, data: &[u8]) {
        self.content
            .put_bytes(
                &ContentDescriptor {
                    file_name: name.into(),
                    size: data.len() as u64,
                    digests: vec![
                        FileDigest {
                            algorithm: DigestAlgorithm::Sha1,
                            bytes: Sha1::digest(data).to_vec(),
                        },
                        FileDigest {
                            algorithm: DigestAlgorithm::Sha256,
                            bytes: sha2::Sha256::digest(data).to_vec(),
                        },
                    ],
                },
                data,
            )
            .unwrap();
    }

    // ---- raw protocol ----

    pub fn post(&self, path: &str, enc: wsus_protocol::soap::EncodedMessage) -> HttpResponseParts {
        let mut r = HttpRequestParts::new("POST", path)
            .with_header("Content-Type", &enc.content_type)
            .with_header("Host", "uss.test:8530")
            .with_body(enc.body);
        if let Some(a) = &enc.soap_action {
            r = r.with_header("SOAPAction", a);
        }
        self.server.handle(r)
    }

    pub fn call<R: SoapRequest>(&self, req: &R) -> Result<R::Response, (u16, Box<SoapFault>)> {
        let path = if R::NAMESPACE == DSS_AUTH_NS {
            AUTH_PATH
        } else {
            SYNC_PATH
        };
        let resp = self.post(path, encode_request(SoapVersion::V11, req));
        let status = resp.status;
        let body = resp.into_bytes().unwrap();
        match decode_response::<R::Response>(&body, &Limits::default()) {
            Ok(r) => {
                assert_eq!(status, 200);
                Ok(r)
            }
            Err(wsus_protocol::ProtocolError::Fault(f)) => Err((status, f)),
            Err(e) => panic!("undecodable response ({status}): {e}"),
        }
    }

    pub fn fault<R: SoapRequest>(&self, req: &R) -> (ErrorCode, Option<String>) {
        let (status, f) = self.call(req).err().expect("expected a fault");
        assert_eq!(status, 500, "SOAP 1.1 faults are HTTP 500");
        let d = f.wsus.expect("WSUS fault detail");
        (d.error_code, d.message)
    }

    pub fn fault_code<R: SoapRequest>(&self, req: &R) -> ErrorCode {
        self.fault(req).0
    }

    pub fn auth_cookie(&self, name: &str, guid: &str) -> AuthorizationCookie {
        self.call(&GetAuthorizationCookie {
            account_name: Presence::Value(name.into()),
            account_guid: Presence::Value(guid.into()),
            program_keys: Presence::Absent,
        })
        .unwrap()
        .result
        .into_value()
        .unwrap()
    }

    pub fn get_cookie_req(&self, auth: AuthorizationCookie, version: &str) -> GetCookie {
        GetCookie {
            auth_cookies: Presence::Value(vec![auth]),
            old_cookie: Presence::Absent,
            protocol_version: Presence::Value(version.into()),
        }
    }

    /// Full handshake as the default account.
    pub fn cookie(&self) -> Cookie {
        self.cookie_for(ACCOUNT, ACCOUNT_GUID)
    }

    pub fn cookie_for(&self, name: &str, guid: &str) -> Cookie {
        let auth = self.auth_cookie(name, guid);
        self.call(&self.get_cookie_req(auth, "1.20"))
            .unwrap()
            .result
            .into_value()
            .unwrap()
    }

    pub fn revision_list(
        &self,
        cookie: &Cookie,
        anchor: Option<&str>,
        get_config: bool,
    ) -> RevisionIdList {
        self.call(&revision_req(cookie, anchor, get_config))
            .unwrap()
            .result
            .into_value()
            .unwrap()
    }

    pub fn update_data(&self, cookie: &Cookie, ids: &[UpdateRevision]) -> ServerUpdateData {
        self.call(&GetUpdateData {
            cookie: Presence::Value(cookie.clone()),
            update_ids: Presence::Value(ids.to_vec()),
        })
        .unwrap()
        .result
        .into_value()
        .unwrap()
    }

    pub fn config_data(&self, cookie: &Cookie, anchor: Option<&str>) -> ServerSyncConfigData {
        self.call(&GetConfigData {
            cookie: Presence::Value(cookie.clone()),
            config_anchor: anchor.map_or(Presence::Absent, |a| Presence::Value(a.into())),
        })
        .unwrap()
        .result
        .into_value()
        .unwrap()
    }
}

pub fn revision_req(cookie: &Cookie, anchor: Option<&str>, get_config: bool) -> GetRevisionIdList {
    GetRevisionIdList {
        cookie: Presence::Value(cookie.clone()),
        filter: Presence::Value(ServerSyncFilter {
            dss_protocol_version: Presence::Absent,
            anchor: anchor.map_or(Presence::Absent, |a| Presence::Value(a.into())),
            get_config,
            get63_language_only: Presence::Absent,
            categories: Presence::Absent,
            classifications: Presence::Absent,
            languages: Presence::Absent,
        }),
    }
}

pub fn ids(list: &RevisionIdList) -> Vec<UpdateRevision> {
    list.new_revisions.value().cloned().unwrap_or_default()
}

/// Forward client requests to the handler, in process.
pub fn bridge(server: UpstreamServer) -> MockTransport {
    MockTransport::with_handler(move |r: &HttpRequest| {
        let url = r.url.expose().to_owned();
        let after = url.split_once("://").map_or(url.as_str(), |x| x.1);
        let (authority, rest) = after.split_once('/').unwrap_or((after, ""));
        let rest = format!("/{rest}");
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
            None => (rest.clone(), None),
        };
        let mut parts = HttpRequestParts::new(
            match r.method {
                Method::Get => "GET",
                Method::Post => "POST",
            },
            &path,
        )
        .with_header("Host", authority)
        .with_body(r.body.clone());
        parts.query = query;
        for (k, v) in r.headers.iter() {
            parts = parts.with_header(k, v);
        }
        let resp = server.handle(parts);
        let status = resp.status;
        let headers = resp.headers.clone();
        let body = resp.into_bytes().unwrap();
        let mut out = HttpResponse::new(status, body);
        for (k, v) in headers {
            out.headers.append(k, v);
        }
        MockStep::Respond(out)
    })
}

pub fn client_config(account: &str, guid: &str) -> WsusssConfig {
    let mut c = WsusssConfig::new("http://uss.test:8530", account, guid);
    c.retry = RetryPolicy::none();
    c.busy_delay = std::time::Duration::ZERO;
    c.download_files_wait = std::time::Duration::ZERO;
    c.content_base_url = Some("http://uss.test:80".into());
    c
}

pub type Client = WsusssClient<MockTransport, ImmediateTimer>;

pub fn client(server: &UpstreamServer) -> Client {
    WsusssClient::new(
        client_config(ACCOUNT, ACCOUNT_GUID),
        bridge(server.clone()),
        ImmediateTimer,
    )
}

pub fn path_of(p: &Path) -> String {
    p.display().to_string()
}

pub fn fault_envelope(resp: HttpResponseParts) -> (u16, SoapFault) {
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
