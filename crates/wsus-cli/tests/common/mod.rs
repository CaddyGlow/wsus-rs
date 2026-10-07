#![allow(dead_code)]
//! Shared harness: a synthetic bounded update, a server assembled through the
//! CLI's own `server_cmd::open`, and an in-process `Transport` bridge.
//!
//! EVIDENCE STATUS: everything built on this harness proves only that this
//! workspace's client and this workspace's server agree with each other. It is
//! not WSUS compatibility evidence and not Windows Update client evidence.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};
use uuid::Uuid;
use wsus_cli::{
    admin::{self, Admin},
    config::Config,
    server_cmd::{self, Opened},
};
use wsus_client::{
    session::Clock,
    transport::{
        BodySink, Headers, HttpRequest, HttpResponse, ResponseHead, Transport, TransportError,
    },
};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest, Revision, UpdateId, UpdateRevision};
use wsus_server::{
    catalog::{ActivateOutcome, FileDescriptor, FragmentImport},
    content::ContentDescriptor,
    endpoints::{HttpRequestParts, WsusServer},
};

pub const ORIGIN: &str = "http://wsus.test:8530";

/// Clock shared by the client and the server so expiry is deterministic.
#[derive(Clone)]
pub struct SharedClock(pub Arc<AtomicI64>);

impl SharedClock {
    pub fn new() -> Self {
        Self(Arc::new(AtomicI64::new(wsus_server::storage::now_unix())))
    }
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
    pub fn server_clock(&self) -> wsus_server::session::Clock {
        let c = self.0.clone();
        Arc::new(move || c.load(Ordering::SeqCst))
    }
}

impl Clock for SharedClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

pub fn update_id(n: u128) -> UpdateId {
    UpdateId(Uuid::from_u128(n))
}

pub fn revision(n: u128) -> UpdateRevision {
    UpdateRevision {
        id: update_id(n),
        revision: Revision(1),
    }
}

/// Imports one bounded synthetic update with a payload into the catalog and
/// the content store, and activates the generation.
pub fn seed_update(
    admin: &Admin,
    source: &str,
    n: u128,
    file_name: &str,
    data: &[u8],
) -> UpdateRevision {
    let rev = revision(n);
    let sha1 = Sha1::digest(data).to_vec();
    let sha256 = Sha256::digest(data).to_vec();
    let core = format!(
        "<Update><UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>\
         <Properties UpdateType=\"Software\"/><Relationships/></Update>",
        rev.id
    );
    let extended = format!(
        "<Update><Properties/><Files><File FileName=\"{file_name}\" Size=\"{}\" Digest=\"{}\" \
         DigestAlgorithm=\"SHA1\"><AdditionalDigest Algorithm=\"SHA256\">{}</AdditionalDigest>\
         </File></Files></Update>",
        data.len(),
        STANDARD.encode(&sha1),
        STANDARD.encode(&sha256),
    );
    let digests = vec![
        FileDigest {
            algorithm: DigestAlgorithm::Sha1,
            bytes: sha1,
        },
        FileDigest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: sha256,
        },
    ];
    let mut frag = FragmentImport::new(rev, "Software", core.as_bytes());
    frag.extended_xml = Some(extended.into_bytes());
    frag.files.push(FileDescriptor {
        file_name: file_name.to_owned(),
        size: data.len() as u64,
        digests: digests.clone(),
    });
    admin
        .content
        .put_bytes(
            &ContentDescriptor {
                file_name: file_name.to_owned(),
                size: data.len() as u64,
                digests,
            },
            data,
        )
        .expect("store payload");
    let source = admin
        .catalog
        .source_by_name(source)
        .unwrap()
        .expect("source exists");
    let g = admin.catalog.begin_generation(source.id, None).unwrap();
    admin.catalog.import_fragments(g, &[frag]).unwrap();
    match admin.catalog.activate(g).unwrap() {
        ActivateOutcome::Activated { .. } => {}
        other => panic!("activation rejected: {other:?}"),
    }
    rev
}

/// Imports a chain of `len` software updates in one generation: update `k` has update `k - 1`
/// as its only prerequisite (a bare `UpdateIdentity` clause in its Core fragment and the
/// matching relationship row), so every update but the last is non-leaf.
pub fn seed_chain(admin: &Admin, source: &str, first: u128, len: u128) -> Vec<UpdateRevision> {
    use wsus_server::catalog::{RelationshipImport, RelationshipKind};
    let mut frags = Vec::new();
    let mut revs = Vec::new();
    for k in 0..len {
        let rev = revision(first + k);
        let rel = if k == 0 {
            String::new()
        } else {
            format!(
                "<Relationships><Prerequisites><UpdateIdentity UpdateID=\"{}\"/>\
                 </Prerequisites></Relationships>",
                revision(first + k - 1).id
            )
        };
        let core = format!(
            "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>\
             <Properties UpdateType=\"Software\"/>{rel}",
            rev.id
        );
        let mut f = FragmentImport::new(rev, "Software", core.as_bytes());
        if k > 0 {
            f.relationships.push(RelationshipImport {
                kind: RelationshipKind::Prerequisite,
                target: revision(first + k - 1).id,
                revision: None,
            });
        }
        frags.push(f);
        revs.push(rev);
    }
    let source = admin
        .catalog
        .source_by_name(source)
        .unwrap()
        .expect("source");
    let g = admin.catalog.begin_generation(source.id, None).unwrap();
    admin.catalog.import_fragments(g, &frags).unwrap();
    match admin.catalog.activate(g).unwrap() {
        ActivateOutcome::Activated { .. } => {}
        other => panic!("activation rejected: {other:?}"),
    }
    revs
}

/// Fault injection and request log shared by clones of a [`Bridge`].
#[derive(Default)]
pub struct BridgeState {
    /// Interrupt the next content GET after this many body bytes.
    pub interrupt_next_content_after: Option<usize>,
    /// `(method, path, range header)` of every request.
    pub log: Vec<(String, String, Option<String>)>,
}

/// In-process `Transport` that calls `WsusServer::handle` directly. The server
/// can be swapped to simulate a restart.
#[derive(Clone)]
pub struct Bridge {
    pub server: Arc<Mutex<WsusServer>>,
    pub state: Arc<Mutex<BridgeState>>,
}

impl Bridge {
    pub fn new(server: WsusServer) -> Self {
        Self {
            server: Arc::new(Mutex::new(server)),
            state: Arc::default(),
        }
    }

    pub fn swap_server(&self, server: WsusServer) {
        *self.server.lock().unwrap() = server;
    }

    pub fn content_gets(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|(m, p, _)| m == "GET" && p.starts_with("/Content/"))
            .count()
    }

    pub fn ranges(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .log
            .iter()
            .filter_map(|(_, _, r)| r.clone())
            .collect()
    }

    fn parts(&self, request: &HttpRequest) -> HttpRequestParts {
        let url = request.url.expose();
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let slash = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..slash];
        let path_query = if slash == rest.len() {
            "/"
        } else {
            &rest[slash..]
        };
        let (path, query) = match path_query.split_once('?') {
            Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
            None => (path_query.to_owned(), None),
        };
        let mut parts = HttpRequestParts::new(request.method.as_str(), &path);
        parts.query = query;
        parts.headers = request
            .headers
            .iter()
            .map(|(n, v)| (n.to_owned(), v.to_owned()))
            .collect();
        parts.headers.push(("Host".into(), authority.to_owned()));
        parts.body = request.body.clone();
        self.state.lock().unwrap().log.push((
            request.method.as_str().to_owned(),
            path,
            request.headers.get("Range").map(str::to_owned),
        ));
        parts
    }

    async fn call(
        &self,
        request: &HttpRequest,
    ) -> Result<wsus_server::endpoints::HttpResponseParts, TransportError> {
        let parts = self.parts(request);
        let server = self.server.lock().unwrap().clone();
        tokio::task::spawn_blocking(move || server.handle(parts))
            .await
            .map_err(|_| TransportError::io("server task failed"))
    }
}

fn headers_of(resp: &wsus_server::endpoints::HttpResponseParts) -> Headers {
    let mut h = Headers::new();
    for (n, v) in &resp.headers {
        h.append(n.clone(), v.clone());
    }
    h
}

impl Transport for Bridge {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let resp = self.call(&request).await?;
        let status = resp.status;
        let headers = headers_of(&resp);
        let body = resp
            .into_bytes()
            .map_err(|_| TransportError::io("body read failed"))?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    async fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> Result<ResponseHead, TransportError> {
        let is_content = request.url.expose().contains("/Content/");
        let resp = self.call(&request).await?;
        let head = ResponseHead {
            status: resp.status,
            headers: headers_of(&resp),
        };
        let body = resp
            .into_bytes()
            .map_err(|_| TransportError::io("body read failed"))?;
        if sink.start(&head).map_err(|_| TransportError::aborted())? {
            let cut = if is_content && (head.status == 200 || head.status == 206) {
                self.state
                    .lock()
                    .unwrap()
                    .interrupt_next_content_after
                    .take()
            } else {
                None
            };
            match cut {
                Some(n) => {
                    for chunk in body[..n.min(body.len())].chunks(16 * 1024) {
                        sink.write(chunk).map_err(|_| TransportError::aborted())?;
                    }
                    return Err(TransportError::io("connection reset by peer"));
                }
                None => {
                    for chunk in body.chunks(64 * 1024) {
                        sink.write(chunk).map_err(|_| TransportError::aborted())?;
                    }
                }
            }
        }
        Ok(head)
    }
}

/// One temporary deployment: configuration, server, bridge and client paths.
pub struct Deployment {
    pub dir: tempfile::TempDir,
    pub config: Config,
    pub clock: SharedClock,
    pub opened: Opened,
    pub bridge: Bridge,
}

impl Deployment {
    pub fn new() -> Self {
        Self::with_delivery(wsus_cli::config::SyncDeliverySetting::default())
    }

    /// A deployment whose server uses the given `SyncUpdates` delivery mode.
    pub fn with_delivery(mode: wsus_cli::config::SyncDeliverySetting) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::defaults_in(dir.path());
        config.server.sync_delivery = mode;
        config.client.origin = Some(ORIGIN.into());
        config.client.dns_name = "client1.example.invalid".into();
        config.client.max_retries = 0;
        config.server.advertised_content_url = Some(ORIGIN.into());
        config.server.database = dir.path().join("server/wsus.sqlite");
        config.server.content_dir = dir.path().join("server/content");
        config.client.state_dir = dir.path().join("client");
        let clock = SharedClock::new();
        let opened = server_cmd::open(&config, Some(clock.server_clock())).unwrap();
        let bridge = Bridge::new(opened.server.clone());
        let d = Self {
            dir,
            config,
            clock,
            opened,
            bridge,
        };
        let admin = d.admin();
        admin::source_add(&admin, "upstream", "local", "synthetic").unwrap();
        d
    }

    /// Local administration over the same database the server uses.
    pub fn admin(&self) -> Admin {
        Admin::open(&self.config).unwrap()
    }

    /// Simulates a server process restart: everything is reopened from disk.
    pub fn restart_server(&mut self) {
        let opened = server_cmd::open(&self.config, Some(self.clock.server_clock())).unwrap();
        self.bridge.swap_server(opened.server.clone());
        self.opened = opened;
    }

    pub fn client_dir(&self) -> PathBuf {
        self.config.client.state_dir.clone()
    }
}

pub fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}
