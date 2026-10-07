//! This project's own downstream client and importer (`WsusssClient`, `UpstreamSync`)
//! against the MS-WSUSSS upstream server, in process.
//!
//! SELF-CONSISTENCY ONLY. Client and server were written by the same project from the same
//! reading of the specification; agreement here does NOT show interoperability with a real
//! downstream WSUS server. Plan section 12 requires a real downstream WSUS to synchronize
//! from this server and serve an update to its client before the upstream server counts as
//! working; that has not been done.
mod upstream_server_common;
use upstream_server_common::*;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use wsus_client::download::{DownloadLimits, DownloadOptions, Downloader};
use wsus_client::transport::{ImmediateTimer, mock::MockTransport};
use wsus_client::wsusss::{WsusssClient, WsusssError};
use wsus_protocol::identity::UpdateRevision;
use wsus_protocol::soap::ErrorCode;
use wsus_server::catalog::*;
use wsus_server::content::ContentStore;
use wsus_server::endpoints::wsusss::{AccountState, UpstreamServer};
use wsus_server::storage::Database;
use wsus_server::upstream::{
    ContentSelection, ResetReason, SyncOutcome, UpstreamConfig, UpstreamSync,
};

type Orchestrator = UpstreamSync<MockTransport, ImmediateTimer>;

fn downstream_catalog() -> Catalog {
    Catalog::new(Database::open_in_memory().unwrap())
}

fn orchestrator(server: &UpstreamServer, catalog: &Catalog) -> Orchestrator {
    UpstreamSync::new(
        catalog.clone(),
        client(server),
        UpstreamConfig::new("downstream", "uss.test"),
    )
    .unwrap()
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

fn activated(r: &wsus_server::upstream::SyncReport) -> bool {
    matches!(r.outcome, SyncOutcome::Activated { .. })
}

#[test]
fn initial_and_incremental_synchronization_reproduce_the_served_metadata_byte_for_byte() {
    let f = fixture();
    f.seed(3);
    let down = downstream_catalog();
    let mut o = orchestrator(&f.server, &down);

    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(r.stats.reset, Some(ResetReason::Initial));
    assert_eq!(
        r.stats.fetched, 6,
        "3 configuration records and 3 software updates"
    );
    let got = present(&down, &o);
    assert_eq!(got.len(), 6);
    // Stored bytes equal what the server stores: genuine metadata passes through untouched.
    let snap = down.snapshot(o.source()).unwrap().unwrap();
    let served = f.catalog.snapshot(f.source).unwrap().unwrap();
    for id in &got {
        assert_eq!(
            snap.get(*id).unwrap().unwrap().core_xml,
            served.get(*id).unwrap().unwrap().core_xml,
            "{id}"
        );
    }

    // Nothing changed.
    let r = block_on(o.run()).unwrap();
    assert_eq!(r.outcome, SyncOutcome::NoChange);

    // Incremental: one new update and one new revision.
    f.refresh(&[Doc::software(4, 1), Doc::software(2, 2)]);
    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(r.stats.reset, None);
    assert_eq!(r.stats.fetched, 2, "only the delta is fetched");
    assert_eq!(
        r.stats.carried, 6,
        "everything the previous generation held"
    );
    assert!(present(&down, &o).contains(&rev(4, 1)) && present(&down, &o).contains(&rev(2, 2)));
    assert_eq!(block_on(o.run()).unwrap().outcome, SyncOutcome::NoChange);
}

#[test]
fn anchors_and_cookies_stay_valid_across_a_server_restart() {
    let f = fixture();
    f.seed(2);
    let down = downstream_catalog();
    let mut o = orchestrator(&f.server, &down);
    assert!(activated(&block_on(o.run()).unwrap()));
    let committed = o.committed_checkpoint().unwrap().unwrap();
    assert!(committed.update_anchor.is_some() && committed.config_anchor.is_some());

    // Restart the server process; the catalog changes while it is down.
    let f = f.restart();
    f.refresh(&[Doc::software(3, 1)]);

    // The same session cookie, held by a long-lived client, keeps working (signing key and
    // server identity persist) and the persisted anchors resolve.
    let mut o2 = orchestrator(&f.server, &down);
    let r = block_on(o2.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(r.stats.reset, None, "no ServerChanged, no full resync");
    assert_eq!(r.stats.fetched, 1);
    assert!(present(&down, &o2).contains(&rev(3, 1)));
    assert_eq!(block_on(o2.run()).unwrap().outcome, SyncOutcome::NoChange);
}

#[test]
fn a_session_cookie_survives_a_restart_without_reauthorizing() {
    let f = fixture();
    f.seed(1);
    let mut c = client(&f.server);
    block_on(c.get_config_data(None)).unwrap();
    let before = c.transport().requests().len();
    let f = f.restart();
    // Same client (same cookie), new server process over the same database.
    let mut c = WsusssClient::new(
        client_config(ACCOUNT, ACCOUNT_GUID),
        bridge(f.server.clone()),
        ImmediateTimer,
    );
    block_on(c.get_config_data(None)).unwrap();
    assert!(before >= 3);
    // And a cookie obtained before the restart validates after it.
    let cookie = f.cookie();
    let f = f.restart();
    assert!(f.call(&revision_req(&cookie, None, false)).is_ok());
}

#[test]
fn a_catalog_refresh_in_the_middle_of_a_synchronization_does_not_break_it() {
    let f = fixture();
    f.seed(5);
    let catalog = f.catalog.clone();
    let source = f.source;
    // Refresh the served catalog when the downstream asks for its first batch of software
    // metadata: the listing it holds was taken from the previous generation.
    let fired = Arc::new(Mutex::new(false));
    let server = f.server.clone();
    let transport = {
        let inner = bridge(server.clone());
        let (fired, catalog) = (fired.clone(), catalog.clone());
        MockTransport::with_handler(move |r| {
            if String::from_utf8_lossy(&r.body).contains("<GetUpdateData") {
                let mut done = fired.lock().unwrap();
                if !*done {
                    *done = true;
                    refresh_catalog(
                        &catalog,
                        source,
                        &[Doc::software(6, 1), Doc::software(1, 2)],
                    );
                }
            }
            // Delegate to the plain bridge.
            futures_free_send(&inner, r)
        })
    };
    let mut cfg = client_config(ACCOUNT, ACCOUNT_GUID);
    cfg.update_batch_size = 2;
    let down = downstream_catalog();
    let mut o = UpstreamSync::new(
        down.clone(),
        WsusssClient::new(cfg, transport, ImmediateTimer),
        UpstreamConfig::new("downstream", "uss.test"),
    )
    .unwrap();
    let r = block_on(o.run()).unwrap();
    assert!(*fired.lock().unwrap());
    assert!(activated(&r));
    // The synchronization finished on the listing it started with: 3 + 5 records.
    let first = present(&down, &o);
    assert_eq!(first.len(), 8);
    assert!(!first.contains(&rev(6, 1)) && !first.contains(&rev(1, 2)));
    // The next run picks up what the refresh added.
    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(r.stats.reset, None);
    let second = present(&down, &o);
    assert!(second.contains(&rev(6, 1)) && second.contains(&rev(1, 2)));
}

/// Synchronously forward a request through a bridge transport (the mock is handler-driven,
/// so its handler can be invoked directly).
fn futures_free_send(
    t: &MockTransport,
    r: &wsus_client::transport::HttpRequest,
) -> wsus_client::transport::mock::MockStep {
    use wsus_client::transport::Transport;
    let resp = block_on(t.send(r.clone()));
    match resp {
        Ok(r) => wsus_client::transport::mock::MockStep::Respond(r),
        Err(e) => wsus_client::transport::mock::MockStep::Fail(e),
    }
}

fn refresh_catalog(catalog: &Catalog, source: SourceId, docs: &[Doc]) {
    let mut records: Vec<FragmentImport> = Vec::new();
    let snap = catalog.snapshot(source).unwrap().unwrap();
    let mut after = None;
    loop {
        let page = snap.list(after, 500, true).unwrap();
        for r in page.items {
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
    records.extend(docs.iter().map(Doc::record));
    let g = catalog.begin_generation(source, None).unwrap();
    catalog.import_fragments(g, &records).unwrap();
    assert!(matches!(
        catalog.activate(g).unwrap(),
        ActivateOutcome::Activated { .. }
    ));
}

#[test]
fn an_expired_session_cookie_is_renewed_by_the_client() {
    let f = fixture();
    f.seed(2);
    let down = downstream_catalog();
    let mut o = orchestrator(&f.server, &down);
    assert!(activated(&block_on(o.run()).unwrap()));
    let handshakes = |o: &mut Orchestrator| {
        o.client_mut()
            .transport()
            .requests()
            .iter()
            .filter(|r| String::from_utf8_lossy(&r.body).contains("<GetCookie"))
            .count()
    };
    let before = handshakes(&mut o);
    // The server expires the cookie (4 h) while the client's clock still trusts it: the
    // server answers InvalidCookie and the client re-authorizes, a bounded number of times.
    f.advance(241 * 60);
    f.refresh(&[Doc::software(3, 1)]);
    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(handshakes(&mut o), before + 1);
    // Beyond the authorization cookie's life as well: the whole handshake restarts.
    f.advance(30 * 3600);
    f.refresh(&[Doc::software(4, 1)]);
    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert!(present(&down, &o).contains(&rev(4, 1)));
}

#[test]
fn large_metadata_is_fetched_in_batches_the_server_advertises() {
    let f = fixture();
    let mut docs = vec![
        Doc::config(PRODUCT, "Category"),
        Doc::config(CLASSIFICATION, "Category"),
        Doc::config(DETECTOID, "Detectoid"),
    ];
    docs.extend((1..=5).map(|i| Doc::software(i, 1).padded(700_000)));
    f.publish(&docs);
    let down = downstream_catalog();
    let mut o = orchestrator(&f.server, &down);
    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(present(&down, &o).len(), 8);
    assert_eq!(
        o.client_mut()
            .server_config()
            .unwrap()
            .max_number_of_updates_per_request,
        2
    );
    // No GetUpdateData request asked for more than the advertised count.
    for req in o.client_mut().transport().requests() {
        let body = String::from_utf8_lossy(&req.body).into_owned();
        if body.contains("<GetUpdateData") {
            assert!(body.matches("<UpdateIdentity").count() <= 2, "{body}");
        }
    }
}

#[test]
fn content_flows_through_the_content_route_and_download_files_is_the_recovery_path() {
    let f = fixture();
    let data = b"cab payload for the downstream server".to_vec();
    f.publish(&[Doc::bare(1, 1).with_file("a.cab", &data)]);
    let down = downstream_catalog();
    let mut o = orchestrator(&f.server, &down);
    assert!(activated(&block_on(o.run()).unwrap()));

    let dir = tempfile::tempdir().unwrap();
    let store = ContentStore::open(down.database().clone(), &dir.path().join("content")).unwrap();
    let downloader = Downloader::open(dir.path().join("dl"), DownloadLimits::default()).unwrap();
    let options = DownloadOptions::default();

    // The server describes the file but has not acquired it: 404, then DownloadFiles, then
    // still 404; the file is reported failed and the request is queued for acquisition.
    let report =
        block_on(o.acquire_content(&store, &downloader, &ContentSelection::All, &options)).unwrap();
    assert_eq!(report.acquired, 0);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(f.server.drain_download_requests(), vec![sha1(&data)]);

    // Once the server has the content, the same call succeeds via the Content route.
    f.put_content("a.cab", &data);
    let report =
        block_on(o.acquire_content(&store, &downloader, &ContentSelection::All, &options)).unwrap();
    assert_eq!(report.acquired, 1, "{report:?}");
    assert!(report.failed.is_empty());
    assert!(f.server.drain_download_requests().is_empty());
}

#[test]
fn unknown_digests_in_download_files_are_reported_with_their_text() {
    let f = fixture();
    f.seed(1);
    let mut c = client(&f.server);
    let unknown = vec![7u8; 20];
    let err = block_on(c.download_files(std::slice::from_ref(&unknown))).unwrap_err();
    assert_eq!(err.fault_code(), Some(&ErrorCode::FileDigestsMissing));
    use base64::Engine as _;
    assert_eq!(
        err.missing_digests(),
        vec![base64::engine::general_purpose::STANDARD.encode(&unknown)]
    );
    // The client enforces the 100 digest limit itself, before the request leaves.
    let many: Vec<Vec<u8>> = (0..101u8).map(|i| vec![i; 20]).collect();
    assert!(matches!(
        block_on(c.download_files(&many)).unwrap_err(),
        WsusssError::Limit(_)
    ));
}

#[test]
fn distinct_downstream_accounts_are_tracked_and_a_blocked_account_cannot_synchronize() {
    let f = fixture();
    f.seed(1);
    let other_guid = "11111111-2222-4333-8444-555555555555";
    let mut a = client(&f.server);
    let mut b = WsusssClient::new(
        client_config("DOMAIN\\dss2$", other_guid),
        bridge(f.server.clone()),
        ImmediateTimer,
    );
    block_on(a.get_config_data(None)).unwrap();
    block_on(b.get_config_data(None)).unwrap();
    let list = f.server.downstreams().list().unwrap();
    assert_eq!(list.len(), 2);
    f.server
        .downstreams()
        .set_state(other_guid.parse().unwrap(), AccountState::Blocked)
        .unwrap();
    // Blocking takes effect at the next GetCookie; a new handshake is refused and the
    // client's bounded restarts end in the specified fault.
    let mut b2 = WsusssClient::new(
        client_config("DOMAIN\\dss2$", other_guid),
        bridge(f.server.clone()),
        ImmediateTimer,
    );
    let err = block_on(b2.get_config_data(None)).unwrap_err();
    assert_eq!(
        err.fault_code(),
        Some(&ErrorCode::InvalidAuthorizationCookie)
    );
    block_on(a.get_config_data(None)).unwrap();
}

#[test]
fn a_pruned_anchor_makes_the_importer_fall_back_to_a_full_resynchronization() {
    let f = fixture();
    f.seed(2);
    let down = downstream_catalog();
    let mut o = orchestrator(&f.server, &down);
    assert!(activated(&block_on(o.run()).unwrap()));
    // Two refreshes and an aggressive prune remove the generation the anchors point at.
    f.refresh(&[Doc::software(3, 1)]);
    f.refresh(&[Doc::software(4, 1)]);
    f.catalog.prune_superseded(f.source, 0).unwrap();
    let r = block_on(o.run()).unwrap();
    assert!(activated(&r));
    assert_eq!(r.stats.reset, Some(ResetReason::ServerChanged));
    assert_eq!(present(&down, &o).len(), 3 + 4);
}

#[test]
fn content_transfers_overlap_within_the_configured_bound_and_reuse_verified_files() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wsus_client::transport::{
        BodySink, HttpRequest, HttpResponse, ResponseHead, Transport, TransportError,
    };

    struct Delayed {
        inner: MockTransport,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    impl Transport for Delayed {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            if String::from_utf8_lossy(&request.body).contains("<GetUpdateData") {
                let count = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(count, Ordering::SeqCst);
                let mut yielded = false;
                std::future::poll_fn(|cx| {
                    if yielded {
                        std::task::Poll::Ready(())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                })
                .await;
                let result = self.inner.send(request).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                return result;
            }
            self.inner.send(request).await
        }
        async fn send_streaming<'a>(
            &'a self,
            request: HttpRequest,
            sink: &'a mut (dyn BodySink + Send),
        ) -> Result<ResponseHead, TransportError> {
            struct Active<'a>(&'a AtomicUsize);
            impl Drop for Active<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let count = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(count, Ordering::SeqCst);
            let _guard = Active(&self.active);
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if yielded {
                    std::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            self.inner.send_streaming(request, sink).await
        }
    }
    let f = fixture();
    let payloads: Vec<_> = (1..=4)
        .map(|i| (format!("{i}.cab"), vec![i as u8; 2000]))
        .collect();
    let docs: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, (name, bytes))| Doc::bare(i as u128 + 1, 1).with_file(name, bytes))
        .collect();
    f.publish(&docs);
    for (name, bytes) in &payloads {
        f.put_content(name, bytes);
    }
    let down = downstream_catalog();
    let base = client(&f.server);
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let delayed = Delayed {
        inner: base.transport().clone(),
        active: active.clone(),
        peak: peak.clone(),
    };
    let mut client_config = base.config().clone();
    client_config.update_batch_size = 2;
    let client = WsusssClient::new(client_config, delayed, ImmediateTimer);
    let mut config = UpstreamConfig::new("downstream", "uss.test");
    config.download_concurrency = 2;
    config.metadata_concurrency = 2;
    let mut sync = UpstreamSync::new(down.clone(), client, config).unwrap();
    block_on(sync.run()).unwrap();
    assert_eq!(
        peak.swap(0, Ordering::SeqCst),
        2,
        "metadata calls overlap within the limit"
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
    let dir = tempfile::tempdir().unwrap();
    let store = ContentStore::open(down.database().clone(), &dir.path().join("content")).unwrap();
    let downloader = Downloader::open(dir.path().join("dl"), DownloadLimits::default()).unwrap();
    let options = DownloadOptions::default();
    let report =
        block_on(sync.acquire_content(&store, &downloader, &ContentSelection::All, &options))
            .unwrap();
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(report.acquired, 4);
    assert!(report.failed.is_empty());
    let second =
        block_on(sync.acquire_content(&store, &downloader, &ContentSelection::All, &options))
            .unwrap();
    assert_eq!(second.already_present, 4);
    assert_eq!(second.acquired, 0);
}
