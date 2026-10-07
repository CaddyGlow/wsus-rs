//! The downstream importer against a REAL upstream WSUS. Ignored by default.
//!
//! Needs a disposable lab WSUS acting as upstream (the one of the 2026-10-04 run: Windows
//! Server 2025 10.0.26100, Microsoft Defender Antivirus product synchronized, update
//! `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe` revision 200 approved and downloaded). Set
//! `WSUS_REAL_ORIGIN` (for example `http://10.83.20.149:8530`) and run
//!
//! ```text
//! WSUS_REAL_ORIGIN=http://10.83.20.149:8530 cargo test -p wsus-cli --test real_upstream -- --ignored
//! ```
//!
//! Optional: `WSUS_REAL_CONTENT=1` also downloads the approved update's 155 files (about 1.2
//! GiB) into a temporary store; `WSUS_REAL_UPDATE` overrides the approved update id.
//!
//! The test reads the real server only (handshake, configuration, revision lists,
//! `GetUpdateData`, content `GET`s); it never calls `DownloadFiles` (the fallback is off), so it
//! leaves the upstream untouched. The assertions describe what that server build did on that
//! day and will not hold against another catalog.
use std::time::Duration;

use wsus_cli::config::NetworkSection;
use wsus_cli::net::build_transport;
use wsus_client::download::{DownloadLimits, DownloadOptions, Downloader};
use wsus_client::transport::reqwest_backend::TokioTimer;
use wsus_client::wsusss::{WsusssClient, WsusssConfig};
use wsus_protocol::identity::UpdateId;
use wsus_server::catalog::{Catalog, FragmentState};
use wsus_server::content::ContentStore;
use wsus_server::fragments::{PrefixMap, derive_if_whole};
use wsus_server::storage::Database;
use wsus_server::upstream::{
    CategoryFilter, ContentSelection, StageOutcome, SyncOutcome, UpstreamConfig, UpstreamSync,
};

const PRODUCT: &str = "8c3fcc84-7410-4a95-8b89-a166a0190486";
const CLASSIFICATION: &str = "e0789628-ce08-4437-be74-2495b842f43b";

fn origin() -> Option<String> {
    std::env::var("WSUS_REAL_ORIGIN")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uid(s: &str) -> UpdateId {
    UpdateId(s.parse().unwrap())
}

fn sync_for(
    catalog: &Catalog,
    origin: &str,
    send_wire_filter: bool,
) -> UpstreamSync<wsus_client::transport::reqwest_backend::ReqwestTransport, TokioTimer> {
    let mut wc = WsusssConfig::new(
        origin,
        "real-test.lab.invalid",
        "6f1c2f6e-3f0b-4d3a-9b1e-0d2f6a1c5e21",
    );
    wc.content_base_url = Some(origin.to_owned());
    wc.download_files_fallback = false;
    wc.request_timeout = Duration::from_secs(300);
    let transport = build_transport(&NetworkSection::default(), Duration::from_secs(30)).unwrap();
    let client = WsusssClient::new(wc, transport, TokioTimer);
    let mut cfg = UpstreamConfig::new("real", "real-test-endpoint");
    cfg.filter = CategoryFilter {
        products: vec![uid(PRODUCT)],
        classifications: vec![uid(CLASSIFICATION)],
    };
    cfg.send_wire_filter = send_wire_filter;
    UpstreamSync::new(catalog.clone(), client, cfg).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs WSUS_REAL_ORIGIN pointing at a disposable lab WSUS"]
async fn real_upstream_filtered_sync_derives_fragments_and_reports_no_change() {
    let Some(origin) = origin() else {
        eprintln!("WSUS_REAL_ORIGIN not set; nothing to do");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("wsus.sqlite")).unwrap();
    let catalog = Catalog::new(db.clone());
    let bundle = std::env::var("WSUS_REAL_UPDATE")
        .unwrap_or_else(|_| "a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe".into());

    // Initial filtered synchronization, wire filter on (product AND classification).
    let mut sync = sync_for(&catalog, &origin, true);
    let report = sync.run().await.expect("initial synchronization");
    let SyncOutcome::Activated { fragments, .. } = report.outcome else {
        panic!("expected an activated generation, got no change");
    };
    assert!(
        fragments > 4000,
        "categories, detectoids and the Defender bundles: {fragments}"
    );
    assert!(report.stats.listed > 24_000, "{:?}", report.stats);
    assert!(
        report.stats.pulled_by_dependency > 0,
        "bundled revisions are pulled by dependency"
    );

    // The approved bundle and its closure are present and every whole document derives.
    let snapshot = catalog.snapshot(sync.source()).unwrap().unwrap();
    let closure = snapshot.closure(&[uid(&bundle)]).unwrap();
    assert!(closure.len() > 400, "bundle closure: {}", closure.len());
    let mut files = 0;
    let mut derived = 0;
    for record in &closure {
        if record.state != FragmentState::Present {
            continue;
        }
        files += snapshot.files(record.local).unwrap().len();
        if derive_if_whole(
            &record.core_xml,
            &PrefixMap::specified(),
            &Default::default(),
        )
        .expect("a real document derives")
        .is_some()
        {
            derived += 1;
        }
    }
    assert!(derived > 400, "derived {derived} documents");
    assert!(files > 150, "files declared by the closure: {files}");

    // Incremental call: nothing changed since the committed anchors, and with Delta=true the
    // upstream does not resend the whole filtered set (inventory 9.5).
    let mut again = sync_for(&catalog, &origin, true);
    match again.stage().await.expect("incremental stage") {
        StageOutcome::NoChange => {}
        StageOutcome::Staged(s) => panic!("expected no change, staged {:?}", s.stats),
    }

    // Content: only when asked for (about 1.2 GiB).
    if std::env::var("WSUS_REAL_CONTENT").is_ok_and(|v| v == "1") {
        let store = ContentStore::open(db.clone(), &dir.path().join("content")).unwrap();
        let downloader =
            Downloader::open(dir.path().join("dl"), DownloadLimits::default()).unwrap();
        let ids = std::iter::once(uid(&bundle)).collect();
        let r = again
            .acquire_content(
                &store,
                &downloader,
                &ContentSelection::Updates(ids),
                &DownloadOptions::default(),
            )
            .await
            .expect("content acquisition");
        assert_eq!(r.failed.len(), 0, "{:?}", r.failed);
        assert_eq!(r.acquired, 155, "{r:?}");
    }
}
