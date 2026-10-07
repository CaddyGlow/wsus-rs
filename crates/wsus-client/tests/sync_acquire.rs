//! File locations and verified acquisition (spec-derived fake; not validated
//! against a real WSUS).

mod session_common;

use session_common::*;
use std::fs;
use wsus_client::{
    download::{DownloadLimits, DownloadOptions, Downloader},
    sync::{ClosureOptions, FileStatus, SyncOptions},
    transport::RetryPolicy,
};
use wsus_protocol::{soap::ErrorCode, wusp::XmlUpdateFragmentType};

fn walk(dir: &std::path::Path, out: &mut Vec<Vec<u8>>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(fs::read(&p).unwrap());
        }
    }
}

async fn ready(h: &Harness) -> Engine {
    {
        let mut f = h.fake();
        f.add(1, 1, true).file = Some(("a.bin".into(), vec![7u8; 5000]));
        f.add(2, 1, true).file = Some(("b.bin".into(), b"second payload".to_vec()));
    }
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let all: Vec<_> = e
        .session()
        .state()
        .cached_revisions
        .keys()
        .copied()
        .collect();
    e.fetch_fragments(&all, XmlUpdateFragmentType::Extended, &[])
        .await
        .unwrap();
    e
}

fn options() -> DownloadOptions {
    DownloadOptions {
        retry: RetryPolicy::none(),
        ..DownloadOptions::default()
    }
}

#[tokio::test]
async fn locations_are_transient_and_never_persisted() {
    let h = Harness::new();
    let mut e = ready(&h).await;
    let locations = e.file_locations(&[sha1_of(&[7u8; 5000])]).await.unwrap();
    assert_eq!(locations.len(), 1);
    let shown = format!("{locations:?}");
    assert!(
        !shown.contains("SECRET") && !shown.contains("sig="),
        "{shown}"
    );
    // FileUrl through GetExtendedUpdateInfo is transient too.
    let r = e
        .fetch_fragments(&[rev(1, 1)], XmlUpdateFragmentType::FileUrl, &[])
        .await
        .unwrap();
    assert_eq!(r.locations.len(), 1);
    let mut files = Vec::new();
    walk(h.dir.path(), &mut files);
    assert!(!files.is_empty());
    for bytes in files {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("SECRET") && !text.contains("content.test"));
    }
}

#[tokio::test]
async fn acquire_downloads_verified_payloads_and_skips_complete_ones() {
    let h = Harness::new();
    let mut e = ready(&h).await;
    let catalog = e.catalog().unwrap();
    let closure = catalog.acquisition_closure(&[rev(1, 1), rev(2, 1)], &ClosureOptions::default());
    let dl = Downloader::open(h.dir.path().join("content"), DownloadLimits::default()).unwrap();
    let report = e.acquire(&closure, &dl, &options()).await.unwrap();
    assert!(report.all_complete(), "{report:?}");
    let FileStatus::Complete(done) = &report.files[0].status else {
        panic!()
    };
    assert_eq!(fs::read(&done.path).unwrap(), vec![7u8; 5000]);
    assert_eq!(h.fake().gets, 2);

    // Restart and repeat: verified objects need neither locations nor GETs.
    drop(e);
    let mut e = h.engine();
    let locs = h.fake().count("GetFileLocations");
    let report = e.acquire(&closure, &dl, &options()).await.unwrap();
    assert!(report.all_complete());
    assert!(
        report
            .files
            .iter()
            .all(|f| matches!(&f.status, FileStatus::Complete(d) if d.already_complete))
    );
    assert_eq!(h.fake().count("GetFileLocations"), locs);
    assert_eq!(h.fake().gets, 2);
}

#[tokio::test]
async fn expired_location_is_refreshed_by_digest_and_retried() {
    let h = Harness::new();
    let mut e = ready(&h).await;
    {
        let mut f = h.fake();
        f.location_generation = 2;
        f.stale_location_responses = 1; // first answer carries an expired URL
    }
    let catalog = e.catalog().unwrap();
    let closure = catalog.acquisition_closure(&[rev(2, 1)], &ClosureOptions::default());
    let dl = Downloader::open(h.dir.path().join("content"), DownloadLimits::default()).unwrap();
    let report = e.acquire(&closure, &dl, &options()).await.unwrap();
    assert!(report.all_complete(), "{report:?}");
    assert_eq!(h.fake().count("GetFileLocations"), 2);
    assert_eq!(h.fake().gets, 2, "one rejected GET, one successful");
}

#[tokio::test]
async fn file_location_changed_fault_is_answered_by_asking_again() {
    let h = Harness::new();
    let mut e = ready(&h).await;
    h.fake()
        .faults
        .push_back(("GetFileLocations".into(), ErrorCode::FileLocationChanged));
    let before = h.fake().count("GetFileLocations");
    let locations = e.file_locations(&[sha1_of(&[7u8; 5000])]).await.unwrap();
    assert_eq!(locations.len(), 1);
    assert_eq!(
        h.fake().count("GetFileLocations"),
        before + 2,
        "fault, then success"
    );
}

#[tokio::test]
async fn persistent_file_location_changed_fault_is_bounded() {
    let h = Harness::new();
    let mut e = ready(&h).await;
    h.fake()
        .always_fault
        .insert("GetFileLocations".into(), ErrorCode::FileLocationChanged);
    let before = h.fake().count("GetFileLocations");
    let error = e
        .file_locations(&[sha1_of(&[7u8; 5000])])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("FileLocationChanged"), "{error}");
    assert_eq!(
        h.fake().count("GetFileLocations") - before,
        4,
        "one try plus three retries"
    );
}

#[tokio::test]
async fn corrupt_content_is_never_published() {
    let h = Harness::new();
    let mut e = ready(&h).await;
    h.fake().content_corruption = true;
    let catalog = e.catalog().unwrap();
    let closure = catalog.acquisition_closure(&[rev(2, 1)], &ClosureOptions::default());
    let dl = Downloader::open(h.dir.path().join("content"), DownloadLimits::default()).unwrap();
    let report = e.acquire(&closure, &dl, &options()).await.unwrap();
    assert!(!report.all_complete());
    assert!(
        matches!(&report.files[0].status, FileStatus::Failed(m) if m.contains("digest")),
        "{report:?}"
    );
    let mut complete = Vec::new();
    walk(
        &h.dir.path().join("content").join("complete"),
        &mut complete,
    );
    assert!(complete.is_empty());
}
