//! SyncUpdates, checkpointing, extended metadata and localized selection
//! against the in-process fake server (spec-derived; not validated against a
//! real WSUS).

mod session_common;

use session_common::*;
use std::fs;
use wsus_client::sync::{RevisionStore, SyncError, SyncOptions, select_localized};
use wsus_protocol::wusp::XmlUpdateFragmentType;

fn five(h: &Harness) {
    let mut f = h.fake();
    for n in 1..=5 {
        f.add(n, 1, n % 2 == 0);
    }
    f.page_size = 2;
}

#[tokio::test]
async fn pagination_commits_every_page_and_sends_each_revision_once() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    // Three pages of data plus one more request because the last page held a
    // non-leaf update (MS-WUSP 3.1.5.7).
    assert_eq!(report.pages, 4);
    assert_eq!(report.new_revisions, 5);
    assert!(!report.unchanged);
    assert_eq!(e.session().state().cached_revisions.len(), 5);
    assert_eq!(e.store().list().unwrap().len(), 5);
    assert!(e.session().state().sync_checkpoint.is_some());
    assert!(h.fake().sent_counts.values().all(|n| *n == 1));
    // Leaf and non-leaf revisions land in the right id lists of later calls;
    // the second run lists all five as cached and receives nothing.
    let again = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(again.unchanged);
    assert_eq!(again.pages, 1);
}

#[tokio::test]
async fn no_change_incremental_sync_is_one_request_and_no_writes() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let before = e.session().state().write_counter;
    let record_bytes = fs::read(
        fs::read_dir(h.dir.path().join("meta").join("revisions"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap();
    let calls = h.fake().count("SyncUpdates");
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(report.unchanged);
    assert_eq!(h.fake().count("SyncUpdates") - calls, 1);
    assert_eq!(
        e.session().state().write_counter,
        before,
        "no state write when nothing changed"
    );
    drop(record_bytes);
}

#[tokio::test]
async fn interruption_mid_sync_resumes_without_loss_or_duplication() {
    let h = Harness::new();
    five(&h);
    let mut run = h.engine();
    // Stop after exactly one committed page (a deterministic interruption).
    let opts = SyncOptions {
        max_pages: 1,
        ..SyncOptions::default()
    };
    let err = run.sync_updates(&opts).await.unwrap_err();
    assert!(matches!(err, SyncError::TooManyPages(1)));
    assert_eq!(
        run.session().state().cached_revisions.len(),
        2,
        "page 1 is committed"
    );
    drop(run);

    // "Process restart": a fresh engine over the same directories.
    let mut resumed = h.engine();
    assert_eq!(resumed.session().state().cached_revisions.len(), 2);
    let report = resumed.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 3);
    assert_eq!(resumed.session().state().cached_revisions.len(), 5);
    assert_eq!(resumed.store().list().unwrap().len(), 5);
    assert!(
        h.fake().sent_counts.values().all(|n| *n == 1),
        "{:?}",
        h.fake().sent_counts
    );
}

#[tokio::test]
async fn transport_failure_on_a_later_page_keeps_committed_pages() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    // Page 1 succeeds; the failure injected afterwards hits page 2.
    let fake = h.fake.clone();
    let first = e
        .sync_updates(&SyncOptions {
            max_pages: 1,
            ..SyncOptions::default()
        })
        .await;
    assert!(first.is_err());
    // The next request, the one for page 2, is lost mid-flight.
    fake.lock()
        .unwrap()
        .transport_failures
        .push_back("SyncUpdates".into());
    assert!(e.sync_updates(&SyncOptions::default()).await.is_err());
    assert_eq!(e.session().state().cached_revisions.len(), 2);
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 3);
    assert!(h.fake().sent_counts.values().all(|n| *n == 1));
}

#[tokio::test]
async fn metadata_stored_but_not_checkpointed_is_overwritten_idempotently() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions {
        max_pages: 1,
        ..SyncOptions::default()
    })
    .await
    .unwrap_err();
    // Simulate a crash between step 1 and step 2 of the next page: its
    // records exist but state does not list them as cached.
    let store = RevisionStore::open(h.dir.path().join("meta")).unwrap();
    let existing = store.list().unwrap();
    assert_eq!(existing.len(), 2);
    let mut orphan = existing[0].clone();
    orphan.identity = rev(3, 1);
    store.put(&orphan).unwrap();
    drop(e);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(e.session().state().cached_revisions.len(), 5);
    let stored = store.get(&rev(3, 1)).unwrap().unwrap();
    assert!(
        stored
            .core
            .xml
            .contains("00000000-0000-0000-0000-000000000003")
    );
}

#[tokio::test]
async fn out_of_scope_and_changed_updates_are_applied() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    {
        let mut f = h.fake();
        f.revisions[0].retired = true;
        let id = f.revisions[1].local_id;
        f.revisions[1].action = "Evaluate".into();
        f.changed_next.insert(id);
    }
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.removed_revisions, 1);
    assert_eq!(report.changed_revisions, 1);
    assert_eq!(e.session().state().cached_revisions.len(), 4);
    let rec = e.store().get(&rev(2, 1)).unwrap().unwrap();
    assert_eq!(rec.deployment.unwrap().action, "Evaluate");
    // Metadata is kept for the changed revision even though the changed
    // entry carried no Xml.
    assert!(rec.core.xml.contains("UpdateIdentity"));
}

#[tokio::test]
async fn truncated_without_progress_stops() {
    let h = Harness::new();
    five(&h);
    {
        let mut f = h.fake();
        f.page_size = 0; // truncated forever, nothing delivered
    }
    let mut e = h.engine();
    let err = e.sync_updates(&SyncOptions::default()).await.unwrap_err();
    assert!(matches!(err, SyncError::NoProgress));
    assert_eq!(h.fake().count("SyncUpdates"), 1);
}

#[tokio::test]
async fn extended_info_batches_and_stores_fragments() {
    let h = Harness::new();
    five(&h);
    {
        let mut f = h.fake();
        f.max_extended = 3; // MUST be below the limit: batches of 2
        f.page_size = 100;
        f.revisions[0].file = Some(("a.bin".into(), b"payload".to_vec()));
    }
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let revs: Vec<_> = (1..=5).map(|n| rev(n, 1)).collect();
    let r = e
        .fetch_fragments(&revs, XmlUpdateFragmentType::Extended, &[])
        .await
        .unwrap();
    assert_eq!(r.stored, 5);
    assert_eq!(h.fake().extended_batches, [2, 2, 1]);
    let rec = e.store().get(&rev(1, 1)).unwrap().unwrap();
    assert!(rec.fragments[0].xml.contains("a.bin"));
    // Unknown revision has no local id.
    let err = e
        .fetch_fragments(&[rev(99, 1)], XmlUpdateFragmentType::Extended, &[])
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::UnknownRevision(_)));
}

#[tokio::test]
async fn out_of_scope_ids_in_extended_info_are_reported() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    // Server forgets a revision after the client cached it.
    h.fake().revisions.remove(0);
    let r = e
        .fetch_fragments(
            &[rev(1, 1), rev(2, 1)],
            XmlUpdateFragmentType::Extended,
            &[],
        )
        .await
        .unwrap();
    assert_eq!(r.out_of_scope, [rev(1, 1)]);
    assert_eq!(r.stored, 1);
}

#[tokio::test]
async fn localized_metadata_selection() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let locales: Vec<String> = ["en", "fr", "pt-BR"].map(String::from).to_vec();
    e.fetch_fragments(
        &[rev(1, 1)],
        XmlUpdateFragmentType::LocalizedProperties,
        &locales,
    )
    .await
    .unwrap();
    let rec = e.store().get(&rev(1, 1)).unwrap().unwrap();
    assert_eq!(rec.fragments.len(), 3);

    let pick = |prefs: &[&str]| select_localized(&rec, prefs).unwrap().title.unwrap();
    assert_eq!(pick(&["fr"]), "Title fr");
    assert_eq!(pick(&["FR"]), "Title fr", "case-insensitive");
    assert_eq!(pick(&["fr-CA"]), "Title fr", "primary language subtag");
    assert_eq!(pick(&["pt-BR", "en"]), "Title pt-BR");
    assert_eq!(pick(&["pt-PT"]), "Title pt-BR");
    assert_eq!(pick(&["de"]), "Title en", "English fallback");
    assert_eq!(pick(&[]), "Title en");
    let sel = select_localized(&rec, &["fr"]).unwrap();
    assert_eq!(sel.description.as_deref(), Some("Desc fr"));
    assert_eq!(sel.locale.as_deref(), Some("fr"));

    // Refetching one locale replaces, not duplicates.
    e.fetch_fragments(
        &[rev(1, 1)],
        XmlUpdateFragmentType::LocalizedProperties,
        &["fr".into()],
    )
    .await
    .unwrap();
    assert_eq!(
        e.store().get(&rev(1, 1)).unwrap().unwrap().fragments.len(),
        3
    );
}

#[tokio::test]
async fn extended_info_2_is_keyed_by_identity() {
    let h = Harness::new();
    five(&h);
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let r = e
        .fetch_fragments2(
            &[rev(1, 1), rev(2, 1)],
            XmlUpdateFragmentType::Extended,
            &[],
        )
        .await
        .unwrap();
    assert_eq!(r.stored, 2);
    assert_eq!(h.fake().count("GetExtendedUpdateInfo2"), 1);
    assert_eq!(h.fake().count("GetExtendedUpdateInfo"), 0);
}
