//! Cap policy of the cached-id lists of `SyncUpdates` against the in-process
//! fake, which can emulate the lab WSUS limit (400 installed non-leaf ids).

mod session_common;

use session_common::*;
use wsus_client::sync::{SyncError, SyncOptions};

fn many(h: &Harness, non_leaf: u128, leaf: u128, page: usize) {
    let mut f = h.fake();
    for n in 1..=non_leaf {
        f.add(n, 1, false);
    }
    for n in 1..=leaf {
        f.add(10_000 + n, 1, true);
    }
    f.page_size = page;
}

#[tokio::test]
async fn installed_list_is_capped_and_overflow_goes_to_other_cached() {
    let h = Harness::new();
    many(&h, 10, 4, 5);
    h.fake().max_installed_non_leaf = Some(4);
    let mut config = h.config();
    config.installed_non_leaf_limit = 4;
    let mut e = h.engine_with(config);
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 14);
    let sizes = h.fake().list_sizes.clone();
    assert!(sizes.iter().all(|(installed, _)| *installed <= 4));
    // The last ranked call precedes the final page: 10 cached non-leaf revisions are
    // 4 installed plus 6 overflow (the probes after it also list 4).
    assert!(sizes.contains(&(4, 6)));
    // The cap resends nothing: every revision was delivered exactly once.
    assert!(h.fake().sent_counts.values().all(|n| *n == 1));
    let again = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(again.unchanged);
}

#[tokio::test]
async fn default_limit_is_the_observed_400() {
    let h = Harness::new();
    assert_eq!(h.config().installed_non_leaf_limit, 400);
    many(&h, 501, 0, 100);
    h.fake().max_installed_non_leaf = Some(400);
    let mut e = h.engine();
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 501);
    assert_eq!(*h.fake().list_sizes.last().unwrap(), (400, 101));
}

#[tokio::test]
async fn server_rejection_after_capping_is_a_typed_error_without_looping() {
    let h = Harness::new();
    many(&h, 10, 0, 5);
    h.fake().max_installed_non_leaf = Some(2);
    let mut config = h.config();
    config.installed_non_leaf_limit = 4;
    let mut e = h.engine_with(config);
    let err = e.sync_updates(&SyncOptions::default()).await.unwrap_err();
    match err {
        SyncError::CachedListRejected {
            installed, limit, ..
        } => {
            assert_eq!(limit, 4);
            assert_eq!(installed, 4);
        }
        other => panic!("unexpected error: {other}"),
    }
    // Page 1 had an empty cache and passed; page 2 was rejected once.
    assert_eq!(h.fake().count("SyncUpdates"), 2);
}

#[tokio::test]
async fn zero_limit_sends_no_installed_ids() {
    let h = Harness::new();
    many(&h, 3, 0, 2);
    let mut config = h.config();
    config.installed_non_leaf_limit = 0;
    let mut e = h.engine_with(config);
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(h.fake().list_sizes.iter().all(|(i, _)| *i == 0));
    assert_eq!(*h.fake().list_sizes.last().unwrap(), (0, 3));
}

/// Six non-leaf revisions (1 to 6) and a software leaf under each; limit 4. The ranking lists
/// the four non-leaf revisions with the most known dependents and withholds 5 and 6, so the
/// leaves under them (10_005, 10_006) can only arrive when those ids are listed. The leaf
/// under revision 6 is the one nothing known depends on yet (as the approved Defender bundle
/// was in the P3 run, ledger C52).
fn staged_with_withheld_prerequisites(h: &Harness) {
    let mut f = h.fake();
    f.enforce_prerequisites = true;
    for n in 1..=6u128 {
        f.add(n, 1, false);
    }
    for n in 1..=6u128 {
        f.add(10_000 + n, 1, true).prerequisites = vec![rev(n, 1).id];
    }
    f.page_size = 100;
    f.max_installed_non_leaf = Some(4);
}

#[tokio::test]
async fn leaf_behind_a_withheld_prerequisite_is_delivered_by_a_probe() {
    let h = Harness::new();
    staged_with_withheld_prerequisites(&h);
    let mut config = h.config();
    config.installed_non_leaf_limit = 4;
    let mut e = h.engine_with(config);
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 12, "every revision is delivered");
    assert_eq!(report.removed_revisions, 0);
    assert_eq!(e.session().state().cached_revisions.len(), 12);
    // No request ever exceeded the cap.
    assert!(
        h.fake()
            .list_sizes
            .iter()
            .all(|(installed, _)| *installed <= 4)
    );
}

#[tokio::test]
async fn revision_kept_for_a_withheld_prerequisite_is_not_dropped_and_repeat_sync_is_unchanged() {
    let h = Harness::new();
    staged_with_withheld_prerequisites(&h);
    let mut config = h.config();
    config.installed_non_leaf_limit = 4;
    let mut e = h.engine_with(config);
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    // The ranked list withholds revisions 5 and 6, so the server answers the leaves under
    // them as out of scope on every ranked request; the client holds those ids and keeps them.
    let again = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(again.new_revisions, 0);
    assert_eq!(again.removed_revisions, 0);
    assert!(again.unchanged);
    assert_eq!(e.session().state().cached_revisions.len(), 12);
}

#[tokio::test]
async fn out_of_scope_answer_not_explained_by_the_cap_still_removes() {
    let h = Harness::new();
    staged_with_withheld_prerequisites(&h);
    let mut config = h.config();
    config.installed_non_leaf_limit = 4;
    let mut e = h.engine_with(config);
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    // Leaf 10_001 hangs under a listed prerequisite: its removal is genuine.
    h.fake()
        .revisions
        .iter_mut()
        .find(|s| s.identity == rev(10_001, 1))
        .unwrap()
        .retired = true;
    let again = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(again.removed_revisions, 1);
    assert_eq!(e.session().state().cached_revisions.len(), 11);
}
