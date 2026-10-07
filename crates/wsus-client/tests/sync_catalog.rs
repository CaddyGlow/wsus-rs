//! Catalog relationships and acquisition closure (spec-derived fake data).

mod session_common;

use session_common::*;
use wsus_client::sync::{ClosureOptions, MissingRef, SyncOptions};
use wsus_protocol::{identity::UpdateId, wusp::XmlUpdateFragmentType};

async fn populated(h: &Harness) -> Engine {
    {
        let mut f = h.fake();
        {
            let b = f.add(10, 1, false);
            b.bundled = vec![rev(11, 1), rev(12, 1), rev(99, 1)];
        }
        {
            let c = f.add(11, 1, true);
            c.file = Some(("c.bin".into(), b"c-content".to_vec()));
            c.prerequisites = vec![UpdateId(uuid::Uuid::from_u128(20))];
        }
        f.add(12, 1, true).file = Some(("d.bin".into(), b"d-content".to_vec()));
        // Same content as 11: de-duplicated by size and digests.
        f.add(13, 1, true).file = Some(("c.bin".into(), b"c-content".to_vec()));
        f.add(20, 1, true).file = Some(("p1.bin".into(), b"p-old".to_vec()));
        f.add(20, 3, true).file = Some(("p3.bin".into(), b"p-new".to_vec()));
        f.add(30, 1, false).bundled = vec![rev(31, 1)];
        f.add(31, 1, false).bundled = vec![rev(30, 1)];
    }
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    e
}

async fn with_extended(e: &mut Engine) {
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
}

#[tokio::test]
async fn bundle_closure_includes_all_alternatives_and_reports_missing() {
    let h = Harness::new();
    let mut e = populated(&h).await;
    with_extended(&mut e).await;
    let catalog = e.catalog().unwrap();
    assert_eq!(catalog.len(), 8);
    let c = catalog.acquisition_closure(&[rev(10, 1)], &ClosureOptions::default());
    assert_eq!(c.members, [rev(10, 1), rev(11, 1), rev(12, 1)]);
    assert_eq!(c.missing, [MissingRef::Revision(rev(99, 1))]);
    let names: Vec<_> = c.files.iter().map(|f| f.file_name.as_str()).collect();
    assert_eq!(names, ["c.bin", "d.bin"]);
    assert!(c.needs_extended.is_empty());
    assert!(c.files.iter().all(|f| f.sha1.is_some()));
}

#[tokio::test]
async fn prerequisites_are_installation_data_not_acquisition_by_default() {
    let h = Harness::new();
    let mut e = populated(&h).await;
    with_extended(&mut e).await;
    let catalog = e.catalog().unwrap();
    let plain = catalog.acquisition_closure(&[rev(11, 1)], &ClosureOptions::default());
    assert_eq!(plain.members, [rev(11, 1)]);
    // The prerequisite is exposed for an applicability evaluator and resolves
    // to the highest stored revision (3), not the first (1).
    let rel = catalog.relationships(&rev(11, 1)).unwrap();
    assert_eq!(rel.prerequisites.len(), 1);
    assert_eq!(rel.prerequisites[0].resolved, [rev(20, 3)]);
    assert_eq!(
        catalog.latest_revision(UpdateId(uuid::Uuid::from_u128(20))),
        Some(rev(20, 3))
    );

    let full = catalog.acquisition_closure(
        &[rev(11, 1)],
        &ClosureOptions {
            include_prerequisite_content: true,
        },
    );
    assert_eq!(full.members, [rev(11, 1), rev(20, 3)]);
    assert_eq!(full.files.len(), 2);
}

#[tokio::test]
async fn identical_content_is_deduplicated_across_revisions() {
    let h = Harness::new();
    let mut e = populated(&h).await;
    with_extended(&mut e).await;
    let catalog = e.catalog().unwrap();
    let c = catalog.acquisition_closure(&[rev(11, 1), rev(13, 1)], &ClosureOptions::default());
    assert_eq!(c.files.len(), 1);
    assert_eq!(c.files[0].revisions, [rev(11, 1), rev(13, 1)]);
}

#[tokio::test]
async fn closure_without_extended_metadata_says_what_is_missing() {
    let h = Harness::new();
    let e = populated(&h).await;
    let catalog = e.catalog().unwrap();
    let c = catalog.acquisition_closure(&[rev(11, 1)], &ClosureOptions::default());
    assert!(c.files.is_empty());
    assert_eq!(c.needs_extended, [rev(11, 1)]);
}

#[tokio::test]
async fn bundle_cycles_and_unknown_selection_terminate() {
    let h = Harness::new();
    let mut e = populated(&h).await;
    with_extended(&mut e).await;
    let catalog = e.catalog().unwrap();
    let c = catalog.acquisition_closure(&[rev(30, 1), rev(77, 1)], &ClosureOptions::default());
    assert_eq!(c.members, [rev(30, 1), rev(31, 1)]);
    assert_eq!(c.missing, [MissingRef::Revision(rev(77, 1))]);
    assert_eq!(c.selected, [rev(30, 1), rev(77, 1)]);
}

#[tokio::test]
async fn non_well_formed_spec_style_fragments_sync_and_close() {
    let h = Harness::new();
    {
        let mut f = h.fake();
        f.add(10, 1, false).bundled = vec![rev(11, 1)];
        f.add(11, 1, true).file = Some(("c.bin".into(), b"c-content".to_vec()));
        for r in f.revisions.iter_mut() {
            r.lenient = true;
        }
    }
    let mut e = h.engine();
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 2);
    // Stored bytes are exactly what was received: no root, no declarations.
    let rec = e.store().get(&rev(10, 1)).unwrap().unwrap();
    assert!(rec.core.xml.starts_with("<UpdateIdentity"));
    assert!(rec.core.xml.contains("<b.WindowsVersion"));
    let sha = rec.core.sha256.clone();
    with_extended(&mut e).await;
    let rec11 = e.store().get(&rev(11, 1)).unwrap().unwrap();
    assert!(rec11.fragments[0].xml.starts_with("<Properties"));
    assert!(rec11.fragments[0].xml.contains("<d.Thing/>"));
    assert_eq!(
        e.store().get(&rev(10, 1)).unwrap().unwrap().core.sha256,
        sha
    );

    let catalog = e.catalog().unwrap();
    let c = catalog.acquisition_closure(&[rev(10, 1)], &ClosureOptions::default());
    assert_eq!(c.members, [rev(10, 1), rev(11, 1)]);
    assert_eq!(c.files.len(), 1);
    assert_eq!(c.files[0].file_name, "c.bin");
    // Applicability stays opaque in the index.
    let entry = catalog.get(&rev(10, 1)).unwrap();
    assert!(entry.index.applicability_rules.is_some());
}

#[tokio::test]
async fn well_formed_full_update_documents_still_work() {
    let h = Harness::new();
    {
        let mut f = h.fake();
        f.add(10, 1, true).file = Some(("c.bin".into(), b"c".to_vec()));
    }
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    with_extended(&mut e).await;
    let catalog = e.catalog().unwrap();
    assert_eq!(
        catalog
            .acquisition_closure(&[rev(10, 1)], &ClosureOptions::default())
            .files
            .len(),
        1
    );
}
