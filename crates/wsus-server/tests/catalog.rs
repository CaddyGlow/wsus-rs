use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_server::catalog::*;
use wsus_server::storage::Database;

fn uid(n: u128) -> UpdateId {
    UpdateId(Uuid::from_u128(n))
}

fn rev(n: u128, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: uid(n),
        revision: Revision(r),
    }
}

fn frag(n: u128, r: u32) -> FragmentImport {
    FragmentImport::new(
        rev(n, r),
        "Software",
        format!("<Update id={n}/>").as_bytes(),
    )
}

fn with_prereq(mut f: FragmentImport, target: u128) -> FragmentImport {
    f.relationships.push(RelationshipImport {
        kind: RelationshipKind::Prerequisite,
        target: uid(target),
        revision: None,
    });
    f
}

fn setup() -> (Catalog, SourceId) {
    let cat = Catalog::new(Database::open_in_memory().unwrap());
    let src = cat
        .add_source("upstream", SourceKind::Upstream, "")
        .unwrap();
    (cat, src)
}

#[test]
fn staged_generation_is_invisible_until_activated() {
    let (cat, src) = setup();
    let g = cat.begin_generation(src, Some("anchor-1")).unwrap();
    cat.import_fragments(g, &[frag(1, 1), with_prereq(frag(2, 1), 1)])
        .unwrap();
    assert!(cat.snapshot(src).unwrap().is_none());
    assert!(cat.snapshot_of(g).is_err());
    assert_eq!(
        cat.activate(g).unwrap(),
        ActivateOutcome::Activated { fragments: 2 }
    );
    let snap = cat.snapshot(src).unwrap().unwrap();
    assert_eq!(snap.count().unwrap(), 2);
    assert_eq!(cat.generation(g).unwrap().state, GenerationState::Active);
}

#[test]
fn invalid_generation_never_replaces_active_and_keeps_evidence() {
    let (cat, src) = setup();
    let g1 = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g1, &[frag(1, 1)]).unwrap();
    cat.activate(g1).unwrap();

    let g2 = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g2, &[frag(1, 2), with_prereq(frag(3, 1), 99)])
        .unwrap();
    match cat.activate(g2).unwrap() {
        ActivateOutcome::Rejected(report) => {
            assert_eq!(report.issues.len(), 1);
            assert_eq!(report.issues[0].problem, IssueKind::MissingTarget);
        }
        other => panic!("expected rejection, got {other:?}"),
    }
    assert_eq!(cat.active_generation(src).unwrap(), Some(g1));
    let info = cat.generation(g2).unwrap();
    assert_eq!(info.state, GenerationState::Failed);
    assert!(info.evidence.unwrap().contains("MissingTarget"));
    // Failed generation cannot be read as a snapshot but its rows remain.
    assert!(cat.snapshot_of(g2).is_err());
    let snap = cat.snapshot(src).unwrap().unwrap();
    assert!(snap.get(rev(1, 1)).unwrap().is_some());
    assert!(snap.get(rev(1, 2)).unwrap().is_none());
}

#[test]
fn self_prerequisite_and_empty_generation_are_rejected() {
    let (cat, src) = setup();
    let g = cat.begin_generation(src, None).unwrap();
    assert!(matches!(
        cat.activate(g).unwrap(),
        ActivateOutcome::Rejected(_)
    ));
    let g = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g, &[with_prereq(frag(1, 1), 1)])
        .unwrap();
    match cat.activate(g).unwrap() {
        ActivateOutcome::Rejected(r) => assert_eq!(r.issues[0].problem, IssueKind::SelfReference),
        other => panic!("{other:?}"),
    }
}

#[test]
fn duplicate_fragment_batch_rolls_back_atomically() {
    let (cat, src) = setup();
    let g = cat.begin_generation(src, None).unwrap();
    assert!(cat.import_fragments(g, &[frag(1, 1), frag(1, 1)]).is_err());
    cat.import_fragments(g, &[frag(2, 1)]).unwrap();
    cat.activate(g).unwrap();
    assert_eq!(cat.snapshot(src).unwrap().unwrap().count().unwrap(), 1);
}

#[test]
fn old_snapshot_stays_stable_across_new_activation_and_paging_is_stable() {
    let (cat, src) = setup();
    let g1 = cat.begin_generation(src, None).unwrap();
    let batch: Vec<_> = (1..=7).map(|n| frag(n, 1)).collect();
    cat.import_fragments(g1, &batch).unwrap();
    cat.activate(g1).unwrap();
    let old = cat.snapshot(src).unwrap().unwrap();

    let page1 = old.list(None, 3, true).unwrap();
    assert_eq!(page1.items.len(), 3);

    // New generation activates between pages.
    let g2 = cat.begin_generation(src, None).unwrap();
    let batch: Vec<_> = (1..=2).map(|n| frag(n, 2)).collect();
    cat.import_fragments(g2, &batch).unwrap();
    cat.activate(g2).unwrap();
    assert_eq!(
        cat.generation(g1).unwrap().state,
        GenerationState::Superseded
    );

    let mut seen: Vec<_> = page1.items.iter().map(|f| f.identity).collect();
    let mut next = page1.next;
    while let Some(after) = next {
        let p = old.list(Some(after), 3, true).unwrap();
        seen.extend(p.items.iter().map(|f| f.identity));
        next = p.next;
    }
    let expected: Vec<_> = (1..=7).map(|n| rev(n, 1)).collect();
    assert_eq!(seen, expected);
    assert_eq!(cat.snapshot(src).unwrap().unwrap().count().unwrap(), 2);
}

#[test]
fn local_ids_are_scoped_stable_and_independent_of_rows() {
    let (cat, _) = setup();
    let a = cat.local_id(rev(10, 1)).unwrap();
    let b = cat.local_id(rev(10, 2)).unwrap();
    assert_ne!(a, b);
    assert_eq!(cat.local_id(rev(10, 1)).unwrap(), a);
    assert_eq!(cat.lookup_local(b).unwrap(), Some(rev(10, 2)));
    assert_eq!(a.server, cat.database().server_id().unwrap());
    let mut foreign = a;
    foreign.server = wsus_protocol::identity::ServerId(Uuid::from_u128(5));
    assert!(cat.lookup_local(foreign).is_err());
}

#[test]
fn withdrawn_and_superseded_content_is_retained() {
    let (cat, src) = setup();
    let g = cat.begin_generation(src, None).unwrap();
    let mut old = frag(1, 1);
    old.state = FragmentState::Withdrawn;
    let mut new = with_prereq(frag(2, 1), 1);
    new.relationships.push(RelationshipImport {
        kind: RelationshipKind::Supersedes,
        target: uid(1),
        revision: None,
    });
    new.relationships.push(RelationshipImport {
        kind: RelationshipKind::Supersedes,
        target: uid(500), // dangling supersedence is tolerated
        revision: None,
    });
    cat.import_fragments(g, &[old, new]).unwrap();
    cat.activate(g).unwrap();
    let snap = cat.snapshot(src).unwrap().unwrap();
    assert_eq!(snap.list(None, 10, false).unwrap().items.len(), 1);
    assert_eq!(snap.list(None, 10, true).unwrap().items.len(), 2);
    // The prerequisite on a withdrawn update still resolves, so closure retains it.
    let closure = snap.closure(&[uid(2)]).unwrap();
    assert_eq!(closure.len(), 2);
    assert_eq!(closure[0].state, FragmentState::Withdrawn);
}

#[test]
fn interrupted_staging_is_abandoned_with_evidence() {
    let (cat, src) = setup();
    let g = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g, &[frag(1, 1)]).unwrap();
    assert_eq!(cat.abandon_interrupted().unwrap(), vec![g]);
    let info = cat.generation(g).unwrap();
    assert_eq!(info.state, GenerationState::Failed);
    assert!(cat.activate(g).is_err());
}

#[test]
fn files_roundtrip_and_prune_keeps_active() {
    use wsus_protocol::identity::{DigestAlgorithm, FileDigest};
    let (cat, src) = setup();
    let mut f = frag(1, 1);
    f.files.push(FileDescriptor {
        file_name: "a.cab".into(),
        size: 10,
        digests: vec![FileDigest {
            algorithm: DigestAlgorithm::Sha1,
            bytes: vec![7; 20],
        }],
    });
    let g1 = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g1, &[f]).unwrap();
    cat.activate(g1).unwrap();
    let snap = cat.snapshot(src).unwrap().unwrap();
    let local = snap.get(rev(1, 1)).unwrap().unwrap().local;
    let files = snap.files(local).unwrap();
    assert_eq!(files[0].file_name, "a.cab");
    assert_eq!(files[0].digests[0].bytes, vec![7; 20]);

    let g2 = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g2, &[frag(1, 2)]).unwrap();
    cat.activate(g2).unwrap();
    assert_eq!(cat.prune_superseded(src, 0).unwrap(), 1);
    assert_eq!(cat.active_generation(src).unwrap(), Some(g2));

    // Bad digest length is rejected at import.
    let mut bad = frag(3, 1);
    bad.files.push(FileDescriptor {
        file_name: "b".into(),
        size: 1,
        digests: vec![FileDigest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: vec![1; 3],
        }],
    });
    let g3 = cat.begin_generation(src, None).unwrap();
    assert!(cat.import_fragments(g3, &[bad]).is_err());
}
