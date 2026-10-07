use std::fs;
use std::io::{Read, Write};
use std::time::Duration;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wsus_protocol::identity::{DigestAlgorithm, FileDigest, Revision, UpdateId, UpdateRevision};
use wsus_server::catalog::*;
use wsus_server::content::*;
use wsus_server::storage::Database;

fn desc(name: &str, data: &[u8]) -> ContentDescriptor {
    ContentDescriptor {
        file_name: name.into(),
        size: data.len() as u64,
        digests: vec![
            FileDigest {
                algorithm: DigestAlgorithm::Sha1,
                bytes: Sha1::digest(data).to_vec(),
            },
            FileDigest {
                algorithm: DigestAlgorithm::Sha256,
                bytes: Sha256::digest(data).to_vec(),
            },
        ],
    }
}

fn setup() -> (tempfile::TempDir, Database, ContentStore) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("db.sqlite")).unwrap();
    let store = ContentStore::open(db.clone(), &dir.path().join("content")).unwrap();
    (dir, db, store)
}

fn read_all(mut r: impl Read) -> Vec<u8> {
    let mut v = Vec::new();
    r.read_to_end(&mut v).unwrap();
    v
}

const DATA: &[u8] = b"0123456789abcdefghij";

#[test]
fn lifecycle_promotes_and_records_aliases() {
    let (_d, _db, store) = setup();
    let d = desc("a.cab", DATA);
    let mut up = store.begin(&d).unwrap();
    up.write_all(&DATA[..7]).unwrap();
    up.write_all(&DATA[7..]).unwrap();
    let id = up.finish().unwrap();
    assert_eq!(id.sha256_bytes(), Sha256::digest(DATA).to_vec());
    assert!(store.object_path(&id).is_file());
    let info = store.info(&id).unwrap().unwrap();
    assert_eq!(info.size, 20);
    assert_eq!(info.file_names, vec!["a.cab".to_string()]);
    assert_eq!(store.find_available(&d).unwrap(), Some(id));
}

#[test]
fn corrupted_content_is_rejected_and_quarantined() {
    let (dir, _db, store) = setup();
    let mut bad = desc("a.cab", DATA);
    bad.digests[0].bytes[0] ^= 1;
    let mut up = store.begin(&bad).unwrap();
    up.write_all(DATA).unwrap();
    assert!(up.finish().is_err());
    assert!(
        store
            .find_available(&desc("a.cab", DATA))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read_dir(dir.path().join("content/quarantine"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(dir.path().join("content/partial"))
            .unwrap()
            .count(),
        0
    );

    // Wrong length (short) is also rejected.
    let d = desc("b", DATA);
    let mut up = store.begin(&d).unwrap();
    up.write_all(&DATA[..5]).unwrap();
    assert!(up.finish().is_err());
    // Overlong write is refused outright.
    let mut up = store.begin(&d).unwrap();
    assert!(up.write_all(&[0u8; 21]).is_err());
}

#[test]
fn ranges_edge_cases() {
    let (_d, _db, store) = setup();
    let id = store.put_bytes(&desc("a", DATA), DATA).unwrap();

    let ServeOutcome::Full(r) = store.serve(&id, None).unwrap() else {
        panic!()
    };
    assert_eq!((r.len(), r.total_size()), (20, 20));
    assert_eq!(read_all(r), DATA);

    let cases: &[(&str, &[u8], &str)] = &[
        ("bytes=0-0", b"0", "bytes 0-0/20"),
        ("bytes=5-9", b"56789", "bytes 5-9/20"),
        ("bytes=15-", b"fghij", "bytes 15-19/20"),
        ("bytes=-5", b"fghij", "bytes 15-19/20"),
        ("bytes=-100", DATA, "bytes 0-19/20"),
        ("bytes=10-1000", b"abcdefghij", "bytes 10-19/20"),
        ("bytes=19-19", b"j", "bytes 19-19/20"),
    ];
    for (h, want, cr) in cases {
        match store.serve(&id, Some(h)).unwrap() {
            ServeOutcome::Partial(mut v) => {
                assert_eq!(v.len(), 1, "{h}");
                let (range, reader) = v.remove(0);
                assert_eq!(range.content_range(20), *cr, "{h}");
                assert_eq!(reader.len(), want.len() as u64);
                assert_eq!(read_all(reader), *want, "{h}");
            }
            other => panic!("{h}: {other:?}"),
        }
    }
    for h in ["bytes=20-", "bytes=20-30", "bytes=-0", "bytes=25-30,40-"] {
        match store.serve(&id, Some(h)).unwrap() {
            ServeOutcome::Unsatisfiable {
                size,
                content_range,
            } => {
                assert_eq!(size, 20, "{h}");
                assert_eq!(content_range, "bytes */20");
            }
            other => panic!("{h}: {other:?}"),
        }
    }
    // Malformed, reversed, and non-bytes units are ignored: full response.
    for h in [
        "bytes=5-2",
        "bytes=abc",
        "items=0-1",
        "bytes",
        "bytes=",
        "bytes=1-2-3",
    ] {
        assert!(
            matches!(store.serve(&id, Some(h)).unwrap(), ServeOutcome::Full(_)),
            "{h}"
        );
    }
    // Multiple ranges, with one unsatisfiable dropped.
    match store.serve(&id, Some("bytes=0-1, 50-60, 18-")).unwrap() {
        ServeOutcome::Partial(v) => {
            let got: Vec<Vec<u8>> = v.into_iter().map(|(_, r)| read_all(r)).collect();
            assert_eq!(got, vec![b"01".to_vec(), b"ij".to_vec()]);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        store
            .serve(&ObjectId::parse(&"0".repeat(64)).unwrap(), None)
            .unwrap(),
        ServeOutcome::NotFound
    ));
}

#[test]
fn zero_length_object_serving() {
    let (_d, _db, store) = setup();
    let id = store.put_bytes(&desc("empty", b""), b"").unwrap();
    let ServeOutcome::Full(r) = store.serve(&id, None).unwrap() else {
        panic!()
    };
    assert_eq!(r.len(), 0);
    assert!(read_all(r).is_empty());
    assert!(matches!(
        store.serve(&id, Some("bytes=0-0")).unwrap(),
        ServeOutcome::Unsatisfiable { size: 0, .. }
    ));
    assert!(matches!(
        store.serve(&id, Some("bytes=-1")).unwrap(),
        ServeOutcome::Unsatisfiable { .. }
    ));
}

#[test]
fn object_ids_reject_path_tricks() {
    for bad in [
        "../etc/passwd",
        "",
        &"A".repeat(64),
        &"g".repeat(64),
        &"a".repeat(63),
    ] {
        assert!(ObjectId::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn crash_between_promote_and_commit_is_completed() {
    let (_d, db, store) = setup();
    let d = desc("a.cab", DATA);
    // Simulate: partial row marked promoting, object renamed into place, no record.
    let up = store.begin(&d).unwrap();
    let pid = up.partial_id();
    let id = ObjectId::from_sha256(&Sha256::digest(DATA)).unwrap();
    let dest = store.object_path(&id);
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::write(&dest, DATA).unwrap();
    drop(up);
    db.transaction(|tx| {
        tx.execute(
            "UPDATE content_partials SET state='promoting', target_object=?2 WHERE partial_id=?1",
            rusqlite::params![pid.to_string(), id.as_str()],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(store.info(&id).unwrap().is_none());
    let report = store.reconcile(false).unwrap();
    assert_eq!(report.completed_promotions, vec![id.clone()]);
    assert_eq!(store.find_available(&d).unwrap(), Some(id));
}

#[test]
fn orphan_objects_quarantined_stale_partials_discarded_missing_marked() {
    let (dir, db, store) = setup();
    // Orphan promoted object, no record.
    let orphan = ObjectId::from_sha256(&Sha256::digest(b"orphan")).unwrap();
    let p = store.object_path(&orphan);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, b"orphan").unwrap();
    // Stale receiving partial and stray partial file.
    let mut up = store.begin(&desc("s", DATA)).unwrap();
    up.write_all(&DATA[..3]).unwrap();
    drop(up);
    fs::write(dir.path().join("content/partial/stray.part"), b"x").unwrap();
    // Recorded object whose file vanished.
    let d = desc("gone", DATA);
    let gone = store.put_bytes(&d, DATA).unwrap();
    fs::remove_file(store.object_path(&gone)).unwrap();
    assert!(store.info(&gone).unwrap().is_none());

    let report = store.reconcile(false).unwrap();
    assert_eq!(report.quarantined_objects, vec![orphan]);
    assert_eq!(report.discarded_partials, 2);
    assert_eq!(report.missing_objects, vec![gone.clone()]);
    assert!(!p.exists());
    assert!(store.find_available(&d).unwrap().is_none());

    // The object returns (restored from backup): reconciliation re-enables it.
    fs::write(store.object_path(&gone), DATA).unwrap();
    let report = store.reconcile(false).unwrap();
    assert_eq!(report.restored_objects, vec![gone.clone()]);
    assert!(store.info(&gone).unwrap().is_some());
    drop(db);
}

#[test]
fn deep_reconcile_catches_bit_rot() {
    let (_d, _db, store) = setup();
    let id = store.put_bytes(&desc("a", DATA), DATA).unwrap();
    let mut rotted = DATA.to_vec();
    rotted[3] ^= 0xff;
    fs::write(store.object_path(&id), &rotted).unwrap();
    assert!(!store.verify(&id).unwrap());
    // Shallow pass trusts size; deep pass catches it.
    assert!(store.reconcile(false).unwrap().corrupt_objects.is_empty());
    let report = store.reconcile(true).unwrap();
    assert_eq!(report.corrupt_objects, vec![id.clone()]);
    assert!(store.info(&id).unwrap().is_none());
}

#[test]
fn gc_respects_references_pins_partials_and_leases() {
    let (_d, db, store) = setup();
    let cat = Catalog::new(db.clone());
    let src = cat.add_source("s", SourceKind::Upstream, "").unwrap();

    let referenced = desc("ref", b"referenced-bytes");
    let unreferenced = desc("unref", b"unreferenced-bytes");
    let pinned = desc("pin", b"pinned-bytes");
    let leased = desc("lease", b"leased-bytes");
    let r = store.put_bytes(&referenced, b"referenced-bytes").unwrap();
    let u = store
        .put_bytes(&unreferenced, b"unreferenced-bytes")
        .unwrap();
    let p = store.put_bytes(&pinned, b"pinned-bytes").unwrap();
    let l = store.put_bytes(&leased, b"leased-bytes").unwrap();
    store.pin(&p, "job-1").unwrap();

    let mut f = FragmentImport::new(
        UpdateRevision {
            id: UpdateId(Uuid::from_u128(1)),
            revision: Revision(1),
        },
        "Software",
        b"<u/>",
    );
    f.files.push(FileDescriptor {
        file_name: "ref".into(),
        size: referenced.size,
        digests: referenced.digests.clone(),
    });
    // Staged (not yet active) metadata also protects content.
    let g = cat.begin_generation(src, None).unwrap();
    cat.import_fragments(g, &[f]).unwrap();

    let reader = match store.serve(&l, None).unwrap() {
        ServeOutcome::Full(r) => r,
        o => panic!("{o:?}"),
    };
    let report = store.gc(Duration::ZERO).unwrap();
    assert_eq!(report.removed, vec![u.clone()]);
    assert_eq!(report.skipped_leased, vec![l.clone()]);
    assert!(store.info(&u).unwrap().is_none());
    for keep in [&r, &p, &l] {
        assert!(store.info(keep).unwrap().is_some());
    }
    // Reader still works after GC attempt; once dropped the object is collectable.
    assert_eq!(read_all(reader), b"leased-bytes");
    store.unpin(&p, "job-1").unwrap();
    let report = store.gc(Duration::ZERO).unwrap();
    assert!(report.removed.contains(&p) && report.removed.contains(&l));
    assert!(!report.removed.contains(&r));

    // An in-flight partial for the same descriptor protects an existing object.
    let again = store
        .put_bytes(&unreferenced, b"unreferenced-bytes")
        .unwrap();
    let up = store.begin(&unreferenced).unwrap();
    assert!(store.gc(Duration::ZERO).unwrap().removed.is_empty());
    up.abort().unwrap();
    // min_age protects freshly promoted objects.
    assert!(
        store
            .gc(Duration::from_secs(3600))
            .unwrap()
            .removed
            .is_empty()
    );
    assert_eq!(store.gc(Duration::ZERO).unwrap().removed, vec![again]);
}

#[test]
fn concurrent_serving_and_gc_do_not_race() {
    let (_d, _db, store) = setup();
    let id = store.put_bytes(&desc("a", DATA), DATA).unwrap();
    let s2 = store.clone();
    let id2 = id.clone();
    let t = std::thread::spawn(move || {
        let mut ok = 0;
        for _ in 0..200 {
            match s2.serve(&id2, Some("bytes=0-9")).unwrap() {
                ServeOutcome::Partial(mut v) => {
                    assert_eq!(read_all(v.remove(0).1), b"0123456789");
                    ok += 1;
                }
                ServeOutcome::NotFound => {}
                o => panic!("{o:?}"),
            }
        }
        ok
    });
    for _ in 0..50 {
        store.gc(Duration::ZERO).unwrap();
    }
    t.join().unwrap();
}
