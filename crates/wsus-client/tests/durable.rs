use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
};
use tempfile::TempDir;
use uuid::Uuid;
use wsus_client::{
    reporting::{AppendOutcome, EventQueue, QueueConfig, QueueError},
    state::{
        CachedRevision, RegistrationState, StateError, StateStore, StoredCookie, SyncCheckpoint,
    },
    transport::SecretBytes,
};
use wsus_protocol::identity::{ComputerId, Revision, ServerId, UpdateId, UpdateRevision};

fn open(dir: &TempDir) -> EventQueue {
    EventQueue::open(dir.path().join("q"), QueueConfig::default()).unwrap()
}

#[test]
fn queue_survives_restart_and_acks_are_durable() {
    let dir = TempDir::new().unwrap();
    let mut q = open(&dir);
    for i in 0..5 {
        assert_eq!(
            q.append(&format!("k{i}"), json!({"n": i})).unwrap(),
            AppendOutcome::Queued { seq: i }
        );
    }
    assert_eq!(q.ack(&[1, 3, 99]).unwrap(), 2);
    drop(q); // crash: no clean shutdown step exists

    let mut q = open(&dir);
    let seqs: Vec<u64> = q.pending(10).iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![0, 2, 4]);
    assert_eq!(q.pending(10)[1].payload, json!({"n": 2}));
    // Sequence numbers are never reused.
    assert_eq!(
        q.append("k9", json!(null)).unwrap(),
        AppendOutcome::Queued { seq: 5 }
    );
    assert_eq!(q.pending(2).len(), 2);
}

#[test]
fn dedup_keys_cover_pending_and_acknowledged_events() {
    let dir = TempDir::new().unwrap();
    let mut q = open(&dir);
    assert_eq!(
        q.append("a", json!(1)).unwrap(),
        AppendOutcome::Queued { seq: 0 }
    );
    assert_eq!(
        q.append("a", json!(2)).unwrap(),
        AppendOutcome::Duplicate { seq: 0 }
    );
    q.ack(&[0]).unwrap();
    assert_eq!(
        q.append("a", json!(3)).unwrap(),
        AppendOutcome::AlreadyDelivered
    );
    drop(q);
    let mut q = open(&dir);
    assert_eq!(
        q.append("a", json!(4)).unwrap(),
        AppendOutcome::AlreadyDelivered
    );
    assert!(q.is_empty());
    assert!(matches!(
        q.append("bad key", json!(1)),
        Err(QueueError::InvalidKey)
    ));
    assert!(matches!(
        q.append("", json!(1)),
        Err(QueueError::InvalidKey)
    ));
}

#[test]
fn torn_final_record_is_truncated_on_replay() {
    let dir = TempDir::new().unwrap();
    let mut q = open(&dir);
    q.append("a", json!(1)).unwrap();
    q.append("b", json!(2)).unwrap();
    drop(q);
    let log = dir.path().join("q/events.log");
    let good_len = fs::metadata(&log).unwrap().len();
    OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(b"deadbeef00000000 {\"t\":\"ev")
        .unwrap();
    let mut q = open(&dir);
    assert_eq!(q.len(), 2);
    assert_eq!(fs::metadata(&log).unwrap().len(), good_len);
    // The queue is writable again after recovery and replays cleanly.
    q.append("c", json!(3)).unwrap();
    drop(q);
    assert_eq!(open(&dir).len(), 3);
}

#[test]
fn corruption_before_the_tail_is_reported() {
    let dir = TempDir::new().unwrap();
    let mut q = open(&dir);
    for k in ["a", "b", "c"] {
        q.append(k, json!(k)).unwrap();
    }
    drop(q);
    let log = dir.path().join("q/events.log");
    let mut bytes = fs::read(&log).unwrap();
    let first_newline = bytes.iter().position(|b| *b == b'\n').unwrap();
    bytes[first_newline + 20] ^= 0x01;
    fs::write(&log, bytes).unwrap();
    let err = EventQueue::open(dir.path().join("q"), QueueConfig::default()).unwrap_err();
    assert!(matches!(err, QueueError::Corrupt { record: 1 }), "{err:?}");
}

#[test]
fn limits_and_compaction() {
    let dir = TempDir::new().unwrap();
    let cfg = QueueConfig {
        max_pending: 3,
        max_payload_bytes: 16,
        dedup_history: 2,
    };
    let mut q = EventQueue::open(dir.path().join("q"), cfg).unwrap();
    assert!(matches!(
        q.append("big", json!("x".repeat(64))),
        Err(QueueError::PayloadTooLarge(_))
    ));
    for k in ["a", "b", "c"] {
        q.append(k, json!(1)).unwrap();
    }
    assert!(matches!(q.append("d", json!(1)), Err(QueueError::Full(3))));
    q.ack(&[0, 1]).unwrap();
    q.compact().unwrap();
    let before = fs::metadata(dir.path().join("q/events.log")).unwrap().len();
    drop(q);
    let mut q = EventQueue::open(dir.path().join("q"), cfg).unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(
        q.append("a", json!(1)).unwrap(),
        AppendOutcome::AlreadyDelivered
    );
    assert_eq!(
        q.append("e", json!(1)).unwrap(),
        AppendOutcome::Queued { seq: 3 }
    );
    assert!(before > 0);
    assert!(!format!("{:?}", q.pending(1)[0]).contains("payload"));
}

#[cfg(unix)]
#[test]
fn queue_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let mut q = open(&dir);
    q.append("a", json!(1)).unwrap();
    let mode = |p: &str| {
        fs::metadata(dir.path().join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("q"), 0o700);
    assert_eq!(mode("q/events.log"), 0o600);
}

fn rev(n: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(Uuid::from_u128(7)),
        revision: Revision(n),
    }
}

#[test]
fn state_round_trips_across_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s/state.json");
    let computer = ComputerId(Uuid::new_v4());
    let server = ServerId(Uuid::new_v4());
    let mut store = StateStore::open(&path).unwrap();
    assert_eq!(store.state().write_counter, 0);
    store
        .update(|s| {
            s.computer_id = Some(computer);
            s.source_server = Some(server);
            s.config_generation = Some("cfg-7".into());
            s.cookie = Some(StoredCookie {
                expires_unix: 1000,
                data: SecretBytes::new(vec![1, 2, 3, 255]),
            });
            s.registration = RegistrationState::Registered { at_unix: 5 };
            s.sync_checkpoint = Some(SyncCheckpoint {
                anchor: "anchor-1".into(),
                committed_unix: 6,
            });
            s.cached_revisions.insert(
                rev(2),
                CachedRevision {
                    local_revision_id: Some(42),
                    metadata_sha256: None,
                },
            );
            s.cached_revisions.insert(rev(1), CachedRevision::default());
        })
        .unwrap();
    drop(store);

    let store = StateStore::open(&path).unwrap();
    let s = store.state();
    assert_eq!(s.write_counter, 1);
    assert_eq!(s.computer_id, Some(computer));
    assert_eq!(s.source_server, Some(server));
    assert_eq!(s.cookie.as_ref().unwrap().data.expose(), &[1, 2, 3, 255]);
    assert!(s.cookie.as_ref().unwrap().is_expired(990, 10));
    assert!(!s.cookie.as_ref().unwrap().is_expired(900, 10));
    assert_eq!(s.cached_revisions.len(), 2);
    assert_eq!(s.cached_revisions[&rev(2)].local_revision_id, Some(42));
    assert_eq!(s.registration, RegistrationState::Registered { at_unix: 5 });
}

#[test]
fn state_debug_redacts_cookie() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
    store
        .update(|s| {
            s.cookie = Some(StoredCookie {
                expires_unix: 1,
                data: SecretBytes::new(vec![0xAB, 0xCD, 0xEF]),
            })
        })
        .unwrap();
    let text = format!("{store:?}");
    assert!(
        !text.contains("abcdef") && !text.contains("171") && text.contains("<redacted>"),
        "{text}"
    );
}

#[cfg(unix)]
#[test]
fn state_file_is_private_and_loose_permissions_are_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("priv/state.json");
    let mut store = StateStore::open(&path).unwrap();
    store
        .update(|s| s.config_generation = Some("x".into()))
        .unwrap();
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    drop(StateStore::open(&path).unwrap());
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn crash_during_write_leaves_previous_state_and_stale_temp_is_cleaned() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let mut store = StateStore::open(&path).unwrap();
    store
        .update(|s| s.config_generation = Some("old".into()))
        .unwrap();
    drop(store);
    // A crash between temp write and rename leaves a (possibly torn) temp file.
    let stale = dir.path().join(".state.json.tmp.99999.0");
    fs::write(&stale, b"{\"version\":1,\"torn").unwrap();
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.state().config_generation.as_deref(), Some("old"));
    assert!(!stale.exists());
}

#[test]
fn corrupt_or_future_state_is_an_error_not_a_reset() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    fs::write(&path, b"{ nope").unwrap();
    assert!(matches!(
        StateStore::open(&path),
        Err(StateError::Corrupt(_))
    ));
    let mut store = StateStore::open(dir.path().join("ok.json")).unwrap();
    store.update(|_| {}).unwrap();
    let text = fs::read_to_string(dir.path().join("ok.json"))
        .unwrap()
        .replace("\"version\": 1", "\"version\": 9");
    fs::write(&path, text).unwrap();
    assert!(matches!(
        StateStore::open(&path),
        Err(StateError::UnsupportedVersion(9))
    ));
}
