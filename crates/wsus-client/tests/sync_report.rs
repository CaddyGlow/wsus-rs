//! Durable event reporting through ReportEventBatch (spec-derived fake; not
//! validated against a real WSUS).

mod session_common;

use session_common::*;
use std::collections::BTreeSet;
use uuid::Uuid;
use wsus_client::{
    reporting::{AppendOutcome, EventQueue, QueueConfig},
    sync::{ReportEvent, SyncError},
};

fn event(n: u128, event_id: i16) -> ReportEvent {
    ReportEvent {
        event_instance_id: Uuid::from_u128(n),
        sequence_number: n as i32,
        time_at_target: "2024-01-01T00:00:00Z".into(),
        namespace_id: 1,
        event_id,
        source_id: 0,
        update: Some(rev(1, 1)),
        win32_hresult: 0,
        app_name: Some("test".into()),
        detail: None,
    }
}

fn queue(h: &Harness) -> EventQueue {
    EventQueue::open(h.dir.path().join("events"), QueueConfig::default()).unwrap()
}

#[tokio::test]
async fn events_are_sent_in_batches_and_acknowledged_after_success() {
    let h = Harness::new();
    let mut q = queue(&h);
    for n in 1..=5 {
        assert!(matches!(
            event(n, 1).enqueue(&mut q).unwrap(),
            AppendOutcome::Queued { .. }
        ));
    }
    let mut e = h.engine();
    let out = e.flush_events(&mut q, 2).await.unwrap();
    assert_eq!((out.batches, out.delivered), (3, 5));
    assert!(q.is_empty());
    assert_eq!(h.fake().reported.len(), 5);
    // Nothing left: no further request, no repeat.
    let out = e.flush_events(&mut q, 2).await.unwrap();
    assert_eq!(out.batches, 0);
    assert_eq!(h.fake().count("ReportEventBatch"), 3);
}

#[tokio::test]
async fn repeated_reports_are_not_duplicated() {
    let h = Harness::new();
    let mut q = queue(&h);
    assert!(matches!(
        event(1, 1).enqueue(&mut q).unwrap(),
        AppendOutcome::Queued { .. }
    ));
    assert!(matches!(
        event(1, 1).enqueue(&mut q).unwrap(),
        AppendOutcome::Duplicate { .. }
    ));
    let mut e = h.engine();
    e.flush_events(&mut q, 10).await.unwrap();
    // After acknowledgement the same event cannot be queued again.
    assert_eq!(
        event(1, 1).enqueue(&mut q).unwrap(),
        AppendOutcome::AlreadyDelivered
    );
    e.flush_events(&mut q, 10).await.unwrap();
    assert_eq!(h.fake().reported, [Uuid::from_u128(1)]);
}

#[tokio::test]
async fn lost_response_keeps_events_queued_and_resend_reuses_instance_ids() {
    let h = Harness::new();
    let mut q = queue(&h);
    for n in 1..=3 {
        event(n, 1).enqueue(&mut q).unwrap();
    }
    h.fake().report_mode = ReportMode::LoseResponseOnce;
    let mut e = h.engine();
    let err = e.flush_events(&mut q, 10).await.unwrap_err();
    assert!(matches!(err, SyncError::Session(_)));
    assert_eq!(q.len(), 3, "not acknowledged without a response");
    // Non-idempotent: no automatic replay inside the failed call.
    assert_eq!(h.fake().count("ReportEventBatch"), 1);

    // Restart: events survive and are sent again.
    drop(q);
    drop(e);
    let mut q = queue(&h);
    let mut e = h.engine();
    e.flush_events(&mut q, 10).await.unwrap();
    assert!(q.is_empty());
    let f = h.fake();
    assert_eq!(
        f.reported.len(),
        6,
        "delivered twice at the transport level"
    );
    let unique: BTreeSet<_> = f.reported.iter().collect();
    assert_eq!(
        unique.len(),
        3,
        "same EventInstanceIDs, so the server can de-duplicate"
    );
}

#[tokio::test]
async fn fault_leaves_events_queued() {
    let h = Harness::new();
    let mut q = queue(&h);
    event(1, 1).enqueue(&mut q).unwrap();
    h.fake().faults.push_back((
        "ReportEventBatch".into(),
        wsus_protocol::soap::ErrorCode::InvalidParameters,
    ));
    let mut e = h.engine();
    assert!(e.flush_events(&mut q, 10).await.is_err());
    assert_eq!(q.len(), 1);
}

#[tokio::test]
async fn undecodable_and_disallowed_events_do_not_block_the_queue() {
    let h = Harness::new();
    h.fake().allowed_events = vec![1];
    let mut q = queue(&h);
    q.append("garbage", serde_json::json!({"not": "an event"}))
        .unwrap();
    event(2, 99).enqueue(&mut q).unwrap(); // not in AllowedEventIds
    event(3, 1).enqueue(&mut q).unwrap();
    let mut e = h.engine();
    // AllowedEventIds is known after the handshake.
    e.session_mut().ensure_ready().await.unwrap();
    let out = e.flush_events(&mut q, 10).await.unwrap();
    assert_eq!(
        (out.dropped_invalid, out.dropped_not_allowed, out.delivered),
        (1, 1, 1)
    );
    assert!(q.is_empty());
    assert_eq!(h.fake().reported, [Uuid::from_u128(3)]);
}
