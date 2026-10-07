//! MS-WUSP session behaviour against the in-process fake server (spec-derived;
//! not validated against a real WSUS).

mod session_common;

use session_common::*;
use std::fs;
use wsus_client::{
    session::{SessionConfig, WuspError},
    state::{RegistrationState, StateStore},
    sync::SyncOptions,
    transport::{
        HttpResponse, ImmediateTimer, RetryPolicy, TransportError,
        mock::{MockStep, MockTransport},
    },
};
use wsus_protocol::{identity::ServerId, soap::ErrorCode};

fn seeded() -> Harness {
    let h = Harness::new();
    {
        let mut f = h.fake();
        f.add(1, 1, true);
    }
    h
}

#[tokio::test]
async fn handshake_sequence_then_cookie_reuse() {
    let h = seeded();
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(
        h.ops(),
        [
            "GetConfig",
            "GetAuthorizationCookie",
            "GetCookie",
            "SyncUpdates",
            "SyncUpdates"
        ]
    );
    let stats = e.session().stats();
    assert_eq!((stats.handshakes, stats.cookie_renewals), (1, 0));
}

#[tokio::test]
async fn cookie_is_redacted_in_debug_and_persisted_for_restart() {
    let h = seeded();
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let debug = format!("{:?} {:?}", e.session().state(), e);
    assert!(!debug.contains("636f6f6b6965"), "hex of cookie leaked");
    assert!(debug.contains("redacted"));
    drop(e);
    // Restart: the persisted cookie is reused, no new handshake.
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(h.fake().count("GetConfig"), 1);
    assert_eq!(h.fake().count("GetCookie"), 1);
}

#[tokio::test]
async fn cookie_is_renewed_before_expiry_without_get_config() {
    let h = seeded();
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    // 3600 s lifetime, 300 s skew.
    h.clock.advance(3400);
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(h.fake().count("GetConfig"), 1);
    assert_eq!(h.fake().count("GetAuthorizationCookie"), 2);
    assert_eq!(h.fake().count("GetCookie"), 2);
    assert_eq!(h.fake().old_cookies_seen, [false, true]);
    assert_eq!(e.session().stats().cookie_renewals, 1);
    assert_eq!(e.session().stats().recoveries, 0);
}

#[tokio::test]
async fn cookie_expired_fault_renews_and_retries_once() {
    let h = seeded();
    let mut e = h.engine();
    e.session_mut().ensure_ready().await.unwrap();
    h.fake()
        .faults
        .push_back(("SyncUpdates".into(), ErrorCode::CookieExpired));
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 1);
    assert_eq!(h.fake().count("SyncUpdates"), 2);
    assert_eq!(e.session().stats().recoveries, 1);
    assert_eq!(h.fake().count("GetConfig"), 1);
}

#[tokio::test]
async fn config_change_fault_restarts_handshake_and_records_generation() {
    let h = seeded();
    let mut e = h.engine();
    e.session_mut().ensure_ready().await.unwrap();
    let before = e.session().state().config_generation.clone();
    h.fake().last_change = "2024-02-02T00:00:00Z".into();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let stats = e.session().stats();
    assert_eq!(
        (stats.handshakes, stats.config_changes, stats.recoveries),
        (2, 1, 1)
    );
    assert_ne!(e.session().state().config_generation, before);
    assert_eq!(
        e.session().state().config_generation.as_deref(),
        Some("2024-02-02T00:00:00Z")
    );
}

#[tokio::test]
async fn config_change_is_detected_after_restart() {
    let h = seeded();
    let mut e = h.engine();
    e.session_mut().ensure_ready().await.unwrap();
    drop(e);
    h.fake().last_change = "2024-03-03T00:00:00Z".into();
    h.clock.advance(7200); // cookie expired: a restart must renew via GetConfig
    let mut s = h.session();
    s.ensure_ready().await.unwrap();
    assert_eq!(s.stats().config_changes, 1);
    assert_eq!(s.stats().handshakes, 1);
}

#[tokio::test]
async fn registration_when_required_is_done_once_and_persisted() {
    let h = seeded();
    h.fake().registration_required = true;
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(h.fake().registered);
    assert_eq!(h.fake().count("RegisterComputer"), 1);
    assert!(matches!(
        e.session().state().registration,
        RegistrationState::Registered { .. }
    ));
    drop(e);
    h.clock.advance(7200);
    let mut s = h.session();
    s.ensure_ready().await.unwrap();
    assert_eq!(
        h.fake().count("RegisterComputer"),
        1,
        "registered state survives a restart"
    );
}

#[tokio::test]
async fn registration_required_without_computer_info_is_a_config_error() {
    let h = seeded();
    h.fake().registration_required = true;
    let mut cfg = h.config();
    cfg.computer_info = None;
    let mut s = h.session_with(cfg);
    assert!(matches!(s.ensure_ready().await, Err(WuspError::Config(_))));
}

#[tokio::test]
async fn registration_required_fault_registers_then_repeats_the_call() {
    let h = seeded();
    let mut e = h.engine();
    e.session_mut().ensure_ready().await.unwrap();
    // The server starts requiring registration after the session began.
    h.fake().registration_required = true;
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(report.new_revisions, 1);
    assert_eq!(h.fake().count("RegisterComputer"), 1);
    assert_eq!(h.fake().count("SyncUpdates"), 2);
}

#[tokio::test]
async fn different_server_discards_server_local_state() {
    let h = seeded();
    let mut cfg = h.config();
    cfg.server_id = Some(ServerId(uuid::Uuid::from_u128(1)));
    let mut e = h.engine_with(cfg.clone());
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let computer = e.session().state().computer_id;
    assert_eq!(e.session().state().cached_revisions.len(), 1);
    drop(e);
    cfg.server_id = Some(ServerId(uuid::Uuid::from_u128(2)));
    let s = h.session_with(cfg);
    assert_eq!(s.stats().server_changes, 1);
    assert!(s.state().cached_revisions.is_empty());
    assert!(s.state().cookie.is_none());
    assert_eq!(
        s.state().computer_id,
        computer,
        "computer identity is stable"
    );
}

#[tokio::test]
async fn server_changed_fault_restarts_handshake_and_refreshes_cache() {
    let h = Harness::new();
    {
        let mut f = h.fake();
        f.add(1, 1, true);
        f.add(2, 1, false);
    }
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    // Server restored from another database: new epoch, new local ids.
    {
        let mut f = h.fake();
        f.cookie_epoch = 2;
        f.server_changed_fault = true;
        for (i, r) in f.revisions.iter_mut().enumerate() {
            r.local_id = 900 + i as i32;
        }
    }
    let report = e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(
        report.unchanged,
        "nothing is re-sent after refresh: {report:?}"
    );
    assert_eq!(h.fake().count("RefreshCache"), 1);
    let ids: Vec<i32> = e
        .session()
        .state()
        .cached_revisions
        .values()
        .map(|c| c.local_revision_id.unwrap())
        .collect();
    assert_eq!(ids, [900, 901]);
    assert!(h.fake().sent_counts.values().all(|n| *n == 1));
}

#[tokio::test]
async fn recovery_is_bounded_per_call_and_never_restarts_forever() {
    let h = seeded();
    let mut e = h.engine();
    h.fake()
        .always_fault
        .insert("SyncUpdates".into(), ErrorCode::CookieExpired);
    let err = e.sync_updates(&SyncOptions::default()).await.unwrap_err();
    assert!(
        matches!(
            err,
            wsus_client::sync::SyncError::Session(WuspError::RecoveryExhausted { .. })
        ),
        "{err:?}"
    );
    let f = h.fake();
    // initial + 3 recoveries
    assert_eq!(f.count("SyncUpdates"), 4);
    assert!(f.calls.len() < 20, "{:?}", f.calls);
}

#[tokio::test]
async fn recovery_budget_is_bounded_per_run_across_operations() {
    let h = seeded();
    let mut cfg = h.config();
    cfg.max_recoveries_per_call = 100;
    cfg.max_recoveries_per_run = 2;
    let mut e = h.engine_with(cfg);
    h.fake()
        .always_fault
        .insert("SyncUpdates".into(), ErrorCode::ConfigChanged);
    let err = e.sync_updates(&SyncOptions::default()).await.unwrap_err();
    assert!(err.to_string().contains("recovery budget"), "{err}");
    assert!(h.fake().count("GetConfig") <= 3);
}

#[tokio::test]
async fn faults_without_specified_recovery_are_returned_immediately() {
    let h = seeded();
    let mut e = h.engine();
    h.fake()
        .faults
        .push_back(("SyncUpdates".into(), ErrorCode::InvalidParameters));
    let err = e.sync_updates(&SyncOptions::default()).await.unwrap_err();
    // InvalidParameters on SyncUpdates is reported as a typed error naming the
    // cached-list sizes; it is not retried.
    assert!(
        matches!(err, wsus_client::sync::SyncError::CachedListRejected { .. }),
        "{err:?}"
    );
    assert_eq!(h.fake().count("SyncUpdates"), 1);
}

#[tokio::test]
async fn server_busy_is_retried_with_bounded_backoff() {
    let h = seeded();
    let mut cfg = h.config();
    cfg.retry = RetryPolicy::default();
    let mut e = h.engine_with(cfg);
    h.fake()
        .faults
        .push_back(("SyncUpdates".into(), ErrorCode::ServerBusy));
    h.fake()
        .faults
        .push_back(("SyncUpdates".into(), ErrorCode::ServerBusy));
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    assert_eq!(h.fake().count("SyncUpdates"), 3);
    assert_eq!(e.session().stats().recoveries, 0);
    // Persistently busy: gives up after max_retries.
    h.fake()
        .always_fault
        .insert("SyncUpdates".into(), ErrorCode::ServerBusy);
    let before = h.fake().count("SyncUpdates");
    assert!(e.sync_updates(&SyncOptions::default()).await.is_err());
    assert_eq!(h.fake().count("SyncUpdates") - before, 4);
}

#[tokio::test]
async fn error_taxonomy_transport_http_metadata_storage() {
    // Transport.
    let t = MockTransport::scripted(vec![MockStep::Fail(TransportError::connect("refused"))]);
    let h = Harness::new();
    let mut s = wsus_client::session::WuspSession::new(
        t,
        ImmediateTimer,
        h.clock.clone(),
        h.config(),
        StateStore::open(h.state_path()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        s.ensure_ready().await,
        Err(WuspError::Transport(_))
    ));

    // HTTP status without a SOAP body.
    let t = MockTransport::scripted(vec![MockStep::Respond(HttpResponse::new(
        502,
        b"bad gateway".to_vec(),
    ))]);
    let h = Harness::new();
    let mut s = wsus_client::session::WuspSession::new(
        t,
        ImmediateTimer,
        h.clock.clone(),
        h.config(),
        StateStore::open(h.state_path()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        s.ensure_ready().await,
        Err(WuspError::Http { status: 502, .. })
    ));

    // Malformed success body is a metadata/decoding failure.
    let t = MockTransport::scripted(vec![MockStep::Respond(HttpResponse::new(
        200,
        b"<not-soap/>".to_vec(),
    ))]);
    let h = Harness::new();
    let mut s = wsus_client::session::WuspSession::new(
        t,
        ImmediateTimer,
        h.clock.clone(),
        h.config(),
        StateStore::open(h.state_path()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        s.ensure_ready().await,
        Err(WuspError::Metadata(_))
    ));

    // Local storage: the state directory disappears before the cookie is saved.
    let h = seeded();
    let mut s = h.session();
    fs::remove_dir_all(h.state_path().parent().unwrap()).unwrap();
    assert!(matches!(s.ensure_ready().await, Err(WuspError::Storage(_))));
}

#[tokio::test]
async fn retries_follow_operation_idempotence() {
    // GetConfig (idempotent) is retried after a mid-flight failure ...
    let h = seeded();
    let mut cfg = h.config();
    cfg.retry = RetryPolicy::default();
    let mut s = h.session_with(cfg.clone());
    h.fake().transport_failures.push_back("GetConfig".into());
    s.ensure_ready().await.unwrap();
    assert_eq!(h.fake().count("GetConfig"), 2);

    // ... RegisterComputer (non-idempotent) is not, after the request may have
    // been processed.
    let h = seeded();
    h.fake().registration_required = true;
    let mut s = h.session_with(cfg);
    h.fake()
        .transport_failures
        .push_back("RegisterComputer".into());
    assert!(matches!(
        s.ensure_ready().await,
        Err(WuspError::Transport(_))
    ));
    assert_eq!(h.fake().count("RegisterComputer"), 1);
    // The unconfirmed attempt is persisted as Pending and re-resolved later.
    assert!(matches!(
        s.state().registration,
        RegistrationState::Pending { .. }
    ));
    s.ensure_ready().await.unwrap();
    assert!(matches!(
        s.state().registration,
        RegistrationState::Registered { .. }
    ));
}

#[test]
fn config_defaults_are_documented_paths() {
    let c = SessionConfig::new("http://h:1/", "d");
    assert_eq!(c.base_url, "http://h:1");
    assert!(c.client_path.ends_with("Client.asmx"));
}
