//! Our client against our server, in process.
//!
//! EVIDENCE STATUS: these tests prove only that this workspace's client and
//! this workspace's server are consistent with each other (and with the pinned
//! specification text both were written from). They are NOT WSUS compatibility
//! evidence: no real WSUS server and no native Windows Update client takes part.
//! The server is assembled through the CLI's own `server_cmd::open`, the
//! administration goes through the CLI's `admin` functions, and the client
//! through the CLI's `client_cmd` functions.

mod common;

use common::*;
use sha2::{Digest, Sha256};
use std::fs;
use uuid::Uuid;
use wsus_cli::{
    admin,
    client_cmd::{self, ReportArgs, Selection},
    output::Output,
};
use wsus_client::{
    reporting::{AppendOutcome, EventQueue, QueueConfig},
    sync::{ReportEvent, SyncEngine},
    transport::ImmediateTimer,
};

type Engine = SyncEngine<Bridge, ImmediateTimer, SharedClock>;

fn engine(d: &Deployment) -> Engine {
    client_cmd::open_engine(&d.config, d.bridge.clone(), ImmediateTimer, d.clock.clone()).unwrap()
}

async fn sync(e: &mut Engine, d: &Deployment) -> Output {
    client_cmd::sync(e, &d.config).await.unwrap().0
}

async fn download_all(e: &mut Engine, d: &Deployment) -> Output {
    client_cmd::download(e, &d.config, &Selection::All, false)
        .await
        .unwrap()
        .0
}

fn approve(d: &Deployment, n: u128) {
    admin::approval_set(
        &d.admin(),
        None,
        &update_id(n).to_string(),
        "All Computers",
        "install",
        None,
    )
    .unwrap();
}

const PAYLOAD_LEN: usize = 200_000;

#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_visible_until_approval_then_download_is_verified() {
    let d = Deployment::new();
    let data = payload(PAYLOAD_LEN);
    let rev = seed_update(&d.admin(), "upstream", 1, "payload.bin", &data);
    let mut e = engine(&d);

    // Imported but not approved: the client sees an empty scope.
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["visible_revisions"], 0, "{}", out.value);
    assert_eq!(out.value["new_revisions"], 0);
    let listed = admin::updates_list(&d.admin(), None, None, 10, false).unwrap();
    assert_eq!(listed.value["total"], 1);
    assert_eq!(listed.value["updates"][0]["active_approvals"], 0);

    // Approve; the next synchronization delivers it, including the file list.
    approve(&d, 1);
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["new_revisions"], 1, "{}", out.value);
    assert_eq!(out.value["extended_fragments_stored"], 1);
    let inspect = client_cmd::inspect(&e, Some(&rev.to_string())).unwrap();
    assert_eq!(inspect.value["files"][0]["name"], "payload.bin");
    assert_eq!(inspect.value["files"][0]["size"], PAYLOAD_LEN);

    // Verified download; the object on disk is exactly the payload.
    let out = download_all(&mut e, &d).await;
    assert!(out.ok, "{}", out.value);
    assert_eq!(out.value["all_complete"], true);
    let path = out.value["files"][0]["path"].as_str().unwrap().to_owned();
    assert_eq!(fs::read(&path).unwrap(), data);

    // A repeat needs no content transfer: the verified object is reused.
    let gets = d.bridge.content_gets();
    let out = download_all(&mut e, &d).await;
    assert_eq!(out.value["files"][0]["already_complete"], true);
    assert_eq!(d.bridge.content_gets(), gets);

    // Server-side view agrees: one registered computer, an inspectable update.
    let inspect = admin::updates_inspect(&d.admin(), None, &rev.to_string()).unwrap();
    assert_eq!(inspect.value["files"][0]["content_available"], true);
    assert_eq!(inspect.value["approvals"][0]["state"], "active");
    assert_eq!(
        client_cmd::state_summary(&e)["registration"]["state"],
        "registered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_download_resumes_from_the_proven_prefix() {
    let d = Deployment::new();
    let data = payload(PAYLOAD_LEN);
    seed_update(&d.admin(), "upstream", 1, "payload.bin", &data);
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;

    // The connection drops after 90 000 bytes; retries are disabled so the
    // first run fails and leaves a partial object behind.
    d.bridge.state.lock().unwrap().interrupt_next_content_after = Some(90_000);
    let (out, _) = client_cmd::download(&mut e, &d.config, &Selection::All, false)
        .await
        .unwrap();
    assert!(!out.ok, "{}", out.value);
    assert_eq!(out.value["files"][0]["status"], "failed");
    let mut files = Vec::new();
    walk(&d.client_dir().join("content"), &mut files);
    assert!(
        files
            .iter()
            .any(|f| f.to_string_lossy().contains("partial")),
        "a partial object must be kept: {files:?}"
    );
    assert!(
        !files
            .iter()
            .any(|f| f.to_string_lossy().contains("complete/")),
        "nothing may be promoted before verification"
    );

    // A fresh process resumes with a Range request instead of starting over.
    let mut e = engine(&d);
    let out = download_all(&mut e, &d).await;
    assert!(out.ok, "{}", out.value);
    let file = &out.value["files"][0];
    assert!(file["resumed_from"].as_u64().unwrap() > 0, "{file}");
    assert!(d.bridge.ranges().iter().any(|r| r.starts_with("bytes=")));
    assert_eq!(fs::read(file["path"].as_str().unwrap()).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn cookie_expiry_key_rotation_and_config_change_are_recovered() {
    let d = Deployment::new();
    seed_update(&d.admin(), "upstream", 1, "payload.bin", &payload(1000));
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;
    let handshakes = e.session().stats().handshakes;
    assert_eq!(handshakes, 1);

    // Session cookie lifetime passes (240 minutes by default).
    d.clock.advance(5 * 3600);
    // The server ignores an expired old cookie's synchronization state (the
    // specification allows it), so deployment data may be sent again as
    // "changed"; nothing may be new or removed.
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["new_revisions"], 0, "{}", out.value);
    assert_eq!(out.value["removed_revisions"], 0);
    assert_eq!(out.value["visible_revisions"], 1);
    let renewals = e.session().stats().cookie_renewals + e.session().stats().handshakes;
    assert!(renewals > handshakes, "the expired cookie must be renewed");

    // Signing key rotation without keeping the old key invalidates every cookie.
    d.opened.services.sessions.rotate(false).unwrap();
    let before = e.session().stats().recoveries;
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["new_revisions"], 0, "{}", out.value);
    assert_eq!(out.value["visible_revisions"], 1);
    assert!(
        e.session().stats().recoveries > before,
        "InvalidCookie recovery expected"
    );

    // A configuration change advances the generation; the client re-reads it.
    d.opened.services.sessions.bump_config().unwrap();
    let before = e.session().stats().config_changes;
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["new_revisions"], 0, "{}", out.value);
    assert_eq!(out.value["visible_revisions"], 1);
    assert!(e.session().stats().config_changes > before);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_and_client_restarts_keep_sessions_and_incremental_state() {
    let mut d = Deployment::new();
    seed_update(&d.admin(), "upstream", 1, "payload.bin", &payload(1000));
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;
    let computer = client_cmd::state_summary(&e)["computer_id"].clone();

    // Server restart: signing key, catalog and policy come back from disk, so
    // the existing cookie still works and nothing is resent.
    d.restart_server();
    assert!(d.opened.reconcile.quarantined_objects.is_empty());
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["unchanged"], true, "{}", out.value);
    assert_eq!(e.session().stats().handshakes, 1);

    // Client restart: identity, registration and the sync checkpoint persist.
    drop(e);
    let mut e = engine(&d);
    assert_eq!(client_cmd::state_summary(&e)["computer_id"], computer);
    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["unchanged"], true);
    assert_eq!(out.value["visible_revisions"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_removal_hides_the_update() {
    let d = Deployment::new();
    let rev = seed_update(&d.admin(), "upstream", 1, "payload.bin", &payload(1000));
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;
    assert_eq!(
        client_cmd::inspect(&e, None).unwrap().value["updates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let removed =
        admin::approval_remove(&d.admin(), &update_id(1).to_string(), "All Computers", None)
            .unwrap();
    assert_eq!(removed.value["withdrawn"].as_array().unwrap().len(), 1);
    // Removing again is an error rather than a silent no-op.
    assert!(
        admin::approval_remove(&d.admin(), &update_id(1).to_string(), "All Computers", None)
            .is_err()
    );

    let out = sync(&mut e, &d).await;
    assert_eq!(out.value["removed_revisions"], 1, "{}", out.value);
    assert_eq!(out.value["visible_revisions"], 0);
    assert!(
        client_cmd::inspect(&e, None).unwrap().value["updates"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The hidden update can no longer be selected for download.
    let err = client_cmd::download(
        &mut e,
        &d.config,
        &Selection::Updates(vec![rev.to_string()]),
        false,
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("not in the current scope"));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_reports_are_deduplicated_on_both_sides() {
    let d = Deployment::new();
    let rev = seed_update(&d.admin(), "upstream", 1, "payload.bin", &payload(1000));
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;
    let instance = Uuid::new_v4();
    let args = ReportArgs {
        update: Some(rev.to_string()),
        namespace_id: 1,
        event_id: 2,
        source_id: 3,
        hresult: 0,
        sequence: 1,
        instance_id: Some(instance),
        app_name: None,
        job: None,
        inventory: false,
        force: false,
        facts_file: None,
        flush_only: false,
        no_flush: false,
        batch_size: 10,
    };
    let (out, _) = client_cmd::report(&mut e, &d.config, &args).await.unwrap();
    assert_eq!(out.value["flush"]["delivered"], 1, "{}", out.value);

    // Same instance id again: the client queue recognizes it as delivered.
    let (out, _) = client_cmd::report(&mut e, &d.config, &args).await.unwrap();
    assert_eq!(
        out.value["enqueue"]["outcome"], "already_delivered",
        "{}",
        out.value
    );
    assert_eq!(out.value["flush"]["delivered"], 0);

    // The client loses its queue (lost acknowledgement): the same event is
    // sent again and the server must still hold exactly one copy.
    fs::remove_dir_all(client_cmd::paths(&d.config).events_dir).unwrap();
    let mut queue = EventQueue::open(
        &client_cmd::paths(&d.config).events_dir,
        QueueConfig::default(),
    )
    .unwrap();
    let event = ReportEvent {
        event_instance_id: instance,
        sequence_number: 1,
        time_at_target: wsus_client::session::unix_to_xs(
            d.clock.0.load(std::sync::atomic::Ordering::SeqCst),
        )
        .as_str()
        .to_owned(),
        namespace_id: 1,
        event_id: 2,
        source_id: 3,
        update: Some(rev),
        win32_hresult: 0,
        app_name: None,
        detail: None,
    };
    assert!(matches!(
        event.enqueue(&mut queue).unwrap(),
        AppendOutcome::Queued { .. }
    ));
    drop(queue);
    let flush_only = ReportArgs {
        job: None,
        inventory: false,
        force: false,
        facts_file: None,
        flush_only: true,
        ..args
    };
    let (out, _) = client_cmd::report(&mut e, &d.config, &flush_only)
        .await
        .unwrap();
    assert_eq!(out.value["flush"]["delivered"], 1, "{}", out.value);

    let computer = e.session().state().computer_id.unwrap();
    let events = d
        .opened
        .services
        .reporting
        .events_for_computer(computer, None, 100)
        .unwrap();
    assert_eq!(
        events.len(),
        1,
        "server must deduplicate by event instance id"
    );
}

/// A recorded install job that failed, as the executor would have left it.
fn failed_job(
    target: wsus_protocol::identity::UpdateRevision,
) -> wsus_client::install::job::JobRecord {
    use wsus_client::install::{
        handlers::ExitClass,
        job::{Flags, JOB_SCHEMA, JobRecord, JobStatus, PostCheck, StepRecord, StepState},
        plan::{FactsRef, InstallPlan, PayloadRef, PlanOutcome},
    };
    JobRecord {
        schema: JOB_SCHEMA.into(),
        job_id: "job-report-1".into(),
        status: JobStatus::Failed,
        started_at: "2026-10-06T14:56:40Z".into(),
        updated_at: "2026-10-06T14:57:40Z".into(),
        finished_at: Some("2026-10-06T14:57:39Z".into()),
        facts_source: "windows".into(),
        facts_hash: "00".into(),
        plan_hash: "00".into(),
        trusted_signers: Vec::new(),
        flags: Flags {
            allow_unknown: false,
            allow_writable_store: false,
        },
        plan: InstallPlan {
            schema: "wsus-install-plan/2".into(),
            target: target.to_string(),
            allow_unknown: false,
            facts: FactsRef {
                hash: "00".into(),
                queries: 0,
            },
            outcome: PlanOutcome::Install,
            steps: Vec::new(),
            blockers: Vec::new(),
            decisions: Vec::new(),
            notes: Vec::new(),
        },
        steps: vec![StepRecord {
            index: 0,
            update: target.to_string(),
            handler: "cbs".into(),
            payload: PayloadRef::none(),
            state: StepState::Finished,
            program: None,
            arguments: Vec::new(),
            digest_verified: Some(true),
            signature: None,
            exit_code: Some(1603),
            exit_class: Some(ExitClass::Failed),
            timed_out: false,
            refusal: None,
            started_at: None,
            finished_at: None,
            stdout_tail: None,
            stderr_tail: None,
            launcher: None,
            stub_result: None,
            servicing: None,
        }],
        post_check: PostCheck::default(),
        handler_log_excerpt: None,
        defender: None,
        servicing: None,
        recovered: Vec::new(),
        notes: Vec::new(),
        reporting_sent: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_failed_job_is_reported_once_and_the_server_derives_failed() {
    let d = Deployment::new();
    let rev = seed_update(&d.admin(), "upstream", 1, "payload.bin", &payload(1000));
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;
    let jobs =
        wsus_client::install::job::JobStore::open(d.config.client.state_dir.join("jobs")).unwrap();
    jobs.write(&failed_job(rev)).unwrap();
    let args = ReportArgs {
        update: None,
        namespace_id: 0,
        event_id: 0,
        source_id: 0,
        hresult: 0,
        sequence: 0,
        instance_id: None,
        app_name: None,
        job: Some("job-report-1".into()),
        inventory: false,
        force: false,
        facts_file: None,
        flush_only: false,
        no_flush: false,
        batch_size: 10,
    };
    let (out, _) = client_cmd::report(&mut e, &d.config, &args).await.unwrap();
    assert_eq!(out.value["flush"]["delivered"], 2, "{}", out.value);
    let ids: Vec<i64> = out.value["enqueue"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["event_id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [181, 182]);
    // The same job again adds nothing: the derived instance ids were delivered.
    let (out, _) = client_cmd::report(&mut e, &d.config, &args).await.unwrap();
    assert_eq!(out.value["flush"]["delivered"], 0, "{}", out.value);
    assert_eq!(
        out.value["enqueue"]["events"][0]["result"]["outcome"],
        "already_delivered"
    );

    let computer = e.session().state().computer_id.unwrap();
    let reporting = &d.opened.services.reporting;
    let events = reporting.events_for_computer(computer, None, 100).unwrap();
    assert_eq!(events.len(), 2, "one copy of each event");
    let st = reporting
        .status(computer, rev)
        .unwrap()
        .expect("derived status");
    assert_eq!(
        st.status,
        wsus_server::reporting::UpdateStatus::InstallFailed
    );
    assert_eq!(st.result_code, Some(0x8007_0643_u32 as i32 as i64));
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_server_content_is_rejected_by_the_client_and_found_by_verify() {
    let d = Deployment::new();
    let data = payload(PAYLOAD_LEN);
    seed_update(&d.admin(), "upstream", 1, "payload.bin", &data);
    approve(&d, 1);
    let mut e = engine(&d);
    sync(&mut e, &d).await;

    // Flip one byte of the stored object, keeping its length.
    let mut objects = Vec::new();
    walk(&d.config.server.content_dir.join("objects"), &mut objects);
    assert_eq!(objects.len(), 1);
    let mut bytes = fs::read(&objects[0]).unwrap();
    bytes[1234] ^= 0xff;
    fs::write(&objects[0], &bytes).unwrap();

    // The client verifies every digest over the whole object and refuses it.
    let (out, _) = client_cmd::download(&mut e, &d.config, &Selection::All, false)
        .await
        .unwrap();
    assert!(!out.ok, "{}", out.value);
    let reason = out.value["files"][0]["reason"].as_str().unwrap();
    assert!(reason.contains("digest mismatch"), "{reason}");
    let mut files = Vec::new();
    walk(&d.client_dir().join("content").join("complete"), &mut files);
    assert!(
        files.is_empty(),
        "corrupt bytes must never be promoted: {files:?}"
    );
    let digest_of_bad = format!("{:x}", Sha256::digest(&bytes));
    assert_ne!(digest_of_bad, format!("{:x}", Sha256::digest(&data)));

    // `admin content verify --deep` detects and quarantines the object.
    let verify = admin::content_verify(&d.admin(), None, true).unwrap();
    assert!(!verify.ok, "{}", verify.value);
    assert_eq!(verify.value["corrupt_objects"].as_array().unwrap().len(), 1);
    assert_eq!(verify.value["catalog_files_unavailable"], 1);
}

/// Our client converges against both delivery modes of our server on a prerequisite chain:
/// staged delivery hands out one dependency level per call and the engine's installed list
/// ("non-leaf revisions cached") unlocks the next; closure delivery sends the chain at once.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_converges_on_a_prerequisite_chain_in_both_delivery_modes() {
    use wsus_cli::config::SyncDeliverySetting::{Closure, Staged};
    for mode in [Staged, Closure] {
        let d = Deployment::with_delivery(mode);
        let revs = seed_chain(&d.admin(), "upstream", 1, 6);
        approve(&d, 6);
        let mut e = engine(&d);
        let out = sync(&mut e, &d).await;
        assert_eq!(out.value["new_revisions"], 6, "{mode:?}: {}", out.value);
        assert_eq!(out.value["visible_revisions"], 6, "{mode:?}");
        // Nothing left to fetch, and the cache survives a repeat.
        let out = sync(&mut e, &d).await;
        assert_eq!(out.value["new_revisions"], 0, "{mode:?}: {}", out.value);
        assert_eq!(out.value["removed_revisions"], 0, "{mode:?}");
        assert!(client_cmd::inspect(&e, Some(&revs[5].to_string())).is_ok());
    }
}
