//! Install and uninstall outcome events: built from job records, queued
//! durably, de-duplicated, delivered by the existing flush against the fake
//! server. The shapes are the ones recorded from a native Windows Update Agent
//! (inventory 9.10); the fake server is a model, not evidence.

mod session_common;

use session_common::*;
use std::collections::BTreeMap;
use uuid::Uuid;
use wsus_client::{
    install::{
        handlers::ExitClass,
        job::{
            Flags, JOB_SCHEMA, JobRecord, JobStatus, PostCheck, ReportHook, StepRecord, StepState,
        },
        plan::{FactsRef, InstallPlan, PayloadRef, PlanOutcome},
        servicing::{ServicingClass, StepOperation, StepServicing},
        testkit::{Child, rev, write_bundle},
    },
    reporting::{
        EventQueue, QueueConfig,
        install_events::{
            InstallReportOptions, InstallReporter, WU_S_REBOOT_REQUIRED, events_for_job,
            failure_hresult, reported_update,
        },
    },
    sync::{Catalog, DeploymentSummary, RevisionStore},
};
use wsus_protocol::{soap::Limits, wusp::ReportingEvent};

const TARGET: &str = "88661612-7dd9-49d4-bb34-1e54802c99b9@100";
const TITLE: &str = "2026-09 Cumulative Update for .NET Framework (KB5126052)";

fn plan(outcome: PlanOutcome) -> InstallPlan {
    InstallPlan {
        schema: "wsus-install-plan/2".into(),
        target: TARGET.into(),
        allow_unknown: false,
        facts: FactsRef {
            hash: "00".into(),
            queries: 0,
        },
        outcome,
        steps: Vec::new(),
        blockers: Vec::new(),
        decisions: Vec::new(),
        notes: Vec::new(),
    }
}

fn step(exit_code: Option<i32>, class: Option<ExitClass>) -> StepRecord {
    StepRecord {
        index: 0,
        update: TARGET.into(),
        handler: "cbs".into(),
        payload: PayloadRef::none(),
        state: StepState::Finished,
        program: None,
        arguments: Vec::new(),
        digest_verified: Some(true),
        signature: None,
        exit_code,
        exit_class: class,
        timed_out: false,
        refusal: None,
        started_at: None,
        finished_at: None,
        stdout_tail: None,
        stderr_tail: None,
        launcher: None,
        stub_result: None,
        servicing: None,
    }
}

fn record(job: &str, status: JobStatus, outcome: PlanOutcome, steps: Vec<StepRecord>) -> JobRecord {
    JobRecord {
        schema: JOB_SCHEMA.into(),
        job_id: job.into(),
        status,
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
        plan: plan(outcome),
        steps,
        post_check: PostCheck::default(),
        handler_log_excerpt: None,
        defender: None,
        servicing: None,
        recovered: Vec::new(),
        notes: Vec::new(),
        reporting_sent: false,
    }
}

fn titles() -> BTreeMap<String, String> {
    BTreeMap::from([(TARGET.to_owned(), TITLE.to_owned())])
}

fn opts() -> InstallReportOptions {
    InstallReportOptions::default()
}

fn ids(events: &[wsus_client::sync::ReportEvent]) -> Vec<i16> {
    events.iter().map(|e| e.event_id).collect()
}

#[test]
fn a_reboot_required_install_reports_started_then_pending_with_the_native_result() {
    let rec = record(
        "job-1",
        JobStatus::RebootRequired,
        PlanOutcome::Install,
        vec![step(Some(3010), Some(ExitClass::Reboot))],
    );
    let events = events_for_job(&rec, &titles(), &opts());
    assert_eq!(ids(&events), [181, 201]);
    for e in &events {
        assert_eq!(
            (e.namespace_id, e.source_id, e.sequence_number),
            (1, 101, 0)
        );
        assert_eq!(e.update.unwrap().to_string(), TARGET);
        assert_eq!(e.app_name.as_deref(), Some("wsus-client"));
        assert!(e.detail.is_some());
    }
    assert_eq!(events[0].win32_hresult, 0);
    assert_eq!(events[0].time_at_target, "2026-10-06T14:56:40Z");
    assert_eq!(events[1].win32_hresult, WU_S_REBOOT_REQUIRED);
    assert_eq!(events[1].win32_hresult, 2_359_301);
    assert_eq!(events[1].time_at_target, "2026-10-06T14:57:39Z");
    let d = events[1].detail.as_ref().unwrap();
    assert_eq!(d.replacement_strings, [TITLE]);
    assert_eq!(d.misc_data, ["D=1", "AppName=wsus-client"]);
}

#[test]
fn a_successful_install_reports_started_then_succeeded() {
    let rec = record(
        "job-2",
        JobStatus::Succeeded,
        PlanOutcome::Install,
        vec![step(Some(0), Some(ExitClass::Success))],
    );
    let events = events_for_job(&rec, &titles(), &opts());
    assert_eq!(ids(&events), [181, 183]);
    assert_eq!(events[1].win32_hresult, 0);
    assert_eq!(
        events[1].detail.as_ref().unwrap().misc_data,
        ["D=1", "AppName=wsus-client"]
    );
}

#[test]
fn a_failed_install_reports_the_code_with_the_native_182_shape() {
    // A process exit code is a Win32 code: it becomes an HRESULT.
    let rec = record(
        "job-3",
        JobStatus::Failed,
        PlanOutcome::Install,
        vec![step(Some(1603), Some(ExitClass::Failed))],
    );
    assert_eq!(failure_hresult(&rec), 0x8007_0643_u32 as i32);
    let events = events_for_job(&rec, &titles(), &opts());
    assert_eq!(ids(&events), [181, 182]);
    let e = &events[1];
    assert_eq!(e.win32_hresult, 0x8007_0643_u32 as i32);
    let d = e.detail.as_ref().unwrap();
    assert_eq!(d.replacement_strings, ["0x80070643", TITLE]);
    assert_eq!(
        d.misc_data,
        [
            "C=1".to_owned(),
            format!("F={}", 0x8007_0643_u32 as i32),
            "AppName=wsus-client".to_owned()
        ]
    );
    // The servicing result wins over the exit code; an HRESULT is kept as is.
    let mut s = step(Some(1), Some(ExitClass::Failed));
    s.servicing = Some(StepServicing {
        backend: "dism".into(),
        native_code: Some(0x800F_0922),
        class: Some(ServicingClass::Failed),
        description: String::new(),
        applicable: None,
        identity_expected: None,
        log_paths: Vec::new(),
        os_installer: None,
        operation: StepOperation::Install,
        refusal_class: None,
    });
    let rec = record("job-3b", JobStatus::Failed, PlanOutcome::Install, vec![s]);
    assert_eq!(failure_hresult(&rec), 0x800F_0922_u32 as i32);
    // A timeout and a failure without a code have their own results.
    let mut s = step(None, None);
    s.timed_out = true;
    let rec = record("job-3c", JobStatus::Failed, PlanOutcome::Install, vec![s]);
    assert_eq!(failure_hresult(&rec), 0x8007_05B4_u32 as i32);
    let rec = record("job-3d", JobStatus::Failed, PlanOutcome::Install, vec![]);
    assert_eq!(failure_hresult(&rec), 0x8000_4005_u32 as i32);
}

#[test]
fn jobs_that_did_not_install_or_are_not_confirmed_report_nothing() {
    for status in [
        JobStatus::Planned,
        JobStatus::Running,
        JobStatus::Unconfirmed,
        JobStatus::Refused,
        JobStatus::NoAction,
        JobStatus::Interrupted,
    ] {
        let rec = record("job-4", status, PlanOutcome::Install, vec![]);
        assert!(
            events_for_job(&rec, &titles(), &opts()).is_empty(),
            "{status:?}"
        );
    }
}

#[test]
fn uninstall_events_need_an_explicit_request_and_use_the_server_table_ids() {
    let rec = record(
        "job-5",
        JobStatus::RebootRequired,
        PlanOutcome::Uninstall,
        vec![step(Some(3010), Some(ExitClass::Reboot))],
    );
    assert!(events_for_job(&rec, &titles(), &opts()).is_empty());
    let on = InstallReportOptions {
        include_uninstall: true,
        ..opts()
    };
    assert_eq!(ids(&events_for_job(&rec, &titles(), &on)), [226, 224]);
    let ok = record(
        "job-5b",
        JobStatus::Succeeded,
        PlanOutcome::Uninstall,
        vec![],
    );
    assert_eq!(ids(&events_for_job(&ok, &titles(), &on)), [226, 222]);
    let bad = record(
        "job-5c",
        JobStatus::Failed,
        PlanOutcome::Uninstall,
        vec![step(Some(5), Some(ExitClass::Failed))],
    );
    let events = events_for_job(&bad, &titles(), &on);
    assert_eq!(ids(&events), [226, 221]);
    assert_eq!(events[1].win32_hresult, 0x8007_0005_u32 as i32);
}

#[test]
fn instance_ids_are_stable_per_job_and_differ_between_jobs() {
    let a = record("job-6", JobStatus::Succeeded, PlanOutcome::Install, vec![]);
    let b = record("job-7", JobStatus::Succeeded, PlanOutcome::Install, vec![]);
    let ea = events_for_job(&a, &titles(), &opts());
    let again = events_for_job(&a, &titles(), &opts());
    let eb = events_for_job(&b, &titles(), &opts());
    assert_eq!(
        ea.iter().map(|e| e.event_instance_id).collect::<Vec<_>>(),
        again
            .iter()
            .map(|e| e.event_instance_id)
            .collect::<Vec<_>>()
    );
    assert_ne!(ea[0].event_instance_id, ea[1].event_instance_id);
    assert_ne!(ea[0].event_instance_id, eb[0].event_instance_id);
    assert_eq!(ea[0].event_instance_id.get_version_num(), 5);
}

fn queue(h: &Harness) -> EventQueue {
    EventQueue::open(h.dir.path().join("events"), QueueConfig::default()).unwrap()
}

fn wire(
    e: &ReportingEvent,
) -> (
    &wsus_protocol::wusp::BasicData,
    &wsus_protocol::wusp::ExtendedData,
) {
    (
        e.basic_data.value().unwrap(),
        e.extended_data.value().unwrap(),
    )
}

#[tokio::test]
async fn the_hook_queues_once_and_the_flush_delivers_the_native_shape() {
    let h = Harness::new();
    let reporter = InstallReporter::new(queue(&h), titles(), opts());
    let rec = record(
        "job-8",
        JobStatus::RebootRequired,
        PlanOutcome::Install,
        vec![step(Some(3010), Some(ExitClass::Reboot))],
    );
    reporter.job_finished(&rec);
    // The hook called again for the same job (a retried finish): no second pair.
    reporter.job_finished(&rec);
    let (q, log) = reporter.finish();
    assert_eq!((log.queued, log.already_known, log.errors.len()), (2, 2, 0));
    assert_eq!(q.len(), 2);

    // Nothing is sent until a flush; a restart between enqueue and delivery keeps both.
    assert_eq!(h.fake().count("ReportEventBatch"), 0);
    drop(q);
    let mut q = queue(&h);
    assert_eq!(q.len(), 2);
    let mut e = h.engine();
    let out = e.flush_events(&mut q, 10).await.unwrap();
    assert_eq!((out.batches, out.delivered), (1, 2));
    assert!(q.is_empty());

    let f = h.fake();
    assert_eq!(f.reported_events.len(), 2);
    let (b0, x0) = wire(&f.reported_events[0]);
    assert_eq!((b0.event_id, b0.namespace_id, b0.source_id), (181, 1, 101));
    let (b1, x1) = wire(&f.reported_events[1]);
    assert_eq!((b1.event_id, b1.win32_hresult), (201, 2_359_301));
    assert_eq!(b1.update_id.value().unwrap().to_string(), TARGET);
    assert_eq!(b1.app_name.value().map(String::as_str), Some("wsus-client"));
    assert_eq!(x0.replacement_strings.value().unwrap(), &[TITLE.to_owned()]);
    assert_eq!(
        x1.misc_data.value().unwrap(),
        &["D=1".to_owned(), "AppName=wsus-client".to_owned()]
    );
    // The client description comes from the registration info.
    assert_eq!(x1.os_version.build, 26100);
    assert_eq!(x1.os_locale_id, 1033);
    assert!(f.reported_events[1].private_data.value().is_some());
    drop(f);

    // After acknowledgement the same job can never queue the same events again.
    let reporter = InstallReporter::new(queue(&h), titles(), opts());
    reporter.job_finished(&rec);
    let (q, log) = reporter.finish();
    assert_eq!((log.queued, log.already_known), (0, 2));
    assert!(q.is_empty());
    let unique: std::collections::BTreeSet<Uuid> = h.fake().reported.iter().copied().collect();
    assert_eq!(unique.len(), 2);
}

#[tokio::test]
async fn plain_events_still_carry_no_detail_records() {
    let h = Harness::new();
    let mut q = queue(&h);
    wsus_client::sync::ReportEvent {
        event_instance_id: Uuid::from_u128(1),
        sequence_number: 0,
        time_at_target: "2024-01-01T00:00:00Z".into(),
        namespace_id: 1,
        event_id: 147,
        source_id: 101,
        update: None,
        win32_hresult: 0,
        app_name: None,
        detail: None,
    }
    .enqueue(&mut q)
    .unwrap();
    h.engine().flush_events(&mut q, 10).await.unwrap();
    let f = h.fake();
    assert!(f.reported_events[0].extended_data.value().is_none());
    assert!(f.reported_events[0].private_data.value().is_none());
}

#[test]
fn a_bundle_child_is_reported_under_its_deployed_bundle() {
    let dir = tempfile::TempDir::new().unwrap();
    let child = Child::new(0xA, "a.exe", b"payload");
    let root = write_bundle(dir.path(), 0x1, None, &[vec![child.clone()]]);
    // Only the root carries a deployment, as a server delivers it.
    let store = RevisionStore::open(dir.path()).unwrap();
    let mut record = store.get(&root).unwrap().unwrap();
    record.deployment = Some(DeploymentSummary {
        id: 7,
        action: "Install".into(),
        is_assigned: true,
        deadline: None,
        last_change_time: "2026-10-06T00:00:00Z".into(),
    });
    store.put(&record).unwrap();
    let catalog = Catalog::load(&store, &Limits::default()).unwrap();
    assert_eq!(reported_update(&catalog, root), root);
    assert_eq!(reported_update(&catalog, child.revision()), root);
    // Something the catalog does not know is reported as itself.
    assert_eq!(reported_update(&catalog, rev(0x99)), rev(0x99));

    // The events name the override and its title.
    let mut rec = record_for(child.revision());
    rec.status = JobStatus::Succeeded;
    let opts = InstallReportOptions {
        update: Some(root),
        ..InstallReportOptions::default()
    };
    let titles = BTreeMap::from([(root.to_string(), "Bundle title".to_owned())]);
    let events = events_for_job(&rec, &titles, &opts);
    assert!(events.iter().all(|e| e.update == Some(root)));
    assert_eq!(
        events[0].detail.as_ref().unwrap().replacement_strings,
        ["Bundle title"]
    );
}

fn record_for(target: wsus_protocol::identity::UpdateRevision) -> JobRecord {
    let mut r = record("job-9", JobStatus::Succeeded, PlanOutcome::Install, vec![]);
    r.plan.target = target.to_string();
    r
}
