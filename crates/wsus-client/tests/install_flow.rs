//! Host tests of the installing client with fakes: planning over a synthetic
//! catalog, the Unknown policy, the gates, the executor's write-ahead evidence,
//! exit-code mapping, recovery and idempotence. Nothing here is evidence about
//! Windows or a native agent.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use wsus_client::{
    install::{
        PlanOptions, PlanOutcome, RecordingFacts, build_plan,
        executor::{ExecConfig, Executor, NoSleep, Sleeper},
        handler_log::{DetachedProcess, FixedWatcher, HandlerLog, NoWatcher},
        job::{JobError, JobStatus, JobStore, NoReport, PostCheck, StepState},
        plan::{InstallPlan, NodeStatus, Planner},
        runner::{FakeRunner, RunResult},
        safety::PathPolicy,
        signature::{FakeVerifier, TrustPolicy},
        store::FixedStore,
        testkit::{Child, rev, write_bundle},
    },
    session::SystemClock,
    sync::{Catalog, RevisionStore},
};
use wsus_protocol::{
    applicability::{FactProvider, FakeFacts},
    identity::UpdateRevision,
    soap::Limits,
};

const SPEC_OK: &str = r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Test" />"#;

fn catalog(dir: &Path) -> Catalog {
    let store = RevisionStore::open_read_only(dir).unwrap();
    Catalog::load(&store, &Limits::default()).unwrap()
}

fn facts(version: u32) -> FakeFacts {
    let mut f = FakeFacts::windows11_x64();
    f.set_dword("SOFTWARE\\Test", "Version", version);
    f
}

fn child(id: u128, name: &str) -> Child {
    Child::new(id, name, format!("payload of {name}").as_bytes())
}

fn plan_of(catalog: &Catalog, facts: &dyn FactProvider, root: UpdateRevision) -> InstallPlan {
    build_plan(catalog, facts, root, &PlanOptions::default())
}

#[test]
fn bundle_children_are_selected_by_their_own_verdicts() {
    let t = TempDir::new().unwrap();
    let a = child(0xA, "a.exe");
    let mut b = child(0xB, "b.exe");
    b.installable = Some(
        r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Test" Value="Mode" Comparison="EqualTo" Data="9" />"#.into(),
    );
    let root = write_bundle(
        t.path(),
        0x1,
        Some((0xC, "<True />")),
        &[vec![a.clone(), b.clone()]],
    );
    let cat = catalog(t.path());
    let plan = plan_of(&cat, &facts(1), root);
    assert_eq!(plan.outcome, PlanOutcome::Install);
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.steps[0].update, a.revision().to_string());
    assert_eq!(plan.steps[0].payload, a.payload_ref());
    assert_eq!(
        plan.decision(&b.revision().to_string()).unwrap().status,
        NodeStatus::NotApplicable
    );
    assert!(plan.blockers.is_empty());
    // Deterministic, and the facts hash identifies the facts used.
    let again = plan_of(&cat, &facts(1), root);
    assert_eq!(plan.to_json(), again.to_json());
    // Different facts give a different hash.
    let other = plan_of(&cat, &facts(7), root);
    assert_ne!(other.facts.hash, plan.facts.hash);
}

#[test]
fn unknown_on_the_decision_path_refuses_unless_allowed() {
    let t = TempDir::new().unwrap();
    let a = child(0xA, "a.exe");
    let mut u = child(0xB, "b.exe");
    // SystemMetric is unavailable in the fake: Unknown.
    u.installable = Some(r#"<b.SystemMetric Index="4" Comparison="EqualTo" Value="0" />"#.into());
    let root = write_bundle(t.path(), 0x1, None, &[vec![a.clone(), u.clone()]]);
    let cat = catalog(t.path());
    let f = facts(1);
    let plan = plan_of(&cat, &f, root);
    assert_eq!(plan.outcome, PlanOutcome::Refused);
    assert!(
        plan.steps.is_empty(),
        "a refused plan carries no steps to run"
    );
    assert!(
        plan.blockers
            .iter()
            .any(|b| b.text.contains("system metric")
                || b.text.contains("SystemMetric")
                || b.text.contains("metric")),
        "{:?}",
        plan.blockers
    );
    let allowed = build_plan(
        &cat,
        &f,
        root,
        &PlanOptions {
            allow_unknown: true,
            ..PlanOptions::default()
        },
    );
    assert_eq!(allowed.outcome, PlanOutcome::Install);
    assert_eq!(allowed.steps.len(), 1);
    assert_eq!(allowed.steps[0].update, a.revision().to_string());
    assert!(allowed.allow_unknown);
    assert!(allowed.decision(&u.revision().to_string()).unwrap().status == NodeStatus::Unknown);
}

#[test]
fn prerequisites_gate_the_bundle() {
    let a = child(0xA, "a.exe");
    // False prerequisite: nothing to do, not applicable.
    let t = TempDir::new().unwrap();
    let root = write_bundle(
        t.path(),
        0x1,
        Some((
            0xC,
            r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\NoSuch" />"#,
        )),
        &[vec![a.clone()]],
    );
    let plan = plan_of(&catalog(t.path()), &facts(1), root);
    assert_eq!(plan.outcome, PlanOutcome::NothingToDoNotApplicable);
    // Unknown prerequisite: refuse.
    let t = TempDir::new().unwrap();
    let root = write_bundle(
        t.path(),
        0x1,
        Some((
            0xC,
            r#"<b.SystemMetric Index="4" Comparison="EqualTo" Value="0" />"#,
        )),
        &[vec![a.clone()]],
    );
    let plan = plan_of(&catalog(t.path()), &facts(1), root);
    assert_eq!(plan.outcome, PlanOutcome::Refused);
    // Satisfied prerequisite: install.
    let t = TempDir::new().unwrap();
    let root = write_bundle(t.path(), 0x1, Some((0xC, SPEC_OK)), &[vec![a]]);
    let plan = plan_of(&catalog(t.path()), &facts(1), root);
    assert_eq!(plan.outcome, PlanOutcome::Install);
}

#[test]
fn installed_children_mean_nothing_to_do() {
    let t = TempDir::new().unwrap();
    let root = write_bundle(
        t.path(),
        0x1,
        Some((0xC, "<True />")),
        &[vec![child(0xA, "a.exe")]],
    );
    let plan = plan_of(&catalog(t.path()), &facts(2), root);
    assert_eq!(plan.outcome, PlanOutcome::NothingToDoInstalled);
    assert!(plan.steps.is_empty());
}

#[test]
fn a_child_not_in_the_catalog_is_unknown() {
    let t = TempDir::new().unwrap();
    let root = write_bundle(t.path(), 0x1, None, &[vec![child(0xA, "a.exe")]]);
    // Remove the child's record.
    for e in fs::read_dir(t.path().join("revisions")).unwrap().flatten() {
        if e.file_name()
            .to_string_lossy()
            .starts_with("00000000-0000-0000-0000-00000000000a")
        {
            fs::remove_file(e.path()).unwrap();
        }
    }
    let plan = plan_of(&catalog(t.path()), &facts(1), root);
    assert_eq!(plan.outcome, PlanOutcome::Refused);
}

// ---------------------------------------------------------------- executor

struct Rig {
    _dir: TempDir,
    root: PathBuf,
    store: FixedStore,
    jobs: JobStore,
    catalog: Catalog,
    target: UpdateRevision,
    state: Arc<Mutex<FakeFacts>>,
}

fn rig(clauses: Vec<Vec<Child>>) -> Rig {
    let dir = TempDir::new().unwrap();
    let meta = dir.path().join("meta");
    let target = write_bundle(&meta, 0x1, Some((0xC, "<True />")), &clauses);
    let root = dir.path().join("store");
    fs::create_dir_all(&root).unwrap();
    let mut files = BTreeMap::new();
    let children: Vec<Child> = clauses.into_iter().flatten().collect();
    for c in &children {
        let p = root.join(&c.file_name);
        fs::write(&p, &c.payload).unwrap();
        files.insert(c.file_name.clone(), p);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for f in files.values() {
            fs::set_permissions(f, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let jobs = JobStore::open(dir.path().join("jobs")).unwrap();
    let catalog = catalog(&meta);
    Rig {
        store: FixedStore {
            root: root.clone(),
            files,
        },
        root,
        jobs,
        catalog,
        target,
        state: Arc::new(Mutex::new(facts(1))),
        _dir: dir,
    }
}

impl Rig {
    fn plan(&self) -> InstallPlan {
        let f = self.state.lock().unwrap().clone();
        plan_of(&self.catalog, &f, self.target)
    }

    fn post_check(&self) -> impl FnMut(&[String]) -> PostCheck + '_ {
        move |executed: &[String]| {
            let f = self.state.lock().unwrap().clone();
            let rec = RecordingFacts::new(&f);
            let mut planner = Planner::new(&self.catalog, &rec, PlanOptions::default());
            let mut pc = PostCheck {
                performed: true,
                ..PostCheck::default()
            };
            for u in executed {
                let (id, r) = u.split_once('@').unwrap();
                let rv = UpdateRevision {
                    id: wsus_protocol::identity::UpdateId(id.parse().unwrap()),
                    revision: wsus_protocol::identity::Revision(r.parse().unwrap()),
                };
                match planner.verdict(rv).0 {
                    NodeStatus::AlreadyInstalled => pc.installed.push(u.clone()),
                    NodeStatus::Unknown => pc.unknown.push(u.clone()),
                    _ => pc.not_installed.push(u.clone()),
                }
            }
            pc
        }
    }

    fn executor<'a>(
        &'a self,
        runner: &'a FakeRunner,
        verifier: &'a FakeVerifier,
        trust: TrustPolicy,
    ) -> Executor<'a> {
        Executor {
            store: &self.store,
            runner,
            verifier,
            jobs: &self.jobs,
            clock: &SystemClock,
            hook: &NoReport,
            sleeper: &NoSleep,
            watcher: &NoWatcher,
            config: ExecConfig {
                trust,
                path_policy: PathPolicy::default(),
                timeout: Duration::from_secs(5),
                ..ExecConfig::default()
            },
        }
    }
}

/// A runner that "installs": it raises the registry version, then exits `code`.
fn installing_runner(state: Arc<Mutex<FakeFacts>>, code: i32) -> FakeRunner {
    FakeRunner::new(move |_req| {
        state
            .lock()
            .unwrap()
            .set_dword("SOFTWARE\\Test", "Version", 2);
        Ok(RunResult {
            exit_code: Some(code),
            ..RunResult::default()
        })
    })
}

#[test]
fn install_runs_the_exact_command_and_the_post_check_confirms() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install);
    let runner = installing_runner(r.state.clone(), 0);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let ex = r.executor(&runner, &verifier, TrustPolicy::default());
    let rec = ex.run(&plan, &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Succeeded, "{rec:#?}");
    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, r.root.join("a.exe"));
    assert_eq!(calls[0].args, ["WD", "/q"]);
    assert!(rec.post_check.performed && rec.post_check.installed.len() == 1);
    assert_eq!(rec.steps[0].exit_code, Some(0));
    assert_eq!(
        rec.steps[0]
            .signature
            .as_ref()
            .unwrap()
            .organization
            .as_deref(),
        Some("Microsoft Corporation")
    );
    assert!(!rec.reporting_sent);
    // Evidence is on disk and arguments are redacted of foreign paths.
    let on_disk = r.jobs.read(&rec.job_id).unwrap();
    assert_eq!(on_disk.status, JobStatus::Succeeded);
    assert_eq!(on_disk.steps[0].program.as_deref(), Some("<store>/a.exe"));
    // Re-running is a no-op: the evaluator now says installed.
    let again = r.plan();
    assert_eq!(again.outcome, PlanOutcome::NothingToDoInstalled);
    let rec2 = ex.run(&again, &mut r.post_check()).unwrap();
    assert_eq!(rec2.status, JobStatus::NoAction);
    assert_eq!(runner.calls().len(), 1, "no second execution");
}

#[test]
fn the_step_is_written_ahead_of_the_process() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let plan = r.plan();
    let jobs_dir = r.jobs.dir().to_path_buf();
    let seen: Arc<Mutex<Option<(JobStatus, StepState)>>> = Arc::default();
    let seen2 = seen.clone();
    let state = r.state.clone();
    let runner = FakeRunner::new(move |_| {
        let jobs = JobStore::open(&jobs_dir).unwrap();
        let rec = jobs.list().unwrap().pop().unwrap();
        *seen2.lock().unwrap() = Some((rec.status, rec.steps[0].state));
        state
            .lock()
            .unwrap()
            .set_dword("SOFTWARE\\Test", "Version", 2);
        Ok(RunResult {
            exit_code: Some(0),
            ..RunResult::default()
        })
    });
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    r.executor(&runner, &verifier, TrustPolicy::default())
        .run(&plan, &mut r.post_check())
        .unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        Some((JobStatus::Running, StepState::Started))
    );
}

#[test]
fn refuses_unsigned_and_foreign_signers_and_honours_the_override() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let plan = r.plan();
    for (verifier, trust) in [
        (FakeVerifier::unsigned(), TrustPolicy::default()),
        (FakeVerifier::signed_by("Evil Corp"), TrustPolicy::default()),
    ] {
        let runner = installing_runner(r.state.clone(), 0);
        let rec = r
            .executor(&runner, &verifier, trust)
            .run(&plan, &mut r.post_check())
            .unwrap();
        assert_eq!(rec.status, JobStatus::Refused);
        assert!(rec.steps[0].refusal.is_some());
        assert!(runner.calls().is_empty(), "nothing executed on refusal");
    }
    // The explicit override lets another signer through.
    let runner = installing_runner(r.state.clone(), 0);
    let verifier = FakeVerifier::signed_by("Evil Corp");
    let rec = r
        .executor(
            &runner,
            &verifier,
            TrustPolicy {
                allowed_signers: vec!["Evil Corp".into()],
            },
        )
        .run(&plan, &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Succeeded);
}

#[test]
fn a_changed_payload_is_refused_before_anything_runs() {
    let r = rig(vec![vec![child(0xA, "a.exe"), child(0xB, "b.exe")]]);
    let plan = r.plan();
    assert_eq!(plan.steps.len(), 2);
    // Same length, different bytes in the SECOND payload.
    let p = r.root.join("b.exe");
    let mut bytes = fs::read(&p).unwrap();
    bytes[0] ^= 0xFF;
    fs::write(&p, bytes).unwrap();
    let runner = installing_runner(r.state.clone(), 0);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&plan, &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[1].refusal.as_deref().unwrap().contains("digest"),
        "{:?}",
        rec.steps[1].refusal
    );
    assert!(
        runner.calls().is_empty(),
        "the first step must not run either"
    );
}

#[test]
fn a_missing_payload_is_refused() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let plan = r.plan();
    fs::remove_file(r.root.join("a.exe")).unwrap();
    let runner = FakeRunner::exiting(0);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&plan, &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Refused);
}

#[test]
fn exit_codes_map_to_success_reboot_and_failure() {
    // Reboot class.
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let runner = installing_runner(r.state.clone(), 3010);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&r.plan(), &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::RebootRequired);
    // Unlisted code fails closed and stops the run.
    let r = rig(vec![vec![child(0xA, "a.exe")], vec![child(0xB, "b.exe")]]);
    let runner = FakeRunner::exiting(1);
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&r.plan(), &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Failed);
    assert_eq!(runner.calls().len(), 1, "the failure stops the run");
    assert_eq!(rec.steps[1].state, StepState::Pending);
    // A timeout is a failure.
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let runner = FakeRunner::new(|_| {
        Ok(RunResult {
            exit_code: None,
            timed_out: true,
            ..RunResult::default()
        })
    });
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&r.plan(), &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Failed);
    assert!(rec.steps[0].timed_out);
}

#[test]
fn success_exit_without_an_installed_verdict_is_unconfirmed() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let runner = FakeRunner::exiting(0); // exits 0 but changes nothing
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&r.plan(), &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    assert_eq!(rec.post_check.not_installed.len(), 1);
}

#[test]
fn an_interrupted_run_is_marked_and_the_rerun_is_idempotent() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let plan = r.plan();
    // The runner snapshots the record as it is mid-run (status running, step
    // started) and then "installs".
    let jobs_dir = r.jobs.dir().to_path_buf();
    type Snapshot = Arc<Mutex<Option<(PathBuf, Vec<u8>)>>>;
    let snapshot: Snapshot = Arc::default();
    let snap = snapshot.clone();
    let state = r.state.clone();
    let runner = FakeRunner::new(move |_| {
        let rec = JobStore::open(&jobs_dir)
            .unwrap()
            .list()
            .unwrap()
            .pop()
            .unwrap();
        let path = jobs_dir.join(format!("{}.json", rec.job_id));
        *snap.lock().unwrap() = Some((path.clone(), fs::read(path).unwrap()));
        state
            .lock()
            .unwrap()
            .set_dword("SOFTWARE\\Test", "Version", 2);
        Ok(RunResult {
            exit_code: Some(0),
            ..RunResult::default()
        })
    });
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let ex = r.executor(&runner, &verifier, TrustPolicy::default());
    let first = ex.run(&plan, &mut r.post_check()).unwrap();
    assert_eq!(first.status, JobStatus::Succeeded);
    // Simulate a crash: the record on disk is the mid-run one.
    let (path, bytes) = snapshot.lock().unwrap().clone().unwrap();
    fs::write(path, bytes).unwrap();
    // The next run recovers it...
    let again = r.plan();
    let rec = ex.run(&again, &mut r.post_check()).unwrap();
    assert_eq!(rec.recovered, vec![first.job_id.clone()]);
    let old = r.jobs.read(&first.job_id).unwrap();
    assert_eq!(old.status, JobStatus::Interrupted);
    assert!(
        old.notes.iter().any(|n| n.contains("[0]")),
        "{:?}",
        old.notes
    );
    // ...and, because the evaluator says installed, executes nothing.
    assert_eq!(rec.status, JobStatus::NoAction);
    assert_eq!(runner.calls().len(), 1);
}

#[test]
fn a_second_run_cannot_start_while_one_holds_the_lock() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let _held = r.jobs.lock().unwrap();
    let runner = FakeRunner::exiting(0);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let err = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&r.plan(), &mut r.post_check())
        .unwrap_err();
    assert!(matches!(
        err,
        wsus_client::install::executor::ExecError::Job(JobError::Locked(_))
    ));
}

#[test]
fn a_refused_plan_is_recorded_and_not_executed() {
    let t = TempDir::new().unwrap();
    let mut u = child(0xB, "b.exe");
    u.installable = Some(r#"<b.SystemMetric Index="4" Comparison="EqualTo" Value="0" />"#.into());
    let root = write_bundle(t.path(), 0x1, None, &[vec![u]]);
    let cat = catalog(t.path());
    let plan = plan_of(&cat, &facts(1), root);
    assert_eq!(plan.outcome, PlanOutcome::Refused);
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let runner = FakeRunner::exiting(0);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let rec = r
        .executor(&runner, &verifier, TrustPolicy::default())
        .run(&plan, &mut r.post_check())
        .unwrap();
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(runner.calls().is_empty());
    let _ = rev(1);
}

#[cfg(feature = "msi-handler")]
mod msi {
    use super::*;

    const URI: &str = "urn:test:msi-handler";

    #[test]
    fn an_operator_declared_msi_handler_runs_msiexec_with_separate_arguments() {
        let mut c = Child::new(0xA, "tool.msi", b"fake msi bytes");
        c.handler_uri = URI.into();
        let r = rig(vec![vec![c]]);
        let f = r.state.lock().unwrap().clone();
        // Not declared: unsupported handler, the plan is refused.
        assert_eq!(
            plan_of(&r.catalog, &f, r.target).outcome,
            PlanOutcome::Refused
        );
        let opts = PlanOptions {
            msi_handler_uris: vec![URI.into()],
            ..PlanOptions::default()
        };
        let plan = build_plan(&r.catalog, &f, r.target, &opts);
        assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
        let runner = installing_runner(r.state.clone(), 3010);
        let verifier = FakeVerifier::signed_by("Microsoft Corporation");
        let mut ex = r.executor(&runner, &verifier, TrustPolicy::default());
        ex.config.system_dir = Some(PathBuf::from("/sys"));
        let rec = ex.run(&plan, &mut r.post_check()).unwrap();
        assert_eq!(rec.status, JobStatus::RebootRequired);
        let call = &runner.calls()[0];
        assert_eq!(call.program, PathBuf::from("/sys/msiexec.exe"));
        assert_eq!(call.args[0], "/i");
        assert_eq!(call.args[1], r.root.join("tool.msi").display().to_string());
        assert_eq!(&call.args[2..], ["/qn", "/norestart"]);
    }
}

// ------------------------------------------------------- post-check waiting

struct CountingSleeper {
    count: Mutex<u32>,
    on_sleep: Box<dyn Fn(u32) + Send + Sync>,
}

impl CountingSleeper {
    fn new(on_sleep: impl Fn(u32) + Send + Sync + 'static) -> Self {
        Self {
            count: Mutex::new(0),
            on_sleep: Box::new(on_sleep),
        }
    }
    fn sleeps(&self) -> u32 {
        *self.count.lock().unwrap()
    }
}

impl Sleeper for CountingSleeper {
    fn sleep(&self, d: Duration) {
        assert_eq!(d, Duration::from_secs(2));
        let mut c = self.count.lock().unwrap();
        *c += 1;
        (self.on_sleep)(*c);
    }
}

fn run_waiting(
    r: &Rig,
    code: i32,
    install_now: bool,
    wait_secs: u64,
    sleeper: &CountingSleeper,
    watcher: &FixedWatcher,
    log: Option<HandlerLog>,
) -> wsus_client::install::job::JobRecord {
    let runner = if install_now {
        installing_runner(r.state.clone(), code)
    } else {
        FakeRunner::exiting(code)
    };
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let mut ex = r.executor(&runner, &verifier, TrustPolicy::default());
    ex.sleeper = sleeper;
    ex.watcher = watcher;
    ex.config.post_check_wait = Duration::from_secs(wait_secs);
    ex.config.handler_log = log;
    ex.run(&r.plan(), &mut r.post_check()).unwrap()
}

#[test]
fn the_post_check_waits_until_the_evaluator_converges() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let state = r.state.clone();
    // The "detached helper" applies the update during the third wait.
    let sleeper = CountingSleeper::new(move |n| {
        if n == 3 {
            state
                .lock()
                .unwrap()
                .set_dword("SOFTWARE\\Test", "Version", 2);
        }
    });
    let rec = run_waiting(&r, 0, false, 180, &sleeper, &FixedWatcher::default(), None);
    assert_eq!(rec.status, JobStatus::Succeeded);
    let pc = &rec.post_check;
    assert!(pc.converged);
    assert_eq!((pc.polls, pc.waited_secs, sleeper.sleeps()), (4, 6, 3));
}

#[test]
fn convergence_on_the_first_poll_does_not_wait() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let sleeper = CountingSleeper::new(|_| {});
    let rec = run_waiting(&r, 0, true, 180, &sleeper, &FixedWatcher::default(), None);
    assert_eq!(rec.status, JobStatus::Succeeded);
    assert_eq!((rec.post_check.polls, sleeper.sleeps()), (1, 0));
}

#[test]
fn never_converging_is_bounded_and_unconfirmed() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let sleeper = CountingSleeper::new(|_| {});
    let rec = run_waiting(&r, 0, false, 180, &sleeper, &FixedWatcher::default(), None);
    assert_eq!(
        rec.status,
        JobStatus::Unconfirmed,
        "exit 0 alone is never success"
    );
    let pc = &rec.post_check;
    assert!(!pc.converged);
    assert_eq!(
        (pc.polls, pc.waited_secs, pc.wait_bound_secs),
        (91, 180, 180)
    );
    assert_eq!(sleeper.sleeps(), 90);
}

#[test]
fn disabled_waiting_evaluates_once() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let sleeper = CountingSleeper::new(|_| {});
    let rec = run_waiting(&r, 0, false, 0, &sleeper, &FixedWatcher::default(), None);
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    assert_eq!((rec.post_check.polls, sleeper.sleeps()), (1, 0));
}

#[test]
fn a_failed_exit_code_beats_convergence() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let sleeper = CountingSleeper::new(|_| {});
    // The facts say installed, but the exit code said failed.
    let rec = run_waiting(&r, 1, true, 180, &sleeper, &FixedWatcher::default(), None);
    assert_eq!(rec.status, JobStatus::Failed);
    assert_eq!(sleeper.sleeps(), 0, "no waiting after a failure");
}

#[test]
fn the_handler_log_tail_and_detached_processes_are_recorded_as_evidence() {
    let r = rig(vec![vec![child(0xA, "a.exe")]]);
    let log = r.root.join("..").join("MpSigStub.log");
    let utf16 = |s: &str, bom: bool| -> Vec<u8> {
        let mut v = if bom { vec![0xFF, 0xFE] } else { vec![] };
        for u in s.encode_utf16() {
            v.extend(u.to_le_bytes());
        }
        v
    };
    fs::write(&log, utf16("earlier run\r\n", true)).unwrap();
    let hl = HandlerLog {
        programs: vec!["a.exe".into()],
        program_prefixes: vec![],
        log_path: log.clone(),
        watch_process: "MpSigStub.exe".into(),
    };
    // The runner appends to the log like the detached stub would.
    let (l2, state) = (log.clone(), r.state.clone());
    let runner = FakeRunner::new(move |_| {
        let mut b = fs::read(&l2).unwrap();
        b.extend(utf16("MpSigStub successfully updated\r\n", false));
        fs::write(&l2, b).unwrap();
        let _ = &state;
        Ok(RunResult {
            exit_code: Some(0),
            ..RunResult::default()
        })
    });
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let sleeper = CountingSleeper::new(|_| {});
    let watcher = FixedWatcher(vec![DetachedProcess {
        name: "mpsigstub.exe".into(),
        pid: 4242,
        started_unix: None,
    }]);
    let mut ex = r.executor(&runner, &verifier, TrustPolicy::default());
    ex.sleeper = &sleeper;
    ex.watcher = &watcher;
    ex.config.post_check_wait = Duration::from_secs(4);
    ex.config.handler_log = Some(hl);
    let rec = ex.run(&r.plan(), &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    assert_eq!(
        rec.handler_log_excerpt.as_deref(),
        Some("MpSigStub successfully updated\r\n")
    );
    assert_eq!(rec.post_check.detached_processes.len(), 1);
    assert_eq!(rec.post_check.detached_processes[0].pid, 4242);
    // An unreadable log never fails the install.
    fs::remove_file(&log).unwrap();
    let r2 = rig(vec![vec![child(0xA, "a.exe")]]);
    let hl = HandlerLog {
        programs: vec!["a.exe".into()],
        program_prefixes: vec![],
        log_path: r2.root.join("missing.log"),
        watch_process: "MpSigStub.exe".into(),
    };
    let rec = run_waiting(
        &r2,
        0,
        true,
        0,
        &sleeper,
        &FixedWatcher::default(),
        Some(hl),
    );
    assert_eq!(rec.status, JobStatus::Succeeded);
    assert!(rec.handler_log_excerpt.is_none());
}

// ------------------------------------------------- Defender launcher family

fn defender_rig() -> Rig {
    rig(vec![vec![
        child(0xD, "AM_Delta.exe"),
        child(0xE, "AM_Engine.exe"),
        child(0xF, "AM_Base.exe"),
    ]])
}

fn names(plan: &InstallPlan) -> Vec<String> {
    plan.steps
        .iter()
        .map(|s| s.payload.file_name.clone())
        .collect()
}

/// Runner: every package exits 0 except the one named, which exits `code`; the
/// installed state is raised when the terminal package (`AM_Delta*`) runs.
fn stub_runner(state: Arc<Mutex<FakeFacts>>, terminal_code: i32, apply: bool) -> FakeRunner {
    FakeRunner::new(move |req| {
        let name = req
            .program
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        if name.to_ascii_lowercase().starts_with("am_delta") {
            if apply {
                state
                    .lock()
                    .unwrap()
                    .set_dword("SOFTWARE\\Test", "Version", 2);
            }
            Ok(RunResult {
                exit_code: Some(terminal_code),
                ..RunResult::default()
            })
        } else {
            Ok(RunResult {
                exit_code: Some(0),
                ..RunResult::default()
            })
        }
    })
}

#[test]
fn defender_packages_run_with_the_terminal_package_last() {
    let r = defender_rig();
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install);
    assert_eq!(
        names(&plan),
        ["AM_Engine.exe", "AM_Base.exe", "AM_Delta.exe"]
    );
    assert!(plan.steps[2].launcher.as_ref().unwrap().is_terminal());
    let runner = stub_runner(r.state.clone(), 0, true);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let ex = r.executor(&runner, &verifier, TrustPolicy::default());
    let rec = ex.run(&plan, &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Succeeded, "{rec:#?}");
    let order: Vec<String> = runner
        .calls()
        .iter()
        .map(|c| c.program.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(order, ["AM_Engine.exe", "AM_Base.exe", "AM_Delta.exe"]);
    // Only the terminal package carries the stub's result.
    assert!(rec.steps[0].stub_result.is_none() && rec.steps[1].stub_result.is_none());
    let t = rec.steps[2].stub_result.as_ref().unwrap();
    assert_eq!(
        (t.name.as_str(), t.hresult.as_str()),
        ("success", "0x00000000")
    );
    let d = rec.defender.as_ref().unwrap();
    assert_eq!(d.terminal_step, Some(2));
    assert_eq!(d.parent_pid, std::process::id());
    assert!(rec.notes.iter().any(|n| n.contains("terminal package")));
}

#[test]
fn a_defender_selection_without_a_terminal_package_is_refused_by_the_plan() {
    let r = rig(vec![vec![
        child(0xE, "AM_Engine.exe"),
        child(0xF, "AM_Base.exe"),
    ]]);
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Refused);
    assert!(plan.steps.is_empty());
    assert!(
        plan.blockers
            .iter()
            .any(|b| b.text.contains("no terminal package") && b.text.contains("0x800705b4")),
        "{:?}",
        plan.blockers
    );
}

#[test]
fn a_hand_made_plan_that_does_not_end_with_the_terminal_package_is_refused_before_running() {
    let r = defender_rig();
    let mut plan = r.plan();
    plan.steps.reverse(); // terminal first
    for (i, s) in plan.steps.iter_mut().enumerate() {
        s.index = i;
    }
    let runner = stub_runner(r.state.clone(), 0, true);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let ex = r.executor(&runner, &verifier, TrustPolicy::default());
    let rec = ex.run(&plan, &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(runner.calls().is_empty(), "nothing may run");
    assert!(rec.steps.iter().any(|s| {
        s.refusal
            .as_deref()
            .is_some_and(|t| t.contains("terminal package") && t.contains("0x800705b4"))
    }));
}

#[test]
fn the_terminal_exit_code_is_the_stubs_result_and_a_failure_is_never_success() {
    for (code, name) in [
        (0x8007_0670u32 as i32, "no_patch_for_installed_version"),
        (0x8007_000Du32 as i32, "invalid_data"),
        (0x8499_03F9u32 as i32, "mpsp_patch_error"),
        (0x8007_05B4u32 as i32, "accumulate_timeout"),
    ] {
        let r = defender_rig();
        // Even if the facts would say installed, the failure code wins.
        let runner = stub_runner(r.state.clone(), code, true);
        let verifier = FakeVerifier::signed_by("Microsoft Corporation");
        let ex = r.executor(&runner, &verifier, TrustPolicy::default());
        let rec = ex.run(&r.plan(), &mut r.post_check()).unwrap();
        assert_eq!(rec.status, JobStatus::Failed, "{name}");
        assert_eq!(rec.steps[2].stub_result.as_ref().unwrap().name, name);
        assert_eq!(rec.steps[2].exit_code, Some(code));
    }
}

#[test]
fn the_environment_preconditions_of_the_launcher_refuse_the_whole_run() {
    use wsus_client::install::defender::{EXPECTED_STUB_VERSION, Machine, StubEnv};
    let r = defender_rig();
    let runner = stub_runner(r.state.clone(), 0, true);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let mut ex = r.executor(&runner, &verifier, TrustPolicy::default());
    ex.config.stub_env = Some(StubEnv {
        system_version: Some("1.1.1.1".into()),
        wow64_version: None,
        host_machine: Machine::X64,
    });
    let rec = ex.run(&r.plan(), &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(runner.calls().is_empty());
    assert!(rec.steps.iter().any(|s| {
        s.refusal
            .as_deref()
            .is_some_and(|t| t.contains("0x80070650"))
    }));
    // The payloads here are not PE images, so with a correct stub the machine
    // check is what refuses.
    ex.config.stub_env = Some(StubEnv {
        system_version: Some(EXPECTED_STUB_VERSION.into()),
        wow64_version: None,
        host_machine: Machine::X64,
    });
    let rec = ex.run(&r.plan(), &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps
            .iter()
            .any(|s| s.refusal.as_deref().is_some_and(|t| t.contains("PE image")))
    );
}

#[test]
fn nothing_to_update_in_the_stub_log_does_not_wait_and_is_recorded() {
    let r = defender_rig();
    let log = r.root.join("..").join("MpSigStub.log");
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
    fs::write(&log, [0xFFu8, 0xFE]).unwrap();
    let hl = HandlerLog {
        programs: vec![],
        program_prefixes: vec!["am_".into()],
        log_path: log.clone(),
        watch_process: "MpSigStub.exe".into(),
    };
    let l2 = log.clone();
    let runner = FakeRunner::new(move |_| {
        let mut b = fs::read(&l2).unwrap();
        b.extend(utf16("No products found to update\r\n"));
        fs::write(&l2, b).unwrap();
        Ok(RunResult {
            exit_code: Some(0),
            ..RunResult::default()
        })
    });
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let sleeper = CountingSleeper::new(|_| {});
    let mut ex = r.executor(&runner, &verifier, TrustPolicy::default());
    ex.sleeper = &sleeper;
    ex.config.post_check_wait = Duration::from_secs(180);
    ex.config.handler_log = Some(hl);
    let rec = ex.run(&r.plan(), &mut r.post_check()).unwrap();
    assert_eq!(
        rec.status,
        JobStatus::Unconfirmed,
        "nothing applied is never success"
    );
    assert!(rec.defender.as_ref().unwrap().nothing_applied);
    assert_eq!(sleeper.sleeps(), 0);
    assert_eq!(rec.post_check.wait_bound_secs, 0);
}

#[test]
fn a_failed_terminal_package_with_nothing_else_executed_does_not_report_convergence() {
    // Observed on the guest: the post-check of a failed patch run had empty
    // lists and said `converged: true` (vacuous truth). It must not.
    let r = rig(vec![vec![child(0xD, "AM_Delta_Patch_1.459.537.0.exe")]]);
    let runner = stub_runner(r.state.clone(), 0x8499_0402u32 as i32, false);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let ex = r.executor(&runner, &verifier, TrustPolicy::default());
    let rec = ex.run(&r.plan(), &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Failed);
    assert!(!rec.post_check.converged);
    let t = rec.steps[0].stub_result.as_ref().unwrap();
    assert_eq!(
        (t.name.as_str(), t.hresult.as_str()),
        ("mpsp_patch_error", "0x84990402")
    );
    assert!(t.reason.contains("error 1026"));
}

/// Windows servicing handlers (real shapes from a Windows 11 catalog) are planned and read, but the
/// executor refuses the run before it touches anything.
#[test]
fn a_servicing_handler_is_planned_but_refused_before_anything_runs() {
    use wsus_client::sync::StoredFragment;
    let r = rig(vec![vec![child(0xA, "Windows11.0-KB1-x64.cab")]]);
    let meta = r._dir.path().join("meta");
    let store = RevisionStore::open(&meta).unwrap();
    let c = child(0xA, "Windows11.0-KB1-x64.cab");
    let mut rec = store.get(&c.revision()).unwrap().unwrap();
    let p = c.payload_ref();
    let b64 = |hex: &str| {
        use base64::Engine as _;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    let sha1 = p.digests.iter().find(|d| d.algorithm == "sha1").unwrap();
    let sha256 = p.digests.iter().find(|d| d.algorithm == "sha256").unwrap();
    rec.fragments = vec![StoredFragment {
        kind: "Extended".into(),
        locale: None,
        sha256: String::new(),
        xml: format!(
            r#"<ExtendedProperties DefaultPropertiesLanguage="en" Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs" MaxDownloadSize="{size}" CompatibleProtocolVersion="1.4"><InstallationBehavior RebootBehavior="CanRequestReboot" /><UninstallationBehavior RebootBehavior="CanRequestReboot" /></ExtendedProperties><Files><File Digest="{d1}" DigestAlgorithm="SHA1" FileName="{name}" Size="{size}" PatchingType="SelfContained"><AdditionalDigest Algorithm="SHA256">{d2}</AdditionalDigest></File></Files><HandlerSpecificData type="cbs:Cbs"><CbsData PackageIdentity="" /></HandlerSpecificData>"#,
            size = p.size,
            d1 = b64(&sha1.hex),
            d2 = b64(&sha256.hex),
            name = p.file_name,
        ),
    }];
    store.put(&rec).unwrap();
    let r = Rig {
        catalog: catalog(&meta),
        ..r
    };
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{plan:#?}");
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.steps[0].spec.kind(), "cbs");
    let runner = installing_runner(r.state.clone(), 0);
    let verifier = FakeVerifier::signed_by("Microsoft Corporation");
    let ex = r.executor(&runner, &verifier, TrustPolicy::default());
    let rec = ex.run(&plan, &mut r.post_check()).unwrap();
    assert_eq!(rec.status, JobStatus::Refused, "{rec:#?}");
    assert!(runner.calls().is_empty());
    assert_eq!(rec.steps[0].state, StepState::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .is_some_and(|m| m.starts_with("planned handler cbs, not executable by this client")),
        "{:?}",
        rec.steps[0].refusal
    );
}
