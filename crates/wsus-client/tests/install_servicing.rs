//! Host tests of the servicing (`Cbs`) install path with a fake servicing backend: planning of the
//! servicing stack update as a prerequisite, the gates, the reboot barrier, the two post-check
//! oracles, the timeout and failure handling. The catalog is synthetic but uses the REAL handler
//! shape (inventory 12.17). Nothing here is evidence about Windows or DISM.
use base64::Engine as _;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use uuid::Uuid;
use wsus_client::{
    install::{
        PlanOptions, PlanOutcome, RecordingFacts, build_plan,
        executor::{ExecConfig, Executor, NoSleep},
        handler_log::NoWatcher,
        job::{JobStatus, JobStore, NoReport, PostCheck, StepState},
        plan::{InstallPlan, NodeStatus, Planner},
        runner::FakeRunner,
        safety::PathPolicy,
        servicing::{
            BackendError, FakeBackend, PackageEntry, PackageSnapshot, PendingIndicators,
            ServicingBackend, ServicingResult, fake::AddScript,
        },
        signature::{FakeVerifier, TrustPolicy},
        store::FixedStore,
    },
    session::SystemClock,
    sync::{Catalog, RevisionRecord, RevisionStore, StoredFragment},
};
use wsus_protocol::{
    applicability::FakeFacts,
    identity::{Revision, UpdateId, UpdateRevision},
    soap::Limits,
};

const CBS_URI: &str = "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs";
const OSI_URI: &str = "http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller";

fn rev(n: u128) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(Uuid::from_u128(n)),
        revision: Revision(1),
    }
}

fn frag(kind: &str, xml: String) -> StoredFragment {
    StoredFragment {
        kind: kind.into(),
        locale: None,
        sha256: String::new(),
        xml,
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[derive(Clone)]
struct Cbs {
    id: u128,
    package: &'static str,
    version: &'static str,
    file: &'static str,
    payload: Vec<u8>,
    prerequisite: Option<u128>,
    uri: &'static str,
    /// The real catalog's `IsInstallable` of every `Cbs` update: `<CbsPackageInstallable />`.
    installable_cbs: bool,
}

impl Cbs {
    fn new(id: u128, package: &'static str, version: &'static str, file: &'static str) -> Self {
        Self {
            id,
            package,
            version,
            file,
            payload: format!("payload of {file}").into_bytes(),
            prerequisite: None,
            uri: CBS_URI,
            installable_cbs: false,
        }
    }

    fn identity(&self) -> String {
        format!("{}~31bf3856ad364e35~amd64~~{}", self.package, self.version)
    }
}

fn write_catalog(dir: &Path, updates: &[Cbs]) {
    let store = RevisionStore::open(dir).unwrap();
    for u in updates {
        let prereq = u
            .prerequisite
            .map(|p| {
                format!(
                    r#"<Relationships><Prerequisites><AtLeastOne><UpdateIdentity UpdateID="{}" /></AtLeastOne></Prerequisites></Relationships>"#,
                    rev(p).id
                )
            })
            .unwrap_or_default();
        let core = format!(
            r#"<UpdateIdentity UpdateID="{}" RevisionNumber="1" /><Properties UpdateType="Software" />{prereq}<ApplicabilityRules><IsInstalled><CbsPackageInstalled /></IsInstalled>{installable}<Metadata><CbsPackageApplicabilityMetadata><assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="{}" version="{}" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" /><package identifier="KB1" restart="possible"></package></assembly></CbsPackageApplicabilityMetadata></Metadata></ApplicabilityRules>"#,
            rev(u.id).id,
            u.package,
            u.version,
            installable = if u.installable_cbs {
                "<IsInstallable><CbsPackageInstallable /></IsInstallable>"
            } else {
                ""
            }
        );
        let data = if u.uri == CBS_URI {
            r#"<HandlerSpecificData type="cbs:Cbs"><CbsData PackageIdentity="" /></HandlerSpecificData>"#
        } else {
            r#"<HandlerSpecificData type="OSInstallerMetadata"><OSInstallData InitialModule="UpdateAgent.dll" /></HandlerSpecificData>"#
        };
        let ext = format!(
            r#"<ExtendedProperties DefaultPropertiesLanguage="en" Handler="{}" MaxDownloadSize="{}"><InstallationBehavior RebootBehavior="CanRequestReboot" /></ExtendedProperties><Files><File Digest="{}" DigestAlgorithm="SHA1" FileName="{}" Size="{}"><AdditionalDigest Algorithm="SHA256">{}</AdditionalDigest></File></Files>{data}"#,
            u.uri,
            u.payload.len(),
            b64(&Sha1::digest(&u.payload)),
            u.file,
            u.payload.len(),
            b64(&Sha256::digest(&u.payload)),
        );
        store
            .put(&RevisionRecord {
                identity: rev(u.id),
                is_leaf: true,
                update_type: Some("Software".into()),
                deployment: None,
                core: frag("Core", core),
                fragments: vec![frag("Extended", ext)],
            })
            .unwrap();
    }
}

struct Rig {
    _dir: TempDir,
    store: FixedStore,
    jobs: JobStore,
    catalog: Catalog,
    state: Arc<Mutex<FakeFacts>>,
    updates: Vec<Cbs>,
}

fn rig(updates: Vec<Cbs>) -> Rig {
    let dir = TempDir::new().unwrap();
    let meta = dir.path().join("meta");
    write_catalog(&meta, &updates);
    let root = dir.path().join("store");
    fs::create_dir_all(&root).unwrap();
    let mut files = BTreeMap::new();
    for u in &updates {
        let p = root.join(u.file);
        fs::write(&p, &u.payload).unwrap();
        files.insert(u.file.to_owned(), p);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for f in files.values() {
            fs::set_permissions(f, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let catalog = Catalog::load(
        &RevisionStore::open_read_only(&meta).unwrap(),
        &Limits::default(),
    )
    .unwrap();
    Rig {
        store: FixedStore { root, files },
        jobs: JobStore::open(dir.path().join("jobs")).unwrap(),
        catalog,
        state: Arc::new(Mutex::new(FakeFacts::windows11_x64())),
        updates,
        _dir: dir,
    }
}

impl Rig {
    fn set_installed(&self, u: &Cbs) {
        self.state
            .lock()
            .unwrap()
            .set_cbs_package(&u.identity(), 112);
    }

    fn plan(&self, target: u128, options: &PlanOptions) -> InstallPlan {
        let f = self.state.lock().unwrap().clone();
        build_plan(&self.catalog, &f, rev(target), options)
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
                    id: UpdateId(id.parse().unwrap()),
                    revision: Revision(r.parse().unwrap()),
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

    fn run(
        &self,
        plan: &InstallPlan,
        backend: Option<Arc<dyn ServicingBackend>>,
        allow_unknown: bool,
    ) -> wsus_client::install::job::JobRecord {
        let runner = FakeRunner::exiting(0);
        let verifier = FakeVerifier::signed_by("Nobody");
        let ex = Executor {
            store: &self.store,
            runner: &runner,
            verifier: &verifier,
            jobs: &self.jobs,
            clock: &SystemClock,
            hook: &NoReport,
            sleeper: &NoSleep,
            watcher: &NoWatcher,
            config: ExecConfig {
                // an untrusted signer: CBS payloads must not be subject to the Authenticode gate
                trust: TrustPolicy {
                    allowed_signers: vec!["Microsoft Corporation".into()],
                },
                path_policy: PathPolicy::default(),
                timeout: Duration::from_secs(5),
                allow_unknown,
                servicing: backend,
                ..ExecConfig::default()
            },
        };
        ex.run(plan, &mut self.post_check()).unwrap()
    }
}

/// A backend that also flips the evaluator's facts when a package is added successfully (the way a
/// real install changes the registry state the evaluator reads).
#[derive(Debug)]
struct Linked {
    inner: FakeBackend,
    state: Arc<Mutex<FakeFacts>>,
    flips: Vec<(String, u32)>,
}

impl ServicingBackend for Linked {
    fn name(&self) -> &'static str {
        "linked-fake"
    }
    fn payload_extensions(&self) -> &'static [&'static str] {
        self.inner.payload_extensions()
    }
    fn list_packages(&self) -> Result<PackageSnapshot, BackendError> {
        self.inner.list_packages()
    }
    fn payload_applicability(&self, p: &Path) -> Result<Option<bool>, BackendError> {
        self.inner.payload_applicability(p)
    }
    fn pending_indicators(&self) -> Result<PendingIndicators, BackendError> {
        self.inner.pending_indicators()
    }
    fn free_disk_bytes(&self) -> Result<Option<u64>, BackendError> {
        self.inner.free_disk_bytes()
    }
    fn add_package(
        &self,
        payload: &Path,
        log_dir: &Path,
        timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        let r = self.inner.add_package(payload, log_dir, timeout)?;
        if r.native_code == Some(0) {
            for (id, st) in &self.flips {
                self.state.lock().unwrap().set_cbs_package(id, *st);
            }
        }
        Ok(r)
    }
}

fn entry(identity: &str, state: &str) -> PackageEntry {
    PackageEntry {
        identity: identity.into(),
        state: state.into(),
    }
}

fn lcu() -> Cbs {
    Cbs::new(0x10, "Package_for_RollupFix", "26100.5000.1.0", "lcu.cab")
}

fn ssu() -> Cbs {
    Cbs::new(
        0x20,
        "Package_for_ServicingStack_5000",
        "26100.5000.1.0",
        "ssu.cab",
    )
}

fn lcu_with_ssu_prerequisite() -> Cbs {
    let mut l = lcu();
    l.prerequisite = Some(0x20);
    l
}

fn options() -> PlanOptions {
    PlanOptions::default()
}

#[test]
fn the_servicing_stack_update_is_scheduled_before_the_lcu_only_with_the_option() {
    let r = rig(vec![lcu_with_ssu_prerequisite(), ssu()]);
    // Default planner: the prerequisite is only checked, so the LCU is not installable.
    let p = r.plan(0x10, &options());
    assert_eq!(p.outcome, PlanOutcome::NothingToDoNotApplicable);
    assert_eq!(p.schema, "wsus-install-plan/1");
    // With the option the SSU becomes an earlier step.
    let p = r.plan(
        0x10,
        &PlanOptions {
            plan_prerequisites: true,
            ..options()
        },
    );
    assert_eq!(p.outcome, PlanOutcome::Install, "{:?}", p.blockers);
    assert_eq!(p.schema, "wsus-install-plan/2");
    let order: Vec<&str> = p
        .steps
        .iter()
        .map(|s| s.payload.file_name.as_str())
        .collect();
    assert_eq!(order, ["ssu.cab", "lcu.cab"]);
    assert_eq!(
        p.steps[0].servicing_identity.as_deref(),
        Some("Package_for_ServicingStack_5000~31bf3856ad364e35~amd64~~26100.5000.1.0")
    );
    assert_eq!(
        p.steps[1].servicing_identity.as_deref(),
        Some("Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.5000.1.0")
    );
    assert!(
        p.decision(&rev(0x10).to_string())
            .unwrap()
            .notes
            .iter()
            .any(|n| n.contains("prerequisite updates scheduled"))
    );
    // SSU already installed: only the LCU is planned, and the option changes nothing else.
    r.set_installed(&ssu());
    let p = r.plan(
        0x10,
        &PlanOptions {
            plan_prerequisites: true,
            ..options()
        },
    );
    assert_eq!(p.steps.len(), 1);
    assert_eq!(p.steps[0].payload.file_name, "lcu.cab");
}

#[test]
fn a_cbs_step_is_refused_without_a_backend_exactly_as_before() {
    let r = rig(vec![lcu()]);
    let p = r.plan(0x10, &options());
    assert_eq!(p.outcome, PlanOutcome::Install);
    let rec = r.run(&p, None, false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .starts_with("planned handler cbs, not executable by this client")
    );
    assert_eq!(rec.schema, "wsus-install-job/1");
}

#[test]
fn the_os_installer_handler_stays_refused_even_with_a_backend() {
    let mut u = lcu();
    u.uri = OSI_URI;
    let r = rig(vec![u]);
    let p = r.plan(0x10, &options());
    assert_eq!(p.outcome, PlanOutcome::Install);
    let backend = Arc::new(FakeBackend::new(vec![]));
    let rec = r.run(&p, Some(backend.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("does not declare a complete acquirable file set")
    );
    assert!(
        backend.calls().is_empty(),
        "nothing may be asked of the stack"
    );
}

fn linked(r: &Rig, fake: FakeBackend, flips: &[&Cbs]) -> Arc<Linked> {
    Arc::new(Linked {
        inner: fake,
        state: r.state.clone(),
        flips: flips.iter().map(|u| (u.identity(), 112)).collect(),
    })
}

#[test]
fn both_oracles_agreeing_is_a_success_and_trust_is_delegated() {
    let l = lcu();
    let r = rig(vec![l.clone()]);
    let p = r.plan(0x10, &options());
    let fake = FakeBackend::new(vec![entry("Package_for_Other~1~amd64~~1.0", "Installed")])
        .script(AddScript::installed(&l.identity()));
    let b = linked(&r, fake, &[&l]);
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::Succeeded, "{rec:#?}");
    assert_eq!(rec.schema, "wsus-install-job/2");
    // the Authenticode gate was NOT applied (the verifier's signer is not allowed)
    assert!(rec.steps[0].signature.is_none());
    assert_eq!(rec.steps[0].digest_verified, Some(true));
    let ev = rec.servicing.as_ref().unwrap();
    assert_eq!(ev.trust, "servicing_stack");
    assert_eq!(ev.pre_count, 1);
    assert_eq!(ev.post_count, Some(2));
    assert_eq!(
        ev.diff,
        [format!("{}: (absent) -> Installed", l.identity())]
    );
    assert_eq!(ev.expected_after, [format!("{}: Installed", l.identity())]);
    assert_eq!(ev.oracles.as_ref().unwrap().combined, "agree_installed");
    let sv = rec.steps[0].servicing.as_ref().unwrap();
    assert_eq!(sv.native_code, Some(0));
    assert_eq!(sv.identity_expected.as_deref(), Some(l.identity().as_str()));
    assert!(!rec.reporting_sent);
    // order of the calls: gates first, then the add, then the post listing
    let calls = b.inner.calls();
    assert_eq!(calls[0], "pending");
    assert!(calls.iter().position(|c| c == "add lcu.cab").unwrap() > 2);
    assert_eq!(calls.last().unwrap(), "pending");
}

#[test]
fn disagreeing_oracles_are_never_a_success() {
    let l = lcu();
    let r = rig(vec![l.clone()]);
    let p = r.plan(0x10, &options());
    // the stack lists the package Installed but the evaluator's facts never change
    let fake = FakeBackend::new(vec![]).script(AddScript::installed(&l.identity()));
    let rec = r.run(&p, Some(Arc::new(fake)), false);
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    let o = rec.servicing.as_ref().unwrap().oracles.clone().unwrap();
    assert_eq!(o.combined, "disagree_packages_installed");
    assert!(rec.notes.iter().any(|n| n.contains("oracles disagree")));
    // and the opposite: evaluator installed, stack does not list the package
    let r = rig(vec![l.clone()]);
    let p = r.plan(0x10, &options());
    let mut silent = AddScript::installed(&l.identity());
    silent.upsert.clear();
    let b = linked(&r, FakeBackend::new(vec![]).script(silent), &[&l]);
    let rec = r.run(&p, Some(b), false);
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    assert_eq!(
        rec.servicing.unwrap().oracles.unwrap().combined,
        "disagree_evaluator_installed"
    );
}

#[test]
fn a_reboot_after_the_ssu_stops_the_run_and_records_the_remaining_steps() {
    let (s, l) = (ssu(), lcu_with_ssu_prerequisite());
    let r = rig(vec![l.clone(), s.clone()]);
    let p = r.plan(
        0x10,
        &PlanOptions {
            plan_prerequisites: true,
            ..options()
        },
    );
    assert_eq!(p.steps.len(), 2);
    let fake = FakeBackend::new(vec![])
        .script(AddScript::reboot(&s.identity()))
        .script(AddScript::installed(&l.identity()));
    let b = Arc::new(fake);
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    assert_eq!(rec.steps[0].state, StepState::Finished);
    assert_eq!(
        rec.steps[1].state,
        StepState::Pending,
        "the LCU must wait for the reboot"
    );
    assert_eq!(rec.servicing.as_ref().unwrap().remaining_steps, [1]);
    assert_eq!(rec.steps[0].exit_code, Some(3010));
    assert_eq!(
        b.calls().iter().filter(|c| c.starts_with("add ")).count(),
        1
    );
    // after the reboot the operator reruns: a fresh plan continues with what is left
    r.set_installed(&s);
    let p2 = r.plan(
        0x10,
        &PlanOptions {
            plan_prerequisites: true,
            ..options()
        },
    );
    assert_eq!(p2.steps.len(), 1);
    assert_eq!(p2.steps[0].payload.file_name, "lcu.cab");
}

#[test]
fn an_install_pending_package_after_a_zero_exit_means_reboot_required() {
    let l = lcu();
    let r = rig(vec![l.clone()]);
    let p = r.plan(0x10, &options());
    let mut script = AddScript::installed(&l.identity());
    script.upsert[0].state = "Install Pending".into();
    let rec = r.run(
        &p,
        Some(Arc::new(FakeBackend::new(vec![]).script(script))),
        false,
    );
    assert_eq!(rec.status, JobStatus::RebootRequired);
    assert!(rec.notes.iter().any(|n| n.contains("Install Pending")));
}

#[test]
fn a_failed_add_is_a_failure_with_the_native_code() {
    let l = lcu();
    let r = rig(vec![l.clone()]);
    let p = r.plan(0x10, &options());
    let rec = r.run(
        &p,
        Some(Arc::new(
            FakeBackend::new(vec![]).script(AddScript::failed(0x800f0922)),
        )),
        false,
    );
    assert_eq!(rec.status, JobStatus::Failed);
    assert_eq!(rec.steps[0].exit_code, Some(0x800f0922u32 as i32));
    assert_eq!(
        rec.steps[0].servicing.as_ref().unwrap().native_code,
        Some(0x800f0922)
    );
}

#[test]
fn a_timeout_leaves_the_step_unconfirmed_and_does_not_wait() {
    let l = lcu();
    let r = rig(vec![l.clone()]);
    let p = r.plan(0x10, &options());
    let b = Arc::new(FakeBackend::new(vec![]).script(AddScript::timeout()));
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    assert!(rec.steps[0].timed_out);
    assert_eq!(rec.steps[0].exit_code, None);
    assert_eq!(rec.post_check.wait_bound_secs, 0);
    assert!(rec.notes.iter().any(|n| n.contains("NOT killed")));
    // the stack is busy with the timed-out call: no second listing is requested (it would block)
    assert_eq!(
        b.calls().iter().filter(|c| c.as_str() == "list").count(),
        1,
        "only the pre-state listing"
    );
    assert_eq!(rec.servicing.as_ref().unwrap().post_count, None);
}

#[test]
fn a_pending_restart_refuses_the_run_before_anything_is_added() {
    let l = lcu();
    let r = rig(vec![l]);
    let p = r.plan(0x10, &options());
    let b = Arc::new(FakeBackend::new(vec![]).pending(PendingIndicators {
        set: vec!["CBS RebootPending".into()],
        unavailable: vec![],
    }));
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("restart the machine first")
    );
    assert!(!b.calls().iter().any(|c| c.starts_with("add ")));
}

#[test]
fn low_disk_and_unreadable_state_refuse_the_run() {
    let l = lcu();
    let r = rig(vec![l]);
    let p = r.plan(0x10, &options());
    let low = Arc::new(FakeBackend::new(vec![]).free_disk(Some(1024)));
    let rec = r.run(&p, Some(low), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("free disk")
    );
    let blind = Arc::new(
        FakeBackend::new(vec![]).list_fails(BackendError::Command("dism exited 0x1".into())),
    );
    let rec = r.run(&p, Some(blind), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("cannot list")
    );
}

#[test]
fn allow_unknown_is_refused_for_servicing_steps() {
    let l = lcu();
    let r = rig(vec![l]);
    let p = r.plan(0x10, &options());
    let rec = r.run(&p, Some(Arc::new(FakeBackend::new(vec![]))), true);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("--allow-unknown")
    );
}

#[test]
fn the_stack_saying_not_applicable_conflicts_with_the_evaluator_and_nothing_is_installed() {
    let l = lcu();
    let r = rig(vec![l]);
    let p = r.plan(0x10, &options());
    let b = Arc::new(FakeBackend::new(vec![]).applicability(Some(false)));
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::Failed);
    assert_eq!(rec.steps[0].state, StepState::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("oracles conflict")
    );
    assert!(!b.calls().iter().any(|c| c.starts_with("add ")));
}

#[test]
fn a_digest_mismatch_refuses_before_anything_runs() {
    let l = lcu();
    let r = rig(vec![l]);
    let p = r.plan(0x10, &options());
    fs::write(r.store.files["lcu.cab"].clone(), b"tampered payload").unwrap();
    let b = Arc::new(FakeBackend::new(vec![]));
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(b.calls().is_empty());
}

#[test]
fn a_payload_the_backend_cannot_add_is_refused() {
    let mut u = lcu();
    u.file = "update.msu";
    let r = rig(vec![u]);
    let p = r.plan(0x10, &options());
    let rec = r.run(&p, Some(Arc::new(FakeBackend::new(vec![]))), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(rec.steps[0].refusal.as_deref().unwrap().contains(".msu"));
    // a backend that supports .msu accepts it
    let r = rig(vec![{
        let mut u = lcu();
        u.file = "update.msu";
        u
    }]);
    let p = r.plan(0x10, &options());
    let ok = FakeBackend::new(vec![])
        .extensions(&["msu"])
        .script(AddScript::installed(&lcu().identity()));
    let rec = r.run(&p, Some(Arc::new(ok)), false);
    assert_ne!(rec.status, JobStatus::Refused);
}

#[test]
fn old_job_records_stay_readable() {
    // A /1 record has no `servicing` keys at all: they are skipped when absent and defaulted on read.
    let r = rig(vec![lcu()]);
    let p = r.plan(0x10, &options());
    let rec = r.run(&p, None, false);
    let text = serde_json::to_string(&rec).unwrap();
    assert!(!text.contains("\"servicing\":"));
    let back: wsus_client::install::job::JobRecord = serde_json::from_str(&text).unwrap();
    assert_eq!(back.schema, "wsus-install-job/1");
    assert!(back.servicing.is_none());
    let _ = r.updates.len();
    let _: PathBuf = PathBuf::new();
}

#[test]
fn cbs_installable_is_unknown_unless_delegated_to_the_servicing_stack() {
    let mut u = lcu();
    u.installable_cbs = true;
    let r = rig(vec![u]);
    // The real catalog shape: CbsPackageInstallable cannot be evaluated from facts, so the plan is refused.
    let p = r.plan(0x10, &options());
    assert_eq!(p.outcome, PlanOutcome::Refused);
    assert!(
        p.blockers
            .iter()
            .any(|b| b.text.contains("CbsPackageInstallable")),
        "{:?}",
        p.blockers
    );
    // With the explicit delegation the plan installs and says so.
    let p = r.plan(
        0x10,
        &PlanOptions {
            delegate_cbs_installable: true,
            ..options()
        },
    );
    assert_eq!(p.outcome, PlanOutcome::Install, "{:?}", p.blockers);
    assert!(
        p.notes
            .iter()
            .any(|n| n.contains("CbsPackageInstallable was treated as True"))
    );
    // The executor still refuses a package the stack says is not applicable.
    let b = Arc::new(FakeBackend::new(vec![]).applicability(Some(false)));
    let rec = r.run(&p, Some(b.clone()), false);
    assert_eq!(rec.status, JobStatus::Failed);
    assert!(!b.calls().iter().any(|c| c.starts_with("add ")));
}
