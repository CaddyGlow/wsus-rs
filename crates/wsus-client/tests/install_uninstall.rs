//! Host tests of the client-side uninstall (docs/wsus-osinstaller-spike.md 18.9) with a fake servicing
//! backend: the uninstall plan, the gates, the reboot and permanent-package handling, the two
//! post-check oracles and the timeout. The catalog is synthetic and uses the real handler shape of a
//! `.NET` rollup (`OSInstaller`) and of a `Cbs` update with `UninstallationBehavior`. Nothing here is
//! evidence about Windows or DISM; the guest runs are recorded in docs/wsus-validation.md.
use base64::Engine as _;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use uuid::Uuid;
use wsus_client::{
    install::{
        PlanOptions, PlanOutcome, RecordingFacts, build_plan, build_uninstall_plan,
        executor::{ExecConfig, Executor, NoSleep},
        handler_log::NoWatcher,
        job::{JobRecord, JobStatus, JobStore, NoReport, PostCheck, StepState},
        plan::{InstallPlan, Planner},
        runner::FakeRunner,
        servicing::{
            BackendError, FakeBackend, PackageEntry, PackageSnapshot, PendingIndicators,
            ServicingBackend, ServicingResult, StepOperation, fake::RemoveScript,
        },
        signature::{FakeVerifier, TrustPolicy},
        store::FixedStore,
    },
    session::SystemClock,
    sync::{Catalog, RevisionRecord, RevisionStore, StoredFragment},
};
use wsus_protocol::{
    applicability::{FakeFacts, RegValue, RegView, Tri},
    identity::{Revision, UpdateId, UpdateRevision},
    soap::Limits,
};

const CBS_URI: &str = "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs";
const OSI_URI: &str = "http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller";
const CMD_URI: &str =
    "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation";

const COMPDB: &str = include_str!("../../../docs/fixtures/wsus-m0-osinstaller/dotnet-CompDB.xml");
const COMPDB_CAB: &str = "DotNetServicingCompDB_KB5126052.xml.cab";

const DOTNET_ID: &str = "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1";
const PREDECESSOR: &str = "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9321.3";
const LCU_ID: &str = "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0";

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

fn compdb_cab() -> Vec<u8> {
    let mut b = cabinet::CabinetBuilder::new(cabinet::WriteCompression::MsZip);
    b.add_file("DotNetServicingCompDB_KB5126052.xml", COMPDB.as_bytes())
        .unwrap();
    let mut out = Cursor::new(Vec::new());
    b.write(&mut out).unwrap();
    out.into_inner()
}

#[derive(Clone)]
struct Upd {
    id: u128,
    package: &'static str,
    version: &'static str,
    uri: &'static str,
    uninstallable: bool,
    /// The core fragment carries the package manifest (real `Cbs` updates; the real `.NET` OSInstaller
    /// updates do not).
    metadata: bool,
    /// Put the CompDB cabinet in the store (an OSInstaller update).
    compdb_in_store: bool,
}

/// The real shape of the `.NET` rollup leaf: OSInstaller handler, `ProductReleaseInstalled` rule, no
/// package manifest and NO `UninstallationBehavior` (OBSERVED in the lab catalog, KB5126052).
fn dotnet() -> Upd {
    Upd {
        id: 0x10,
        package: "Package_for_DotNetRollup_481",
        version: "10.0.9347.1",
        uri: OSI_URI,
        uninstallable: false,
        metadata: false,
        compdb_in_store: true,
    }
}

/// A `Cbs` update with the manifest and an `UninstallationBehavior` (the real `Cbs` shape).
fn cbs_rollup() -> Upd {
    Upd {
        id: 0x20,
        package: "Package_for_RollupFix",
        version: "26100.9457.1.0",
        uri: CBS_URI,
        uninstallable: true,
        metadata: true,
        compdb_in_store: false,
    }
}

fn lcu() -> Upd {
    cbs_rollup()
}

fn write_catalog(dir: &Path, updates: &[Upd]) {
    let store = RevisionStore::open(dir).unwrap();
    let compdb = compdb_cab();
    for u in updates {
        let osi = u.uri == OSI_URI;
        let (installed, metadata) = if osi {
            (
                r#"<ProductReleaseInstalled Name="Microsoft.NetFX.amd64" Version="2400.26200.9347.1" />"#
                    .to_owned(),
                String::new(),
            )
        } else {
            (
                "<CbsPackageInstalled />".to_owned(),
                if u.metadata {
                    format!(
                        r#"<Metadata><CbsPackageApplicabilityMetadata><assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="{}" version="{}" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" /><package identifier="KB1" restart="possible"></package></assembly></CbsPackageApplicabilityMetadata></Metadata>"#,
                        u.package, u.version
                    )
                } else {
                    String::new()
                },
            )
        };
        let core = format!(
            r#"<UpdateIdentity UpdateID="{}" RevisionNumber="1" /><Properties UpdateType="Software" /><ApplicabilityRules><IsInstalled>{installed}</IsInstalled>{metadata}</ApplicabilityRules>"#,
            rev(u.id).id,
        );
        let data = if u.uri == CBS_URI {
            r#"<HandlerSpecificData type="cbs:Cbs"><CbsData PackageIdentity="" /></HandlerSpecificData>"#
        } else if osi {
            r#"<HandlerSpecificData type="OSInstallerMetadata"><OSInstallData InitialModule="UpdateAgent.dll" /></HandlerSpecificData>"#
        } else {
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Arguments="/q" Program="x.exe" RebootByDefault="false" DefaultResult="Failed" /></HandlerSpecificData>"#
        };
        let uninstall = if u.uninstallable {
            r#"<UninstallationBehavior RebootBehavior="CanRequestReboot" />"#
        } else {
            ""
        };
        let file = |name: &str, bytes: &[u8], extra: &str| {
            format!(
                r#"<File {extra} Digest="{}" DigestAlgorithm="SHA1" FileName="{name}" Size="{}"><AdditionalDigest Algorithm="SHA256">{}</AdditionalDigest></File>"#,
                b64(&Sha1::digest(bytes)),
                bytes.len(),
                b64(&Sha256::digest(bytes)),
            )
        };
        let mut files = file(
            "x.cab",
            b"the update's payload",
            r#"PatchingType="SelfContained""#,
        );
        if osi {
            files += &file(COMPDB_CAB, &compdb, r#"PatchingTypePreferred="Metadata""#);
        }
        let ext = format!(
            r#"<ExtendedProperties DefaultPropertiesLanguage="en" Handler="{}" MaxDownloadSize="10"><InstallationBehavior RebootBehavior="CanRequestReboot" />{uninstall}</ExtendedProperties><Files>{files}</Files>{data}"#,
            u.uri,
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

const CBS_PACKAGES: &str =
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";

/// The package in `state` as both the CBS state fact and the registry the `.NET` evaluator reads.
fn mark_package(f: &mut FakeFacts, id: &str, state: u32) {
    f.set_cbs_package(id, state);
    let key = format!("{CBS_PACKAGES}\\{id}");
    f.add_key(RegView::Native, CBS_PACKAGES);
    f.add_key(RegView::Native, &key);
    f.set_value(
        RegView::Native,
        &key,
        "CurrentState",
        RegValue::Dword(state),
    );
}

struct Rig {
    _dir: TempDir,
    store: FixedStore,
    jobs: JobStore,
    catalog: Catalog,
    state: Arc<Mutex<FakeFacts>>,
    /// The executor's override (the plan option is separate): on by default.
    allow_undeclared: std::cell::Cell<bool>,
}

fn rig(updates: Vec<Upd>) -> Rig {
    let dir = TempDir::new().unwrap();
    let meta = dir.path().join("meta");
    write_catalog(&meta, &updates);
    let root = dir.path().join("store");
    fs::create_dir_all(&root).unwrap();
    let mut files = BTreeMap::new();
    if updates.iter().any(|u| u.compdb_in_store) {
        let p = root.join(COMPDB_CAB);
        fs::write(&p, compdb_cab()).unwrap();
        files.insert(COMPDB_CAB.to_owned(), p);
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
        // only the CompDB cabinet (evidence of the package identity) is ever read; the update's
        // own payload is not in the store and an uninstall never asks for it
        store: FixedStore { root, files },
        jobs: JobStore::open(dir.path().join("jobs")).unwrap(),
        catalog,
        state: Arc::new(Mutex::new(FakeFacts::windows11_x64())),
        allow_undeclared: std::cell::Cell::new(true),
        _dir: dir,
    }
}

impl Rig {
    fn set_installed(&self, id: &str) {
        mark_package(&mut self.state.lock().unwrap(), id, 112);
    }

    fn plan(&self, target: u128) -> InstallPlan {
        let f = self.state.lock().unwrap().clone();
        build_uninstall_plan(&self.catalog, &f, rev(target), &undeclared())
    }

    /// The same callback the CLI uses: `installed` means STILL installed.
    fn post_check(&self) -> impl FnMut(&[String]) -> PostCheck + '_ {
        move |executed: &[String]| {
            let f = self.state.lock().unwrap().clone();
            let rec = RecordingFacts::new(&f);
            let planner = Planner::new(&self.catalog, &rec, PlanOptions::default());
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
                match planner.installed_verdict(rv).0 {
                    Tri::True => pc.installed.push(u.clone()),
                    Tri::Unknown => pc.unknown.push(u.clone()),
                    Tri::False => pc.not_installed.push(u.clone()),
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
    ) -> JobRecord {
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
                trust: TrustPolicy {
                    allowed_signers: vec!["Microsoft Corporation".into()],
                },
                timeout: Duration::from_secs(5),
                allow_unknown,
                servicing: backend,
                allow_undeclared_uninstall: self.allow_undeclared.get(),
                ..ExecConfig::default()
            },
        };
        ex.run(plan, &mut self.post_check()).unwrap()
    }
}

/// A backend that also changes the evaluator's facts when a removal completes (the way a real removal
/// changes the registry state the evaluator reads). `after` is the facts after the call.
#[derive(Debug)]
struct Linked {
    inner: FakeBackend,
    state: Arc<Mutex<FakeFacts>>,
    /// Package state the evaluator reads after the call (`None`: the package is gone).
    after: Option<u32>,
    id: String,
}

impl ServicingBackend for Linked {
    fn name(&self) -> &'static str {
        "linked-fake"
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
        self.inner.add_package(payload, log_dir, timeout)
    }
    fn supports_remove_package(&self) -> bool {
        true
    }
    fn remove_package(
        &self,
        identity: &str,
        log_dir: &Path,
        timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        let r = self.inner.remove_package(identity, log_dir, timeout)?;
        if matches!(r.native_code, Some(0) | Some(3010)) {
            let mut f = self.state.lock().unwrap();
            *f = FakeFacts::windows11_x64();
            if let Some(st) = self.after {
                mark_package(&mut f, &self.id, st);
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

/// The lab state of spike 18.4: the new rollup Installed, its predecessor Superseded.
fn rollup_listing() -> Vec<PackageEntry> {
    vec![
        entry(DOTNET_ID, "Installed"),
        entry(PREDECESSOR, "Superseded"),
        entry(
            "Package_for_Other~31bf3856ad364e35~amd64~~1.0.0.0",
            "Installed",
        ),
    ]
}

fn linked(r: &Rig, fake: FakeBackend, after: Option<u32>) -> Arc<dyn ServicingBackend> {
    Arc::new(Linked {
        inner: fake,
        state: Arc::clone(&r.state),
        after,
        id: DOTNET_ID.into(),
    })
}

/// The options an operator needs for the real `.NET` rollup leaf (it declares no UninstallationBehavior).
fn undeclared() -> PlanOptions {
    PlanOptions {
        allow_undeclared_uninstall: true,
        ..PlanOptions::default()
    }
}

// ---- plan ----------------------------------------------------------------------------------

#[test]
fn an_installed_dotnet_rollup_plans_an_uninstall_step_that_reads_its_identity_from_the_compdb() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    assert_eq!(p.outcome, PlanOutcome::Uninstall, "{:?}", p.blockers);
    assert_eq!(p.schema, "wsus-install-plan/3");
    assert_eq!(p.steps.len(), 1);
    // the real leaf's metadata names no package: the identity is read from the CompDB when it runs
    assert_eq!(p.steps[0].servicing_identity, None);
    assert!(
        p.steps[0]
            .extra_payloads
            .iter()
            .any(|e| e.file_name == COMPDB_CAB)
    );
    assert!(
        p.notes
            .iter()
            .any(|n| n.contains("declares no UninstallationBehavior"))
    );
    // the document round-trips and the outcome value is new, so an older reader cannot run it as an
    // install
    let json = p.to_json();
    assert!(json.contains("\"outcome\": \"uninstall\""));
    let back: InstallPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

#[test]
fn the_real_dotnet_leaf_declares_no_uninstall_behavior_and_is_refused_without_the_override() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let f = r.state.lock().unwrap().clone();
    let p = build_uninstall_plan(&r.catalog, &f, rev(0x10), &PlanOptions::default());
    assert_eq!(p.outcome, PlanOutcome::Refused);
    assert!(p.steps.is_empty());
    assert!(
        p.blockers
            .iter()
            .any(|b| b.text.contains("--allow-undeclared"))
    );
}

#[test]
fn a_cbs_update_takes_its_identity_from_the_manifest_and_needs_no_override() {
    let r = rig(vec![lcu()]);
    r.set_installed(LCU_ID);
    let f = r.state.lock().unwrap().clone();
    let p = build_uninstall_plan(&r.catalog, &f, rev(0x20), &PlanOptions::default());
    assert_eq!(p.outcome, PlanOutcome::Uninstall, "{:?}", p.blockers);
    assert_eq!(p.steps[0].servicing_identity.as_deref(), Some(LCU_ID));
}

#[test]
fn an_update_that_is_not_installed_has_nothing_to_remove() {
    let r = rig(vec![dotnet()]);
    let p = r.plan(0x10);
    assert_eq!(p.outcome, PlanOutcome::NothingToDoNotInstalled);
    assert!(p.steps.is_empty());
    let rec = r.run(&p, Some(Arc::new(FakeBackend::new(vec![]))), false);
    assert_eq!(rec.status, JobStatus::NoAction);
}

#[test]
fn updates_that_cannot_be_uninstalled_by_this_client_are_refused_in_the_plan() {
    let mut no_behavior = lcu();
    no_behavior.uninstallable = false;
    let mut no_identity = lcu();
    no_identity.metadata = false;
    let mut command = lcu();
    command.uri = CMD_URI;
    command.uninstallable = true;
    for (name, upd, needle) in [
        (
            "no UninstallationBehavior",
            no_behavior,
            "UninstallationBehavior",
        ),
        ("no package identity", no_identity, "no package identity"),
        ("command line handler", command, "not a servicing"),
    ] {
        let r = rig(vec![upd]);
        r.set_installed(LCU_ID);
        let f = r.state.lock().unwrap().clone();
        let p = build_uninstall_plan(&r.catalog, &f, rev(0x20), &PlanOptions::default());
        assert_eq!(p.outcome, PlanOutcome::Refused, "{name}");
        assert!(p.steps.is_empty(), "{name}");
        assert!(
            p.blockers.iter().any(|b| b.text.contains(needle)),
            "{name}: {:?}",
            p.blockers
        );
    }
}

#[test]
fn an_operator_named_package_is_validated_and_used() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let f = r.state.lock().unwrap().clone();
    let named = |p: &str| {
        build_uninstall_plan(
            &r.catalog,
            &f,
            rev(0x10),
            &PlanOptions {
                uninstall_package: Some(p.into()),
                ..undeclared()
            },
        )
    };
    let ok = named(DOTNET_ID);
    assert_eq!(ok.outcome, PlanOutcome::Uninstall);
    assert_eq!(ok.steps[0].servicing_identity.as_deref(), Some(DOTNET_ID));
    assert!(ok.notes.iter().any(|n| n.contains("named by the operator")));
    let bad = named("Package_for_X /Online");
    assert_eq!(bad.outcome, PlanOutcome::Refused);
}

#[test]
fn an_unknown_update_is_refused_and_allow_unknown_changes_nothing() {
    let r = rig(vec![dotnet()]);
    let p = {
        let f = r.state.lock().unwrap().clone();
        build_uninstall_plan(
            &r.catalog,
            &f,
            rev(0x99),
            &PlanOptions {
                allow_unknown: true,
                ..PlanOptions::default()
            },
        )
    };
    assert_eq!(p.outcome, PlanOutcome::Refused);
    assert!(!p.allow_unknown);
}

#[test]
fn install_plans_keep_their_schema_and_do_not_carry_uninstall_fields() {
    let r = rig(vec![dotnet()]);
    let f = r.state.lock().unwrap().clone();
    let p = build_plan(&r.catalog, &f, rev(0x10), &PlanOptions::default());
    assert_eq!(p.schema, "wsus-install-plan/1");
    assert!(!p.to_json().contains("uninstall\""));
}

// ---- execution -----------------------------------------------------------------------------

#[test]
fn a_removal_that_needs_a_restart_is_reboot_required_with_both_oracles_recorded() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    // DISM's observed behaviour: the predecessor returns to Install Pending in the same call
    let fake = FakeBackend::new(rollup_listing()).script_remove(
        RemoveScript::reboot(DOTNET_ID).with_upsert(entry(PREDECESSOR, "Install Pending")),
    );
    let backend = linked(&r, fake, None);
    let rec = r.run(&p, Some(backend), false);
    assert_eq!(rec.status, JobStatus::RebootRequired, "{:?}", rec.steps);
    assert_eq!(rec.schema, "wsus-install-job/3");
    let st = &rec.steps[0];
    assert_eq!(st.state, StepState::Finished);
    assert_eq!(st.exit_code, Some(3010));
    let sv = st.servicing.as_ref().unwrap();
    assert_eq!(sv.operation, StepOperation::Uninstall);
    assert_eq!(sv.identity_expected.as_deref(), Some(DOTNET_ID));
    let ev = rec.servicing.as_ref().unwrap();
    assert_eq!(
        ev.expected_after,
        [format!("{DOTNET_ID}: Uninstall Pending")]
    );
    assert!(
        ev.diff
            .contains(&format!("{PREDECESSOR}: Superseded -> Install Pending"))
    );
    assert!(
        ev.diff
            .contains(&format!("{DOTNET_ID}: Installed -> Uninstall Pending"))
    );
    assert!(ev.pending_after.as_ref().unwrap().reboot_pending());
    let o = ev.oracles.as_ref().unwrap();
    assert_eq!(o.packages, "pending");
    assert_eq!(o.combined, "agree_pending");
    // no evaluator wait after a restart request
    assert_eq!(rec.post_check.polls, 1);
    assert_eq!(rec.post_check.wait_bound_secs, 0);
}

#[test]
fn a_removal_without_a_restart_succeeds_only_when_both_oracles_say_removed() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let fake = FakeBackend::new(rollup_listing()).script_remove(RemoveScript::removed(DOTNET_ID));
    let rec = r.run(&p, Some(linked(&r, fake, None)), false);
    assert_eq!(rec.status, JobStatus::Succeeded, "{:?}", rec.notes);
    let o = rec.servicing.as_ref().unwrap().oracles.as_ref().unwrap();
    assert_eq!(o.packages, "absent");
    assert!(
        o.evaluator_installed,
        "for an uninstall: evaluator says removed"
    );
    assert_eq!(o.combined, "agree_removed");
    assert!(rec.post_check.converged);
    assert_eq!(rec.post_check.not_installed.len(), 1);
}

#[test]
fn oracles_that_disagree_never_make_a_succeeded_removal() {
    // the package is gone from the listing but the evaluator still says installed
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let fake = FakeBackend::new(rollup_listing()).script_remove(RemoveScript::removed(DOTNET_ID));
    // keep the evaluator's state at 112 after the call
    let rec = r.run(&p, Some(linked(&r, fake, Some(112))), false);
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    let o = rec.servicing.as_ref().unwrap().oracles.as_ref().unwrap();
    assert_eq!(o.combined, "disagree_packages_absent");
    assert!(rec.notes.iter().any(|n| n.contains("oracles disagree")));
}

#[test]
fn a_permanent_package_is_a_classified_failed_refusal_that_is_not_retried() {
    let r = rig(vec![lcu()]);
    r.set_installed(LCU_ID);
    let p = r.plan(0x20);
    assert_eq!(p.outcome, PlanOutcome::Uninstall, "{:?}", p.blockers);
    let fake =
        FakeBackend::new(vec![entry(LCU_ID, "Installed")]).script_remove(RemoveScript::permanent());
    let backend: Arc<dyn ServicingBackend> = Arc::new(fake);
    let rec = r.run(&p, Some(backend.clone()), false);
    assert_eq!(rec.status, JobStatus::Failed);
    let st = &rec.steps[0];
    assert_eq!(st.exit_code, Some(0x800f_0825u32 as i32));
    assert!(
        st.refusal
            .as_deref()
            .unwrap()
            .starts_with("permanent package")
    );
    let sv = st.servicing.as_ref().unwrap();
    assert_eq!(sv.refusal_class.as_deref(), Some("permanent_package"));
    // nothing changed: the listing diff is empty and both oracles say still installed
    let ev = rec.servicing.as_ref().unwrap();
    assert!(ev.diff.is_empty());
    assert_eq!(ev.oracles.as_ref().unwrap().combined, "neither_removed");
    assert!(rec.notes.iter().any(|n| n.contains("permanent package")));

    // a second run is refused before the stack is asked again (no second scripted result exists, so
    // a call would be an error)
    let again = r.run(&p, Some(backend.clone()), false);
    assert_eq!(again.status, JobStatus::Refused);
    assert!(
        again.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("already refused")
    );
}

#[test]
fn the_fake_records_exactly_one_remove_call_for_a_refused_retry() {
    let r = rig(vec![lcu()]);
    r.set_installed(LCU_ID);
    let p = r.plan(0x20);
    let fake = Arc::new(
        FakeBackend::new(vec![entry(LCU_ID, "Installed")]).script_remove(RemoveScript::permanent()),
    );
    let backend: Arc<dyn ServicingBackend> = fake.clone();
    r.run(&p, Some(backend.clone()), false);
    r.run(&p, Some(backend), false);
    let removes = fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("remove "))
        .count();
    assert_eq!(removes, 1);
}

#[test]
fn a_timeout_is_unconfirmed_and_the_stack_is_not_listed_again() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let fake = Arc::new(FakeBackend::new(rollup_listing()).script_remove(RemoveScript::timeout()));
    let backend: Arc<dyn ServicingBackend> = fake.clone();
    let rec = r.run(&p, Some(backend), false);
    assert_eq!(rec.status, JobStatus::Unconfirmed);
    assert!(rec.steps[0].timed_out);
    assert_eq!(rec.steps[0].exit_code, None);
    let calls = fake.calls();
    // one listing before the call and none after it
    assert_eq!(
        calls.iter().filter(|c| *c == "list").count(),
        1,
        "{calls:?}"
    );
    let ev = rec.servicing.as_ref().unwrap();
    assert_eq!(ev.oracles.as_ref().unwrap().packages, "unavailable");
}

#[test]
fn other_stack_failures_are_failed_jobs() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let fake = FakeBackend::new(rollup_listing()).script_remove(RemoveScript::failed(0x800f0922));
    let rec = r.run(&p, Some(Arc::new(fake)), false);
    assert_eq!(rec.status, JobStatus::Failed);
    assert_eq!(rec.steps[0].exit_code, Some(0x800f_0922u32 as i32));
    assert_eq!(rec.steps[0].servicing.as_ref().unwrap().refusal_class, None);
}

// ---- gates ---------------------------------------------------------------------------------

#[test]
fn a_pending_restart_refuses_the_removal_before_the_stack_is_asked() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let fake = Arc::new(
        FakeBackend::new(rollup_listing())
            .pending(PendingIndicators {
                set: vec!["CBS RebootPending".into()],
                unavailable: vec![],
            })
            .script_remove(RemoveScript::reboot(DOTNET_ID)),
    );
    let rec = r.run(&p, Some(fake.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(rec.steps[0].refusal.as_deref().unwrap().contains("restart"));
    assert!(!fake.calls().iter().any(|c| c.starts_with("remove ")));
}

#[test]
fn a_package_that_is_not_listed_installed_is_refused() {
    for (listing, needle) in [
        (vec![entry(DOTNET_ID, "Install Pending")], "Install Pending"),
        (vec![entry(DOTNET_ID, "Superseded")], "Superseded"),
        (vec![], "not in the servicing stack's listing"),
    ] {
        let r = rig(vec![dotnet()]);
        r.set_installed(DOTNET_ID);
        let p = r.plan(0x10);
        let fake =
            Arc::new(FakeBackend::new(listing).script_remove(RemoveScript::reboot(DOTNET_ID)));
        let rec = r.run(&p, Some(fake.clone()), false);
        assert_eq!(rec.status, JobStatus::Refused, "{needle}");
        assert!(
            rec.steps[0].refusal.as_deref().unwrap().contains(needle),
            "{:?}",
            rec.steps[0].refusal
        );
        assert!(!fake.calls().iter().any(|c| c.starts_with("remove ")));
    }
}

#[test]
fn a_backend_without_removal_and_a_missing_backend_refuse_the_plan() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let rec = r.run(&p, None, false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("no servicing backend")
    );
    let fake = Arc::new(FakeBackend::new(rollup_listing()).without_remove());
    let rec = r.run(&p, Some(fake.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("cannot remove")
    );
    assert!(!fake.calls().iter().any(|c| c.starts_with("remove ")));
}

#[test]
fn a_plan_file_alone_cannot_enable_the_undeclared_override() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10); // planned with the override
    r.allow_undeclared.set(false); // executed without it
    let fake =
        Arc::new(FakeBackend::new(rollup_listing()).script_remove(RemoveScript::reboot(DOTNET_ID)));
    let rec = r.run(&p, Some(fake.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("--allow-undeclared")
    );
    assert!(!fake.calls().iter().any(|c| c.starts_with("remove ")));
}

#[test]
fn a_compdb_that_is_not_in_the_store_refuses_the_step() {
    let mut u = dotnet();
    u.compdb_in_store = false;
    let r = rig(vec![u]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    assert_eq!(p.outcome, PlanOutcome::Uninstall);
    let fake = Arc::new(FakeBackend::new(rollup_listing()));
    let rec = r.run(&p, Some(fake.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(rec.steps[0].refusal.as_deref().unwrap().contains("CompDB"));
    assert!(!fake.calls().iter().any(|c| c.starts_with("remove ")));
}

#[test]
fn allow_unknown_is_refused_for_an_uninstall() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let p = r.plan(0x10);
    let fake =
        Arc::new(FakeBackend::new(rollup_listing()).script_remove(RemoveScript::reboot(DOTNET_ID)));
    let rec = r.run(&p, Some(fake), true);
    assert_eq!(rec.status, JobStatus::Refused);
}

#[test]
fn a_tampered_identity_in_a_plan_file_is_refused() {
    let r = rig(vec![dotnet()]);
    r.set_installed(DOTNET_ID);
    let mut p = r.plan(0x10);
    p.steps[0].servicing_identity = Some("x~y~z~~1 /Online".into());
    let fake = Arc::new(FakeBackend::new(rollup_listing()));
    let rec = r.run(&p, Some(fake.clone()), false);
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(!fake.calls().iter().any(|c| c.starts_with("remove ")));
}

// ---- compatibility -------------------------------------------------------------------------

#[test]
fn job_records_of_installs_are_unchanged_and_old_servicing_records_still_read() {
    let old = r#"{"backend":"dism","native_code":0,"class":"success","description":"d","applicable":null,"identity_expected":"x","log_paths":[]}"#;
    let sv: wsus_client::install::servicing::StepServicing = serde_json::from_str(old).unwrap();
    assert_eq!(sv.operation, StepOperation::Install);
    assert_eq!(sv.refusal_class, None);
    let again = serde_json::to_string(&sv).unwrap();
    assert!(!again.contains("operation"));
    assert!(!again.contains("refusal_class"));
}
