//! Host tests of the `OSInstaller` install path (docs/wsus-osinstaller-spike.md): stage 1 covers the
//! `.NET` updates, a complete small set of `.cab` payloads (the KB cabinet and the servicing CompDB
//! cabinet). The catalog is synthetic but uses the REAL handler shape and a REAL CompDB (fixture of the
//! native `.NET` update) inside a cabinet built with `cabinet`; the evaluator rule is an evaluable stand-in
//! for `ProductReleaseInstalled` (the real rule is covered in `wsus-protocol`). Nothing here is evidence
//! about Windows, DISM or `UpdateAgent.dll`.
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
        PlanOptions, PlanOutcome, RecordingFacts, build_plan,
        executor::{ExecConfig, Executor, NoSleep},
        handler_log::NoWatcher,
        job::{JobRecord, JobStatus, JobStore, NoReport, PostCheck, StepState},
        plan::{InstallPlan, NodeStatus, Planner},
        runner::FakeRunner,
        safety::PathPolicy,
        servicing::{
            BackendError, FakeBackend, FakeOsBackend, OsInstallerBackend, OsInstallerMode,
            PackageSnapshot, PendingIndicators, ServicingBackend, ServicingResult,
            fake::AddScript,
            os_installer::{DownloadItem, DownloadPayloadType},
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

const OSI_URI: &str = "http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller";
const COMPDB: &str = include_str!("../../../docs/fixtures/wsus-m0-osinstaller/dotnet-CompDB.xml");
const IDENTITY: &str = "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1";
const KB: &str = "Windows11.0-KB5126052-x64-NDP481.cab";
const COMPDB_CAB: &str = "DotNetServicingCompDB_KB5126052.xml.cab";
const STACK_CAB: &str = "DesktopDeployment.cab";
const UPDATE: u128 = 0x30;

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

struct Files {
    kb: Vec<u8>,
    compdb: Vec<u8>,
    /// Extra declared file that makes the update a monthly-style set (not a complete cab set).
    psf: Option<Vec<u8>>,
    /// The declared `DesktopDeployment.cab` (`PatchingType="ServicingStack"`).
    stack: Option<Vec<u8>>,
    /// Declare the stack without any digest.
    stack_without_digest: bool,
    /// Do not declare the servicing CompDB cabinet (the monthly cumulative updates have none).
    no_compdb: bool,
    /// Declare the extra `psf` file without any digest (an incomplete set).
    psf_without_digest: bool,
}

/// A cabinet shaped like `DesktopDeployment.cab` (flat member names), built with `cabinet`.
fn stack_cab(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = cabinet::CabinetBuilder::new(cabinet::WriteCompression::MsZip);
    for (n, c) in members {
        b.add_file(n, c).unwrap();
    }
    let mut out = Cursor::new(Vec::new());
    b.write(&mut out).unwrap();
    out.into_inner()
}

fn plain_stack() -> Vec<u8> {
    stack_cab(&[
        ("UpdateAgent.dll", b"stand-in for UpdateAgent.dll"),
        ("wcp.dll", b"stand-in for wcp.dll"),
        ("Deployment.cab", b"stand-in for the nested cabinet"),
    ])
}

fn write_catalog(dir: &Path, f: &Files) {
    let store = RevisionStore::open(dir).unwrap();
    let core = format!(
        r#"<UpdateIdentity UpdateID="{}" RevisionNumber="1" /><Properties UpdateType="Software" /><ApplicabilityRules><IsInstalled><CbsPackageInstalledByIdentity PackageIdentity="{IDENTITY}" /></IsInstalled></ApplicabilityRules>"#,
        rev(UPDATE).id
    );
    let file = |name: &str, bytes: &[u8], extra: &str| {
        format!(
            r#"<File {extra} Digest="{}" DigestAlgorithm="SHA1" FileName="{name}" Size="{}"><AdditionalDigest Algorithm="SHA256">{}</AdditionalDigest></File>"#,
            b64(&Sha1::digest(bytes)),
            bytes.len(),
            b64(&Sha256::digest(bytes)),
        )
    };
    let mut files = file(KB, &f.kb, r#"PatchingType="SelfContained""#);
    if !f.no_compdb {
        files += &file(COMPDB_CAB, &f.compdb, r#"PatchingTypePreferred="Metadata""#);
    }
    if let Some(p) = &f.psf {
        files += &if f.psf_without_digest {
            format!(
                r#"<File PatchingType="SelfContained" FileName="Windows11.0-KB1-x64.psf" Size="{}" />"#,
                p.len()
            )
        } else {
            file(
                "Windows11.0-KB1-x64.psf",
                p,
                r#"PatchingType="SelfContained""#,
            )
        };
    }
    if let Some(st) = &f.stack {
        files += &if f.stack_without_digest {
            format!(
                r#"<File PatchingType="ServicingStack" FileName="{STACK_CAB}" Size="{}" />"#,
                st.len()
            )
        } else {
            file(STACK_CAB, st, r#"PatchingTypePreferred="ServicingStack""#)
        };
    }
    let total = f.kb.len()
        + if f.no_compdb { 0 } else { f.compdb.len() }
        + f.psf.as_ref().map_or(0, Vec::len)
        + f.stack.as_ref().map_or(0, Vec::len);
    let ext = format!(
        r#"<ExtendedProperties ProductName="Microsoft.NetFX.amd64" ReleaseVersion="2400.26200.9347.1" ReleaseRevision="1" DefaultPropertiesLanguage="en" Handler="{OSI_URI}" MaxDownloadSize="{total}"><InstallationBehavior RebootBehavior="CanRequestReboot" /></ExtendedProperties><Files>{files}</Files><HandlerSpecificData type="OSInstallerMetadata"><OSInstallData InitialModule="UpdateAgent.dll" /></HandlerSpecificData>"#
    );
    store
        .put(&RevisionRecord {
            identity: rev(UPDATE),
            is_leaf: true,
            update_type: Some("Software".into()),
            deployment: None,
            core: frag("Core", core),
            fragments: vec![frag("Extended", ext)],
        })
        .unwrap();
}

struct Rig {
    _dir: TempDir,
    store: FixedStore,
    jobs: JobStore,
    catalog: Catalog,
    state: Arc<Mutex<FakeFacts>>,
}

fn rig(f: &Files) -> Rig {
    let dir = TempDir::new().unwrap();
    let meta = dir.path().join("meta");
    write_catalog(&meta, f);
    let root = dir.path().join("store");
    fs::create_dir_all(&root).unwrap();
    let mut files = BTreeMap::new();
    let mut put = |name: &str, bytes: &[u8]| {
        let p = root.join(name);
        fs::write(&p, bytes).unwrap();
        files.insert(name.to_owned(), p);
    };
    put(KB, &f.kb);
    if !f.no_compdb {
        put(COMPDB_CAB, &f.compdb);
    }
    if let Some(p) = &f.psf {
        put("Windows11.0-KB1-x64.psf", p);
    }
    if let Some(st) = &f.stack {
        put(STACK_CAB, st);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for p in files.values() {
            fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
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
        _dir: dir,
    }
}

fn files() -> Files {
    Files {
        kb: b"the canonical .NET rollup cabinet".to_vec(),
        compdb: compdb_cab(),
        psf: None,
        stack: None,
        stack_without_digest: false,
        no_compdb: false,
        psf_without_digest: false,
    }
}

impl Rig {
    fn plan(&self) -> InstallPlan {
        let f = self.state.lock().unwrap().clone();
        build_plan(&self.catalog, &f, rev(UPDATE), &PlanOptions::default())
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
        mode: OsInstallerMode,
        servicing: Option<Arc<dyn ServicingBackend>>,
        os: Option<Arc<dyn OsInstallerBackend>>,
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
                path_policy: PathPolicy::default(),
                timeout: Duration::from_secs(5),
                allow_unknown,
                servicing,
                os_installer: os,
                os_installer_mode: mode,
                ..ExecConfig::default()
            },
        };
        ex.run(plan, &mut self.post_check()).unwrap()
    }
}

/// A backend that flips the evaluator's facts when a package is added successfully.
#[derive(Debug)]
struct Linked {
    inner: FakeBackend,
    state: Arc<Mutex<FakeFacts>>,
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
            self.state.lock().unwrap().set_cbs_package(IDENTITY, 112);
        }
        Ok(r)
    }
}

fn plain_backend() -> Arc<FakeBackend> {
    Arc::new(FakeBackend::new(vec![]).script(AddScript::installed(IDENTITY)))
}

fn items(name: &str) -> Vec<DownloadItem> {
    vec![DownloadItem {
        payload_type: DownloadPayloadType::Canonical,
        source: format!("C:\\sandbox\\{name}"),
        target_file_name: name.to_owned(),
    }]
}

#[test]
fn a_dotnet_update_plans_the_kb_cabinet_as_primary_and_the_compdb_as_extra() {
    let r = rig(&files());
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
    let step = &plan.steps[0];
    assert_eq!(step.payload.file_name, KB);
    assert_eq!(
        step.extra_payloads
            .iter()
            .map(|p| p.file_name.as_str())
            .collect::<Vec<_>>(),
        vec![COMPDB_CAB]
    );
    assert_eq!(step.extra_payloads[0].patching.as_deref(), Some("Metadata"));
}

#[test]
fn dism_mode_adds_the_cabinet_and_succeeds_when_both_oracles_agree() {
    let r = rig(&files());
    let plan = r.plan();
    let backend = Arc::new(Linked {
        inner: FakeBackend::new(vec![]).script(AddScript::installed(IDENTITY)),
        state: r.state.clone(),
    });
    let rec = r.run(&plan, OsInstallerMode::Dism, Some(backend), None, false);
    assert_eq!(rec.status, JobStatus::Succeeded, "{rec:#?}");
    let sv = rec.steps[0].servicing.as_ref().unwrap();
    let os = sv.os_installer.as_ref().unwrap();
    assert_eq!(os.mode, "dism");
    assert_eq!(os.expected_identities, vec![IDENTITY.to_owned()]);
    assert_eq!(sv.identity_expected.as_deref(), Some(IDENTITY));
}

#[test]
fn update_agent_mode_runs_the_backend_over_a_sandbox_with_every_payload_and_records_the_evidence() {
    let r = rig(&files());
    let plan = r.plan();
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone()),
        false,
    );
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    let reqs = os.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let mut declared = reqs[0].declared.clone();
    declared.sort();
    assert_eq!(declared, vec![COMPDB_CAB.to_owned(), KB.to_owned()]);
    assert!(
        !reqs[0].sandbox.exists(),
        "the sandbox copies are removed after the run"
    );
    let ev = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    assert_eq!(ev.mode, "update_agent");
    assert_eq!(ev.download_list.len(), 1);
    assert!(ev.missing.is_empty());
    assert_eq!(ev.phases.len(), 3);
}

#[test]
fn a_download_list_naming_an_unheld_file_fails_the_step() {
    let r = rig(&files());
    let plan = r.plan();
    let os = Arc::new(FakeOsBackend::reboot(
        IDENTITY,
        items("Windows11.0-KB1-x64.psf"),
    ));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os),
        false,
    );
    assert_eq!(rec.status, JobStatus::Failed);
    let ev = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    assert_eq!(ev.missing, vec!["Windows11.0-KB1-x64.psf".to_owned()]);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("needs files")
    );
}

#[test]
fn a_set_with_more_than_cabinets_is_planned_complete_and_runs_in_update_agent_mode() {
    let mut f = files();
    f.psf = Some(vec![7u8; 64]);
    let r = rig(&f);
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
    let mut extras: Vec<&str> = plan.steps[0]
        .extra_payloads
        .iter()
        .map(|p| p.file_name.as_str())
        .collect();
    extras.sort();
    assert_eq!(extras, vec![COMPDB_CAB, "Windows11.0-KB1-x64.psf"]);
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone()),
        false,
    );
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    let mut declared = os.requests.lock().unwrap()[0].declared.clone();
    declared.sort();
    assert_eq!(
        declared,
        vec![
            COMPDB_CAB.to_owned(),
            "Windows11.0-KB1-x64.psf".to_owned(),
            KB.to_owned()
        ]
    );
}

#[test]
fn a_file_the_backend_took_out_of_a_declared_msu_counts_as_held_and_is_recorded() {
    let mut f = files();
    f.psf = Some(vec![7u8; 64]);
    let r = rig(&f);
    let plan = r.plan();
    let os = Arc::new(
        FakeOsBackend::reboot(IDENTITY, items("Windows11.0-KB5043080-x64.wim")).with_provisioned(
            &["Windows11.0-KB5043080-x64.wim"],
            "Windows11.0-KB5043080-x64.msu",
        ),
    );
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone()),
        false,
    );
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    let ev = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    assert!(ev.missing.is_empty());
    assert_eq!(ev.provisioned.len(), 1);
    assert_eq!(ev.provisioned[0].container, "Windows11.0-KB5043080-x64.msu");
    // only declared .msu files are offered to the backend as containers (none declared here)
    assert!(os.requests.lock().unwrap()[0].containers.is_empty());
}

#[test]
fn a_set_with_a_file_lacking_a_digest_is_incomplete_and_never_planned_for_execution() {
    let mut f = files();
    f.psf = Some(vec![7u8; 64]);
    f.psf_without_digest = true;
    let r = rig(&f);
    let plan = r.plan();
    assert_ne!(plan.outcome, PlanOutcome::Install, "{plan:#?}");
    let why = plan
        .blockers
        .iter()
        .map(|g| g.text.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        why.contains("Windows11.0-KB1-x64.psf has no SHA-1 or SHA-256 digest"),
        "{why}"
    );
}

#[test]
fn a_single_file_os_installer_update_is_refused_as_incomplete() {
    let mut f = files();
    f.no_compdb = true;
    let r = rig(&f);
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
    assert!(plan.steps[0].extra_payloads.is_empty());
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)))),
        false,
    );
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("does not declare a complete acquirable file set")
    );
    assert_eq!(rec.steps[0].state, StepState::Refused);
}

#[test]
fn a_set_without_a_compdb_is_refused_in_dism_mode_but_runs_in_update_agent_mode() {
    let mut f = files();
    f.no_compdb = true;
    f.psf = Some(vec![7u8; 64]);
    let r = rig(&f);
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
    assert_eq!(plan.steps[0].extra_payloads.len(), 1);
    let rec = r.run(
        &plan,
        OsInstallerMode::Dism,
        Some(plain_backend()),
        None,
        false,
    );
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("needs osinstaller_mode update_agent")
    );
    // update_agent mode: the identity comes from the ActionList the stack generated
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os),
        false,
    );
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    let ev = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    assert_eq!(ev.expected_identities, vec![IDENTITY.to_owned()]);
    assert_eq!(
        rec.servicing.as_ref().unwrap().expected_after,
        vec![format!("{IDENTITY}: absent")],
        "the post-check looked for the ActionList identity"
    );
}

#[test]
fn a_tampered_extra_payload_is_refused_before_anything_runs() {
    let r = rig(&files());
    let plan = r.plan();
    fs::write(r.store.root.join(COMPDB_CAB), b"not the cabinet").unwrap();
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone()),
        false,
    );
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(os.requests.lock().unwrap().is_empty());
}

#[test]
fn missing_backends_and_allow_unknown_are_refused() {
    let r = rig(&files());
    let plan = r.plan();
    // update_agent mode without the UpdateAgent backend
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        None,
        false,
    );
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("update_agent")
    );
    // no servicing backend at all
    let rec = r.run(&plan, OsInstallerMode::Dism, None, None, false);
    assert_eq!(rec.status, JobStatus::Refused);
    // --allow-unknown
    let rec = r.run(
        &plan,
        OsInstallerMode::Dism,
        Some(plain_backend()),
        None,
        true,
    );
    assert_eq!(rec.status, JobStatus::Refused);
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("allow-unknown")
    );
}

#[test]
fn an_empty_action_list_from_the_stack_is_a_failed_step() {
    let r = rig(&files());
    let plan = r.plan();
    // the stack answers success-class NotApplicable (empty ActionList)
    let outcome = wsus_client::install::servicing::os_installer::OsInstallOutcome {
        phases: Vec::new(),
        action_list: None,
        download_list: Vec::new(),
        provisioned: Vec::new(),
        expected_identities: Vec::new(),
        result: ServicingResult {
            backend: "fake_update_agent".into(),
            native_code: Some(0),
            class: wsus_client::install::servicing::ServicingClass::NotApplicable,
            description: "the update stack produced an empty ActionList".into(),
            timed_out: false,
            stdout_tail: None,
            stderr_tail: None,
            log_paths: Vec::new(),
        },
    };
    let os = Arc::new(FakeOsBackend::new(Ok(outcome)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os),
        false,
    );
    assert_eq!(rec.status, JobStatus::Failed);
}

fn files_with_stack() -> Files {
    Files {
        stack: Some(plain_stack()),
        ..files()
    }
}

fn run_os(r: &Rig, os: &Arc<FakeOsBackend>) -> JobRecord {
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
    r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone() as Arc<dyn OsInstallerBackend>),
        false,
    )
}

#[test]
fn a_declared_stack_cabinet_is_a_step_field_not_a_sandbox_payload() {
    let r = rig(&files_with_stack());
    let plan = r.plan();
    let step = &plan.steps[0];
    assert_eq!(step.payload.file_name, KB);
    assert_eq!(
        step.extra_payloads
            .iter()
            .map(|p| p.file_name.as_str())
            .collect::<Vec<_>>(),
        vec![COMPDB_CAB]
    );
    let wsus_client::install::handlers::HandlerSpec::Servicing(sp) = &step.spec else {
        panic!("not a servicing step");
    };
    let stack = sp.stack_payload.as_ref().expect("the stack is planned");
    assert_eq!(stack.file_name, STACK_CAB);
    assert_eq!(stack.patching.as_deref(), Some("ServicingStack"));
}

#[test]
fn a_declared_stack_without_a_digest_is_not_planned_as_a_stack() {
    let r = rig(&Files {
        stack_without_digest: true,
        ..files_with_stack()
    });
    let plan = r.plan();
    assert_eq!(plan.outcome, PlanOutcome::Install, "{:?}", plan.blockers);
    let wsus_client::install::handlers::HandlerSpec::Servicing(sp) = &plan.steps[0].spec else {
        panic!("not a servicing step");
    };
    assert!(sp.stack_payload.is_none());
}

#[test]
fn the_declared_stack_is_extracted_to_a_job_directory_and_handed_to_the_backend() {
    let r = rig(&files_with_stack());
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = run_os(&r, &os);
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    let reqs = os.requests.lock().unwrap();
    let dir = reqs[0].stack_dir.clone().expect("a stack directory");
    assert!(
        dir.starts_with(r._dir.path().join("jobs")),
        "job-owned: {}",
        dir.display()
    );
    assert_eq!(
        os.stack_files.lock().unwrap()[0],
        vec![
            "Deployment.cab".to_owned(),
            "UpdateAgent.dll".to_owned(),
            "wcp.dll".to_owned()
        ]
    );
    assert!(
        !dir.exists(),
        "the stack directory is removed after the run"
    );
    let mut declared = reqs[0].declared.clone();
    declared.sort();
    assert_eq!(declared, vec![COMPDB_CAB.to_owned(), KB.to_owned()]);
    let ev = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    let fetched = ev.fetched_stack.as_ref().expect("evidence of the stack");
    assert_eq!(fetched.file_name, STACK_CAB);
    assert!(fetched.digest.starts_with("sha256:"), "{}", fetched.digest);
    assert_eq!(fetched.files.len(), 3);
}

#[test]
fn a_configured_stack_directory_overrides_the_delivered_cabinet() {
    let r = rig(&files_with_stack());
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)).with_stack_override());
    let rec = run_os(&r, &os);
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    assert!(os.requests.lock().unwrap()[0].stack_dir.is_none());
    let ev = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    assert!(ev.fetched_stack.is_none());
}

#[test]
fn an_update_without_a_declared_stack_leaves_the_backend_on_its_own_stack() {
    let r = rig(&files());
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = run_os(&r, &os);
    assert_eq!(rec.status, JobStatus::RebootRequired, "{rec:#?}");
    assert!(os.requests.lock().unwrap()[0].stack_dir.is_none());
}

#[test]
fn a_tampered_stack_cabinet_is_refused_before_the_backend_runs() {
    let r = rig(&files_with_stack());
    let plan = r.plan();
    fs::write(r.store.root.join(STACK_CAB), b"not the stack cabinet").unwrap();
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone()),
        false,
    );
    assert_eq!(rec.status, JobStatus::Failed, "{rec:#?}");
    assert_eq!(rec.steps[0].state, StepState::Refused);
    assert!(os.requests.lock().unwrap().is_empty());
    assert!(
        rec.steps[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("differs from the plan"),
        "{:?}",
        rec.steps[0].refusal
    );
}

#[test]
fn a_stack_cabinet_missing_from_the_store_is_refused() {
    let r = rig(&files_with_stack());
    let plan = r.plan();
    fs::remove_file(r.store.root.join(STACK_CAB)).unwrap();
    let os = Arc::new(FakeOsBackend::reboot(IDENTITY, items(KB)));
    let rec = r.run(
        &plan,
        OsInstallerMode::UpdateAgent,
        Some(plain_backend()),
        Some(os.clone()),
        false,
    );
    assert_eq!(rec.status, JobStatus::Failed, "{rec:#?}");
    assert_eq!(rec.steps[0].state, StepState::Refused);
    assert!(os.requests.lock().unwrap().is_empty());
}

#[test]
fn dism_mode_does_not_touch_the_declared_stack() {
    let r = rig(&files_with_stack());
    let plan = r.plan();
    let backend = Arc::new(Linked {
        inner: FakeBackend::new(vec![]).script(AddScript::installed(IDENTITY)),
        state: r.state.clone(),
    });
    let rec = r.run(&plan, OsInstallerMode::Dism, Some(backend), None, false);
    assert_eq!(rec.status, JobStatus::Succeeded, "{rec:#?}");
    let os = rec.steps[0]
        .servicing
        .as_ref()
        .unwrap()
        .os_installer
        .as_ref()
        .unwrap();
    assert!(os.fetched_stack.is_none());
}
