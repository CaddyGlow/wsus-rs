//! Execution of an [`InstallPlan`]: gates, write-ahead evidence, steps and
//! the post-state check.
//!
//! Order of a run:
//!
//! 1. take the job lock; mark interrupted records left by dead runs;
//! 2. write the job record (`planned`);
//! 3. PREFLIGHT every step before running any: the payload must exist in the
//!    verified store, pass the path policy, match every digest of the plan and
//!    carry an Authenticode signature by an allowed signer. One refusal
//!    refuses the whole run (`refused`, nothing executed);
//! 4. for each step, immediately before starting it: open the payload (share
//!    mode denying writers on Windows), re-verify the digests over that handle,
//!    verify the signature over it, write the step as `started` (write-ahead),
//!    start the process through the [`Runner`], write the result;
//! 5. a failed or timed-out step stops the run (`failed`);
//! 6. the post-state check: the caller supplies the evaluation of the executed
//!    updates against fresh facts; `succeeded` requires every executed update
//!    to evaluate installed. Exit codes alone never mean success.
//!
//! No reporting event is sent ([`ReportHook`] is the extension point).
use super::{
    defender::{self, StubEnv},
    handler_log::{self, HandlerLog, ProcessWatcher},
    handlers::{ExitClass, HandlerSpec},
    job::{
        DefenderEvidence, Flags, JOB_SCHEMA, JOB_SCHEMA_V2, JOB_SCHEMA_V3, JobError, JobLock,
        JobRecord, JobStatus, JobStore, NoReport, PostCheck, ReportHook, StepRecord, StepState,
    },
    plan::{InstallPlan, InstallStep, PlanOutcome},
    runner::{RunRequest, Runner},
    safety::{self, PathPolicy},
    servicing::{
        LogRange, Oracles, OsInstallerBackend, OsInstallerMode, PackageSnapshot, ServicingBackend,
        ServicingClass, ServicingEvidence, StepOperation, StepServicing,
        os_installer::{OsInstallRequest, OsStepEvidence},
    },
    signature::{SignatureInfo, SignatureVerifier, TrustPolicy},
    store::PayloadStore,
};
use crate::{
    download::Hashers,
    session::{Clock, unix_to_xs},
};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Executor settings.
#[derive(Debug, Clone)]
pub struct ExecConfig {
    pub trust: TrustPolicy,
    pub path_policy: PathPolicy,
    pub timeout: Duration,
    pub output_limit: usize,
    /// Windows system directory (for `msiexec.exe`); needed only by the MSI
    /// handler.
    pub system_dir: Option<PathBuf>,
    /// Description of where the facts came from (evidence).
    pub facts_source: String,
    pub allow_unknown: bool,
    /// Longest wait for the evaluator to say installed after the last step
    /// (0 disables waiting: one evaluation).
    pub post_check_wait: Duration,
    pub poll_interval: Duration,
    /// Handler log and detached-process hook (Defender is the first user).
    pub handler_log: Option<HandlerLog>,
    /// Environment the Defender launcher packages depend on, probed by the
    /// caller (the live system on Windows). `None`: not checked (host tests).
    pub stub_env: Option<StubEnv>,
    /// The servicing stack behind `Cbs` steps. `None` (the default): such steps are refused.
    pub servicing: Option<Arc<dyn ServicingBackend>>,
    /// The update stack behind `OSInstaller` steps in `update_agent` mode.
    pub os_installer: Option<Arc<dyn OsInstallerBackend>>,
    /// How `OSInstaller` steps are executed (`[install] osinstaller_mode`).
    pub os_installer_mode: OsInstallerMode,
    /// Directory the servicing backend writes its logs into (default: a directory named after the
    /// job inside the job store).
    pub servicing_log_dir: Option<PathBuf>,
    /// `CBS.log`; only its growth (offsets) is recorded.
    pub cbs_log: Option<PathBuf>,
    /// Minimum free bytes on the system volume before a servicing run (at least three times the
    /// payload sizes is also required).
    pub servicing_min_free: u64,
    /// Uninstall runs only: accept a step whose update declares no `UninstallationBehavior` (the real
    /// `.NET` rollup leaf). Both the plan (`PlanOptions::allow_undeclared_uninstall`) and the executor
    /// must agree, so a plan file alone cannot enable it.
    pub allow_undeclared_uninstall: bool,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            trust: TrustPolicy::default(),
            path_policy: PathPolicy::default(),
            timeout: Duration::from_secs(30 * 60),
            output_limit: 64 * 1024,
            system_dir: None,
            facts_source: "unspecified".into(),
            allow_unknown: false,
            post_check_wait: Duration::from_secs(180),
            poll_interval: Duration::from_secs(2),
            handler_log: None,
            stub_env: None,
            servicing: None,
            os_installer: None,
            os_installer_mode: OsInstallerMode::default(),
            servicing_log_dir: None,
            cbs_log: None,
            servicing_min_free: 2 * 1024 * 1024 * 1024,
            allow_undeclared_uninstall: false,
        }
    }
}

/// Sleeping behind a trait so tests do not sleep.
pub trait Sleeper {
    fn sleep(&self, d: Duration);
}

/// Real sleeping.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Does not sleep (tests).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSleep;

impl Sleeper for NoSleep {
    fn sleep(&self, _d: Duration) {}
}

/// The executor and its collaborators.
pub struct Executor<'a> {
    pub store: &'a dyn PayloadStore,
    pub runner: &'a dyn Runner,
    pub verifier: &'a dyn SignatureVerifier,
    pub jobs: &'a JobStore,
    pub clock: &'a dyn Clock,
    pub hook: &'a dyn ReportHook,
    pub sleeper: &'a dyn Sleeper,
    pub watcher: &'a dyn ProcessWatcher,
    pub config: ExecConfig,
}

/// Why a run could not even start.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error(transparent)]
    Job(#[from] JobError),
}

/// How one servicing step ended.
enum StepVerdict {
    Executed,
    /// Installed, a restart completes it: later steps wait for the rerun after the reboot.
    RebootBarrier,
    /// The call hit the timeout and the process was left running.
    Unconfirmed,
    Failed,
}

/// The exact command of a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

/// Builds the command of `step` for the payload at `payload`. Arguments stay
/// separate strings; nothing is pasted into a shell line.
pub fn prepare_command(
    step: &InstallStep,
    payload: &Path,
    system_dir: Option<&Path>,
    store_root: &Path,
) -> Result<Prepared, String> {
    #[cfg(not(feature = "msi-handler"))]
    let _ = system_dir;
    match &step.spec {
        HandlerSpec::CommandLine(spec) => {
            if !spec.program.eq_ignore_ascii_case(&step.payload.file_name) {
                return Err("Program differs from the payload file name".into());
            }
            spec.validate().map_err(|e| e.to_string())?;
            Ok(Prepared {
                program: payload.to_path_buf(),
                args: spec.argument_tokens().map_err(|e| e.to_string())?,
                cwd: payload
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| store_root.to_path_buf()),
            })
        }
        HandlerSpec::Servicing(spec) => Err(spec.refusal()),
        #[cfg(feature = "msi-handler")]
        HandlerSpec::Msi(spec) => {
            let sys =
                system_dir.ok_or_else(|| "the Windows system directory is not known".to_owned())?;
            spec.properties().map_err(|e| e.to_string())?;
            let file = spec.installer_file(payload)?;
            Ok(Prepared {
                program: super::handlers::msi::MsiSpec::program(sys),
                args: spec.arguments(&file),
                cwd: sys.to_path_buf(),
            })
        }
    }
}

/// Command-line text for display only (quotes arguments with spaces); the
/// executor never builds a line like this.
pub fn display_command(p: &Prepared) -> String {
    let q = |s: &str| {
        if s.contains(' ') {
            format!("\"{s}\"")
        } else {
            s.to_owned()
        }
    };
    let mut out = q(&p.program.display().to_string());
    for a in &p.args {
        out.push(' ');
        out.push_str(&q(a));
    }
    out
}

/// True when the step's payloads include a servicing CompDB cabinet (`*.xml.cab`, the `.NET` updates).
fn has_compdb(step: &InstallStep) -> bool {
    step.extra_payloads
        .iter()
        .any(|p| p.file_name.to_ascii_lowercase().ends_with(".xml.cab"))
}

/// Puts `src` at `dst` without a second copy of the bytes when the volume allows it (a hard link: a
/// monthly set is 14 GB and the guest's disk would not hold two copies), else copies it. The stack reads
/// the sandbox files and is not expected to write them; the store re-hashes every file before each use.
fn link_or_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => std::fs::copy(src, dst).map(|_| ()),
    }
}

fn tail(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text = decode_output(bytes);
    let t: String = text.chars().take(4096).collect();
    Some(t)
}

/// Captured console bytes as text. Some programs write UTF-16LE (OBSERVED: `msiexec.exe` error
/// messages); that is recognised by a BOM or by NUL bytes in most odd positions and decoded as such,
/// anything else is read as UTF-8 with replacement.
fn decode_output(bytes: &[u8]) -> String {
    let bom = bytes.starts_with(&[0xFF, 0xFE]);
    let odd_nul = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    let pairs = bytes.len() / 2;
    if bytes.len() >= 4 && (bom || (pairs > 0 && odd_nul * 10 >= pairs * 7)) {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .skip(usize::from(bom))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

impl<'a> Executor<'a> {
    fn now(&self) -> String {
        unix_to_xs(self.clock.now_unix()).as_str().to_owned()
    }

    /// Opens and hashes one payload file against its plan reference (confined to the store, name, size
    /// and every declared digest). Returns the open handle (kept by the caller until the process
    /// started) and the absolute path.
    fn gate_ref(
        &self,
        payload: &super::plan::PayloadRef,
        path: &Path,
    ) -> Result<(std::fs::File, PathBuf), String> {
        let path = &safety::absolute(path)?;
        safety::confine(path, self.store.root(), &self.config.path_policy)?;
        let expected = payload.expected()?;
        if path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            != Some(payload.file_name.to_ascii_lowercase())
        {
            return Err("the located file name differs from the plan".into());
        }
        let mut file =
            safety::open_payload(path).map_err(|e| format!("cannot open the payload: {e}"))?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        if len != payload.size {
            return Err(format!(
                "payload size {len} differs from the plan ({})",
                payload.size
            ));
        }
        let mut hashers = Hashers::for_digests(expected.digests());
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                break;
            }
            hashers.update(&buf[..n]);
        }
        if let Some(alg) = hashers.mismatch(expected.digests()) {
            return Err(format!(
                "{alg:?} digest of the payload differs from the plan"
            ));
        }
        Ok((file, path.clone()))
    }

    /// Opens, hashes and signature-checks a payload. Returns the open handle
    /// (kept by the caller until the process started) and the signer.
    fn gate(
        &self,
        step: &InstallStep,
        path: &Path,
    ) -> Result<(std::fs::File, Option<SignatureInfo>, PathBuf), String> {
        let (file, path) = self.gate_ref(&step.payload, path)?;
        // Servicing payloads: trust is delegated to the servicing stack (DISM/CBS authenticate the
        // package); the metadata digests above were still verified.
        if matches!(step.spec, HandlerSpec::Servicing(_)) {
            return Ok((file, None, path));
        }
        let info = self
            .verifier
            .verify(&file, &path)
            .map_err(|e| e.to_string())?;
        self.config.trust.check(&info)?;
        Ok((file, Some(info), path))
    }

    /// The verified paths of every payload of `step` (primary first), each gated again.
    fn gate_all(
        &self,
        step: &InstallStep,
    ) -> Result<Vec<(std::fs::File, PathBuf, super::plan::PayloadRef)>, String> {
        let mut out = Vec::new();
        for p in std::iter::once(&step.payload).chain(step.extra_payloads.iter()) {
            let path = match self.store.locate(p) {
                Ok(Some(path)) => path,
                Ok(None) => {
                    return Err(format!(
                        "the verified payload {} is not in the store (download it first)",
                        p.file_name
                    ));
                }
                Err(e) => return Err(e),
            };
            let (f, abs) = self.gate_ref(p, &path)?;
            out.push((f, abs, p.clone()));
        }
        Ok(out)
    }

    /// The package identities an `OSInstaller` step must leave behind, read from the servicing CompDB
    /// cabinet among its verified payloads (`.NET` updates).
    ///
    /// A monthly cumulative update declares no servicing CompDB cabinet: in `update_agent` mode its
    /// identities are the `InstallPackage` keyforms of the ActionList the stack generates (recorded by the
    /// step), so the answer here is empty and not an error.
    fn os_identities(&self, step: &InstallStep) -> Result<Vec<String>, String> {
        if !has_compdb(step) && self.config.os_installer_mode == OsInstallerMode::UpdateAgent {
            return Ok(Vec::new());
        }
        let compdb = step
            .extra_payloads
            .iter()
            .find(|p| p.file_name.to_ascii_lowercase().ends_with(".xml.cab"))
            .ok_or_else(|| "the update declares no servicing CompDB cabinet".to_owned())?;
        let path = self
            .store
            .locate(compdb)?
            .ok_or_else(|| "the CompDB cabinet is not in the store".to_owned())?;
        let (_f, abs) = self.gate_ref(compdb, &path)?;
        let mut cab = cabinet::Cabinet::open(&abs)
            .map_err(|e| format!("cannot read the CompDB cabinet: {e}"))?;
        let member = cab
            .entries()
            .iter()
            .map(|e| e.name.clone())
            .find(|n| n.to_ascii_lowercase().ends_with(".xml"))
            .ok_or_else(|| "the CompDB cabinet holds no .xml file".to_owned())?;
        let bytes = cab
            .read_file_bytes(&member, 4 * 1024 * 1024)
            .map_err(|e| format!("cannot read {member}: {e}"))?;
        let text = String::from_utf8_lossy(&bytes);
        let ids = super::servicing::os_installer::identities_from_compdb(&text);
        if ids.is_empty() {
            return Err("the CompDB names no installable package identity".to_owned());
        }
        Ok(ids)
    }

    /// Why a servicing step cannot run at all (before any gate touches the payload).
    fn servicing_refusal(
        &self,
        spec: &super::handlers::ServicingSpec,
        step: &InstallStep,
    ) -> Option<String> {
        use super::handlers::ServicingKind;
        if self.config.allow_unknown {
            return Some(
                "--allow-unknown is not accepted for servicing steps: a wrongly skipped or wrongly assumed servicing update can damage the installation"
                    .into(),
            );
        }
        if spec.kind == ServicingKind::OsInstaller {
            return self.os_installer_refusal(spec, step);
        }
        let Some(backend) = self.config.servicing.as_ref() else {
            return Some(spec.refusal());
        };
        let ext = Path::new(&step.payload.file_name)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !backend.payload_extensions().contains(&ext.as_str()) {
            return Some(format!(
                "the `{}` backend cannot add a `.{ext}` payload (supports: {})",
                backend.name(),
                backend.payload_extensions().join(", ")
            ));
        }
        if step.servicing_identity.is_none() {
            return Some(
                "no package identity could be derived from the update's metadata, so the package listing cannot be used as the second post-check oracle"
                    .into(),
            );
        }
        None
    }

    /// Why an `OSInstaller` step cannot run. A step needs a complete declared file set (every file named,
    /// sized and digested, planned as the primary payload plus extra payloads): the `.NET` updates (two
    /// cabinets) and the monthly cumulative updates (19 files), whose download list only the stack itself
    /// can name. A set that is not complete is refused. The monthly set is `update_agent` only: `dism`
    /// mode adds one canonical cabinet and needs the servicing CompDB cabinet for its package identity.
    fn os_installer_refusal(
        &self,
        spec: &super::handlers::ServicingSpec,
        step: &InstallStep,
    ) -> Option<String> {
        if step.extra_payloads.is_empty() {
            return Some(format!(
                "OSInstaller update `{}` does not declare a complete acquirable file set (a complete small cabinet set or a monthly set of which every declared file has a name, a size and a SHA-1 or SHA-256 digest): the stack picks its files from its own download list, so a partial set is not handed over; {}",
                spec.product_name.as_deref().unwrap_or("?"),
                spec.engine_needs()
            ));
        }
        if self.config.os_installer_mode == OsInstallerMode::Dism && !has_compdb(step) {
            return Some(
                "osinstaller_mode dism cannot install this update: it declares no servicing CompDB cabinet (a monthly cumulative update needs osinstaller_mode update_agent)"
                    .into(),
            );
        }
        if self.config.servicing.is_none() {
            return Some(
                "an OSInstaller step needs the servicing backend as the package-state oracle (configure install.servicing_backend with the cbs-handler feature)"
                    .into(),
            );
        }
        match self.config.os_installer_mode {
            OsInstallerMode::UpdateAgent => {
                if self.config.os_installer.is_none() {
                    return Some(
                        "osinstaller_mode update_agent needs the UpdateAgent backend (osinstaller-handler feature, Windows)"
                            .into(),
                    );
                }
            }
            OsInstallerMode::Dism => {
                let backend = self.config.servicing.as_ref().expect("checked above");
                let ext = Path::new(&step.payload.file_name)
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                if !backend.payload_extensions().contains(&ext.as_str()) {
                    return Some(format!(
                        "osinstaller_mode dism: the `{}` backend cannot add a `.{ext}` payload",
                        backend.name()
                    ));
                }
            }
        }
        None
    }

    /// Pending indicators, free disk space and the package listing before the first servicing step.
    fn servicing_prestate(
        &self,
        plan: &InstallPlan,
        backend: &dyn ServicingBackend,
    ) -> Result<(ServicingEvidence, PackageSnapshot), String> {
        let pending = backend
            .pending_indicators()
            .map_err(|e| format!("cannot read the pending-servicing indicators: {e}"))?;
        if pending.reboot_pending() {
            return Err(format!(
                "a restart or servicing operation is already pending ({}): restart the machine first",
                pending.set.join(", ")
            ));
        }
        // Free space the run needs: three times the payload for a single package (the store copy, the
        // copy the backend works on and the installed result). An `OSInstaller` step in `update_agent`
        // mode hands the stack hard links of the store files (no second copy; a monthly set is 14 GB), so
        // its payloads count once; the stack's own working space is not known and is recorded as the
        // free space before and after.
        let payload_bytes: u64 = plan
            .steps
            .iter()
            .filter_map(|s| match &s.spec {
                HandlerSpec::Servicing(sp) => {
                    let stack = sp.stack_payload.as_ref().map_or(0, |p| p.size);
                    let bytes = s.payload.size
                        + stack
                        + s.extra_payloads.iter().map(|p| p.size).sum::<u64>();
                    let linked = sp.kind == super::handlers::ServicingKind::OsInstaller
                        && self.config.os_installer_mode == OsInstallerMode::UpdateAgent;
                    Some(bytes.saturating_mul(if linked { 1 } else { 3 }))
                }
                _ => None,
            })
            .sum();
        let need = self.config.servicing_min_free.max(payload_bytes);
        let free = backend
            .free_disk_bytes()
            .map_err(|e| format!("cannot read the free disk space: {e}"))?;
        if let Some(f) = free.filter(|f| *f < need) {
            return Err(format!(
                "not enough free disk space on the system volume: {f} bytes free, {need} needed"
            ));
        }
        let snapshot = backend
            .list_packages()
            .map_err(|e| format!("cannot list the installed packages: {e}"))?;
        Ok((
            ServicingEvidence {
                backend: backend.name().into(),
                trust: "servicing_stack".into(),
                pre_count: snapshot.packages.len(),
                pre_sha256: snapshot.digest(),
                pending_before: pending,
                free_disk_before: free,
                ..ServicingEvidence::default()
            },
            snapshot,
        ))
    }

    /// Runs one servicing step through the backend, with the write-ahead state around the call.
    fn run_servicing_step(
        &self,
        rec: &mut JobRecord,
        i: usize,
        step: &InstallStep,
        path: &Path,
        backend: &dyn ServicingBackend,
        log_dir: Option<&Path>,
    ) -> StepVerdict {
        let mut sv = StepServicing {
            backend: backend.name().into(),
            native_code: None,
            class: None,
            description: String::new(),
            applicable: None,
            identity_expected: step.servicing_identity.clone(),
            log_paths: Vec::new(),
            os_installer: None,
            operation: StepOperation::Install,
            refusal_class: None,
        };
        rec.steps[i].program = Some(format!("servicing:{}", backend.name()));
        rec.steps[i].arguments = vec![step.payload.file_name.clone()];
        // Applicability is asked just before the call: an earlier step may have changed it.
        match backend.payload_applicability(path) {
            Ok(Some(false)) => {
                sv.applicable = Some(false);
                rec.steps[i].state = StepState::Refused;
                rec.steps[i].refusal = Some(
                    "the servicing stack says the package is not applicable to this system although the evaluator said installable: the oracles conflict, nothing was installed"
                        .into(),
                );
                rec.steps[i].servicing = Some(sv);
                return StepVerdict::Failed;
            }
            Ok(a) => sv.applicable = a,
            Err(e) => {
                rec.steps[i].state = StepState::Refused;
                rec.steps[i].refusal =
                    Some(format!("cannot query the package's applicability: {e}"));
                rec.steps[i].servicing = Some(sv);
                return StepVerdict::Failed;
            }
        }
        rec.steps[i].state = StepState::Started;
        rec.steps[i].started_at = Some(self.now());
        rec.steps[i].servicing = Some(sv.clone());
        if self.save(rec).is_err() {
            // The write-ahead record could not be written: do not start the install.
            rec.steps[i].state = StepState::Refused;
            rec.steps[i].refusal = Some("the write-ahead job record could not be written".into());
            return StepVerdict::Failed;
        }
        let dir = log_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.jobs.dir().to_path_buf());
        let call = backend.add_package(path, &dir, self.config.timeout);
        rec.steps[i].finished_at = Some(self.now());
        rec.steps[i].state = StepState::Finished;
        let verdict = match call {
            Err(e) => {
                sv.description = e.to_string();
                rec.steps[i].refusal = Some(e.to_string());
                rec.steps[i].exit_class = Some(ExitClass::Failed);
                StepVerdict::Failed
            }
            Ok(r) => {
                sv.native_code = r.native_code;
                sv.class = Some(r.class);
                sv.description = r.description.clone();
                sv.log_paths = r.log_paths.clone();
                rec.steps[i].exit_code = r.native_code.map(|c| c as i32);
                rec.steps[i].timed_out = r.timed_out;
                rec.steps[i].stdout_tail = r.stdout_tail;
                rec.steps[i].stderr_tail = r.stderr_tail;
                if r.timed_out {
                    StepVerdict::Unconfirmed
                } else {
                    match r.class {
                        ServicingClass::Success => {
                            rec.steps[i].exit_class = Some(ExitClass::Success);
                            StepVerdict::Executed
                        }
                        ServicingClass::Reboot => {
                            rec.steps[i].exit_class = Some(ExitClass::Reboot);
                            StepVerdict::RebootBarrier
                        }
                        ServicingClass::NotApplicable
                        | ServicingClass::Busy
                        | ServicingClass::Permanent
                        | ServicingClass::Failed => {
                            rec.steps[i].exit_class = Some(ExitClass::Failed);
                            rec.steps[i].refusal = Some(r.description);
                            StepVerdict::Failed
                        }
                    }
                }
            }
        };
        rec.steps[i].servicing = Some(sv);
        verdict
    }

    /// SessionData handed to the update stack: none, as the native agent does for a `.NET` update.
    const OS_SESSION_JSON: &'static str = "";

    /// Runs one `OSInstaller` step through the `UpdateAgent` backend, with the write-ahead state around
    /// the call. Every payload of the update is copied into a private sandbox (the stack reads files by
    /// their declared names); the copies are removed afterwards, the generated ActionList is kept.
    fn run_update_agent_step(
        &self,
        rec: &mut JobRecord,
        i: usize,
        step: &InstallStep,
        ids: Vec<String>,
        job_id: &str,
        log_dir: Option<&Path>,
    ) -> StepVerdict {
        let backend = self
            .config
            .os_installer
            .clone()
            .expect("the preflight refuses a step without the UpdateAgent backend");
        let mut sv = StepServicing {
            backend: backend.name().into(),
            native_code: None,
            class: None,
            description: String::new(),
            applicable: None,
            identity_expected: ids.first().cloned(),
            log_paths: Vec::new(),
            os_installer: None,
            operation: StepOperation::Install,
            refusal_class: None,
        };
        rec.steps[i].program = Some(format!("os_installer:{}", backend.name()));
        rec.steps[i].arguments = vec![step.payload.file_name.clone()];
        let fail = |rec: &mut JobRecord, mut sv: StepServicing, why: String| {
            rec.steps[i].state = StepState::Refused;
            rec.steps[i].refusal = Some(why.clone());
            sv.description = why;
            rec.steps[i].servicing = Some(sv);
            StepVerdict::Failed
        };
        let gated = match self.gate_all(step) {
            Ok(g) => g,
            Err(why) => return fail(rec, sv, why),
        };
        let work = self.jobs.dir().join(format!("{job_id}-os"));
        let sandbox = work.join("sandbox");
        if let Err(e) = std::fs::create_dir_all(&sandbox) {
            return fail(rec, sv, format!("cannot create the sandbox: {e}"));
        }
        let container_paths: Vec<PathBuf> = gated
            .iter()
            .filter(|(_, _, p)| p.file_name.to_ascii_lowercase().ends_with(".msu"))
            .map(|(_, abs, _)| abs.clone())
            .collect();
        let declared: Vec<String> = gated
            .iter()
            .map(|(_, _, p)| super::servicing::os_installer::sandbox_file_name(&p.file_name))
            .collect();
        for ((_, abs, p), name) in gated.iter().zip(&declared) {
            if let Err(e) = link_or_copy(abs, &sandbox.join(name)) {
                let _ = std::fs::remove_dir_all(&sandbox);
                return fail(
                    rec,
                    sv,
                    format!("cannot stage {} into the sandbox: {e}", p.file_name),
                );
            }
        }
        drop(gated);
        // The update's own servicing stack, unless the backend has an explicit stack directory.
        let mut stack_dir = None;
        let mut fetched_stack = None;
        if let HandlerSpec::Servicing(sp) = &step.spec
            && let Some(stack) = sp.stack_payload.as_ref()
            && !backend.stack_overridden()
        {
            match self.stage_stack(stack, &work.join("stack")) {
                Ok((dir, ev)) => {
                    stack_dir = Some(dir);
                    fetched_stack = Some(ev);
                }
                Err(why) => {
                    let _ = std::fs::remove_dir_all(&sandbox);
                    let _ = std::fs::remove_dir_all(work.join("stack"));
                    return fail(rec, sv, why);
                }
            }
        }
        rec.steps[i].state = StepState::Started;
        rec.steps[i].started_at = Some(self.now());
        rec.steps[i].servicing = Some(sv.clone());
        if self.save(rec).is_err() {
            let _ = std::fs::remove_dir_all(&sandbox);
            let _ = std::fs::remove_dir_all(work.join("stack"));
            rec.steps[i].state = StepState::Refused;
            rec.steps[i].refusal = Some("the write-ahead job record could not be written".into());
            return StepVerdict::Failed;
        }
        let logs = log_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| work.join("logs"));
        let _ = std::fs::create_dir_all(&logs);
        let request = OsInstallRequest {
            sandbox: sandbox.clone(),
            declared: declared.clone(),
            session_json: Self::OS_SESSION_JSON.to_owned(),
            stack_dir: stack_dir.clone(),
            log_dir: logs,
            timeout: self.config.timeout,
            containers: container_paths,
        };
        let call = backend.run(&request);
        rec.steps[i].finished_at = Some(self.now());
        rec.steps[i].state = StepState::Finished;
        let mut verdict = StepVerdict::Failed;
        match call {
            Err(e) => {
                sv.description = e.to_string();
                rec.steps[i].refusal = Some(e.to_string());
                rec.steps[i].exit_class = Some(ExitClass::Failed);
            }
            Ok(out) => {
                let mut action_sha = None;
                let mut action_path = None;
                if let Some(src) = out.action_list.as_ref()
                    && let Ok(bytes) = std::fs::read(src)
                {
                    action_sha = Some(crate::download::hex_encode(&Sha256::digest(&bytes)));
                    let keep = work.join("ActionList.xml");
                    if std::fs::write(&keep, &bytes).is_ok() {
                        action_path = Some(keep.display().to_string());
                    }
                }
                // Files taken out of a declared `.msu` count as held by the sandbox.
                let mut held = declared.clone();
                held.extend(out.provisioned.iter().map(|p| p.name.clone()));
                let missing =
                    super::servicing::os_installer::missing_from_sandbox(&out.download_list, &held);
                let mut expected = ids;
                for id in &out.expected_identities {
                    if !expected.contains(id) {
                        expected.push(id.clone());
                    }
                }
                sv.os_installer = Some(OsStepEvidence {
                    mode: OsInstallerMode::UpdateAgent.name().into(),
                    declared,
                    download_list: out.download_list.clone(),
                    missing: missing.clone(),
                    expected_identities: expected,
                    phases: out.phases.clone(),
                    action_list_sha256: action_sha,
                    action_list_path: action_path,
                    fetched_stack,
                    provisioned: out.provisioned.clone(),
                    stack_stdout: out.result.stdout_tail.clone(),
                });
                let r = out.result;
                sv.native_code = r.native_code;
                sv.class = Some(r.class);
                sv.description = r.description.clone();
                sv.log_paths = r.log_paths.clone();
                rec.steps[i].exit_code = r.native_code.map(|c| c as i32);
                rec.steps[i].timed_out = r.timed_out;
                rec.steps[i].stdout_tail = r.stdout_tail;
                rec.steps[i].stderr_tail = r.stderr_tail;
                verdict = if !missing.is_empty() {
                    let why = format!(
                        "the update stack needs files that neither the declared set nor a declared .msu container holds: {}",
                        missing.join(", ")
                    );
                    rec.steps[i].exit_class = Some(ExitClass::Failed);
                    rec.steps[i].refusal = Some(why.clone());
                    sv.description = why;
                    StepVerdict::Failed
                } else if r.timed_out {
                    StepVerdict::Unconfirmed
                } else {
                    match r.class {
                        ServicingClass::Success => {
                            rec.steps[i].exit_class = Some(ExitClass::Success);
                            StepVerdict::Executed
                        }
                        ServicingClass::Reboot => {
                            rec.steps[i].exit_class = Some(ExitClass::Reboot);
                            StepVerdict::RebootBarrier
                        }
                        ServicingClass::NotApplicable
                        | ServicingClass::Busy
                        | ServicingClass::Permanent
                        | ServicingClass::Failed => {
                            rec.steps[i].exit_class = Some(ExitClass::Failed);
                            rec.steps[i].refusal = Some(r.description);
                            StepVerdict::Failed
                        }
                    }
                };
            }
        }
        let _ = std::fs::remove_dir_all(&sandbox);
        // A timed-out stack may still have its DLLs loaded and is not stopped: keep its directory.
        if stack_dir.is_some() && !matches!(verdict, StepVerdict::Unconfirmed) {
            let _ = std::fs::remove_dir_all(work.join("stack"));
        }
        rec.steps[i].servicing = Some(sv);
        verdict
    }

    /// Re-hashes the update's declared `DesktopDeployment.cab` from the store (the acquisition path
    /// already verified it) and extracts every member into `dir`, a job-owned directory. Members must be
    /// plain file names. The signature of each DLL is verified by the backend before the first load.
    fn stage_stack(
        &self,
        stack: &super::plan::PayloadRef,
        dir: &Path,
    ) -> Result<(PathBuf, super::servicing::os_installer::FetchedStack), String> {
        const MEMBER_LIMIT: u64 = 256 * 1024 * 1024;
        const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
        let path = self
            .store
            .locate(stack)?
            .ok_or_else(|| {
                format!(
                    "the update declares {} as its servicing stack but the verified file is not in the store (download it first)",
                    stack.file_name
                )
            })?;
        let (_held, abs) = self.gate_ref(stack, &path)?;
        let mut cab = cabinet::Cabinet::open(&abs)
            .map_err(|e| format!("cannot read the servicing stack {}: {e}", stack.file_name))?;
        let names: Vec<String> = cab.entries().iter().map(|e| e.name.clone()).collect();
        let total: u64 = cab.entries().iter().map(|e| u64::from(e.size)).sum();
        if total > TOTAL_LIMIT {
            return Err(format!(
                "the servicing stack {} would extract to {total} bytes (limit {TOTAL_LIMIT})",
                stack.file_name
            ));
        }
        if names.is_empty() {
            return Err(format!("the servicing stack {} is empty", stack.file_name));
        }
        for n in &names {
            if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\\', ':', '\0']) {
                return Err(format!(
                    "the servicing stack {} has an unsafe member name `{n}`",
                    stack.file_name
                ));
            }
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create the stack directory: {e}"))?;
        for n in &names {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(n))
                .map_err(|e| format!("cannot create {n} in the stack directory: {e}"))?;
            let mut r = cab
                .read_file(n)
                .map_err(|e| format!("cannot read {n} from the servicing stack: {e}"))?
                .take(MEMBER_LIMIT);
            std::io::copy(&mut r, &mut out)
                .map_err(|e| format!("cannot extract {n} from the servicing stack: {e}"))?;
        }
        let digest = stack
            .digests
            .iter()
            .find(|d| d.algorithm == "sha256")
            .or_else(|| stack.digests.first())
            .map(|d| format!("{}:{}", d.algorithm, d.hex))
            .unwrap_or_default();
        Ok((
            dir.to_path_buf(),
            super::servicing::os_installer::FetchedStack {
                file_name: stack.file_name.clone(),
                digest,
                files: names,
            },
        ))
    }

    fn record(&self, plan: &InstallPlan, job_id: &str, recovered: Vec<String>) -> JobRecord {
        let now = self.now();
        JobRecord {
            schema: JOB_SCHEMA.into(),
            job_id: job_id.into(),
            status: JobStatus::Planned,
            started_at: now.clone(),
            updated_at: now,
            finished_at: None,
            facts_source: self.config.facts_source.clone(),
            facts_hash: plan.facts.hash.clone(),
            plan_hash: plan.hash(),
            trusted_signers: self.config.trust.allowed_signers.clone(),
            flags: Flags {
                allow_unknown: self.config.allow_unknown,
                allow_writable_store: self.config.path_policy.allow_writable_store,
            },
            plan: plan.clone(),
            steps: plan
                .steps
                .iter()
                .map(|s| StepRecord {
                    index: s.index,
                    update: s.update.clone(),
                    handler: s.spec.kind().into(),
                    payload: s.payload.clone(),
                    state: StepState::Pending,
                    program: None,
                    arguments: vec![],
                    digest_verified: None,
                    signature: None,
                    exit_code: None,
                    exit_class: None,
                    timed_out: false,
                    refusal: None,
                    started_at: None,
                    finished_at: None,
                    stdout_tail: None,
                    stderr_tail: None,
                    launcher: s.launcher.clone(),
                    stub_result: None,
                    servicing: None,
                })
                .collect(),
            post_check: PostCheck::default(),
            handler_log_excerpt: None,
            defender: None,
            servicing: None,
            recovered,
            notes: vec![
                "No reporting event was sent: native event id semantics are not established."
                    .into(),
            ],
            reporting_sent: false,
        }
    }

    fn save(&self, rec: &mut JobRecord) -> Result<(), ExecError> {
        rec.updated_at = self.now();
        self.jobs.write(rec)?;
        Ok(())
    }

    /// Runs `plan`. `post_check` evaluates, against fresh facts, which of the
    /// given update identities now evaluate installed. It is called once after
    /// the steps ran (also after a failure, to record the state).
    pub fn run(
        &self,
        plan: &InstallPlan,
        post_check: &mut dyn FnMut(&[String]) -> PostCheck,
    ) -> Result<JobRecord, ExecError> {
        let _lock: JobLock = self.jobs.lock()?;
        let store_root =
            safety::absolute(self.store.root()).unwrap_or_else(|_| self.store.root().to_path_buf());
        let recovered = self.jobs.recover_interrupted(&self.now())?;
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let job_id = format!(
            "{}-{}-{}",
            self.clock.now_unix(),
            &plan.hash()[..12],
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let mut rec = self.record(plan, &job_id, recovered);
        self.save(&mut rec)?;
        if plan.outcome == PlanOutcome::Uninstall {
            return self.run_uninstall(plan, post_check, rec, &job_id);
        }
        if plan.outcome != PlanOutcome::Install {
            rec.status = match plan.outcome {
                PlanOutcome::Refused => JobStatus::Refused,
                _ => JobStatus::NoAction,
            };
            rec.finished_at = Some(self.now());
            self.save(&mut rec)?;
            self.hook.job_finished(&rec);
            return Ok(rec);
        }
        // Preflight: nothing runs unless every step passes every gate.
        let mut refused = false;
        // Package identities an OSInstaller step must leave behind (read from its CompDB cabinet).
        let mut os_ids: std::collections::HashMap<usize, Vec<String>> =
            std::collections::HashMap::new();
        for (i, step) in plan.steps.iter().enumerate() {
            if let HandlerSpec::Servicing(spec) = &step.spec {
                // Servicing steps run only with a configured backend, the `Cbs` handler, no
                // --allow-unknown and a derivable package identity; otherwise refuse before touching
                // anything. Trust is delegated: only the metadata digests are checked here.
                let is_os = spec.kind == super::handlers::ServicingKind::OsInstaller;
                let refusal = self.servicing_refusal(spec, step).or_else(|| {
                    if is_os {
                        // Every declared payload of the update is gated, then the CompDB names the
                        // packages the post-check expects.
                        if let Err(e) = self.gate_all(step) {
                            return Some(e);
                        }
                        return match self.os_identities(step) {
                            Ok(ids) => {
                                os_ids.insert(i, ids);
                                None
                            }
                            Err(e) => Some(e),
                        };
                    }
                    let outcome = match self.store.locate(&step.payload) {
                        Ok(Some(path)) => self.gate(step, &path).map(|_| ()),
                        Ok(None) => Err(
                            "the verified payload is not in the store (download it first)"
                                .to_owned(),
                        ),
                        Err(e) => Err(e),
                    };
                    outcome.err()
                });
                match refusal {
                    Some(why) => {
                        rec.steps[i].state = StepState::Refused;
                        rec.steps[i].refusal = Some(why);
                        refused = true;
                    }
                    None => rec.steps[i].digest_verified = Some(true),
                }
                continue;
            }
            let outcome = match self.store.locate(&step.payload) {
                Ok(Some(path)) => self.gate(step, &path).map(|(_, info, _)| info),
                Ok(None) => {
                    Err("the verified payload is not in the store (download it first)".to_owned())
                }
                Err(e) => Err(e),
            };
            match outcome {
                Ok(info) => {
                    rec.steps[i].digest_verified = Some(true);
                    rec.steps[i].signature = info;
                }
                Err(why) => {
                    rec.steps[i].state = StepState::Refused;
                    rec.steps[i].refusal = Some(why);
                    refused = true;
                }
            }
        }
        // Defender launcher packages: the run must end with the terminal
        // package (else the stub would wait and update nothing) and the
        // machine must satisfy the launcher's preconditions.
        let launcher_idx: Vec<usize> = plan
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.launcher.is_some())
            .map(|(i, _)| i)
            .collect();
        if !launcher_idx.is_empty() {
            let last = *launcher_idx.last().expect("non-empty");
            let terminal_last = plan.steps[last]
                .launcher
                .as_ref()
                .is_some_and(defender::LauncherPackage::is_terminal)
                && launcher_idx
                    .iter()
                    .filter(|i| {
                        plan.steps[**i]
                            .launcher
                            .as_ref()
                            .is_some_and(|l| l.is_terminal())
                    })
                    .count()
                    == 1;
            if !terminal_last {
                rec.steps[last].state = StepState::Refused;
                rec.steps[last].refusal = Some(
                    "the last Defender package of the run is not the single terminal package (Delta or \
                     Delta patch): the stub would wait for it, time out (0x800705b4) and update nothing"
                        .into(),
                );
                refused = true;
            }
            if let Some(env) = &self.config.stub_env {
                let machines: Vec<Option<defender::Machine>> = plan
                    .steps
                    .iter()
                    .map(|st| match self.store.locate(&st.payload) {
                        Ok(Some(path)) => std::fs::File::open(&path)
                            .ok()
                            .and_then(|mut f| defender::pe_machine(&mut f)),
                        _ => None,
                    })
                    .collect();
                for (i, why) in defender::check_environment(&plan.steps, &machines, env) {
                    if rec.steps[i].state != StepState::Refused {
                        rec.steps[i].state = StepState::Refused;
                        rec.steps[i].refusal = Some(why);
                    }
                    refused = true;
                }
            }
            rec.notes.push(
                "Defender launcher packages: only the terminal package's exit code is the stub's final HRESULT; the others exit 0 after about a second whatever the stub later does."
                    .into(),
            );
            rec.defender = Some(DefenderEvidence {
                parent_pid: std::process::id(),
                terminal_step: None,
                environment: self.config.stub_env.clone(),
                nothing_applied: false,
            });
        }
        // Servicing steps: pre-state of the servicing stack (pending reboot, disk space, package
        // listing). Anything unreadable or already pending refuses the run.
        let servicing_steps: Vec<usize> = plan
            .steps
            .iter()
            .enumerate()
            .filter(|(_, st)| matches!(st.spec, HandlerSpec::Servicing(_)))
            .map(|(i, _)| i)
            .collect();
        let mut pre_snapshot: Option<PackageSnapshot> = None;
        let mut sv_log_dir: Option<PathBuf> = None;
        let mut cbs_mark: Option<u64> = None;
        if let (false, false, Some(backend)) = (
            servicing_steps.is_empty(),
            refused,
            self.config.servicing.clone(),
        ) {
            {
                match self.servicing_prestate(plan, backend.as_ref()) {
                    Ok((evidence, snapshot)) => {
                        rec.servicing = Some(evidence);
                        rec.schema = JOB_SCHEMA_V2.into();
                        pre_snapshot = Some(snapshot);
                        let dir =
                            self.config.servicing_log_dir.clone().unwrap_or_else(|| {
                                self.jobs.dir().join(format!("{job_id}-servicing"))
                            });
                        let _ = std::fs::create_dir_all(&dir);
                        sv_log_dir = Some(dir);
                        cbs_mark = self.config.cbs_log.as_deref().map(handler_log::mark);
                        rec.notes.push(
                            "Servicing steps: trust is delegated to the servicing stack (DISM/CBS authenticate the package); the metadata digests were verified by this client. Reporting is not sent for servicing updates."
                                .into(),
                        );
                    }
                    Err(why) => {
                        let first = servicing_steps[0];
                        rec.steps[first].state = StepState::Refused;
                        rec.steps[first].refusal = Some(why);
                        refused = true;
                    }
                }
            }
        }
        if refused {
            rec.status = JobStatus::Refused;
            rec.finished_at = Some(self.now());
            self.save(&mut rec)?;
            self.hook.job_finished(&rec);
            return Ok(rec);
        }
        rec.status = JobStatus::Running;
        self.save(&mut rec)?;
        let log_mark = self
            .config
            .handler_log
            .as_ref()
            .filter(|h| {
                plan.steps
                    .iter()
                    .any(|s| h.applies_to(&s.payload.file_name))
            })
            .map(|h| (h.clone(), handler_log::mark(&h.log_path)));
        let mut first_started: Option<i64> = None;
        let mut reboot = false;
        let mut failed = false;
        let mut unconfirmed_timeout = false;
        let mut executed: Vec<String> = Vec::new();
        for (i, step) in plan.steps.iter().enumerate() {
            // Immediately before execution: open, re-verify, hold the handle.
            let gated = match self.store.locate(&step.payload) {
                Ok(Some(path)) => self.gate(step, &path),
                Ok(None) => Err("the verified payload disappeared from the store".to_owned()),
                Err(e) => Err(e),
            };
            let (held, info, path) = match gated {
                Ok(v) => v,
                Err(why) => {
                    rec.steps[i].state = StepState::Refused;
                    rec.steps[i].refusal = Some(why);
                    failed = true;
                    break;
                }
            };
            rec.steps[i].signature = info;
            rec.steps[i].digest_verified = Some(true);
            if let (HandlerSpec::Servicing(spec), Some(backend)) =
                (&step.spec, self.config.servicing.as_ref())
            {
                let verdict = if spec.kind == super::handlers::ServicingKind::OsInstaller {
                    let ids = os_ids.get(&i).cloned().unwrap_or_default();
                    match self.config.os_installer_mode {
                        OsInstallerMode::Dism => {
                            // The canonical `.cab` through DISM or wusa: the CompDB names the package
                            // the second oracle expects.
                            let mut os_step = step.clone();
                            os_step.servicing_identity = ids.first().cloned();
                            let v = self.run_servicing_step(
                                &mut rec,
                                i,
                                &os_step,
                                &path,
                                backend.as_ref(),
                                sv_log_dir.as_deref(),
                            );
                            if let Some(sv) = rec.steps[i].servicing.as_mut() {
                                sv.os_installer = Some(OsStepEvidence {
                                    mode: OsInstallerMode::Dism.name().into(),
                                    declared: std::iter::once(&step.payload)
                                        .chain(step.extra_payloads.iter())
                                        .map(|p| p.file_name.clone())
                                        .collect(),
                                    download_list: Vec::new(),
                                    missing: Vec::new(),
                                    expected_identities: ids,
                                    phases: Vec::new(),
                                    action_list_sha256: None,
                                    action_list_path: None,
                                    fetched_stack: None,
                                    provisioned: Vec::new(),
                                    stack_stdout: None,
                                });
                            }
                            v
                        }
                        OsInstallerMode::UpdateAgent => self.run_update_agent_step(
                            &mut rec,
                            i,
                            step,
                            ids,
                            &job_id,
                            sv_log_dir.as_deref(),
                        ),
                    }
                } else {
                    self.run_servicing_step(
                        &mut rec,
                        i,
                        step,
                        &path,
                        backend.as_ref(),
                        sv_log_dir.as_deref(),
                    )
                };
                drop(held);
                self.save(&mut rec)?;
                match verdict {
                    StepVerdict::Executed => executed.push(step.update.clone()),
                    StepVerdict::RebootBarrier => {
                        executed.push(step.update.clone());
                        reboot = true;
                        if i + 1 < plan.steps.len() {
                            if let Some(ev) = rec.servicing.as_mut() {
                                ev.remaining_steps = (i + 1..plan.steps.len()).collect();
                            }
                            self.save(&mut rec)?;
                            break;
                        }
                    }
                    StepVerdict::Unconfirmed => {
                        unconfirmed_timeout = true;
                        break;
                    }
                    StepVerdict::Failed => {
                        failed = true;
                        break;
                    }
                }
                continue;
            }
            let prepared = match prepare_command(
                step,
                &path,
                self.config.system_dir.as_deref(),
                &store_root,
            ) {
                Ok(p) => p,
                Err(why) => {
                    rec.steps[i].state = StepState::Refused;
                    rec.steps[i].refusal = Some(why);
                    failed = true;
                    break;
                }
            };
            rec.steps[i].program = Some(safety::redact_program(&prepared.program, &store_root));
            rec.steps[i].arguments = safety::redact_args(&prepared.args, &store_root);
            rec.steps[i].state = StepState::Started;
            rec.steps[i].started_at = Some(self.now());
            first_started.get_or_insert(self.clock.now_unix());
            self.save(&mut rec)?; // write-ahead
            let request = RunRequest {
                program: prepared.program,
                args: prepared.args,
                cwd: prepared.cwd,
                timeout: self.config.timeout,
                output_limit: self.config.output_limit,
                kill_on_timeout: true,
            };
            let result = self.runner.run(&request);
            drop(held);
            rec.steps[i].finished_at = Some(self.now());
            rec.steps[i].state = StepState::Finished;
            match result {
                Err(e) => {
                    rec.steps[i].refusal = Some(e.to_string());
                    rec.steps[i].exit_class = Some(ExitClass::Failed);
                    failed = true;
                }
                Ok(r) => {
                    rec.steps[i].exit_code = r.exit_code;
                    rec.steps[i].timed_out = r.timed_out;
                    rec.steps[i].stdout_tail = tail(&r.stdout);
                    rec.steps[i].stderr_tail = tail(&r.stderr);
                    let class = match r.exit_code {
                        Some(code) if !r.timed_out => step.spec.classify(code).class,
                        _ => ExitClass::Failed,
                    };
                    rec.steps[i].exit_class = Some(class);
                    if let (Some(code), true) = (
                        r.exit_code,
                        step.launcher.as_ref().is_some_and(|l| l.is_terminal()),
                    ) {
                        // The terminal package's exit code is the stub's final HRESULT.
                        rec.steps[i].stub_result = Some(defender::describe_exit(code));
                        if let Some(d) = rec.defender.as_mut() {
                            d.terminal_step = Some(i);
                        }
                    }
                    match class {
                        ExitClass::Success => executed.push(step.update.clone()),
                        ExitClass::Reboot => {
                            reboot = true;
                            executed.push(step.update.clone());
                        }
                        ExitClass::Failed => failed = true,
                    }
                }
            }
            self.save(&mut rec)?;
            if failed {
                break;
            }
        }
        // Servicing steps: the second oracle. The stack's package listing after the run, the
        // pending indicators and the growth of CBS.log are recorded as evidence.
        let mut packages_oracle: Option<String> = None;
        if let (Some(backend), Some(_)) = (self.config.servicing.clone(), rec.servicing.as_ref()) {
            // After a call that hit the timeout the stack is still busy with it and a listing would
            // block until it finishes (OBSERVED: 7.5 minutes on a guest): skip it, the next run judges.
            let post = if unconfirmed_timeout {
                Err(super::servicing::BackendError::Command(
                    "skipped: the servicing stack is still busy with the call that timed out"
                        .into(),
                ))
            } else {
                backend.list_packages()
            };
            let pending_after = backend.pending_indicators().ok();
            let identities: Vec<String> = plan
                .steps
                .iter()
                .enumerate()
                .filter(|(i, st)| {
                    matches!(st.spec, HandlerSpec::Servicing(_))
                        && rec.steps[*i].state == StepState::Finished
                })
                .flat_map(|(i, st)| match os_ids.get(&i) {
                    Some(ids) if !ids.is_empty() => ids.clone(),
                    // an OSInstaller step without a CompDB (monthly update): the ActionList's identities
                    Some(_) => rec.steps[i]
                        .servicing
                        .as_ref()
                        .and_then(|sv| sv.os_installer.as_ref())
                        .map(|ev| ev.expected_identities.clone())
                        .unwrap_or_default(),
                    None => st.servicing_identity.clone().into_iter().collect(),
                })
                .collect();
            if let Some(ev) = rec.servicing.as_mut() {
                ev.pending_after = pending_after;
                if let (Some(path), Some(start)) = (self.config.cbs_log.as_ref(), cbs_mark) {
                    ev.cbs_log = Some(LogRange {
                        path: path.display().to_string(),
                        start,
                        end: handler_log::mark(path),
                    });
                }
                match &post {
                    Ok(snapshot) => {
                        ev.post_count = Some(snapshot.packages.len());
                        ev.post_sha256 = Some(snapshot.digest());
                        if let Some(pre) = pre_snapshot.as_ref() {
                            ev.diff = snapshot.diff_from(pre);
                        }
                        ev.expected_after = identities
                            .iter()
                            .map(|id| {
                                let found = snapshot.find(id);
                                match found.as_slice() {
                                    [] => format!("{id}: absent"),
                                    [one] => format!("{id}: {}", one.state),
                                    _ => format!("{id}: ambiguous ({} entries)", found.len()),
                                }
                            })
                            .collect();
                    }
                    Err(e) => ev.expected_after = vec![format!("package listing unavailable: {e}")],
                }
            }
            packages_oracle = Some(match &post {
                Err(_) => "unavailable".to_owned(),
                Ok(_) if identities.is_empty() => "absent".to_owned(),
                Ok(snapshot) => {
                    let states: Vec<Option<&str>> = identities
                        .iter()
                        .map(|id| match snapshot.find(id).as_slice() {
                            [one] => Some(one.state.as_str()),
                            _ => None,
                        })
                        .collect();
                    if states.iter().all(|s| *s == Some("Installed")) {
                        "installed".to_owned()
                    } else if states.contains(&Some("Install Pending")) {
                        "pending".to_owned()
                    } else if states.iter().any(Option::is_none) {
                        "absent".to_owned()
                    } else {
                        "not_installed".to_owned()
                    }
                }
            });
            if !failed && !reboot && packages_oracle.as_deref() == Some("pending") {
                reboot = true;
                rec.notes.push(
                    "The servicing stack lists the package as Install Pending although the call returned success: a restart completes it."
                        .into(),
                );
            }
        }
        // Exit codes cannot prove success (the Defender packages exit 0 before
        // the update is applied): poll the evaluator until every executed
        // update is installed or the bound expires.
        let converged_pc = |pc: &PostCheck| {
            pc.performed
                && !executed.is_empty()
                && pc.not_installed.is_empty()
                && pc.unknown.is_empty()
                && pc.installed.len() == executed.len()
        };
        // The stub says it found nothing to update (exit 0): waiting would only
        // burn the bound. Read the new log text once, early; the full excerpt
        // is stored below as before.
        let nothing_applied = !failed
            && log_mark
                .as_ref()
                .and_then(|(h, mark)| handler_log::read_excerpt(&h.log_path, *mark))
                .is_some_and(|t| defender::log_says_nothing_applied(&t));
        if nothing_applied {
            if let Some(d) = rec.defender.as_mut() {
                d.nothing_applied = true;
            }
            rec.notes.push(
                "The stub's log says `No products found to update`: nothing was applied (not applicable at this state); the post-check did not wait."
                    .into(),
            );
        }
        let bound = if failed || reboot || nothing_applied || unconfirmed_timeout {
            0
        } else {
            self.config.post_check_wait.as_secs()
        };
        let step = self.config.poll_interval.as_secs().max(1);
        let (mut polls, mut waited) = (0u32, 0u64);
        let mut detached: Vec<handler_log::DetachedProcess> = Vec::new();
        let mut pc = loop {
            let pc = post_check(&executed);
            polls += 1;
            if converged_pc(&pc) || waited + step > bound {
                break pc;
            }
            if let Some((h, _)) = &log_mark {
                for p in self.watcher.running(&h.watch_process) {
                    let late = match (p.started_unix, first_started) {
                        (Some(s), Some(f)) => s >= f,
                        _ => true,
                    };
                    if late && !detached.iter().any(|d| d.pid == p.pid) {
                        detached.push(p);
                    }
                }
            }
            self.sleeper.sleep(self.config.poll_interval);
            waited += step;
        };
        pc.polls = polls;
        pc.waited_secs = waited;
        pc.wait_bound_secs = bound;
        pc.converged = converged_pc(&pc);
        pc.detached_processes = detached;
        rec.post_check = pc;
        if let Some((h, mark)) = &log_mark {
            // Best effort; an unreadable log never fails the install.
            rec.handler_log_excerpt = handler_log::read_excerpt(&h.log_path, *mark);
        }
        // Two oracles for servicing steps: success needs the evaluator AND the package listing.
        let evaluator_installed = rec.post_check.converged;
        let mut oracle_verdict: Option<&str> = None;
        if let Some(pk) = packages_oracle.as_deref() {
            let combined = match (evaluator_installed, pk) {
                (true, "installed") => "agree_installed",
                (false, "pending") => "agree_pending",
                (true, _) => "disagree_evaluator_installed",
                (false, "installed") => "disagree_packages_installed",
                (false, _) => "neither_installed",
            };
            oracle_verdict = Some(combined);
            if let Some(ev) = rec.servicing.as_mut() {
                ev.oracles = Some(Oracles {
                    evaluator_installed,
                    packages: pk.to_owned(),
                    combined: combined.to_owned(),
                });
            }
            if combined.starts_with("disagree") {
                rec.notes.push(format!(
                    "The two post-check oracles disagree ({combined}): never reported as succeeded on one oracle; this is evidence about the evaluator's CBS reading or the package listing."
                ));
            }
        }
        rec.status = if failed {
            JobStatus::Failed
        } else if unconfirmed_timeout {
            rec.notes.push(
                "A servicing call hit the timeout and was NOT killed: the install is judged by fresh state on the next run."
                    .into(),
            );
            JobStatus::Unconfirmed
        } else if reboot {
            JobStatus::RebootRequired
        } else if rec.post_check.converged && oracle_verdict.is_none_or(|v| v == "agree_installed")
        {
            JobStatus::Succeeded
        } else {
            JobStatus::Unconfirmed
        };
        rec.finished_at = Some(self.now());
        self.save(&mut rec)?;
        self.hook.job_finished(&rec);
        Ok(rec)
    }
}

/// Stable `refusal_class` of a step the stack refused as a permanent package.
pub const REFUSAL_PERMANENT: &str = "permanent_package";

impl<'a> Executor<'a> {
    /// Why an uninstall step cannot run at all (before anything is asked of the stack).
    fn uninstall_refusal(&self, step: &InstallStep) -> Option<String> {
        if self.config.allow_unknown {
            return Some(
                "--allow-unknown is not accepted for servicing steps: a wrongly skipped or wrongly assumed servicing change can damage the installation"
                    .into(),
            );
        }
        let HandlerSpec::Servicing(spec) = &step.spec else {
            return Some("an uninstall step must be a servicing (Cbs or OSInstaller) step".into());
        };
        if spec.uninstallation.is_none() && !self.config.allow_undeclared_uninstall {
            return Some(
                "the update declares no UninstallationBehavior and this run was not given the explicit override (--allow-undeclared)"
                    .into(),
            );
        }
        let Some(backend) = self.config.servicing.as_ref() else {
            return Some(
                "no servicing backend is configured (install.servicing_backend dism or dism_api, cbs-handler feature)"
                    .into(),
            );
        };
        if !backend.supports_remove_package() {
            return Some(format!(
                "the `{}` backend cannot remove packages (use dism or dism_api)",
                backend.name()
            ));
        }
        let Some(identity) = step.servicing_identity.as_deref() else {
            return Some("the step names no package identity".into());
        };
        if !super::servicing::is_valid_package_identity(identity) {
            return Some(format!("`{identity}` is not a package identity"));
        }
        // A package the stack already refused as permanent is not asked again: the answer is a
        // property of the package, and a retry cannot succeed.
        if let Ok(records) = self.jobs.list() {
            for r in records.iter().rev() {
                let hit = r.steps.iter().any(|s| {
                    s.servicing.as_ref().is_some_and(|sv| {
                        sv.refusal_class.as_deref() == Some(REFUSAL_PERMANENT)
                            && sv
                                .identity_expected
                                .as_deref()
                                .is_some_and(|i| i.eq_ignore_ascii_case(identity))
                    })
                });
                if hit {
                    return Some(format!(
                        "the servicing stack already refused to remove {identity} as a permanent package (job {}); not asked again",
                        r.job_id
                    ));
                }
            }
        }
        None
    }

    /// Runs one uninstall step through the backend, with the write-ahead state around the call.
    fn run_uninstall_step(
        &self,
        rec: &mut JobRecord,
        i: usize,
        step: &InstallStep,
        backend: &dyn ServicingBackend,
        log_dir: Option<&Path>,
    ) -> StepVerdict {
        let identity = step.servicing_identity.clone().unwrap_or_default();
        let mut sv = StepServicing {
            backend: backend.name().into(),
            native_code: None,
            class: None,
            description: String::new(),
            applicable: None,
            identity_expected: step.servicing_identity.clone(),
            log_paths: Vec::new(),
            os_installer: None,
            operation: StepOperation::Uninstall,
            refusal_class: None,
        };
        rec.steps[i].program = Some(format!("servicing:{}", backend.name()));
        rec.steps[i].arguments = vec![format!("remove {identity}")];
        rec.steps[i].state = StepState::Started;
        rec.steps[i].started_at = Some(self.now());
        rec.steps[i].servicing = Some(sv.clone());
        if self.save(rec).is_err() {
            rec.steps[i].state = StepState::Refused;
            rec.steps[i].refusal = Some("the write-ahead job record could not be written".into());
            return StepVerdict::Failed;
        }
        let dir = log_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.jobs.dir().to_path_buf());
        let call = backend.remove_package(&identity, &dir, self.config.timeout);
        rec.steps[i].finished_at = Some(self.now());
        rec.steps[i].state = StepState::Finished;
        let verdict = match call {
            Err(e) => {
                sv.description = e.to_string();
                rec.steps[i].refusal = Some(e.to_string());
                rec.steps[i].exit_class = Some(ExitClass::Failed);
                StepVerdict::Failed
            }
            Ok(r) => {
                sv.native_code = r.native_code;
                sv.class = Some(r.class);
                sv.description = r.description.clone();
                sv.log_paths = r.log_paths.clone();
                rec.steps[i].exit_code = r.native_code.map(|c| c as i32);
                rec.steps[i].timed_out = r.timed_out;
                rec.steps[i].stdout_tail = r.stdout_tail;
                rec.steps[i].stderr_tail = r.stderr_tail;
                if r.timed_out {
                    StepVerdict::Unconfirmed
                } else {
                    match r.class {
                        ServicingClass::Success => {
                            rec.steps[i].exit_class = Some(ExitClass::Success);
                            StepVerdict::Executed
                        }
                        ServicingClass::Reboot => {
                            rec.steps[i].exit_class = Some(ExitClass::Reboot);
                            StepVerdict::RebootBarrier
                        }
                        ServicingClass::Permanent => {
                            sv.refusal_class = Some(REFUSAL_PERMANENT.into());
                            rec.steps[i].exit_class = Some(ExitClass::Failed);
                            rec.steps[i].refusal = Some(format!(
                                "permanent package: the servicing stack refuses to remove it, nothing changed, not retried ({})",
                                r.description
                            ));
                            StepVerdict::Failed
                        }
                        ServicingClass::NotApplicable
                        | ServicingClass::Busy
                        | ServicingClass::Failed => {
                            rec.steps[i].exit_class = Some(ExitClass::Failed);
                            rec.steps[i].refusal = Some(r.description);
                            StepVerdict::Failed
                        }
                    }
                }
            }
        };
        rec.steps[i].servicing = Some(sv);
        verdict
    }

    /// Runs an uninstall plan (docs/wsus-osinstaller-spike.md 18.9). Nothing is downloaded and no
    /// payload is touched. The two oracles after the call are the evaluator (the update must no longer
    /// evaluate installed) and the package listing (the identity must be absent).
    fn run_uninstall(
        &self,
        plan: &InstallPlan,
        post_check: &mut dyn FnMut(&[String]) -> PostCheck,
        mut rec: JobRecord,
        job_id: &str,
    ) -> Result<JobRecord, ExecError> {
        rec.schema = JOB_SCHEMA_V3.into();
        rec.notes.push(
            "Uninstall run: the servicing stack removes the package; trust is the stack's, no payload is downloaded or executed. The post-check passes only when the update no longer evaluates installed AND the package listing no longer has the identity. Reporting is not sent."
                .into(),
        );
        let mut refused = false;
        let mut steps: Vec<InstallStep> = plan.steps.clone();
        if plan.steps.is_empty() {
            rec.notes.push("an uninstall plan without steps".to_owned());
            refused = true;
        }
        // An OSInstaller update names no package in its metadata: the identity is read from its
        // digest-verified CompDB cabinet in the store (exactly one package, else the target is
        // ambiguous and the step is refused).
        for (i, step) in steps.iter_mut().enumerate() {
            let needs_compdb = step.servicing_identity.is_none()
                && matches!(
                    &step.spec,
                    HandlerSpec::Servicing(sp) if sp.kind == super::handlers::ServicingKind::OsInstaller
                );
            if !needs_compdb {
                continue;
            }
            match self.os_identities(step) {
                Ok(ids) if ids.len() == 1 => {
                    rec.notes.push(format!(
                        "step {i}: the package identity {} was read from the update's CompDB cabinet",
                        ids[0]
                    ));
                    step.servicing_identity = ids.into_iter().next();
                }
                Ok(ids) => {
                    rec.steps[i].state = StepState::Refused;
                    rec.steps[i].refusal = Some(format!(
                        "the CompDB cabinet names {} packages ({}): the one to remove is ambiguous, name it with --package",
                        ids.len(),
                        ids.join(", ")
                    ));
                    refused = true;
                }
                Err(why) => {
                    rec.steps[i].state = StepState::Refused;
                    rec.steps[i].refusal = Some(format!(
                        "the package identity cannot be read from the CompDB cabinet: {why}"
                    ));
                    refused = true;
                }
            }
        }
        for (i, step) in steps.iter().enumerate() {
            if rec.steps[i].state == StepState::Refused {
                continue;
            }
            if let Some(why) = self.uninstall_refusal(step) {
                rec.steps[i].state = StepState::Refused;
                rec.steps[i].refusal = Some(why);
                refused = true;
            }
        }
        let backend = self.config.servicing.clone();
        let mut pre_snapshot: Option<PackageSnapshot> = None;
        let mut sv_log_dir: Option<PathBuf> = None;
        let mut cbs_mark: Option<u64> = None;
        if let (false, Some(backend)) = (refused, backend.as_ref()) {
            match self.servicing_prestate(plan, backend.as_ref()) {
                Ok((evidence, snapshot)) => {
                    // Every target must be exactly one package the stack lists as Installed.
                    for (i, step) in steps.iter().enumerate() {
                        let id = step.servicing_identity.as_deref().unwrap_or_default();
                        let found = snapshot.find(id);
                        let why = match found.as_slice() {
                            [one] if one.is_installed() => None,
                            [one] => Some(format!(
                                "the package is listed as `{}`, not Installed: nothing is removed from this state (a pending operation needs a restart first)",
                                one.state
                            )),
                            [] => Some(
                                "the package is not in the servicing stack's listing".to_owned(),
                            ),
                            _ => Some(format!(
                                "{} listing entries match the identity",
                                found.len()
                            )),
                        };
                        if let Some(why) = why {
                            rec.steps[i].state = StepState::Refused;
                            rec.steps[i].refusal = Some(why);
                            refused = true;
                        }
                    }
                    rec.servicing = Some(evidence);
                    pre_snapshot = Some(snapshot);
                    let dir = self
                        .config
                        .servicing_log_dir
                        .clone()
                        .unwrap_or_else(|| self.jobs.dir().join(format!("{job_id}-servicing")));
                    let _ = std::fs::create_dir_all(&dir);
                    sv_log_dir = Some(dir);
                    cbs_mark = self.config.cbs_log.as_deref().map(handler_log::mark);
                }
                Err(why) => {
                    rec.steps[0].state = StepState::Refused;
                    rec.steps[0].refusal = Some(why);
                    refused = true;
                }
            }
        }
        if refused {
            rec.status = JobStatus::Refused;
            rec.finished_at = Some(self.now());
            self.save(&mut rec)?;
            self.hook.job_finished(&rec);
            return Ok(rec);
        }
        let backend = backend.expect("checked by uninstall_refusal");
        rec.status = JobStatus::Running;
        self.save(&mut rec)?;
        let mut reboot = false;
        let mut failed = false;
        let mut unconfirmed_timeout = false;
        let mut executed: Vec<String> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let verdict =
                self.run_uninstall_step(&mut rec, i, step, backend.as_ref(), sv_log_dir.as_deref());
            self.save(&mut rec)?;
            match verdict {
                StepVerdict::Executed => executed.push(step.update.clone()),
                StepVerdict::RebootBarrier => {
                    executed.push(step.update.clone());
                    reboot = true;
                    if i + 1 < steps.len() {
                        if let Some(ev) = rec.servicing.as_mut() {
                            ev.remaining_steps = (i + 1..steps.len()).collect();
                        }
                        self.save(&mut rec)?;
                        break;
                    }
                }
                StepVerdict::Unconfirmed => {
                    unconfirmed_timeout = true;
                    break;
                }
                StepVerdict::Failed => {
                    failed = true;
                    break;
                }
            }
        }
        if rec.steps.iter().any(|s| {
            s.servicing
                .as_ref()
                .is_some_and(|sv| sv.refusal_class.as_deref() == Some(REFUSAL_PERMANENT))
        }) {
            rec.notes.push(
                "A permanent package: the servicing stack answered 0x800f0825 and changed nothing. This is a classified refusal, not retried; a later uninstall of the same package is refused without asking the stack again."
                    .into(),
            );
        }
        // Second oracle: the package listing (never listed after a timeout: the stack is still busy).
        let post = if unconfirmed_timeout {
            Err(super::servicing::BackendError::Command(
                "skipped: the servicing stack is still busy with the call that timed out".into(),
            ))
        } else {
            backend.list_packages()
        };
        let pending_after = backend.pending_indicators().ok();
        let identities: Vec<String> = steps
            .iter()
            .enumerate()
            .filter(|(i, _)| rec.steps[*i].state == StepState::Finished)
            .filter_map(|(_, st)| st.servicing_identity.clone())
            .collect();
        if let Some(ev) = rec.servicing.as_mut() {
            ev.pending_after = pending_after;
            if let (Some(path), Some(start)) = (self.config.cbs_log.as_ref(), cbs_mark) {
                ev.cbs_log = Some(LogRange {
                    path: path.display().to_string(),
                    start,
                    end: handler_log::mark(path),
                });
            }
            match &post {
                Ok(snapshot) => {
                    ev.post_count = Some(snapshot.packages.len());
                    ev.post_sha256 = Some(snapshot.digest());
                    if let Some(pre) = pre_snapshot.as_ref() {
                        // Includes the predecessor's change (for the .NET rollup: the superseded
                        // 9321.3 returning to Install Pending), which is evidence, not an assumption.
                        ev.diff = snapshot.diff_from(pre);
                    }
                    ev.expected_after = identities
                        .iter()
                        .map(|id| {
                            let found = snapshot.find(id);
                            match found.as_slice() {
                                [] => format!("{id}: absent"),
                                [one] => format!("{id}: {}", one.state),
                                _ => format!("{id}: ambiguous ({} entries)", found.len()),
                            }
                        })
                        .collect();
                }
                Err(e) => ev.expected_after = vec![format!("package listing unavailable: {e}")],
            }
        }
        // `absent`: every identity is gone; `pending`: at least one is `Uninstall Pending`;
        // `installed`: at least one is still Installed; `other`: any other state or ambiguity.
        let packages_oracle = match &post {
            Err(_) => "unavailable".to_owned(),
            Ok(_) if identities.is_empty() => "unavailable".to_owned(),
            Ok(snapshot) => {
                let states: Vec<Option<String>> = identities
                    .iter()
                    .map(|id| match snapshot.find(id).as_slice() {
                        [] => None,
                        [one] => Some(one.state.clone()),
                        _ => Some("ambiguous".to_owned()),
                    })
                    .collect();
                if states.iter().any(|s| s.as_deref() == Some("Installed")) {
                    "installed"
                } else if states
                    .iter()
                    .any(|s| s.as_deref() == Some("Uninstall Pending"))
                {
                    "pending"
                } else if states.iter().all(Option::is_none) {
                    "absent"
                } else {
                    "other"
                }
                .to_owned()
            }
        };
        if !failed && !reboot && !unconfirmed_timeout && packages_oracle == "pending" {
            reboot = true;
            rec.notes.push(
                "The servicing stack lists the package as Uninstall Pending although the call returned success: a restart completes the removal."
                    .into(),
            );
        }
        // Evaluator oracle: after a plain success poll until no executed update evaluates installed.
        // (`installed` of the post-check callback means STILL installed here.)
        let removed = |pc: &PostCheck| {
            pc.performed
                && !executed.is_empty()
                && pc.installed.is_empty()
                && pc.unknown.is_empty()
                && pc.not_installed.len() == executed.len()
        };
        let bound = if failed || reboot || unconfirmed_timeout {
            0
        } else {
            self.config.post_check_wait.as_secs()
        };
        let step_secs = self.config.poll_interval.as_secs().max(1);
        let (mut polls, mut waited) = (0u32, 0u64);
        let mut pc = loop {
            let pc = post_check(&executed);
            polls += 1;
            if removed(&pc) || waited + step_secs > bound {
                break pc;
            }
            self.sleeper.sleep(self.config.poll_interval);
            waited += step_secs;
        };
        pc.polls = polls;
        pc.waited_secs = waited;
        pc.wait_bound_secs = bound;
        pc.converged = removed(&pc);
        let evaluator_removed = pc.converged;
        rec.post_check = pc;
        let combined = match (evaluator_removed, packages_oracle.as_str()) {
            (true, "absent") => "agree_removed",
            (_, "pending") => "agree_pending",
            (true, _) => "disagree_evaluator_removed",
            (false, "absent") => "disagree_packages_absent",
            (false, _) => "neither_removed",
        };
        if let Some(ev) = rec.servicing.as_mut() {
            ev.oracles = Some(Oracles {
                // For an uninstall this is the evaluator's verdict that the update no longer
                // evaluates installed (the field name is shared with installs).
                evaluator_installed: evaluator_removed,
                packages: packages_oracle.clone(),
                combined: combined.to_owned(),
            });
        }
        if combined.starts_with("disagree") {
            rec.notes.push(format!(
                "The two post-check oracles disagree ({combined}): never reported as removed on one oracle."
            ));
        }
        rec.status = if failed {
            JobStatus::Failed
        } else if unconfirmed_timeout {
            rec.notes.push(
                "A servicing call hit the timeout and was NOT killed: the removal is judged by fresh state on the next run."
                    .into(),
            );
            JobStatus::Unconfirmed
        } else if reboot {
            JobStatus::RebootRequired
        } else if combined == "agree_removed" {
            JobStatus::Succeeded
        } else {
            JobStatus::Unconfirmed
        };
        rec.finished_at = Some(self.now());
        self.save(&mut rec)?;
        self.hook.job_finished(&rec);
        Ok(rec)
    }
}

/// An executor with the default (no-op) report hook.
pub static NO_REPORT: NoReport = NoReport;

#[cfg(test)]
mod output_tests {
    use super::{decode_output, tail};

    fn utf16(s: &str, bom: bool) -> Vec<u8> {
        let mut v = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn utf16le_console_output_is_decoded_with_or_without_a_bom() {
        let msg = "This installation package could not be opened.";
        assert_eq!(decode_output(&utf16(msg, false)), msg);
        assert_eq!(decode_output(&utf16(msg, true)), msg);
        assert_eq!(tail(&utf16(msg, false)).as_deref(), Some(msg));
    }

    #[test]
    fn utf8_and_short_output_are_left_alone() {
        assert_eq!(decode_output(b"plain ascii text"), "plain ascii text");
        assert_eq!(decode_output("caf\u{e9}".as_bytes()), "caf\u{e9}");
        assert_eq!(decode_output(b"a"), "a");
        assert_eq!(tail(b""), None);
    }
}
