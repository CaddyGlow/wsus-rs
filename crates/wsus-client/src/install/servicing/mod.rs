//! Online servicing of CBS updates behind a backend trait (design: docs/wsus-cbs-integration.md).
//!
//! The executor never installs a CBS package itself. It asks a [`ServicingBackend`] to list the
//! packages the servicing stack knows, to say whether a payload is applicable, to report pending
//! reboot indicators and free disk space, to add one package and (uninstall, `remove_package`) to remove one. The trait and the
//! [`FakeBackend`] are always compiled so the executor logic is host-testable; the Windows backends
//! (`dism`, `wusa`, and `dism_api`, the in-process DISM API) are behind the `cbs-handler` feature because they use
//! the servicing crates' text parsers.
//!
//! Trust is DELEGATED to the servicing stack (owner decision, design 8.3a Q-A): the client verifies
//! the metadata digests of the payload, does not apply its Authenticode gate to CBS payloads, and
//! records the delegation in the job.
//!
//! Evidence labels in this module: READ = read in the servicing crates or their evidence docs;
//! OBSERVED = seen on a guest (see docs/wsus-install.md); INFERRED = reasoned, not observed.
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, time::Duration};

#[cfg(feature = "cbs-handler")]
pub mod dism;
#[cfg(feature = "cbs-handler")]
pub mod dism_api;
pub mod fake;
#[cfg(feature = "osinstaller-handler")]
pub mod msu;
pub mod os_installer;
pub mod pending;
#[cfg(all(windows, feature = "osinstaller-handler"))]
pub mod update_agent;
#[cfg(feature = "cbs-handler")]
pub mod wusa;

pub use fake::FakeBackend;
pub use os_installer::{FakeOsBackend, OsInstallerBackend, OsInstallerMode};

/// One package as the servicing stack lists it (`state` is DISM's English text, for example
/// `Installed`, `Install Pending`, `Superseded`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEntry {
    pub identity: String,
    pub state: String,
}

impl PackageEntry {
    pub fn is_installed(&self) -> bool {
        self.state == "Installed"
    }
}

/// A listing of the installed packages.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackageSnapshot {
    pub packages: Vec<PackageEntry>,
}

impl PackageSnapshot {
    /// Entries whose identity equals `identity`, ignoring case.
    pub fn find(&self, identity: &str) -> Vec<&PackageEntry> {
        self.packages
            .iter()
            .filter(|p| p.identity.eq_ignore_ascii_case(identity))
            .collect()
    }

    /// SHA-256 (hex) of the canonical `identity|state` lines, sorted.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut lines: Vec<String> = self
            .packages
            .iter()
            .map(|p| format!("{}|{}", p.identity.to_ascii_lowercase(), p.state))
            .collect();
        lines.sort();
        let mut h = Sha256::new();
        for l in &lines {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        crate::download::hex_encode(&h.finalize())
    }

    /// Entries that are new or changed state compared with `before`, as `identity: old -> new`.
    pub fn diff_from(&self, before: &PackageSnapshot) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.packages {
            match before.find(&p.identity).first() {
                None => out.push(format!("{}: (absent) -> {}", p.identity, p.state)),
                Some(b) if b.state != p.state => {
                    out.push(format!("{}: {} -> {}", p.identity, b.state, p.state))
                }
                _ => {}
            }
        }
        for b in &before.packages {
            if self.find(&b.identity).is_empty() {
                out.push(format!("{}: {} -> (absent)", b.identity, b.state));
            }
        }
        out.sort();
        out
    }
}

/// Reboot and servicing indicators that were set (evidence; a set indicator before a run refuses it).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PendingIndicators {
    /// Names of indicators found set, for example `CBS RebootPending`.
    pub set: Vec<String>,
    /// Indicators that could not be read (never silently treated as clear).
    pub unavailable: Vec<String>,
}

impl PendingIndicators {
    pub fn reboot_pending(&self) -> bool {
        !self.set.is_empty()
    }
}

/// How the backend classifies a native result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicingClass {
    Success,
    /// Installed, a reboot completes it.
    Reboot,
    /// The servicing stack says the package does not apply to this system.
    NotApplicable,
    /// The servicing stack was busy or another servicing session is pending.
    Busy,
    /// The servicing stack refuses to remove the package because it is permanent (`0x800f0825`,
    /// OBSERVED for the monthly cumulative update, docs/wsus-osinstaller-spike.md 18.6). Never retried.
    Permanent,
    Failed,
}

/// What a servicing step does to its package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOperation {
    #[default]
    Install,
    /// Removal of an installed package (`remove_package`).
    Uninstall,
}

impl StepOperation {
    pub fn is_install(&self) -> bool {
        *self == StepOperation::Install
    }
}

/// True for a CBS package identity the backends may pass on a command line or to the DISM API:
/// `name~publicKeyToken~architecture~language~version`, with only characters that occur in such
/// identities. Anything else is refused before a process is started.
pub fn is_valid_package_identity(identity: &str) -> bool {
    let parts: Vec<&str> = identity.split('~').collect();
    parts.len() == 5
        && !parts[0].is_empty()
        && !parts[4].is_empty()
        && identity.len() <= 512
        && identity
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '~'))
}

/// The result of one add-package call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicingResult {
    pub backend: String,
    /// Exit code or HRESULT as the native tool returned it (`None`: no code, for example a timeout).
    pub native_code: Option<u32>,
    pub class: ServicingClass,
    /// Human-readable meaning of the code (labelled where inferred).
    pub description: String,
    /// The call hit the timeout. The process was NOT killed.
    pub timed_out: bool,
    pub stdout_tail: Option<String>,
    pub stderr_tail: Option<String>,
    /// Log files the backend wrote or knows (paths only, never contents).
    pub log_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The backend does not implement the operation (a backend that lacks it).
    #[error("not supported by this backend: {0}")]
    Unsupported(String),
    #[error("servicing command failed: {0}")]
    Command(String),
    #[error("servicing output not understood: {0}")]
    Parse(String),
}

/// The servicing stack behind the executor. Implementations never kill a servicing process.
pub trait ServicingBackend: fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;

    /// File extensions of payloads this backend can add (lower case, no dot).
    fn payload_extensions(&self) -> &'static [&'static str] {
        &["cab"]
    }

    /// Every package the servicing stack lists, strictly parsed.
    fn list_packages(&self) -> Result<PackageSnapshot, BackendError>;

    /// `Some(true/false)`: the stack's own applicability verdict for the payload; `None`: the
    /// backend cannot say (then only the evaluator decides).
    fn payload_applicability(&self, payload: &Path) -> Result<Option<bool>, BackendError>;

    /// Reboot and servicing indicators (never an install decision by itself).
    fn pending_indicators(&self) -> Result<PendingIndicators, BackendError>;

    /// Free bytes on the system volume, `None` when unknown.
    fn free_disk_bytes(&self) -> Result<Option<u64>, BackendError>;

    /// Adds one payload without rebooting. Must not kill the process on timeout: on timeout the
    /// result has `timed_out` and no code and the install is judged by fresh state later.
    fn add_package(
        &self,
        payload: &Path,
        log_dir: &Path,
        timeout: Duration,
    ) -> Result<ServicingResult, BackendError>;

    /// True when [`ServicingBackend::remove_package`] is implemented. Additive: a backend that does
    /// not override both methods refuses uninstall steps before anything is changed.
    fn supports_remove_package(&self) -> bool {
        false
    }

    /// Removes one installed package by its identity without rebooting (DISM `/Remove-Package`,
    /// `DismRemovePackage`). Same rules as `add_package`: never kill on timeout (the result has
    /// `timed_out` and no code); `0x800f0825` is classified [`ServicingClass::Permanent`].
    fn remove_package(
        &self,
        identity: &str,
        _log_dir: &Path,
        _timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        Err(BackendError::Unsupported(format!(
            "the `{}` backend cannot remove `{identity}`",
            self.name()
        )))
    }
}

/// What the job records about the servicing stack for a run (written only when a servicing step
/// exists).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ServicingEvidence {
    pub backend: String,
    /// Always `servicing_stack`: signature verification of CBS payloads is delegated to DISM/CBS;
    /// the metadata digests were still verified by the client.
    pub trust: String,
    pub pre_count: usize,
    pub pre_sha256: String,
    pub post_count: Option<usize>,
    pub post_sha256: Option<String>,
    /// Packages added or changed between the two listings.
    pub diff: Vec<String>,
    /// The expected identities and their state after the run (`identity: state`).
    pub expected_after: Vec<String>,
    pub pending_before: PendingIndicators,
    pub pending_after: Option<PendingIndicators>,
    pub free_disk_before: Option<u64>,
    /// `CBS.log` growth during the run (offsets only; the text is not copied).
    pub cbs_log: Option<LogRange>,
    /// Steps not run because an earlier step needs a reboot first (rerun after the reboot).
    pub remaining_steps: Vec<usize>,
    /// The two oracles of the post-check and how they combined.
    pub oracles: Option<Oracles>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRange {
    pub path: String,
    pub start: u64,
    pub end: u64,
}

/// Post-check oracles (design 5.5): the evaluator over fresh facts and the package listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oracles {
    /// Every executed update evaluates installed.
    pub evaluator_installed: bool,
    /// `installed`, `pending`, `not_installed`, `absent`, `unavailable` (no expected identity or no
    /// listing).
    pub packages: String,
    pub combined: String,
}

/// Per-step servicing evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepServicing {
    pub backend: String,
    pub native_code: Option<u32>,
    pub class: Option<ServicingClass>,
    pub description: String,
    /// The stack's own applicability verdict before the call.
    pub applicable: Option<bool>,
    pub identity_expected: Option<String>,
    pub log_paths: Vec<String>,
    /// Evidence of an `OSInstaller` step (mode, phases, ActionList, download list); absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_installer: Option<os_installer::OsStepEvidence>,
    /// `uninstall` for a removal step; absent for installs (records of earlier versions stay readable).
    #[serde(default, skip_serializing_if = "StepOperation::is_install")]
    pub operation: StepOperation,
    /// Why the stack refused, as a stable class (`permanent_package`); absent otherwise. A later run
    /// reads it to refuse the same package without asking the stack again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_class: Option<String>,
}
