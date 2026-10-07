//! Job records: the evidence of an install run, written before and after
//! every transition (write-ahead), so an interrupted run leaves a record that
//! says exactly how far it got.
//!
//! Layout: `<dir>/<job-id>.json`, one file per run, replaced atomically on
//! every transition; `<dir>/install.lock` is an advisory lock held for the
//! duration of a run (released by the OS when the process dies).
//!
//! Recovery is by re-evaluation: a record left in `running` by a dead process
//! is marked `interrupted` by the next run, which then plans again from the
//! machine's facts. An update that did get installed evaluates installed and
//! drops out of the new plan, so re-running is idempotent. The record keeps
//! which step was `started` but not `finished`: that step's outcome is unknown
//! until the evaluator says.
use super::{
    handlers::ExitClass,
    plan::{InstallPlan, PayloadRef},
    signature::SignatureInfo,
};
use crate::state::atomic_write;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

pub const JOB_SCHEMA: &str = "wsus-install-job/1";
/// Schema of job records that carry servicing evidence ([`JobRecord::servicing`]). `/1` records stay
/// readable (every added field has a default); runs without a servicing step still write `/1`.
pub const JOB_SCHEMA_V2: &str = "wsus-install-job/2";
/// Schema of job records of uninstall plans (servicing evidence with `operation: uninstall`).
pub const JOB_SCHEMA_V3: &str = "wsus-install-job/3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Plan recorded, nothing verified or run yet.
    Planned,
    /// Gates passed or being passed; steps are being executed.
    Running,
    /// Every step succeeded and the evaluator now says installed.
    Succeeded,
    /// Steps succeeded and at least one asked for a reboot.
    RebootRequired,
    /// A step failed or timed out.
    Failed,
    /// Every step exited as success but the evaluator does not say installed.
    Unconfirmed,
    /// A gate (digest, signature, path, plan) refused; nothing was executed.
    Refused,
    /// The plan had nothing to do.
    NoAction,
    /// Left running by a process that no longer exists.
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pending,
    /// Gates passed; the command is about to start (write-ahead).
    Started,
    Finished,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub index: usize,
    pub update: String,
    pub handler: String,
    pub payload: PayloadRef,
    pub state: StepState,
    /// Program, relative to the store (`<store>/...`).
    pub program: Option<String>,
    /// Arguments with paths outside the store replaced.
    pub arguments: Vec<String>,
    pub digest_verified: Option<bool>,
    pub signature: Option<SignatureInfo>,
    pub exit_code: Option<i32>,
    pub exit_class: Option<ExitClass>,
    pub timed_out: bool,
    pub refusal: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub stdout_tail: Option<String>,
    pub stderr_tail: Option<String>,
    /// Set for Defender launcher packages (see `defender`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<super::defender::LauncherPackage>,
    /// For the TERMINAL launcher package only: its exit code is the stub's
    /// final HRESULT; this is what that code means. The exit codes of the
    /// other launcher packages are not the stub's result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stub_result: Option<super::defender::ExitDescription>,
    /// For servicing (`Cbs`) steps: the backend's native result and the stack's own verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servicing: Option<super::servicing::StepServicing>,
}

/// What the run learned about the Defender stub (evidence; never decides
/// success on its own).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefenderEvidence {
    /// Process id of the process that started every package (the common
    /// parent the stub's pipe name is derived from).
    pub parent_pid: u32,
    /// Index of the terminal package step, when one ran.
    pub terminal_step: Option<usize>,
    /// The environment the preconditions were checked against.
    pub environment: Option<super::defender::StubEnv>,
    /// The stub's log said it found nothing to update.
    pub nothing_applied: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostCheck {
    pub performed: bool,
    /// Evaluations made (1 when waiting is disabled).
    #[serde(default)]
    pub polls: u32,
    /// Seconds waited between polls (counted from the poll interval).
    #[serde(default)]
    pub waited_secs: u64,
    /// True when every executed update evaluated installed within the bound.
    #[serde(default)]
    pub converged: bool,
    /// Bound in seconds (`post_check_wait_secs`).
    #[serde(default)]
    pub wait_bound_secs: u64,
    /// Processes of the handler's detached helper seen running while waiting
    /// (never killed).
    #[serde(default)]
    pub detached_processes: Vec<super::handler_log::DetachedProcess>,
    /// Steps whose update now evaluates installed.
    pub installed: Vec<String>,
    pub not_installed: Vec<String>,
    pub unknown: Vec<String>,
    pub facts_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flags {
    pub allow_unknown: bool,
    pub allow_writable_store: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub schema: String,
    pub job_id: String,
    pub status: JobStatus,
    pub started_at: String,
    pub updated_at: String,
    pub finished_at: Option<String>,
    /// `windows` or `file:<sha256 of the facts file>`.
    pub facts_source: String,
    pub facts_hash: String,
    pub plan_hash: String,
    pub trusted_signers: Vec<String>,
    pub flags: Flags,
    pub plan: InstallPlan,
    pub steps: Vec<StepRecord>,
    pub post_check: PostCheck,
    /// New tail of the handler's own log (best effort, bounded; evidence only).
    #[serde(default)]
    pub handler_log_excerpt: Option<String>,
    /// Defender launcher-package evidence (absent for other updates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defender: Option<DefenderEvidence>,
    /// Servicing-stack evidence (absent unless a servicing step was part of the plan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servicing: Option<super::servicing::ServicingEvidence>,
    /// Job ids marked interrupted by this run.
    pub recovered: Vec<String>,
    pub notes: Vec<String>,
    /// Always false: no reporting event is sent by the install path (the
    /// native event id semantics are not established). See `ReportHook`.
    pub reporting_sent: bool,
}

/// Job directory.
#[derive(Debug, Clone)]
pub struct JobStore {
    dir: PathBuf,
}

/// Held for the duration of a run.
#[derive(Debug)]
pub struct JobLock {
    _file: File,
}

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("job store I/O: {0}")]
    Io(#[from] io::Error),
    #[error("job record: {0}")]
    Json(#[from] serde_json::Error),
    #[error("another install run holds the lock ({0})")]
    Locked(PathBuf),
}

impl JobStore {
    /// Creates the directory.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, JobError> {
        let dir = dir.into();
        crate::state::create_private_dir(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Takes the run lock without blocking.
    pub fn lock(&self) -> Result<JobLock, JobError> {
        let path = self.dir.join("install.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(JobLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(JobError::Locked(path)),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Atomically writes the record.
    pub fn write(&self, record: &JobRecord) -> Result<(), JobError> {
        let bytes = serde_json::to_vec_pretty(record)?;
        atomic_write(&self.path(&record.job_id), &bytes)?;
        Ok(())
    }

    pub fn read(&self, id: &str) -> Result<JobRecord, JobError> {
        Ok(serde_json::from_slice(&fs::read(self.path(id))?)?)
    }

    /// All records, oldest id first.
    pub fn list(&self) -> Result<Vec<JobRecord>, JobError> {
        let mut names: Vec<PathBuf> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        names.sort();
        let mut out = Vec::new();
        for n in names {
            if let Ok(r) = serde_json::from_slice::<JobRecord>(&fs::read(&n)?) {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Marks every record still `planned` or `running` as `interrupted`.
    /// Call it only while holding the lock (then no other run is alive).
    pub fn recover_interrupted(&self, now: &str) -> Result<Vec<String>, JobError> {
        let mut ids = Vec::new();
        for mut r in self.list()? {
            if matches!(r.status, JobStatus::Running | JobStatus::Planned) {
                r.status = JobStatus::Interrupted;
                r.updated_at = now.to_owned();
                r.finished_at = Some(now.to_owned());
                let started: Vec<usize> = r
                    .steps
                    .iter()
                    .filter(|s| s.state == StepState::Started)
                    .map(|s| s.index)
                    .collect();
                r.notes.push(format!(
                    "marked interrupted by a later run; steps started but not finished: {started:?} (their effect is decided by re-evaluation)"
                ));
                self.write(&r)?;
                ids.push(r.job_id.clone());
            }
        }
        Ok(ids)
    }
}

/// Hook for reporting install results to the server. The install path does
/// NOT call anything that sends events: the event id semantics of a native
/// client are not established (see the inventory), and a success marker in a
/// report is not install evidence. A future implementation plugs in here.
pub trait ReportHook {
    fn job_finished(&self, _record: &JobRecord) {}
}

/// The default hook: does nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReport;

impl ReportHook for NoReport {}
