//! Install and uninstall outcome events built from a finished job record.
//!
//! The events are queued durably in the [`EventQueue`] (delivered later by
//! `flush_events`, never from the hook: the install path has no network
//! dependency). Every event id is derived from the job id, the update and the
//! event id, so a hook called twice for one job, a rerun of the same record or
//! a restart between enqueue and delivery queues one event, not two.
//!
//! Evidence (inventory 9.10, `docs/wsus-validation.md` C61):
//!
//! * Observed from a native Windows Update Agent, namespace 1, source 101, an
//!   update the client installed: `181` (installation started) then, for a
//!   reboot-requiring install, `201` ("Installation pending") with
//!   `Win32HResult` `0x00240005` (`WU_S_REBOOT_REQUIRED`) and `MiscData` `D=1`;
//!   for a plain success `183` with `D=1` (the Defender definitions run, C29);
//!   for a failure `182` whose `Win32HResult` is the failure, with
//!   `ReplacementStrings` the hexadecimal result and the title, and `MiscData`
//!   `C=1` and `F=<result>`. The update id and revision are the deployed update
//!   (the bundle root), the title is its `ReplacementStrings[0]` or `[1]`.
//! * NOT observed from a native client: any uninstall event (no update of the
//!   lab catalog is uninstallable through the Windows Update Agent). The ids
//!   `226`, `222`, `224` and `221` are those of the real WSUS's own event table
//!   (`SUSDB.dbo.tbEvent` with its message templates), the shape is the install
//!   shape by analogy. They are queued only when the caller asks for them.
//! * Not sent: download events (`167`, `162`, `161`), the post-restart events
//!   (`202`, `203`: a native client was not seen to send any, within the minutes
//!   it was watched after a restart), and `MiscData` keys whose meaning is
//!   unknown (`Q`, `G`, `J`, `K`, `L`, `T`, the numeric flags). Nothing is sent
//!   for a job that was refused, did nothing, was interrupted or whose outcome
//!   the evaluator did not confirm.

use crate::{
    install::{
        handlers::ExitClass,
        job::{JobRecord, JobStatus, ReportHook, StepRecord},
        plan::PlanOutcome,
        servicing::{ServicingClass, StepOperation},
    },
    reporting::{AppendOutcome, EventQueue},
    sync::{Catalog, EventDetail, ReportEvent, select_localized},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};

/// `NamespaceID` of client events (`MSUS 2.0 Client Event Namespace`).
pub const CLIENT_NAMESPACE: i32 = 1;
/// `SourceID` of the client agent (`Client Agent`), the source of every observed install event.
pub const CLIENT_AGENT_SOURCE: i16 = 101;
/// Installation started.
pub const INSTALL_STARTED: i16 = 181;
/// Installation failure (`Win32HResult` is the error).
pub const INSTALL_FAILED: i16 = 182;
/// Installation successful, no restart needed.
pub const INSTALL_SUCCEEDED: i16 = 183;
/// Installation pending (restart required).
pub const INSTALL_PENDING_REBOOT: i16 = 201;
/// Uninstallation failure (table only, not observed).
pub const UNINSTALL_FAILED: i16 = 221;
/// Uninstallation successful (table only, not observed).
pub const UNINSTALL_SUCCEEDED: i16 = 222;
/// Uninstallation successful and restart required (table only, not observed).
pub const UNINSTALL_PENDING_REBOOT: i16 = 224;
/// Uninstallation started (table only, not observed).
pub const UNINSTALL_STARTED: i16 = 226;
/// `WU_S_REBOOT_REQUIRED`, the `Win32HResult` of the observed event 201.
pub const WU_S_REBOOT_REQUIRED: i32 = 0x0024_0005;
/// `E_FAIL`, when a failed job carries no better code.
const E_FAIL: i32 = 0x8000_4005_u32 as i32;
/// `HRESULT_FROM_WIN32(ERROR_TIMEOUT)`.
const TIMEOUT_HRESULT: i32 = 0x8007_05B4_u32 as i32;

/// Options of the reporter.
#[derive(Debug, Clone)]
pub struct InstallReportOptions {
    /// `AppName` of the events (basic data and the `AppName=` misc entry).
    pub app_name: String,
    /// Also build events for uninstall jobs (shape not observed natively).
    pub include_uninstall: bool,
    /// The update the events name instead of the job's plan target, when the target is a bundle's
    /// child (see [`reported_update`]). The title map is keyed by this update.
    pub update: Option<UpdateRevision>,
}

impl Default for InstallReportOptions {
    fn default() -> Self {
        Self {
            app_name: "wsus-client".to_owned(),
            include_uninstall: false,
            update: None,
        }
    }
}

/// An `HRESULT` for a process or servicing code: values with the severity bit
/// set are already `HRESULT`s, other non-zero values are Win32 codes.
fn hresult_from_code(code: u32) -> i32 {
    if code & 0x8000_0000 != 0 {
        code as i32
    } else if code == 0 {
        E_FAIL
    } else {
        (0x8007_0000 | (code & 0xFFFF)) as i32
    }
}

fn step_failed(s: &StepRecord) -> bool {
    s.timed_out
        || s.exit_class == Some(ExitClass::Failed)
        || s.servicing.as_ref().is_some_and(|v| {
            matches!(
                v.class,
                Some(
                    ServicingClass::Failed
                        | ServicingClass::Busy
                        | ServicingClass::Permanent
                        | ServicingClass::NotApplicable
                )
            )
        })
}

/// The `HRESULT` that describes why a failed job failed: the first failing
/// step's timeout, servicing result or exit code, else `E_FAIL`.
pub fn failure_hresult(rec: &JobRecord) -> i32 {
    let Some(step) = rec.steps.iter().find(|s| step_failed(s)) else {
        return E_FAIL;
    };
    if step.timed_out {
        return TIMEOUT_HRESULT;
    }
    if let Some(code) = step.servicing.as_ref().and_then(|v| v.native_code)
        && code != 0
    {
        return hresult_from_code(code);
    }
    match step.exit_code {
        Some(code) if code != 0 => hresult_from_code(code as u32),
        _ => E_FAIL,
    }
}

/// The update a native agent names in its events: the DEPLOYED update. An update the operator named
/// that carries no deployment of its own but is bundled by one that does (the installer child of a
/// bundle) is reported under that bundle, as the real WSUS knows only the deployed update; any
/// other update is reported as itself.
pub fn reported_update(catalog: &Catalog, target: UpdateRevision) -> UpdateRevision {
    let deployed = |r: &UpdateRevision| {
        catalog
            .get(r)
            .is_some_and(|e| e.record.deployment.is_some())
    };
    if deployed(&target) {
        return target;
    }
    catalog
        .revisions()
        .find(|r| {
            deployed(r)
                && catalog.relationships(r).is_some_and(|rel| {
                    rel.bundles
                        .iter()
                        .any(|c| c.revisions.iter().any(|b| b.id == target.id))
                })
        })
        .copied()
        .unwrap_or(target)
}

/// The title of an update in the catalog (the English or best available localized fragment).
pub fn catalog_title(catalog: &Catalog, update: UpdateRevision) -> Option<String> {
    catalog
        .get(&update)
        .and_then(|e| select_localized(&e.record, &["en-US"]))
        .and_then(|l| l.title)
}

fn parse_target(text: &str) -> Option<UpdateRevision> {
    let (id, revision) = text.split_once('@')?;
    Some(UpdateRevision {
        id: UpdateId(Uuid::parse_str(id).ok()?),
        revision: Revision(revision.parse().ok()?),
    })
}

/// Deterministic event instance id (a version 5 shaped UUID of a SHA-256
/// over the job, the update and the event id).
fn instance_id(job_id: &str, update: &str, event_id: i16) -> Uuid {
    let digest = Sha256::digest(format!(
        "wsus-client-install-event|{job_id}|{update}|{event_id}"
    ));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0F) | 0x50;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(bytes)
}

/// The events of one finished job, in the order they are queued; empty for a
/// job that does not report (see the module documentation).
pub fn events_for_job(
    rec: &JobRecord,
    titles: &BTreeMap<String, String>,
    opts: &InstallReportOptions,
) -> Vec<ReportEvent> {
    let uninstall = rec.plan.outcome == PlanOutcome::Uninstall
        || rec.steps.iter().any(|s| {
            s.servicing
                .as_ref()
                .is_some_and(|v| v.operation == StepOperation::Uninstall)
        });
    if uninstall && !opts.include_uninstall {
        return Vec::new();
    }
    if !matches!(
        rec.status,
        JobStatus::Succeeded | JobStatus::RebootRequired | JobStatus::Failed
    ) {
        return Vec::new();
    }
    let Some(update) = opts.update.or_else(|| parse_target(&rec.plan.target)) else {
        return Vec::new();
    };
    let title = titles
        .get(&update.to_string())
        .cloned()
        .unwrap_or_else(|| update.to_string());
    let started_at = rec.started_at.clone();
    let finished_at = rec
        .finished_at
        .clone()
        .unwrap_or_else(|| rec.updated_at.clone());
    let (start, ok, pending, failed) = if uninstall {
        (
            UNINSTALL_STARTED,
            UNINSTALL_SUCCEEDED,
            UNINSTALL_PENDING_REBOOT,
            UNINSTALL_FAILED,
        )
    } else {
        (
            INSTALL_STARTED,
            INSTALL_SUCCEEDED,
            INSTALL_PENDING_REBOOT,
            INSTALL_FAILED,
        )
    };
    let app = format!("AppName={}", opts.app_name);
    let make = |event_id: i16, at: &str, hresult: i32, repl: Vec<String>, mut misc: Vec<String>| {
        misc.push(app.clone());
        ReportEvent {
            event_instance_id: instance_id(&rec.job_id, &rec.plan.target, event_id),
            sequence_number: 0,
            time_at_target: at.to_owned(),
            namespace_id: CLIENT_NAMESPACE,
            event_id,
            source_id: CLIENT_AGENT_SOURCE,
            update: Some(update),
            win32_hresult: hresult,
            app_name: Some(opts.app_name.clone()),
            detail: Some(EventDetail {
                replacement_strings: repl,
                misc_data: misc,
            }),
        }
    };
    let mut events = vec![make(start, &started_at, 0, vec![title.clone()], Vec::new())];
    events.push(match rec.status {
        JobStatus::Succeeded => make(ok, &finished_at, 0, vec![title], vec!["D=1".to_owned()]),
        JobStatus::RebootRequired => make(
            pending,
            &finished_at,
            WU_S_REBOOT_REQUIRED,
            vec![title],
            vec!["D=1".to_owned()],
        ),
        _ => {
            let hr = failure_hresult(rec);
            make(
                failed,
                &finished_at,
                hr,
                vec![format!("0x{:08X}", hr as u32), title],
                vec!["C=1".to_owned(), format!("F={hr}")],
            )
        }
    });
    events
}

/// What the reporter did, for the command output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallReportLog {
    /// Events newly queued.
    pub queued: usize,
    /// Events already pending or already delivered (same instance id).
    pub already_known: usize,
    /// Queue failures (the install result is unaffected).
    pub errors: Vec<String>,
}

/// A [`ReportHook`] that queues the events of every finished job.
pub struct InstallReporter {
    queue: Mutex<EventQueue>,
    titles: BTreeMap<String, String>,
    opts: InstallReportOptions,
    log: Mutex<InstallReportLog>,
}

impl InstallReporter {
    /// `titles` maps `UUID@REVISION` of the planned target to its title.
    pub fn new(
        queue: EventQueue,
        titles: BTreeMap<String, String>,
        opts: InstallReportOptions,
    ) -> Self {
        Self {
            queue: Mutex::new(queue),
            titles,
            opts,
            log: Mutex::new(InstallReportLog::default()),
        }
    }

    /// Gives the queue back (for delivery) with what the hook did.
    pub fn finish(self) -> (EventQueue, InstallReportLog) {
        let queue = self
            .queue
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = self
            .log
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (queue, log)
    }
}

impl ReportHook for InstallReporter {
    fn job_finished(&self, record: &JobRecord) {
        let events = events_for_job(record, &self.titles, &self.opts);
        if events.is_empty() {
            return;
        }
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut log = self
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for e in events {
            match e.enqueue(&mut queue) {
                Ok(AppendOutcome::Queued { .. }) => log.queued += 1,
                Ok(_) => log.already_known += 1,
                Err(err) => log.errors.push(format!("event {}: {err}", e.event_id)),
            }
        }
    }
}
