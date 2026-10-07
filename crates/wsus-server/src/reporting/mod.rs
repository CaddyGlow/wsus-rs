//! Raw client event storage with deduplication and derived per-update status.
use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, Revision, UpdateId, UpdateRevision};

use crate::computers::stamp_tx;
use crate::storage::{Database, Error, Result, now_unix, string_enum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    DownloadStarted,
    DownloadCompleted,
    DownloadFailed,
    InstallStarted,
    InstallSucceeded,
    InstallFailed,
    RebootRequired,
    UninstallSucceeded,
    UninstallFailed,
    NotApplicable,
    /// The client status event (`156`, "Reporting client status"): its `U` and `V` lists are the
    /// updates the client evaluates as not installed and installed. Derives `NotInstalled` and
    /// `Installed` through [`Reporting::record_inventory`], not through [`EventKind::derived`].
    ClientStatus,
    /// Stored but does not affect derived status.
    Other,
}
string_enum!(EventKind {
    DownloadStarted => "download_started", DownloadCompleted => "download_completed",
    DownloadFailed => "download_failed", InstallStarted => "install_started",
    InstallSucceeded => "install_succeeded", InstallFailed => "install_failed",
    RebootRequired => "reboot_required", UninstallSucceeded => "uninstall_succeeded",
    UninstallFailed => "uninstall_failed", NotApplicable => "not_applicable",
    ClientStatus => "client_status", Other => "other"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UpdateStatus {
    Downloading,
    Downloaded,
    DownloadFailed,
    Installing,
    Installed,
    InstallFailed,
    RebootPending,
    Uninstalled,
    UninstallFailed,
    NotApplicable,
    /// From a client status inventory (`156`): evaluated and not installed.
    NotInstalled,
}
string_enum!(UpdateStatus {
    Downloading => "downloading", Downloaded => "downloaded", DownloadFailed => "download_failed",
    Installing => "installing", Installed => "installed", InstallFailed => "install_failed",
    RebootPending => "reboot_pending", Uninstalled => "uninstalled",
    UninstallFailed => "uninstall_failed", NotApplicable => "not_applicable",
    NotInstalled => "not_installed"
});

impl EventKind {
    fn derived(self) -> Option<UpdateStatus> {
        Some(match self {
            Self::DownloadStarted => UpdateStatus::Downloading,
            Self::DownloadCompleted => UpdateStatus::Downloaded,
            Self::DownloadFailed => UpdateStatus::DownloadFailed,
            Self::InstallStarted => UpdateStatus::Installing,
            Self::InstallSucceeded => UpdateStatus::Installed,
            Self::InstallFailed => UpdateStatus::InstallFailed,
            Self::RebootRequired => UpdateStatus::RebootPending,
            Self::UninstallSucceeded => UpdateStatus::Uninstalled,
            Self::UninstallFailed => UpdateStatus::UninstallFailed,
            Self::NotApplicable => UpdateStatus::NotApplicable,
            Self::ClientStatus | Self::Other => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    pub computer: ComputerId,
    pub update: Option<UpdateRevision>,
    pub kind: EventKind,
    /// Native result code (HRESULT or similar) as reported.
    pub result_code: Option<i64>,
    /// Client-reported event time (unix seconds).
    pub event_time: i64,
    /// Client-supplied identity of the event, when the protocol provides one. Events with
    /// the same (computer, key) are stored once.
    pub dedup_key: Option<String>,
    /// Raw payload as received, retained verbatim.
    pub raw: String,
}

/// The updates a client status event (`156`) lists, resolved to revisions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// The `V` list: evaluated installed.
    pub installed: Vec<UpdateRevision>,
    /// The `U` list: evaluated not installed.
    pub not_installed: Vec<UpdateRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    Recorded { event_id: i64 },
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub id: i64,
    pub event: NewEvent,
    pub received_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRecord {
    pub computer: ComputerId,
    pub update: UpdateRevision,
    pub status: UpdateStatus,
    pub result_code: Option<i64>,
    pub last_event_time: i64,
}

#[derive(Debug, Clone)]
pub struct Reporting {
    db: Database,
}

impl Reporting {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store a raw event and fold it into derived status. The event is persisted even if
    /// it does not change status. A status is only replaced by an event at least as new.
    pub fn record(&self, event: &NewEvent) -> Result<RecordOutcome> {
        self.record_with(event, None)
    }

    /// [`Reporting::record`] for a client status event (`156`): besides the raw event, every
    /// listed update gets `Installed` or `NotInstalled`, and a status that an EARLIER client status
    /// event derived for an update the new lists do not name is removed. This is what the real WSUS
    /// did with a native `156` (inventory 9.11, ledger C77 and C79): a new computer's per-update rows were
    /// exactly the listed ones (`U` NotInstalled, `V` Installed), a later event that listed fewer
    /// updates left only those rows, an unchanged row kept its change time, and the admin API read
    /// the update as Installed once it moved to `V`. Statuses derived from other events (a failure
    /// from `182`) are not removed; a status is only replaced by an event at least as new.
    pub fn record_inventory(
        &self,
        event: &NewEvent,
        inventory: &Inventory,
    ) -> Result<RecordOutcome> {
        self.record_with(event, Some(inventory))
    }

    fn record_with(
        &self,
        event: &NewEvent,
        inventory: Option<&Inventory>,
    ) -> Result<RecordOutcome> {
        self.db.transaction(|tx| {
            let cid = event.computer.0.to_string();
            let known: Option<i64> = tx
                .query_row("SELECT 1 FROM computers WHERE id=?1", [&cid], |r| r.get(0))
                .optional()?;
            if known.is_none() {
                return Err(Error::NotFound(format!("computer {}", event.computer.0)));
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO events(computer_id,update_id,revision,kind,result_code,\
                 event_time,received_at,dedup_key,raw) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    cid,
                    event.update.map(|u| u.id.0.to_string()),
                    event.update.map(|u| u.revision.0),
                    event.kind.as_str(),
                    event.result_code,
                    event.event_time,
                    now_unix(),
                    event.dedup_key,
                    event.raw
                ],
            )?;
            if inserted == 0 {
                return Ok(RecordOutcome::Duplicate);
            }
            let event_id = tx.last_insert_rowid();
            // `change_only`: a row whose status does not change keeps its time (inventory entries).
            let upsert =
                |update: UpdateRevision, status: UpdateStatus, change_only: bool| -> Result<()> {
                    tx.execute(
                    "INSERT INTO update_status(computer_id,update_id,revision,status,result_code,\
                     last_event_id,last_event_time) VALUES(?1,?2,?3,?4,?5,?6,?7) \
                     ON CONFLICT(computer_id,update_id,revision) DO UPDATE SET \
                       status=excluded.status, result_code=excluded.result_code, \
                       last_event_id=excluded.last_event_id, \
                       last_event_time=excluded.last_event_time \
                     WHERE excluded.last_event_time>=update_status.last_event_time \
                       AND (?8=0 OR update_status.status<>excluded.status)",
                    params![
                        cid,
                        update.id.0.to_string(),
                        update.revision.0,
                        status.as_str(),
                        event.result_code,
                        event_id,
                        event.event_time,
                        i64::from(change_only)
                    ],
                )?;
                    Ok(())
                };
            if let (Some(update), Some(status)) = (event.update, event.kind.derived()) {
                upsert(update, status, false)?;
            }
            if let Some(inv) = inventory {
                let mut listed = std::collections::BTreeSet::new();
                for (list, status) in [
                    (&inv.not_installed, UpdateStatus::NotInstalled),
                    (&inv.installed, UpdateStatus::Installed),
                ] {
                    for u in list {
                        // An update on both lists counts as installed (the later pass wins).
                        listed.insert(*u);
                        upsert(*u, status, true)?;
                    }
                }
                // Rows an earlier client status event derived for updates this one omits. (A row
                // that kept its status keeps its earlier event as `last_event_id`, so it is found
                // here too.)
                let mut st = tx.prepare(
                    "SELECT s.update_id,s.revision FROM update_status s \
                     JOIN events e ON e.id=s.last_event_id \
                     WHERE s.computer_id=?1 AND e.kind='client_status' AND s.last_event_id<>?2 \
                       AND s.last_event_time<=?3",
                )?;
                let rows = st
                    .query_map(params![cid, event_id, event.event_time], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                drop(st);
                for (uid, revision) in rows {
                    if !listed.contains(&UpdateRevision {
                        id: parse_update(&uid)?,
                        revision: Revision(revision),
                    }) {
                        tx.execute(
                            "DELETE FROM update_status WHERE computer_id=?1 AND update_id=?2 \
                             AND revision=?3",
                            params![cid, uid, revision],
                        )?;
                    }
                }
            }
            stamp_tx(tx, event.computer, "last_report")?;
            Ok(RecordOutcome::Recorded { event_id })
        })
    }

    pub fn events_for_computer(
        &self,
        computer: ComputerId,
        after_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<StoredEvent>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT id,update_id,revision,kind,result_code,event_time,received_at,dedup_key,raw \
                 FROM events WHERE computer_id=?1 AND id>?2 ORDER BY id LIMIT ?3",
            )?;
            let rows = st.query_map(
                params![computer.0.to_string(), after_id.unwrap_or(0), limit as i64],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<u32>>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, String>(8)?,
                    ))
                },
            )?;
            let mut out = Vec::new();
            for row in rows {
                let (id, uid, rev, kind, result_code, event_time, received_at, dedup_key, raw) = row?;
                let update = match (uid, rev) {
                    (Some(u), Some(r)) => Some(UpdateRevision {
                        id: parse_update(&u)?,
                        revision: Revision(r),
                    }),
                    _ => None,
                };
                out.push(StoredEvent {
                    id,
                    received_at,
                    event: NewEvent {
                        computer,
                        update,
                        kind: EventKind::parse(&kind)?,
                        result_code,
                        event_time,
                        dedup_key,
                        raw,
                    },
                });
            }
            Ok(out)
        })
    }

    pub fn status(
        &self,
        computer: ComputerId,
        update: UpdateRevision,
    ) -> Result<Option<StatusRecord>> {
        self.db.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT status,result_code,last_event_time FROM update_status \
                     WHERE computer_id=?1 AND update_id=?2 AND revision=?3",
                    params![
                        computer.0.to_string(),
                        update.id.0.to_string(),
                        update.revision.0
                    ],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Option<i64>>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            match row {
                Some((s, result_code, t)) => Ok(Some(StatusRecord {
                    computer,
                    update,
                    status: UpdateStatus::parse(&s)?,
                    result_code,
                    last_event_time: t,
                })),
                None => Ok(None),
            }
        })
    }

    /// Number of computers per derived status for an update (all revisions).
    pub fn status_counts(&self, update: UpdateId) -> Result<BTreeMap<UpdateStatus, u64>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT status,COUNT(*) FROM update_status WHERE update_id=?1 GROUP BY status",
            )?;
            let rows = st.query_map([update.0.to_string()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            let mut out = BTreeMap::new();
            for row in rows {
                let (s, n) = row?;
                out.insert(UpdateStatus::parse(&s)?, n as u64);
            }
            Ok(out)
        })
    }
}

fn parse_update(s: &str) -> Result<UpdateId> {
    Uuid::parse_str(s)
        .map(UpdateId)
        .map_err(|e| Error::Integrity(format!("stored update id invalid: {e}")))
}
