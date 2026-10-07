//! Computer registration records.
use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, GroupId};

use crate::policy::{UNASSIGNED_COMPUTERS, bump_policy_generation};
use crate::storage::{Database, Error, Result, now_unix};

/// Registration data supplied by the client. Unknown attributes go in `extra`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerDetails {
    pub dns_name: Option<String>,
    pub os_version: Option<String>,
    pub ip_address: Option<String>,
    pub client_version: Option<String>,
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Computer {
    pub id: ComputerId,
    pub registered_at: i64,
    pub last_contact: Option<i64>,
    pub last_sync: Option<i64>,
    pub last_report: Option<i64>,
    pub details: ComputerDetails,
    /// Client-requested target group name, kept as supplied.
    pub requested_group: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Computers {
    db: Database,
}

impl Computers {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Register or re-register a computer. New computers join the requested group when
    /// one exists with that exact name, otherwise `Unassigned Computers`. Existing
    /// computers keep their memberships; only details and contact time are refreshed.
    pub fn register(
        &self,
        id: ComputerId,
        details: &ComputerDetails,
        requested_group: Option<&str>,
    ) -> Result<Computer> {
        let json = serde_json::to_string(details)?;
        self.db.transaction(|tx| {
            let now = now_unix();
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM computers WHERE id=?1",
                    [id.0.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if existing.is_some() {
                tx.execute(
                    "UPDATE computers SET info=?2, requested_group=?3, last_contact=?4 WHERE id=?1",
                    params![id.0.to_string(), json, requested_group, now],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO computers(id,registered_at,last_contact,info,requested_group) \
                     VALUES(?1,?2,?2,?3,?4)",
                    params![id.0.to_string(), now, json, requested_group],
                )?;
                let target: Option<String> = match requested_group {
                    Some(name) => tx
                        .query_row(
                            "SELECT id FROM groups WHERE name=?1 AND id<>?2",
                            params![name, crate::policy::ALL_COMPUTERS.0.to_string()],
                            |r| r.get(0),
                        )
                        .optional()?,
                    None => None,
                };
                let group = target.unwrap_or_else(|| UNASSIGNED_COMPUTERS.0.to_string());
                tx.execute(
                    "INSERT INTO group_members(group_id,computer_id,added_at) VALUES(?1,?2,?3)",
                    params![group, id.0.to_string(), now],
                )?;
                bump_policy_generation(tx)?;
            }
            get_tx(tx, id)?.ok_or_else(|| Error::NotFound("computer".into()))
        })
    }

    pub fn get(&self, id: ComputerId) -> Result<Option<Computer>> {
        self.db.with_conn(|c| get_tx(c, id))
    }

    pub fn list(&self, after: Option<ComputerId>, limit: usize) -> Result<Vec<Computer>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare("SELECT id FROM computers WHERE id>?1 ORDER BY id LIMIT ?2")?;
            let ids: Vec<String> = st
                .query_map(
                    params![
                        after.map(|a| a.0.to_string()).unwrap_or_default(),
                        limit as i64
                    ],
                    |r| r.get(0),
                )?
                .collect::<std::result::Result<_, _>>()?;
            let mut out = Vec::new();
            for id in ids {
                if let Some(comp) = get_tx(c, parse_computer(&id)?)? {
                    out.push(comp);
                }
            }
            Ok(out)
        })
    }

    pub fn touch_contact(&self, id: ComputerId) -> Result<()> {
        self.stamp(id, "last_contact")
    }

    pub fn record_sync(&self, id: ComputerId) -> Result<()> {
        self.stamp(id, "last_sync")
    }

    pub(crate) fn stamp(&self, id: ComputerId, column: &'static str) -> Result<()> {
        self.db.transaction(|tx| stamp_tx(tx, id, column))
    }
}

pub(crate) fn stamp_tx(tx: &Transaction<'_>, id: ComputerId, column: &'static str) -> Result<()> {
    debug_assert!(matches!(
        column,
        "last_contact" | "last_sync" | "last_report"
    ));
    let now = now_unix();
    let n = tx.execute(
        &format!("UPDATE computers SET {column}=?2, last_contact=?2 WHERE id=?1"),
        params![id.0.to_string(), now],
    )?;
    if n == 0 {
        return Err(Error::NotFound(format!("computer {}", id.0)));
    }
    Ok(())
}

fn parse_computer(s: &str) -> Result<ComputerId> {
    Uuid::parse_str(s)
        .map(ComputerId)
        .map_err(|e| Error::Integrity(format!("stored computer id invalid: {e}")))
}

pub(crate) fn parse_group(s: &str) -> Result<GroupId> {
    Uuid::parse_str(s)
        .map(GroupId)
        .map_err(|e| Error::Integrity(format!("stored group id invalid: {e}")))
}

fn get_tx(c: &rusqlite::Connection, id: ComputerId) -> Result<Option<Computer>> {
    let row = c
        .query_row(
            "SELECT registered_at,last_contact,last_sync,last_report,info,requested_group \
             FROM computers WHERE id=?1",
            [id.0.to_string()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some((registered_at, last_contact, last_sync, last_report, info, requested_group)) => {
            Ok(Some(Computer {
                id,
                registered_at,
                last_contact,
                last_sync,
                last_report,
                details: serde_json::from_str(&info)?,
                requested_group,
            }))
        }
        None => Ok(None),
    }
}
