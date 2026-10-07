//! Groups, membership, approvals and deployments.
//!
//! Nothing is visible to a computer unless an active approval targets a group it belongs
//! to; there is no default publish-all. Every mutation commits in a transaction (and bumps
//! the policy generation) before it can be observed by any read.
use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, DeploymentId, GroupId, UpdateId};

use crate::computers::parse_group;
use crate::storage::{Database, Error, Result, bump_counter, now_unix, read_counter, string_enum};

/// Implicit group containing every registered computer.
pub const ALL_COMPUTERS: GroupId = GroupId(Uuid::from_u128(0xa0a08746_4dbe_4a37_9adf_9e7652c0b421));
/// Default group for newly registered computers.
pub const UNASSIGNED_COMPUTERS: GroupId =
    GroupId(Uuid::from_u128(0xb73ca6ed_5727_47f3_84de_015e03f6a88a));

const POLICY_GENERATION: &str = "policy_generation";

pub(crate) fn bump_policy_generation(tx: &Transaction<'_>) -> Result<i64> {
    bump_counter(tx, POLICY_GENERATION)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeploymentAction {
    Install,
    Uninstall,
}
string_enum!(DeploymentAction { Install => "install", Uninstall => "uninstall" });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalState {
    Active,
    Withdrawn,
}
string_enum!(ApprovalState { Active => "active", Withdrawn => "withdrawn" });

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    pub description: String,
    pub builtin: bool,
}

/// An approval of an update for a group. This is also the deployment record: the
/// `DeploymentId` identifies it and `deadline` (unix seconds) is the install deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub id: DeploymentId,
    pub update: UpdateId,
    pub group: GroupId,
    pub action: DeploymentAction,
    pub deadline: Option<i64>,
    pub state: ApprovalState,
    pub created_at: i64,
    pub withdrawn_at: Option<i64>,
}

/// What a computer is entitled to see for one update after merging its groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleUpdate {
    pub update: UpdateId,
    pub action: DeploymentAction,
    /// Earliest deadline among the matching approvals.
    pub deadline: Option<i64>,
    pub approvals: Vec<DeploymentId>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    db: Database,
}

impl Policy {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Monotonic counter bumped by every policy change; endpoints can bind cookies or
    /// cached scopes to it.
    pub fn generation(&self) -> Result<i64> {
        self.db.with_conn(|c| read_counter(c, POLICY_GENERATION))
    }

    // ---- groups ----

    pub fn create_group(&self, name: &str, description: &str) -> Result<GroupId> {
        if name.trim().is_empty() {
            return Err(Error::Invalid("group name is empty".into()));
        }
        self.db.transaction(|tx| {
            let id = GroupId(Uuid::new_v4());
            let n = tx.execute(
                "INSERT OR IGNORE INTO groups(id,name,description,builtin,created_at) \
                 VALUES(?1,?2,?3,0,?4)",
                params![id.0.to_string(), name, description, now_unix()],
            )?;
            if n == 0 {
                return Err(Error::Conflict(format!("group {name} already exists")));
            }
            bump_policy_generation(tx)?;
            Ok(id)
        })
    }

    pub fn delete_group(&self, id: GroupId) -> Result<()> {
        self.db.transaction(|tx| {
            let group = get_group(tx, id)?.ok_or_else(|| Error::NotFound("group".into()))?;
            if group.builtin {
                return Err(Error::Invalid("built-in groups cannot be deleted".into()));
            }
            let any: i64 = tx.query_row(
                "SELECT COUNT(*) FROM approvals WHERE group_id=?1",
                [id.0.to_string()],
                |r| r.get(0),
            )?;
            if any > 0 {
                return Err(Error::Conflict(
                    "group has approvals or approval history".into(),
                ));
            }
            tx.execute("DELETE FROM groups WHERE id=?1", [id.0.to_string()])?;
            bump_policy_generation(tx)?;
            Ok(())
        })
    }

    pub fn group(&self, id: GroupId) -> Result<Option<Group>> {
        self.db.with_conn(|c| get_group(c, id))
    }

    pub fn group_by_name(&self, name: &str) -> Result<Option<Group>> {
        self.db.with_conn(|c| {
            let id: Option<String> = c
                .query_row("SELECT id FROM groups WHERE name=?1", [name], |r| r.get(0))
                .optional()?;
            match id {
                Some(id) => get_group(c, parse_group(&id)?),
                None => Ok(None),
            }
        })
    }

    pub fn groups(&self) -> Result<Vec<Group>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare("SELECT id FROM groups ORDER BY name")?;
            let ids: Vec<String> = st
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            let mut out = Vec::new();
            for id in ids {
                if let Some(g) = get_group(c, parse_group(&id)?)? {
                    out.push(g);
                }
            }
            Ok(out)
        })
    }

    // ---- membership ----

    pub fn add_member(&self, group: GroupId, computer: ComputerId) -> Result<()> {
        if group == ALL_COMPUTERS {
            return Err(Error::Invalid(
                "All Computers membership is implicit".into(),
            ));
        }
        self.db.transaction(|tx| {
            if get_group(tx, group)?.is_none() {
                return Err(Error::NotFound("group".into()));
            }
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM computers WHERE id=?1",
                    [computer.0.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(Error::NotFound(format!("computer {}", computer.0)));
            }
            tx.execute(
                "INSERT OR IGNORE INTO group_members(group_id,computer_id,added_at) VALUES(?1,?2,?3)",
                params![group.0.to_string(), computer.0.to_string(), now_unix()],
            )?;
            bump_policy_generation(tx)?;
            Ok(())
        })
    }

    pub fn remove_member(&self, group: GroupId, computer: ComputerId) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute(
                "DELETE FROM group_members WHERE group_id=?1 AND computer_id=?2",
                params![group.0.to_string(), computer.0.to_string()],
            )?;
            bump_policy_generation(tx)?;
            Ok(())
        })
    }

    /// Explicit groups of a computer plus the implicit `All Computers`.
    pub fn groups_of(&self, computer: ComputerId) -> Result<Vec<GroupId>> {
        self.db.with_conn(|c| groups_of_conn(c, computer))
    }

    pub fn members(&self, group: GroupId) -> Result<Vec<ComputerId>> {
        self.db.with_conn(|c| {
            let sql = if group == ALL_COMPUTERS {
                "SELECT id FROM computers ORDER BY id"
            } else {
                "SELECT computer_id FROM group_members WHERE group_id=?1 ORDER BY computer_id"
            };
            let mut st = c.prepare(sql)?;
            let rows = if group == ALL_COMPUTERS {
                st.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            } else {
                st.query_map([group.0.to_string()], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            };
            rows.into_iter()
                .map(|s| {
                    Uuid::parse_str(&s)
                        .map(ComputerId)
                        .map_err(|e| Error::Integrity(e.to_string()))
                })
                .collect()
        })
    }

    // ---- approvals ----

    /// Approve `update` for `group`. Re-approving with the same action updates the
    /// deadline of the existing active approval. Declined updates cannot be approved.
    pub fn approve(
        &self,
        update: UpdateId,
        group: GroupId,
        action: DeploymentAction,
        deadline: Option<i64>,
    ) -> Result<Approval> {
        self.db.transaction(|tx| {
            if get_group(tx, group)?.is_none() {
                return Err(Error::NotFound("group".into()));
            }
            let declined: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM declined_updates WHERE update_id=?1",
                    [update.0.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if declined.is_some() {
                return Err(Error::Conflict("update is declined".into()));
            }
            let existing: Option<String> = tx
                .query_row(
                    "SELECT id FROM approvals WHERE update_id=?1 AND group_id=?2 AND action=?3 \
                     AND state='active'",
                    params![update.0.to_string(), group.0.to_string(), action.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let id = match existing {
                Some(id) => {
                    tx.execute(
                        "UPDATE approvals SET deadline=?2 WHERE id=?1",
                        params![id, deadline],
                    )?;
                    id
                }
                None => {
                    let id = Uuid::new_v4().to_string();
                    tx.execute(
                        "INSERT INTO approvals(id,update_id,group_id,action,deadline,state,created_at) \
                         VALUES(?1,?2,?3,?4,?5,'active',?6)",
                        params![
                            id,
                            update.0.to_string(),
                            group.0.to_string(),
                            action.as_str(),
                            deadline,
                            now_unix()
                        ],
                    )?;
                    id
                }
            };
            bump_policy_generation(tx)?;
            get_approval(tx, &id)?.ok_or_else(|| Error::NotFound("approval".into()))
        })
    }

    pub fn withdraw(&self, id: DeploymentId) -> Result<()> {
        self.db.transaction(|tx| {
            let n = tx.execute(
                "UPDATE approvals SET state='withdrawn', withdrawn_at=?2 WHERE id=?1 AND state='active'",
                params![id.0.to_string(), now_unix()],
            )?;
            if n == 0 {
                return Err(Error::NotFound(format!("active approval {}", id.0)));
            }
            bump_policy_generation(tx)?;
            Ok(())
        })
    }

    /// Decline an update everywhere: active approvals are withdrawn and new ones refused.
    pub fn decline(&self, update: UpdateId) -> Result<()> {
        self.db.transaction(|tx| {
            let now = now_unix();
            tx.execute(
                "INSERT OR IGNORE INTO declined_updates(update_id,declined_at) VALUES(?1,?2)",
                params![update.0.to_string(), now],
            )?;
            tx.execute(
                "UPDATE approvals SET state='withdrawn', withdrawn_at=?2 WHERE update_id=?1 \
                 AND state='active'",
                params![update.0.to_string(), now],
            )?;
            bump_policy_generation(tx)?;
            Ok(())
        })
    }

    pub fn undecline(&self, update: UpdateId) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute(
                "DELETE FROM declined_updates WHERE update_id=?1",
                [update.0.to_string()],
            )?;
            bump_policy_generation(tx)?;
            Ok(())
        })
    }

    /// Every declined update id.
    pub fn declined_updates(&self) -> Result<Vec<UpdateId>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare("SELECT update_id FROM declined_updates ORDER BY update_id")?;
            let rows = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|u| {
                    Uuid::parse_str(&u)
                        .map(UpdateId)
                        .map_err(|e| Error::Integrity(e.to_string()))
                })
                .collect()
        })
    }

    pub fn is_declined(&self, update: UpdateId) -> Result<bool> {
        self.db.with_conn(|c| {
            Ok(c.query_row(
                "SELECT 1 FROM declined_updates WHERE update_id=?1",
                [update.0.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
        })
    }

    pub fn approval(&self, id: DeploymentId) -> Result<Option<Approval>> {
        self.db.with_conn(|c| get_approval(c, &id.0.to_string()))
    }

    pub fn approvals_for_update(&self, update: UpdateId) -> Result<Vec<Approval>> {
        self.approvals_where("update_id=?1", &update.0.to_string())
    }

    pub fn approvals_for_group(&self, group: GroupId) -> Result<Vec<Approval>> {
        self.approvals_where("group_id=?1", &group.0.to_string())
    }

    fn approvals_where(&self, clause: &str, arg: &str) -> Result<Vec<Approval>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(&format!(
                "SELECT id FROM approvals WHERE {clause} ORDER BY created_at,id"
            ))?;
            let ids: Vec<String> = st
                .query_map([arg], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            let mut out = Vec::new();
            for id in ids {
                if let Some(a) = get_approval(c, &id)? {
                    out.push(a);
                }
            }
            Ok(out)
        })
    }

    // ---- scoping ----

    /// Updates a computer may see: active approvals on any of its groups, merged per
    /// (update, action), excluding declined updates. Unregistered computers see nothing.
    pub fn visible_to(&self, computer: ComputerId) -> Result<Vec<VisibleUpdate>> {
        self.db.with_conn(|c| {
            let groups = groups_of_conn(c, computer)?;
            let mut merged: BTreeMap<(String, DeploymentAction), VisibleUpdate> = BTreeMap::new();
            for g in groups {
                let mut st = c.prepare(
                    "SELECT a.id,a.update_id,a.action,a.deadline FROM approvals a \
                     WHERE a.group_id=?1 AND a.state='active' AND NOT EXISTS \
                     (SELECT 1 FROM declined_updates d WHERE d.update_id=a.update_id)",
                )?;
                let rows = st.query_map([g.0.to_string()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                })?;
                for row in rows {
                    let (id, update, action, deadline) = row?;
                    let action = DeploymentAction::parse(&action)?;
                    let update_id = Uuid::parse_str(&update)
                        .map(UpdateId)
                        .map_err(|e| Error::Integrity(e.to_string()))?;
                    let dep = DeploymentId(
                        Uuid::parse_str(&id).map_err(|e| Error::Integrity(e.to_string()))?,
                    );
                    let entry = merged
                        .entry((update, action))
                        .or_insert_with(|| VisibleUpdate {
                            update: update_id,
                            action,
                            deadline,
                            approvals: Vec::new(),
                        });
                    entry.deadline = match (entry.deadline, deadline) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                    entry.approvals.push(dep);
                }
            }
            Ok(merged.into_values().collect())
        })
    }

    pub fn is_visible(&self, computer: ComputerId, update: UpdateId) -> Result<bool> {
        Ok(self
            .visible_to(computer)?
            .iter()
            .any(|v| v.update == update))
    }
}

fn groups_of_conn(c: &rusqlite::Connection, computer: ComputerId) -> Result<Vec<GroupId>> {
    let registered: Option<i64> = c
        .query_row(
            "SELECT 1 FROM computers WHERE id=?1",
            [computer.0.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if registered.is_none() {
        return Ok(Vec::new());
    }
    let mut st =
        c.prepare("SELECT group_id FROM group_members WHERE computer_id=?1 ORDER BY group_id")?;
    let ids: Vec<String> = st
        .query_map([computer.0.to_string()], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    let mut out = vec![ALL_COMPUTERS];
    for id in ids {
        out.push(parse_group(&id)?);
    }
    Ok(out)
}

fn get_group(c: &rusqlite::Connection, id: GroupId) -> Result<Option<Group>> {
    Ok(c.query_row(
        "SELECT name,description,builtin FROM groups WHERE id=?1",
        [id.0.to_string()],
        |r| {
            Ok(Group {
                id,
                name: r.get(0)?,
                description: r.get(1)?,
                builtin: r.get::<_, i64>(2)? != 0,
            })
        },
    )
    .optional()?)
}

fn get_approval(c: &rusqlite::Connection, id: &str) -> Result<Option<Approval>> {
    let row = c
        .query_row(
            "SELECT update_id,group_id,action,deadline,state,created_at,withdrawn_at \
             FROM approvals WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((update, group, action, deadline, state, created_at, withdrawn_at)) = row else {
        return Ok(None);
    };
    let bad = |e: uuid::Error| Error::Integrity(e.to_string());
    Ok(Some(Approval {
        id: DeploymentId(Uuid::parse_str(id).map_err(bad)?),
        update: UpdateId(Uuid::parse_str(&update).map_err(bad)?),
        group: parse_group(&group)?,
        action: DeploymentAction::parse(&action)?,
        deadline,
        state: ApprovalState::parse(&state)?,
        created_at,
        withdrawn_at,
    }))
}
