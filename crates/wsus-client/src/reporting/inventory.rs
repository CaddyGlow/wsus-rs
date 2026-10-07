//! The client status event `156` ("Reporting client status"): the lists of updates the client
//! evaluates as not installed (`U`) and installed (`V`).
//!
//! Evidence (inventory 9.11, `docs/wsus-validation.md` C77 and C78): on the real WSUS the installed and
//! not-installed state of an update for a computer comes from this event, not from the install
//! events `181`, `183` or `201`. A native Windows Update Agent sends it next to `147` after a scan
//! that reached the server, namespace 1, source 101, the zero update id at revision 0, an empty
//! `PrivateData`, and in `MiscData` (a list of `Key=Value` strings) `U=<ids>` and `V=<ids>`: the
//! update ids (not revision ids) of the LEAF software updates, upper case, joined by `;`, one string
//! per list, the key omitted when the list is empty. The sizes of the lists equalled the server's
//! `NotInstalled` and `Installed` counts for the computer.
//!
//! This module builds the same event from this client's own applicability evaluation
//! ([`evaluate_inventory`]) and queues it through the durable queue. Not observed from a native
//! agent: a list too long for one string (the largest seen has 39 ids, 1.4 KB), so no chunking is
//! done; a list that does not fit the queue's payload limit is refused.

use crate::{
    install::{
        job::PostCheck,
        plan::{NodeStatus, PlanOptions, Planner},
    },
    reporting::{AppendOutcome, EventQueue, QueueError},
    state::atomic,
    sync::{Catalog, EventDetail, ReportEvent, SyncError},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use wsus_protocol::{
    applicability::FactProvider,
    identity::{Revision, UpdateId, UpdateRevision},
};

use super::install_events::{CLIENT_AGENT_SOURCE, CLIENT_NAMESPACE, reported_update};

/// `EventID` of the client status event (`Reporting client status`).
pub const CLIENT_STATUS: i16 = 156;
/// Name of the file (in the queue directory) that remembers the last queued inventory.
const LAST_FILE: &str = "inventory.last";

/// The evaluator's verdicts for the updates in scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Applicable and not installed (`U`), sorted.
    pub not_installed: Vec<UpdateId>,
    /// Evaluated installed (`V`), sorted.
    pub installed: Vec<UpdateId>,
    /// Updates in scope that are neither (not applicable, superseded or not decidable); not sent.
    pub left_out: usize,
    /// Of `left_out`, the ones whose verdict is Unknown (a missing fact), never guessed.
    pub unknown: usize,
}

impl Inventory {
    /// Digest of both lists, the identity of the inventory.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        for (tag, list) in [("U", &self.not_installed), ("V", &self.installed)] {
            h.update(tag.as_bytes());
            for id in list {
                h.update(id.0.as_bytes());
            }
        }
        crate::download::hex_encode(&h.finalize())
    }

    /// The `MiscData` strings `U=...` and `V=...` (an empty list has no entry).
    pub fn misc_lists(&self) -> Vec<String> {
        let join = |ids: &[UpdateId]| {
            ids.iter()
                .map(|i| i.0.hyphenated().to_string().to_uppercase())
                .collect::<Vec<_>>()
                .join(";")
        };
        let mut misc = Vec::new();
        if !self.not_installed.is_empty() {
            misc.push(format!("U={}", join(&self.not_installed)));
        }
        if !self.installed.is_empty() {
            misc.push(format!("V={}", join(&self.installed)));
        }
        misc
    }
}

/// Updates in scope: the latest revision of every leaf software update of the catalog that carries
/// a deployment of its own and is not delivered as `Bundle`. Measured against one native agent on one
/// machine (ledger C77): of the 1,102 leaf software revisions this client's catalog held, the 57 the
/// native lists named that the catalog also held had `Install` or `PreDeploymentCheck` deployments,
/// and none of the 564 `Bundle` deployments (the updates other deployed updates bundle) was listed,
/// installed or not.
pub fn inventory_scope(catalog: &Catalog) -> Vec<UpdateRevision> {
    catalog
        .revisions()
        .filter(|r| catalog.latest_revision(r.id) == Some(**r))
        .filter(|r| {
            catalog.get(r).is_some_and(|e| {
                e.record.is_leaf
                    && e.record.update_type.as_deref() == Some("Software")
                    && e.record
                        .deployment
                        .as_ref()
                        .is_some_and(|d| d.action != "Bundle")
            })
        })
        .copied()
        .collect()
}

/// Which updates supersede which (latest revisions only), with the installed verdict of each
/// superseding update evaluated at most once.
struct Supersedence {
    by: BTreeMap<UpdateId, Vec<UpdateRevision>>,
    installed: BTreeMap<UpdateId, bool>,
}

impl Supersedence {
    fn new(catalog: &Catalog) -> Self {
        let mut by: BTreeMap<UpdateId, Vec<UpdateRevision>> = BTreeMap::new();
        for r in catalog.revisions() {
            if catalog.latest_revision(r.id) != Some(*r) {
                continue;
            }
            if let Some(e) = catalog.get(r) {
                for s in &e.index.superseded {
                    if *s != r.id {
                        by.entry(*s).or_default().push(*r);
                    }
                }
            }
        }
        Self {
            by,
            installed: BTreeMap::new(),
        }
    }

    /// Does any update that supersedes `id` evaluate installed (the planner's verdict, like the
    /// verdicts of the lists themselves)?
    fn installed_superseder(&mut self, planner: &mut Planner<'_>, id: UpdateId) -> bool {
        let Some(list) = self.by.get(&id) else {
            return false;
        };
        for r in list.clone() {
            let installed = *self
                .installed
                .entry(r.id)
                .or_insert_with(|| planner.verdict(r).0 == NodeStatus::AlreadyInstalled);
            if installed {
                return true;
            }
        }
        false
    }
}

/// Evaluates every update in scope against `facts` (the planner's verdict, the same as
/// `client scan`): `Install` is not installed, `AlreadyInstalled` is installed, anything else is
/// left out. `post_check` is the finished job's own re-evaluation: an update it lists as installed
/// is reported installed, one it lists as not installed (an install waiting for a restart) is
/// reported not installed, whatever the live facts say; its entries name steps, which are mapped to
/// the deployed update they are reported under.
pub fn evaluate_inventory(
    catalog: &Catalog,
    facts: &dyn FactProvider,
    opts: &PlanOptions,
    post_check: Option<&PostCheck>,
) -> Inventory {
    let mut planner = Planner::new(catalog, facts, opts.clone());
    let mut forced: BTreeMap<UpdateId, bool> = BTreeMap::new();
    if let Some(pc) = post_check.filter(|p| p.performed) {
        let parse = |s: &str| {
            let (id, rev) = s.split_once('@')?;
            Some(UpdateRevision {
                id: UpdateId(Uuid::parse_str(id).ok()?),
                revision: Revision(rev.parse().ok()?),
            })
        };
        for (list, installed) in [(&pc.installed, true), (&pc.not_installed, false)] {
            for step in list.iter().filter_map(|s| parse(s)) {
                let root = reported_update(catalog, step).id;
                let e = forced.entry(root).or_insert(installed);
                *e = *e && installed;
            }
        }
    }
    let mut supersedence = Supersedence::new(catalog);
    let mut inv = Inventory::default();
    for rev in inventory_scope(catalog) {
        if let Some(installed) = forced.get(&rev.id) {
            if *installed {
                inv.installed.push(rev.id);
            } else {
                inv.not_installed.push(rev.id);
            }
            continue;
        }
        match planner.verdict(rev).0 {
            NodeStatus::Install => inv.not_installed.push(rev.id),
            // An installed update that an installed update supersedes was in neither native list
            // (108 of the 110 installed older cumulative updates the planner listed were absent).
            NodeStatus::AlreadyInstalled
                if supersedence.installed_superseder(&mut planner, rev.id) =>
            {
                inv.left_out += 1
            }
            NodeStatus::AlreadyInstalled => inv.installed.push(rev.id),
            NodeStatus::Unknown => {
                inv.left_out += 1;
                inv.unknown += 1;
            }
            NodeStatus::NotApplicable | NodeStatus::Superseded => inv.left_out += 1,
        }
    }
    inv.not_installed.sort();
    inv.installed.sort();
    inv
}

/// The event of an inventory. The update is the zero id at revision 0, as every native event
/// without an update carries.
pub fn inventory_event(inv: &Inventory, at: &str, app_name: &str, instance: Uuid) -> ReportEvent {
    let mut misc = inv.misc_lists();
    misc.push(format!("AppName={app_name}"));
    ReportEvent {
        event_instance_id: instance,
        sequence_number: 0,
        time_at_target: at.to_owned(),
        namespace_id: CLIENT_NAMESPACE,
        event_id: CLIENT_STATUS,
        source_id: CLIENT_AGENT_SOURCE,
        update: Some(UpdateRevision {
            id: UpdateId(Uuid::nil()),
            revision: Revision(0),
        }),
        win32_hresult: 0,
        app_name: Some(app_name.to_owned()),
        detail: Some(EventDetail {
            replacement_strings: Vec::new(),
            misc_data: misc,
        }),
    }
}

fn instance_id(digest: &str, epoch: u64) -> Uuid {
    let d = Sha256::digest(format!("wsus-client-inventory-event|{digest}|{epoch}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&d[..16]);
    bytes[6] = (bytes[6] & 0x0F) | 0x50;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(bytes)
}

/// What [`queue_inventory`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryQueued {
    /// A new event was queued.
    Queued { instance_id: Uuid },
    /// The same inventory is what was last queued (pending or already delivered): nothing queued.
    Unchanged { instance_id: Uuid },
}

/// Errors of [`queue_inventory`].
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    #[error("inventory memory I/O failure")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Queue(#[from] QueueError),
}

fn last_path(dir: &Path) -> PathBuf {
    dir.join(LAST_FILE)
}

fn read_last(dir: &Path) -> Option<(String, u64)> {
    let text = std::fs::read_to_string(last_path(dir)).ok()?;
    let (digest, epoch) = text.trim().split_once(' ')?;
    Some((digest.to_owned(), epoch.parse().ok()?))
}

/// Queues the inventory event, de-duplicated. The instance id derives from the digest of the lists
/// and an epoch that advances only when the lists change (remembered in `dir`, the queue's
/// directory), so an unchanged inventory is queued once however often it is evaluated, and a return
/// to an earlier inventory (installed, removed, installed again) is a new event. `force` queues a
/// fresh event even when nothing changed (an explicit `client report --inventory --force`).
pub fn queue_inventory(
    queue: &mut EventQueue,
    dir: &Path,
    inv: &Inventory,
    at: &str,
    app_name: &str,
    force: bool,
) -> Result<InventoryQueued, InventoryError> {
    let digest = inv.digest();
    let (epoch, same) = match read_last(dir) {
        Some((d, e)) if d == digest && force => (e + 1, false),
        Some((d, e)) if d == digest => (e, true),
        Some((_, e)) => (e + 1, false),
        None => (1, false),
    };
    let id = instance_id(&digest, epoch);
    if same {
        return Ok(InventoryQueued::Unchanged { instance_id: id });
    }
    let event = inventory_event(inv, at, app_name, id);
    match event.enqueue(queue)? {
        AppendOutcome::Queued { .. } => {
            atomic::atomic_write(&last_path(dir), format!("{digest} {epoch}\n").as_bytes())?;
            Ok(InventoryQueued::Queued { instance_id: id })
        }
        AppendOutcome::Duplicate { .. } | AppendOutcome::AlreadyDelivered => {
            Ok(InventoryQueued::Unchanged { instance_id: id })
        }
    }
}
