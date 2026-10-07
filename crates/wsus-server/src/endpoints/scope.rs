//! What one computer may see: policy scope plus the prerequisite closure.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use wsus_protocol::identity::{FileDigest, UpdateId};

use crate::catalog::{FileDescriptor, FragmentRecord, FragmentState, RelationshipKind, Snapshot};
use crate::policy::{Policy, VisibleUpdate};
use crate::storage::Result;
use wsus_protocol::identity::{ComputerId, DigestAlgorithm};

/// One update (its newest revision) that is in scope for a computer.
#[derive(Debug, Clone)]
pub(crate) struct ScopedUpdate {
    pub record: FragmentRecord,
    /// False when another in-scope update lists this one as a prerequisite or bundle member.
    pub is_leaf: bool,
    /// Present only for updates approved for the computer; prerequisite-only metadata
    /// carries no deployment.
    pub deployment: Option<VisibleUpdate>,
    /// True when another in-scope update lists this one as a bundle member. A real WSUS marks
    /// such revisions `Action=Bundle` (Observed 2026-10-04: 86 of 159 deployments).
    pub bundled: bool,
    /// The update's `Properties/@UpdateType` is `Software`. Set only by the `all_non_declined`
    /// scope (the approved scope keeps its `Evaluate` and `Bundle` rule and never emits
    /// `PreDeploymentCheck`).
    pub software: bool,
    /// `record` carries no XML (the `all_non_declined` scope holds a whole Windows catalog);
    /// load the full record with [`ScopedUpdate::full`] before reading it.
    pub light: bool,
    /// Prerequisite clauses computed while the XML was in memory (light records only).
    pub clauses: Option<Arc<Vec<Clause>>>,
}

impl ScopedUpdate {
    /// The record with its XML: borrowed when it is already complete, read from the snapshot
    /// for light records.
    pub fn full(&self, snapshot: &Snapshot) -> Result<std::borrow::Cow<'_, FragmentRecord>> {
        if !self.light {
            return Ok(std::borrow::Cow::Borrowed(&self.record));
        }
        snapshot
            .get_local(self.record.local)?
            .map(std::borrow::Cow::Owned)
            .ok_or_else(|| {
                crate::storage::Error::NotFound(format!("revision {}", self.record.local.id))
            })
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    /// Ordered by local revision id.
    pub updates: Vec<ScopedUpdate>,
}

impl Scope {
    pub fn by_local(&self, id: i32) -> Option<&ScopedUpdate> {
        self.updates.iter().find(|u| u.record.local.id == id)
    }

    pub fn local_ids(&self) -> BTreeSet<i32> {
        self.updates.iter().map(|u| u.record.local.id).collect()
    }

    /// Descriptor of the in-scope file with this SHA-1, if any (lowest local id first).
    pub fn file_by_sha1(&self, snapshot: &Snapshot, sha1: &[u8]) -> Result<Option<FileDescriptor>> {
        for local in snapshot.locals_with_sha1(sha1)? {
            let Some(u) = self.by_local(local) else {
                continue;
            };
            for f in snapshot.files(u.record.local)? {
                if f.digests.iter().any(|d| is_sha1(d, sha1)) {
                    return Ok(Some(f));
                }
            }
        }
        Ok(None)
    }
}

fn is_sha1(d: &FileDigest, bytes: &[u8]) -> bool {
    d.algorithm == DigestAlgorithm::Sha1 && d.bytes == bytes
}

/// Compute the scope: approved updates for `computer`, closed over prerequisite and bundle
/// edges, keeping only the newest revision of each update and only if it is `Present`.
pub(crate) fn compute(snapshot: &Snapshot, policy: &Policy, computer: ComputerId) -> Result<Scope> {
    let mut approved: BTreeMap<UpdateId, VisibleUpdate> = BTreeMap::new();
    for v in policy.visible_to(computer)? {
        // `visible_to` orders Install before Uninstall; the first action wins.
        approved.entry(v.update).or_insert(v);
    }
    if approved.is_empty() {
        return Ok(Scope::default());
    }
    let roots: Vec<UpdateId> = approved.keys().copied().collect();
    let closure = snapshot.closure(&roots)?;
    let mut newest: BTreeMap<UpdateId, FragmentRecord> = BTreeMap::new();
    for f in closure {
        match newest.get(&f.identity.id) {
            Some(cur) if cur.identity.revision >= f.identity.revision => {}
            _ => {
                newest.insert(f.identity.id, f);
            }
        }
    }
    newest.retain(|_, f| f.state == FragmentState::Present);
    // `IsLeaf` is false exactly for updates that are a prerequisite of something in the whole
    // catalog generation, not just in this client's scope, and bundle members are leaves
    // (Observed on a real WSUS, 2026-10-04: all 86 `Bundle` deployments are leaves, and the 476
    // distinct prerequisite targets are all non-leaf). Marking bundle members non-leaf made a
    // native Windows Update Agent report only 2 non-leaf updates installed and evaluate 5 of
    // 442 delivered entities.
    let non_leaf: BTreeSet<UpdateId> = snapshot.prerequisite_targets()?;
    let mut bundle_members: BTreeSet<UpdateId> = BTreeSet::new();
    for f in newest.values() {
        for r in snapshot.relationships(f.local)? {
            if r.kind == RelationshipKind::Bundle {
                bundle_members.insert(r.target);
            }
        }
    }
    let mut updates: Vec<ScopedUpdate> = newest
        .into_iter()
        .map(|(id, record)| ScopedUpdate {
            is_leaf: !non_leaf.contains(&id),
            bundled: bundle_members.contains(&id),
            deployment: approved.get(&id).cloned(),
            record,
            software: false,
            light: false,
            clauses: None,
        })
        .collect();
    updates.sort_by_key(|u| u.record.local.id);
    Ok(Scope { updates })
}

// ---- prerequisite clauses and staged selection -------------------------------------

/// One AND-clause of a prerequisite CNF: satisfied when at least one alternative update is
/// installed. A bare `UpdateIdentity` is a clause of one; `AtLeastOne` (category or not) is a
/// clause of its members.
pub(crate) type Clause = Vec<UpdateId>;

/// Parsed clauses per (generation, local revision id). Local ids are never reused and a
/// generation is immutable, so entries never go stale; the map is cleared when it grows large.
type ClauseMap = HashMap<(i64, i32), Arc<Vec<Clause>>>;

#[derive(Debug, Default)]
pub(crate) struct ClauseCache(Mutex<ClauseMap>);

const CLAUSE_CACHE_LIMIT: usize = 200_000;

/// Prerequisite CNF of a record, parsed from its Core slot (a whole update document or a WUSP
/// fragment sequence), which keeps the AND-of-ORs structure. The `relationships` table
/// flattens it (and prunes alternatives unknown at import), so it is used only as a fallback
/// when the stored XML carries no `Prerequisites` or cannot be parsed (synthetic catalogs
/// that store opaque XML and declare prerequisites through the table): each `prerequisite` or
/// `category` row is then a clause of one.
pub(crate) fn clauses(
    cache: &ClauseCache,
    snapshot: &Snapshot,
    record: &FragmentRecord,
) -> Result<Arc<Vec<Clause>>> {
    let key = (snapshot.generation().0, record.local.id);
    if let Some(hit) = cache.0.lock().expect("clause cache").get(&key) {
        return Ok(hit.clone());
    }
    let clauses = match parse_clauses(record) {
        Some(c) => c,
        None => relationship_clauses(&snapshot.relationships(record.local)?),
    };
    let arc = Arc::new(clauses);
    let mut map = cache.0.lock().expect("clause cache");
    if map.len() >= CLAUSE_CACHE_LIMIT {
        map.clear();
    }
    map.insert(key, arc.clone());
    Ok(arc)
}

/// Prerequisite clauses from the stored Core XML, `None` when it carries none or cannot be parsed.
fn parse_clauses(record: &FragmentRecord) -> Option<Vec<Clause>> {
    wsus_protocol::metadata::FragmentIndex::parse(
        &record.core_xml,
        &wsus_protocol::soap::Limits::stored_documents(),
    )
    .ok()
    .map(|i| {
        i.prerequisites
            .into_iter()
            .map(|c| c.update_ids)
            .collect::<Vec<Clause>>()
    })
    .filter(|c| !c.is_empty())
}

fn relationship_clauses(rels: &[crate::catalog::Relationship]) -> Vec<Clause> {
    rels.iter()
        .filter(|r| {
            matches!(
                r.kind,
                RelationshipKind::Prerequisite | RelationshipKind::Category
            )
        })
        .map(|r| vec![r.target])
        .collect()
}

/// What a staged `SyncUpdates` call answers.
#[derive(Debug, Default)]
pub(crate) struct Staged {
    /// Indices into `Scope::updates`, in delivery order (non-leaf first, then by local id).
    pub deliverable: Vec<usize>,
    /// Cached ids the server no longer considers valid for this client.
    pub out_of_scope: Vec<i32>,
    /// In-scope updates that are cached and whose clauses are satisfied, for deployment
    /// change reporting.
    pub held: BTreeSet<i32>,
}

/// Staged selection (inventory 5.3, 9.3): a revision is deliverable when it is not cached and
/// every prerequisite clause has an alternative among the in-scope updates whose server-local
/// id is in `installed`. Only the newest in-scope revision of an update can satisfy a clause
/// (a clause names an update id, which "implicitly means the highest revision", MS-WUSP
/// 3.1.1.1).
pub(crate) fn staged(
    cache: &ClauseCache,
    snapshot: &Snapshot,
    scope: &Scope,
    installed: &[i32],
    other: &[i32],
    out_of_scope_unsatisfied: bool,
) -> Result<Staged> {
    let installed_updates: BTreeSet<UpdateId> = installed
        .iter()
        .filter_map(|id| scope.by_local(*id))
        .map(|u| u.record.identity.id)
        .collect();
    let cached: BTreeSet<i32> = installed.iter().chain(other.iter()).copied().collect();
    let in_scope = scope.local_ids();
    let scope_updates: BTreeSet<UpdateId> =
        scope.updates.iter().map(|u| u.record.identity.id).collect();
    let mut out: BTreeSet<i32> = cached.difference(&in_scope).copied().collect();
    let mut deliverable = Vec::new();
    let mut held = BTreeSet::new();
    for (idx, u) in scope.updates.iter().enumerate() {
        let own = match &u.clauses {
            Some(c) => c.clone(),
            None => clauses(cache, snapshot, &u.record)?,
        };
        let satisfied = own.iter().all(|clause| {
            clause.iter().any(|a| installed_updates.contains(a))
                    // Implementation decision (a guess): a clause none of whose alternatives
                    // exists in what this server can serve cannot be evaluated by any client
                    // and would hide the update forever; the importer rejects such catalogs,
                    // so this only matters for hand-built ones. It counts as satisfied.
                    || !clause.iter().any(|a| scope_updates.contains(a))
        });
        let id = u.record.local.id;
        if cached.contains(&id) {
            if satisfied {
                held.insert(id);
            } else if out_of_scope_unsatisfied {
                out.insert(id);
            }
        } else if satisfied {
            deliverable.push(idx);
        }
    }
    deliverable.sort_by_key(|&i| (scope.updates[i].is_leaf, scope.updates[i].record.local.id));
    Ok(Staged {
        deliverable,
        out_of_scope: out.into_iter().collect(),
        held,
    })
}

// ---- the all_non_declined scope ----------------------------------------------------

/// One update (newest present revision) of the `all_non_declined` index, without its XML.
#[derive(Debug, Clone)]
struct AllEntry {
    record: FragmentRecord,
    is_leaf: bool,
    bundled: bool,
    software: bool,
    clauses: Arc<Vec<Clause>>,
}

/// The offered set of the `all_non_declined` scope for one (catalog generation, policy
/// generation). Computer independent: approvals only decide each entry's deployment.
#[derive(Debug, Default)]
pub(crate) struct AllIndex {
    entries: Vec<AllEntry>,
}

/// (catalog generation, policy generation).
type AllIndexKey = (i64, i64);

/// Cache of [`AllIndex`] values (at most two: the current and the previous generation pair),
/// so a computer's consecutive requests do not re-read a catalog of over a gigabyte.
#[derive(Debug, Default)]
pub(crate) struct AllIndexCache(Mutex<Vec<(AllIndexKey, Arc<AllIndex>)>>);

/// `Properties/@UpdateType` is `Software`: the first `UpdateType="..."` inside the first
/// `Properties` start tag (with or without a namespace prefix, as in a Core fragment or a whole
/// `upd:Update` document).
fn is_software(core_xml: &[u8]) -> bool {
    fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        hay.get(from..)?
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|i| i + from)
    }
    let mut at = 0;
    while let Some(p) = find(core_xml, b"Properties", at) {
        at = p + 10;
        let opens = p > 0 && matches!(core_xml[p - 1], b'<' | b':');
        let attrs = core_xml
            .get(p + 10)
            .is_some_and(|b| b.is_ascii_whitespace());
        if !(opens && attrs) {
            continue;
        }
        let end = core_xml[p..]
            .iter()
            .position(|b| *b == b'>')
            .map_or(core_xml.len(), |i| p + i);
        let Some(t) = find(&core_xml[..end], b"UpdateType=\"", p) else {
            return false;
        };
        return core_xml[t + 12..].starts_with(b"Software\"");
    }
    false
}

struct Seen {
    record: FragmentRecord,
    software: bool,
    clauses: Arc<Vec<Clause>>,
    bundle_targets: Vec<UpdateId>,
}

fn build_all_index(snapshot: &Snapshot, policy: &Policy) -> Result<AllIndex> {
    let declined: BTreeSet<UpdateId> = policy.declined_updates()?.into_iter().collect();
    // Newest present revision of each update, read one row at a time; the XML is dropped as
    // soon as the clauses and the update type are taken from it.
    let mut newest: BTreeMap<UpdateId, Seen> = BTreeMap::new();
    snapshot.for_each_present(|record, rels| {
        if let Some(cur) = newest.get(&record.identity.id)
            && cur.record.identity.revision >= record.identity.revision
        {
            return Ok(());
        }
        let clauses = parse_clauses(record).unwrap_or_else(|| relationship_clauses(&rels));
        let mut light = record.clone();
        light.core_xml = Vec::new();
        light.extended_xml = None;
        newest.insert(
            record.identity.id,
            Seen {
                software: is_software(&record.core_xml),
                clauses: Arc::new(clauses),
                bundle_targets: rels
                    .iter()
                    .filter(|r| r.kind == RelationshipKind::Bundle)
                    .map(|r| r.target)
                    .collect(),
                record: light,
            },
        );
        Ok(())
    })?;
    let non_leaf = snapshot.prerequisite_targets()?;
    // Bundle members reachable from a non-declined bundle. A member whose bundles are all
    // declined is not offered (INFERRED: the real WSUS lists members only through live bundles).
    let mut live_members: BTreeSet<UpdateId> = BTreeSet::new();
    let mut declined_members: BTreeSet<UpdateId> = BTreeSet::new();
    for (id, s) in &newest {
        let set = if declined.contains(id) {
            &mut declined_members
        } else {
            &mut live_members
        };
        set.extend(s.bundle_targets.iter().copied());
    }
    let mut entries: Vec<AllEntry> = newest
        .into_iter()
        .filter(|(id, _)| {
            !declined.contains(id) && (live_members.contains(id) || !declined_members.contains(id))
        })
        .map(|(id, s)| AllEntry {
            is_leaf: !non_leaf.contains(&id),
            bundled: live_members.contains(&id),
            software: s.software,
            clauses: s.clauses,
            record: s.record,
        })
        .collect();
    entries.sort_by_key(|e| e.record.local.id);
    Ok(AllIndex { entries })
}

/// Scope for the `all_non_declined` delivery rule: every non-declined update of the snapshot,
/// each with the approval's deployment for `computer` when there is one.
pub(crate) fn compute_all(
    snapshot: &Snapshot,
    policy: &Policy,
    computer: ComputerId,
    cache: &AllIndexCache,
) -> Result<Scope> {
    let key = (snapshot.generation().0, policy.generation()?);
    let cached = cache
        .0
        .lock()
        .expect("all index cache")
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.clone());
    let index = match cached {
        Some(i) => i,
        None => {
            let built = Arc::new(build_all_index(snapshot, policy)?);
            let mut guard = cache.0.lock().expect("all index cache");
            guard.retain(|(k, _)| *k != key);
            guard.push((key, built.clone()));
            let excess = guard.len().saturating_sub(2);
            guard.drain(..excess);
            built
        }
    };
    let mut approved: BTreeMap<UpdateId, VisibleUpdate> = BTreeMap::new();
    for v in policy.visible_to(computer)? {
        approved.entry(v.update).or_insert(v);
    }
    let updates = index
        .entries
        .iter()
        .map(|e| ScopedUpdate {
            record: e.record.clone(),
            is_leaf: e.is_leaf,
            deployment: approved.get(&e.record.identity.id).cloned(),
            bundled: e.bundled,
            software: e.software,
            light: true,
            clauses: Some(e.clauses.clone()),
        })
        .collect();
    Ok(Scope { updates })
}

#[cfg(test)]
mod tests {
    use super::is_software;

    #[test]
    fn update_type_is_read_from_fragments_and_prefixed_documents() {
        assert!(is_software(
            br#"<UpdateIdentity/><Properties UpdateType="Software" />"#
        ));
        assert!(!is_software(br#"<Properties UpdateType="Detectoid" />"#));
        assert!(is_software(
            br#"<upd:Update><upd:UpdateIdentity UpdateID="x"/><upd:Properties UpdateType="Software" ProductName="p">"#
        ));
        assert!(!is_software(br#"<upd:Properties UpdateType="Category">"#));
        assert!(!is_software(b"<Relationships/>"));
        assert!(!is_software(b"<Properties/>"));
    }
}
