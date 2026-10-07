//! `SyncUpdates`, extended metadata and file locations.
//!
//! # Checkpointing
//!
//! The synchronization state is the set of revisions the client already holds
//! (the three id lists of MS-WUSP 3.1.5.7). Each response page is committed in
//! two ordered steps: (1) every revision record is written durably to the
//! [`RevisionStore`]; (2) one atomic [`StateStore`](crate::state::StateStore)
//! update adds the revisions to the cache, removes out-of-scope ones and sets
//! the checkpoint. An interruption before step 2 loses nothing and duplicates
//! nothing: the page is simply requested again and its records are
//! overwritten. After step 2 the next request lists those revisions as cached,
//! so the server does not resend them.
//!
//! # Cached id lists
//!
//! MS-WUSP 3.1.5.7 has the client list in `InstalledNonLeafUpdateIDs` the
//! non-leaf updates it evaluated as installed, and everything else it holds in
//! `OtherCachedUpdateIDs`. Implementation decision: this acquisition-only
//! client has no installed inventory and does not invent one; it lists its
//! cached non-leaf revisions as the non-leaf ids (the server needs them to
//! deliver dependent leaves) and caps that list at
//! `SessionConfig::installed_non_leaf_limit`, sending the overflow in
//! `OtherCachedUpdateIDs`. Observed (lab WSUS, Windows Server 2025): 400
//! entries accepted, 401 rejected with `InvalidParameters`
//! (`parameters.InstalledNonLeafUpdateIDs`); `OtherCachedUpdateIDs` accepted
//! 3679 entries; pages carried 30 `NewUpdates`, not 200. A residual
//! `InvalidParameters` ends the run with `SyncError::CachedListRejected`.
//!
//! Past the cap the ranked list withholds some non-leaf ids, and the server
//! (staged delivery) delivers nothing whose prerequisite is withheld. When a
//! run reaches its end with ids withheld, the client therefore sends probe
//! requests, each listing a chunk of the withheld ids plus the best-ranked
//! ones (`CachedIds::probe_lists`), and a probe that delivers anything sends
//! the run back to the ranked list. A cached revision the server answers as
//! out of scope only because a prerequisite id was withheld is kept
//! (`withheld_explains`). Implementation decision (the probes are this
//! project's own; no native client sends them). Cost: with ids withheld every
//! run, a repeat run included, ends with `2 * ceil(withheld / 200)` extra
//! requests.
//!
//! Implementation decisions (partly validated, see above): the cached
//! lists are sent from the first call, which makes a repeat synchronization
//! incremental; a response with `Truncated == false` ends the run;
//! `DeployedOutOfScopeRevisionIds` are treated like `OutOfScopeRevisionIDs`;
//! the driver pass (`SkipSoftwareSync`, `SystemSpec`) is not implemented.

use super::{
    catalog::Catalog,
    error::SyncError,
    localized::language_of,
    store::{DeploymentSummary, RevisionRecord, RevisionStore, StoredFragment},
};
use crate::{
    download::Location,
    session::{Clock, Service, WuspError, WuspSession},
    state::{CachedRevision, SyncCheckpoint},
    transport::{Idempotence, RetryTimer, Transport},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use wsus_protocol::{
    ProtocolError,
    identity::{ServerId, UpdateId, UpdateRevision, WireRevisionId},
    metadata::{FragmentOrigin, FragmentSource, RawFragment, UpdateIndex, UpdateType},
    soap::{ErrorCode, Limits, Presence, Scalar},
    wusp::{
        CategoryIdentifier, GetExtendedUpdateInfo, GetExtendedUpdateInfo2, GetFileLocations,
        SyncInfo, SyncUpdateParameters, SyncUpdates, UpdateData, XmlUpdateFragmentType,
    },
};

/// How often `GetFileLocations` is repeated after `FileLocationChanged` faults.
const MAX_FILE_LOCATION_RETRIES: u32 = 3;

/// Options of [`SyncEngine::sync_updates`].
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// Category filter (`FilterCategoryIds`); empty sends none.
    pub filter_categories: Vec<Uuid>,
    /// Upper bound on pages per run.
    pub max_pages: u32,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            filter_categories: Vec::new(),
            max_pages: 1000,
        }
    }
}

/// Outcome of a synchronization run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pages: u32,
    /// Revisions stored for the first time in this run.
    pub new_revisions: usize,
    /// Revisions delivered again (changed deployment or metadata).
    pub changed_revisions: usize,
    /// Revisions dropped from the cache as out of scope.
    pub removed_revisions: usize,
    /// Changed entries without metadata that match no cached revision.
    pub unresolved: usize,
    /// Nothing new, changed or removed: the local catalog was current.
    pub unchanged: bool,
    pub checkpoint: Option<SyncCheckpoint>,
}

/// A transient content location. Never persisted or serialized; `Debug`
/// redacts the URL.
#[derive(Debug, Clone)]
pub struct ResolvedLocation {
    /// SHA-1 digest the server keyed the location by.
    pub sha1: Vec<u8>,
    pub location: Location,
    /// The server marked the file as encrypted (`DecryptionInformation` or an
    /// encrypted digest); decryption is not implemented.
    pub encrypted: bool,
}

/// Outcome of a fragment fetch.
#[derive(Debug, Default)]
pub struct FragmentReport {
    /// Fragments stored.
    pub stored: usize,
    /// Revisions the server reported out of scope.
    pub out_of_scope: Vec<UpdateRevision>,
    /// Locations that came back with the request (`FileUrl`); transient.
    pub locations: Vec<ResolvedLocation>,
    /// Entries of decryption data (`GetExtendedUpdateInfo2`); not interpreted.
    pub decryption_entries: usize,
}

/// Synchronization engine over a [`WuspSession`] and a [`RevisionStore`].
pub struct SyncEngine<T: Transport, S: RetryTimer, C: Clock> {
    pub(crate) session: WuspSession<T, S, C>,
    pub(crate) store: RevisionStore,
}

impl<T: Transport, S: RetryTimer, C: Clock> std::fmt::Debug for SyncEngine<T, S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncEngine")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

fn type_name(t: &UpdateType) -> String {
    match t {
        UpdateType::Software => "Software".into(),
        UpdateType::Driver => "Driver".into(),
        UpdateType::Category => "Category".into(),
        UpdateType::Detectoid => "Detectoid".into(),
        UpdateType::Other(o) => o.clone(),
    }
}

fn stored(fragment: &RawFragment, kind: &str, locale: Option<String>) -> StoredFragment {
    StoredFragment {
        kind: kind.to_owned(),
        locale,
        sha256: fragment.provenance.hex(),
        xml: String::from_utf8_lossy(fragment.xml()).into_owned(),
    }
}

/// Fault reason plus the server's `Message` detail, for the typed error.
fn fault_detail(e: &WuspError) -> String {
    match e {
        WuspError::Fault(f) => match &f.message {
            Some(m) => format!("{}: {m}", f.reason),
            None => f.reason.clone(),
        },
        WuspError::RecoveryExhausted { last, .. } => fault_detail(last),
        other => other.to_string(),
    }
}

/// What the request builder needs to know about a stored revision.
#[derive(Debug, Clone, Default)]
struct KindInfo {
    leaf: bool,
    driver: bool,
    software: bool,
    /// Update ids named by the revision's prerequisite clauses (every
    /// alternative); only filled for non-leaf and software revisions.
    prerequisites: Vec<UpdateId>,
    /// The prerequisite clauses (a clause holds when at least one of its
    /// alternatives is listed as installed); filled for every revision that
    /// is not a driver.
    clauses: Vec<Vec<UpdateId>>,
}

fn kind_of(record: &RevisionRecord, limits: &Limits) -> Result<KindInfo, SyncError> {
    let mut kind = KindInfo {
        leaf: record.is_leaf,
        driver: record.update_type.as_deref() == Some("Driver"),
        software: record.update_type.as_deref() == Some("Software"),
        prerequisites: Vec::new(),
        clauses: Vec::new(),
    };
    if !kind.driver {
        let core = RawFragment::from_xml_text(
            FragmentOrigin::new(FragmentSource::Other("revision store".into())),
            &record.core.xml,
        );
        let index = UpdateIndex::from_fragments([&core], None, limits).map_err(|source| {
            SyncError::Metadata {
                context: format!("revision {}", record.identity),
                source,
            }
        })?;
        kind.clauses = index
            .prerequisites
            .iter()
            .map(|c| c.update_ids.clone())
            .collect();
        if !record.is_leaf || kind.software {
            kind.prerequisites = kind.clauses.iter().flatten().copied().collect();
        }
    }
    Ok(kind)
}

/// The three id lists of one request: the ranked list, or probe `n`.
fn request_lists(
    state: &crate::state::ClientState,
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
    limit: usize,
    probe: Option<usize>,
) -> (Vec<i32>, Vec<i32>, Vec<i32>) {
    match probe {
        Some(n) => classify_cached(state, kinds, limit).probe_lists(limit, n),
        None => split_cached(state, kinds, limit),
    }
}

/// Splits the cached revisions into the three `SyncUpdates` id lists.
///
/// Implementation decision (see `SessionConfig::installed_non_leaf_limit`):
/// non-leaf revisions go to `InstalledNonLeafUpdateIDs` up to `limit`; the
/// remainder and all leaves go to `OtherCachedUpdateIDs`; drivers to
/// `CachedDriverIDs`.
///
/// While the cached non-leaf revisions fit under `limit` all of them are
/// listed. Beyond it they are ranked by how many stored software revisions
/// depend on them, directly or through other non-leaf revisions (more first),
/// then by prerequisite depth, then by server-local id. A revision always has
/// at least the score of what depends on it, so a revision never ranks behind
/// its own dependents and the choice only changes when new software revisions
/// are stored (the store keeps revisions the server later declared out of
/// scope, so a withheld prerequisite does not lower anyone's score).
///
/// Observed: the server treats a prerequisite as satisfied only when its id is
/// in `InstalledNonLeafUpdateIDs`; revisions with an unlisted prerequisite are
/// returned in `OutOfScopeRevisionIDs` and are not delivered again until it is
/// listed. With 473 non-leaf revisions and a limit of 400, ranking by
/// prerequisite depth alone withheld prerequisites of 780 of 808 software
/// revisions; ranking by dependent software revisions keeps the useful ones.
fn split_cached(
    state: &crate::state::ClientState,
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
    limit: usize,
) -> (Vec<i32>, Vec<i32>, Vec<i32>) {
    let cached = classify_cached(state, kinds, limit);
    let listed = cached.ranked.len().min(limit);
    cached.lists(cached.ranked[..listed].iter().copied())
}

/// The cached revisions by role: non-leaf ids best first, leaves, drivers.
struct CachedIds {
    /// Non-leaf server-local ids, the first to list first (see
    /// [`split_cached`]).
    ranked: Vec<i32>,
    leaves: Vec<i32>,
    drivers: Vec<i32>,
}

fn classify_cached(
    state: &crate::state::ClientState,
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
    limit: usize,
) -> CachedIds {
    let (mut leaves, mut drivers) = (Vec::new(), Vec::new());
    let mut non_leaf: Vec<(UpdateRevision, i32)> = Vec::new();
    for (rev, cached) in &state.cached_revisions {
        let (Some(id), Some(kind)) = (cached.local_revision_id, kinds.get(rev)) else {
            continue;
        };
        if kind.driver {
            drivers.push(id);
        } else if kind.leaf {
            leaves.push(id);
        } else {
            non_leaf.push((*rev, id));
        }
    }
    let mut ranked: Vec<Ranked> = if non_leaf.len() <= limit {
        non_leaf
            .iter()
            .map(|(_, id)| (std::cmp::Reverse(0), 0, *id))
            .collect()
    } else {
        rank_non_leaf(&non_leaf, kinds)
    };
    ranked.sort_unstable();
    CachedIds {
        ranked: ranked.into_iter().map(|(_, _, id)| id).collect(),
        leaves,
        drivers,
    }
}

impl CachedIds {
    /// `(InstalledNonLeafUpdateIDs, OtherCachedUpdateIDs, CachedDriverIDs)`
    /// when exactly `installed` is listed as installed.
    fn lists(&self, installed: impl Iterator<Item = i32>) -> (Vec<i32>, Vec<i32>, Vec<i32>) {
        let mut installed: Vec<i32> = installed.collect();
        installed.sort_unstable();
        let mut other: Vec<i32> = self
            .ranked
            .iter()
            .copied()
            .filter(|id| installed.binary_search(id).is_err())
            .chain(self.leaves.iter().copied())
            .collect();
        other.sort_unstable();
        let mut drivers = self.drivers.clone();
        drivers.sort_unstable();
        (installed, other, drivers)
    }

    /// Number of probe lists for `limit`, 0 when nothing is withheld.
    fn probe_count(&self, limit: usize) -> usize {
        let tail = self.ranked.len().saturating_sub(limit);
        if limit == 0 || tail == 0 {
            return 0;
        }
        2 * tail.div_ceil(Self::chunk(limit))
    }

    fn chunk(limit: usize) -> usize {
        (limit / 2).max(1)
    }

    /// Probe list `n` (0-based, below [`Self::probe_count`]): a chunk of the
    /// withheld ids plus the best-ranked ids that fit, taken from the front
    /// of the listed part for even `n` and from its back for odd `n`.
    fn probe_lists(&self, limit: usize, n: usize) -> (Vec<i32>, Vec<i32>, Vec<i32>) {
        let (head, tail) = self.ranked.split_at(limit.min(self.ranked.len()));
        let chunk_len = Self::chunk(limit);
        let chunk = tail.chunks(chunk_len).nth(n / 2).unwrap_or(&[]);
        let fill = limit.saturating_sub(chunk.len()).min(head.len());
        let fill_ids = if n.is_multiple_of(2) {
            &head[..fill]
        } else {
            &head[head.len() - fill..]
        };
        self.lists(chunk.iter().chain(fill_ids).copied())
    }
}

/// Whether the server's out-of-scope answer for the cached revision `id` is
/// explained by the ids this client withheld from `installed`: one of its
/// prerequisite clauses has no listed alternative but has a cached
/// alternative that was left out of the list. Such a revision is still in
/// scope (the withheld id is held), so the client keeps it.
fn withheld_explains(
    id: i32,
    state: &crate::state::ClientState,
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
    installed: &[i32],
) -> bool {
    let mut listed: BTreeSet<UpdateId> = BTreeSet::new();
    let mut withheld: BTreeSet<UpdateId> = BTreeSet::new();
    let mut clauses: Option<&Vec<Vec<UpdateId>>> = None;
    for (rev, cached) in &state.cached_revisions {
        let Some(local) = cached.local_revision_id else {
            continue;
        };
        let Some(kind) = kinds.get(rev) else {
            continue;
        };
        if local == id {
            clauses = Some(&kind.clauses);
        }
        if !kind.leaf && !kind.driver {
            if installed.binary_search(&local).is_ok() {
                listed.insert(rev.id);
            } else {
                withheld.insert(rev.id);
            }
        }
    }
    clauses.is_some_and(|clauses| {
        clauses.iter().any(|clause| {
            !clause.iter().any(|a| listed.contains(a))
                && clause
                    .iter()
                    .any(|a| withheld.contains(a) && !listed.contains(a))
        })
    })
}

type Ranked = (std::cmp::Reverse<usize>, usize, i32);

fn rank_non_leaf(
    non_leaf: &[(UpdateRevision, i32)],
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
) -> Vec<Ranked> {
    let mut members: BTreeMap<UpdateId, Vec<UpdateRevision>> = BTreeMap::new();
    for (rev, _) in non_leaf {
        members.entry(rev.id).or_default().push(*rev);
    }
    let mut closures: BTreeMap<UpdateId, BTreeSet<UpdateId>> = BTreeMap::new();
    let mut depths: BTreeMap<UpdateId, usize> = BTreeMap::new();
    let mut score: BTreeMap<UpdateId, usize> = BTreeMap::new();
    for kind in kinds.values().filter(|k| k.software) {
        let mut seen = BTreeSet::new();
        for pre in &kind.prerequisites {
            if members.contains_key(pre) {
                seen.insert(*pre);
                seen.extend(ancestors(
                    *pre,
                    &members,
                    kinds,
                    &mut closures,
                    &mut Vec::new(),
                ));
            }
        }
        for id in seen {
            *score.entry(id).or_default() += 1;
        }
    }
    non_leaf
        .iter()
        .map(|(rev, id)| {
            let depth = depth_of(rev.id, &members, kinds, &mut depths, &mut Vec::new());
            (
                std::cmp::Reverse(score.get(&rev.id).copied().unwrap_or(0)),
                depth,
                *id,
            )
        })
        .collect()
}

/// Cached non-leaf ids reachable through prerequisite clauses from `id`.
fn ancestors(
    id: UpdateId,
    members: &BTreeMap<UpdateId, Vec<UpdateRevision>>,
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
    memo: &mut BTreeMap<UpdateId, BTreeSet<UpdateId>>,
    visiting: &mut Vec<UpdateId>,
) -> BTreeSet<UpdateId> {
    if let Some(done) = memo.get(&id) {
        return done.clone();
    }
    if visiting.contains(&id) {
        return BTreeSet::new();
    }
    visiting.push(id);
    let mut out = BTreeSet::new();
    for rev in members.get(&id).into_iter().flatten() {
        for pre in kinds.get(rev).into_iter().flat_map(|k| &k.prerequisites) {
            if members.contains_key(pre) {
                out.insert(*pre);
                out.extend(ancestors(*pre, members, kinds, memo, visiting));
            }
        }
    }
    visiting.pop();
    memo.insert(id, out.clone());
    out
}

fn depth_of(
    id: UpdateId,
    members: &BTreeMap<UpdateId, Vec<UpdateRevision>>,
    kinds: &BTreeMap<UpdateRevision, KindInfo>,
    memo: &mut BTreeMap<UpdateId, usize>,
    visiting: &mut Vec<UpdateId>,
) -> usize {
    if let Some(d) = memo.get(&id) {
        return *d;
    }
    if visiting.contains(&id) {
        return usize::MAX;
    }
    visiting.push(id);
    let mut best = usize::MAX;
    for rev in members.get(&id).into_iter().flatten() {
        for pre in kinds.get(rev).into_iter().flat_map(|k| &k.prerequisites) {
            if members.contains_key(pre) {
                best = best.min(depth_of(*pre, members, kinds, memo, visiting));
            }
        }
    }
    visiting.pop();
    let depth = if best == usize::MAX { 0 } else { best + 1 };
    memo.insert(id, depth);
    depth
}

fn anchor_of(ids: impl Iterator<Item = i32>) -> String {
    let mut ids: Vec<i32> = ids.collect();
    ids.sort_unstable();
    let mut hasher = Sha256::new();
    for id in &ids {
        hasher.update(id.to_le_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("cache:{}:{hex}", ids.len())
}

impl<T: Transport, S: RetryTimer, C: Clock> SyncEngine<T, S, C> {
    /// Combines a session and a revision store.
    pub fn new(session: WuspSession<T, S, C>, store: RevisionStore) -> Self {
        Self { session, store }
    }

    /// The session.
    pub fn session(&self) -> &WuspSession<T, S, C> {
        &self.session
    }

    /// The session, mutably (for `begin_run`, `handshake`, ...).
    pub fn session_mut(&mut self) -> &mut WuspSession<T, S, C> {
        &mut self.session
    }

    /// The revision store.
    pub fn store(&self) -> &RevisionStore {
        &self.store
    }

    /// Builds the catalog from everything stored.
    pub fn catalog(&self) -> Result<Catalog, SyncError> {
        Catalog::load(&self.store, &self.session.config().limits)
    }

    fn server(&self) -> ServerId {
        self.session.server_id()
    }

    /// Classification of every stored revision that is cached or may rank a
    /// cached one (software), read from the store once per run and kept
    /// current by [`Self::commit_page`].
    fn cached_kinds(&self) -> Result<BTreeMap<UpdateRevision, KindInfo>, SyncError> {
        let limits = &self.session.config().limits;
        let mut kinds = BTreeMap::new();
        for record in self.store.list()? {
            // A cached revision whose record is missing is not really held:
            // it is absent here, so the server sends it again.
            kinds.insert(record.identity, kind_of(&record, limits)?);
        }
        Ok(kinds)
    }

    /// Runs `SyncUpdates` until the server reports no truncation, committing
    /// each page as described in the module documentation.
    pub async fn sync_updates(&mut self, options: &SyncOptions) -> Result<SyncReport, SyncError> {
        self.session.begin_run();
        let mut report = SyncReport::default();
        let mut kinds = self.cached_kinds()?;
        // `Some(n)`: the next request is withheld-id probe `n` (see
        // `CachedIds::probe_lists`) instead of the ranked list.
        let mut probe: Option<usize> = None;
        loop {
            if report.pages >= options.max_pages {
                return Err(SyncError::TooManyPages(options.max_pages));
            }
            let filter = if options.filter_categories.is_empty() {
                Presence::Absent
            } else {
                Presence::Value(
                    options
                        .filter_categories
                        .iter()
                        .map(|id| CategoryIdentifier { id: *id })
                        .collect::<Vec<_>>(),
                )
            };
            let limit = self.session.config().installed_non_leaf_limit;
            let result = self
                .session
                .call(
                    Service::Client,
                    "SyncUpdates",
                    Idempotence::Idempotent,
                    |cookie, state| {
                        let (non_leaf, other, drivers) = request_lists(state, &kinds, limit, probe);
                        SyncUpdates {
                            cookie: Presence::Value(cookie.clone()),
                            parameters: Presence::Value(SyncUpdateParameters {
                                express_query: false,
                                installed_non_leaf_update_ids: Presence::Value(non_leaf),
                                other_cached_update_ids: Presence::Value(other),
                                system_spec: Presence::Absent,
                                cached_driver_ids: Presence::Value(drivers),
                                skip_software_sync: false,
                                filter_category_ids: filter.clone(),
                                need_two_group_out_of_scope_updates: Presence::Absent,
                                computer_spec: Presence::Absent,
                                feature_score_matching_key: Presence::Absent,
                            }),
                        }
                    },
                )
                .await;
            let response = match result {
                Ok(r) => r,
                Err(e) if e.fault_code() == Some(&ErrorCode::InvalidParameters) => {
                    let (non_leaf, other, _) = split_cached(self.session.state(), &kinds, limit);
                    return Err(SyncError::CachedListRejected {
                        installed: non_leaf.len(),
                        other: other.len(),
                        limit,
                        detail: fault_detail(&e),
                    });
                }
                Err(e) => return Err(e.into()),
            };
            let mut info = response
                .result
                .into_value()
                .ok_or_else(|| ProtocolError::MissingElement("SyncUpdatesResult".into()))
                .map_err(WuspError::from)?;
            // A cached revision the server answers as out of scope only
            // because this client withheld one of its prerequisite ids from
            // `InstalledNonLeafUpdateIDs` is kept (see `withheld_explains`).
            if let Presence::Value(oos) = &mut info.out_of_scope_revision_ids {
                let (installed, _, _) = request_lists(self.session.state(), &kinds, limit, probe);
                oos.retain(|id| !withheld_explains(*id, self.session.state(), &kinds, &installed));
            }
            report.pages += 1;
            let progress = self.commit_page(&info, &mut report, &mut kinds)?;
            if let Some(cookie) = info.new_cookie.value() {
                self.session.adopt_cookie(cookie)?;
            }
            // MS-WUSP 3.1.5.7: a complete (not truncated) response that
            // delivered a non-leaf update calls for one more request, since
            // the new non-leaf ids change which dependents the server
            // delivers. Observed: the lab WSUS answered such a request with 10
            // more revisions and 4 out-of-scope ids after the last page had
            // brought new non-leaf revisions.
            let delivered_non_leaf = info
                .new_updates
                .value()
                .into_iter()
                .flatten()
                .any(|u| !u.is_leaf);
            let delivered = info.new_updates.value().is_some_and(|v| !v.is_empty());
            if let Some(n) = probe {
                // A probe that delivered something returns to the ranked
                // list, which delivers what that list can; one that did not
                // moves on, and the last one ends the run.
                if delivered {
                    probe = None;
                } else if n + 1
                    >= classify_cached(self.session.state(), &kinds, limit).probe_count(limit)
                {
                    break;
                } else {
                    probe = Some(n + 1);
                }
                continue;
            }
            if !info.truncated && !delivered_non_leaf {
                // The ranked list withholds the non-leaf ids beyond `limit`,
                // so a revision whose prerequisite is withheld is never
                // delivered by it: ask again with each withheld id listed.
                if classify_cached(self.session.state(), &kinds, limit).probe_count(limit) > 0 {
                    probe = Some(0);
                    continue;
                }
                break;
            }
            if !progress {
                return Err(SyncError::NoProgress);
            }
        }
        report.unchanged =
            report.new_revisions + report.changed_revisions + report.removed_revisions == 0;
        report.checkpoint = self.session.state().sync_checkpoint.clone();
        Ok(report)
    }

    /// Stores a page then commits it. Returns whether it carried anything.
    fn commit_page(
        &mut self,
        info: &SyncInfo,
        report: &mut SyncReport,
        kinds: &mut BTreeMap<UpdateRevision, KindInfo>,
    ) -> Result<bool, SyncError> {
        let server = Some(self.server());
        let limits = self.session.config().limits.clone();
        let removed: Vec<i32> = info
            .out_of_scope_revision_ids
            .value()
            .into_iter()
            .chain(info.deployed_out_of_scope_revision_ids.value())
            .flatten()
            .copied()
            .collect();
        let entries = info
            .new_updates
            .value()
            .into_iter()
            .flatten()
            .map(|u| (u, false))
            .chain(
                info.changed_updates
                    .value()
                    .into_iter()
                    .flatten()
                    .map(|u| (u, true)),
            );

        let mut staged: Vec<(i32, RevisionRecord, bool)> = Vec::new();
        for (update, changed) in entries {
            let deployment = update.deployment.value().map(DeploymentSummary::from_wire);
            let identity_and_core = match RawFragment::from_update_info(server, update) {
                Some(fragment) => {
                    let index = UpdateIndex::from_fragments([&fragment], None, &limits).map_err(
                        |source| SyncError::Metadata {
                            context: format!("core fragment of server revision {}", update.id),
                            source,
                        },
                    )?;
                    Some((fragment, index))
                }
                None => None,
            };
            let reverse = |id: i32| {
                self.session
                    .state()
                    .cached_revisions
                    .iter()
                    .find(|(_, c)| c.local_revision_id == Some(id))
                    .map(|(r, _)| *r)
            };
            let record = match identity_and_core {
                Some((fragment, index)) => {
                    let identity = index.identity;
                    let core = stored(&fragment, "Core", None);
                    let fragments = self
                        .store
                        .get(&identity)?
                        .map(|r| r.fragments)
                        .unwrap_or_default();
                    Some(RevisionRecord {
                        identity,
                        is_leaf: update.is_leaf,
                        update_type: index.properties.update_type.as_ref().map(type_name),
                        deployment,
                        core,
                        fragments,
                    })
                }
                None => match reverse(update.id) {
                    Some(identity) => self.store.get(&identity)?.map(|mut r| {
                        r.is_leaf = update.is_leaf;
                        if deployment.is_some() {
                            r.deployment = deployment;
                        }
                        r
                    }),
                    None => None,
                },
            };
            match record {
                Some(r) => staged.push((update.id, r, changed)),
                None => report.unresolved += 1,
            }
        }

        // Step 1: metadata is durable before the checkpoint moves.
        for (_, record, _) in &staged {
            self.store.put(record)?;
            kinds.insert(record.identity, kind_of(record, &limits)?);
        }
        // Step 2: one atomic state update.
        let now = self.session.now_unix();
        let mut counts = (0usize, 0usize, 0usize);
        let known: BTreeMap<UpdateRevision, bool> = self
            .session
            .state()
            .cached_revisions
            .keys()
            .map(|k| (*k, true))
            .collect();
        for (_, record, changed) in &staged {
            if *changed || known.contains_key(&record.identity) {
                counts.1 += 1;
            } else {
                counts.0 += 1;
            }
        }
        let carried = !staged.is_empty() || !removed.is_empty();
        if carried {
            self.session.store_mut().update(|s| {
                for (id, record, _) in &staged {
                    s.cached_revisions.insert(
                        record.identity,
                        CachedRevision {
                            local_revision_id: Some(*id),
                            metadata_sha256: Some(record.core.sha256.clone()),
                        },
                    );
                }
                let before = s.cached_revisions.len();
                s.cached_revisions
                    .retain(|_, c| !c.local_revision_id.is_some_and(|id| removed.contains(&id)));
                counts.2 = before - s.cached_revisions.len();
                s.sync_checkpoint = Some(SyncCheckpoint {
                    anchor: anchor_of(
                        s.cached_revisions
                            .values()
                            .filter_map(|c| c.local_revision_id),
                    ),
                    committed_unix: now,
                });
            })?;
        }
        report.new_revisions += counts.0;
        report.changed_revisions += counts.1;
        report.removed_revisions += counts.2;
        Ok(carried)
    }

    // ---- GetExtendedUpdateInfo[2] ------------------------------------------

    fn local_ids(
        &self,
        revisions: &[UpdateRevision],
    ) -> Result<Vec<(UpdateRevision, i32)>, SyncError> {
        revisions
            .iter()
            .map(|r| {
                self.session
                    .state()
                    .cached_revisions
                    .get(r)
                    .and_then(|c| c.local_revision_id)
                    .map(|id| (*r, id))
                    .ok_or(SyncError::UnknownRevision(*r))
            })
            .collect()
    }

    fn store_updates(
        &mut self,
        updates: &[UpdateData],
        kind: &XmlUpdateFragmentType,
        locales: &[String],
        source: FragmentSource,
        report: &mut FragmentReport,
    ) -> Result<(), SyncError> {
        let server = Some(self.server());
        let reverse: BTreeMap<i32, UpdateRevision> = self
            .session
            .state()
            .cached_revisions
            .iter()
            .filter_map(|(r, c)| c.local_revision_id.map(|id| (id, *r)))
            .collect();
        for data in updates {
            let Some(rev) = reverse.get(&data.id) else {
                continue;
            };
            let Some(fragment) =
                RawFragment::from_update_data(server, data, source.clone(), Some(kind.clone()))
            else {
                continue;
            };
            let Some(mut record) = self.store.get(rev)? else {
                continue;
            };
            // Fragments are unlabeled on the wire: the fragment's own
            // `Language` element names its locale; failing that, a single
            // requested locale labels the result.
            let locale = matches!(
                kind,
                XmlUpdateFragmentType::LocalizedProperties | XmlUpdateFragmentType::Eula
            )
            .then(|| {
                language_of(&String::from_utf8_lossy(fragment.xml()))
                    .or_else(|| (locales.len() == 1).then(|| locales[0].clone()))
            })
            .flatten();
            record.put_fragment(stored(&fragment, &kind.format(), locale));
            self.store.put(&record)?;
            report.stored += 1;
        }
        Ok(())
    }

    fn resolve_locations(
        locations: &[wsus_protocol::wusp::FileLocation],
    ) -> Result<Vec<ResolvedLocation>, SyncError> {
        let mut out = Vec::new();
        for l in locations {
            let (Some(digest), Some(url)) = (l.file_digest.value(), l.url.value()) else {
                continue;
            };
            out.push(ResolvedLocation {
                sha1: digest.clone(),
                location: Location::parse(url).map_err(|_| SyncError::InvalidLocation)?,
                encrypted: l.decryption_information.value().is_some()
                    || l.encrypted_file_digest.value().is_some(),
            });
        }
        Ok(out)
    }

    /// `GetExtendedUpdateInfo` for one fragment kind (one request per batch
    /// of at most `MaxExtendedUpdatesPerRequest - 1` revisions). Fragments are
    /// stored in the revision records; locations returned with the response
    /// are handed back transiently. Kinds are requested one at a time because
    /// the response does not label fragments.
    pub async fn fetch_fragments(
        &mut self,
        revisions: &[UpdateRevision],
        kind: XmlUpdateFragmentType,
        locales: &[String],
    ) -> Result<FragmentReport, SyncError> {
        self.local_ids(revisions)?;
        let mut report = FragmentReport::default();
        for batch in revisions.chunks(self.session.max_extended_updates()) {
            let response = self
                .session
                .call(
                    Service::Client,
                    "GetExtendedUpdateInfo",
                    Idempotence::Idempotent,
                    |cookie, state| GetExtendedUpdateInfo {
                        cookie: Presence::Value(cookie.clone()),
                        // Re-resolved from the current state: a recovery may
                        // have renumbered the server-local ids.
                        revision_ids: Presence::Value(
                            batch
                                .iter()
                                .filter_map(|r| {
                                    state
                                        .cached_revisions
                                        .get(r)
                                        .and_then(|c| c.local_revision_id)
                                })
                                .collect(),
                        ),
                        info_types: Presence::Value(vec![kind.clone()]),
                        locales: if locales.is_empty() {
                            Presence::Absent
                        } else {
                            Presence::Value(locales.to_vec())
                        },
                        geo_id: Presence::Absent,
                        caller_attributes: Presence::Absent,
                    },
                )
                .await?;
            let info = response
                .result
                .into_value()
                .ok_or_else(|| ProtocolError::MissingElement("GetExtendedUpdateInfoResult".into()))
                .map_err(WuspError::from)?;
            self.store_updates(
                info.updates.value().map_or(&[][..], Vec::as_slice),
                &kind,
                locales,
                FragmentSource::WuspGetExtendedUpdateInfo,
                &mut report,
            )?;
            for oos in info.out_of_scope_revision_ids.value().into_iter().flatten() {
                if let Some(rev) = batch.iter().find(|r| {
                    self.session
                        .state()
                        .cached_revisions
                        .get(r)
                        .and_then(|c| c.local_revision_id)
                        == Some(*oos)
                }) {
                    report.out_of_scope.push(*rev);
                }
            }
            report.locations.extend(Self::resolve_locations(
                info.file_locations.value().map_or(&[][..], Vec::as_slice),
            )?);
        }
        Ok(report)
    }

    /// `GetExtendedUpdateInfo2`, keyed by update identity. Same storage
    /// behaviour as [`SyncEngine::fetch_fragments`]; decryption data is only
    /// counted. Only the MS-WUSP `soap` WSDL binding lists this operation.
    pub async fn fetch_fragments2(
        &mut self,
        revisions: &[UpdateRevision],
        kind: XmlUpdateFragmentType,
        locales: &[String],
    ) -> Result<FragmentReport, SyncError> {
        self.local_ids(revisions)?;
        let mut report = FragmentReport::default();
        for batch in revisions.chunks(self.session.max_extended_updates()) {
            let response = self
                .session
                .call(
                    Service::Client,
                    "GetExtendedUpdateInfo2",
                    Idempotence::Idempotent,
                    |cookie, _| GetExtendedUpdateInfo2 {
                        cookie: Presence::Value(cookie.clone()),
                        update_ids: Presence::Value(batch.to_vec()),
                        info_types: Presence::Value(vec![kind.clone()]),
                        locales: if locales.is_empty() {
                            Presence::Absent
                        } else {
                            Presence::Value(locales.to_vec())
                        },
                        caller_attributes: Presence::Absent,
                    },
                )
                .await?;
            let info = response
                .result
                .into_value()
                .ok_or_else(|| ProtocolError::MissingElement("GetExtendedUpdateInfo2Result".into()))
                .map_err(WuspError::from)?;
            self.store_updates(
                info.updates.value().map_or(&[][..], Vec::as_slice),
                &kind,
                locales,
                FragmentSource::WuspGetExtendedUpdateInfo2,
                &mut report,
            )?;
            report.decryption_entries += info.file_decryption_data.value().map_or(0, Vec::len)
                + info.file_decryption_data2.value().map_or(0, Vec::len);
            report.locations.extend(Self::resolve_locations(
                info.file_locations.value().map_or(&[][..], Vec::as_slice),
            )?);
        }
        Ok(report)
    }

    /// `GetFileLocations` for SHA-1 digests. Locations are transient values:
    /// they are returned, never written to disk. A `NewCookie` in the answer
    /// replaces the session cookie.
    pub async fn file_locations(
        &mut self,
        sha1_digests: &[Vec<u8>],
    ) -> Result<Vec<ResolvedLocation>, SyncError> {
        let mut out = Vec::new();
        for batch in sha1_digests.chunks(100) {
            // `FileLocationChanged` (MS-WUSP fault table): the locations moved; ask again.
            let mut changed = 0u32;
            let response = loop {
                match self
                    .session
                    .call(
                        Service::Client,
                        "GetFileLocations",
                        Idempotence::Idempotent,
                        |cookie, _| GetFileLocations {
                            cookie: Presence::Value(cookie.clone()),
                            file_digests: Presence::Value(batch.to_vec()),
                        },
                    )
                    .await
                {
                    Ok(response) => break response,
                    Err(e)
                        if e.fault_code() == Some(&ErrorCode::FileLocationChanged)
                            && changed < MAX_FILE_LOCATION_RETRIES =>
                    {
                        changed += 1;
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            let result = response
                .result
                .into_value()
                .ok_or_else(|| ProtocolError::MissingElement("GetFileLocationsResult".into()))
                .map_err(WuspError::from)?;
            if let Some(cookie) = result.new_cookie.value() {
                self.session.adopt_cookie(cookie)?;
            }
            out.extend(Self::resolve_locations(
                result.file_locations.value().map_or(&[][..], Vec::as_slice),
            )?);
        }
        Ok(out)
    }

    /// Server-local id of a cached revision.
    pub fn local_id(&self, rev: &UpdateRevision) -> Option<WireRevisionId> {
        self.session
            .state()
            .cached_revisions
            .get(rev)
            .and_then(|c| c.local_revision_id)
            .map(WireRevisionId)
    }
}
