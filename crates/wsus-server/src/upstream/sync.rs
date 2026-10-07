//! Initial and incremental synchronization into catalog generations.
use futures_util::{StreamExt, stream};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use wsus_client::wsusss::UpdateBatch;

use wsus_client::transport::{RetryTimer, Transport};
use wsus_client::wsusss::{RevisionList, RevisionQuery, UpdateRecord, WsusssClient};
use wsus_protocol::identity::{UpdateId, UpdateRevision};
use wsus_protocol::metadata::UpdateType;

use super::checkpoint::Checkpoint;
use super::config::UpstreamConfig;
use super::convert::{Converted, convert};
use super::error::UpstreamError;
use super::ext;
use crate::catalog::{
    ActivateOutcome, Catalog, FragmentImport, FragmentState, GenerationId, IssueKind,
    RelationshipImport, SourceId, SourceKind,
};

/// Why a synchronization started from reset anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// No committed checkpoint exists.
    Initial,
    /// The configured endpoint identity differs from the committed one.
    EndpointChanged,
    /// The category filter differs from the committed one.
    FilterChanged,
    /// The upstream answered `ServerChanged`.
    ServerChanged,
    /// The committed checkpoint could not be read.
    CheckpointUnreadable,
}

/// Counters of one synchronization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncStats {
    /// Why anchors were reset, if they were.
    pub reset: Option<ResetReason>,
    /// An interrupted staging generation was continued.
    pub resumed: bool,
    /// Revisions listed by the upstream.
    pub listed: usize,
    /// Revisions whose metadata was fetched and staged in this call.
    pub fetched: usize,
    /// Revisions carried over from the previous active generation.
    pub carried: usize,
    /// Revisions a full resynchronization no longer listed, kept as tombstones.
    pub tombstoned: usize,
    /// Revisions dropped by the category filter.
    pub excluded_by_filter: usize,
    /// Excluded revisions pulled in because a staged revision needs them.
    pub pulled_by_dependency: usize,
    /// Staged revisions the upstream marks as withdrawn.
    pub withdrawn: usize,
    /// File entries without name, size or digest that were not imported.
    pub files_without_descriptor: usize,
}

/// A fully staged, not yet activated generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSync {
    /// Staging generation.
    pub generation: GenerationId,
    /// Checkpoint that becomes committed on activation.
    pub checkpoint: Checkpoint,
    /// Counters so far.
    pub stats: SyncStats,
}

/// Result of [`UpstreamSync::stage`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum StageOutcome {
    /// Nothing changed upstream; the committed generation stays.
    NoChange,
    /// A generation is ready for activation.
    Staged(StagedSync),
}

/// Result of a synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Nothing changed.
    NoChange,
    /// A new generation is active and its checkpoint committed.
    Activated {
        generation: GenerationId,
        fragments: u64,
        checkpoint: Checkpoint,
    },
}

/// Metadata synchronization result. File acquisition is reported separately
/// by [`super::ContentReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub outcome: SyncOutcome,
    pub stats: SyncStats,
}

/// A category found upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCategory {
    pub identity: UpdateRevision,
    /// `CategoryType` of a `CategoryInformation` element, when the metadata
    /// carries one (location in the blob is Unverified).
    pub category_type: Option<String>,
    /// English localized title, falling back to the first available title.
    pub title: Option<String>,
}

/// Result of category discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub categories: Vec<DiscoveredCategory>,
    pub detectoids: usize,
}

struct Lists {
    config: wsus_protocol::wsusss::ServerSyncConfigData,
    categories: RevisionList,
    updates: RevisionList,
}

/// Observer of committed metadata batch counters.
type ProgressCallback = Arc<dyn Fn(&SyncStats) + Send + Sync>;

/// Synchronizes one upstream source into the catalog.
pub struct UpstreamSync<T: Transport, S: RetryTimer> {
    catalog: Catalog,
    pub(super) client: WsusssClient<T, S>,
    pub(super) config: UpstreamConfig,
    source: SourceId,
    progress: Option<ProgressCallback>,
}

fn find_category_type(el: &wsus_protocol::soap::Element) -> Option<String> {
    if el.name.local == "CategoryInformation"
        && let Some(t) = el.attr("CategoryType")
    {
        return Some(t.to_owned());
    }
    el.elements().find_map(find_category_type)
}

fn find_title(el: &wsus_protocol::soap::Element) -> Option<String> {
    if el.name.local == "Title" {
        return Some(el.text());
    }
    el.elements().find_map(find_title)
}

fn find_english_title(el: &wsus_protocol::soap::Element) -> Option<String> {
    if el.name.local == "LocalizedProperties" {
        let language = el.attr("Language").map(str::to_owned).or_else(|| {
            el.elements()
                .find(|c| c.name.local == "Language")
                .map(|c| c.text())
        });
        if language.is_some_and(|s| s.eq_ignore_ascii_case("en") || s.eq_ignore_ascii_case("en-US"))
        {
            return find_title(el);
        }
    }
    el.elements().find_map(find_english_title)
}

impl<T: Transport, S: RetryTimer> UpstreamSync<T, S> {
    /// Bind the orchestrator to a source, creating it when absent.
    pub fn new(
        catalog: Catalog,
        client: WsusssClient<T, S>,
        config: UpstreamConfig,
    ) -> Result<Self, UpstreamError> {
        if config.import_batch == 0
            || !(1..=32).contains(&config.download_concurrency)
            || !(1..=16).contains(&config.metadata_concurrency)
        {
            return Err(UpstreamError::Invalid(
                "import_batch must be positive; download_concurrency must be 1..=32 and metadata_concurrency 1..=16".into(),
            ));
        }
        let source = match catalog.source_by_name(&config.source_name)? {
            Some(s) if s.kind == SourceKind::Upstream => s.id,
            Some(_) => {
                return Err(UpstreamError::Invalid(format!(
                    "source {} exists and is not an upstream source",
                    config.source_name
                )));
            }
            None => {
                catalog.add_source(&config.source_name, SourceKind::Upstream, "upstream WSUS")?
            }
        };
        Ok(Self {
            catalog,
            client,
            config,
            source,
            progress: None,
        })
    }

    /// Receive staged metadata counters after each committed import batch.
    pub fn with_progress(mut self, progress: ProgressCallback) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Catalog source id.
    pub fn source(&self) -> SourceId {
        self.source
    }

    /// Catalog handle.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Protocol client.
    pub fn client_mut(&mut self) -> &mut WsusssClient<T, S> {
        &mut self.client
    }

    async fn fetch_parallel(
        &self,
        requested: &[UpdateRevision],
    ) -> Result<UpdateBatch, UpstreamError> {
        let mut calls = stream::iter(requested.chunks(self.client.update_batch_size()).map(
            |ids| {
                let mut client = self.client.fork();
                async move { client.get_update_data(ids).await }
            },
        ))
        .buffered(self.config.metadata_concurrency);
        let mut combined = UpdateBatch::default();
        while let Some(result) = calls.next().await {
            let batch = result?;
            combined.updates.extend(batch.updates);
            combined.file_locations.extend(batch.file_locations);
        }
        Ok(combined)
    }

    /// Checkpoint of the active generation, if any.
    pub fn committed_checkpoint(&self) -> Result<Option<Checkpoint>, UpstreamError> {
        Ok(self.committed()?.and_then(|(_, cp)| cp))
    }

    #[allow(clippy::type_complexity)]
    fn committed(&self) -> Result<Option<(GenerationId, Option<Checkpoint>)>, UpstreamError> {
        let Some(g) = self.catalog.active_generation(self.source)? else {
            return Ok(None);
        };
        let anchor = self.catalog.generation(g)?.anchor;
        Ok(Some((g, anchor.as_deref().and_then(Checkpoint::decode))))
    }

    /// Stage and activate. Safe to call again after any failure or crash.
    pub async fn run(&mut self) -> Result<SyncReport, UpstreamError> {
        match self.stage().await? {
            StageOutcome::NoChange => Ok(SyncReport {
                outcome: SyncOutcome::NoChange,
                stats: SyncStats::default(),
            }),
            StageOutcome::Staged(staged) => self.activate(staged),
        }
    }

    /// Validate and activate a staged generation. The checkpoint stored with
    /// the generation becomes the committed one in the same transaction.
    pub fn activate(&self, staged: StagedSync) -> Result<SyncReport, UpstreamError> {
        match self.catalog.activate(staged.generation)? {
            ActivateOutcome::Rejected(report) => Err(UpstreamError::Rejected {
                generation: staged.generation,
                report,
            }),
            ActivateOutcome::Activated { fragments } => {
                if let Some(keep) = self.config.keep_superseded {
                    self.catalog.prune_superseded(self.source, keep)?;
                }
                Ok(SyncReport {
                    outcome: SyncOutcome::Activated {
                        generation: staged.generation,
                        fragments,
                        checkpoint: staged.checkpoint,
                    },
                    stats: staged.stats,
                })
            }
        }
    }

    async fn fetch_lists(&mut self, anchors: &Checkpoint) -> Result<Lists, UpstreamError> {
        let config = self
            .client
            .get_config_data(anchors.config_anchor.as_deref())
            .await?;
        let categories = self
            .client
            .get_revision_ids(&RevisionQuery {
                anchor: anchors.category_anchor.clone(),
                get_config: true,
                ..RevisionQuery::default()
            })
            .await?;
        // Observed on a real WSUS (inventory 9.5): the wire filter selects an update only
        // when BOTH a listed product and a listed classification match, and a filter that
        // lists only one of the two returns nothing. So it is sent only when both lists are
        // configured; otherwise the filter is applied locally.
        let wire = self.config.send_wire_filter
            && !self.config.filter.products.is_empty()
            && !self.config.filter.classifications.is_empty();
        let updates = self
            .client
            .get_revision_ids(&RevisionQuery {
                anchor: anchors.update_anchor.clone(),
                get_config: false,
                categories: if wire {
                    self.config.filter.products.clone()
                } else {
                    Vec::new()
                },
                classifications: if wire {
                    self.config.filter.classifications.clone()
                } else {
                    Vec::new()
                },
            })
            .await?;
        Ok(Lists {
            config,
            categories,
            updates,
        })
    }

    /// Discover the categories the upstream offers (initial anchors; nothing
    /// is staged).
    pub async fn discover_categories(&mut self) -> Result<Discovery, UpstreamError> {
        self.client.get_config_data(None).await?;
        let list = self
            .client
            .get_revision_ids(&RevisionQuery {
                get_config: true,
                ..RevisionQuery::default()
            })
            .await?;
        let mut out = Discovery::default();
        let mut queue: std::collections::VecDeque<_> = list.revisions.into_iter().collect();
        while !queue.is_empty() {
            let n = (self.client.update_batch_size() * self.config.metadata_concurrency)
                .min(queue.len());
            let requested: Vec<_> = queue.drain(..n).collect();
            let batch = self.fetch_parallel(&requested).await?;
            let wanted: BTreeSet<_> = requested.iter().copied().collect();
            let got: BTreeSet<_> = batch.updates.iter().map(|r| r.identity).collect();
            if got.is_empty() {
                return Err(UpstreamError::MissingUpdateData(requested[0]));
            }
            if let Some(extra) = got.difference(&wanted).next() {
                return Err(UpstreamError::UnrequestedUpdateData(*extra));
            }
            for id in requested.iter().rev().filter(|id| !got.contains(id)) {
                queue.push_front(*id);
            }
            for record in batch.updates {
                let index = record.fragment.index(&self.config.limits).map_err(|e| {
                    UpstreamError::Metadata {
                        identity: record.identity,
                        reason: e.to_string(),
                    }
                })?;
                match index.properties.update_type {
                    Some(UpdateType::Category) => {
                        let category_type = index
                            .extensions
                            .iter()
                            .find_map(|x| find_category_type(&x.element));
                        out.categories.push(DiscoveredCategory {
                            identity: record.identity,
                            category_type,
                            title: wsus_protocol::soap::xml::parse(
                                record.fragment.xml(),
                                &self.config.limits,
                            )
                            .ok()
                            .and_then(|root| {
                                find_english_title(&root).or_else(|| find_title(&root))
                            }),
                        });
                    }
                    Some(UpdateType::Detectoid) => out.detectoids += 1,
                    _ => {}
                }
            }
        }
        Ok(out)
    }

    /// Stage a generation for the current upstream state, resuming an
    /// interrupted one when its pending checkpoint still matches. Nothing is
    /// activated.
    pub async fn stage(&mut self) -> Result<StageOutcome, UpstreamError> {
        let committed = self.committed()?;
        let filter_fp = self.config.filter.fingerprint();
        let mut stats = SyncStats::default();
        let mut full = match &committed {
            None => {
                stats.reset = Some(ResetReason::Initial);
                true
            }
            Some((_, None)) => {
                stats.reset = Some(ResetReason::CheckpointUnreadable);
                true
            }
            Some((_, Some(cp))) if cp.endpoint != self.config.endpoint_key => {
                stats.reset = Some(ResetReason::EndpointChanged);
                true
            }
            Some((_, Some(cp))) if cp.filter != filter_fp => {
                stats.reset = Some(ResetReason::FilterChanged);
                true
            }
            Some(_) => false,
        };
        let committed_cp = committed.as_ref().and_then(|(_, cp)| cp.clone());
        let lists = loop {
            let anchors = match (&committed_cp, full) {
                (Some(cp), false) => cp.clone(),
                _ => Checkpoint::new(&self.config.endpoint_key, &filter_fp),
            };
            match self.fetch_lists(&anchors).await {
                Ok(l) => break l,
                Err(UpstreamError::Wsusss(e)) if e.is_server_changed() && !full => {
                    full = true;
                    stats.reset = Some(ResetReason::ServerChanged);
                }
                Err(e) => return Err(e),
            }
        };

        let staging = ext::staging_generations(&self.catalog, self.source)?;
        if !full && lists.categories.revisions.is_empty() && lists.updates.revisions.is_empty() {
            for (g, _) in staging {
                self.catalog
                    .fail_generation(g, "superseded: upstream reports no change")?;
            }
            return Ok(StageOutcome::NoChange);
        }

        let mut pending = Checkpoint::new(&self.config.endpoint_key, &filter_fp);
        pending.config_anchor = lists.config.new_config_anchor.value().cloned();
        pending.category_anchor = lists.categories.anchor.clone();
        pending.update_anchor = lists.updates.anchor.clone();
        pending.full = full;
        let pending_json = pending.encode();

        let mut resumed = None;
        for (g, anchor) in staging {
            if resumed.is_none() && anchor.as_deref() == Some(pending_json.as_str()) {
                resumed = Some(g);
            } else {
                self.catalog
                    .fail_generation(g, "stale or duplicate staging generation")?;
            }
        }
        stats.resumed = resumed.is_some();
        let generation = match resumed {
            Some(g) => g,
            None => self
                .catalog
                .begin_generation(self.source, Some(&pending_json))?,
        };

        let mut staged = ext::generation_identities(&self.catalog, generation)?;
        let prior = match &committed {
            Some((g, _)) => ext::generation_identities(&self.catalog, *g)?,
            None => BTreeMap::new(),
        };
        let mut listed: Vec<UpdateRevision> = Vec::new();
        let mut seen = BTreeSet::new();
        for r in lists
            .categories
            .revisions
            .iter()
            .chain(&lists.updates.revisions)
        {
            if seen.insert(*r) {
                listed.push(*r);
            }
        }
        stats.listed = listed.len();
        let listed_set: BTreeSet<UpdateRevision> = listed.iter().copied().collect();
        let mut known_revisions: BTreeSet<UpdateRevision> = BTreeSet::new();
        known_revisions.extend(staged.keys());
        known_revisions.extend(&listed_set);
        known_revisions.extend(prior.keys());
        let known_ids: BTreeSet<UpdateId> = known_revisions.iter().map(|r| r.id).collect();
        let max_listed: BTreeMap<UpdateId, u32> = {
            let mut m: BTreeMap<UpdateId, u32> = BTreeMap::new();
            for r in &listed {
                let e = m.entry(r.id).or_insert(0);
                *e = (*e).max(r.revision.0);
            }
            m
        };

        // Fetch metadata not yet staged.
        let todo: Vec<UpdateRevision> = listed
            .iter()
            .copied()
            .filter(|r| !staged.contains_key(r))
            .collect();
        self.fetch_and_import(
            generation,
            &todo,
            true,
            &known_ids,
            &known_revisions,
            &mut staged,
            &mut stats,
        )
        .await?;

        // Carry over the previous generation.
        if let Some((prior_gen, _)) = &committed {
            self.carry_over(
                generation,
                *prior_gen,
                full,
                &listed_set,
                &max_listed,
                &mut staged,
                &mut stats,
            )?;
        }

        // Pull in excluded revisions that staged ones depend on.
        for _ in 0..self.config.closure_rounds {
            let report = self.catalog.validate(generation)?;
            let missing: BTreeSet<UpdateId> = report
                .issues
                .iter()
                .filter(|i| i.problem == IssueKind::MissingTarget)
                .map(|i| i.target)
                .collect();
            let pull: Vec<UpdateRevision> = listed
                .iter()
                .copied()
                .filter(|r| missing.contains(&r.id) && !staged.contains_key(r))
                .collect();
            if pull.is_empty() {
                break;
            }
            let before = stats.fetched;
            self.fetch_and_import(
                generation,
                &pull,
                false,
                &known_ids,
                &known_revisions,
                &mut staged,
                &mut stats,
            )
            .await?;
            stats.pulled_by_dependency += stats.fetched - before;
        }

        Ok(StageOutcome::Staged(StagedSync {
            generation,
            checkpoint: pending,
            stats,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch_and_import(
        &mut self,
        generation: GenerationId,
        todo: &[UpdateRevision],
        apply_filter: bool,
        known_ids: &BTreeSet<UpdateId>,
        known_revisions: &BTreeSet<UpdateRevision>,
        staged: &mut BTreeMap<UpdateRevision, FragmentState>,
        stats: &mut SyncStats,
    ) -> Result<(), UpstreamError> {
        // OBSERVED on a real Windows Server 2025 WSUS with a Windows 11 catalog: one `GetUpdateData`
        // batch of 100 revisions answered with the first 80 (a 2.6 MB response); the others are asked
        // for again. A batch that returns nothing is still a failure.
        let mut queue: std::collections::VecDeque<UpdateRevision> = todo.iter().copied().collect();
        while !queue.is_empty() {
            let n = (self.client.update_batch_size() * self.config.metadata_concurrency)
                .min(queue.len())
                .max(1);
            let requested: Vec<UpdateRevision> = queue.drain(..n).collect();
            let batch = self.fetch_parallel(&requested).await?;
            let wanted: BTreeSet<UpdateRevision> = requested.iter().copied().collect();
            let mut got: BTreeMap<UpdateRevision, UpdateRecord> = BTreeMap::new();
            for record in batch.updates {
                if !wanted.contains(&record.identity) {
                    return Err(UpstreamError::UnrequestedUpdateData(record.identity));
                }
                got.insert(record.identity, record);
            }
            if got.is_empty() {
                return Err(UpstreamError::MissingUpdateData(requested[0]));
            }
            let unanswered: Vec<UpdateRevision> = requested
                .iter()
                .filter(|id| !got.contains_key(id))
                .copied()
                .collect();
            for id in unanswered.into_iter().rev() {
                queue.push_front(id);
            }
            let requested: Vec<UpdateRevision> = requested
                .into_iter()
                .filter(|id| got.contains_key(id))
                .collect();
            let mut imports: Vec<FragmentImport> = Vec::new();
            for id in &requested {
                let record = got.get(id).ok_or(UpstreamError::MissingUpdateData(*id))?;
                let Converted {
                    import,
                    categories,
                    filterable,
                    withdrawn,
                    files_without_descriptor,
                } = convert(record, known_ids, known_revisions, &self.config.limits)?;
                if apply_filter && filterable && !self.config.filter.accepts(&categories) {
                    stats.excluded_by_filter += 1;
                    continue;
                }
                stats.files_without_descriptor += files_without_descriptor;
                if withdrawn {
                    stats.withdrawn += 1;
                }
                staged.insert(import.identity, import.state);
                imports.push(import);
            }
            if !imports.is_empty() {
                stats.fetched += imports.len();
                self.import_checked(generation, &imports, staged)?;
                if let Some(progress) = &self.progress {
                    progress(stats);
                }
            }
        }
        Ok(())
    }

    fn import_checked(
        &self,
        generation: GenerationId,
        imports: &[FragmentImport],
        staged: &mut BTreeMap<UpdateRevision, FragmentState>,
    ) -> Result<(), UpstreamError> {
        if let Err(e) = self.catalog.import_fragments(generation, imports) {
            for i in imports {
                staged.remove(&i.identity);
            }
            return Err(e.into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn carry_over(
        &self,
        generation: GenerationId,
        prior_gen: GenerationId,
        full: bool,
        listed: &BTreeSet<UpdateRevision>,
        max_listed: &BTreeMap<UpdateId, u32>,
        staged: &mut BTreeMap<UpdateRevision, FragmentState>,
        stats: &mut SyncStats,
    ) -> Result<(), UpstreamError> {
        let snapshot = self.catalog.snapshot_of(prior_gen)?;
        let mut after = None;
        let mut buffer: Vec<FragmentImport> = Vec::new();
        loop {
            let page = snapshot.list(after, 500, true)?;
            for record in page.items {
                let identity = record.identity;
                if staged.contains_key(&identity) || listed.contains(&identity) {
                    continue;
                }
                let superseded_by_listed = max_listed
                    .get(&identity.id)
                    .is_some_and(|m| *m > identity.revision.0);
                let tombstone =
                    full && !superseded_by_listed && record.state != FragmentState::Deleted;
                let import = if tombstone {
                    stats.tombstoned += 1;
                    let mut i = FragmentImport::new(identity, &record.kind, &record.core_xml);
                    i.state = FragmentState::Deleted;
                    i.extended_xml = record.extended_xml.clone();
                    i
                } else {
                    stats.carried += 1;
                    let mut i = FragmentImport::new(identity, &record.kind, &record.core_xml);
                    i.state = record.state;
                    i.extended_xml = record.extended_xml.clone();
                    i.relationships = snapshot
                        .relationships(record.local)?
                        .into_iter()
                        .map(|r| RelationshipImport {
                            kind: r.kind,
                            target: r.target,
                            revision: r.revision,
                        })
                        .collect();
                    i.files = snapshot.files(record.local)?;
                    i
                };
                staged.insert(identity, import.state);
                buffer.push(import);
                if buffer.len() >= self.config.import_batch {
                    self.import_checked(generation, &buffer, staged)?;
                    buffer.clear();
                }
            }
            match page.next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        if !buffer.is_empty() {
            self.import_checked(generation, &buffer, staged)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn selects_english_title_when_the_first_localization_uses_another_language() {
        let root = wsus_protocol::soap::xml::parse(b"<Update><LocalizedPropertiesCollection><LocalizedProperties><Language>ar</Language><Title>first</Title></LocalizedProperties><LocalizedProperties><Language>en</Language><Title>Critical Updates</Title></LocalizedProperties></LocalizedPropertiesCollection></Update>", &wsus_protocol::soap::Limits::default()).unwrap();
        assert_eq!(
            find_english_title(&root).as_deref(),
            Some("Critical Updates")
        );
    }
}
