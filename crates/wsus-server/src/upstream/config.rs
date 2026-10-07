use std::collections::BTreeSet;

use wsus_protocol::identity::UpdateId;
use wsus_protocol::soap::Limits;

/// Which software revisions to keep. Matching is by the category ids a
/// revision lists in its `IsCategory` prerequisite clauses. Both lists empty
/// keeps everything; otherwise a revision needs one id from each non-empty
/// list. Categories, classifications and detectoids themselves are always
/// kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CategoryFilter {
    /// Product category ids.
    pub products: Vec<UpdateId>,
    /// Update classification ids.
    pub classifications: Vec<UpdateId>,
}

impl CategoryFilter {
    /// True when no restriction applies.
    pub fn is_empty(&self) -> bool {
        self.products.is_empty() && self.classifications.is_empty()
    }

    /// Whether a revision listing `categories` passes.
    pub fn accepts(&self, categories: &BTreeSet<UpdateId>) -> bool {
        let hit = |wanted: &[UpdateId]| {
            wanted.is_empty() || wanted.iter().any(|w| categories.contains(w))
        };
        hit(&self.products) && hit(&self.classifications)
    }

    /// Stable identity of the filter; a change forces a full resynchronization.
    pub fn fingerprint(&self) -> String {
        let join = |v: &[UpdateId]| {
            let mut ids: Vec<String> = v.iter().map(|u| u.to_string()).collect();
            ids.sort();
            ids.dedup();
            ids.join(",")
        };
        format!(
            "p:{};c:{}",
            join(&self.products),
            join(&self.classifications)
        )
    }
}

/// Settings of one upstream source.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Catalog source name (created as an upstream source when absent).
    pub source_name: String,
    /// Identity of the upstream endpoint (for example its base URL or a
    /// configured server name). A change forces a full resynchronization with
    /// reset anchors. The protocol offers no server identity of its own that
    /// is verified here; `ServerChanged` faults are handled separately.
    pub endpoint_key: String,
    /// Category filter.
    pub filter: CategoryFilter,
    /// Also send the filter in `GetRevisionIdList`. Observed on one real WSUS
    /// (inventory 9.5): an update matches only if one listed product AND one
    /// listed classification match, and a filter naming only one of the two
    /// returns nothing, so it is sent only when both lists are non-empty. The
    /// filter is enforced locally either way.
    pub send_wire_filter: bool,
    /// Simultaneous content downloads; metadata/session operations stay serialized.
    pub download_concurrency: usize,
    /// Simultaneous read-only metadata batches with independent client sessions.
    pub metadata_concurrency: usize,
    /// Fragments per `import_fragments` call while carrying over.
    pub import_batch: usize,
    /// Rounds of pulling in excluded prerequisites before validation.
    pub closure_rounds: usize,
    /// Keep this many superseded generations after activation (`None`: no pruning).
    pub keep_superseded: Option<usize>,
    /// Limits for parsing update metadata.
    pub limits: Limits,
}

impl UpstreamConfig {
    /// Defaults for a source.
    pub fn new(source_name: &str, endpoint_key: &str) -> Self {
        Self {
            source_name: source_name.to_owned(),
            endpoint_key: endpoint_key.to_owned(),
            filter: CategoryFilter::default(),
            send_wire_filter: true,
            download_concurrency: 1,
            metadata_concurrency: 1,
            import_batch: 200,
            closure_rounds: 5,
            keep_superseded: Some(2),
            limits: Limits::stored_documents(),
        }
    }
}
