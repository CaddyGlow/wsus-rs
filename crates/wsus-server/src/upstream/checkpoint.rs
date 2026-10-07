use serde::{Deserialize, Serialize};

const CHECKPOINT_VERSION: u32 = 1;

/// Synchronization checkpoint stored as a generation's anchor.
///
/// Anchors are opaque to the protocol and kept verbatim. A staging
/// generation carries the checkpoint it will have once activated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Format version.
    pub version: u32,
    /// Upstream endpoint identity.
    pub endpoint: String,
    /// Filter fingerprint.
    pub filter: String,
    /// `NewConfigAnchor` of `GetConfigData`.
    pub config_anchor: Option<String>,
    /// Anchor of `GetRevisionIdList` with `GetConfig=true`.
    pub category_anchor: Option<String>,
    /// Anchor of `GetRevisionIdList` with `GetConfig=false`.
    pub update_anchor: Option<String>,
    /// Whether the generation was a full resynchronization.
    pub full: bool,
}

impl Checkpoint {
    pub(crate) fn new(endpoint: &str, filter: &str) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            endpoint: endpoint.to_owned(),
            filter: filter.to_owned(),
            config_anchor: None,
            category_anchor: None,
            update_anchor: None,
            full: true,
        }
    }

    /// Deterministic text form.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("checkpoint serializes")
    }

    /// Parse; `None` for foreign or unknown-version text.
    pub fn decode(text: &str) -> Option<Self> {
        let c: Self = serde_json::from_str(text).ok()?;
        (c.version == CHECKPOINT_VERSION).then_some(c)
    }
}
