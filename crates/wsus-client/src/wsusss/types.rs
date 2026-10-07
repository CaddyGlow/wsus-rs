//! Results handed to callers.
use wsus_protocol::identity::UpdateRevision;
use wsus_protocol::metadata::RawFragment;

use crate::download::Location;
use crate::transport::SecretBytes;

/// Result of `GetRevisionIdList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionList {
    /// Opaque anchor of this response; store it only after the whole phase
    /// committed.
    pub anchor: Option<String>,
    /// Revisions changed after the request anchor (one per update GUID).
    pub revisions: Vec<UpdateRevision>,
}

/// Parameters of `GetRevisionIdList`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevisionQuery {
    /// Anchor of the previous successful response; `None` for the first call.
    pub anchor: Option<String>,
    /// True for categories, classifications and detectoids; false for
    /// software and driver revisions.
    pub get_config: bool,
    /// Product filter sent on the wire. Observed on one real WSUS (inventory
    /// 9.5): an update matches only when a listed product AND a listed
    /// classification match, so send both lists or neither.
    pub categories: Vec<wsus_protocol::identity::UpdateId>,
    /// Classification filter sent on the wire (see `categories`). `Delta` is
    /// `true` exactly when [`RevisionQuery::anchor`] is set.
    pub classifications: Vec<wsus_protocol::identity::UpdateId>,
}

/// One revision's metadata from `GetUpdateData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRecord {
    /// Revision identity from the response.
    pub identity: UpdateRevision,
    /// Metadata with provenance; compressed blobs are already decompressed.
    pub fragment: RawFragment,
    /// SHA-1 digests the upstream listed for the revision's files.
    pub file_digests: Vec<Vec<u8>>,
}

/// Transient content locations for one file digest. Never persisted.
#[derive(Debug, Clone)]
pub struct FileLocation {
    /// SHA-1 digest.
    pub digest: Vec<u8>,
    /// Microsoft Update URL.
    pub mu: Option<Location>,
    /// URL on the upstream server.
    pub uss: Option<Location>,
    /// Decryption key of encrypted content (decryption is not implemented).
    pub decryption_key: Option<SecretBytes>,
}

/// Merged result of one or more `GetUpdateData` calls.
#[derive(Debug, Clone, Default)]
pub struct UpdateBatch {
    /// Metadata records in response order.
    pub updates: Vec<UpdateRecord>,
    /// Locations, valid only for this process run.
    pub file_locations: Vec<FileLocation>,
}
