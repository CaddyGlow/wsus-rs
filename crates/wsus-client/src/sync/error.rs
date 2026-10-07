//! Errors of the synchronization layer.

use crate::{
    download::DownloadError,
    session::{StorageError, WuspError},
};
use wsus_protocol::{ProtocolError, identity::UpdateRevision};

/// Failures of synchronization, metadata, acquisition and reporting.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Session or protocol operation failed (transport, HTTP, fault, ...).
    #[error(transparent)]
    Session(#[from] WuspError),
    /// Local persistence failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Metadata could not be interpreted.
    #[error("metadata ({context}): {source}")]
    Metadata {
        context: String,
        #[source]
        source: ProtocolError,
    },
    /// A verified download failed.
    #[error(transparent)]
    Download(#[from] DownloadError),
    /// The server kept reporting a truncated result without delivering
    /// anything new; synchronization stops instead of looping.
    #[error("server reported a truncated result without progress")]
    NoProgress,
    /// The server answered `InvalidParameters` to a `SyncUpdates` call whose
    /// cached-id lists had already been capped; retrying the same lists
    /// cannot succeed, so the run stops. Lower
    /// `SessionConfig::installed_non_leaf_limit` if the server's cap is
    /// smaller than configured.
    #[error(
        "server rejected SyncUpdates parameters ({detail}); sent {installed} installed non-leaf \
         ids (limit {limit}) and {other} other cached ids"
    )]
    CachedListRejected {
        installed: usize,
        other: usize,
        limit: usize,
        detail: String,
    },
    /// More pages than `SyncOptions::max_pages`.
    #[error("synchronization exceeded {0} pages")]
    TooManyPages(u32),
    /// The revision is not in the local cache, so it has no server-local id.
    #[error("revision {0} is not in the local cache")]
    UnknownRevision(UpdateRevision),
    /// The server returned a location that is not an http(s) URL.
    #[error("server returned an invalid file location")]
    InvalidLocation,
    /// `ReportEventBatch` answered `false`.
    #[error("server did not accept the event batch")]
    ReportRejected,
}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        Self::Storage(e.into())
    }
}

impl From<serde_json::Error> for SyncError {
    fn from(e: serde_json::Error) -> Self {
        Self::Storage(e.into())
    }
}

impl From<crate::state::StateError> for SyncError {
    fn from(e: crate::state::StateError) -> Self {
        Self::Storage(e.into())
    }
}

impl From<crate::reporting::QueueError> for SyncError {
    fn from(e: crate::reporting::QueueError) -> Self {
        Self::Storage(e.into())
    }
}
