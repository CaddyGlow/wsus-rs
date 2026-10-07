use wsus_client::wsusss::WsusssError;
use wsus_protocol::identity::UpdateRevision;

use crate::catalog::{GenerationId, ValidationReport};
use crate::storage;

/// Failure of an upstream operation.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream protocol failure: {0}")]
    Wsusss(#[from] WsusssError),
    #[error("catalog failure: {0}")]
    Catalog(#[from] storage::Error),
    #[error("metadata of {identity} is unusable: {reason}")]
    Metadata {
        identity: UpdateRevision,
        reason: String,
    },
    #[error("upstream returned no data for requested revision {0}")]
    MissingUpdateData(UpdateRevision),
    #[error("upstream returned data for unrequested revision {0}")]
    UnrequestedUpdateData(UpdateRevision),
    /// Relationship validation failed; the generation is kept as failed
    /// evidence and the committed catalog and checkpoint are unchanged.
    #[error("generation {} rejected: {} relationship issues", generation.0, report.issues.len())]
    Rejected {
        generation: GenerationId,
        report: ValidationReport,
    },
    #[error("invalid upstream configuration: {0}")]
    Invalid(String),
    #[error("i/o failure: {0}")]
    Io(#[from] std::io::Error),
}
