//! Synchronization of update metadata and content over MS-WUSP.
//!
//! * [`SyncEngine`]: `SyncUpdates` with continuation and cached revisions,
//!   `GetExtendedUpdateInfo[2]`, `GetFileLocations`, verified acquisition and
//!   event reporting.
//! * [`RevisionStore`]: durable per-revision metadata records.
//! * [`Catalog`]: relationships and selection by `UpdateRevision`, with the
//!   acquisition closure kept separate from installation applicability.
//! * [`select_localized`]: localized metadata selection.
//!
//! Nothing here has been validated against a real WSUS server; behaviour
//! follows the pinned specification and is tested against in-process fakes.

mod acquire;
mod catalog;
mod engine;
mod error;
mod localized;
mod report;
mod store;

pub use acquire::{AcquireReport, FileOutcome, FileStatus};
pub use catalog::{
    AcquisitionClosure, Catalog, CatalogEntry, ClosureOptions, FileRequirement, MissingRef,
    PrerequisiteRef, Relationships, UnusableFile,
};
pub use engine::{FragmentReport, ResolvedLocation, SyncEngine, SyncOptions, SyncReport};
pub use error::SyncError;
pub use localized::{LocalizedProperties, select_localized};
pub use report::{EventDetail, ReportEvent, ReportOutcome};
pub use store::{DeploymentSummary, RevisionRecord, RevisionStore, StoredFragment};
