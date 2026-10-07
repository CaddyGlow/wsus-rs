//! Downstream orchestration of an upstream WSUS source into the catalog
//! (autonomous mode; replica mode and deployments are out of scope).
//!
//! Flow of one synchronization ([`UpstreamSync::run`]):
//!
//! 1. authorize and read the upstream configuration (`GetConfigData`);
//! 2. `GetRevisionIdList` for categories/classifications/detectoids and for
//!    software revisions, from the committed anchors;
//! 3. stage everything in a catalog generation: fetch metadata in batches
//!    (`GetUpdateData`), carry over unchanged revisions of the previous active
//!    generation, tombstone revisions a full resync no longer lists, and pull
//!    in prerequisites that a filter excluded;
//! 4. validate relationships and only then activate.
//!
//! The pending checkpoint (all anchors plus the endpoint and filter identity)
//! is stored as the generation's anchor when the generation begins, so the
//! checkpoint becomes the committed one in the same SQLite transaction that
//! activates the generation. An interrupted staging generation whose pending
//! checkpoint equals the freshly computed one is resumed without refetching
//! what it already holds; anything else is failed and kept as evidence.
//!
//! Metadata synchronization and file acquisition are separate operations with
//! separate results ([`SyncReport`] versus [`ContentReport`]): a content
//! failure never affects the committed catalog. Locally managed approvals live
//! in the policy module and are never read from or written to upstream data.
//!
//! Evidence status: exercised against fake upstreams written in the tests of this crate
//! and, on 2026-10-04, once against a real WSUS upstream (Windows Server 2025
//! 10.0.26100, anonymous, HTTP, the Defender catalog; inventory 9.5, validation rows C15 to
//! C18, `Partially validated`): the compressed-metadata format, the wire filter and `Delta`
//! semantics, the anchor behavior, the content URL rule and `PublicationState` `Expired`
//! for withdrawn revisions were observed there. Still open: recovery against a real
//! upstream, revision changes and withdrawals arriving after the first sync, `ServerChanged`,
//! `DownloadFiles`, other builds. The WSUSSS update blob is a complete update document. That
//! document is stored unmodified in the Core slot; the MS-WUSP
//! Core, Extended, Localized and Eula fragments are derived from it on read by
//! [`crate::fragments`] (checked against real fragments for nine revisions, C30), so the
//! MS-WUSP server can serve what this importer stores.
//!
//! Startup note: [`crate::catalog::Catalog::abandon_interrupted`] fails every
//! staging generation of every source, which would discard resumable upstream work. At
//! startup call [`crate::catalog::Catalog::recover_after_restart`] (skips upstream
//! sources) or [`crate::catalog::Catalog::abandon_interrupted_in`] with an explicit
//! [`crate::catalog::AbandonScope`]; [`UpstreamSync::stage`] itself resumes the matching
//! staging generation and fails stale ones.
mod checkpoint;
mod config;
mod content;
mod convert;
mod error;
mod ext;
mod sync;

pub use checkpoint::Checkpoint;
pub use config::{CategoryFilter, UpstreamConfig};
pub use content::{ContentFailure, ContentReport, ContentSelection};
pub use error::UpstreamError;
pub use sync::{
    DiscoveredCategory, Discovery, ResetReason, StageOutcome, StagedSync, SyncOutcome, SyncReport,
    SyncStats, UpstreamSync,
};
