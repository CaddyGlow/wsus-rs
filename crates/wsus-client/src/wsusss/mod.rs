//! MS-WSUSSS downstream client (autonomous mode).
//!
//! Evidence status: message shapes come from the pinned MS-WSUSSS 17.0 text
//! through `wsus-protocol`; one real WSUS (Windows Server 2025 10.0.26100) has
//! been exercised with them, see inventory 9.5. Points the specification leaves open are marked
//! "Unverified" and, where a choice was needed, "Implementation decision":
//!
//! * `XmlUpdateBlobCompressed` has no documented format (inventory section 8
//!   item 11); the real server's blob was observed to be a one-member LZX
//!   Cabinet of UTF-16LE XML (inventory 9.5) and [`CabMetadataDecompressor`],
//!   the default, reads exactly that. [`MetadataDecompressor`] stays
//!   injectable.
//! * The meaning of the `Categories` / `Classifications` filter and its
//!   `Delta` flag is undocumented (item 10); callers choose whether to send it.
//! * The content folder rule is ambiguous (item 1); [`ContentFolderRule`] is a
//!   configuration choice and the file name is the lower-case hex SHA-1.
//! * Session handling follows the recovery table (inventory section 7.2):
//!   `InvalidCookie` and `InvalidAuthorizationCookie` restart authorization, a
//!   bounded number of times; `ServerChanged` is surfaced to the caller, which
//!   owns the anchors; `ServerBusy` is retried a bounded number of times.
//!
//! Signed URLs received from the upstream (`fileUrls`) are wrapped in
//! [`crate::download::Location`] and [`crate::transport::SecretBytes`], are
//! never serialized and are redacted in `Debug` output.

mod client;
mod clock;
mod compress;
mod config;
mod error;
mod types;

pub use client::WsusssClient;
pub use clock::{Clock, SystemClock, parse_unix};
pub use compress::{
    CabMetadataDecompressor, DecompressError, MAX_METADATA_BYTES, MetadataDecompressor,
    UnsupportedDecompressor,
};
pub use config::{
    ContentFolderRule, MAX_DOWNLOAD_FILES_DIGESTS, MAX_UPDATE_RESPONSE_BYTES, WsusssConfig,
};
pub use error::WsusssError;
pub use types::{FileLocation, RevisionList, RevisionQuery, UpdateBatch, UpdateRecord};
