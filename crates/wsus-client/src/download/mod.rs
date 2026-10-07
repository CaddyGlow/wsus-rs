//! Verified, resumable content acquisition.
//!
//! Layout under the downloader root:
//!
//! ```text
//! partial/<content-id>.part   bytes received so far (never a complete object)
//! partial/<content-id>.json   sidecar: descriptor + validated length + prefix hash
//! complete/<content-id>/<file name>   verified object, promoted atomically
//! ```
//!
//! A partial object is resumed only when its sidecar matches the expected
//! descriptor exactly and the prefix hash recorded at the last checkpoint
//! matches the bytes on disk; otherwise it is discarded. Unproven bytes are
//! never trusted, and the final digests are always checked over the whole file.
//! Signed location URLs are transient arguments: they are never written to the
//! sidecar, to logs, or to `Debug` output.

mod descriptor;
mod digest;
mod downloader;

pub use descriptor::{ExpectedFile, digest_len, validate_file_name};
pub use digest::{Hashers, hex_decode, hex_encode};
pub use downloader::{DownloadLimits, DownloadOptions, DownloadedFile, Downloader, Location};

use crate::transport::TransportError;
use std::{io, time::Duration};
use wsus_protocol::identity::DigestAlgorithm;

/// Download failures. Messages never contain URLs or credentials.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("invalid file name: {0}")]
    InvalidFileName(&'static str),
    #[error("invalid descriptor: {0}")]
    InvalidDescriptor(&'static str),
    #[error("object of {length} bytes exceeds the {limit} byte limit")]
    TooLarge { length: u64, limit: u64 },
    #[error("concurrent download limit reached")]
    Busy,
    #[error("a download of this content is already running")]
    AlreadyInProgress,
    #[error("reserved byte budget exhausted")]
    ReservationExceeded,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("unexpected HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after: Option<Duration>,
    },
    #[error("server ignored the range request and returned the full object")]
    RangeIgnored,
    #[error("range not satisfiable; partial object discarded")]
    RangeNotSatisfiable,
    #[error("range response mismatch: {0}")]
    RangeMismatch(&'static str),
    #[error("response uses a content encoding")]
    UnexpectedEncoding,
    #[error("server announced {actual} bytes, expected {expected}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("server sent more bytes than expected; partial object discarded")]
    Overrun,
    #[error("body ended after {received} of {expected} bytes")]
    Truncated { received: u64, expected: u64 },
    #[error("{0:?} digest mismatch; partial object discarded")]
    DigestMismatch(DigestAlgorithm),
    #[error("storage failure")]
    Io(#[from] io::Error),
}
