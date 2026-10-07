//! Content-addressed object store.
//!
//! Layout under the store root:
//! - `objects/ab/cd/<sha256>`: promoted, immutable objects (path derived from the id only)
//! - `partial/<uuid>.part`: in-flight downloads
//! - `quarantine/`: objects or partials that failed verification or lost their record
//!
//! Lifecycle: [`ContentStore::begin`] records the expected descriptor and creates a partial;
//! bytes are streamed in; [`PartialUpload::finish`] verifies length and digests, fsyncs,
//! atomically renames into `objects/`, and commits the record in one database transaction.
mod range;
mod store;

use std::fmt;

use wsus_protocol::identity::FileDigest;

pub use range::{ByteRange, RangeRequest, resolve_range, unsatisfied_content_range};
pub use store::{
    ContentStore, GcReport, ObjectInfo, ObjectReader, PartialUpload, ReconcileReport, ServeOutcome,
};

use crate::storage::{Error, Result, hex_decode, hex_encode};

/// Local identity of a stored object: lowercase hex SHA-256 of its bytes. Construction
/// validates the form, so it is safe to derive filesystem paths from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(String);

impl ObjectId {
    pub fn parse(s: &str) -> Result<Self> {
        let ok = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(Error::Invalid(format!("invalid object id {s:?}")));
        }
        Ok(Self(s.to_owned()))
    }

    pub fn from_sha256(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::Invalid("sha256 digest must be 32 bytes".into()));
        }
        Ok(Self(hex_encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn sha256_bytes(&self) -> Vec<u8> {
        hex_decode(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Expected properties of an object, as published in update metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDescriptor {
    /// Protocol file name, retained for delivery. Never used to build paths.
    pub file_name: String,
    pub size: u64,
    /// Protocol digests; at least one is required and every one is verified.
    pub digests: Vec<FileDigest>,
}

impl ContentDescriptor {
    pub(crate) fn check(&self) -> Result<()> {
        if self.file_name.is_empty() {
            return Err(Error::Invalid("descriptor file name is empty".into()));
        }
        if self.digests.is_empty() {
            return Err(Error::Invalid(
                "descriptor needs at least one digest".into(),
            ));
        }
        if self.size > i64::MAX as u64 {
            return Err(Error::Invalid("descriptor size out of range".into()));
        }
        Ok(())
    }
}
