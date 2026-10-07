//! Typed identities. A `LocalRevisionId` is scoped to its originating server and is
//! never interchangeable with an update `Revision` number.
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// GUID shared by every revision of one update (`UpdateID` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UpdateId(pub Uuid);

impl fmt::Display for UpdateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

/// Update revision number (`RevisionNumber` on the wire). Not a server-local id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Revision(pub u32);

/// Globally unique `(UpdateID, RevisionNumber)` pair (`UpdateIdentity` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UpdateRevision {
    pub id: UpdateId,
    pub revision: Revision,
}

impl fmt::Display for UpdateRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.revision.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerId(pub Uuid);

/// Server-local revision id, valid only together with its originating `ServerId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LocalRevisionId {
    pub server: ServerId,
    pub id: i32,
}

/// Server-local revision id exactly as it appears on the wire (`ID`,
/// `RevisionID`, `OutOfScopeRevisionIDs`, ...).
///
/// The wire carries no server scope. Combine it with the originating
/// [`ServerId`] via [`LocalRevisionId::from_wire`] before storing it anywhere
/// that outlives a single exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WireRevisionId(pub i32);

impl LocalRevisionId {
    /// Scope a wire revision id to the server that issued it.
    pub fn from_wire(server: ServerId, wire: WireRevisionId) -> Self {
        Self { server, id: wire.0 }
    }

    /// Drop the server scope again, for building a request to that server.
    pub fn to_wire(self) -> WireRevisionId {
        WireRevisionId(self.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComputerId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GroupId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeploymentId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl DigestAlgorithm {
    /// Digest length in bytes.
    pub fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Always false; present for clippy's `len_without_is_empty`.
    pub fn is_empty(self) -> bool {
        false
    }

    /// Parse the algorithm names used in update metadata (case-insensitive,
    /// with or without a dash: `SHA1`, `SHA-256`, ...).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Canonical metadata name (`SHA1`, `SHA256`, `SHA512`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileDigest {
    pub algorithm: DigestAlgorithm,
    pub bytes: Vec<u8>,
}
