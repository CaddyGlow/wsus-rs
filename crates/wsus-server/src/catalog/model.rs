use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wsus_protocol::identity::{FileDigest, Revision, UpdateId, UpdateRevision};

use crate::storage::{Error, Result, string_enum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GenerationId(pub i64);

pub(crate) fn parse_update_id(s: &str) -> Result<UpdateId> {
    Uuid::parse_str(s)
        .map(UpdateId)
        .map_err(|e| Error::Integrity(format!("stored update id {s:?} invalid: {e}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    Upstream,
    Local,
    Import,
}
string_enum!(SourceKind { Upstream => "upstream", Local => "local", Import => "import" });

/// Which sources' interrupted staging generations
/// [`Catalog::abandon_interrupted_in`](super::Catalog::abandon_interrupted_in) fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbandonScope {
    /// Every source.
    All,
    /// Every source except upstream ones, whose staging generations may be resumable.
    SkipUpstream,
    /// Only sources of these kinds.
    Kinds(Vec<SourceKind>),
    /// Only this source.
    Source(SourceId),
}

impl AbandonScope {
    pub(crate) fn includes(&self, source: SourceId, kind: SourceKind) -> bool {
        match self {
            Self::All => true,
            Self::SkipUpstream => kind != SourceKind::Upstream,
            Self::Kinds(k) => k.contains(&kind),
            Self::Source(s) => *s == source,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenerationState {
    Staging,
    Active,
    Superseded,
    Failed,
}
string_enum!(GenerationState {
    Staging => "staging", Active => "active", Superseded => "superseded", Failed => "failed"
});

/// Availability of a revision's metadata. Supersedence never changes this: a superseded
/// update stays `Present` until the source says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FragmentState {
    Present,
    /// Withdrawn/expired at the source; metadata retained, not offered to clients.
    Withdrawn,
    /// Tombstone for deleted metadata; retained so identities stay resolvable.
    Deleted,
}
string_enum!(FragmentState { Present => "present", Withdrawn => "withdrawn", Deleted => "deleted" });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipKind {
    Prerequisite,
    Bundle,
    Supersedes,
    Classification,
    Product,
    Category,
    Other,
}
string_enum!(RelationshipKind {
    Prerequisite => "prerequisite", Bundle => "bundle", Supersedes => "supersedes",
    Classification => "classification", Product => "product", Category => "category",
    Other => "other"
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub id: SourceId,
    pub name: String,
    pub kind: SourceKind,
    pub description: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationInfo {
    pub id: GenerationId,
    pub source: SourceId,
    pub state: GenerationState,
    pub anchor: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub activated_at: Option<i64>,
    /// JSON evidence recorded when the generation failed.
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptor {
    pub file_name: String,
    pub size: u64,
    pub digests: Vec<FileDigest>,
}

/// Relationship target; `revision: None` means "any revision of this update id".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipImport {
    pub kind: RelationshipKind,
    pub target: UpdateId,
    pub revision: Option<Revision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentImport {
    pub identity: UpdateRevision,
    /// Free-form protocol kind (for example "Software", "Driver", "Detectoid").
    pub kind: String,
    pub state: FragmentState,
    /// Raw metadata exactly as received. Never regenerated.
    pub core_xml: Vec<u8>,
    pub extended_xml: Option<Vec<u8>>,
    pub relationships: Vec<RelationshipImport>,
    pub files: Vec<FileDescriptor>,
}

impl FragmentImport {
    pub fn new(identity: UpdateRevision, kind: &str, core_xml: &[u8]) -> Self {
        Self {
            identity,
            kind: kind.to_owned(),
            state: FragmentState::Present,
            core_xml: core_xml.to_vec(),
            extended_xml: None,
            relationships: Vec::new(),
            files: Vec::new(),
        }
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.kind.is_empty() {
            return Err(Error::Invalid("fragment kind is empty".into()));
        }
        for f in &self.files {
            if f.file_name.is_empty() || f.digests.is_empty() || f.size > i64::MAX as u64 {
                return Err(Error::Invalid(format!(
                    "file descriptor {:?} needs a name, a size within range, and at least one digest",
                    f.file_name
                )));
            }
            for d in &f.digests {
                let want = match d.algorithm {
                    wsus_protocol::identity::DigestAlgorithm::Sha1 => 20,
                    wsus_protocol::identity::DigestAlgorithm::Sha256 => 32,
                    wsus_protocol::identity::DigestAlgorithm::Sha512 => 64,
                };
                if d.bytes.len() != want {
                    return Err(Error::Invalid(format!(
                        "digest for {:?} has wrong length",
                        f.file_name
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueKind {
    MissingTarget,
    SelfReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationIssue {
    pub from: UpdateRevision,
    pub kind: RelationshipKind,
    pub target: UpdateId,
    pub target_revision: Option<Revision>,
    pub problem: IssueKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub fragments: u64,
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty() && self.fragments > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateOutcome {
    Activated { fragments: u64 },
    Rejected(ValidationReport),
}
