//! Durable store of received metadata, one JSON record per update revision.
//!
//! Records are written atomically (temporary file, fsync, rename). The sync
//! engine stores records before it advances the checkpoint, so a crash leaves
//! either complete records the checkpoint does not yet cover (re-fetched and
//! overwritten idempotently) or nothing.

use crate::{
    session::StorageError,
    state::{atomic_write, create_private_dir},
};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use wsus_protocol::{
    identity::UpdateRevision,
    soap::Scalar,
    wusp::{Deployment, XmlUpdateFragmentType},
};

/// A metadata fragment exactly as received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFragment {
    /// Fragment kind (`Core`, `Extended`, `LocalizedProperties`, ...).
    pub kind: String,
    /// Locale for localized fragments.
    pub locale: Option<String>,
    /// SHA-256 (hex) over the received representation.
    pub sha256: String,
    /// Fragment XML text.
    pub xml: String,
}

/// Deployment fields kept from `SyncUpdates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSummary {
    pub id: i32,
    pub action: String,
    pub is_assigned: bool,
    pub deadline: Option<String>,
    pub last_change_time: String,
}

impl DeploymentSummary {
    pub(crate) fn from_wire(d: &Deployment) -> Self {
        Self {
            id: d.id,
            action: d.action.format(),
            is_assigned: d.is_assigned,
            deadline: d.deadline.value().cloned(),
            last_change_time: d.last_change_time.clone(),
        }
    }
}

/// Everything stored for one revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionRecord {
    pub identity: UpdateRevision,
    pub is_leaf: bool,
    /// `Software`, `Driver`, ... as in `Properties/@UpdateType`.
    pub update_type: Option<String>,
    pub deployment: Option<DeploymentSummary>,
    pub core: StoredFragment,
    /// Fragments fetched through `GetExtendedUpdateInfo[2]`.
    pub fragments: Vec<StoredFragment>,
}

impl RevisionRecord {
    /// Fragments of one kind.
    pub fn fragments_of(
        &self,
        kind: &XmlUpdateFragmentType,
    ) -> impl Iterator<Item = &StoredFragment> {
        let kind = kind.format();
        self.fragments.iter().filter(move |f| f.kind == kind)
    }

    /// Inserts a fragment, replacing one with the same kind and locale.
    pub fn put_fragment(&mut self, fragment: StoredFragment) {
        self.fragments
            .retain(|f| !(f.kind == fragment.kind && f.locale == fragment.locale));
        self.fragments.push(fragment);
    }
}

/// Directory of revision records.
#[derive(Debug, Clone)]
pub struct RevisionStore {
    dir: PathBuf,
}

impl RevisionStore {
    /// Opens (creating, with private permissions) the store directory.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let dir = dir.as_ref().join("revisions");
        create_private_dir(&dir)?;
        if let Ok(entries) = fs::read_dir(&dir) {
            // Leftovers of interrupted atomic writes.
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && name.contains(".tmp.") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(Self { dir })
    }

    /// Opens an existing store without creating, chmod-ing or cleaning
    /// anything (for read-only use of a store that must stay untouched).
    pub fn open_read_only(dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let dir = dir.as_ref().join("revisions");
        if !dir.is_dir() {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "revision store directory does not exist",
            )));
        }
        Ok(Self { dir })
    }

    fn path(&self, rev: &UpdateRevision) -> PathBuf {
        self.dir.join(format!("{}_{}.json", rev.id, rev.revision.0))
    }

    /// Durably writes a record.
    pub fn put(&self, record: &RevisionRecord) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec(record)?;
        atomic_write(&self.path(&record.identity), &bytes)?;
        Ok(())
    }

    /// Reads a record.
    pub fn get(&self, rev: &UpdateRevision) -> Result<Option<RevisionRecord>, StorageError> {
        match fs::read(self.path(rev)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// All records, in file-name order.
    pub fn list(&self) -> Result<Vec<RevisionRecord>, StorageError> {
        let mut names: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        names.sort();
        names
            .iter()
            .map(|p| Ok(serde_json::from_slice(&fs::read(p)?)?))
            .collect()
    }
}
