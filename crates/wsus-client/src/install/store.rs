//! Where verified payloads live.
use super::plan::PayloadRef;
use crate::download::Downloader;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Resolves a payload to a file in the verified download area. It never
/// downloads: acquisition happens before planning's execution step through
/// the existing `acquire` path.
pub trait PayloadStore {
    /// Root of the verified area (the path policy confines payloads to it).
    fn root(&self) -> &Path;
    /// Path of the payload when the verified object exists.
    fn locate(&self, payload: &PayloadRef) -> Result<Option<PathBuf>, String>;
    /// Where the verified object lives (or would live) in the store.
    fn expected_path(&self, payload: &PayloadRef) -> Result<PathBuf, String>;
}

/// The store written by [`Downloader`] (`complete/<content-id>/<name>`).
pub struct DownloaderStore {
    downloader: Downloader,
    root: PathBuf,
}

impl DownloaderStore {
    /// `root` must be the directory the downloader was opened on.
    pub fn new(downloader: Downloader, root: impl Into<PathBuf>) -> Self {
        Self {
            downloader,
            root: root.into(),
        }
    }
}

impl PayloadStore for DownloaderStore {
    fn root(&self) -> &Path {
        &self.root
    }

    fn locate(&self, payload: &PayloadRef) -> Result<Option<PathBuf>, String> {
        let expected = payload.expected()?;
        let path = self.downloader.complete_path(&expected);
        Ok(path.is_file().then_some(path))
    }

    fn expected_path(&self, payload: &PayloadRef) -> Result<PathBuf, String> {
        Ok(self.downloader.complete_path(&payload.expected()?))
    }
}

/// Test double: payloads by file name.
#[derive(Debug, Clone, Default)]
pub struct FixedStore {
    pub root: PathBuf,
    pub files: BTreeMap<String, PathBuf>,
}

impl PayloadStore for FixedStore {
    fn root(&self) -> &Path {
        &self.root
    }

    fn locate(&self, payload: &PayloadRef) -> Result<Option<PathBuf>, String> {
        Ok(self.files.get(&payload.file_name).cloned())
    }

    fn expected_path(&self, payload: &PayloadRef) -> Result<PathBuf, String> {
        Ok(self
            .files
            .get(&payload.file_name)
            .cloned()
            .unwrap_or_else(|| self.root.join(&payload.file_name)))
    }
}
