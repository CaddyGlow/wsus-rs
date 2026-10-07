//! Verified acquisition of an [`AcquisitionClosure`] through the existing
//! [`Downloader`], with transient locations refreshed by stable digest.

use super::{
    catalog::{AcquisitionClosure, FileRequirement},
    engine::{ResolvedLocation, SyncEngine},
    error::SyncError,
};
use crate::{
    download::{DownloadError, DownloadOptions, DownloadedFile, Downloader, ExpectedFile},
    session::{Clock, WuspError},
    transport::{RetryTimer, Transport},
};
use std::collections::HashMap;
use wsus_protocol::identity::UpdateRevision;

/// Result for one file.
#[derive(Debug)]
pub enum FileStatus {
    /// Verified and promoted (possibly already present).
    Complete(DownloadedFile),
    /// Not acquired; the reason never contains URLs.
    Failed(String),
}

/// One file of an acquisition run.
#[derive(Debug)]
pub struct FileOutcome {
    pub file_name: String,
    pub revisions: Vec<UpdateRevision>,
    pub status: FileStatus,
}

/// Result of [`SyncEngine::acquire`].
#[derive(Debug, Default)]
pub struct AcquireReport {
    pub files: Vec<FileOutcome>,
}

impl AcquireReport {
    /// True when every file is verified.
    pub fn all_complete(&self) -> bool {
        self.files
            .iter()
            .all(|f| matches!(f.status, FileStatus::Complete(_)))
    }
}

fn stale_location(error: &DownloadError) -> bool {
    matches!(
        error,
        DownloadError::HttpStatus {
            status: 401 | 403 | 404 | 410,
            ..
        }
    )
}

impl<T: Transport, S: RetryTimer, C: Clock> SyncEngine<T, S, C> {
    /// Acquires every file of `closure`. Already verified objects need no
    /// network access. Locations come from `GetFileLocations`; on a
    /// rejected-location status (401/403/404/410) the location is refreshed
    /// once by digest and the download retried (it resumes from the proven
    /// partial object). A failing file does not stop the others; inspect
    /// [`AcquireReport::all_complete`]. Session-level failures (cookie,
    /// transport to the WSUS server) abort with an error.
    pub async fn acquire(
        &mut self,
        closure: &AcquisitionClosure,
        downloader: &Downloader,
        options: &DownloadOptions,
    ) -> Result<AcquireReport, SyncError> {
        self.session.begin_run();
        let mut report = AcquireReport::default();
        let mut pending: Vec<(&FileRequirement, ExpectedFile, Vec<u8>)> = Vec::new();
        for file in &closure.files {
            let mut fail = |reason: String| {
                report.files.push(FileOutcome {
                    file_name: file.file_name.clone(),
                    revisions: file.revisions.clone(),
                    status: FileStatus::Failed(reason),
                });
            };
            let expected = match ExpectedFile::new(&file.file_name, file.size, file.digests.clone())
            {
                Ok(e) => e,
                Err(e) => {
                    fail(e.to_string());
                    continue;
                }
            };
            if let Some(path) = downloader.verified(&expected)? {
                report.files.push(FileOutcome {
                    file_name: file.file_name.clone(),
                    revisions: file.revisions.clone(),
                    status: FileStatus::Complete(DownloadedFile {
                        path,
                        length: expected.length(),
                        content_id: expected.content_id(),
                        resumed_from: 0,
                        restarted: false,
                        already_complete: true,
                    }),
                });
                continue;
            }
            match &file.sha1 {
                Some(sha1) => pending.push((file, expected, sha1.clone())),
                None => fail("no SHA-1 digest to request a location with".into()),
            }
        }
        if pending.is_empty() {
            return Ok(report);
        }
        let digests: Vec<Vec<u8>> = pending.iter().map(|(_, _, d)| d.clone()).collect();
        let mut locations: HashMap<Vec<u8>, ResolvedLocation> = self
            .file_locations(&digests)
            .await?
            .into_iter()
            .map(|l| (l.sha1.clone(), l))
            .collect();
        for (file, expected, sha1) in pending {
            let mut refreshed = false;
            let status = loop {
                let Some(location) = locations.get(&sha1) else {
                    break FileStatus::Failed("server returned no location".into());
                };
                if location.encrypted {
                    break FileStatus::Failed("encrypted content is not supported".into());
                }
                let result = downloader
                    .download_with_retry(
                        self.session.transport(),
                        self.session.timer(),
                        &expected,
                        &location.location,
                        options,
                    )
                    .await;
                match result {
                    Ok(done) => break FileStatus::Complete(done),
                    Err(error) if stale_location(&error) && !refreshed => {
                        refreshed = true;
                        match self.file_locations(std::slice::from_ref(&sha1)).await {
                            Ok(fresh) => {
                                for l in fresh {
                                    locations.insert(l.sha1.clone(), l);
                                }
                            }
                            Err(SyncError::Session(e @ WuspError::Transport(_))) => {
                                return Err(SyncError::Session(e));
                            }
                            Err(e) => break FileStatus::Failed(e.to_string()),
                        }
                    }
                    Err(error) => break FileStatus::Failed(error.to_string()),
                }
            };
            report.files.push(FileOutcome {
                file_name: file.file_name.clone(),
                revisions: file.revisions.clone(),
                status,
            });
        }
        Ok(report)
    }
}
