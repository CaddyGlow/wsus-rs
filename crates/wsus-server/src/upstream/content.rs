//! File acquisition, separate from metadata synchronization.
use futures_util::{StreamExt, stream};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;

use wsus_client::download::{DownloadOptions, Downloader, ExpectedFile, Location};
use wsus_client::transport::{RetryTimer, Transport};
use wsus_client::wsusss::{FileLocation, MAX_DOWNLOAD_FILES_DIGESTS};
use wsus_protocol::identity::{DigestAlgorithm, UpdateId, UpdateRevision};

use super::error::UpstreamError;
use super::sync::UpstreamSync;
use crate::content::{ContentDescriptor, ContentStore};

/// Which files to acquire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentSelection {
    /// Every file of every present revision in the active generation.
    All,
    /// Files of the listed updates only (for example those a local policy
    /// approved; this crate never reads upstream approvals).
    Updates(BTreeSet<UpdateId>),
}

/// One file that could not be acquired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFailure {
    pub update: UpdateRevision,
    pub file_name: String,
    /// Error text without URLs.
    pub reason: String,
}

/// Result of [`UpstreamSync::acquire_content`]. Independent of the metadata
/// outcome: failures here never affect the active generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentReport {
    /// Newly stored files.
    pub acquired: usize,
    /// Files the store already had.
    pub already_present: usize,
    /// The upstream is a catalog-only server: no content is hosted.
    pub catalog_only: bool,
    /// Files that failed; they are retried by the next call.
    pub failed: Vec<ContentFailure>,
}

impl<T: Transport, S: RetryTimer> UpstreamSync<T, S> {
    /// Download selected files of the active generation into `store` using
    /// the verified, resumable `downloader`. Signed URLs are fetched with
    /// `GetUpdateData`, used in memory and never stored. Encrypted content
    /// (a `DecryptionKey` is present) is reported as failed: decryption is not
    /// implemented.
    pub async fn acquire_content(
        &mut self,
        store: &ContentStore,
        downloader: &Downloader,
        selection: &ContentSelection,
        options: &DownloadOptions,
    ) -> Result<ContentReport, UpstreamError> {
        let mut report = ContentReport::default();
        let Some(snapshot) = self.catalog().snapshot(self.source())? else {
            return Ok(report);
        };
        let server_config = match self.client_mut().server_config().cloned() {
            Some(c) => c,
            None => self.client_mut().get_config_data(None).await?,
        };
        report.catalog_only = server_config.catalog_only_sync;
        if server_config.catalog_only_sync && !self.client.config().allow_mu_url {
            return Ok(report);
        }

        let mut work: Vec<(UpdateRevision, ContentDescriptor)> = Vec::new();
        let mut seen: BTreeSet<(Vec<u8>, u64)> = BTreeSet::new();
        // The records whose files are wanted. For `Updates` that is the closure over
        // prerequisite and bundle edges: an approved bundle carries no files itself, its
        // bundled revisions do (observed on a real WSUS, inventory 9.5), and the WUSP server
        // delivers the same closure.
        let records: Vec<_> = match selection {
            ContentSelection::All => {
                let mut all = Vec::new();
                let mut after = None;
                loop {
                    let page = snapshot.list(after, 500, false)?;
                    all.extend(page.items);
                    match page.next {
                        Some(n) => after = Some(n),
                        None => break,
                    }
                }
                all
            }
            ContentSelection::Updates(wanted) => {
                let roots: Vec<UpdateId> = wanted.iter().copied().collect();
                snapshot
                    .closure(&roots)?
                    .into_iter()
                    .filter(|r| {
                        !matches!(
                            r.state,
                            crate::catalog::FragmentState::Deleted
                                | crate::catalog::FragmentState::Withdrawn
                        )
                    })
                    .collect()
            }
        };
        for record in records {
            for file in snapshot.files(record.local)? {
                let key = (file.digests[0].bytes.clone(), file.size);
                if !seen.insert(key) {
                    continue;
                }
                let descriptor = ContentDescriptor {
                    file_name: file.file_name,
                    size: file.size,
                    digests: file.digests,
                };
                if store.find_available(&descriptor)?.is_some() {
                    report.already_present += 1;
                } else {
                    work.push((record.identity, descriptor));
                }
            }
        }

        // Signed locations, per update, held only in memory.
        let mut locations: BTreeMap<Vec<u8>, FileLocation> = BTreeMap::new();
        let mut update_ids: Vec<UpdateRevision> = Vec::new();
        for (id, _) in &work {
            if !update_ids.contains(id) {
                update_ids.push(*id);
            }
        }
        let mut rest: &[UpdateRevision] = &update_ids;
        while !rest.is_empty() {
            let n = self.client_mut().update_batch_size().min(rest.len());
            let batch = self.client_mut().get_update_data(&rest[..n]).await?;
            rest = &rest[n..];
            for l in batch.file_locations {
                locations.insert(l.digest.clone(), l);
            }
        }

        // Pass 1 fetches from the known locations. Files every location answered 404 for are
        // collected; when the fallback is enabled they are requested from the upstream with
        // batched `DownloadFiles` calls (at most 100 digests each, MS-WSUSSS 3.2.4.4), after
        // one wait, and fetched again in pass 2. The fallback changes the upstream's state,
        // so it is configurable.
        let mut retry: Vec<(UpdateRevision, ContentDescriptor, Vec<u8>, Vec<Location>)> =
            Vec::new();
        let mut ready = Vec::new();
        for (update, descriptor) in work {
            let sha1 = descriptor
                .digests
                .iter()
                .find(|d| d.algorithm == DigestAlgorithm::Sha1)
                .map(|d| d.bytes.clone());
            let location = sha1.as_ref().and_then(|d| locations.get(d));
            let fail = |report: &mut ContentReport, reason: String| {
                report.failed.push(ContentFailure {
                    update,
                    file_name: descriptor.file_name.clone(),
                    reason,
                });
            };
            if location.is_some_and(|l| l.decryption_key.is_some()) {
                fail(&mut report, "encrypted content is not supported".into());
                continue;
            }
            let candidates = self.client_mut().content_candidates(
                sha1.as_deref(),
                Some(&descriptor.file_name),
                location,
            );
            let expected = match ExpectedFile::new(
                &descriptor.file_name,
                descriptor.size,
                descriptor.digests.clone(),
            ) {
                Ok(e) => e,
                Err(e) => {
                    fail(&mut report, e.to_string());
                    continue;
                }
            };
            ready.push((update, descriptor, sha1, expected, candidates));
        }
        // Only transfers run concurrently. Session/metadata calls and content
        // publication remain serialized; the downloader retains digest checks,
        // durable partial checkpoints and its per-object exclusion.
        let concurrency = self.config.download_concurrency;
        let client = &self.client;
        let mut transfers = stream::iter(ready.into_iter().map(
            |(update, descriptor, sha1, expected, candidates)| async move {
                let result = client
                    .download_content_once(downloader, &expected, &candidates, options)
                    .await;
                (update, descriptor, sha1, candidates, result)
            },
        ))
        .buffer_unordered(concurrency);
        while let Some((update, descriptor, sha1, candidates, result)) = transfers.next().await {
            match result {
                Ok(d) => match store_file(store, &descriptor, &d.path) {
                    Ok(()) => report.acquired += 1,
                    Err(e) => report.failed.push(ContentFailure {
                        update,
                        file_name: descriptor.file_name,
                        reason: e.to_string(),
                    }),
                },
                Err(e) if e.is_not_found() && sha1.is_some() => {
                    retry.push((update, descriptor, sha1.unwrap_or_default(), candidates));
                }
                Err(e) => report.failed.push(ContentFailure {
                    update,
                    file_name: descriptor.file_name,
                    reason: e.to_string(),
                }),
            }
        }
        drop(transfers);

        if !retry.is_empty() && self.client_mut().config().download_files_fallback {
            for chunk in retry.chunks(MAX_DOWNLOAD_FILES_DIGESTS) {
                let digests: Vec<Vec<u8>> = chunk.iter().map(|(_, _, d, _)| d.clone()).collect();
                self.client_mut().download_files(&digests).await?;
            }
            let wait = self.client_mut().config().download_files_wait;
            self.client_mut().timer().sleep(wait).await;
            let pending = std::mem::take(&mut retry);
            for (update, descriptor, _sha1, candidates) in pending {
                let reason = match ExpectedFile::new(
                    &descriptor.file_name,
                    descriptor.size,
                    descriptor.digests.clone(),
                ) {
                    Err(e) => e.to_string(),
                    Ok(expected) => match self
                        .client_mut()
                        .download_content_once(downloader, &expected, &candidates, options)
                        .await
                    {
                        Ok(d) => match store_file(store, &descriptor, &d.path) {
                            Ok(()) => {
                                report.acquired += 1;
                                continue;
                            }
                            Err(e) => e.to_string(),
                        },
                        Err(e) => e.to_string(),
                    },
                };

                report.failed.push(ContentFailure {
                    update,
                    file_name: descriptor.file_name.clone(),
                    reason,
                });
            }
        }
        for (update, descriptor, _, _) in retry {
            report.failed.push(ContentFailure {
                update,
                file_name: descriptor.file_name,
                reason: "not found at any location (DownloadFiles fallback disabled)".into(),
            });
        }
        Ok(report)
    }
}

fn store_file(
    store: &ContentStore,
    descriptor: &ContentDescriptor,
    path: &std::path::Path,
) -> Result<(), UpstreamError> {
    let mut file = File::open(path)?;
    let mut upload = store.begin(descriptor)?;
    if let Err(e) = io::copy(&mut file, &mut upload) {
        let _ = upload.abort();
        return Err(e.into());
    }
    upload.finish()?;
    Ok(())
}
