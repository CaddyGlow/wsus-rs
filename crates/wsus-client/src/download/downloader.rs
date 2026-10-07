use super::{DownloadError, ExpectedFile, Hashers, hex_decode, hex_encode};
use crate::{
    state::atomic::{atomic_write, create_private_dir, sync_dir},
    transport::{
        BodySink, Failure, HttpRequest, Idempotence, ResponseHead, RetryPolicy, RetryTimer,
        SensitiveUrl, Transport, TransportError, retry::parse_retry_after,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest};

const SIDECAR_VERSION: u32 = 1;

/// Limits shared by all downloads of one [`Downloader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadLimits {
    /// Maximum simultaneous downloads; excess calls fail with `Busy`.
    pub max_concurrent: usize,
    /// Largest accepted object.
    pub max_file_size: u64,
    /// Sum of expected lengths of simultaneously running downloads.
    pub max_reserved_bytes: u64,
}

impl Default for DownloadLimits {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_file_size: 64 * 1024 * 1024 * 1024,
            max_reserved_bytes: u64::MAX,
        }
    }
}

/// Per-download behavior.
#[derive(Debug, Clone, Copy)]
pub struct DownloadOptions {
    /// Bytes between durable checkpoints (fsync plus sidecar update).
    pub checkpoint_interval: u64,
    pub request_timeout: Duration,
    /// When a server answers a Range request with a full 200 response, restart
    /// from zero instead of failing. Off by default so a misbehaving server is
    /// visible.
    pub allow_restart_on_full_response: bool,
    pub retry: RetryPolicy,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            checkpoint_interval: 8 * 1024 * 1024,
            request_timeout: Duration::from_secs(600),
            allow_restart_on_full_response: false,
            retry: RetryPolicy::default(),
        }
    }
}

/// A transient content location. Never persisted; `Debug` redacts it.
#[derive(Debug, Clone)]
pub struct Location(SensitiveUrl);

impl Location {
    /// Wraps a validated http(s) URL.
    pub fn new(url: SensitiveUrl) -> Self {
        Self(url)
    }

    /// Parses a URL string.
    pub fn parse(url: &str) -> Result<Self, crate::transport::InvalidUrl> {
        SensitiveUrl::parse(url).map(Self)
    }
}

/// A verified object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedFile {
    pub path: PathBuf,
    pub length: u64,
    pub content_id: String,
    /// Bytes already present and reused when this call started.
    pub resumed_from: u64,
    /// The partial object was discarded or a full response restarted it.
    pub restarted: bool,
    /// A verified object already existed; no network request was made.
    pub already_complete: bool,
}

#[derive(Default)]
struct Inner {
    active: HashSet<String>,
    reserved: u64,
}

struct Permit {
    shared: Arc<Mutex<Inner>>,
    id: String,
    reserved: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.shared.lock() {
            inner.active.remove(&self.id);
            inner.reserved = inner.reserved.saturating_sub(self.reserved);
        }
    }
}

/// Verified resumable downloader rooted at a directory. Cloning shares the
/// concurrency accounting.
#[derive(Clone)]
pub struct Downloader {
    root: PathBuf,
    limits: DownloadLimits,
    shared: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Downloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Downloader")
            .field("root", &self.root)
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct Sidecar {
    version: u32,
    content_id: String,
    file_name: String,
    length: u64,
    digests: Vec<(String, String)>,
    validated_len: u64,
    prefix_sha256: String,
}

fn algorithm_name(a: DigestAlgorithm) -> &'static str {
    match a {
        DigestAlgorithm::Sha1 => "sha1",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha512 => "sha512",
    }
}

fn encode_digests(digests: &[FileDigest]) -> Vec<(String, String)> {
    digests
        .iter()
        .map(|d| (algorithm_name(d.algorithm).to_owned(), hex_encode(&d.bytes)))
        .collect()
}

impl Sidecar {
    fn new(expected: &ExpectedFile) -> Self {
        Self {
            version: SIDECAR_VERSION,
            content_id: expected.content_id(),
            file_name: expected.file_name().to_owned(),
            length: expected.length(),
            digests: encode_digests(expected.digests()),
            validated_len: 0,
            prefix_sha256: hex_encode(&Sha256::digest([])),
        }
    }

    fn matches(&self, expected: &ExpectedFile) -> bool {
        self.version == SIDECAR_VERSION
            && self.content_id == expected.content_id()
            && self.file_name == expected.file_name()
            && self.length == expected.length()
            && self.digests == encode_digests(expected.digests())
            && self.validated_len <= self.length
            && hex_decode(&self.prefix_sha256).is_some_and(|b| b.len() == 32)
    }
}

struct Partial {
    file: File,
    hashers: Hashers,
    prefix: Sha256,
    len: u64,
    checkpointed: u64,
    sidecar: Sidecar,
    sidecar_path: PathBuf,
    part_path: PathBuf,
    digests: Vec<FileDigest>,
}

impl Partial {
    fn checkpoint(&mut self) -> io::Result<()> {
        self.file.sync_data()?;
        self.sidecar.validated_len = self.len;
        self.sidecar.prefix_sha256 = hex_encode(&self.prefix.clone().finalize());
        let bytes = serde_json::to_vec(&self.sidecar).map_err(io::Error::other)?;
        atomic_write(&self.sidecar_path, &bytes)?;
        self.checkpointed = self.len;
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.hashers = Hashers::for_digests(&self.digests);
        self.prefix = Sha256::new();
        self.len = 0;
        self.checkpoint()
    }
}

struct Sink<'a> {
    partial: &'a mut Partial,
    length: u64,
    resume_from: u64,
    interval: u64,
    allow_restart: bool,
    restarted: bool,
    error: Option<DownloadError>,
    discard: bool,
}

impl Sink<'_> {
    fn fail(&mut self, error: DownloadError, discard: bool) -> io::Result<bool> {
        self.error = Some(error);
        self.discard = discard;
        Ok(false)
    }

    fn check_range(&self, head: &ResponseHead) -> Result<(), DownloadError> {
        let value = head
            .headers
            .get("content-range")
            .ok_or(DownloadError::RangeMismatch("missing Content-Range"))?;
        let spec = value
            .trim()
            .strip_prefix("bytes ")
            .ok_or(DownloadError::RangeMismatch("unsupported range unit"))?;
        let (range, total) = spec
            .split_once('/')
            .ok_or(DownloadError::RangeMismatch("malformed Content-Range"))?;
        let (start, end) = range
            .split_once('-')
            .ok_or(DownloadError::RangeMismatch("malformed Content-Range"))?;
        let parse = |s: &str| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| DownloadError::RangeMismatch("malformed Content-Range"))
        };
        if parse(start)? != self.resume_from {
            return Err(DownloadError::RangeMismatch(
                "range start differs from request",
            ));
        }
        if parse(total)? != self.length || parse(end)? + 1 != self.length {
            return Err(DownloadError::RangeMismatch(
                "range does not cover the object tail",
            ));
        }
        Ok(())
    }

    fn check_content_length(
        &self,
        head: &ResponseHead,
        expected: u64,
    ) -> Result<(), DownloadError> {
        if let Some(value) = head.headers.get("content-length") {
            match value.trim().parse::<u64>() {
                Ok(actual) if actual == expected => {}
                Ok(actual) => return Err(DownloadError::LengthMismatch { expected, actual }),
                Err(_) => return Err(DownloadError::RangeMismatch("malformed Content-Length")),
            }
        }
        Ok(())
    }
}

impl BodySink for Sink<'_> {
    fn start(&mut self, head: &ResponseHead) -> io::Result<bool> {
        let encoded = head
            .headers
            .get("content-encoding")
            .is_some_and(|v| !v.trim().eq_ignore_ascii_case("identity"));
        match head.status {
            200 | 206 if encoded => self.fail(DownloadError::UnexpectedEncoding, false),
            206 => {
                let checked = if self.resume_from == 0 {
                    Err(DownloadError::RangeMismatch(
                        "partial response to a full request",
                    ))
                } else {
                    self.check_range(head).and_then(|()| {
                        self.check_content_length(head, self.length - self.resume_from)
                    })
                };
                match checked {
                    Ok(()) => Ok(true),
                    Err(e) => self.fail(e, false),
                }
            }
            200 => {
                if self.resume_from > 0 {
                    if !self.allow_restart {
                        return self.fail(DownloadError::RangeIgnored, false);
                    }
                    self.partial.reset()?;
                    self.restarted = true;
                }
                match self.check_content_length(head, self.length) {
                    Ok(()) => Ok(true),
                    Err(e) => self.fail(e, false),
                }
            }
            416 => self.fail(DownloadError::RangeNotSatisfiable, true),
            status => {
                let retry_after = parse_retry_after(head.headers.get("retry-after"));
                self.fail(
                    DownloadError::HttpStatus {
                        status,
                        retry_after,
                    },
                    false,
                )
            }
        }
    }

    fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        let p = &mut *self.partial;
        if p.len + chunk.len() as u64 > self.length {
            self.error = Some(DownloadError::Overrun);
            self.discard = true;
            return Err(io::Error::other("overrun"));
        }
        let result: io::Result<()> = (|| {
            p.file.write_all(chunk)?;
            p.hashers.update(chunk);
            p.prefix.update(chunk);
            p.len += chunk.len() as u64;
            if p.len - p.checkpointed >= self.interval {
                p.checkpoint()?;
            }
            Ok(())
        })();
        if let Err(e) = &result {
            self.error = Some(DownloadError::Io(io::Error::new(e.kind(), "write failed")));
        }
        result
    }
}

fn file_matches(path: &Path, expected: &ExpectedFile) -> io::Result<bool> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != expected.length() {
        return Ok(false);
    }
    let mut hashers = Hashers::for_digests(expected.digests());
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hashers.update(&buf[..n]);
    }
    Ok(hashers.mismatch(expected.digests()).is_none())
}

impl Downloader {
    /// Creates the directory layout under `root`.
    pub fn open(root: impl Into<PathBuf>, limits: DownloadLimits) -> Result<Self, DownloadError> {
        let root = root.into();
        create_private_dir(&root)?;
        create_private_dir(&root.join("partial"))?;
        create_private_dir(&root.join("complete"))?;
        Ok(Self {
            root,
            limits,
            shared: Arc::default(),
        })
    }

    fn part_path(&self, id: &str) -> PathBuf {
        self.root.join("partial").join(format!("{id}.part"))
    }

    fn sidecar_path(&self, id: &str) -> PathBuf {
        self.root.join("partial").join(format!("{id}.json"))
    }

    /// Where the verified object will live.
    pub fn complete_path(&self, expected: &ExpectedFile) -> PathBuf {
        self.root
            .join("complete")
            .join(expected.content_id())
            .join(expected.file_name())
    }

    /// Returns the path of a fully re-verified existing object, if any.
    pub fn verified(&self, expected: &ExpectedFile) -> Result<Option<PathBuf>, DownloadError> {
        let path = self.complete_path(expected);
        match file_matches(&path, expected) {
            Ok(true) => Ok(Some(path)),
            Ok(false) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes any partial object for this content.
    pub fn discard_partial(&self, expected: &ExpectedFile) -> Result<(), DownloadError> {
        let id = expected.content_id();
        for path in [self.part_path(&id), self.sidecar_path(&id)] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn acquire(&self, expected: &ExpectedFile) -> Result<Permit, DownloadError> {
        let length = expected.length();
        if length > self.limits.max_file_size {
            return Err(DownloadError::TooLarge {
                length,
                limit: self.limits.max_file_size,
            });
        }
        let id = expected.content_id();
        let mut inner = self.shared.lock().expect("download accounting lock");
        if inner.active.contains(&id) {
            return Err(DownloadError::AlreadyInProgress);
        }
        if inner.active.len() >= self.limits.max_concurrent {
            return Err(DownloadError::Busy);
        }
        if inner.reserved.saturating_add(length) > self.limits.max_reserved_bytes {
            return Err(DownloadError::ReservationExceeded);
        }
        inner.active.insert(id.clone());
        inner.reserved += length;
        Ok(Permit {
            shared: Arc::clone(&self.shared),
            id,
            reserved: length,
        })
    }

    /// Opens a partial object that provably matches `expected`, or starts a new
    /// one. The boolean reports that unproven or mismatching bytes were dropped.
    fn open_partial(&self, expected: &ExpectedFile) -> Result<(Partial, bool), DownloadError> {
        let id = expected.content_id();
        let part_path = self.part_path(&id);
        let sidecar_path = self.sidecar_path(&id);
        let mut dropped = false;
        if let Some(partial) = self.try_resume(expected, &part_path, &sidecar_path)? {
            return Ok((partial, false));
        }
        if part_path.exists() || sidecar_path.exists() {
            dropped = true;
            self.discard_partial(expected)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)?;
        let mut partial = Partial {
            file,
            hashers: Hashers::for_digests(expected.digests()),
            prefix: Sha256::new(),
            len: 0,
            checkpointed: 0,
            sidecar: Sidecar::new(expected),
            sidecar_path,
            part_path,
            digests: expected.digests().to_vec(),
        };
        partial.checkpoint()?;
        Ok((partial, dropped))
    }

    fn try_resume(
        &self,
        expected: &ExpectedFile,
        part_path: &Path,
        sidecar_path: &Path,
    ) -> Result<Option<Partial>, DownloadError> {
        let Ok(bytes) = fs::read(sidecar_path) else {
            return Ok(None);
        };
        let Ok(sidecar) = serde_json::from_slice::<Sidecar>(&bytes) else {
            return Ok(None);
        };
        if !sidecar.matches(expected) {
            return Ok(None);
        }
        let Ok(mut file) = OpenOptions::new().read(true).write(true).open(part_path) else {
            return Ok(None);
        };
        if file.metadata()?.len() < sidecar.validated_len {
            return Ok(None);
        }
        let mut hashers = Hashers::for_digests(expected.digests());
        let mut prefix = Sha256::new();
        let mut remaining = sidecar.validated_len;
        let mut buf = vec![0u8; 1024 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            file.read_exact(&mut buf[..want])?;
            hashers.update(&buf[..want]);
            prefix.update(&buf[..want]);
            remaining -= want as u64;
        }
        if hex_encode(&prefix.clone().finalize()) != sidecar.prefix_sha256 {
            return Ok(None);
        }
        file.set_len(sidecar.validated_len)?;
        file.seek(SeekFrom::Start(sidecar.validated_len))?;
        Ok(Some(Partial {
            file,
            hashers,
            prefix,
            len: sidecar.validated_len,
            checkpointed: sidecar.validated_len,
            sidecar,
            sidecar_path: sidecar_path.to_path_buf(),
            part_path: part_path.to_path_buf(),
            digests: expected.digests().to_vec(),
        }))
    }

    fn finalize(
        &self,
        partial: Partial,
        expected: &ExpectedFile,
    ) -> Result<PathBuf, DownloadError> {
        partial.file.sync_all()?;
        let Partial {
            file,
            hashers,
            sidecar_path,
            part_path,
            ..
        } = partial;
        drop(file);
        if let Some(algorithm) = hashers.mismatch(expected.digests()) {
            let _ = fs::remove_file(&part_path);
            let _ = fs::remove_file(&sidecar_path);
            return Err(DownloadError::DigestMismatch(algorithm));
        }
        let dest = self.complete_path(expected);
        let dir = dest
            .parent()
            .expect("complete path has a parent")
            .to_path_buf();
        fs::create_dir_all(&dir)?;
        fs::rename(&part_path, &dest)?;
        sync_dir(&dir)?;
        sync_dir(&self.root.join("complete"))?;
        match fs::remove_file(&sidecar_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        sync_dir(&self.root.join("partial"))?;
        Ok(dest)
    }

    /// One acquisition attempt: reuse a verified object, resume a proven
    /// partial object with a Range request, verify and promote.
    pub async fn download<T: Transport>(
        &self,
        transport: &T,
        expected: &ExpectedFile,
        location: &Location,
        options: &DownloadOptions,
    ) -> Result<DownloadedFile, DownloadError> {
        let _permit = self.acquire(expected)?;
        let content_id = expected.content_id();
        if let Some(path) = self.verified(expected)? {
            return Ok(DownloadedFile {
                path,
                length: expected.length(),
                content_id,
                resumed_from: 0,
                restarted: false,
                already_complete: true,
            });
        }
        // A complete file that fails verification must not be kept.
        let _ = fs::remove_file(self.complete_path(expected));

        let (mut partial, mut restarted) = self.open_partial(expected)?;
        let resumed_from = partial.len;
        if partial.len < expected.length() {
            let mut request = HttpRequest::get(location.0.clone(), options.request_timeout)
                .with_header("Accept-Encoding", "identity");
            request.idempotence = Idempotence::Idempotent;
            if partial.len > 0 {
                request = request.with_range(partial.len, None);
            }
            let mut sink = Sink {
                resume_from: partial.len,
                partial: &mut partial,
                length: expected.length(),
                interval: options.checkpoint_interval.max(1),
                allow_restart: options.allow_restart_on_full_response,
                restarted: false,
                error: None,
                discard: false,
            };
            let result = transport.send_streaming(request, &mut sink).await;
            let sink_error = sink.error.take();
            let discard = sink.discard;
            restarted |= sink.restarted;
            drop(sink);
            if let Some(error) = sink_error {
                if discard {
                    let _ = fs::remove_file(&partial.part_path);
                    let _ = fs::remove_file(&partial.sidecar_path);
                } else {
                    let _ = partial.checkpoint();
                }
                return Err(error);
            }
            if let Err(error) = result {
                let _ = partial.checkpoint();
                return Err(error.into());
            }
            if partial.len < expected.length() {
                let _ = partial.checkpoint();
                return Err(DownloadError::Truncated {
                    received: partial.len,
                    expected: expected.length(),
                });
            }
        }
        let resumed_from = if restarted { 0 } else { resumed_from };
        let path = self.finalize(partial, expected)?;
        Ok(DownloadedFile {
            path,
            length: expected.length(),
            content_id,
            resumed_from,
            restarted,
            already_complete: false,
        })
    }

    /// Like [`Downloader::download`], retrying resumable failures (transport
    /// errors, truncated bodies, 408/429/5xx) with the options' retry policy.
    /// Each retry resumes from the last checkpoint.
    pub async fn download_with_retry<T: Transport, S: RetryTimer>(
        &self,
        transport: &T,
        timer: &S,
        expected: &ExpectedFile,
        location: &Location,
        options: &DownloadOptions,
    ) -> Result<DownloadedFile, DownloadError> {
        let mut attempt = 0u32;
        loop {
            let error = match self.download(transport, expected, location, options).await {
                Ok(file) => return Ok(file),
                Err(error) => error,
            };
            let truncated = TransportError::io("body truncated");
            let failure = match &error {
                DownloadError::Transport(e) => Some(Failure::Transport(e)),
                DownloadError::Truncated { .. } => Some(Failure::Transport(&truncated)),
                DownloadError::HttpStatus {
                    status,
                    retry_after,
                } => Some(Failure::Status {
                    status: *status,
                    retry_after: *retry_after,
                }),
                _ => None,
            };
            let Some(delay) =
                failure.and_then(|f| options.retry.decide(Idempotence::Idempotent, attempt, f))
            else {
                return Err(error);
            };
            timer.sleep(delay).await;
            attempt += 1;
        }
    }
}
