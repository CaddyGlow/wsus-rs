use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rusqlite::{OptionalExtension, Transaction, params};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;
use wsus_protocol::identity::DigestAlgorithm;

use super::range::{ByteRange, RangeRequest, resolve_range, unsatisfied_content_range};
use super::{ContentDescriptor, ObjectId};
use crate::storage::{Database, Error, Result, algorithm_name, now_unix, parse_algorithm};

#[derive(Debug, Default)]
struct Shared {
    leases: Mutex<HashMap<ObjectId, usize>>,
    /// Promotion and commit hold the read side; garbage collection holds the write side,
    /// so GC never observes a promoted-but-uncommitted object.
    gate: RwLock<()>,
}

impl Shared {
    fn lease(self: &Arc<Self>, id: &ObjectId) -> Lease {
        *self
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(id.clone())
            .or_insert(0) += 1;
        Lease {
            shared: Arc::clone(self),
            id: id.clone(),
        }
    }

    fn is_leased(&self, id: &ObjectId) -> bool {
        self.leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }
}

#[derive(Debug)]
struct Lease {
    shared: Arc<Shared>,
    id: ObjectId,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut map = self.shared.leases.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.id);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContentStore {
    db: Database,
    root: PathBuf,
    shared: Arc<Shared>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub id: ObjectId,
    pub size: u64,
    /// Strong validator derived from the content hash.
    pub etag: String,
    /// Protocol file names recorded for this object.
    pub file_names: Vec<String>,
    pub promoted_at: i64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub removed: Vec<ObjectId>,
    pub bytes_freed: u64,
    pub skipped_leased: Vec<ObjectId>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Promotions that crashed before the commit and were completed.
    pub completed_promotions: Vec<ObjectId>,
    /// Promoted objects with no record, moved to quarantine.
    pub quarantined_objects: Vec<ObjectId>,
    /// Object records whose file is missing (now marked missing).
    pub missing_objects: Vec<ObjectId>,
    /// Objects whose content failed verification (deep mode); quarantined.
    pub corrupt_objects: Vec<ObjectId>,
    /// Missing records whose file reappeared and verified.
    pub restored_objects: Vec<ObjectId>,
    /// Stale in-flight partials removed.
    pub discarded_partials: u64,
}

pub enum ServeOutcome {
    NotFound,
    /// 200: whole object.
    Full(ObjectReader),
    /// 206: ranges in request order, each with its reader.
    Partial(Vec<(ByteRange, ObjectReader)>),
    /// 416 with `Content-Range: bytes */size`.
    Unsatisfiable {
        size: u64,
        content_range: String,
    },
}

impl std::fmt::Debug for ServeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("NotFound"),
            Self::Full(_) => f.write_str("Full"),
            Self::Partial(p) => write!(f, "Partial({})", p.len()),
            Self::Unsatisfiable { size, .. } => write!(f, "Unsatisfiable({size})"),
        }
    }
}

/// Streaming reader over one byte range of an object. Holds a lease that blocks garbage
/// collection of the object until dropped; dropping (for example on client cancellation)
/// releases it.
pub struct ObjectReader {
    file: io::Take<File>,
    range: ByteRange,
    len: u64,
    total: u64,
    _lease: Lease,
}

impl ObjectReader {
    pub fn range(&self) -> ByteRange {
        self.range
    }

    pub fn total_size(&self) -> u64 {
        self.total
    }

    /// Number of bytes this reader yields (the `Content-Length`).
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Read for ObjectReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl ContentStore {
    pub fn open(db: Database, root: &Path) -> Result<Self> {
        for d in ["objects", "partial", "quarantine"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(Self {
            db,
            root: root.to_owned(),
            shared: Arc::default(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of a promoted object, derived only from its validated id.
    pub fn object_path(&self, id: &ObjectId) -> PathBuf {
        let h = id.as_str();
        self.root
            .join("objects")
            .join(&h[0..2])
            .join(&h[2..4])
            .join(h)
    }

    fn partial_path(&self, partial: &Uuid) -> PathBuf {
        self.root.join("partial").join(format!("{partial}.part"))
    }

    // ---- acquisition ----

    /// Record the expected descriptor and create a recoverable partial object.
    pub fn begin(&self, descriptor: &ContentDescriptor) -> Result<PartialUpload> {
        descriptor.check()?;
        let id = Uuid::new_v4();
        self.db.transaction(|tx| {
            tx.execute(
                "INSERT INTO content_partials(partial_id,file_name,size,state,created_at) \
                 VALUES(?1,?2,?3,'receiving',?4)",
                params![
                    id.to_string(),
                    descriptor.file_name,
                    descriptor.size as i64,
                    now_unix()
                ],
            )?;
            for d in &descriptor.digests {
                tx.execute(
                    "INSERT OR REPLACE INTO content_partial_digests(partial_id,algorithm,digest) \
                     VALUES(?1,?2,?3)",
                    params![id.to_string(), algorithm_name(d.algorithm), d.bytes],
                )?;
            }
            Ok(())
        })?;
        let path = self.partial_path(&id);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        Ok(PartialUpload {
            store: self.clone(),
            id,
            path,
            file: Some(file),
            descriptor: descriptor.clone(),
            written: 0,
        })
    }

    /// Convenience: store a complete buffer through the full lifecycle.
    pub fn put_bytes(&self, descriptor: &ContentDescriptor, data: &[u8]) -> Result<ObjectId> {
        let mut up = self.begin(descriptor)?;
        up.write_all(data)?;
        up.finish()
    }

    /// Object already stored that satisfies every digest and the size of `descriptor`.
    pub fn find_available(&self, descriptor: &ContentDescriptor) -> Result<Option<ObjectId>> {
        descriptor.check()?;
        self.db.with_conn(|c| {
            let first = &descriptor.digests[0];
            let mut st = c.prepare(
                "SELECT o.object_id FROM content_digests d JOIN content_objects o \
                 ON o.object_id=d.object_id WHERE d.algorithm=?1 AND d.digest=?2 \
                 AND o.state='available' AND o.size=?3",
            )?;
            let candidates: Vec<String> = st
                .query_map(
                    params![
                        algorithm_name(first.algorithm),
                        first.bytes,
                        descriptor.size as i64
                    ],
                    |r| r.get(0),
                )?
                .collect::<std::result::Result<_, _>>()?;
            'next: for cand in candidates {
                for d in &descriptor.digests {
                    let n: i64 = c.query_row(
                        "SELECT COUNT(*) FROM content_digests WHERE object_id=?1 AND \
                         algorithm=?2 AND digest=?3",
                        params![cand, algorithm_name(d.algorithm), d.bytes],
                        |r| r.get(0),
                    )?;
                    if n == 0 {
                        continue 'next;
                    }
                }
                return Ok(Some(ObjectId::parse(&cand)?));
            }
            Ok(None)
        })
    }

    // ---- reading ----

    /// `HEAD` information. `None` unless the record is available and the file exists with
    /// the recorded length.
    pub fn info(&self, id: &ObjectId) -> Result<Option<ObjectInfo>> {
        let _g = self.shared.gate.read().unwrap_or_else(|e| e.into_inner());
        self.info_locked(id)
    }

    fn info_locked(&self, id: &ObjectId) -> Result<Option<ObjectInfo>> {
        let row: Option<(i64, i64)> = self.db.with_conn(|c| {
            Ok(c.query_row(
                "SELECT size,promoted_at FROM content_objects WHERE object_id=?1 \
                 AND state='available'",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })?;
        let Some((size, promoted_at)) = row else {
            return Ok(None);
        };
        match fs::metadata(self.object_path(id)) {
            Ok(m) if m.is_file() && m.len() == size as u64 => {}
            Ok(_) | Err(_) => return Ok(None),
        }
        let file_names = self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT file_name FROM content_names WHERE object_id=?1 ORDER BY file_name",
            )?;
            Ok(st
                .query_map([id.as_str()], |r| r.get(0))?
                .collect::<std::result::Result<Vec<String>, _>>()?)
        })?;
        Ok(Some(ObjectInfo {
            id: id.clone(),
            size: size as u64,
            etag: format!("\"{}\"", id.as_str()),
            file_names,
            promoted_at,
        }))
    }

    /// Open a reader for one inclusive range.
    pub fn open_range(&self, id: &ObjectId, range: ByteRange) -> Result<Option<ObjectReader>> {
        let _g = self.shared.gate.read().unwrap_or_else(|e| e.into_inner());
        let Some(info) = self.info_locked(id)? else {
            return Ok(None);
        };
        if range.start > range.end || range.end >= info.size {
            return Err(Error::Invalid("range outside object".into()));
        }
        self.reader_locked(id, range, info.size).map(Some)
    }

    fn reader_locked(&self, id: &ObjectId, range: ByteRange, total: u64) -> Result<ObjectReader> {
        let lease = self.shared.lease(id);
        let mut file = File::open(self.object_path(id))?;
        file.seek(SeekFrom::Start(range.start))?;
        Ok(ObjectReader {
            file: file.take(range.len()),
            range,
            len: range.len(),
            total,
            _lease: lease,
        })
    }

    /// Resolve a `Range` header and open the matching readers.
    pub fn serve(&self, id: &ObjectId, range_header: Option<&str>) -> Result<ServeOutcome> {
        let _g = self.shared.gate.read().unwrap_or_else(|e| e.into_inner());
        let Some(info) = self.info_locked(id)? else {
            return Ok(ServeOutcome::NotFound);
        };
        match resolve_range(range_header, info.size) {
            RangeRequest::Full => {
                if info.size == 0 {
                    let lease = self.shared.lease(id);
                    return Ok(ServeOutcome::Full(ObjectReader {
                        file: File::open(self.object_path(id))?.take(0),
                        range: ByteRange { start: 0, end: 0 },
                        len: 0,
                        total: 0,
                        _lease: lease,
                    }));
                }
                let range = ByteRange {
                    start: 0,
                    end: info.size - 1,
                };
                Ok(ServeOutcome::Full(
                    self.reader_locked(id, range, info.size)?,
                ))
            }
            RangeRequest::Unsatisfiable => Ok(ServeOutcome::Unsatisfiable {
                size: info.size,
                content_range: unsatisfied_content_range(info.size),
            }),
            RangeRequest::Ranges(ranges) => {
                let mut out = Vec::with_capacity(ranges.len());
                for r in ranges {
                    out.push((r, self.reader_locked(id, r, info.size)?));
                }
                Ok(ServeOutcome::Partial(out))
            }
        }
    }

    // ---- pins ----

    /// Keep an object alive for a named owner (for example a retained job).
    pub fn pin(&self, id: &ObjectId, owner: &str) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO content_pins(object_id,owner,created_at) VALUES(?1,?2,?3)",
                params![id.as_str(), owner, now_unix()],
            )?;
            Ok(())
        })
    }

    pub fn unpin(&self, id: &ObjectId, owner: &str) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute(
                "DELETE FROM content_pins WHERE object_id=?1 AND owner=?2",
                params![id.as_str(), owner],
            )?;
            Ok(())
        })
    }

    // ---- garbage collection ----

    /// Remove available objects that no active or staging metadata, in-flight partial, pin
    /// or open reader references and that are older than `min_age`. Excludes concurrent
    /// promotion and serving through the store's gate and leases.
    pub fn gc(&self, min_age: Duration) -> Result<GcReport> {
        let _g = self.shared.gate.write().unwrap_or_else(|e| e.into_inner());
        let cutoff = now_unix() - min_age.as_secs() as i64;
        let candidates: Vec<(String, i64)> = self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT o.object_id,o.size FROM content_objects o
                 WHERE o.state='available' AND o.promoted_at<=?1
                 AND NOT EXISTS (SELECT 1 FROM content_pins p WHERE p.object_id=o.object_id)
                 AND NOT EXISTS (
                    SELECT 1 FROM content_digests d
                    JOIN file_digests fd ON fd.algorithm=d.algorithm AND fd.digest=d.digest
                    JOIN files f ON f.generation_id=fd.generation_id AND f.local_id=fd.local_id
                         AND f.ordinal=fd.ordinal
                    JOIN generations g ON g.id=f.generation_id
                    WHERE d.object_id=o.object_id AND f.size=o.size
                      AND g.state IN ('active','staging'))
                 AND NOT EXISTS (
                    SELECT 1 FROM content_digests d
                    JOIN content_partial_digests pd ON pd.algorithm=d.algorithm AND pd.digest=d.digest
                    JOIN content_partials p ON p.partial_id=pd.partial_id
                    WHERE d.object_id=o.object_id AND p.size=o.size
                      AND p.state IN ('receiving','promoting'))",
            )?;
            Ok(st
                .query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?)
        })?;
        let mut report = GcReport::default();
        for (hex, size) in candidates {
            let id = ObjectId::parse(&hex)?;
            if self.shared.is_leased(&id) {
                report.skipped_leased.push(id);
                continue;
            }
            self.db.transaction(|tx| {
                for t in ["content_digests", "content_names", "content_objects"] {
                    tx.execute(&format!("DELETE FROM {t} WHERE object_id=?1"), [&hex])?;
                }
                Ok(())
            })?;
            match fs::remove_file(self.object_path(&id)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            report.bytes_freed += size as u64;
            report.removed.push(id);
        }
        Ok(report)
    }

    // ---- startup reconciliation ----

    /// Reconcile disk and database after a possible crash. Call before accepting new
    /// uploads: every `receiving` partial found is stale. With `deep`, every available
    /// object is re-hashed.
    pub fn reconcile(&self, deep: bool) -> Result<ReconcileReport> {
        let _g = self.shared.gate.write().unwrap_or_else(|e| e.into_inner());
        let mut report = ReconcileReport::default();

        // 1. Partial rows.
        struct PartialRow {
            id: String,
            file_name: String,
            size: i64,
            state: String,
            target: Option<String>,
        }
        let rows: Vec<PartialRow> = self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT partial_id,file_name,size,state,target_object FROM content_partials",
            )?;
            Ok(st
                .query_map([], |r| {
                    Ok(PartialRow {
                        id: r.get(0)?,
                        file_name: r.get(1)?,
                        size: r.get(2)?,
                        state: r.get(3)?,
                        target: r.get(4)?,
                    })
                })?
                .collect::<std::result::Result<_, _>>()?)
        })?;
        let mut known_partial_files = Vec::new();
        for row in rows {
            let uuid = Uuid::parse_str(&row.id)
                .map_err(|e| Error::Integrity(format!("bad partial id {}: {e}", row.id)))?;
            let ppath = self.partial_path(&uuid);
            known_partial_files.push(ppath.clone());
            match row.state.as_str() {
                "failed" => {}
                "promoting" => {
                    let target = row.target.as_deref().map(ObjectId::parse).transpose()?;
                    let completed = match &target {
                        Some(t) => {
                            let opath = self.object_path(t);
                            if opath.is_file() {
                                let (len, sums) = hash_file(&opath, &[])?;
                                if len == row.size as u64 && sums.sha256 == t.sha256_bytes() {
                                    self.db.transaction(|tx| {
                                        commit_object(tx, &uuid, t, row.size, &row.file_name)
                                    })?;
                                    report.completed_promotions.push(t.clone());
                                    true
                                } else {
                                    quarantine(&self.root, &opath, t.as_str())?;
                                    report.corrupt_objects.push(t.clone());
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        None => false,
                    };
                    if !completed {
                        remove_if_exists(&ppath)?;
                        self.drop_partial_row(&row.id)?;
                        report.discarded_partials += 1;
                    } else {
                        remove_if_exists(&ppath)?;
                    }
                }
                _ => {
                    remove_if_exists(&ppath)?;
                    self.drop_partial_row(&row.id)?;
                    report.discarded_partials += 1;
                }
            }
        }
        // Partial files with no row.
        for entry in fs::read_dir(self.root.join("partial"))? {
            let p = entry?.path();
            if !known_partial_files.contains(&p) {
                remove_if_exists(&p)?;
                report.discarded_partials += 1;
            }
        }

        // 2. Promoted objects without a record.
        let recorded: std::collections::HashSet<String> = self.db.with_conn(|c| {
            let mut st = c.prepare("SELECT object_id FROM content_objects")?;
            Ok(st
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?)
        })?;
        for path in walk_files(&self.root.join("objects"))? {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            match ObjectId::parse(&name) {
                Ok(id) if self.object_path(&id) == path => {
                    if !recorded.contains(&name) {
                        quarantine(&self.root, &path, &name)?;
                        report.quarantined_objects.push(id);
                    }
                }
                _ => {
                    quarantine(&self.root, &path, &name)?;
                }
            }
        }

        // 3. Records whose object is missing, corrupt, or returned.
        let records: Vec<(String, i64, String)> = self.db.with_conn(|c| {
            let mut st = c.prepare("SELECT object_id,size,state FROM content_objects")?;
            Ok(st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<_, _>>()?)
        })?;
        for (hex, size, state) in records {
            let id = ObjectId::parse(&hex)?;
            let path = self.object_path(&id);
            let present = path.is_file();
            let verified = if present && (deep || state == "missing") {
                let (len, sums) = hash_file(&path, &[])?;
                Some(len == size as u64 && sums.sha256 == id.sha256_bytes())
            } else if present {
                Some(fs::metadata(&path)?.len() == size as u64)
            } else {
                None
            };
            match (state.as_str(), verified) {
                ("available", Some(true)) => {}
                ("available", Some(false)) => {
                    quarantine(&self.root, &path, &hex)?;
                    self.set_object_state(&hex, "missing")?;
                    report.corrupt_objects.push(id);
                }
                ("available", None) => {
                    self.set_object_state(&hex, "missing")?;
                    report.missing_objects.push(id);
                }
                (_, Some(true)) => {
                    self.set_object_state(&hex, "available")?;
                    report.restored_objects.push(id);
                }
                (_, Some(false)) => {
                    quarantine(&self.root, &path, &hex)?;
                    report.corrupt_objects.push(id);
                }
                _ => {}
            }
        }
        Ok(report)
    }

    fn drop_partial_row(&self, id: &str) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute("DELETE FROM content_partials WHERE partial_id=?1", [id])?;
            Ok(())
        })
    }

    fn set_object_state(&self, hex: &str, state: &str) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute(
                "UPDATE content_objects SET state=?2 WHERE object_id=?1",
                params![hex, state],
            )?;
            Ok(())
        })
    }

    /// Re-hash one object against its recorded identity.
    pub fn verify(&self, id: &ObjectId) -> Result<bool> {
        let _g = self.shared.gate.read().unwrap_or_else(|e| e.into_inner());
        let path = self.object_path(id);
        if !path.is_file() {
            return Ok(false);
        }
        let (_, sums) = hash_file(&path, &[])?;
        Ok(sums.sha256 == id.sha256_bytes())
    }
}

/// In-flight download. Dropping without `finish` leaves the partial for reconciliation.
pub struct PartialUpload {
    store: ContentStore,
    id: Uuid,
    path: PathBuf,
    file: Option<File>,
    descriptor: ContentDescriptor,
    written: u64,
}

impl PartialUpload {
    pub fn partial_id(&self) -> Uuid {
        self.id
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Discard the partial and its record.
    pub fn abort(mut self) -> Result<()> {
        self.file = None;
        remove_if_exists(&self.path)?;
        self.store.drop_partial_row(&self.id.to_string())
    }

    /// Verify length and digests, flush, atomically promote, and commit the record.
    /// On any verification failure the partial is moved to quarantine, its record is
    /// marked failed, and an error is returned; nothing becomes available.
    pub fn finish(mut self) -> Result<ObjectId> {
        let file = self
            .file
            .take()
            .ok_or_else(|| Error::Conflict("already finished".into()))?;
        file.sync_all()?;
        drop(file);
        let algs: Vec<DigestAlgorithm> = self
            .descriptor
            .digests
            .iter()
            .map(|d| d.algorithm)
            .collect();
        let (len, sums) = hash_file(&self.path, &algs)?;
        let failure = if len != self.descriptor.size {
            Some(format!("length {len} != expected {}", self.descriptor.size))
        } else {
            self.descriptor
                .digests
                .iter()
                .find(|d| sums.get(d.algorithm) != d.bytes.as_slice())
                .map(|d| format!("{} digest mismatch", algorithm_name(d.algorithm)))
        };
        if let Some(reason) = failure {
            quarantine(&self.store.root, &self.path, &format!("{}.part", self.id))?;
            self.store.db.transaction(|tx| {
                tx.execute(
                    "UPDATE content_partials SET state='failed', failure=?2 WHERE partial_id=?1",
                    params![self.id.to_string(), reason],
                )?;
                Ok(())
            })?;
            return Err(Error::Integrity(format!(
                "{}: {reason}",
                self.descriptor.file_name
            )));
        }
        let object = ObjectId::from_sha256(&sums.sha256)?;
        let _g = self
            .store
            .shared
            .gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        self.store.db.transaction(|tx| {
            tx.execute(
                "UPDATE content_partials SET state='promoting', target_object=?2 WHERE partial_id=?1",
                params![self.id.to_string(), object.as_str()],
            )?;
            Ok(())
        })?;
        let dest = self.store.object_path(&object);
        let parent = dest
            .parent()
            .ok_or_else(|| Error::Integrity("no parent".into()))?;
        fs::create_dir_all(parent)?;
        if dest.exists() {
            remove_if_exists(&self.path)?;
        } else {
            fs::rename(&self.path, &dest)?;
        }
        sync_dir(parent)?;
        sync_dir(&self.store.root.join("partial"))?;
        let size = self.descriptor.size as i64;
        self.store.db.transaction(|tx| {
            commit_object(tx, &self.id, &object, size, &self.descriptor.file_name)
        })?;
        Ok(object)
    }
}

impl Write for PartialUpload {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.descriptor.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write exceeds the descriptor size",
            ));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("upload already finished"))?;
        let n = file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

/// Insert the object record and aliases from the partial's recorded digests, then delete
/// the partial row. Idempotent so reconciliation can re-run it.
fn commit_object(
    tx: &Transaction<'_>,
    partial: &Uuid,
    object: &ObjectId,
    size: i64,
    file_name: &str,
) -> Result<()> {
    let pid = partial.to_string();
    tx.execute(
        "INSERT INTO content_objects(object_id,size,state,promoted_at) VALUES(?1,?2,'available',?3) \
         ON CONFLICT(object_id) DO UPDATE SET state='available', size=excluded.size",
        params![object.as_str(), size, now_unix()],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO content_digests(object_id,algorithm,digest) VALUES(?1,'sha256',?2)",
        params![object.as_str(), object.sha256_bytes()],
    )?;
    let digests: Vec<(String, Vec<u8>)> = {
        let mut st =
            tx.prepare("SELECT algorithm,digest FROM content_partial_digests WHERE partial_id=?1")?;
        st.query_map([&pid], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?
    };
    for (alg, bytes) in digests {
        parse_algorithm(&alg)?;
        tx.execute(
            "INSERT OR IGNORE INTO content_digests(object_id,algorithm,digest) VALUES(?1,?2,?3)",
            params![object.as_str(), alg, bytes],
        )?;
    }
    tx.execute(
        "INSERT OR IGNORE INTO content_names(object_id,file_name) VALUES(?1,?2)",
        params![object.as_str(), file_name],
    )?;
    tx.execute("DELETE FROM content_partials WHERE partial_id=?1", [&pid])?;
    Ok(())
}

struct Sums {
    sha256: Vec<u8>,
    sha1: Option<Vec<u8>>,
    sha512: Option<Vec<u8>>,
}

impl Sums {
    fn get(&self, a: DigestAlgorithm) -> &[u8] {
        match a {
            DigestAlgorithm::Sha256 => &self.sha256,
            DigestAlgorithm::Sha1 => self.sha1.as_deref().unwrap_or(&[]),
            DigestAlgorithm::Sha512 => self.sha512.as_deref().unwrap_or(&[]),
        }
    }
}

fn hash_file(path: &Path, extra: &[DigestAlgorithm]) -> Result<(u64, Sums)> {
    let mut f = File::open(path)?;
    let mut s256 = Sha256::new();
    let mut s1 = extra.contains(&DigestAlgorithm::Sha1).then(Sha1::new);
    let mut s512 = extra.contains(&DigestAlgorithm::Sha512).then(Sha512::new);
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        s256.update(&buf[..n]);
        if let Some(h) = s1.as_mut() {
            h.update(&buf[..n]);
        }
        if let Some(h) = s512.as_mut() {
            h.update(&buf[..n]);
        }
    }
    Ok((
        total,
        Sums {
            sha256: s256.finalize().to_vec(),
            sha1: s1.map(|h| h.finalize().to_vec()),
            sha512: s512.map(|h| h.finalize().to_vec()),
        },
    ))
}

fn remove_if_exists(p: &Path) -> Result<()> {
    match fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn quarantine(root: &Path, path: &Path, label: &str) -> Result<()> {
    let dest = root.join("quarantine").join(format!(
        "{label}.{}.{}",
        now_unix(),
        Uuid::new_v4().simple()
    ));
    fs::rename(path, dest)?;
    Ok(())
}

fn sync_dir(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(p)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = p;
    }
    Ok(())
}

fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d)? {
            let e = e?;
            let p = e.path();
            if e.file_type()?.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}
