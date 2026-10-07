//! Durable on-disk event queue with at-least-once delivery semantics.
//!
//! Events are appended to a checksummed, line-oriented log and fsynced before
//! `append` returns. After a crash the log is replayed: a torn final record is
//! truncated, corruption elsewhere is reported. Delivery is acknowledged only
//! after the server accepted the batch; unacknowledged events are redelivered
//! after a restart, so servers (or dedup keys) must tolerate repeats. A single
//! process owns a queue directory; concurrent writers are not supported.

use crate::{download::hex_encode, state::atomic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub mod install_events;
pub mod inventory;

const LOG_NAME: &str = "events.log";

/// Queue limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueConfig {
    pub max_pending: usize,
    pub max_payload_bytes: usize,
    /// Number of acknowledged dedup keys remembered to suppress re-enqueueing.
    pub dedup_history: usize,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_pending: 10_000,
            max_payload_bytes: 1024 * 1024,
            dedup_history: 4096,
        }
    }
}

/// Errors from the queue.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue I/O failure")]
    Io(#[from] io::Error),
    #[error("queue log is corrupt at record {record}")]
    Corrupt { record: usize },
    #[error("queue is full ({0} pending events)")]
    Full(usize),
    #[error("event payload of {0} bytes exceeds the limit")]
    PayloadTooLarge(usize),
    #[error("dedup key must be 1..=256 printable characters without whitespace")]
    InvalidKey,
}

/// A queued event. `Debug` hides the payload, which may hold report details.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedEvent {
    pub seq: u64,
    pub dedup_key: String,
    pub payload: serde_json::Value,
}

impl fmt::Debug for QueuedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedEvent")
            .field("seq", &self.seq)
            .field("dedup_key", &self.dedup_key)
            .finish_non_exhaustive()
    }
}

/// Result of [`EventQueue::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Queued {
        seq: u64,
    },
    /// An event with this key is already pending.
    Duplicate {
        seq: u64,
    },
    /// An event with this key was already acknowledged (within the history).
    AlreadyDelivered,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Record {
    Meta { next_seq: u64 },
    Event(QueuedEvent),
    Ack { seq: u64, key: String },
    Delivered { key: String },
}

/// The queue.
#[derive(Debug)]
pub struct EventQueue {
    dir: PathBuf,
    config: QueueConfig,
    log: File,
    pending: BTreeMap<u64, QueuedEvent>,
    pending_keys: HashMap<String, u64>,
    delivered: VecDeque<String>,
    delivered_set: HashSet<String>,
    next_seq: u64,
    dead_records: usize,
}

fn encode(record: &Record) -> Vec<u8> {
    let json = serde_json::to_string(record).expect("record serializes");
    let sum = hex_encode(&Sha256::digest(json.as_bytes())[..8]);
    format!("{sum} {json}\n").into_bytes()
}

fn decode(line: &[u8]) -> Option<Record> {
    let text = std::str::from_utf8(line).ok()?;
    let (sum, json) = text.split_once(' ')?;
    (sum == hex_encode(&Sha256::digest(json.as_bytes())[..8]))
        .then(|| serde_json::from_str(json).ok())
        .flatten()
}

impl EventQueue {
    /// Opens or creates the queue in `dir`, replaying the log.
    pub fn open(dir: impl AsRef<Path>, config: QueueConfig) -> Result<Self, QueueError> {
        let dir = dir.as_ref().to_path_buf();
        atomic::create_private_dir(&dir)?;
        atomic::remove_stale_temps(&dir, LOG_NAME);
        let path = dir.join(LOG_NAME);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let mut queue_state = Replay::default();
        let mut valid_end = 0usize;
        let mut rest = &bytes[..];
        let mut index = 0usize;
        while !rest.is_empty() {
            let newline = rest.iter().position(|b| *b == b'\n');
            let record = newline.and_then(|n| decode(&rest[..n]));
            match (newline, record) {
                (Some(n), Some(record)) => {
                    queue_state.apply(record);
                    valid_end += n + 1;
                    rest = &rest[n + 1..];
                    index += 1;
                }
                (newline, _) => {
                    // Invalid record: acceptable only as the torn final record.
                    let tail_is_last = newline.is_none_or(|n| !rest[n + 1..].contains(&b'\n'));
                    if !tail_is_last {
                        return Err(QueueError::Corrupt { record: index });
                    }
                    break;
                }
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let log = options.open(&path)?;
        if valid_end < bytes.len() {
            log.set_len(valid_end as u64)?;
            log.sync_all()?;
        }
        atomic::sync_dir(&dir)?;
        let mut queue = Self {
            dir,
            config,
            log,
            pending: queue_state.pending,
            pending_keys: queue_state.pending_keys,
            delivered: queue_state.delivered,
            delivered_set: queue_state.delivered_set,
            next_seq: queue_state.next_seq,
            dead_records: queue_state.dead_records,
        };
        queue.trim_history();
        Ok(queue)
    }

    fn trim_history(&mut self) {
        while self.delivered.len() > self.config.dedup_history {
            if let Some(key) = self.delivered.pop_front() {
                self.delivered_set.remove(&key);
            }
        }
    }

    fn write(&mut self, record: &Record) -> Result<(), QueueError> {
        self.log.write_all(&encode(record))?;
        self.log.sync_data()?;
        Ok(())
    }

    /// Durably appends an event unless its dedup key is already known.
    pub fn append(
        &mut self,
        dedup_key: &str,
        payload: serde_json::Value,
    ) -> Result<AppendOutcome, QueueError> {
        if dedup_key.is_empty()
            || dedup_key.len() > 256
            || dedup_key
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(QueueError::InvalidKey);
        }
        if let Some(seq) = self.pending_keys.get(dedup_key) {
            return Ok(AppendOutcome::Duplicate { seq: *seq });
        }
        if self.delivered_set.contains(dedup_key) {
            return Ok(AppendOutcome::AlreadyDelivered);
        }
        let size = serde_json::to_vec(&payload).map_or(usize::MAX, |v| v.len());
        if size > self.config.max_payload_bytes {
            return Err(QueueError::PayloadTooLarge(size));
        }
        if self.pending.len() >= self.config.max_pending {
            return Err(QueueError::Full(self.pending.len()));
        }
        let event = QueuedEvent {
            seq: self.next_seq,
            dedup_key: dedup_key.to_owned(),
            payload,
        };
        self.write(&Record::Event(event.clone()))?;
        self.next_seq += 1;
        self.pending_keys.insert(event.dedup_key.clone(), event.seq);
        let seq = event.seq;
        self.pending.insert(seq, event);
        Ok(AppendOutcome::Queued { seq })
    }

    /// Up to `limit` oldest unacknowledged events, in append order.
    pub fn pending(&self, limit: usize) -> Vec<QueuedEvent> {
        self.pending.values().take(limit).cloned().collect()
    }

    /// Number of unacknowledged events.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// True when nothing awaits delivery.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Acknowledges delivered events; unknown sequence numbers are ignored.
    /// Returns the number of events removed.
    pub fn ack(&mut self, seqs: &[u64]) -> Result<usize, QueueError> {
        let mut removed = 0;
        for seq in seqs {
            let Some(event) = self.pending.get(seq) else {
                continue;
            };
            let key = event.dedup_key.clone();
            self.write(&Record::Ack {
                seq: *seq,
                key: key.clone(),
            })?;
            self.pending.remove(seq);
            self.pending_keys.remove(&key);
            if self.delivered_set.insert(key.clone()) {
                self.delivered.push_back(key);
            }
            self.dead_records += 2;
            removed += 1;
        }
        self.trim_history();
        if self.dead_records > 1024 && self.dead_records > self.pending.len() * 2 {
            self.compact()?;
        }
        Ok(removed)
    }

    /// Rewrites the log with only live state.
    pub fn compact(&mut self) -> Result<(), QueueError> {
        let mut out = encode(&Record::Meta {
            next_seq: self.next_seq,
        });
        for key in &self.delivered {
            out.extend(encode(&Record::Delivered { key: key.clone() }));
        }
        for event in self.pending.values() {
            out.extend(encode(&Record::Event(event.clone())));
        }
        let path = self.dir.join(LOG_NAME);
        atomic::atomic_write(&path, &out)?;
        let mut options = OpenOptions::new();
        options.append(true);
        self.log = options.open(&path)?;
        self.dead_records = 0;
        Ok(())
    }
}

#[derive(Default)]
struct Replay {
    pending: BTreeMap<u64, QueuedEvent>,
    pending_keys: HashMap<String, u64>,
    delivered: VecDeque<String>,
    delivered_set: HashSet<String>,
    next_seq: u64,
    dead_records: usize,
}

impl Replay {
    fn mark_delivered(&mut self, key: String) {
        if self.delivered_set.insert(key.clone()) {
            self.delivered.push_back(key);
        }
    }

    fn apply(&mut self, record: Record) {
        match record {
            Record::Meta { next_seq } => self.next_seq = self.next_seq.max(next_seq),
            Record::Event(event) => {
                self.next_seq = self.next_seq.max(event.seq + 1);
                self.pending_keys.insert(event.dedup_key.clone(), event.seq);
                self.pending.insert(event.seq, event);
            }
            Record::Ack { seq, key } => {
                self.pending.remove(&seq);
                self.pending_keys.remove(&key);
                self.mark_delivered(key);
                self.dead_records += 2;
            }
            Record::Delivered { key } => self.mark_delivered(key),
        }
    }
}
