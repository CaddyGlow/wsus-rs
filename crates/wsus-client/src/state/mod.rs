//! Persistent client state with atomic writes and protected permissions.
//!
//! The state file holds session material (cookie) and is written with mode
//! 0600 inside a 0700 directory on Unix. `Debug` output redacts the cookie.
//! Time values are Unix seconds supplied by the caller.

pub mod atomic;

pub use atomic::{atomic_write, create_private_dir, sync_dir};

use crate::transport::SecretBytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};
use wsus_protocol::identity::{ComputerId, ServerId, UpdateRevision};

/// Current on-disk schema version.
pub const STATE_VERSION: u32 = 1;

/// Errors from the state store. Messages never include state contents.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state I/O failure")]
    Io(#[from] io::Error),
    #[error("state file is corrupt or unreadable")]
    Corrupt(#[source] serde_json::Error),
    #[error("state file has unsupported version {0}")]
    UnsupportedVersion(u32),
    #[error("state serialization failed")]
    Serialize(#[source] serde_json::Error),
}

/// Registration progress with the source server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RegistrationState {
    #[default]
    Unregistered,
    /// RegisterComputer was attempted; the outcome is not yet confirmed.
    Pending {
        since_unix: i64,
    },
    Registered {
        at_unix: i64,
    },
}

/// Session cookie returned by GetCookie. The opaque payload is secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCookie {
    pub expires_unix: i64,
    pub data: SecretBytes,
}

impl StoredCookie {
    /// True when the cookie is expired or within `skew_secs` of expiring.
    pub fn is_expired(&self, now_unix: i64, skew_secs: i64) -> bool {
        now_unix.saturating_add(skew_secs) >= self.expires_unix
    }
}

/// Opaque synchronization anchor with the time it was committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    /// Opaque anchor as returned by the server.
    pub anchor: String,
    pub committed_unix: i64,
}

/// A revision known locally, keyed by update identity and revision number.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedRevision {
    /// Server-local revision id; only meaningful with the source `ServerId`.
    pub local_revision_id: Option<i32>,
    /// Lowercase hexadecimal SHA-256 of the received metadata representation.
    pub metadata_sha256: Option<String>,
}

mod revision_map {
    use super::{BTreeMap, CachedRevision, UpdateRevision};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Entry {
        update: UpdateRevision,
        info: CachedRevision,
    }

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<UpdateRevision, CachedRevision>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(map.iter().map(|(update, info)| Entry {
            update: *update,
            info: info.clone(),
        }))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<UpdateRevision, CachedRevision>, D::Error> {
        Ok(Vec::<Entry>::deserialize(deserializer)?
            .into_iter()
            .map(|e| (e.update, e.info))
            .collect())
    }
}

/// Everything the client must remember across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub version: u32,
    /// Incremented on every successful save.
    pub write_counter: u64,
    pub computer_id: Option<ComputerId>,
    pub source_server: Option<ServerId>,
    /// Opaque configuration version from the server; a change triggers recovery.
    pub config_generation: Option<String>,
    pub cookie: Option<StoredCookie>,
    pub registration: RegistrationState,
    pub sync_checkpoint: Option<SyncCheckpoint>,
    #[serde(with = "revision_map")]
    pub cached_revisions: BTreeMap<UpdateRevision, CachedRevision>,
}

impl Default for ClientState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            write_counter: 0,
            computer_id: None,
            source_server: None,
            config_generation: None,
            cookie: None,
            registration: RegistrationState::default(),
            sync_checkpoint: None,
            cached_revisions: BTreeMap::new(),
        }
    }
}

/// File-backed state store; every [`StateStore::update`] is durable on return.
#[derive(Debug)]
pub struct StateStore {
    path: PathBuf,
    state: ClientState,
}

impl StateStore {
    /// Opens (or initializes) the store at `path`, creating a private parent
    /// directory, removing stale temporary files and tightening permissions of
    /// an existing state file. A corrupt file is an error, never reset silently.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StateError> {
        let path = path.into();
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        atomic::create_private_dir(&dir)?;
        if let Some(name) = path.file_name() {
            atomic::remove_stale_temps(&dir, &name.to_string_lossy());
        }
        let state = match fs::read(&path) {
            Ok(bytes) => {
                restrict_permissions(&path)?;
                let state: ClientState =
                    serde_json::from_slice(&bytes).map_err(StateError::Corrupt)?;
                if state.version != STATE_VERSION {
                    return Err(StateError::UnsupportedVersion(state.version));
                }
                state
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => ClientState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, state })
    }

    /// Current state.
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// Applies `change` to a copy, persists it atomically and only then adopts
    /// it, so a failed write leaves memory and disk consistent.
    pub fn update<R>(
        &mut self,
        change: impl FnOnce(&mut ClientState) -> R,
    ) -> Result<R, StateError> {
        let mut next = self.state.clone();
        let result = change(&mut next);
        next.version = STATE_VERSION;
        next.write_counter = self.state.write_counter + 1;
        let bytes = serde_json::to_vec_pretty(&next).map_err(StateError::Serialize)?;
        atomic::atomic_write(&self.path, &bytes)?;
        self.state = next;
        Ok(result)
    }

    /// Path of the state file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn restrict_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
