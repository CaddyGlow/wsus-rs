//! SQLite storage: one connection guarded by a mutex (single server process), explicit
//! versioned migrations, and transactional access.
mod migrations;

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use uuid::Uuid;
use wsus_protocol::identity::{DigestAlgorithm, ServerId};

macro_rules! string_enum {
    ($name:ident { $($var:ident => $s:literal),+ $(,)? }) => {
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$var => $s),+ }
            }
            pub(crate) fn parse(s: &str) -> $crate::storage::Result<Self> {
                match s {
                    $($s => Ok(Self::$var),)+
                    other => Err($crate::storage::Error::Integrity(format!(
                        concat!("unknown ", stringify!($name), " {:?}"), other
                    ))),
                }
            }
        }
    };
}
pub(crate) use string_enum;

pub use migrations::{MIGRATIONS, SCHEMA_VERSION, migrate};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("integrity failure: {0}")]
    Integrity(String),
    #[error("database schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: i64, supported: i64 },
}

/// Shared handle to the server database. Cloning shares the same connection.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").finish_non_exhaustive()
    }
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        migrate(&mut conn)?;
        ensure_server_identity(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self.lock();
        f(&guard)
    }

    /// Run `f` in an immediate transaction; commit on `Ok`, roll back on `Err`.
    pub fn transaction<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut guard = self.lock();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn schema_version(&self) -> Result<i64> {
        self.with_conn(|c| Ok(c.pragma_query_value(None, "user_version", |r| r.get(0))?))
    }

    /// Identity of this server; scopes every `LocalRevisionId` it issues.
    pub fn server_id(&self) -> Result<ServerId> {
        self.with_conn(|c| {
            let v: String =
                c.query_row("SELECT value FROM meta WHERE key='server_id'", [], |r| {
                    r.get(0)
                })?;
            let id = Uuid::parse_str(&v)
                .map_err(|e| Error::Integrity(format!("stored server_id is invalid: {e}")))?;
            Ok(ServerId(id))
        })
    }
}

fn ensure_server_identity(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    let existing: Option<String> = tx
        .query_row("SELECT value FROM meta WHERE key='server_id'", [], |r| {
            r.get(0)
        })
        .optional()?;
    if existing.is_none() {
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('server_id', ?1)",
            [Uuid::new_v4().to_string()],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn algorithm_name(a: DigestAlgorithm) -> &'static str {
    match a {
        DigestAlgorithm::Sha1 => "sha1",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha512 => "sha512",
    }
}

pub fn parse_algorithm(s: &str) -> Result<DigestAlgorithm> {
    match s {
        "sha1" => Ok(DigestAlgorithm::Sha1),
        "sha256" => Ok(DigestAlgorithm::Sha256),
        "sha512" => Ok(DigestAlgorithm::Sha512),
        other => Err(Error::Integrity(format!(
            "unknown digest algorithm {other}"
        ))),
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(val(p[0])? << 4 | val(p[1])?))
        .collect()
}

/// Bump the named monotonic counter in `meta` and return the new value.
pub(crate) fn bump_counter(tx: &Transaction<'_>, key: &str) -> Result<i64> {
    let current: Option<String> = tx
        .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .optional()?;
    let next = current.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0) + 1;
    tx.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![key, next.to_string()],
    )?;
    Ok(next)
}

pub(crate) fn read_counter(conn: &Connection, key: &str) -> Result<i64> {
    let v: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .optional()?;
    Ok(v.and_then(|v| v.parse().ok()).unwrap_or(0))
}
