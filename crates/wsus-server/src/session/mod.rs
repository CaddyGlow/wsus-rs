//! MS-WUSP session cookies.
//!
//! Cookies are opaque to clients and integrity-protected with HMAC-SHA-256; no server-side
//! session table exists. Every cookie is bound to the server identity (so a replaced
//! database yields `ServerChanged`), to a configuration generation (so a configuration
//! change yields `ConfigChanged`), to a signing key id (rotation) and to an expiry. All of
//! that is checked from memory, with no database access, and before any payload field is
//! interpreted by endpoint code.
//!
//! Confidentiality: the payload is authenticated, not encrypted. It holds only values the
//! client itself supplied (its computer id, requested group, DNS name) plus generation
//! counters. The protocol names the field `EncryptedData`; the bytes are opaque to clients
//! either way.
//!
//! Key lifecycle (implementation decisions, tested):
//! * The signing key is 32 random bytes persisted in the database `meta` table, so cookies
//!   survive a process restart. The database file is therefore as sensitive as the key;
//!   protect it with filesystem permissions.
//! * [`SessionManager::rotate`] installs a fresh key. With `retain_previous` the old key
//!   still verifies (cookies keep working while clients migrate); without it every
//!   outstanding cookie becomes `InvalidCookie`. Only one previous key is kept, so a second
//!   rotation retires the oldest.
//! * The configuration generation is derived from a fingerprint of the wire-visible
//!   configuration: a changed fingerprint at startup, or [`SessionManager::bump_config`],
//!   increments it and moves `LastChange` forward.
mod cookie;
mod keys;

use std::sync::{Arc, RwLock};

use wsus_protocol::common::Cookie;
use wsus_protocol::identity::ServerId;
use wsus_protocol::soap::XsDateTime;

pub use cookie::{CookieClaims, CookieKind};
pub use keys::KeyRing;

use crate::endpoints::time::format_xs7;
use crate::storage::{Database, Error as StorageError, now_unix};

const META_FINGERPRINT: &str = "wusp_config_fingerprint";
const META_CONFIG_GENERATION: &str = "wusp_config_generation";
const META_CONFIG_LAST_CHANGE: &str = "wusp_config_last_change";

/// Largest cookie accepted before any parsing, in bytes.
pub const MAX_COOKIE_BYTES: usize = 1024;

/// Why a cookie was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    /// Missing, malformed, wrong kind, forged, or signed by a retired key.
    Invalid,
    /// Authentic but past its expiry.
    Expired,
    /// Authentic but issued by a different server identity.
    ServerChanged,
    /// Authentic but issued under an older configuration generation.
    ConfigChanged,
}

impl std::fmt::Display for CookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid cookie",
            Self::Expired => "cookie expired",
            Self::ServerChanged => "server changed",
            Self::ConfigChanged => "configuration changed",
        })
    }
}

impl std::error::Error for CookieError {}

/// Time source in unix seconds; replaceable so expiry is testable.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Lifetimes of the two cookie kinds, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// Authorization cookie lifetime.
    pub auth_cookie_ttl: i64,
    /// Session cookie lifetime (Windows uses 240 minutes, inventory section 6).
    pub cookie_ttl: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            auth_cookie_ttl: 24 * 3600,
            cookie_ttl: 240 * 60,
        }
    }
}

/// Server-wide values every cookie is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerState {
    pub server_id: ServerId,
    pub config_generation: i64,
    /// Unix seconds; reported as `Config.LastChange`.
    pub config_last_change: i64,
}

/// Issues and validates cookies.
pub struct SessionManager {
    db: Database,
    config: SessionConfig,
    clock: Clock,
    keys: RwLock<KeyRing>,
    state: RwLock<ServerState>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// Open with the system clock.
    pub fn open(
        db: Database,
        config: SessionConfig,
        config_fingerprint: &str,
    ) -> Result<Self, StorageError> {
        Self::open_with_clock(db, config, config_fingerprint, Arc::new(now_unix))
    }

    /// Load (or create) the signing key and configuration generation.
    pub fn open_with_clock(
        db: Database,
        config: SessionConfig,
        config_fingerprint: &str,
        clock: Clock,
    ) -> Result<Self, StorageError> {
        let keys = KeyRing::load_or_create(&db)?;
        let server_id = db.server_id()?;
        let state = load_state(&db, server_id, config_fingerprint, &clock)?;
        Ok(Self {
            db,
            config,
            clock,
            keys: RwLock::new(keys),
            state: RwLock::new(state),
        })
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    pub fn config(&self) -> SessionConfig {
        self.config
    }

    pub fn state(&self) -> ServerState {
        *self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    /// `Config.LastChange` as a wire value.
    pub fn config_last_change(&self) -> XsDateTime {
        xs(self.state().config_last_change)
    }

    /// Install a fresh signing key (see the module documentation).
    pub fn rotate(&self, retain_previous: bool) -> Result<(), StorageError> {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        *keys = keys.rotated(&self.db, retain_previous)?;
        Ok(())
    }

    /// Invalidate every cookie by advancing the configuration generation.
    pub fn bump_config(&self) -> Result<(), StorageError> {
        let now = self.now();
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        let (generation, last) = (st.config_generation + 1, now.max(st.config_last_change + 1));
        persist_state(&self.db, generation, last)?;
        st.config_generation = generation;
        st.config_last_change = last;
        Ok(())
    }

    /// Sign a cookie for `claims` (issue and expiry times are taken from the clock and the
    /// configured lifetime for the claim's kind).
    pub fn issue(&self, claims: &CookieClaims) -> Cookie {
        self.issue_until(claims, i64::MAX)
    }

    /// Like [`Self::issue`] but never later than `not_after` (unix seconds). MS-WSUSSS
    /// `GetCookie` uses it to cap a cookie at the expiry of its authorization cookie.
    pub fn issue_until(&self, claims: &CookieClaims, not_after: i64) -> Cookie {
        let now = self.now();
        let ttl = match claims.kind {
            CookieKind::Authorization | CookieKind::DownstreamAuthorization => {
                self.config.auth_cookie_ttl
            }
            CookieKind::Session | CookieKind::DownstreamSession => self.config.cookie_ttl,
        };
        let mut claims = claims.clone();
        claims.issued_at = now;
        claims.expires_at = now.saturating_add(ttl).min(not_after);
        let state = self.state();
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        let data = cookie::seal(&keys, &state, &claims);
        Cookie {
            expiration: xs(claims.expires_at),
            encrypted_data: wsus_protocol::soap::Presence::Value(data),
        }
    }

    /// Validate a presented cookie. Performs no database access. The wire `Expiration`
    /// field is ignored: only the signed expiry counts.
    pub fn validate(
        &self,
        cookie: Option<&Cookie>,
        kind: CookieKind,
    ) -> Result<CookieClaims, CookieError> {
        self.validate_bytes(
            cookie.and_then(|c| c.encrypted_data.value().map(Vec::as_slice)),
            kind,
        )
    }

    /// Like [`Self::validate`] for the raw cookie bytes (an `AuthorizationCookie` carries
    /// them as `CookieData`).
    pub fn validate_bytes(
        &self,
        data: Option<&[u8]>,
        kind: CookieKind,
    ) -> Result<CookieClaims, CookieError> {
        let data = data.ok_or(CookieError::Invalid)?;
        if data.is_empty() || data.len() > MAX_COOKIE_BYTES {
            return Err(CookieError::Invalid);
        }
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        let (header, claims) = cookie::open(&keys, data)?;
        drop(keys);
        if claims.kind != kind {
            return Err(CookieError::Invalid);
        }
        if self.now() >= claims.expires_at {
            return Err(CookieError::Expired);
        }
        let state = self.state();
        if header.server_id != state.server_id {
            return Err(CookieError::ServerChanged);
        }
        if header.config_generation != state.config_generation {
            return Err(CookieError::ConfigChanged);
        }
        Ok(claims)
    }
}

/// Cookie `Expiration` in the real server's seven-digit-fraction form.
fn xs(unix: i64) -> XsDateTime {
    XsDateTime::new(&format_xs7(unix)).expect("format_xs7 yields a valid xs:dateTime")
}

fn load_state(
    db: &Database,
    server_id: ServerId,
    fingerprint: &str,
    clock: &Clock,
) -> Result<ServerState, StorageError> {
    let get = |c: &rusqlite::Connection, k: &str| -> Result<Option<String>, StorageError> {
        use rusqlite::OptionalExtension;
        Ok(
            c.query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
                .optional()?,
        )
    };
    let (fp, generation, last) = db.with_conn(|c| {
        Ok((
            get(c, META_FINGERPRINT)?,
            get(c, META_CONFIG_GENERATION)?.and_then(|v| v.parse::<i64>().ok()),
            get(c, META_CONFIG_LAST_CHANGE)?.and_then(|v| v.parse::<i64>().ok()),
        ))
    })?;
    let now = clock();
    let (generation, last) = match (fp.as_deref() == Some(fingerprint), generation, last) {
        (true, Some(g), Some(l)) => (g, l),
        (_, g, l) => {
            let generation = g.unwrap_or(0) + 1;
            let last = now.max(l.unwrap_or(0) + 1);
            persist_state(db, generation, last)?;
            db.with_conn(|c| {
                c.execute(
                    "INSERT INTO meta(key,value) VALUES(?1,?2) \
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    rusqlite::params![META_FINGERPRINT, fingerprint],
                )?;
                Ok(())
            })?;
            (generation, last)
        }
    };
    Ok(ServerState {
        server_id,
        config_generation: generation,
        config_last_change: last,
    })
}

fn persist_state(db: &Database, generation: i64, last: i64) -> Result<(), StorageError> {
    db.transaction(|tx| {
        for (k, v) in [
            (META_CONFIG_GENERATION, generation),
            (META_CONFIG_LAST_CHANGE, last),
        ] {
            tx.execute(
                "INSERT INTO meta(key,value) VALUES(?1,?2) \
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                rusqlite::params![k, v.to_string()],
            )?;
        }
        Ok(())
    })
}
