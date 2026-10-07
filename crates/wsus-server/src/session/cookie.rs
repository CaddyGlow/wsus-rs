//! Binary cookie layout.
//!
//! ```text
//! magic "WC" | version u8 | kind u8 | key_id u32 | server_id [16] | config_generation i64
//! | issued_at i64 | expires_at i64 | computer [16] | catalog_generation i64
//! | policy_generation i64 | group_len u16 | group | dns_len u16 | dns | hmac [32]
//! ```
//! All integers are big endian. The MAC covers everything before it and is verified before
//! any other field is interpreted.
use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, ServerId};

use super::{CookieError, MAX_COOKIE_BYTES, ServerState, keys::KeyRing};

const MAGIC: &[u8; 2] = b"WC";
const VERSION: u8 = 1;
const TAG_LEN: usize = 32;
const MAX_TEXT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieKind {
    /// From `GetAuthorizationCookie`; only valid for `GetCookie`.
    Authorization,
    /// From `GetCookie`, `SyncUpdates` and `GetFileLocations`.
    Session,
    /// MS-WSUSSS: from the DSS authorization service; only valid for the Server Sync
    /// `GetCookie`. A distinct kind so a downstream server's cookie is never accepted by the
    /// MS-WUSP endpoints and the reverse.
    DownstreamAuthorization,
    /// MS-WSUSSS: from the Server Sync `GetCookie`.
    DownstreamSession,
}

/// What a cookie asserts about its holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieClaims {
    pub kind: CookieKind,
    pub computer: ComputerId,
    /// Set by [`super::SessionManager::issue`].
    pub issued_at: i64,
    /// Set by [`super::SessionManager::issue`].
    pub expires_at: i64,
    /// Catalog generation a synchronization sequence is pinned to (0 = none).
    pub catalog_generation: i64,
    /// Policy generation at the last synchronization (0 = never synchronized).
    pub policy_generation: i64,
    /// Target group requested at authorization time.
    pub target_group: Option<String>,
    /// DNS name supplied at authorization time.
    pub dns_name: Option<String>,
}

impl CookieClaims {
    pub fn new(kind: CookieKind, computer: ComputerId) -> Self {
        Self {
            kind,
            computer,
            issued_at: 0,
            expires_at: 0,
            catalog_generation: 0,
            policy_generation: 0,
            target_group: None,
            dns_name: None,
        }
    }
}

/// Header values that the manager compares against live state.
pub(crate) struct Header {
    pub server_id: ServerId,
    pub config_generation: i64,
}

pub(crate) fn seal(keys: &KeyRing, state: &ServerState, c: &CookieClaims) -> Vec<u8> {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(MAGIC);
    b.push(VERSION);
    b.push(match c.kind {
        CookieKind::Authorization => 1,
        CookieKind::Session => 2,
        CookieKind::DownstreamAuthorization => 3,
        CookieKind::DownstreamSession => 4,
    });
    b.extend_from_slice(&keys.current_id().to_be_bytes());
    b.extend_from_slice(state.server_id.0.as_bytes());
    b.extend_from_slice(&state.config_generation.to_be_bytes());
    b.extend_from_slice(&c.issued_at.to_be_bytes());
    b.extend_from_slice(&c.expires_at.to_be_bytes());
    b.extend_from_slice(c.computer.0.as_bytes());
    b.extend_from_slice(&c.catalog_generation.to_be_bytes());
    b.extend_from_slice(&c.policy_generation.to_be_bytes());
    for t in [&c.target_group, &c.dns_name] {
        let t = t.as_deref().unwrap_or("");
        let t = truncate(t, MAX_TEXT);
        b.extend_from_slice(&(t.len() as u16).to_be_bytes());
        b.extend_from_slice(t.as_bytes());
    }
    debug_assert!(b.len() + TAG_LEN <= MAX_COOKIE_BYTES);
    let tag = keys.sign(&b);
    b.extend_from_slice(&tag);
    b
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut n = max;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// Authenticate, then decode. Anything wrong before authentication is `Invalid`, and so is
/// anything wrong after it (an authentic cookie with a corrupt body cannot occur unless the
/// key leaked).
pub(crate) fn open(keys: &KeyRing, data: &[u8]) -> Result<(Header, CookieClaims), CookieError> {
    // Fixed prefix needed to find the key id: magic(2) version(1) kind(1) key_id(4).
    if data.len() < 8 + TAG_LEN || &data[..2] != MAGIC || data[2] != VERSION {
        return Err(CookieError::Invalid);
    }
    let key_id = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let (body, tag) = data.split_at(data.len() - TAG_LEN);
    if !keys.verify(key_id, body, tag) {
        return Err(CookieError::Invalid);
    }
    let mut r = Reader { b: &body[8..] };
    let kind = match data[3] {
        1 => CookieKind::Authorization,
        2 => CookieKind::Session,
        3 => CookieKind::DownstreamAuthorization,
        4 => CookieKind::DownstreamSession,
        _ => return Err(CookieError::Invalid),
    };
    let server_id = ServerId(Uuid::from_bytes(r.array()?));
    let config_generation = r.i64()?;
    let issued_at = r.i64()?;
    let expires_at = r.i64()?;
    let computer = ComputerId(Uuid::from_bytes(r.array()?));
    let catalog_generation = r.i64()?;
    let policy_generation = r.i64()?;
    let target_group = r.text()?;
    let dns_name = r.text()?;
    if !r.b.is_empty() {
        return Err(CookieError::Invalid);
    }
    Ok((
        Header {
            server_id,
            config_generation,
        },
        CookieClaims {
            kind,
            computer,
            issued_at,
            expires_at,
            catalog_generation,
            policy_generation,
            target_group,
            dns_name,
        },
    ))
}

struct Reader<'a> {
    b: &'a [u8],
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CookieError> {
        if self.b.len() < n {
            return Err(CookieError::Invalid);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CookieError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn i64(&mut self) -> Result<i64, CookieError> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    fn text(&mut self) -> Result<Option<String>, CookieError> {
        let n = u16::from_be_bytes(self.array()?) as usize;
        let s = std::str::from_utf8(self.take(n)?).map_err(|_| CookieError::Invalid)?;
        Ok((!s.is_empty()).then(|| s.to_owned()))
    }
}
