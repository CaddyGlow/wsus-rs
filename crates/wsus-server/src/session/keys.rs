//! Signing keys persisted in the database `meta` table.
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use sha2::Sha256;
use uuid::Uuid;

use crate::storage::{Database, Error, Result, hex_decode, hex_encode};

const META_CURRENT: &str = "wusp_session_key_current";
const META_PREVIOUS: &str = "wusp_session_key_previous";

pub(crate) type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct Key {
    id: u32,
    bytes: [u8; 32],
}

impl Key {
    fn generate(id: u32) -> Self {
        // Two v4 UUIDs: each carries 122 random bits from the operating system RNG.
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self { id, bytes }
    }

    fn encode(&self) -> String {
        format!("{}:{}", self.id, hex_encode(&self.bytes))
    }

    fn decode(s: &str) -> Result<Self> {
        let bad = || Error::Integrity("stored session key is malformed".into());
        let (id, hex) = s.split_once(':').ok_or_else(bad)?;
        let bytes = hex_decode(hex).ok_or_else(bad)?;
        Ok(Self {
            id: id.parse().map_err(|_| bad())?,
            bytes: bytes.try_into().map_err(|_| bad())?,
        })
    }

    fn mac(&self, data: &[u8]) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(&self.bytes).expect("HMAC accepts any key length");
        m.update(data);
        m
    }
}

/// Current and (optionally) previous signing key.
pub struct KeyRing {
    current: Key,
    previous: Option<Key>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("KeyRing")
            .field("current_id", &self.current.id)
            .field("previous_id", &self.previous.as_ref().map(|k| k.id))
            .finish()
    }
}

fn get(c: &rusqlite::Connection, k: &str) -> Result<Option<String>> {
    Ok(
        c.query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
            .optional()?,
    )
}

fn put(tx: &rusqlite::Transaction<'_>, k: &str, v: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![k, v],
    )?;
    Ok(())
}

impl KeyRing {
    pub fn load_or_create(db: &Database) -> Result<Self> {
        db.transaction(|tx| {
            let current = match get(tx, META_CURRENT)? {
                Some(s) => Key::decode(&s)?,
                None => {
                    let k = Key::generate(1);
                    put(tx, META_CURRENT, &k.encode())?;
                    k
                }
            };
            let previous = get(tx, META_PREVIOUS)?
                .filter(|s| !s.is_empty())
                .map(|s| Key::decode(&s))
                .transpose()?;
            Ok(Self { current, previous })
        })
    }

    pub(crate) fn rotated(&self, db: &Database, retain_previous: bool) -> Result<Self> {
        let next = Key::generate(self.current.id.wrapping_add(1));
        let previous = retain_previous.then(|| self.current.clone());
        db.transaction(|tx| {
            put(tx, META_CURRENT, &next.encode())?;
            put(
                tx,
                META_PREVIOUS,
                &previous.as_ref().map(Key::encode).unwrap_or_default(),
            )
        })?;
        Ok(Self {
            current: next,
            previous,
        })
    }

    pub(crate) fn current_id(&self) -> u32 {
        self.current.id
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.current.mac(data).finalize().into_bytes().to_vec()
    }

    /// Constant-time verification against the key named by `key_id`.
    pub(crate) fn verify(&self, key_id: u32, data: &[u8], tag: &[u8]) -> bool {
        let key = if key_id == self.current.id {
            &self.current
        } else {
            match self.previous.as_ref().filter(|k| k.id == key_id) {
                Some(k) => k,
                None => return false,
            }
        };
        key.mac(data).verify_slice(tag).is_ok()
    }
}
