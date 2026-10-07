//! Cheap per-generation summaries for enumeration.
//!
//! `GetRevisionIdList` needs identity, kind, state and a content hash of every revision of a
//! generation, never the metadata itself. A direct query avoids loading every blob (a real
//! catalog is large). Generations are immutable once active, so a summary never goes stale
//! and is cached.
use std::collections::BTreeMap;
use std::sync::Arc;

use rusqlite::params;
use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};

use crate::catalog::{FragmentState, GenerationId};
use crate::storage::{Database, Error, Result};

/// How many leading bytes of a record are inspected to decide whether it is a whole update
/// document.
const SNIFF_BYTES: i64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub identity: UpdateRevision,
    pub kind: String,
    pub state: FragmentState,
    pub sha256: String,
    pub blob_len: u64,
}

impl Entry {
    /// Categories, classifications and detectoids: what `GetConfig=true` enumerates.
    pub fn is_config(&self) -> bool {
        matches!(self.kind.as_str(), "Category" | "Detectoid")
    }
}

/// Highest served revision per update GUID of one generation.
#[derive(Debug, Default)]
pub(crate) struct Summary {
    pub newest: BTreeMap<UpdateId, Entry>,
    /// Largest metadata blob of any served revision.
    pub max_blob: u64,
    /// Records not enumerated: tombstones, revisions below the newest of their GUID, and
    /// records whose Core slot is not a whole update document (stored in WUSP form).
    pub excluded: usize,
}

/// True when the bytes start like an `Update` document root (after BOM, whitespace and an
/// XML declaration). A cheap filter; `GetUpdateData` serves the blob as stored.
pub(crate) fn looks_like_update_document(head: &[u8]) -> bool {
    let mut b = head;
    if let [0xEF, 0xBB, 0xBF, rest @ ..] = b {
        b = rest;
    }
    let trim = |b: &[u8]| -> usize { b.iter().take_while(|c| c.is_ascii_whitespace()).count() };
    b = &b[trim(b)..];
    if b.starts_with(b"<?xml") {
        match b.windows(2).position(|w| w == b"?>") {
            Some(i) => b = &b[i + 2..],
            None => return false,
        }
        b = &b[trim(b)..];
    }
    let Some(rest) = b.strip_prefix(b"<") else {
        return false;
    };
    let name_end = rest
        .iter()
        .position(|c| c.is_ascii_whitespace() || matches!(c, b'>' | b'/'))
        .unwrap_or(rest.len());
    let name = &rest[..name_end];
    name == b"Update" || name.ends_with(b":Update")
}

pub(crate) fn load(db: &Database, generation: GenerationId) -> Result<Summary> {
    db.with_conn(|c| {
        let mut st = c.prepare(
            "SELECT lr.update_id,lr.revision,f.kind,f.state,f.core_sha256,length(f.core_xml),\
             substr(f.core_xml,1,?2) FROM fragments f JOIN local_revisions lr \
             ON lr.local_id=f.local_id WHERE f.generation_id=?1",
        )?;
        let rows = st.query_map(params![generation.0, SNIFF_BYTES], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Vec<u8>>(6)?,
            ))
        })?;
        let mut out = Summary::default();
        for row in rows {
            let (id, rev, kind, state, sha256, len, head) = row?;
            let state = FragmentState::parse(&state)?;
            if state == FragmentState::Deleted || !looks_like_update_document(&head) {
                out.excluded += 1;
                continue;
            }
            let id = UpdateId(
                Uuid::parse_str(&id)
                    .map_err(|e| Error::Integrity(format!("stored update id invalid: {e}")))?,
            );
            let entry = Entry {
                identity: UpdateRevision {
                    id,
                    revision: Revision(rev),
                },
                kind,
                state,
                sha256,
                blob_len: len.max(0) as u64,
            };
            out.max_blob = out.max_blob.max(entry.blob_len);
            match out.newest.get(&id) {
                Some(cur) if cur.identity.revision >= entry.identity.revision => {
                    out.excluded += 1;
                }
                _ => {
                    out.newest.insert(id, entry);
                }
            }
        }
        Ok(out)
    })
}

/// Entries of `new` that differ from `old` (or all, without `old`), restricted to one
/// enumeration class, ordered by update id.
pub(crate) fn delta(old: Option<&Summary>, new: &Summary, config: bool) -> Vec<UpdateRevision> {
    new.newest
        .values()
        .filter(|e| e.is_config() == config)
        .filter(|e| match old.and_then(|o| o.newest.get(&e.identity.id)) {
            Some(o) => o.identity != e.identity || o.sha256 != e.sha256 || o.state != e.state,
            None => true,
        })
        .map(|e| e.identity)
        .collect()
}

/// Bounded cache of summaries keyed by generation.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    items: Vec<(GenerationId, Arc<Summary>)>,
}

const CACHE_LEN: usize = 4;

impl Cache {
    pub fn get_or_load(
        cache: &std::sync::Mutex<Self>,
        db: &Database,
        generation: GenerationId,
    ) -> Result<Arc<Summary>> {
        {
            let c = cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, s)) = c.items.iter().find(|(g, _)| *g == generation) {
                return Ok(Arc::clone(s));
            }
        }
        let loaded = Arc::new(load(db, generation)?);
        let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
        c.items.retain(|(g, _)| *g != generation);
        c.items.push((generation, Arc::clone(&loaded)));
        if c.items.len() > CACHE_LEN {
            c.items.remove(0);
        }
        Ok(loaded)
    }
}

#[cfg(test)]
mod tests {
    use super::looks_like_update_document;

    #[test]
    fn sniffs_the_document_root() {
        assert!(looks_like_update_document(
            b"\xEF\xBB\xBF <?xml version=\"1.0\"?>\n<Update xmlns=\"x\">"
        ));
        assert!(looks_like_update_document(b"<u:Update xmlns:u=\"x\">"));
        assert!(looks_like_update_document(b"<Update/>"));
        assert!(!looks_like_update_document(
            b"<UpdateIdentity UpdateID=\"1\"/>"
        ));
        assert!(!looks_like_update_document(b"<Updates>"));
        assert!(!looks_like_update_document(b""));
    }
}
