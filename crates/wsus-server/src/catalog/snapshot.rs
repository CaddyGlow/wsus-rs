use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, params};
use wsus_protocol::identity::{
    FileDigest, LocalRevisionId, Revision, ServerId, UpdateId, UpdateRevision,
};

use super::model::*;
use crate::storage::{Database, Error, Result, parse_algorithm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentRecord {
    pub local: LocalRevisionId,
    pub identity: UpdateRevision,
    pub kind: String,
    pub state: FragmentState,
    pub core_xml: Vec<u8>,
    pub extended_xml: Option<Vec<u8>>,
    pub core_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    pub kind: RelationshipKind,
    pub target: UpdateId,
    pub revision: Option<Revision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Pass as `after` to fetch the next page; `None` when exhausted.
    pub next: Option<i32>,
}

/// Read-only view of one immutable generation. Paging is keyed by local revision id, so a
/// sequence of pages always sees the same data regardless of later imports or activations.
#[derive(Debug, Clone)]
pub struct Snapshot {
    db: Database,
    generation: GenerationId,
    server: ServerId,
}

impl Snapshot {
    pub(crate) fn new(db: Database, generation: GenerationId) -> Result<Self> {
        let state: Option<String> = db.with_conn(|c| {
            Ok(c.query_row(
                "SELECT state FROM generations WHERE id=?1",
                [generation.0],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        let state = state.ok_or_else(|| Error::NotFound(format!("generation {}", generation.0)))?;
        match GenerationState::parse(&state)? {
            GenerationState::Active | GenerationState::Superseded => {}
            other => {
                return Err(Error::Conflict(format!(
                    "generation {} is {} and cannot be read as a snapshot",
                    generation.0,
                    other.as_str()
                )));
            }
        }
        let server = db.server_id()?;
        Ok(Self {
            db,
            generation,
            server,
        })
    }

    pub fn generation(&self) -> GenerationId {
        self.generation
    }

    pub fn count(&self) -> Result<u64> {
        self.db.with_conn(|c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM fragments WHERE generation_id=?1",
                [self.generation.0],
                |r| r.get(0),
            )?;
            Ok(n as u64)
        })
    }

    /// Page through fragments ordered by local id. `include_inactive` adds withdrawn and
    /// deleted fragments.
    pub fn list(
        &self,
        after: Option<i32>,
        limit: usize,
        include_inactive: bool,
    ) -> Result<Page<FragmentRecord>> {
        let limit = limit.clamp(1, 10_000);
        self.db.with_conn(|c| {
            let mut st = c.prepare(&format!(
                "{SELECT_FRAGMENT} WHERE f.generation_id=?1 AND f.local_id>?2 \
                 AND (?3 OR f.state='present') ORDER BY f.local_id LIMIT ?4"
            ))?;
            let rows = st.query_map(
                params![
                    self.generation.0,
                    after.unwrap_or(i32::MIN),
                    include_inactive,
                    limit as i64 + 1
                ],
                |r| fragment_row(r, self.server),
            )?;
            let mut items = rows.map(|r| r?).collect::<Result<Vec<FragmentRecord>>>()?;
            let next = if items.len() > limit {
                items.truncate(limit);
                items.last().map(|f| f.local.id)
            } else {
                None
            };
            Ok(Page { items, next })
        })
    }

    pub fn get(&self, identity: UpdateRevision) -> Result<Option<FragmentRecord>> {
        self.db.with_conn(|c| {
            let row = c
                .query_row(
                    &format!(
                        "{SELECT_FRAGMENT} WHERE f.generation_id=?1 AND lr.update_id=?2 \
                         AND lr.revision=?3"
                    ),
                    params![
                        self.generation.0,
                        identity.id.0.to_string(),
                        identity.revision.0
                    ],
                    |r| fragment_row(r, self.server),
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn get_local(&self, local: LocalRevisionId) -> Result<Option<FragmentRecord>> {
        if local.server != self.server {
            return Err(Error::Invalid(
                "local revision id belongs to a different server".into(),
            ));
        }
        self.db.with_conn(|c| {
            let row = c
                .query_row(
                    &format!("{SELECT_FRAGMENT} WHERE f.generation_id=?1 AND f.local_id=?2"),
                    params![self.generation.0, local.id],
                    |r| fragment_row(r, self.server),
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn relationships(&self, local: LocalRevisionId) -> Result<Vec<Relationship>> {
        self.db
            .with_conn(|c| relationships_conn(c, self.generation, local.id))
    }

    /// Every update that is the target of a prerequisite relationship anywhere in this
    /// generation. A real WSUS reports `IsLeaf=false` for exactly these, independent of which
    /// updates a given client can see (Observed 2026-10-04: 476 distinct prerequisite targets,
    /// all non-leaf; bundle members are leaves). `IsCategory` clauses are prerequisites too
    /// (kind `category`): in the native `scan` capture the middle category of a chain that is
    /// referenced only through an `IsCategory` clause is `IsLeaf=false`.
    pub fn prerequisite_targets(&self) -> Result<BTreeSet<UpdateId>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT DISTINCT target_update_id FROM relationships \
                 WHERE generation_id=?1 AND kind IN ('prerequisite','category')",
            )?;
            let rows = st.query_map(params![self.generation.0], |r| r.get::<_, String>(0))?;
            rows.map(|r| parse_update_id(&r?)).collect()
        })
    }

    /// True when some revision of `id` is present in this generation (any revision, any
    /// update type).
    pub fn has_present_update(&self, id: UpdateId) -> Result<bool> {
        self.db.with_conn(|c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM local_revisions lr CROSS JOIN fragments f \
                 ON f.generation_id=?1 AND f.local_id=lr.local_id \
                 WHERE lr.update_id=?2 AND f.state='present'",
                params![self.generation.0, id.0.to_string()],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
    }

    /// The highest present revision of `id` in this generation.
    pub fn latest_revision(&self, id: UpdateId) -> Result<Option<Revision>> {
        self.db.with_conn(|c| {
            let n: Option<u32> = c.query_row(
                "SELECT MAX(lr.revision) FROM local_revisions lr CROSS JOIN fragments f \
                 ON f.generation_id=?1 AND f.local_id=lr.local_id \
                 WHERE lr.update_id=?2 AND f.state='present'",
                params![self.generation.0, id.0.to_string()],
                |r| r.get(0),
            )?;
            Ok(n.map(Revision))
        })
    }

    pub fn files(&self, local: LocalRevisionId) -> Result<Vec<FileDescriptor>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT ordinal,file_name,size FROM files WHERE generation_id=?1 AND local_id=?2 \
                 ORDER BY ordinal",
            )?;
            let files: Vec<(i64, String, i64)> = st
                .query_map(params![self.generation.0, local.id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<std::result::Result<_, _>>()?;
            let mut out = Vec::new();
            for (ord, name, size) in files {
                let mut ds = c.prepare(
                    "SELECT algorithm,digest FROM file_digests WHERE generation_id=?1 AND \
                     local_id=?2 AND ordinal=?3 ORDER BY algorithm",
                )?;
                let digests = ds
                    .query_map(params![self.generation.0, local.id, ord], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })?
                    .map(|r| {
                        let (a, b) = r?;
                        Ok(FileDigest {
                            algorithm: parse_algorithm(&a)?,
                            bytes: b,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                out.push(FileDescriptor {
                    file_name: name,
                    size: size as u64,
                    digests,
                });
            }
            Ok(out)
        })
    }

    /// Visit every `present` fragment in local-id order with its relationships, one row in memory
    /// at a time (a real Windows catalog holds about 1.2 GB of documents, one of them 47 MB).
    pub fn for_each_present<F>(&self, mut visit: F) -> Result<()>
    where
        F: FnMut(&FragmentRecord, Vec<Relationship>) -> Result<()>,
    {
        self.db.with_conn(|c| {
            let mut st = c.prepare(&format!(
                "{SELECT_FRAGMENT} WHERE f.generation_id=?1 AND f.state='present' \
                 ORDER BY f.local_id"
            ))?;
            let mut rows = st.query(params![self.generation.0])?;
            while let Some(row) = rows.next()? {
                let record = fragment_row(row, self.server)?;
                let record = record?;
                let rels = relationships_conn(c, self.generation, record.local.id)?;
                visit(&record, rels)?;
            }
            Ok(())
        })
    }

    /// Local ids of the revisions of this generation that declare a file with this SHA-1.
    pub fn locals_with_sha1(&self, sha1: &[u8]) -> Result<Vec<i32>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT DISTINCT local_id FROM file_digests WHERE generation_id=?1 AND \
                 algorithm='sha1' AND digest=?2 ORDER BY local_id",
            )?;
            let ids = st
                .query_map(params![self.generation.0, sha1], |r| r.get(0))?
                .collect::<std::result::Result<Vec<i32>, _>>()?;
            Ok(ids)
        })
    }

    /// Roots plus everything reachable through prerequisite and bundle edges, so scoped
    /// delivery keeps the metadata clients need to evaluate applicability. Ordered by
    /// local id. Withdrawn or deleted fragments are included when referenced.
    pub fn closure(&self, roots: &[UpdateId]) -> Result<Vec<FragmentRecord>> {
        let mut seen_ids: BTreeSet<UpdateId> = BTreeSet::new();
        let mut frontier: Vec<UpdateId> = roots.to_vec();
        let mut locals: BTreeSet<i32> = BTreeSet::new();
        self.db.with_conn(|c| {
            while let Some(id) = frontier.pop() {
                if !seen_ids.insert(id) {
                    continue;
                }
                // Start from `local_revisions` through its (update_id, revision) index; the
                // plain JOIN made SQLite scan every fragment of the generation per id.
                let mut st = c.prepare(
                    "SELECT f.local_id FROM local_revisions lr CROSS JOIN fragments f \
                     ON f.generation_id=?1 AND f.local_id=lr.local_id WHERE lr.update_id=?2",
                )?;
                let ids: Vec<i32> = st
                    .query_map(params![self.generation.0, id.0.to_string()], |r| r.get(0))?
                    .collect::<std::result::Result<_, _>>()?;
                for local in ids {
                    if locals.insert(local) {
                        for r in relationships_conn(c, self.generation, local)? {
                            if matches!(
                                r.kind,
                                RelationshipKind::Prerequisite
                                    | RelationshipKind::Category
                                    | RelationshipKind::Bundle
                            ) {
                                frontier.push(r.target);
                            }
                        }
                    }
                }
            }
            Ok(())
        })?;
        locals
            .into_iter()
            .filter_map(|l| {
                self.get_local(LocalRevisionId {
                    server: self.server,
                    id: l,
                })
                .transpose()
            })
            .collect()
    }
}

const SELECT_FRAGMENT: &str = "SELECT f.local_id,lr.update_id,lr.revision,f.kind,f.state,\
    f.core_xml,f.extended_xml,f.core_sha256 FROM fragments f JOIN local_revisions lr \
    ON lr.local_id=f.local_id";

fn fragment_row(
    r: &rusqlite::Row<'_>,
    server: ServerId,
) -> rusqlite::Result<Result<FragmentRecord>> {
    let uid: String = r.get(1)?;
    let state: String = r.get(4)?;
    let local: i32 = r.get(0)?;
    let rev: u32 = r.get(2)?;
    let kind: String = r.get(3)?;
    let core_xml: Vec<u8> = r.get(5)?;
    let extended_xml: Option<Vec<u8>> = r.get(6)?;
    let core_sha256: String = r.get(7)?;
    Ok((|| {
        Ok(FragmentRecord {
            local: LocalRevisionId { server, id: local },
            identity: UpdateRevision {
                id: parse_update_id(&uid)?,
                revision: Revision(rev),
            },
            kind,
            state: FragmentState::parse(&state)?,
            core_xml,
            extended_xml,
            core_sha256,
        })
    })())
}

fn relationships_conn(
    c: &rusqlite::Connection,
    g: GenerationId,
    local: i32,
) -> Result<Vec<Relationship>> {
    let mut st = c.prepare(
        "SELECT kind,target_update_id,target_revision FROM relationships \
         WHERE generation_id=?1 AND from_local=?2 ORDER BY id",
    )?;
    let rows = st.query_map(params![g.0, local], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<u32>>(2)?,
        ))
    })?;
    rows.map(|r| {
        let (k, t, rev) = r?;
        Ok(Relationship {
            kind: RelationshipKind::parse(&k)?,
            target: parse_update_id(&t)?,
            revision: rev.map(Revision),
        })
    })
    .collect()
}
