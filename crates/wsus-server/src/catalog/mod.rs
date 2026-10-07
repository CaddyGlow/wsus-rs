//! Catalog: sources, synchronization generations, staged imports, validation, atomic
//! activation, and immutable snapshot reads.
//!
//! A generation is a complete set of metadata fragments imported from one source. It is
//! staged, validated, then activated in one transaction. Failed or rejected generations
//! remain readable as recovery evidence but are never visible through [`Catalog::snapshot`].
mod model;
mod snapshot;

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use wsus_protocol::identity::{LocalRevisionId, Revision, ServerId, UpdateId, UpdateRevision};

pub use model::*;
pub use snapshot::{FragmentRecord, Page, Relationship, Snapshot};

use crate::storage::{Database, Error, Result, algorithm_name, bump_counter, hex_encode, now_unix};

const REQUIRED_TARGET_KINDS: &[RelationshipKind] = &[
    RelationshipKind::Prerequisite,
    RelationshipKind::Bundle,
    RelationshipKind::Classification,
    RelationshipKind::Product,
    RelationshipKind::Category,
];

#[derive(Debug, Clone)]
pub struct Catalog {
    db: Database,
}

impl Catalog {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    // ---- sources ----

    pub fn add_source(&self, name: &str, kind: SourceKind, description: &str) -> Result<SourceId> {
        if name.is_empty() {
            return Err(Error::Invalid("source name is empty".into()));
        }
        self.db.transaction(|tx| {
            let exists: Option<i64> = tx
                .query_row("SELECT id FROM sources WHERE name=?1", [name], |r| r.get(0))
                .optional()?;
            if exists.is_some() {
                return Err(Error::Conflict(format!("source {name} already exists")));
            }
            tx.execute(
                "INSERT INTO sources(name,kind,description,created_at) VALUES(?1,?2,?3,?4)",
                params![name, kind.as_str(), description, now_unix()],
            )?;
            Ok(SourceId(tx.last_insert_rowid()))
        })
    }

    pub fn source_by_name(&self, name: &str) -> Result<Option<Source>> {
        self.db.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT id,name,kind,description,created_at FROM sources WHERE name=?1",
                    [name],
                    source_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn sources(&self) -> Result<Vec<Source>> {
        self.db.with_conn(|c| {
            let mut st =
                c.prepare("SELECT id,name,kind,description,created_at FROM sources ORDER BY id")?;
            let rows = st.query_map([], source_row)?;
            rows.map(|r| r?).collect()
        })
    }

    // ---- local revision mapping ----

    /// Map an update revision to its server-scoped local id, allocating one if needed.
    /// Local ids come from a dedicated counter and are independent of any row id.
    pub fn local_id(&self, identity: UpdateRevision) -> Result<LocalRevisionId> {
        let server = self.db.server_id()?;
        self.db
            .transaction(|tx| resolve_local(tx, server, identity))
    }

    pub fn find_local_id(&self, identity: UpdateRevision) -> Result<Option<LocalRevisionId>> {
        let server = self.db.server_id()?;
        self.db.with_conn(|c| {
            let id: Option<i32> = c
                .query_row(
                    "SELECT local_id FROM local_revisions WHERE update_id=?1 AND revision=?2",
                    params![identity.id.0.to_string(), identity.revision.0],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(id.map(|id| LocalRevisionId { server, id }))
        })
    }

    /// Resolve a local id back to its update revision. Ids minted by another server are
    /// rejected rather than interpreted.
    pub fn lookup_local(&self, local: LocalRevisionId) -> Result<Option<UpdateRevision>> {
        if local.server != self.db.server_id()? {
            return Err(Error::Invalid(
                "local revision id belongs to a different server".into(),
            ));
        }
        self.db.with_conn(|c| lookup_local_conn(c, local.id))
    }

    // ---- generations ----

    pub fn begin_generation(&self, source: SourceId, anchor: Option<&str>) -> Result<GenerationId> {
        self.db.transaction(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM sources WHERE id=?1",
                [source.0],
                |r| r.get(0),
            )?;
            if n == 0 {
                return Err(Error::NotFound(format!("source {}", source.0)));
            }
            tx.execute(
                "INSERT INTO generations(source_id,state,anchor,started_at) \
                 VALUES(?1,'staging',?2,?3)",
                params![source.0, anchor, now_unix()],
            )?;
            Ok(GenerationId(tx.last_insert_rowid()))
        })
    }

    pub fn generation(&self, generation: GenerationId) -> Result<GenerationInfo> {
        self.db.with_conn(|c| generation_info(c, generation))
    }

    pub fn active_generation(&self, source: SourceId) -> Result<Option<GenerationId>> {
        self.db.with_conn(|c| {
            Ok(c.query_row(
                "SELECT generation_id FROM active_generations WHERE source_id=?1",
                [source.0],
                |r| r.get(0).map(GenerationId),
            )
            .optional()?)
        })
    }

    /// Import a batch of fragments (with relationships and file descriptors) into a
    /// staging generation. The batch is all-or-nothing.
    pub fn import_fragments(
        &self,
        generation: GenerationId,
        fragments: &[FragmentImport],
    ) -> Result<usize> {
        for f in fragments {
            f.check()?;
        }
        let server = self.db.server_id()?;
        self.db.transaction(|tx| {
            require_state(tx, generation, GenerationState::Staging)?;
            for f in fragments {
                let local = resolve_local(tx, server, f.identity)?;
                let digest = hex_encode(&Sha256::digest(&f.core_xml));
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO fragments(generation_id,local_id,kind,state,core_xml,\
                     extended_xml,core_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        generation.0,
                        local.id,
                        f.kind,
                        f.state.as_str(),
                        f.core_xml,
                        f.extended_xml,
                        digest
                    ],
                )?;
                if inserted == 0 {
                    return Err(Error::Conflict(format!(
                        "fragment {}:{} already imported in generation {}",
                        f.identity.id.0, f.identity.revision.0, generation.0
                    )));
                }
                for r in &f.relationships {
                    tx.execute(
                        "INSERT INTO relationships(generation_id,from_local,kind,target_update_id,\
                         target_revision) VALUES(?1,?2,?3,?4,?5)",
                        params![
                            generation.0,
                            local.id,
                            r.kind.as_str(),
                            r.target.0.to_string(),
                            r.revision.map(|r| r.0)
                        ],
                    )?;
                }
                for (ord, file) in f.files.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO files(generation_id,local_id,ordinal,file_name,size) \
                         VALUES(?1,?2,?3,?4,?5)",
                        params![
                            generation.0,
                            local.id,
                            ord as i64,
                            file.file_name,
                            file.size as i64
                        ],
                    )?;
                    for d in &file.digests {
                        tx.execute(
                            "INSERT OR REPLACE INTO file_digests(generation_id,local_id,ordinal,\
                             algorithm,digest) VALUES(?1,?2,?3,?4,?5)",
                            params![
                                generation.0,
                                local.id,
                                ord as i64,
                                algorithm_name(d.algorithm),
                                d.bytes
                            ],
                        )?;
                    }
                }
            }
            Ok(fragments.len())
        })
    }

    /// Check relationships of a staging generation without changing anything.
    pub fn validate(&self, generation: GenerationId) -> Result<ValidationReport> {
        self.db.with_conn(|c| validate_conn(c, generation))
    }

    /// Validate and atomically activate a staging generation. The previously active
    /// generation of the same source becomes `superseded` in the same transaction. If
    /// validation fails the generation is marked `failed` with the report as evidence and
    /// the active catalog is left untouched.
    pub fn activate(&self, generation: GenerationId) -> Result<ActivateOutcome> {
        let outcome = self.db.transaction(|tx| {
            let info = generation_info(tx, generation)?;
            if info.state != GenerationState::Staging {
                return Err(Error::Conflict(format!(
                    "generation {} is {}, not staging",
                    generation.0,
                    info.state.as_str()
                )));
            }
            let report = validate_conn(tx, generation)?;
            if !report.is_valid() {
                return Ok(ActivateOutcome::Rejected(report));
            }
            let now = now_unix();
            tx.execute(
                "UPDATE generations SET state='superseded', finished_at=?2 WHERE source_id=?1 \
                 AND state='active'",
                params![info.source.0, now],
            )?;
            tx.execute(
                "UPDATE generations SET state='active', finished_at=?2, activated_at=?2 \
                 WHERE id=?1",
                params![generation.0, now],
            )?;
            tx.execute(
                "INSERT INTO active_generations(source_id,generation_id) VALUES(?1,?2) \
                 ON CONFLICT(source_id) DO UPDATE SET generation_id=excluded.generation_id",
                params![info.source.0, generation.0],
            )?;
            let fragments: i64 = tx.query_row(
                "SELECT COUNT(*) FROM fragments WHERE generation_id=?1",
                [generation.0],
                |r| r.get(0),
            )?;
            Ok(ActivateOutcome::Activated {
                fragments: fragments as u64,
            })
        })?;
        if let ActivateOutcome::Rejected(report) = &outcome {
            let evidence = serde_json::to_string(report)?;
            self.db.transaction(|tx| {
                tx.execute(
                    "UPDATE generations SET state='failed', finished_at=?2, evidence=?3 \
                     WHERE id=?1 AND state='staging'",
                    params![generation.0, now_unix(), evidence],
                )?;
                Ok(())
            })?;
        }
        Ok(outcome)
    }

    /// Mark a staging generation failed, keeping its staged rows as evidence.
    pub fn fail_generation(&self, generation: GenerationId, reason: &str) -> Result<()> {
        self.db.transaction(|tx| {
            require_state(tx, generation, GenerationState::Staging)?;
            let evidence = serde_json::json!({ "reason": reason }).to_string();
            tx.execute(
                "UPDATE generations SET state='failed', finished_at=?2, evidence=?3 WHERE id=?1",
                params![generation.0, now_unix(), evidence],
            )?;
            Ok(())
        })
    }

    /// Fail every staging generation of every source. Their rows are retained as evidence.
    ///
    /// This also fails *resumable* upstream staging generations
    /// ([`crate::upstream::UpstreamSync::stage`] continues an interrupted one whose pending
    /// checkpoint still matches), so it is not what a server should call at startup. Use
    /// [`Self::recover_after_restart`] or [`Self::abandon_interrupted_in`] there.
    pub fn abandon_interrupted(&self) -> Result<Vec<GenerationId>> {
        self.abandon_interrupted_in(&AbandonScope::All)
    }

    /// Startup recovery: fail staging generations that nothing can resume, and leave
    /// upstream ones (kind [`SourceKind::Upstream`]) alone so the orchestrator can decide
    /// whether to resume or fail them.
    pub fn recover_after_restart(&self) -> Result<Vec<GenerationId>> {
        self.abandon_interrupted_in(&AbandonScope::SkipUpstream)
    }

    /// Fail the staging generations selected by `scope`, in one transaction. Returns the
    /// failed generations in id order.
    pub fn abandon_interrupted_in(&self, scope: &AbandonScope) -> Result<Vec<GenerationId>> {
        self.db.transaction(|tx| {
            let ids: Vec<i64> = {
                let mut st = tx.prepare(
                    "SELECT g.id, s.id, s.kind FROM generations g JOIN sources s \
                     ON s.id=g.source_id WHERE g.state='staging' ORDER BY g.id",
                )?;
                let rows = st.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?;
                let mut out = Vec::new();
                for row in rows {
                    let (id, source, kind) = row?;
                    if scope.includes(SourceId(source), SourceKind::parse(&kind)?) {
                        out.push(id);
                    }
                }
                out
            };
            let evidence =
                serde_json::json!({ "reason": "interrupted before activation" }).to_string();
            for id in &ids {
                tx.execute(
                    "UPDATE generations SET state='failed', finished_at=?2, evidence=?3 WHERE id=?1",
                    params![id, now_unix(), evidence],
                )?;
            }
            Ok(ids.into_iter().map(GenerationId).collect())
        })
    }

    /// Immutable view of a source's active generation.
    pub fn snapshot(&self, source: SourceId) -> Result<Option<Snapshot>> {
        match self.active_generation(source)? {
            Some(g) => Ok(Some(Snapshot::new(self.db.clone(), g)?)),
            None => Ok(None),
        }
    }

    /// Immutable view of a specific generation. Only active or superseded generations are
    /// immutable and servable; staging and failed ones are refused.
    pub fn snapshot_of(&self, generation: GenerationId) -> Result<Snapshot> {
        Snapshot::new(self.db.clone(), generation)
    }

    /// Delete superseded generations beyond the newest `keep` for a source. Failed
    /// generations (evidence) and the active generation are never pruned.
    pub fn prune_superseded(&self, source: SourceId, keep: usize) -> Result<usize> {
        self.db.transaction(|tx| {
            let ids: Vec<i64> = {
                let mut st = tx.prepare(
                    "SELECT id FROM generations WHERE source_id=?1 AND state='superseded' \
                     ORDER BY id DESC LIMIT -1 OFFSET ?2",
                )?;
                st.query_map(params![source.0, keep as i64], |r| r.get(0))?
                    .collect::<std::result::Result<_, _>>()?
            };
            for id in &ids {
                for table in ["file_digests", "files", "relationships", "fragments"] {
                    tx.execute(&format!("DELETE FROM {table} WHERE generation_id=?1"), [id])?;
                }
                tx.execute("DELETE FROM generations WHERE id=?1", [id])?;
            }
            Ok(ids.len())
        })
    }

    /// Every distinct update id with a fragment in the generation, for scoping.
    pub fn update_ids(&self, generation: GenerationId) -> Result<BTreeSet<UpdateId>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT DISTINCT lr.update_id FROM fragments f JOIN local_revisions lr \
                 ON lr.local_id=f.local_id WHERE f.generation_id=?1",
            )?;
            let rows = st.query_map([generation.0], |r| r.get::<_, String>(0))?;
            let mut out = BTreeSet::new();
            for r in rows {
                out.insert(model::parse_update_id(&r?)?);
            }
            Ok(out)
        })
    }
}

fn source_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Source>> {
    let kind: String = r.get(2)?;
    Ok(SourceKind::parse(&kind).map(|kind| Source {
        id: SourceId(r.get_unwrap(0)),
        name: r.get_unwrap(1),
        kind,
        description: r.get_unwrap(3),
        created_at: r.get_unwrap(4),
    }))
}

pub(crate) fn lookup_local_conn(
    c: &rusqlite::Connection,
    local: i32,
) -> Result<Option<UpdateRevision>> {
    let row: Option<(String, u32)> = c
        .query_row(
            "SELECT update_id,revision FROM local_revisions WHERE local_id=?1",
            [local],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((id, rev)) => Ok(Some(UpdateRevision {
            id: model::parse_update_id(&id)?,
            revision: Revision(rev),
        })),
        None => Ok(None),
    }
}

fn resolve_local(
    tx: &Transaction<'_>,
    server: ServerId,
    identity: UpdateRevision,
) -> Result<LocalRevisionId> {
    let uid = identity.id.0.to_string();
    let existing: Option<i32> = tx
        .query_row(
            "SELECT local_id FROM local_revisions WHERE update_id=?1 AND revision=?2",
            params![uid, identity.revision.0],
            |r| r.get(0),
        )
        .optional()?;
    let id = match existing {
        Some(id) => id,
        None => {
            let next = bump_counter(tx, "next_local_revision")?;
            let id = i32::try_from(next)
                .map_err(|_| Error::Integrity("local revision id space exhausted".into()))?;
            tx.execute(
                "INSERT INTO local_revisions(local_id,update_id,revision) VALUES(?1,?2,?3)",
                params![id, uid, identity.revision.0],
            )?;
            id
        }
    };
    Ok(LocalRevisionId { server, id })
}

fn generation_info(c: &rusqlite::Connection, g: GenerationId) -> Result<GenerationInfo> {
    let row = c
        .query_row(
            "SELECT source_id,state,anchor,started_at,finished_at,activated_at,evidence \
             FROM generations WHERE id=?1",
            [g.0],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("generation {}", g.0)))?;
    Ok(GenerationInfo {
        id: g,
        source: SourceId(row.0),
        state: GenerationState::parse(&row.1)?,
        anchor: row.2,
        started_at: row.3,
        finished_at: row.4,
        activated_at: row.5,
        evidence: row.6,
    })
}

fn require_state(c: &rusqlite::Connection, g: GenerationId, want: GenerationState) -> Result<()> {
    let info = generation_info(c, g)?;
    if info.state != want {
        return Err(Error::Conflict(format!(
            "generation {} is {}, expected {}",
            g.0,
            info.state.as_str(),
            want.as_str()
        )));
    }
    Ok(())
}

fn validate_conn(c: &rusqlite::Connection, g: GenerationId) -> Result<ValidationReport> {
    let mut issues = Vec::new();
    // The target lookup starts from `local_revisions` through its (update_id, revision) index
    // (CROSS JOIN fixes the order). The earlier form let SQLite scan every fragment of the
    // generation per relationship, which took hours on a real 24,509-revision catalog.
    let mut st = c.prepare(
        "SELECT r.from_local, r.kind, r.target_update_id, r.target_revision,
                (SELECT COUNT(*) FROM local_revisions lr CROSS JOIN fragments f
                   ON f.generation_id=r.generation_id AND f.local_id=lr.local_id
                 WHERE lr.update_id=r.target_update_id
                   AND (r.target_revision IS NULL OR lr.revision=r.target_revision)) AS found
         FROM relationships r JOIN fragments src
           ON src.generation_id=r.generation_id AND src.local_id=r.from_local
         WHERE r.generation_id=?1 AND src.state='present'
         ORDER BY r.id",
    )?;
    let rows = st.query_map([g.0], |r| {
        Ok((
            r.get::<_, i32>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<u32>>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (from, kind, target, rev, found) = row?;
        let kind = RelationshipKind::parse(&kind)?;
        let from_id = lookup_local_conn(c, from)?
            .ok_or_else(|| Error::Integrity(format!("fragment local id {from} unmapped")))?;
        let target_id = model::parse_update_id(&target)?;
        let problem = if matches!(
            kind,
            RelationshipKind::Prerequisite | RelationshipKind::Bundle
        ) && target_id == from_id.id
        {
            Some(IssueKind::SelfReference)
        } else if found == 0 && REQUIRED_TARGET_KINDS.contains(&kind) {
            Some(IssueKind::MissingTarget)
        } else {
            None
        };
        if let Some(problem) = problem {
            issues.push(ValidationIssue {
                from: from_id,
                kind,
                target: target_id,
                target_revision: rev.map(Revision),
                problem,
            });
        }
    }
    let empty: i64 = c.query_row(
        "SELECT COUNT(*) FROM fragments WHERE generation_id=?1",
        [g.0],
        |r| r.get(0),
    )?;
    Ok(ValidationReport {
        fragments: empty as u64,
        issues,
    })
}
