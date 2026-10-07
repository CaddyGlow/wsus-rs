//! Explicit, ordered, forward-only migrations tracked in `PRAGMA user_version`.
use rusqlite::Connection;

use super::{Error, Result};

pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "catalog",
        sql: r#"
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE sources(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE generations(
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    state TEXT NOT NULL CHECK(state IN ('staging','active','superseded','failed')),
    anchor TEXT,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    activated_at INTEGER,
    evidence TEXT
) STRICT;
CREATE TABLE active_generations(
    source_id INTEGER PRIMARY KEY REFERENCES sources(id),
    generation_id INTEGER NOT NULL REFERENCES generations(id)
) STRICT;
CREATE TABLE local_revisions(
    row_id INTEGER PRIMARY KEY,
    local_id INTEGER NOT NULL UNIQUE,
    update_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    UNIQUE(update_id, revision)
) STRICT;
CREATE TABLE fragments(
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    local_id INTEGER NOT NULL REFERENCES local_revisions(local_id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('present','withdrawn','deleted')),
    core_xml BLOB NOT NULL,
    extended_xml BLOB,
    core_sha256 TEXT NOT NULL,
    PRIMARY KEY(generation_id, local_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE relationships(
    id INTEGER PRIMARY KEY,
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    from_local INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target_update_id TEXT NOT NULL,
    target_revision INTEGER
) STRICT;
CREATE INDEX relationships_by_from ON relationships(generation_id, from_local);
CREATE TABLE files(
    generation_id INTEGER NOT NULL REFERENCES generations(id),
    local_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    PRIMARY KEY(generation_id, local_id, ordinal)
) STRICT, WITHOUT ROWID;
CREATE TABLE file_digests(
    generation_id INTEGER NOT NULL,
    local_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY(generation_id, local_id, ordinal, algorithm)
) STRICT, WITHOUT ROWID;
CREATE INDEX file_digests_by_digest ON file_digests(algorithm, digest);
"#,
    },
    Migration {
        version: 2,
        name: "content",
        sql: r#"
CREATE TABLE content_objects(
    object_id TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('available','missing')),
    promoted_at INTEGER NOT NULL
) STRICT;
CREATE TABLE content_digests(
    object_id TEXT NOT NULL REFERENCES content_objects(object_id),
    algorithm TEXT NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY(algorithm, digest, object_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE content_names(
    object_id TEXT NOT NULL REFERENCES content_objects(object_id),
    file_name TEXT NOT NULL,
    PRIMARY KEY(object_id, file_name)
) STRICT, WITHOUT ROWID;
CREATE TABLE content_partials(
    partial_id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('receiving','promoting','failed')),
    target_object TEXT,
    created_at INTEGER NOT NULL,
    failure TEXT
) STRICT;
CREATE TABLE content_partial_digests(
    partial_id TEXT NOT NULL REFERENCES content_partials(partial_id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY(partial_id, algorithm)
) STRICT, WITHOUT ROWID;
CREATE TABLE content_pins(
    object_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(object_id, owner)
) STRICT, WITHOUT ROWID;
"#,
    },
    Migration {
        version: 3,
        name: "policy_and_computers",
        sql: r#"
CREATE TABLE computers(
    id TEXT PRIMARY KEY,
    registered_at INTEGER NOT NULL,
    last_contact INTEGER,
    last_sync INTEGER,
    last_report INTEGER,
    info TEXT NOT NULL DEFAULT '{}',
    requested_group TEXT
) STRICT;
CREATE TABLE groups(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE group_members(
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    computer_id TEXT NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
    added_at INTEGER NOT NULL,
    PRIMARY KEY(group_id, computer_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE approvals(
    id TEXT PRIMARY KEY,
    update_id TEXT NOT NULL,
    group_id TEXT NOT NULL REFERENCES groups(id),
    action TEXT NOT NULL CHECK(action IN ('install','uninstall')),
    deadline INTEGER,
    state TEXT NOT NULL CHECK(state IN ('active','withdrawn')),
    created_at INTEGER NOT NULL,
    withdrawn_at INTEGER
) STRICT;
CREATE UNIQUE INDEX approvals_one_active ON approvals(update_id, group_id, action)
    WHERE state='active';
CREATE TABLE declined_updates(
    update_id TEXT PRIMARY KEY,
    declined_at INTEGER NOT NULL
) STRICT;
INSERT INTO groups(id,name,description,builtin,created_at) VALUES
    ('a0a08746-4dbe-4a37-9adf-9e7652c0b421','All Computers','Implicit group of every registered computer',1,0),
    ('b73ca6ed-5727-47f3-84de-015e03f6a88a','Unassigned Computers','Newly registered computers',1,0);
"#,
    },
    Migration {
        version: 4,
        name: "reporting",
        sql: r#"
CREATE TABLE events(
    id INTEGER PRIMARY KEY,
    computer_id TEXT NOT NULL REFERENCES computers(id),
    update_id TEXT,
    revision INTEGER,
    kind TEXT NOT NULL,
    result_code INTEGER,
    event_time INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    dedup_key TEXT,
    raw TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX events_dedup ON events(computer_id, dedup_key)
    WHERE dedup_key IS NOT NULL;
CREATE INDEX events_by_update ON events(update_id);
CREATE TABLE update_status(
    computer_id TEXT NOT NULL REFERENCES computers(id),
    update_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    status TEXT NOT NULL,
    result_code INTEGER,
    last_event_id INTEGER NOT NULL,
    last_event_time INTEGER NOT NULL,
    PRIMARY KEY(computer_id, update_id, revision)
) STRICT, WITHOUT ROWID;
"#,
    },
    Migration {
        version: 5,
        name: "upstream_server",
        sql: r#"
CREATE TABLE downstream_servers(
    account_guid TEXT PRIMARY KEY,
    account_name TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('enabled','blocked')),
    first_seen INTEGER NOT NULL,
    last_contact INTEGER NOT NULL
) STRICT;
-- MS-WSUSSS anchors handed to downstream servers. `seq` comes from its own counter (not a
-- generation or revision row id) and is the only thing the wire shows; `generation_id` has no
-- foreign key so pruning superseded generations never blocks on outstanding anchors.
CREATE TABLE downstream_anchors(
    seq INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL,
    generation_id INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    UNIQUE(source_id, generation_id)
) STRICT;
"#,
    },
];

pub const SCHEMA_VERSION: i64 = 5;

/// Apply every pending migration, each in its own transaction. Safe to call repeatedly.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(Error::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    for m in MIGRATIONS.iter().filter(|m| m.version > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(m.sql)?;
        tx.pragma_update(None, "user_version", m.version)?;
        tx.commit()?;
    }
    Ok(())
}
