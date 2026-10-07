use wsus_server::storage::{Database, MIGRATIONS, SCHEMA_VERSION, migrate};

#[test]
fn migrations_are_idempotent_and_versioned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let server = {
        let db = Database::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
        db.server_id().unwrap()
    };
    // Reopen: no re-run, same server identity.
    let db = Database::open(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(db.server_id().unwrap(), server);
    assert_eq!(MIGRATIONS.last().unwrap().version, SCHEMA_VERSION);
    // Direct re-application is a no-op.
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    migrate(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    drop(Database::open(&path).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    assert!(Database::open(&path).is_err());
}

#[test]
fn failed_transaction_rolls_back() {
    let db = Database::open_in_memory().unwrap();
    let r: Result<(), _> = db.transaction(|tx| {
        tx.execute("INSERT INTO meta(key,value) VALUES('x','1')", [])?;
        Err(wsus_server::storage::Error::Invalid("boom".into()))
    });
    assert!(r.is_err());
    let n: i64 = db
        .with_conn(
            |c| Ok(c.query_row("SELECT COUNT(*) FROM meta WHERE key='x'", [], |r| r.get(0))?),
        )
        .unwrap();
    assert_eq!(n, 0);
}
