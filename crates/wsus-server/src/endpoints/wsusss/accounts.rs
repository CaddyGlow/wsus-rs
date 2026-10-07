//! Downstream server accounts (MS-WSUSSS "DSS Table").
//!
//! A downstream server identifies itself with an account name and an account GUID. This is
//! a concept separate from MS-WUSP computers: different table, different cookie kinds,
//! different policy. The USS inserts an entry on first contact (Specified, inventory section
//! 6.2); whether unknown accounts are admitted is [`DownstreamAccess`].
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::storage::{Database, Error, Result, now_unix};

/// Whether a downstream account may obtain a session cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Enabled,
    Blocked,
}

impl AccountState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Blocked => "blocked",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "enabled" => Ok(Self::Enabled),
            "blocked" => Ok(Self::Blocked),
            other => Err(Error::Integrity(format!(
                "unknown downstream account state {other:?}"
            ))),
        }
    }
}

/// Who may become a downstream server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DownstreamAccess {
    /// Any account is enrolled on first contact, as the specification describes for
    /// Windows. The protocol requires no authentication of a downstream server, so this
    /// admits anyone who can reach the port; use network controls or `Allowlist`.
    #[default]
    Open,
    /// Only accounts added through [`Downstreams::enroll`] and not blocked can obtain a
    /// session cookie. Unknown accounts still receive an authorization cookie (so account
    /// names cannot be probed) and are refused at `GetCookie`.
    Allowlist,
}

/// A stored downstream account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownstreamAccount {
    pub guid: Uuid,
    pub name: String,
    pub state: AccountState,
    pub first_seen: i64,
    pub last_contact: i64,
}

/// Repository of downstream accounts.
#[derive(Debug, Clone)]
pub struct Downstreams {
    db: Database,
}

impl Downstreams {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Add or re-enable nothing: create the account as enabled if absent, otherwise leave
    /// its state alone and refresh the name. Returns the stored account.
    pub fn enroll(&self, guid: Uuid, name: &str) -> Result<DownstreamAccount> {
        let now = now_unix();
        self.db.transaction(|tx| {
            tx.execute(
                "INSERT INTO downstream_servers(account_guid,account_name,state,first_seen,\
                 last_contact) VALUES(?1,?2,'enabled',?3,?3) \
                 ON CONFLICT(account_guid) DO UPDATE SET account_name=excluded.account_name",
                params![guid.to_string(), name, now],
            )?;
            get_tx(tx, guid)?.ok_or_else(|| Error::Integrity("account vanished".into()))
        })
    }

    pub fn get(&self, guid: Uuid) -> Result<Option<DownstreamAccount>> {
        self.db.with_conn(|c| get_tx(c, guid))
    }

    pub fn list(&self) -> Result<Vec<DownstreamAccount>> {
        self.db.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT account_guid,account_name,state,first_seen,last_contact \
                 FROM downstream_servers ORDER BY first_seen, account_guid",
            )?;
            let rows = st.query_map([], row)?;
            rows.map(|r| r?).collect()
        })
    }

    /// Block or unblock an account. Takes effect when its current cookie expires or at its
    /// next `GetCookie`, whichever is first (session cookies are not checked against the
    /// table on every call).
    pub fn set_state(&self, guid: Uuid, state: AccountState) -> Result<()> {
        let n = self.db.with_conn(|c| {
            Ok(c.execute(
                "UPDATE downstream_servers SET state=?2 WHERE account_guid=?1",
                params![guid.to_string(), state.as_str()],
            )?)
        })?;
        if n == 0 {
            return Err(Error::NotFound(format!("downstream account {guid}")));
        }
        Ok(())
    }

    pub(crate) fn touch(&self, guid: Uuid) -> Result<()> {
        self.db.with_conn(|c| {
            c.execute(
                "UPDATE downstream_servers SET last_contact=?2 WHERE account_guid=?1",
                params![guid.to_string(), now_unix()],
            )?;
            Ok(())
        })
    }
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<DownstreamAccount>> {
    let guid: String = r.get(0)?;
    let state: String = r.get(2)?;
    let (name, first_seen, last_contact) = (r.get(1)?, r.get(3)?, r.get(4)?);
    Ok((|| {
        Ok(DownstreamAccount {
            guid: Uuid::parse_str(&guid)
                .map_err(|e| Error::Integrity(format!("stored account guid invalid: {e}")))?,
            name,
            state: AccountState::parse(&state)?,
            first_seen,
            last_contact,
        })
    })())
}

fn get_tx(c: &rusqlite::Connection, guid: Uuid) -> Result<Option<DownstreamAccount>> {
    c.query_row(
        "SELECT account_guid,account_name,state,first_seen,last_contact \
         FROM downstream_servers WHERE account_guid=?1",
        [guid.to_string()],
        row,
    )
    .optional()?
    .transpose()
}
