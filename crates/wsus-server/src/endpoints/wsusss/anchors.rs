//! MS-WSUSSS anchors.
//!
//! An anchor is a record in `downstream_anchors` that maps an opaque value to one immutable
//! catalog generation. The wire text follows the Windows format `nnnn,yyyy-MM-dd HH:mm:ss.fff`
//! (Specified, product behavior, inventory section 6.2) where `nnnn` is `seq`, drawn from a
//! dedicated counter, so the wire never shows a generation, revision or any other row id.
//! Anchors persist in the database and therefore survive restarts.
//!
//! One anchor exists per (source, generation); asking again for the same generation returns
//! the same text, so a downstream server that polls an unchanged catalog sees an unchanged
//! anchor and an empty delta.
//!
//! Resolution outcomes: a syntactically bad anchor is the caller's mistake
//! (`InvalidParameters`); a well-formed anchor this server never issued, or whose generation
//! has been pruned, means the downstream server's state is not ours to continue
//! (`ServerChanged`, whose specified reaction is "reset anchors and continue", that is a full
//! resynchronization).
use rusqlite::{OptionalExtension, params};

use crate::catalog::{GenerationId, SourceId};
use crate::endpoints::time::format_xs;
use crate::storage::{Database, Error, Result, bump_counter};

const COUNTER: &str = "next_downstream_anchor";

/// Largest `nnnn` (Windows: 1 to 2,147,483,647).
const MAX_SEQ: i64 = i32::MAX as i64;

/// An anchor bound to a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: i64,
    pub source: SourceId,
    pub generation: GenerationId,
    pub created_ms: i64,
}

impl Anchor {
    /// Wire text.
    pub fn text(&self) -> String {
        format!("{},{}", self.seq, stamp(self.created_ms))
    }
}

/// `yyyy-MM-dd HH:mm:ss.fff`.
pub(crate) fn stamp(ms: i64) -> String {
    let x = format_xs(ms.div_euclid(1000));
    format!("{} {}.{:03}", &x[..10], &x[11..19], ms.rem_euclid(1000))
}

/// Result of resolving anchor text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Not in the anchor format, or its timestamp does not match what was issued.
    Malformed,
    /// Well-formed but not issued by this server.
    Unknown,
    Found(Anchor),
}

/// Anchor repository.
#[derive(Debug, Clone)]
pub struct Anchors {
    db: Database,
}

impl Anchors {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// The anchor of a generation, minted on first request.
    pub fn for_generation(
        &self,
        source: SourceId,
        generation: GenerationId,
        now_secs: i64,
    ) -> Result<Anchor> {
        self.db.transaction(|tx| {
            if let Some(a) = tx
                .query_row(
                    "SELECT seq,created_ms FROM downstream_anchors \
                     WHERE source_id=?1 AND generation_id=?2",
                    params![source.0, generation.0],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )
                .optional()?
            {
                return Ok(Anchor {
                    seq: a.0,
                    source,
                    generation,
                    created_ms: a.1,
                });
            }
            let seq = bump_counter(tx, COUNTER)?;
            if seq > MAX_SEQ {
                return Err(Error::Integrity("anchor sequence exhausted".into()));
            }
            let created_ms = now_secs.saturating_mul(1000);
            tx.execute(
                "INSERT INTO downstream_anchors(seq,source_id,generation_id,created_ms) \
                 VALUES(?1,?2,?3,?4)",
                params![seq, source.0, generation.0, created_ms],
            )?;
            Ok(Anchor {
                seq,
                source,
                generation,
                created_ms,
            })
        })
    }

    /// Resolve anchor text.
    pub fn resolve(&self, text: &str) -> Result<Resolved> {
        let Some((seq_text, rest)) = text.split_once(',') else {
            return Ok(Resolved::Malformed);
        };
        let Ok(seq) = seq_text.parse::<i64>() else {
            return Ok(Resolved::Malformed);
        };
        // Canonical digits only: no sign, no leading zeros.
        if !(1..=MAX_SEQ).contains(&seq) || seq.to_string() != seq_text {
            return Ok(Resolved::Malformed);
        }
        if !well_formed_stamp(rest) {
            return Ok(Resolved::Malformed);
        }
        let row =
            self.db.with_conn(|c| {
                Ok(c.query_row(
                "SELECT source_id,generation_id,created_ms FROM downstream_anchors WHERE seq=?1",
                [seq],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()?)
            })?;
        Ok(match row {
            None => Resolved::Unknown,
            Some((s, g, ms)) => {
                let a = Anchor {
                    seq,
                    source: SourceId(s),
                    generation: GenerationId(g),
                    created_ms: ms,
                };
                if a.text() == text {
                    Resolved::Found(a)
                } else {
                    Resolved::Malformed
                }
            }
        })
    }

    /// Delete anchors whose generation no longer exists (pruned). Returns how many.
    pub fn prune_orphans(&self) -> Result<usize> {
        self.db.transaction(|tx| {
            Ok(tx.execute(
                "DELETE FROM downstream_anchors WHERE generation_id NOT IN \
                 (SELECT id FROM generations)",
                [],
            )?)
        })
    }
}

pub(crate) fn well_formed_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 23
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            _ => c.is_ascii_digit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_has_the_windows_shape() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00.000");
        assert_eq!(stamp(1_790_000_000_123), "2026-09-21 14:13:20.123");
        assert!(well_formed_stamp(&stamp(1_790_000_000_123)));
        assert!(!well_formed_stamp("2026-09-21T13:46:40.123"));
    }
}
