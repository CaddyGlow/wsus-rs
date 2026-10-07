//! Read-only queries the catalog API does not expose.
use std::collections::BTreeMap;

use rusqlite::params;
use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateRevision};

use crate::catalog::{Catalog, FragmentState, GenerationId, SourceId};
use crate::storage::{Error, Result};

/// Staging generations of a source with their stored anchors.
pub(crate) fn staging_generations(
    catalog: &Catalog,
    source: SourceId,
) -> Result<Vec<(GenerationId, Option<String>)>> {
    catalog.database().with_conn(|c| {
        let mut st = c.prepare(
            "SELECT id,anchor FROM generations WHERE source_id=?1 AND state='staging' ORDER BY id",
        )?;
        let rows = st.query_map(params![source.0], |r| {
            Ok((GenerationId(r.get(0)?), r.get::<_, Option<String>>(1)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    })
}

/// Identities (and states) held by a generation, in any state.
pub(crate) fn generation_identities(
    catalog: &Catalog,
    generation: GenerationId,
) -> Result<BTreeMap<UpdateRevision, FragmentState>> {
    catalog.database().with_conn(|c| {
        let mut st = c.prepare(
            "SELECT lr.update_id,lr.revision,f.state FROM fragments f JOIN local_revisions lr \
             ON lr.local_id=f.local_id WHERE f.generation_id=?1",
        )?;
        let rows = st.query_map(params![generation.0], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (id, rev, state) = row?;
            let uuid = id
                .parse::<Uuid>()
                .map_err(|e| Error::Integrity(format!("stored update id invalid: {e}")))?;
            out.insert(
                UpdateRevision {
                    id: wsus_protocol::identity::UpdateId(uuid),
                    revision: Revision(rev),
                },
                FragmentState::parse(&state)?,
            );
        }
        Ok(out)
    })
}
