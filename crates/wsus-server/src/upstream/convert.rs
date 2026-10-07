//! Update metadata to catalog import.
use std::collections::BTreeSet;

use wsus_client::wsusss::UpdateRecord;
use wsus_protocol::identity::{UpdateId, UpdateRevision};
use wsus_protocol::metadata::UpdateType;
use wsus_protocol::soap::Limits;

use super::error::UpstreamError;
use crate::catalog::{
    FileDescriptor, FragmentImport, FragmentState, RelationshipImport, RelationshipKind,
};

/// A converted revision plus what the orchestrator needs to decide on it.
pub(crate) struct Converted {
    pub import: FragmentImport,
    /// Ids of the `IsCategory` prerequisite clauses (products, classifications).
    pub categories: BTreeSet<UpdateId>,
    /// Software or driver (subject to the category filter).
    pub filterable: bool,
    pub withdrawn: bool,
    pub files_without_descriptor: usize,
}

fn kind_name(t: Option<&UpdateType>) -> String {
    match t {
        Some(UpdateType::Software) => "Software".into(),
        Some(UpdateType::Driver) => "Driver".into(),
        Some(UpdateType::Category) => "Category".into(),
        Some(UpdateType::Detectoid) => "Detectoid".into(),
        Some(UpdateType::Other(o)) if !o.is_empty() => o.clone(),
        _ => "Unknown".into(),
    }
}

/// Convert one `GetUpdateData` record.
///
/// Relationship rule for alternatives (`AtLeastOne`): only alternatives that
/// are known (listed by the upstream or already in the catalog) are emitted,
/// so a clause is satisfied by any known alternative; when none is known all
/// are emitted and validation reports the gap. Single-target clauses are
/// always emitted, so a missing required target is caught.
pub(crate) fn convert(
    record: &UpdateRecord,
    known_ids: &BTreeSet<UpdateId>,
    known_revisions: &BTreeSet<UpdateRevision>,
    limits: &Limits,
) -> Result<Converted, UpstreamError> {
    let bad = |reason: String| UpstreamError::Metadata {
        identity: record.identity,
        reason,
    };
    let index = record
        .fragment
        .index(limits)
        .map_err(|e| bad(e.to_string()))?;
    if index.identity != record.identity {
        return Err(bad(format!(
            "document identity {} differs from the response identity",
            index.identity
        )));
    }
    let mut import = FragmentImport::new(
        record.identity,
        &kind_name(index.properties.update_type.as_ref()),
        record.fragment.xml(),
    );
    let withdrawn = index
        .properties
        .attributes
        .iter()
        .any(|(k, v)| k == "PublicationState" && v.eq_ignore_ascii_case("Expired"));
    if withdrawn {
        import.state = FragmentState::Withdrawn;
    }

    let mut categories = BTreeSet::new();
    for clause in &index.prerequisites {
        let kind = if clause.is_category {
            categories.extend(clause.update_ids.iter().copied());
            RelationshipKind::Category
        } else {
            RelationshipKind::Prerequisite
        };
        let known: Vec<UpdateId> = clause
            .update_ids
            .iter()
            .copied()
            .filter(|u| known_ids.contains(u))
            .collect();
        let chosen = if clause.update_ids.len() == 1 || known.is_empty() {
            &clause.update_ids
        } else {
            &known
        };
        for target in chosen {
            import.relationships.push(RelationshipImport {
                kind,
                target: *target,
                revision: None,
            });
        }
    }
    for clause in &index.bundled {
        let known: Vec<UpdateRevision> = clause
            .revisions
            .iter()
            .copied()
            .filter(|r| known_revisions.contains(r))
            .collect();
        let chosen = if clause.revisions.len() == 1 || known.is_empty() {
            &clause.revisions
        } else {
            &known
        };
        for target in chosen {
            import.relationships.push(RelationshipImport {
                kind: RelationshipKind::Bundle,
                target: target.id,
                revision: Some(target.revision),
            });
        }
    }
    for target in &index.superseded {
        import.relationships.push(RelationshipImport {
            kind: RelationshipKind::Supersedes,
            target: *target,
            revision: None,
        });
    }

    let mut files_without_descriptor = 0;
    for f in &index.files {
        match (&f.file_name, f.size) {
            (Some(name), Some(size)) if !f.digests.is_empty() && !name.is_empty() => {
                import.files.push(FileDescriptor {
                    file_name: name.clone(),
                    size,
                    digests: f.digests.clone(),
                });
            }
            _ => files_without_descriptor += 1,
        }
    }
    Ok(Converted {
        import,
        categories,
        filterable: matches!(
            index.properties.update_type,
            Some(UpdateType::Software | UpdateType::Driver)
        ),
        withdrawn,
        files_without_descriptor,
    })
}
