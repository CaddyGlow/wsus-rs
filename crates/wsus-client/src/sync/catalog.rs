//! Catalog view over stored metadata: relationships and selection.
//!
//! Selection is by [`UpdateRevision`], never by display name. Two questions
//! are kept apart:
//!
//! * the **acquisition closure** answers "which revisions' content must be
//!   downloaded to hold everything this selection needs": the selection plus
//!   every revision reachable through bundle clauses (all alternatives of an
//!   `AtLeastOne` clause, since which alternative applies depends on the
//!   target machine, which this module never evaluates);
//! * **installation relationships** (prerequisites, supersedence, bundle
//!   clauses) are reported as data for an applicability evaluator and are not
//!   used to shrink or extend the closure unless the caller opts in.

use super::{
    error::SyncError,
    store::{RevisionRecord, RevisionStore, StoredFragment},
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use wsus_protocol::{
    identity::{DigestAlgorithm, FileDigest, Revision, UpdateId, UpdateRevision},
    metadata::{
        BundleClause, FileEntry, FragmentOrigin, FragmentSource, PrerequisiteClause, RawFragment,
        UpdateIndex,
    },
    soap::Limits,
};

/// One stored revision with its parsed indexes.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub record: RevisionRecord,
    /// Index of the Core fragment.
    pub index: UpdateIndex,
    /// Index of the Extended fragment (files), when it was fetched.
    pub extended: Option<UpdateIndex>,
}

impl CatalogEntry {
    /// Declared content files: from the Extended fragment when present,
    /// otherwise from the Core fragment.
    pub fn files(&self) -> &[FileEntry] {
        match &self.extended {
            Some(e) if !e.files.is_empty() => &e.files,
            _ => &self.index.files,
        }
    }
}

/// A prerequisite clause with the revisions it currently resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrerequisiteRef {
    pub clause: PrerequisiteClause,
    /// Highest stored revision of each alternative that is in the catalog.
    pub resolved: Vec<UpdateRevision>,
}

/// Relationships of one revision, uninterpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationships {
    pub prerequisites: Vec<PrerequisiteRef>,
    pub bundles: Vec<BundleClause>,
    pub superseded: Vec<UpdateId>,
}

/// Options of [`Catalog::acquisition_closure`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ClosureOptions {
    /// Also pull in the highest stored revision of every prerequisite
    /// alternative (transitively). Off by default: prerequisites concern
    /// installation, not acquisition.
    pub include_prerequisite_content: bool,
}

/// A reference the catalog cannot resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissingRef {
    /// A selected or bundled revision that is not stored.
    Revision(UpdateRevision),
    /// A prerequisite update with no stored revision.
    Update(UpdateId),
}

/// A content file to acquire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequirement {
    pub file_name: String,
    pub size: u64,
    pub digests: Vec<FileDigest>,
    /// The SHA-1 digest keying `GetFileLocations`, if declared.
    pub sha1: Option<Vec<u8>>,
    /// Closure members that declare this content.
    pub revisions: Vec<UpdateRevision>,
}

/// A declared file that cannot be acquired as described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusableFile {
    pub revision: UpdateRevision,
    pub reason: &'static str,
}

/// Result of [`Catalog::acquisition_closure`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcquisitionClosure {
    pub selected: Vec<UpdateRevision>,
    /// Selection plus reachable bundled (and optionally prerequisite)
    /// revisions, in discovery order without duplicates.
    pub members: Vec<UpdateRevision>,
    pub missing: Vec<MissingRef>,
    /// Content to acquire, de-duplicated by size and digests.
    pub files: Vec<FileRequirement>,
    pub unusable_files: Vec<UnusableFile>,
    /// Software members without an Extended fragment: their file lists are
    /// unknown until `fetch_fragments(.., Extended, ..)` runs.
    pub needs_extended: Vec<UpdateRevision>,
}

/// Size and sorted `(algorithm, digest)` pairs identifying content.
type ContentKey = (u64, Vec<(u8, Vec<u8>)>);

/// In-memory catalog built from a [`RevisionStore`].
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    entries: BTreeMap<UpdateRevision, CatalogEntry>,
    latest: HashMap<UpdateId, Revision>,
}

/// Rebuilds a raw fragment from its stored text (bytes unchanged).
fn raw(fragment: &StoredFragment) -> RawFragment {
    RawFragment::from_xml_text(
        FragmentOrigin::new(FragmentSource::Other("revision store".into())),
        &fragment.xml,
    )
}

impl Catalog {
    /// Loads and indexes every stored record.
    pub fn load(store: &RevisionStore, limits: &Limits) -> Result<Self, SyncError> {
        let mut catalog = Self::default();
        for record in store.list()? {
            let meta = |source| SyncError::Metadata {
                context: format!("revision {}", record.identity),
                source,
            };
            // Lenient path: Core and Extended fragments are not well-formed
            // XML. The Extended index is built from Core + Extended so the
            // identity comes from Core, never injected by hand.
            let core = raw(&record.core);
            let index = UpdateIndex::from_fragments([&core], None, limits).map_err(meta)?;
            let extended = record
                .fragments
                .iter()
                .find(|f| f.kind == "Extended")
                .map(|f| UpdateIndex::from_fragments([&core, &raw(f)], None, limits))
                .transpose()
                .map_err(meta)?;
            catalog.insert(CatalogEntry {
                record,
                index,
                extended,
            });
        }
        Ok(catalog)
    }

    fn insert(&mut self, entry: CatalogEntry) {
        let id = entry.record.identity;
        let slot = self.latest.entry(id.id).or_insert(id.revision);
        *slot = (*slot).max(id.revision);
        self.entries.insert(id, entry);
    }

    /// Number of stored revisions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All revisions in identity order.
    pub fn revisions(&self) -> impl Iterator<Item = &UpdateRevision> {
        self.entries.keys()
    }

    /// One entry.
    pub fn get(&self, rev: &UpdateRevision) -> Option<&CatalogEntry> {
        self.entries.get(rev)
    }

    /// Highest stored revision of an update.
    pub fn latest_revision(&self, id: UpdateId) -> Option<UpdateRevision> {
        self.latest
            .get(&id)
            .map(|r| UpdateRevision { id, revision: *r })
    }

    /// Relationships of a revision for an applicability evaluator.
    pub fn relationships(&self, rev: &UpdateRevision) -> Option<Relationships> {
        let entry = self.entries.get(rev)?;
        Some(Relationships {
            prerequisites: entry
                .index
                .prerequisites
                .iter()
                .map(|clause| PrerequisiteRef {
                    clause: clause.clone(),
                    resolved: clause
                        .update_ids
                        .iter()
                        .filter_map(|id| self.latest_revision(*id))
                        .collect(),
                })
                .collect(),
            bundles: entry.index.bundled.clone(),
            superseded: entry.index.superseded.clone(),
        })
    }

    /// Computes the acquisition closure of `selection`. Cycles are tolerated.
    pub fn acquisition_closure(
        &self,
        selection: &[UpdateRevision],
        options: &ClosureOptions,
    ) -> AcquisitionClosure {
        let mut out = AcquisitionClosure {
            selected: selection.to_vec(),
            ..AcquisitionClosure::default()
        };
        let mut seen = BTreeSet::new();
        let mut stack: Vec<UpdateRevision> = selection.iter().rev().copied().collect();
        while let Some(rev) = stack.pop() {
            if !seen.insert(rev) {
                continue;
            }
            let Some(entry) = self.entries.get(&rev) else {
                let missing = MissingRef::Revision(rev);
                if !out.missing.contains(&missing) {
                    out.missing.push(missing);
                }
                continue;
            };
            out.members.push(rev);
            let mut next = Vec::new();
            for clause in &entry.index.bundled {
                next.extend(clause.revisions.iter().copied());
            }
            if options.include_prerequisite_content {
                for clause in &entry.index.prerequisites {
                    for id in &clause.update_ids {
                        match self.latest_revision(*id) {
                            Some(r) => next.push(r),
                            None => {
                                let missing = MissingRef::Update(*id);
                                if !out.missing.contains(&missing) {
                                    out.missing.push(missing);
                                }
                            }
                        }
                    }
                }
            }
            stack.extend(next.into_iter().rev());
        }
        let mut by_content: BTreeMap<ContentKey, usize> = BTreeMap::new();
        for rev in out.members.clone() {
            let entry = &self.entries[&rev];
            if entry.extended.is_none() && entry.record.update_type.as_deref() == Some("Software") {
                out.needs_extended.push(rev);
            }
            for file in entry.files() {
                let (Some(name), Some(size)) = (file.file_name.clone(), file.size) else {
                    out.unusable_files.push(UnusableFile {
                        revision: rev,
                        reason: "file entry lacks a name or size",
                    });
                    continue;
                };
                if file.digests.is_empty() {
                    out.unusable_files.push(UnusableFile {
                        revision: rev,
                        reason: "file entry lacks a digest",
                    });
                    continue;
                }
                let mut key_digests: Vec<(u8, Vec<u8>)> = file
                    .digests
                    .iter()
                    .map(|d| (d.algorithm as u8, d.bytes.clone()))
                    .collect();
                key_digests.sort();
                match by_content.get(&(size, key_digests.clone())) {
                    Some(&i) => {
                        if !out.files[i].revisions.contains(&rev) {
                            out.files[i].revisions.push(rev);
                        }
                    }
                    None => {
                        by_content.insert((size, key_digests), out.files.len());
                        out.files.push(FileRequirement {
                            file_name: name,
                            size,
                            digests: file.digests.clone(),
                            sha1: file
                                .digests
                                .iter()
                                .find(|d| d.algorithm == DigestAlgorithm::Sha1)
                                .map(|d| d.bytes.clone()),
                            revisions: vec![rev],
                        });
                    }
                }
            }
        }
        out
    }
}
