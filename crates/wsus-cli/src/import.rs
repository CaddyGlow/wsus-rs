//! `wsus admin catalog import`: populate the catalog from local files.
//!
//! Input is a directory of well-formed `Update` XML documents (one revision
//! each, the shape MS-WSUSSS `GetUpdateData` delivers) and the payload files
//! those documents declare. Every declared file (name, size, digests) is
//! verified against the actual payload before anything is written. Content is
//! stored first, then the metadata is staged under a new generation and
//! activated atomically through [`Catalog::activate`], so a failed import never
//! changes what the server serves.
//!
//! The import is a full snapshot: the activated generation replaces the
//! source's previous active generation. Nothing is carried over.
//!
//! Evidence status: host-tested against this workspace's own catalog and
//! server only. The documents are not checked against real WSUS output.

use crate::{admin::Admin, output::Output};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use wsus_protocol::{
    identity::{DigestAlgorithm, FileDigest, UpdateId, UpdateRevision},
    metadata::{
        UpdateType,
        fragment::{FragmentOrigin, FragmentSource, RawFragment},
    },
    soap::Limits,
};
use wsus_server::{
    catalog::{
        ActivateOutcome, FileDescriptor, FragmentImport, FragmentState, RelationshipImport,
        RelationshipKind, SourceKind,
    },
    content::{ContentDescriptor, ObjectId},
};

/// Optional `manifest.json`: which documents to import and where their payloads are.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub updates: Vec<ManifestUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUpdate {
    /// Update XML document, relative to the import directory.
    pub xml: PathBuf,
    /// Declared file name to payload path (relative to the import directory).
    /// A declared file that is not listed is looked up as `payloads/<name>`.
    #[serde(default)]
    pub payloads: BTreeMap<String, PathBuf>,
}

/// Maximum size of one update document.
const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

/// A file name from metadata is only ever a key into the payload directory.
fn plain_name(name: &str) -> Result<()> {
    let mut parts = Path::new(name).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(n)), None) if n == name => Ok(()),
        _ => bail!("declared file name `{name}` is not a plain file name"),
    }
}

/// Resolves a relative path inside `root`, refusing absolute paths, `..` and
/// symbolic links that leave the directory.
fn resolve_inside(root: &Path, rel: &Path) -> Result<PathBuf> {
    if rel.is_absolute()
        || rel
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        bail!(
            "path `{}` must be relative and stay inside the import directory",
            rel.display()
        );
    }
    let full = root.join(rel);
    let canon = full
        .canonicalize()
        .with_context(|| format!("cannot read `{}`", full.display()))?;
    if !canon.starts_with(root) {
        bail!(
            "path `{}` resolves outside the import directory",
            rel.display()
        );
    }
    Ok(canon)
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

/// Size and digests of a file, computed in one pass.
struct Measured {
    size: u64,
    sha1: Vec<u8>,
    sha256: Vec<u8>,
    sha512: Vec<u8>,
}

impl Measured {
    fn digest(&self, algorithm: DigestAlgorithm) -> &[u8] {
        match algorithm {
            DigestAlgorithm::Sha1 => &self.sha1,
            DigestAlgorithm::Sha256 => &self.sha256,
            DigestAlgorithm::Sha512 => &self.sha512,
        }
    }
}

fn measure(path: &Path) -> Result<Measured> {
    let mut file = File::open(path).with_context(|| format!("cannot open `{}`", path.display()))?;
    let (mut a, mut b, mut c) = (Sha1::new(), Sha256::new(), Sha512::new());
    let mut size = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read `{}`", path.display()))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        a.update(&buf[..n]);
        b.update(&buf[..n]);
        c.update(&buf[..n]);
    }
    Ok(Measured {
        size,
        sha1: a.finalize().to_vec(),
        sha256: b.finalize().to_vec(),
        sha512: c.finalize().to_vec(),
    })
}

/// One document ready for staging, plus the payloads it needs.
struct Prepared {
    import: FragmentImport,
    /// Alternatives for clauses are resolved after all documents are known.
    prerequisites: Vec<(Vec<UpdateId>, bool)>,
    bundles: Vec<Vec<UpdateRevision>>,
    superseded: Vec<UpdateId>,
    payloads: Vec<(ContentDescriptor, PathBuf)>,
}

fn prepare(
    root: &Path,
    xml_rel: &Path,
    payload_map: &BTreeMap<String, PathBuf>,
) -> Result<Prepared> {
    let xml_path = resolve_inside(root, xml_rel)?;
    let shown = xml_rel.display();
    let meta = fs::metadata(&xml_path).with_context(|| format!("cannot stat `{shown}`"))?;
    if meta.len() > MAX_DOCUMENT_BYTES {
        bail!("`{shown}` is larger than {MAX_DOCUMENT_BYTES} bytes");
    }
    let bytes = fs::read(&xml_path).with_context(|| format!("cannot read `{shown}`"))?;
    let text =
        std::str::from_utf8(&bytes).with_context(|| format!("`{shown}` is not UTF-8 text"))?;
    let fragment = RawFragment::from_xml_text(
        FragmentOrigin::new(FragmentSource::Other("local catalog import".into())),
        text,
    );
    let index = fragment
        .index(&Limits::default())
        .with_context(|| format!("`{shown}` is not a well-formed Update document"))?;

    let mut import = FragmentImport::new(
        index.identity,
        &kind_name(index.properties.update_type.as_ref()),
        fragment.xml(),
    );
    if index
        .properties
        .attributes
        .iter()
        .any(|(k, v)| k == "PublicationState" && v.eq_ignore_ascii_case("Expired"))
    {
        import.state = FragmentState::Withdrawn;
    }

    let mut payloads = Vec::new();
    for f in &index.files {
        let name = f
            .file_name
            .as_deref()
            .filter(|n| !n.is_empty())
            .with_context(|| format!("`{shown}` declares a file without a FileName"))?;
        plain_name(name)?;
        let size = f
            .size
            .with_context(|| format!("`{shown}`: file `{name}` declares no Size"))?;
        if f.digests.is_empty() {
            bail!("`{shown}`: file `{name}` declares no digest");
        }
        let rel = match payload_map.get(name) {
            Some(p) => p.clone(),
            None => Path::new("payloads").join(name),
        };
        let path = resolve_inside(root, &rel).with_context(|| {
            format!("payload for `{name}` declared by `{shown}` is not available")
        })?;
        let m = measure(&path)?;
        if m.size != size {
            bail!(
                "payload `{name}` ({}) is {} bytes but `{shown}` declares {size}",
                rel.display(),
                m.size
            );
        }
        for d in &f.digests {
            if m.digest(d.algorithm) != d.bytes.as_slice() {
                bail!(
                    "payload `{name}` ({}) does not match the {:?} digest declared by `{shown}`",
                    rel.display(),
                    d.algorithm
                );
            }
        }
        let digests: Vec<FileDigest> = f.digests.clone();
        import.files.push(FileDescriptor {
            file_name: name.to_owned(),
            size,
            digests: digests.clone(),
        });
        payloads.push((
            ContentDescriptor {
                file_name: name.to_owned(),
                size,
                digests,
            },
            path,
        ));
    }
    Ok(Prepared {
        import,
        prerequisites: index
            .prerequisites
            .iter()
            .map(|c| (c.update_ids.clone(), c.is_category))
            .collect(),
        bundles: index.bundled.iter().map(|c| c.revisions.clone()).collect(),
        superseded: index.superseded.clone(),
        payloads,
    })
}

/// Relationship rule shared with the upstream importer: for an alternatives
/// clause only alternatives present in the import are emitted; when none is
/// present all are emitted so validation reports the gap.
fn relationships(
    p: &mut Prepared,
    known_ids: &BTreeSet<UpdateId>,
    known_revisions: &BTreeSet<UpdateRevision>,
) {
    for (ids, is_category) in &p.prerequisites {
        let kind = if *is_category {
            RelationshipKind::Category
        } else {
            RelationshipKind::Prerequisite
        };
        let known: Vec<UpdateId> = ids
            .iter()
            .copied()
            .filter(|u| known_ids.contains(u))
            .collect();
        let chosen = if ids.len() == 1 || known.is_empty() {
            ids
        } else {
            &known
        };
        for target in chosen {
            p.import.relationships.push(RelationshipImport {
                kind,
                target: *target,
                revision: None,
            });
        }
    }
    for revs in &p.bundles {
        let known: Vec<UpdateRevision> = revs
            .iter()
            .copied()
            .filter(|r| known_revisions.contains(r))
            .collect();
        let chosen = if revs.len() == 1 || known.is_empty() {
            revs
        } else {
            &known
        };
        for target in chosen {
            p.import.relationships.push(RelationshipImport {
                kind: RelationshipKind::Bundle,
                target: target.id,
                revision: Some(target.revision),
            });
        }
    }
    for target in &p.superseded {
        p.import.relationships.push(RelationshipImport {
            kind: RelationshipKind::Supersedes,
            target: *target,
            revision: None,
        });
    }
}

/// Document list: from the manifest, or every `*.xml` directly inside `dir`.
fn documents(root: &Path, manifest: Option<&Path>) -> Result<Vec<ManifestUpdate>> {
    if let Some(path) = manifest {
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read manifest `{}`", path.display()))?;
        let m: Manifest = serde_json::from_str(&text)
            .with_context(|| format!("manifest `{}` is invalid", path.display()))?;
        return Ok(m.updates);
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("cannot list `{}`", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("xml"))
            && let Some(name) = path.file_name()
        {
            names.push(PathBuf::from(name));
        }
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|xml| ManifestUpdate {
            xml,
            payloads: BTreeMap::new(),
        })
        .collect())
}

/// `admin catalog import`.
pub fn catalog_import(
    admin: &Admin,
    source: Option<&str>,
    dir: &Path,
    manifest: Option<&Path>,
    dry_run: bool,
) -> Result<Output> {
    let source = admin.source(source)?;
    if source.kind == SourceKind::Upstream {
        bail!(
            "source `{}` is an upstream source whose generations belong to `wsus admin sync`; \
             import into a `local` or `import` source (`wsus admin source add NAME --kind import`)",
            source.name
        );
    }
    let root = dir
        .canonicalize()
        .with_context(|| format!("import directory `{}` is not readable", dir.display()))?;
    let docs = documents(&root, manifest)?;
    if docs.is_empty() {
        bail!("no update documents found in `{}`", root.display());
    }

    // Phase 1: parse and verify everything. Nothing is written.
    let mut prepared: Vec<Prepared> = Vec::new();
    let mut seen = BTreeSet::new();
    for d in &docs {
        let p = prepare(&root, &d.xml, &d.payloads)?;
        if !seen.insert(p.import.identity) {
            bail!(
                "update {} appears in more than one document (second: `{}`)",
                p.import.identity,
                d.xml.display()
            );
        }
        prepared.push(p);
    }
    let known_revisions: BTreeSet<UpdateRevision> = seen;
    let known_ids: BTreeSet<UpdateId> = known_revisions.iter().map(|r| r.id).collect();
    for p in &mut prepared {
        relationships(p, &known_ids, &known_revisions);
    }
    let file_count: usize = prepared.iter().map(|p| p.payloads.len()).sum();
    let payload_bytes: u64 = prepared
        .iter()
        .flat_map(|p| p.payloads.iter())
        .map(|(d, _)| d.size)
        .sum();
    let summary = |generation: Option<i64>, stored: usize, activated: bool| {
        json!({
            "source": source.name,
            "dry_run": dry_run,
            "updates": prepared.len(),
            "files_verified": file_count,
            "payload_bytes": payload_bytes,
            "content_objects_stored": stored,
            "generation": generation,
            "activated": activated,
        })
    };
    if dry_run {
        // Relationship closure is only checked by the catalog at activation;
        // a dry run reports that it was not evaluated.
        let mut v = summary(None, 0, false);
        v["relationships_validated"] = Value::Bool(false);
        return Ok(Output::ok(v));
    }

    // A staging generation of this source that is still around was left by a
    // crashed import; nothing can resume it.
    admin
        .catalog
        .abandon_interrupted_in(&wsus_server::catalog::AbandonScope::Source(source.id))?;

    // Phase 2: content first, so an activated catalog never lacks stored files.
    let mut stored: BTreeSet<ObjectId> = BTreeSet::new();
    for p in &prepared {
        for (descriptor, path) in &p.payloads {
            let mut upload = admin
                .content
                .begin(descriptor)
                .with_context(|| format!("cannot start storing `{}`", descriptor.file_name))?;
            let mut file =
                File::open(path).with_context(|| format!("cannot open `{}`", path.display()))?;
            let mut buf = vec![0u8; 256 * 1024];
            let copy: Result<()> = (|| {
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        return Ok(());
                    }
                    upload.write_all(&buf[..n])?;
                }
            })();
            if let Err(e) = copy {
                let _ = upload.abort();
                return Err(e.context(format!("storing `{}` failed", descriptor.file_name)));
            }
            let id = upload.finish().with_context(|| {
                format!(
                    "stored content for `{}` failed verification (the file changed during import?)",
                    descriptor.file_name
                )
            })?;
            stored.insert(id);
        }
    }

    // Phase 3: stage and activate atomically.
    let generation = admin.catalog.begin_generation(source.id, None)?;
    let imports: Vec<FragmentImport> = prepared.into_iter().map(|p| p.import).collect();
    if let Err(e) = admin.catalog.import_fragments(generation, &imports) {
        let _ = admin
            .catalog
            .fail_generation(generation, &format!("import failed: {e}"));
        return Err(anyhow::Error::from(e).context("staging the metadata failed"));
    }
    match admin.catalog.activate(generation)? {
        ActivateOutcome::Activated { fragments } => {
            let mut v = json!({
                "source": source.name,
                "dry_run": false,
                "updates": fragments,
                "files_verified": file_count,
                "payload_bytes": payload_bytes,
                "content_objects_stored": stored.len(),
                "generation": generation.0,
                "activated": true,
            });
            v["objects"] = json!(stored.iter().map(ToString::to_string).collect::<Vec<_>>());
            Ok(Output::ok(v))
        }
        ActivateOutcome::Rejected(report) => {
            let mut lines = Vec::new();
            for i in report.issues.iter().take(20) {
                lines.push(format!(
                    "{} {:?} {} ({:?})",
                    i.from, i.kind, i.target.0, i.problem
                ));
            }
            bail!(
                "the catalog rejected the import: {} relationship problem(s), generation {} kept \
                 failed as evidence, nothing was activated: {}",
                report.issues.len(),
                generation.0,
                lines.join("; ")
            )
        }
    }
}
