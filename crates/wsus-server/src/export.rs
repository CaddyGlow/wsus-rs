//! Metadata-only CAB export following Microsoft's `WsusExport.cs` format.
//!
//! Native WSUS import compatibility requires an independent runtime test. This is
//! not the undocumented modern `.xml.gz` format and does not export content,
//! approvals, computer state, or license files. Full received update XML is retained.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Seek, Write};

use base64::{Engine, engine::general_purpose::STANDARD};
use cabinet::{CabinetBuilder, WriteCompression};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wsus_protocol::identity::{UpdateId, UpdateRevision};
use wsus_protocol::metadata::{UpdateIndex, UpdateType};
use wsus_protocol::soap::{
    Limits,
    xml::{self, Element},
};

use crate::catalog::{FragmentRecord, FragmentState, Snapshot};

/// One explicitly advertised language, not inferred from localized update titles.
#[derive(Debug, Clone)]
pub struct ExportLanguage {
    pub id: u32,
    pub short_name: String,
    pub long_name: String,
    pub enabled: bool,
}

/// Package header and optional origin for this server's `/Content` routes.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub server_id: Uuid,
    /// UTC `yyyy-MM-ddTHH:mm:ssZ` (or an existing xs:dateTime with UTC fraction).
    pub creation_time: String,
    /// Explicit language configuration. The default is our emulated all-languages
    /// row, not evidence of the imported upstream's language configuration.
    pub languages: Vec<ExportLanguage>,
    /// HTTP(S) origin/base advertised by our content server. If absent, every
    /// exported content file must have an actual `Source` URL in its raw XML.
    pub content_base_url: Option<String>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            server_id: Uuid::new_v4(),
            creation_time: crate::endpoints::time::format_xs(crate::storage::now_unix())
                .replace(".000Z", "Z"),
            languages: vec![ExportLanguage {
                id: 0,
                short_name: "all".into(),
                long_name: "All Languages".into(),
                enabled: true,
            }],
            content_base_url: None,
        }
    }
}

/// Statistics for one immutable generation's export; not an import acceptance claim.
#[derive(Debug, Serialize)]
pub struct ExportReport {
    pub generation: i64,
    pub updates: usize,
    pub files: usize,
    pub metadata_bytes: u64,
    pub package_xml_bytes: u64,
    pub cabinet_bytes: u64,
}

/// Fail-closed metadata preparation or output error.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("catalog: {0}")]
    Catalog(#[from] crate::storage::Error),
    #[error("invalid export metadata: {0}")]
    Invalid(String),
    #[error("cabinet/output: {0}")]
    Io(#[from] std::io::Error),
}

struct Update {
    record: FragmentRecord,
    index: UpdateIndex,
    category_type: Option<String>,
}

fn invalid(message: impl Into<String>) -> ExportError {
    ExportError::Invalid(message.into())
}

fn find<'a>(root: &'a Element, name: &str) -> Option<&'a Element> {
    if root.name.local == name {
        return Some(root);
    }
    root.elements().find_map(|child| find(child, name))
}

fn http_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.is_some_and(|s| {
        !s.is_empty()
            && !s.starts_with('/')
            && !s.chars().any(|c| c.is_whitespace() || c.is_control())
            && !s.contains('#')
    })
}

fn validate_options(options: &ExportOptions) -> Result<(), ExportError> {
    if options.server_id.is_nil()
        || !options.creation_time.ends_with('Z')
        || crate::endpoints::time::parse_xs(&options.creation_time).is_none()
    {
        return Err(invalid("non-nil server id and UTC creation time required"));
    }
    let mut ids = BTreeSet::new();
    for lang in &options.languages {
        if !ids.insert(lang.id) || lang.short_name.is_empty() || lang.long_name.is_empty() {
            return Err(invalid("duplicate or empty language row"));
        }
    }
    if options.languages.is_empty() {
        return Err(invalid("language configuration is empty"));
    }
    if let Some(base) = &options.content_base_url
        && (!http_url(base) || base.contains('?'))
    {
        return Err(invalid(
            "content base must be an HTTP(S) URL without query/fragment",
        ));
    }
    Ok(())
}

fn read_updates(snapshot: &Snapshot) -> Result<Vec<Update>, ExportError> {
    let limits = Limits::stored_documents();
    let mut updates = Vec::new();
    let mut after = None;
    loop {
        let page = snapshot.list(after, 256, true)?;
        for record in page.items {
            if crate::storage::hex_encode(&Sha256::digest(&record.core_xml)) != record.core_sha256 {
                return Err(invalid(format!(
                    "{} stored XML provenance hash mismatch",
                    record.identity
                )));
            }
            if record.state == FragmentState::Deleted {
                return Err(invalid(format!(
                    "deleted/tombstone revision {} is unsupported",
                    record.identity
                )));
            }
            std::str::from_utf8(&record.core_xml)
                .map_err(|e| invalid(format!("{}: UTF-8: {e}", record.identity)))?;
            let root = xml::parse(&record.core_xml, &limits).map_err(|e| invalid(e.to_string()))?;
            let index = UpdateIndex::from_element(&root).map_err(|e| invalid(e.to_string()))?;
            if index.identity != record.identity {
                return Err(invalid(format!(
                    "XML identity differs from catalog {}",
                    record.identity
                )));
            }
            // Full ServerSync documents retain the localized collection; WUSP
            // Core fragments do not. Bundles legitimately omit applicability,
            // and ExtendedProperties is a derived WUSP child, not a requirement.
            if !root.elements().any(|e| e.name.local == "Properties")
                || !root
                    .elements()
                    .any(|e| e.name.local == "LocalizedPropertiesCollection")
            {
                return Err(invalid(format!(
                    "{} lacks full Update properties/localized collection",
                    record.identity
                )));
            }
            let category_type = find(&root, "CategoryInformation")
                .and_then(|e| e.attr("CategoryType"))
                .map(str::to_owned);
            updates.push(Update {
                record,
                index,
                category_type,
            });
        }
        let Some(next) = page.next else {
            break;
        };
        after = Some(next);
    }
    if updates.is_empty() {
        return Err(invalid("cannot export an empty generation"));
    }
    Ok(updates)
}

/// Resolve required AND clauses without requiring every alternative to be present.
/// Exact bundle revisions and category/prerequisite identities must be satisfiable
/// within this snapshot. Dependencies are emitted before dependents; cycles reject.
fn order_updates(updates: &[Update]) -> Result<Vec<usize>, ExportError> {
    let identities: BTreeMap<UpdateRevision, usize> = updates
        .iter()
        .enumerate()
        .map(|(i, u)| (u.index.identity, i))
        .collect();
    if identities.len() != updates.len() {
        return Err(invalid("duplicate update revision"));
    }
    let mut latest = BTreeMap::new();
    for (identity, i) in &identities {
        latest.insert(identity.id, *i);
    }
    let mut dependencies = Vec::new();
    for update in updates {
        let mut deps = Vec::new();
        for clause in &update.index.prerequisites {
            let present: Vec<usize> = clause
                .update_ids
                .iter()
                .filter_map(|id| latest.get(id).copied())
                .collect();
            if present.is_empty() {
                return Err(invalid(format!(
                    "{} missing prerequisite/category clause",
                    update.index.identity
                )));
            }
            deps.push(present.into_iter().collect::<BTreeSet<_>>());
        }
        for clause in &update.index.bundled {
            let present: Vec<usize> = clause
                .revisions
                .iter()
                .filter_map(|id| identities.get(id).copied())
                .collect();
            if present.is_empty() {
                return Err(invalid(format!(
                    "{} missing bundle clause",
                    update.index.identity
                )));
            }
            deps.push(present.into_iter().collect::<BTreeSet<_>>());
        }
        dependencies.push(deps);
    }
    let mut order = Vec::new();
    let mut pending: BTreeSet<usize> = (0..updates.len()).collect();
    let mut emitted = BTreeSet::new();
    while !pending.is_empty() {
        let ready: Vec<usize> = pending
            .iter()
            .copied()
            .filter(|i| {
                dependencies[*i]
                    .iter()
                    .all(|clause| !clause.is_disjoint(&emitted))
            })
            .collect();
        if ready.is_empty() {
            return Err(invalid("cyclic required dependencies"));
        }
        for i in ready {
            pending.remove(&i);
            emitted.insert(i);
            order.push(i);
        }
    }
    Ok(order)
}

fn categories(update: &Update, lookup: &BTreeMap<UpdateId, &Update>, kind: &str) -> Vec<UpdateId> {
    let mut pending: Vec<UpdateId> = update
        .index
        .prerequisites
        .iter()
        .filter(|c| c.is_category)
        .flat_map(|c| c.update_ids.iter().copied())
        .collect();
    let mut seen = BTreeSet::new();
    let mut result = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(category) = lookup.get(&id) {
            if category.category_type.as_deref() == Some(kind) {
                result.insert(id);
            }
            pending.extend(
                category
                    .index
                    .prerequisites
                    .iter()
                    .filter(|c| c.is_category)
                    .flat_map(|c| c.update_ids.iter().copied()),
            );
        }
    }
    result.into_iter().collect()
}

/// Validate and export all original documents (including withdrawn revisions) in
/// one immutable generation. No bytes are written for invalid metadata/options.
/// CAB codec/I/O failures can leave partial output: use a new atomic temporary file.
pub fn export_cab<W: Write + Seek>(
    snapshot: &Snapshot,
    options: &ExportOptions,
    output: &mut W,
) -> Result<ExportReport, ExportError> {
    validate_options(options)?;
    let updates = read_updates(snapshot)?;
    let order = order_updates(&updates)?;
    let mut lookup: BTreeMap<UpdateId, &Update> = BTreeMap::new();
    for update in &updates {
        let slot = lookup.entry(update.index.identity.id).or_insert(update);
        if update.index.identity.revision > slot.index.identity.revision {
            *slot = update;
        }
    }
    let mut files = BTreeMap::new();
    let mut per_update = Vec::new();
    for update in &updates {
        let mut digests = BTreeSet::new();
        for file in &update.index.files {
            let digest = file.sha1().filter(|d| d.bytes.len() == 20).ok_or_else(|| {
                invalid(format!(
                    "{} content file lacks SHA-1",
                    update.index.identity
                ))
            })?;
            let name = file
                .file_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid("content file lacks FileName"))?;
            let source = file
                .attributes
                .iter()
                .find(|(k, _)| k == "Source")
                .map(|(_, v)| v.clone());
            let url = if let Some(source) = source.filter(|s| !s.is_empty()) {
                source
            } else if let Some(base) = &options.content_base_url {
                let hex = crate::storage::hex_encode(&digest.bytes);
                format!(
                    "{}/Content/{}/{}",
                    base.trim_end_matches('/'),
                    &hex[38..],
                    hex
                )
            } else {
                return Err(invalid(format!(
                    "{name} lacks Source URL; provide advertised content base"
                )));
            };
            if !http_url(&url) {
                return Err(invalid(format!("invalid content Source URL for {name}")));
            }
            let key = STANDARD.encode(&digest.bytes);
            let value = (name.to_owned(), url, file.size);
            if let Some(existing) = files.insert(key.clone(), value.clone())
                && existing != value
            {
                return Err(invalid("same SHA-1 has conflicting name/source/size"));
            }
            digests.insert(key);
        }
        per_update.push(digests);
    }
    let mut package = Element::unqualified("ExportPackage")
        .with_attr("ServerID", options.server_id.to_string())
        .with_attr("CreationTime", &options.creation_time)
        .with_attr("FormatVersion", "1.0")
        .with_attr("ProtocolVersion", "1.20");
    let mut languages = Element::unqualified("Languages");
    for lang in &options.languages {
        languages.push(
            Element::unqualified("Language")
                .with_attr("Id", lang.id.to_string())
                .with_attr("ShortName", &lang.short_name)
                .with_attr("LongName", &lang.long_name)
                .with_attr("Enabled", if lang.enabled { "1" } else { "0" }),
        );
    }
    package.push(languages);
    let mut file_elements = Element::unqualified("Files");
    for (digest, (name, url, _)) in &files {
        file_elements.push(
            Element::unqualified("File")
                .with_attr("Digest", digest)
                .with_attr("MUUrl", url)
                .with_attr("Name", name),
        );
    }
    package.push(file_elements);
    let mut update_elements = Element::unqualified("Updates");
    let mut metadata = Vec::new();
    for i in &order {
        let update = &updates[*i];
        let text =
            std::str::from_utf8(&update.record.core_xml).map_err(|e| invalid(e.to_string()))?;
        let length = u32::try_from(text.encode_utf16().count())
            .map_err(|_| invalid("XML exceeds 32-bit UTF-16 length"))?;
        let header = format!(
            "{},{:08x},{length:08x},",
            update.index.identity.id.0, update.index.identity.revision.0
        );
        metadata.extend_from_slice(header.as_bytes());
        metadata.extend_from_slice(&update.record.core_xml);
        metadata.extend_from_slice(b"\r\n");
        let mut element = Element::unqualified("Update")
            .with_attr("UpdateId", update.index.identity.id.0.to_string())
            .with_attr(
                "RevisionNumber",
                update.index.identity.revision.0.to_string(),
            );
        let category = matches!(
            update.index.properties.update_type,
            Some(UpdateType::Category | UpdateType::Detectoid)
        );
        let mut update_files = Element::unqualified("Files");
        if !category {
            for digest in &per_update[*i] {
                update_files.push(Element::unqualified("File").with_attr("Digest", digest));
            }
        }
        element.push(update_files);
        for (child, entry, kind) in [
            ("Categories", "Category", "Product"),
            ("Classifications", "Classification", "UpdateClassification"),
        ] {
            let mut categories_element = Element::unqualified(child);
            if !category {
                for id in categories(update, &lookup, kind) {
                    categories_element
                        .push(Element::unqualified(entry).with_attr("Value", id.0.to_string()));
                }
            }
            element.push(categories_element);
        }
        update_elements.push(element);
    }
    package.push(update_elements);
    let package = xml::serialize(&package, true);
    // Validate XML text controls as well as escaping before beginning any output.
    xml::parse(&package, &Limits::stored_documents()).map_err(|e| invalid(e.to_string()))?;
    let mut cabinet = CabinetBuilder::new(WriteCompression::MsZip);
    cabinet.add_file("metadata.txt", &metadata)?;
    cabinet.add_file("package.xml", &package)?;
    let cabinet_bytes = cabinet.write(output)?;
    Ok(ExportReport {
        generation: snapshot.generation().0,
        updates: updates.len(),
        files: files.len(),
        metadata_bytes: metadata.len() as u64,
        package_xml_bytes: package.len() as u64,
        cabinet_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Catalog, FragmentImport, SourceKind};
    use crate::storage::Database;
    use std::io::Cursor;

    fn snapshot(documents: &[(&str, FragmentState)]) -> Snapshot {
        let catalog = Catalog::new(Database::open_in_memory().unwrap());
        let source = catalog
            .add_source("export-test", SourceKind::Upstream, "")
            .unwrap();
        let generation = catalog.begin_generation(source, None).unwrap();
        let fragments: Vec<_> = documents
            .iter()
            .map(|(document, state)| {
                let index = UpdateIndex::parse(document.as_bytes(), &Limits::default()).unwrap();
                let mut import =
                    FragmentImport::new(index.identity, "Software", document.as_bytes());
                import.state = *state;
                import
            })
            .collect();
        catalog.import_fragments(generation, &fragments).unwrap();
        catalog.activate(generation).unwrap();
        catalog.snapshot(source).unwrap().unwrap()
    }

    fn document(extra: &str) -> String {
        format!(
            "<Update><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000001\" RevisionNumber=\"10\"/><Properties UpdateType=\"Software\"/><LocalizedPropertiesCollection/>{extra}<ApplicabilityRules><IsInstalled/></ApplicabilityRules></Update>"
        )
    }

    fn members(snapshot: &Snapshot, options: &ExportOptions) -> (Vec<u8>, Vec<u8>) {
        let mut output = Cursor::new(Vec::new());
        export_cab(snapshot, options, &mut output).unwrap();
        let mut cabinet = cabinet::Cabinet::new(Cursor::new(output.into_inner())).unwrap();
        (
            cabinet.read_file_bytes("metadata.txt", 1 << 20).unwrap(),
            cabinet.read_file_bytes("package.xml", 1 << 20).unwrap(),
        )
    }

    #[test]
    fn frames_original_unicode_multiline_xml_by_utf16_units_and_crlf() {
        let document = document(
            "<LocalizedPropertiesCollection>é😀\nsecond line</LocalizedPropertiesCollection>",
        );
        let snap = snapshot(&[(&document, FragmentState::Present)]);
        let (metadata, _) = members(&snap, &ExportOptions::default());
        let expected = format!(
            "00000000-0000-0000-0000-000000000001,0000000a,{:08x},{document}\r\n",
            document.encode_utf16().count()
        );
        assert_eq!(metadata, expected.as_bytes());
        assert_ne!(document.len(), document.encode_utf16().count());
    }

    #[test]
    fn source_url_and_language_attributes_are_escaped_and_round_trip() {
        let document = document(
            "<Files><File FileName=\"a&amp;b.bin\" Digest=\"AAAAAAAAAAAAAAAAAAAAAAAAAAA=\" Size=\"1\" Source=\"https://example.test/a?x=1&amp;y=2\"/></Files>",
        );
        let snap = snapshot(&[(&document, FragmentState::Present)]);
        let mut options = ExportOptions::default();
        options.languages[0].long_name = "All & \"quoted\" languages".into();
        let (_, package) = members(&snap, &options);
        let root = xml::parse(&package, &Limits::stored_documents()).unwrap();
        assert_eq!(
            find(&root, "Language").unwrap().attr("LongName"),
            Some("All & \"quoted\" languages")
        );
        assert_eq!(
            find(&root, "File").unwrap().attr("MUUrl"),
            Some("https://example.test/a?x=1&y=2")
        );
    }

    #[test]
    fn missing_required_raw_dependency_rejects_before_output_writes() {
        let document = document(
            "<Relationships><Prerequisites><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000099\"/></Prerequisites></Relationships>",
        );
        let snap = snapshot(&[(&document, FragmentState::Present)]);
        let mut output = Cursor::new(Vec::new());
        assert!(export_cab(&snap, &ExportOptions::default(), &mut output).is_err());
        assert!(output.get_ref().is_empty());
    }

    #[test]
    fn missing_sha1_or_url_is_not_silently_omitted() {
        for files in [
            "<Files><File FileName=\"a.bin\" Digest=\"AAAAAAAAAAAAAAAAAAAAAAAAAAA=\" Size=\"1\"/></Files>",
            "<Files><File FileName=\"a.bin\" DigestAlgorithm=\"SHA256\" Digest=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\" Size=\"1\" Source=\"https://example.test/a\"/></Files>",
        ] {
            let document = document(files);
            let snap = snapshot(&[(&document, FragmentState::Present)]);
            let mut output = Cursor::new(Vec::new());
            assert!(export_cab(&snap, &ExportOptions::default(), &mut output).is_err());
            assert!(output.get_ref().is_empty());
        }
    }

    #[test]
    fn advertised_content_base_uses_existing_digest_route_without_inventing_mu_url() {
        let document = document(
            "<Files><File FileName=\"a.bin\" Digest=\"AAAAAAAAAAAAAAAAAAAAAAAAAAA=\" Size=\"1\"/></Files>",
        );
        let snap = snapshot(&[(&document, FragmentState::Present)]);
        let options = ExportOptions {
            content_base_url: Some("https://our-server.test".into()),
            ..ExportOptions::default()
        };
        let (_, package) = members(&snap, &options);
        let root = xml::parse(&package, &Limits::stored_documents()).unwrap();
        assert_eq!(
            find(&root, "File").unwrap().attr("MUUrl"),
            Some("https://our-server.test/Content/00/0000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn wrapped_wusp_core_and_tombstones_are_rejected_before_writes() {
        for (document, state) in [
            (
                document("").replace("<LocalizedPropertiesCollection/>", ""),
                FragmentState::Present,
            ),
            (document(""), FragmentState::Deleted),
        ] {
            let snap = snapshot(&[(&document, state)]);
            let mut output = Cursor::new(Vec::new());
            assert!(export_cab(&snap, &ExportOptions::default(), &mut output).is_err());
            assert!(output.get_ref().is_empty());
        }
    }

    #[test]
    fn catalog_xml_identity_mismatch_rejects_before_writes() {
        let document = document("");
        let catalog = Catalog::new(Database::open_in_memory().unwrap());
        let source = catalog
            .add_source("mismatch", SourceKind::Upstream, "")
            .unwrap();
        let generation = catalog.begin_generation(source, None).unwrap();
        let mut identity = UpdateIndex::parse(document.as_bytes(), &Limits::default())
            .unwrap()
            .identity;
        identity.revision.0 += 1;
        catalog
            .import_fragments(
                generation,
                &[FragmentImport::new(
                    identity,
                    "Software",
                    document.as_bytes(),
                )],
            )
            .unwrap();
        catalog.activate(generation).unwrap();
        let snap = catalog.snapshot(source).unwrap().unwrap();
        let mut output = Cursor::new(Vec::new());
        assert!(export_cab(&snap, &ExportOptions::default(), &mut output).is_err());
        assert!(output.get_ref().is_empty());
    }

    #[test]
    fn real_upstream_category_documents_survive_export_byte_exact() {
        let documents = [
            include_str!(
                "../../../docs/fixtures/wsus-m0-wsusss/docs/56309036-4c77-4dd9-951a-99ee9c246a94-r101.xml"
            ),
            include_str!(
                "../../../docs/fixtures/wsus-m0-wsusss/docs/6964aab4-c5b5-43bd-a17d-ffb4346a8e1d-r100.xml"
            ),
            include_str!(
                "../../../docs/fixtures/wsus-m0-wsusss/docs/dd78b8a1-0b20-45c1-add6-4da72e9364cf-r202.xml"
            ),
        ];
        let imports: Vec<_> = documents
            .iter()
            .map(|d| (*d, FragmentState::Present))
            .collect();
        let snap = snapshot(&imports);
        let (metadata, _) = members(&snap, &ExportOptions::default());
        let text = std::str::from_utf8(&metadata).unwrap();
        for document in documents {
            assert!(text.contains(document));
        }
    }

    #[test]
    fn withdrawn_original_documents_are_retained() {
        let document = document("");
        let snap = snapshot(&[(&document, FragmentState::Withdrawn)]);
        let (metadata, _) = members(&snap, &ExportOptions::default());
        assert!(std::str::from_utf8(&metadata).unwrap().contains(&document));
    }

    #[test]
    fn viable_or_dependency_schedules_even_when_another_branch_depends_on_parent() {
        let a = document(
            "<Relationships><Prerequisites><AtLeastOne><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000002\"/><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000003\"/></AtLeastOne></Prerequisites></Relationships>",
        );
        let b=document("<Relationships><Prerequisites><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000001\"/></Prerequisites></Relationships>")
            .replacen("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", 1);
        let c = document("").replace(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000003",
        );
        let snap = snapshot(&[
            (&a, FragmentState::Present),
            (&b, FragmentState::Present),
            (&c, FragmentState::Present),
        ]);
        let updates = read_updates(&snap).unwrap();
        let order = order_updates(&updates).unwrap();
        let ids: Vec<_> = order
            .into_iter()
            .map(|i| updates[i].index.identity.id.0.as_u128())
            .collect();
        assert_eq!(ids, vec![3, 1, 2]);
    }

    #[test]
    fn unsatisfiable_dependency_cycle_rejects_before_output_writes() {
        let a = document(
            "<Relationships><Prerequisites><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000002\"/></Prerequisites></Relationships>",
        );
        let b=document("<Relationships><Prerequisites><UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000001\"/></Prerequisites></Relationships>")
            .replacen("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", 1);
        let snap = snapshot(&[(&a, FragmentState::Present), (&b, FragmentState::Present)]);
        let mut output = Cursor::new(Vec::new());
        assert!(export_cab(&snap, &ExportOptions::default(), &mut output).is_err());
        assert!(output.get_ref().is_empty());
    }
}
