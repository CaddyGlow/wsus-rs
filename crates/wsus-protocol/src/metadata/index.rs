//! Parsed index over an update metadata document.
//!
//! Paths follow MS-WUSP 3.1.1.1 (`/Update/UpdateIdentity`,
//! `/Update/Properties/@UpdateType`, `/Update/Relationships/Prerequisites`,
//! `/Update/Relationships/BundledUpdates`). The file list
//! (`/Update/Files/File`) and supersedence
//! (`/Update/Relationships/SupersededUpdates`) are Implementation decisions:
//! the pinned pages describe neither, so they are parsed from the commonly
//! seen layout, tolerantly, and anything unrecognised is preserved in
//! `extensions` instead of being dropped.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;

use crate::error::{ProtocolError, Result};
use crate::identity::{DigestAlgorithm, FileDigest, Revision, UpdateId, UpdateRevision};
use crate::soap::xml::{self, Element, Limits};

/// Namespace of update metadata documents.
///
/// The documents may also be unqualified (the MS-WUSP XPaths are written
/// unqualified); both are accepted, and descendants must use the root's
/// namespace.
pub const MSUS_UPDATE_NS: &str = "http://schemas.microsoft.com/msus/2002/12/Update";

/// `Properties/@UpdateType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateType {
    Software,
    Driver,
    Category,
    Detectoid,
    /// Other value, verbatim.
    Other(String),
}

impl UpdateType {
    fn parse(s: &str) -> Self {
        match s {
            "Software" => Self::Software,
            "Driver" => Self::Driver,
            "Category" => Self::Category,
            "Detectoid" => Self::Detectoid,
            o => Self::Other(o.to_owned()),
        }
    }
}

/// `/Update/Properties`: all attributes verbatim plus the parsed type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpdateProperties {
    /// Parsed `UpdateType`, if present.
    pub update_type: Option<UpdateType>,
    /// Every attribute in document order (including `UpdateType`).
    pub attributes: Vec<(String, String)>,
}

/// One AND-clause of the prerequisite CNF: satisfied when at least one id is
/// installed. A bare `UpdateIdentity` is a clause of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrerequisiteClause {
    /// Alternatives. Only the `UpdateID` is declared; it implicitly means the
    /// highest revision.
    pub update_ids: Vec<UpdateId>,
    /// `AtLeastOne/@IsCategory`; false for a bare identity.
    pub is_category: bool,
}

/// One AND-clause of the bundle CNF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleClause {
    /// Alternative bundled revisions.
    pub revisions: Vec<UpdateRevision>,
}

/// A content file declared by the metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// `FileName`.
    pub file_name: Option<String>,
    /// `Size` in bytes.
    pub size: Option<u64>,
    /// Primary digest first (`Digest` / `DigestAlgorithm`, default SHA-1),
    /// then every `AdditionalDigest`.
    pub digests: Vec<FileDigest>,
    /// `Modified`, verbatim.
    pub modified: Option<String>,
    /// Remaining attributes, verbatim.
    pub attributes: Vec<(String, String)>,
    /// Unrecognised child elements.
    pub extensions: Vec<Element>,
}

impl FileEntry {
    /// The SHA-1 digest, which keys file locations in MS-WUSP.
    pub fn sha1(&self) -> Option<&FileDigest> {
        self.digests
            .iter()
            .find(|d| d.algorithm == DigestAlgorithm::Sha1)
    }
}

/// An element the index does not interpret, kept intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Slash path of the parent, for example `/Update/Relationships`.
    pub parent_path: String,
    /// The element as parsed.
    pub element: Element,
}

/// Index of one update revision's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateIndex {
    /// `/Update/UpdateIdentity`.
    pub identity: UpdateRevision,
    /// `/Update/Properties`.
    pub properties: UpdateProperties,
    /// Prerequisite CNF.
    pub prerequisites: Vec<PrerequisiteClause>,
    /// Bundle CNF.
    pub bundled: Vec<BundleClause>,
    /// Superseded updates (location is an Implementation decision).
    pub superseded: Vec<UpdateId>,
    /// Content files.
    pub files: Vec<FileEntry>,
    /// `ApplicabilityRules` subtree, kept opaque: this crate does not evaluate it.
    pub applicability_rules: Option<Element>,
    /// Everything else, unmodified.
    pub extensions: Vec<Extension>,
}

fn bad(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::Metadata(msg.into())
}

/// Name test: local name equal and namespace either absent (fragments have
/// their namespace declarations stripped) or the update-metadata namespace.
/// Attribute added to a slimmed `CbsPackageApplicabilityMetadata`: the number of descendant elements
/// that were dropped (see [`slim_applicability_rules`]).
pub const SLIMMED_DESCENDANTS_ATTR: &str = "SlimmedDescendants";

fn bare_local(el: &Element) -> &str {
    el.name
        .local
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(&el.name.local)
}

fn count_descendants(el: &Element) -> u64 {
    el.elements().map(|c| 1 + count_descendants(c)).sum()
}

/// Copy of an `ApplicabilityRules` element in which every
/// `Metadata/CbsPackageApplicabilityMetadata` subtree is reduced to what the evaluator and the CBS
/// handler need. OBSERVED on a real Windows 11 catalog: that subtree is the complete CBS package
/// manifest and reaches 47 MB for one update (thousands of `assemblyIdentity`, `update` and
/// `component` elements). Kept: `assembly` (attributes), its first `assemblyIdentity` (the package's
/// own identity) and its `package` element with attributes only. Everything else is dropped and the
/// number of dropped descendant elements is recorded in [`SLIMMED_DESCENDANTS_ATTR`]. All other
/// content is cloned unchanged. The stored fragment is never altered; only this in-memory view is.
fn slim_applicability_rules(rules: &Element) -> Element {
    let mut out = Element {
        name: rules.name.clone(),
        attributes: rules.attributes.clone(),
        children: Vec::with_capacity(rules.children.len()),
    };
    for node in &rules.children {
        match node {
            xml::Node::Element(m) if bare_local(m) == "Metadata" => {
                let mut meta = Element {
                    name: m.name.clone(),
                    attributes: m.attributes.clone(),
                    children: Vec::with_capacity(m.children.len()),
                };
                for g in &m.children {
                    match g {
                        xml::Node::Element(c)
                            if bare_local(c) == "CbsPackageApplicabilityMetadata" =>
                        {
                            meta.children.push(xml::Node::Element(slim_cbs_metadata(c)));
                        }
                        other => meta.children.push(other.clone()),
                    }
                }
                out.children.push(xml::Node::Element(meta));
            }
            other => out.children.push(other.clone()),
        }
    }
    out
}

fn slim_cbs_metadata(meta: &Element) -> Element {
    let mut out = Element {
        name: meta.name.clone(),
        attributes: meta.attributes.clone(),
        children: Vec::new(),
    };
    let mut kept = 0u64;
    for assembly in meta.elements().filter(|e| bare_local(e) == "assembly") {
        let mut a = Element {
            name: assembly.name.clone(),
            attributes: assembly.attributes.clone(),
            children: Vec::new(),
        };
        if let Some(id) = assembly
            .elements()
            .find(|e| bare_local(e) == "assemblyIdentity")
        {
            a.children.push(xml::Node::Element(id.clone()));
            kept += 1 + count_descendants(id);
        }
        if let Some(pk) = assembly.elements().find(|e| bare_local(e) == "package") {
            a.children.push(xml::Node::Element(Element {
                name: pk.name.clone(),
                attributes: pk.attributes.clone(),
                children: Vec::new(),
            }));
            kept += 1;
        }
        kept += 1;
        out.children.push(xml::Node::Element(a));
    }
    let dropped = count_descendants(meta).saturating_sub(kept);
    out.attributes.push(xml::Attribute {
        name: xml::QName::unqualified(SLIMMED_DESCENDANTS_ATTR),
        value: dropped.to_string(),
    });
    out
}

fn is(el: &Element, _ns: &Option<String>, local: &str) -> bool {
    el.name.local == local && el.name.ns.as_deref().is_none_or(|n| n == MSUS_UPDATE_NS)
}

fn guid_attr(el: &Element, name: &str) -> Result<Uuid> {
    let v = el
        .attr(name)
        .ok_or_else(|| bad(format!("{} lacks @{name}", el.name.local)))?;
    if v.trim().len() != 36 {
        return Err(bad(format!("invalid GUID `{v}` in @{name}")));
    }
    Uuid::parse_str(v.trim()).map_err(|_| bad(format!("invalid GUID `{v}` in @{name}")))
}

fn revision_of(el: &Element) -> Result<UpdateRevision> {
    let id = guid_attr(el, "UpdateID")?;
    let r = el
        .attr("RevisionNumber")
        .ok_or_else(|| bad("UpdateIdentity lacks @RevisionNumber"))?;
    let r: u32 = r
        .trim()
        .parse()
        .map_err(|_| bad(format!("invalid RevisionNumber `{r}`")))?;
    Ok(UpdateRevision {
        id: UpdateId(id),
        revision: Revision(r),
    })
}

/// Index of a metadata *fragment sequence* (Core, Extended, ...) or of a full
/// document, with every part optional.
///
/// MS-WUSP 3.1.1.1: the Core fragment holds `UpdateIdentity`, `Properties`
/// (a few attributes), `Relationships` and `ApplicabilityRules`; the Extended
/// fragment holds `Properties` (the other attributes), `Files` and
/// `HandlerSpecificData` and has **no** `UpdateIdentity`. Fragments have no
/// common root, no namespace declarations and `b.`/`m.`/`d.`-prefixed
/// applicability elements. Those parts are never interpreted; they stay in
/// `applicability_rules` / `handler_specific_data` / `extensions`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FragmentIndex {
    /// `UpdateIdentity`, if the fragment carried one (Core does, Extended does not).
    pub identity: Option<UpdateRevision>,
    /// `Properties`.
    pub properties: UpdateProperties,
    /// Prerequisite CNF.
    pub prerequisites: Vec<PrerequisiteClause>,
    /// Bundle CNF.
    pub bundled: Vec<BundleClause>,
    /// Superseded updates (Implementation decision, see module docs).
    pub superseded: Vec<UpdateId>,
    /// Content files (`Files/File`).
    pub files: Vec<FileEntry>,
    /// `ApplicabilityRules` subtree, opaque.
    pub applicability_rules: Option<Element>,
    /// `HandlerSpecificData` subtree, opaque.
    pub handler_specific_data: Option<Element>,
    /// Everything else, unmodified.
    pub extensions: Vec<Extension>,
}

impl FragmentIndex {
    /// Parse a fragment sequence leniently (see [`xml::parse_fragments`]). A
    /// single full `Update` document is accepted as well and is flattened.
    pub fn parse(xml: &[u8], limits: &Limits) -> Result<Self> {
        let top = xml::parse_fragments(xml, limits)?;
        Self::from_elements(&top)
    }

    /// Index top-level fragment elements.
    pub fn from_elements(top: &[Element]) -> Result<Self> {
        let mut out = Self::default();
        if let [only] = top
            && only.name.local == "Update"
        {
            for c in only.elements() {
                out.absorb(c)?;
            }
            return Ok(out);
        }
        for c in top {
            out.absorb(c)?;
        }
        Ok(out)
    }

    fn absorb(&mut self, c: &Element) -> Result<()> {
        let ns = None;
        if is(c, &ns, "UpdateIdentity") {
            if self.identity.replace(revision_of(c)?).is_some() {
                return Err(bad("duplicate UpdateIdentity"));
            }
        } else if is(c, &ns, "Properties") {
            self.properties.attributes.extend(
                c.attributes
                    .iter()
                    .filter(|a| a.name.ns.is_none())
                    .map(|a| (a.name.local.clone(), a.value.clone())),
            );
            if let Some(t) = c.attr("UpdateType") {
                self.properties.update_type = Some(UpdateType::parse(t));
            }
            for k in c.elements() {
                self.extensions.push(Extension {
                    parent_path: "/Update/Properties".into(),
                    element: k.clone(),
                });
            }
        } else if is(c, &ns, "Relationships") {
            parse_relationships(
                c,
                &ns,
                &mut self.prerequisites,
                &mut self.bundled,
                &mut self.superseded,
                &mut self.extensions,
            )?;
        } else if is(c, &ns, "ApplicabilityRules") {
            self.applicability_rules = Some(slim_applicability_rules(c));
        } else if is(c, &ns, "HandlerSpecificData") {
            self.handler_specific_data = Some(c.clone());
        } else if is(c, &ns, "Files") {
            for f in c.elements() {
                if is(f, &ns, "File") {
                    self.files.push(parse_file(f, &ns)?);
                } else {
                    self.extensions.push(Extension {
                        parent_path: "/Update/Files".into(),
                        element: f.clone(),
                    });
                }
            }
        } else {
            self.extensions.push(Extension {
                parent_path: "/Update".into(),
                element: c.clone(),
            });
        }
        Ok(())
    }

    /// Combine two fragments of the same revision (typically Core and
    /// Extended). If both carry an identity they must agree. Properties
    /// attributes are concatenated; later duplicates are kept, not merged.
    pub fn merge(mut self, other: FragmentIndex) -> Result<Self> {
        match (self.identity, other.identity) {
            (Some(a), Some(b)) if a != b => {
                return Err(bad(format!("fragments disagree on identity: {a} vs {b}")));
            }
            (None, b) => self.identity = b,
            _ => {}
        }
        self.properties
            .attributes
            .extend(other.properties.attributes);
        if self.properties.update_type.is_none() {
            self.properties.update_type = other.properties.update_type;
        }
        self.prerequisites.extend(other.prerequisites);
        self.bundled.extend(other.bundled);
        self.superseded.extend(other.superseded);
        self.files.extend(other.files);
        self.applicability_rules = self.applicability_rules.or(other.applicability_rules);
        self.handler_specific_data = self.handler_specific_data.or(other.handler_specific_data);
        self.extensions.extend(other.extensions);
        Ok(self)
    }

    /// Supply the identity of a fragment that lacks one (an Extended
    /// fragment). An identity already present must match.
    pub fn with_identity(mut self, identity: UpdateRevision) -> Result<Self> {
        match self.identity {
            Some(i) if i != identity => Err(bad(format!(
                "fragment identity {i} differs from supplied {identity}"
            ))),
            _ => {
                self.identity = Some(identity);
                Ok(self)
            }
        }
    }

    /// Convert to a full [`UpdateIndex`]; fails if no identity is known.
    pub fn into_update_index(self) -> Result<UpdateIndex> {
        Ok(UpdateIndex {
            identity: self
                .identity
                .ok_or_else(|| bad("no UpdateIdentity in the supplied fragments"))?,
            properties: self.properties,
            prerequisites: self.prerequisites,
            bundled: self.bundled,
            superseded: self.superseded,
            files: self.files,
            applicability_rules: self.applicability_rules,
            extensions: {
                let mut e = self.extensions;
                if let Some(h) = self.handler_specific_data {
                    e.push(Extension {
                        parent_path: "/Update".into(),
                        element: h,
                    });
                }
                e
            },
        })
    }
}

impl UpdateIndex {
    /// Parse `xml` (one `Update` document) under `limits`.
    pub fn parse(xml: &[u8], limits: &Limits) -> Result<Self> {
        let root = xml::parse(xml, limits)?;
        Self::from_element(&root)
    }

    /// Build an index from one or more received fragments of the **same**
    /// revision, in any order (for example the Core fragment from
    /// `SyncUpdates` and the Extended fragment from `GetExtendedUpdateInfo`).
    /// Parsing is lenient (see [`FragmentIndex`]). The identity comes from the
    /// fragment that carries it, so callers do not inject one by hand;
    /// `identity_hint` is only used when none does and must match otherwise.
    pub fn from_fragments<'a>(
        fragments: impl IntoIterator<Item = &'a super::fragment::RawFragment>,
        identity_hint: Option<UpdateRevision>,
        limits: &Limits,
    ) -> Result<Self> {
        let mut acc = FragmentIndex::default();
        for f in fragments {
            acc = acc.merge(FragmentIndex::parse(f.xml(), limits)?)?;
        }
        if let Some(h) = identity_hint {
            acc = acc.with_identity(h)?;
        }
        acc.into_update_index()
    }

    /// Index an already parsed `Update` element.
    pub fn from_element(root: &Element) -> Result<Self> {
        if root.name.local != "Update" {
            return Err(bad(format!("root element is {}, not Update", root.name)));
        }
        if let Some(n) = root.name.ns.as_deref().filter(|n| *n != MSUS_UPDATE_NS) {
            return Err(bad(format!("unexpected Update namespace {n}")));
        }
        let mut f = FragmentIndex::default();
        for c in root.elements() {
            f.absorb(c)?;
        }
        f.into_update_index()
    }
}

fn parse_relationships(
    rel: &Element,
    ns: &Option<String>,
    prerequisites: &mut Vec<PrerequisiteClause>,
    bundled: &mut Vec<BundleClause>,
    superseded: &mut Vec<UpdateId>,
    extensions: &mut Vec<Extension>,
) -> Result<()> {
    for c in rel.elements() {
        if is(c, ns, "Prerequisites") {
            for p in c.elements() {
                if is(p, ns, "UpdateIdentity") {
                    prerequisites.push(PrerequisiteClause {
                        update_ids: vec![UpdateId(guid_attr(p, "UpdateID")?)],
                        is_category: false,
                    });
                } else if is(p, ns, "AtLeastOne") {
                    let mut ids = Vec::new();
                    for u in p.elements().filter(|u| is(u, ns, "UpdateIdentity")) {
                        ids.push(UpdateId(guid_attr(u, "UpdateID")?));
                    }
                    prerequisites.push(PrerequisiteClause {
                        update_ids: ids,
                        is_category: matches!(p.attr("IsCategory"), Some("true" | "1")),
                    });
                } else {
                    extensions.push(Extension {
                        parent_path: "/Update/Relationships/Prerequisites".into(),
                        element: p.clone(),
                    });
                }
            }
        } else if is(c, ns, "BundledUpdates") {
            for p in c.elements() {
                if is(p, ns, "UpdateIdentity") {
                    bundled.push(BundleClause {
                        revisions: vec![revision_of(p)?],
                    });
                } else if is(p, ns, "AtLeastOne") {
                    let mut revs = Vec::new();
                    for u in p.elements().filter(|u| is(u, ns, "UpdateIdentity")) {
                        revs.push(revision_of(u)?);
                    }
                    bundled.push(BundleClause { revisions: revs });
                } else {
                    extensions.push(Extension {
                        parent_path: "/Update/Relationships/BundledUpdates".into(),
                        element: p.clone(),
                    });
                }
            }
        } else if is(c, ns, "SupersededUpdates") {
            for u in c.elements() {
                if is(u, ns, "UpdateIdentity") {
                    superseded.push(UpdateId(guid_attr(u, "UpdateID")?));
                } else {
                    extensions.push(Extension {
                        parent_path: "/Update/Relationships/SupersededUpdates".into(),
                        element: u.clone(),
                    });
                }
            }
        } else {
            extensions.push(Extension {
                parent_path: "/Update/Relationships".into(),
                element: c.clone(),
            });
        }
    }
    Ok(())
}

fn digest(alg: &str, b64: &str) -> Result<FileDigest> {
    let algorithm = DigestAlgorithm::from_name(alg)
        .ok_or_else(|| bad(format!("unknown digest algorithm `{alg}`")))?;
    let compact: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| bad(format!("invalid base64 digest `{b64}`")))?;
    if bytes.len() != algorithm.len() {
        return Err(bad(format!(
            "{alg} digest has {} bytes, expected {}",
            bytes.len(),
            algorithm.len()
        )));
    }
    Ok(FileDigest { algorithm, bytes })
}

fn parse_file(f: &Element, ns: &Option<String>) -> Result<FileEntry> {
    let mut entry = FileEntry {
        file_name: f.attr("FileName").map(str::to_owned),
        size: match f.attr("Size") {
            Some(s) => Some(
                s.trim()
                    .parse()
                    .map_err(|_| bad(format!("invalid file Size `{s}`")))?,
            ),
            None => None,
        },
        digests: Vec::new(),
        modified: f.attr("Modified").map(str::to_owned),
        attributes: Vec::new(),
        extensions: Vec::new(),
    };
    if let Some(d) = f.attr("Digest") {
        entry
            .digests
            .push(digest(f.attr("DigestAlgorithm").unwrap_or("SHA1"), d)?);
    }
    for a in &f.attributes {
        if a.name.ns.is_none()
            && !["FileName", "Size", "Modified", "Digest", "DigestAlgorithm"]
                .contains(&a.name.local.as_str())
        {
            entry
                .attributes
                .push((a.name.local.clone(), a.value.clone()));
        }
    }
    for c in f.elements() {
        if is(c, ns, "AdditionalDigest") {
            let alg = c
                .attr("Algorithm")
                .ok_or_else(|| bad("AdditionalDigest lacks @Algorithm"))?;
            entry.digests.push(digest(alg, &c.text())?);
        } else {
            entry.extensions.push(c.clone());
        }
    }
    Ok(entry)
}
