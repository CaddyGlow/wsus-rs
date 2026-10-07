use std::collections::BTreeSet;

use wsus_protocol::ProtocolError;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::metadata::MSUS_UPDATE_NS;
use wsus_protocol::soap::Limits;
use wsus_protocol::soap::xml::{self, Attribute, Element, Node, QName, XML_NS, XSI_NS};

use super::write::write_sequence;

/// Base applicability rules namespace (prefix `b.`), MS-WUSP 3.1.1.1.
pub const BASE_APPLICABILITY_NS: &str =
    "http://schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules";
/// Windows Installer applicability namespace (prefix `m.`).
pub const MSI_APPLICABILITY_NS: &str =
    "http://schemas.microsoft.com/msus/2002/12/MsiApplicabilityRules";
/// Windows Installer patch applicability namespace (`MsiPatch` inside `m.MsiPatchMetadata`).
/// OBSERVED on a real WSUS 10.0.26100: the element keeps a default-namespace declaration
/// (`<MsiPatch ... xmlns="http://www.microsoft.com/msi/patch_applicability.xsd">`), so it is neither
/// prefixed nor stripped.
const PATCH_APPLICABILITY_NS: &str = "http://www.microsoft.com/msi/patch_applicability.xsd";

/// Windows driver handler namespace (prefix `d.`).
pub const DRIVER_NS: &str =
    "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsDriver";

/// `Properties` attributes the Core fragment keeps, in the order a real WSUS wrote them
/// (MS-WUSP 3.1.1.1 as recorded in the protocol inventory section 5.4). Every other
/// attribute and every child element of `Properties` goes to the Extended fragment, except
/// the ones in [`FRAGMENT_OMITTED_PROPERTY_ATTRIBUTES`] and the default-valued ones in
/// [`DEFAULT_PROPERTY_ATTRIBUTES`].
pub const CORE_PROPERTY_ATTRIBUTES: [&str; 5] = [
    "UpdateType",
    "ExplicitlyDeployable",
    "AutoSelectOnWebSites",
    "OSUpgrade",
    "EulaID",
];

/// `Properties` attributes of a whole update document that a real WSUS puts in neither
/// the Core nor the Extended fragment. Observed 2026-10-04 on a WS2025 10.0.26100 WSUS
/// (inventory 9.5): `PublicationState`, `CreationDate` and `PublisherID` were present in the
/// `GetUpdateData` document and absent from the `GetExtendedUpdateInfo` fragment of the same
/// revision, on 9 revisions (software, bundle, category).
pub const FRAGMENT_OMITTED_PROPERTY_ATTRIBUTES: [&str; 3] =
    ["PublicationState", "CreationDate", "PublisherID"];

/// `(attribute, default value)` pairs a real WSUS leaves out of the fragments when the
/// document carries the default. Observed on one category revision: `ExplicitlyDeployable=
/// "false"`, `PerUser="false"` and `IsPublic="true"` were in the `GetUpdateData` document and
/// in neither fragment (inventory 9.5). `AutoSelectOnWebSites="false"` and `OSUpgrade=
/// "false"` follow the same pattern but have not been observed (Unverified).
pub const DEFAULT_PROPERTY_ATTRIBUTES: [(&str, &str); 5] = [
    ("ExplicitlyDeployable", "false"),
    ("PerUser", "false"),
    ("IsPublic", "true"),
    ("AutoSelectOnWebSites", "false"),
    ("OSUpgrade", "false"),
];

/// Name of the `Properties` remainder in the Extended fragment. Observed: a real WSUS
/// renames `Properties` to `ExtendedProperties` there.
pub const EXTENDED_PROPERTIES_ELEMENT: &str = "ExtendedProperties";

/// Why a document could not be derived into fragments.
#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("the update document is not parseable: {0}")]
    Parse(#[from] ProtocolError),
    #[error("not an Update document with an UpdateIdentity")]
    NotAnUpdateDocument,
    #[error("the Update document has more than one UpdateIdentity")]
    DuplicateIdentity,
    #[error("UpdateIdentity is malformed: {0}")]
    BadIdentity(String),
    /// Stripping namespaces would give two attributes of one element the same name.
    #[error("attributes of <{element}> collide once namespaces are stripped: {attribute}")]
    AttributeCollision { element: String, attribute: String },
}

/// Namespace to prefix table used while flattening names.
///
/// `specified()` holds the three mappings the specification names. Namespaces that are not
/// listed (for example CBS or publishing handler namespaces) are stripped without a
/// prefix and reported through [`DerivedFragments::unmapped_namespaces`]; the
/// specification text available to this project does not say what real WSUS emits for them
/// (Unverified), so nothing is invented and nothing is silently hidden.
#[derive(Debug, Clone)]
pub struct PrefixMap {
    entries: Vec<(String, String)>,
    /// Namespaces whose elements keep an `xmlns="..."` declaration on the outermost element in
    /// that namespace (instead of being stripped), as a real WSUS writes them.
    declared: Vec<String>,
}

impl PrefixMap {
    /// `b.`, `m.` and `d.` for the Base, Msi and WindowsDriver namespaces.
    pub fn specified() -> Self {
        Self {
            entries: vec![
                (BASE_APPLICABILITY_NS.into(), "b".into()),
                (MSI_APPLICABILITY_NS.into(), "m".into()),
                (DRIVER_NS.into(), "d".into()),
            ],
            declared: vec![PATCH_APPLICABILITY_NS.into()],
        }
    }

    /// Add or replace a mapping (`prefix` without the trailing dot).
    pub fn with(mut self, ns: &str, prefix: &str) -> Self {
        self.entries.retain(|(n, _)| n != ns);
        self.entries.push((ns.to_owned(), prefix.to_owned()));
        self
    }

    fn is_declared(&self, ns: &str) -> bool {
        self.declared.iter().any(|d| d == ns)
    }

    fn prefix(&self, ns: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _)| n == ns)
            .map(|(_, p)| p.as_str())
    }
}

impl Default for PrefixMap {
    fn default() -> Self {
        Self::specified()
    }
}

/// A fragment that applies to one language (or to all when `language` is `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageFragment {
    pub language: Option<String>,
    pub xml: Vec<u8>,
}

/// WUSP fragments derived from one whole update document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedFragments {
    pub identity: UpdateRevision,
    /// `UpdateIdentity`, reduced `Properties`, `Relationships`, `ApplicabilityRules`.
    pub core: Vec<u8>,
    /// `Properties` remainder, `Files`, `HandlerSpecificData` and any other top-level
    /// element this derivation does not route elsewhere (kept, never dropped). Empty when
    /// the document has none of them.
    pub extended: Vec<u8>,
    /// One per `LocalizedPropertiesCollection/LocalizedProperties`.
    pub localized: Vec<LanguageFragment>,
    /// One per child of a top-level `EulaFiles` element. The element name is an
    /// Implementation decision (Unverified): the pinned pages do not describe the Eula
    /// fragment source.
    pub eula: Vec<LanguageFragment>,
    /// `Properties/@DefaultPropertiesLanguage`, used as the fallback language.
    pub default_language: Option<String>,
    /// Namespaces stripped without a prefix because [`PrefixMap`] does not know them.
    pub unmapped_namespaces: BTreeSet<String>,
}

fn in_update_ns(el: &Element) -> bool {
    el.name.ns.as_deref().is_none_or(|n| n == MSUS_UPDATE_NS)
}

fn is(el: &Element, local: &str) -> bool {
    in_update_ns(el) && el.name.local == local
}

fn bad_identity(el: &Element) -> Result<UpdateRevision, DeriveError> {
    let id = el
        .attr("UpdateID")
        .and_then(|v| uuid::Uuid::parse_str(v.trim()).ok())
        .ok_or_else(|| DeriveError::BadIdentity("UpdateID".into()))?;
    let rev: u32 = el
        .attr("RevisionNumber")
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| DeriveError::BadIdentity("RevisionNumber".into()))?;
    Ok(UpdateRevision {
        id: UpdateId(id),
        revision: Revision(rev),
    })
}

/// Flatten names: drop namespaces, add `b.`/`m.`/`d.` prefixes, keep `xml:` and (other than
/// `type`) `xsi:` attribute qualifiers. `xsi:type` becomes `type`: a real WSUS wrote
/// `<HandlerSpecificData type="cmd:CommandLineInstallation">` for
/// `xsi:type="cmd:CommandLineInstallation"` (inventory 9.5; observed on `HandlerSpecificData`
/// only, applied everywhere). Nothing but names changes; text, attribute values and order
/// are preserved.
pub fn flatten(
    el: &Element,
    prefixes: &PrefixMap,
    unmapped: &mut BTreeSet<String>,
) -> Result<Element, DeriveError> {
    flatten_in(el, prefixes, unmapped, None)
}

/// [`flatten`] with the namespace of the parent element (`None` at the top), which decides where
/// an `xmlns` declaration of a kept namespace is written.
fn flatten_in(
    el: &Element,
    prefixes: &PrefixMap,
    unmapped: &mut BTreeSet<String>,
    parent_ns: Option<&Option<String>>,
) -> Result<Element, DeriveError> {
    let name = |ns: &Option<String>, local: &str, unmapped: &mut BTreeSet<String>| match ns {
        None => local.to_owned(),
        Some(n) if n == MSUS_UPDATE_NS => local.to_owned(),
        Some(n) if prefixes.is_declared(n) => local.to_owned(),
        Some(n) => match prefixes.prefix(n) {
            Some(p) => format!("{p}.{local}"),
            None => {
                unmapped.insert(n.clone());
                local.to_owned()
            }
        },
    };
    let mut out = Element {
        name: QName::unqualified(&name(&el.name.ns, &el.name.local, unmapped)),
        attributes: Vec::new(),
        children: Vec::new(),
    };
    for a in &el.attributes {
        let local = match &a.name.ns {
            Some(n) if n == XSI_NS && a.name.local == "type" => "type".to_owned(),
            Some(n) if n == XSI_NS => format!("xsi:{}", a.name.local),
            Some(n) if n == XML_NS => format!("xml:{}", a.name.local),
            ns => name(ns, &a.name.local, unmapped),
        };
        if out.attributes.iter().any(|b| b.name.local == local) {
            return Err(DeriveError::AttributeCollision {
                element: out.name.local.clone(),
                attribute: local,
            });
        }
        out.attributes.push(Attribute {
            name: QName::unqualified(&local),
            value: a.value.clone(),
        });
    }
    if let Some(ns) = &el.name.ns
        && prefixes.is_declared(ns)
        && parent_ns.is_none_or(|p| p.as_deref() != Some(ns.as_str()))
        && !out.attributes.iter().any(|a| a.name.local == "xmlns")
    {
        out.attributes.push(Attribute {
            name: QName::unqualified("xmlns"),
            value: ns.clone(),
        });
    }
    for c in &el.children {
        out.children.push(match c {
            Node::Text(t) => Node::Text(t.clone()),
            Node::Element(e) => {
                Node::Element(flatten_in(e, prefixes, unmapped, Some(&el.name.ns))?)
            }
        });
    }
    Ok(out)
}

/// Serialize one flattened element (a fragment of a single element).
pub fn serialize_flat(el: &Element) -> Vec<u8> {
    write_sequence([el])
}

fn child_text(el: &Element, local: &str) -> Option<String> {
    el.elements()
        .find(|c| is(c, local))
        .map(|c| c.text().trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn language_of(el: &Element) -> Option<String> {
    el.attr("Language")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| child_text(el, "Language"))
}

/// True when `bytes` parse as an `Update` document that has an `UpdateIdentity`.
pub fn is_whole_update_document(bytes: &[u8], limits: &Limits) -> bool {
    xml::parse(bytes, limits)
        .is_ok_and(|r| is(&r, "Update") && r.elements().any(|c| is(c, "UpdateIdentity")))
}

/// Parse `bytes` as a whole update document. `Ok(None)` when it is not one (a WUSP fragment
/// sequence, a stub, or text that is not XML); the caller then treats the bytes as already
/// being in fragment form. An error means the bytes are a whole document that cannot be
/// transformed.
pub fn derive_if_whole(
    bytes: &[u8],
    prefixes: &PrefixMap,
    limits: &Limits,
) -> Result<Option<DerivedFragments>, DeriveError> {
    let Ok(root) = xml::parse(bytes, limits) else {
        return Ok(None);
    };
    if !is(&root, "Update") || !root.elements().any(|c| is(c, "UpdateIdentity")) {
        return Ok(None);
    }
    derive_element(&root, prefixes).map(Some)
}

/// Derive fragments from a whole `Update` document; fails when `bytes` is not one.
pub fn derive(
    bytes: &[u8],
    prefixes: &PrefixMap,
    limits: &Limits,
) -> Result<DerivedFragments, DeriveError> {
    derive_if_whole(bytes, prefixes, limits)?.ok_or(DeriveError::NotAnUpdateDocument)
}

/// Core of the derivation, on a parsed `Update` element.
pub fn derive_element(
    root: &Element,
    prefixes: &PrefixMap,
) -> Result<DerivedFragments, DeriveError> {
    let mut unmapped = BTreeSet::new();
    let mut identity = None;
    let mut core_identity = Vec::new();
    let mut core_props = Vec::new();
    let mut core_rel = Vec::new();
    let mut core_rules = Vec::new();
    let mut ext_props = Vec::new();
    let mut ext_files = Vec::new();
    let mut ext_handler = Vec::new();
    let mut ext_other = Vec::new();
    let mut localized = Vec::new();
    let mut eula = Vec::new();
    let mut default_language = None;

    for c in root.elements() {
        if is(c, "UpdateIdentity") {
            if identity.replace(bad_identity(c)?).is_some() {
                return Err(DeriveError::DuplicateIdentity);
            }
            core_identity.push(flatten(c, prefixes, &mut unmapped)?);
        } else if is(c, "Properties") {
            default_language = default_language.or_else(|| {
                c.attr("DefaultPropertiesLanguage")
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
            });
            let flat = flatten(c, prefixes, &mut unmapped)?;
            let mut core = Element::unqualified(&flat.name.local);
            let mut rest = Element::unqualified(EXTENDED_PROPERTIES_ELEMENT);
            let mut kept = Vec::new();
            for a in flat.attributes {
                let name = a.name.local.as_str();
                if FRAGMENT_OMITTED_PROPERTY_ATTRIBUTES.contains(&name)
                    || DEFAULT_PROPERTY_ATTRIBUTES
                        .iter()
                        .any(|(n, d)| *n == name && a.value.trim() == *d)
                {
                    continue;
                }
                if CORE_PROPERTY_ATTRIBUTES.contains(&name) {
                    kept.push(a);
                } else {
                    rest.attributes.push(a);
                }
            }
            kept.sort_by_key(|a| {
                CORE_PROPERTY_ATTRIBUTES
                    .iter()
                    .position(|n| *n == a.name.local)
                    .unwrap_or(usize::MAX)
            });
            core.attributes = kept;
            // Children (and any text) of Properties belong with the remainder.
            rest.children = flat.children;
            core_props.push(core);
            if !rest.attributes.is_empty() || !rest.children.is_empty() {
                ext_props.push(rest);
            }
        } else if is(c, "Relationships") {
            core_rel.push(flatten(c, prefixes, &mut unmapped)?);
        } else if is(c, "ApplicabilityRules") {
            core_rules.push(flatten(c, prefixes, &mut unmapped)?);
        } else if is(c, "Files") {
            ext_files.push(flatten(c, prefixes, &mut unmapped)?);
        } else if is(c, "HandlerSpecificData") {
            ext_handler.push(flatten(c, prefixes, &mut unmapped)?);
        } else if is(c, "LocalizedPropertiesCollection") {
            let mut leftover = Element {
                name: c.name.clone(),
                attributes: c.attributes.clone(),
                children: Vec::new(),
            };
            for k in c.elements() {
                if is(k, "LocalizedProperties") {
                    localized.push(LanguageFragment {
                        language: language_of(k),
                        xml: serialize_flat(&flatten(k, prefixes, &mut unmapped)?),
                    });
                } else {
                    leftover.push(k.clone());
                }
            }
            if leftover.elements().next().is_some() {
                ext_other.push(flatten(&leftover, prefixes, &mut unmapped)?);
            }
        } else if is(c, "EulaFiles") {
            for k in c.elements() {
                eula.push(LanguageFragment {
                    language: language_of(k),
                    xml: serialize_flat(&flatten(k, prefixes, &mut unmapped)?),
                });
            }
        } else {
            ext_other.push(flatten(c, prefixes, &mut unmapped)?);
        }
    }
    let identity = identity.ok_or(DeriveError::NotAnUpdateDocument)?;
    Ok(DerivedFragments {
        identity,
        core: write_sequence(
            core_identity
                .iter()
                .chain(&core_props)
                .chain(&core_rel)
                .chain(&core_rules),
        ),
        extended: write_sequence(
            ext_props
                .iter()
                .chain(&ext_files)
                .chain(&ext_handler)
                .chain(&ext_other),
        ),
        localized,
        eula,
        default_language,
        unmapped_namespaces: unmapped,
    })
}

/// Fragments of `fragments` that apply to `locales` (case-insensitive; `en` matches a
/// request for `en-US`). Fragments without a language always apply. When nothing matches,
/// the fragment in `default_language` is returned instead, so a client is not left without a
/// title.
pub fn select_language<'a>(
    fragments: &'a [LanguageFragment],
    locales: &[String],
    default_language: Option<&str>,
) -> Vec<&'a LanguageFragment> {
    let matches = |lang: &str, wanted: &str| {
        let (l, w) = (
            lang.to_ascii_lowercase(),
            wanted.trim().to_ascii_lowercase(),
        );
        l == w || w.strip_prefix(&l).is_some_and(|r| r.starts_with('-'))
    };
    let pick = |wanted: &dyn Fn(&str) -> bool| -> Vec<&LanguageFragment> {
        fragments
            .iter()
            .filter(|f| f.language.as_deref().is_none_or(wanted))
            .collect()
    };
    let hit = pick(&|l| locales.iter().any(|w| matches(l, w)));
    if hit.iter().any(|f| f.language.is_some()) || fragments.iter().all(|f| f.language.is_none()) {
        return hit;
    }
    match default_language {
        Some(d) => pick(&|l| matches(l, d)),
        None => hit,
    }
}
