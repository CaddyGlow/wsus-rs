//! Derivation of MS-WUSP metadata fragments from whole update documents.
//!
//! # Why this exists
//!
//! The downstream importer ([`crate::upstream`]) receives a complete, well-formed `Update`
//! document from MS-WSUSSS `GetUpdateData` and stores it unmodified in the catalog's Core
//! slot. MS-WUSP clients expect something else (MS-WUSP 3.1.1.1, inventory section 5.4):
//! separate Core, Extended, LocalizedProperties and Eula fragments that are not well-formed
//! XML, have namespace declarations removed and carry `b.`/`m.`/`d.`-prefixed applicability
//! elements. This module turns the former into the latter.
//!
//! # Derive on read, not on write
//!
//! The raw bytes and their provenance hash stay the only stored truth. Fragments are a pure
//! function of those bytes and of this module's rules, computed when a WUSP handler needs
//! them. The alternative (storing derived fragments as well) was rejected because it needs a
//! schema migration, creates a second copy that can disagree with the first, and would leave
//! already imported catalogs without fragments until a resynchronization. The price is one
//! XML parse per served update; `SyncUpdates` is capped by `max_sync_new_updates` and
//! extended requests by `max_extended_updates_per_request`, so the cost is bounded. A cache
//! keyed by `core_sha256` can be added without changing the API.
//!
//! # Transform, never synthesize
//!
//! Only names change (namespace removal, prefixing) and elements are routed to a fragment.
//! Applicability rules are copied, never rebuilt from simplified properties. Anything the
//! rules do not recognise is kept in the Extended fragment. Anything that cannot be
//! transformed without loss of meaning (attribute name collisions) is an error rather than a
//! guess.
//!
//! Attribute values are copied verbatim, including QName-valued ones such as `xsi:type`
//! (their prefix declaration is gone in a fragment by definition).
//!
//! Records already stored in WUSP form (a Core fragment sequence, optionally with an Extended
//! fragment) are served exactly as stored.
//!
//! Evidence: the transformation follows the specification text recorded in the inventory and
//! was corrected against the fragments a real WSUS (Windows Server 2025 10.0.26100) returned
//! for nine revisions (inventory 9.5, `tests/fragments_real.rs`, validation row C30): the
//! Extended remainder is `ExtendedProperties`, `PublicationState`, `CreationDate` and
//! `PublisherID` are omitted, default-valued attributes are dropped and `xsi:type` is written
//! `type`. Other handler namespaces (`lar`, `cmd`, `cat`) carry no prefix in the real
//! fragments, as here. Still Unverified: the Eula fragment source, other attribute defaults,
//! MSI, CBS and driver documents.
mod derive;
mod write;

use wsus_protocol::soap::Limits;

use crate::catalog::FragmentRecord;

pub use derive::{
    BASE_APPLICABILITY_NS, CORE_PROPERTY_ATTRIBUTES, DEFAULT_PROPERTY_ATTRIBUTES, DRIVER_NS,
    DeriveError, DerivedFragments, EXTENDED_PROPERTIES_ELEMENT,
    FRAGMENT_OMITTED_PROPERTY_ATTRIBUTES, LanguageFragment, MSI_APPLICABILITY_NS, PrefixMap,
    derive, derive_element, derive_if_whole, flatten, is_whole_update_document, select_language,
    serialize_flat,
};

/// Where the fragments of a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentOrigin {
    /// Served exactly as stored (already in WUSP form).
    Stored,
    /// Derived from a whole update document.
    Derived,
}

/// The WUSP view of one catalog record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WuspFragments {
    pub origin: FragmentOrigin,
    pub core: Vec<u8>,
    pub extended: Option<Vec<u8>>,
    pub localized: Vec<LanguageFragment>,
    pub eula: Vec<LanguageFragment>,
    pub default_language: Option<String>,
}

/// Resolve the WUSP fragments of a record. A whole update document in the Core slot is
/// derived from; anything else is returned as stored. A stored Extended fragment on a
/// whole-document record is honoured over the derived one (the importer never sets it).
pub fn wusp_fragments(
    record: &FragmentRecord,
    prefixes: &PrefixMap,
    limits: &Limits,
) -> Result<WuspFragments, DeriveError> {
    match derive_if_whole(&record.core_xml, prefixes, limits)? {
        Some(d) => Ok(WuspFragments {
            origin: FragmentOrigin::Derived,
            core: d.core,
            extended: record
                .extended_xml
                .clone()
                .or_else(|| (!d.extended.is_empty()).then_some(d.extended)),
            localized: d.localized,
            eula: d.eula,
            default_language: d.default_language,
        }),
        None => Ok(WuspFragments {
            origin: FragmentOrigin::Stored,
            core: record.core_xml.clone(),
            extended: record.extended_xml.clone(),
            localized: Vec::new(),
            eula: Vec::new(),
            default_language: None,
        }),
    }
}

/// True when the record's Core slot holds a whole update document.
pub fn is_whole_document(record: &FragmentRecord, limits: &Limits) -> bool {
    derive::is_whole_update_document(&record.core_xml, limits)
}
