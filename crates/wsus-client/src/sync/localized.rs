//! Localized metadata selection.
//!
//! The server returns one `LocalizedProperties` fragment per requested locale
//! and "SHOULD always return EN". Selection order: an exact preferred locale
//! (case-insensitive), then a preferred locale's primary language subtag, then
//! English, then the first stored fragment.

use super::store::{RevisionRecord, StoredFragment};
use wsus_protocol::soap::{
    Limits,
    xml::{self, Element},
};

/// A selected localized fragment with the commonly needed fields extracted.
/// Title and description are `None` when the fragment is not parseable XML
/// (real fragments are not guaranteed well-formed; the raw text stays
/// available).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedProperties<'a> {
    pub locale: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub fragment: &'a StoredFragment,
}

fn find<'a>(el: &'a Element, name: &str) -> Option<&'a Element> {
    el.elements()
        .find(|c| c.name.local == name)
        .or_else(|| el.elements().find_map(|c| find(c, name)))
}

fn parsed(fragment: &StoredFragment) -> Option<Element> {
    xml::parse(fragment.xml.as_bytes(), &Limits::default()).ok()
}

/// `Language` element of a localized fragment, when it parses.
pub(crate) fn language_of(xml_text: &str) -> Option<String> {
    let root = xml::parse(xml_text.as_bytes(), &Limits::default()).ok()?;
    let text = find(&root, "Language")?.text();
    Some(text.trim().to_owned()).filter(|t| !t.is_empty())
}

fn locale_of(fragment: &StoredFragment) -> Option<String> {
    fragment
        .locale
        .clone()
        .or_else(|| language_of(&fragment.xml))
}

fn primary(locale: &str) -> &str {
    locale.split(['-', '_']).next().unwrap_or(locale)
}

/// Picks the best `LocalizedProperties` fragment of `record` for `preferred`
/// locales (most preferred first).
pub fn select_localized<'a>(
    record: &'a RevisionRecord,
    preferred: &[&str],
) -> Option<LocalizedProperties<'a>> {
    let candidates: Vec<(&StoredFragment, Option<String>)> = record
        .fragments
        .iter()
        .filter(|f| f.kind == "LocalizedProperties")
        .map(|f| (f, locale_of(f)))
        .collect();
    let by = |pred: &dyn Fn(&str) -> bool| {
        candidates
            .iter()
            .find(|(_, l)| l.as_deref().is_some_and(pred))
    };
    let chosen = preferred
        .iter()
        .find_map(|p| by(&|l| l.eq_ignore_ascii_case(p)))
        .or_else(|| {
            preferred
                .iter()
                .find_map(|p| by(&|l| primary(l).eq_ignore_ascii_case(primary(p))))
        })
        .or_else(|| by(&|l| primary(l).eq_ignore_ascii_case("en")))
        .or_else(|| candidates.first())?;
    let root = parsed(chosen.0);
    let text = |name: &str| {
        root.as_ref()
            .and_then(|r| find(r, name))
            .map(|e| e.text().trim().to_owned())
    };
    Some(LocalizedProperties {
        locale: chosen.1.clone(),
        title: text("Title"),
        description: text("Description"),
        fragment: chosen.0,
    })
}
