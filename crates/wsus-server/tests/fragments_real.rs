//! Derived WUSP fragments against fragments a REAL WSUS produced for the same revisions.
//!
//! Provenance (`docs/fixtures/wsus-m0-wsusss/README.md`): `docs/` holds the update documents
//! (`GetUpdateData`, MS-WSUSSS) of nine revisions as decoded from the real WSUS's
//! `XmlUpdateBlobCompressed` (Windows Server 2025 10.0.26100, 2026-10-04); `wusp-reference/`
//! holds the Core, Extended and `en` LocalizedProperties fragments the SAME server returned to
//! a native Windows Update Agent for the same revisions (extracted from the sanitized native
//! captures in `docs/fixtures/wsus-m0-native/`). The tests compare this crate's derivation
//! with that reference, modulo attribute order, insignificant whitespace and the redacted
//! `LinkId` query values of the sanitized reference.
//!
//! Scope: nine revisions of one server build (a Defender definition bundle, five Defender
//! software leaves and three categories). It is evidence that the derivation reproduces those
//! fragments, not that it matches every update type.
use std::path::PathBuf;

use wsus_protocol::metadata::{FragmentOrigin as Origin, FragmentSource, RawFragment, UpdateIndex};
use wsus_protocol::soap::Limits;
use wsus_protocol::soap::xml::{self, Element, Node};
use wsus_server::fragments::{PrefixMap, derive};

const REVISIONS: [&str; 9] = [
    "a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe-r200",
    "266f6222-c89d-43f2-9f8a-69340271e677-r200",
    "7366a74a-ef29-44e1-b738-570b516aca1f-r200",
    "ff36f0b5-dded-4780-8664-cd78af8b62c1-r200",
    "ccb78947-6453-4ecc-9de8-bc0305c98f2d-r200",
    "1f9bd9bb-7390-4aa3-bbdb-ded99fac2583-r200",
    "56309036-4c77-4dd9-951a-99ee9c246a94-r101",
    "6964aab4-c5b5-43bd-a17d-ffb4346a8e1d-r100",
    "dd78b8a1-0b20-45c1-add6-4da72e9364cf-r202",
];

fn fixture(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/fixtures/wsus-m0-wsusss")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn limits() -> Limits {
    Limits::default()
}

/// Canonical text of a fragment sequence: names, sorted attributes, trimmed text, children.
fn canon(bytes: &[u8]) -> String {
    let text = std::str::from_utf8(bytes).expect("utf-8");
    // The sanitized reference redacted URL query values; compare the rest of the URL.
    let text = redact_link_ids(text);
    let els = xml::parse_fragments(text.as_bytes(), &limits()).expect("fragment parses");
    assert!(!els.is_empty(), "empty fragment");
    let mut out = String::new();
    for e in &els {
        canon_el(e, &mut out);
    }
    out
}

fn redact_link_ids(t: &str) -> String {
    let mut out = String::new();
    let mut rest = t;
    while let Some(i) = rest.find("LinkId=").or_else(|| rest.find("linkid=")) {
        let (head, tail) = rest.split_at(i + "LinkId=".len());
        out.push_str(head);
        let end = tail
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tail.len());
        out.push('X');
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn canon_el(e: &Element, out: &mut String) {
    out.push('<');
    out.push_str(&e.name.local);
    let mut attrs: Vec<(String, String)> = e
        .attributes
        .iter()
        .map(|a| (a.name.local.clone(), a.value.clone()))
        .collect();
    attrs.sort();
    for (k, v) in attrs {
        out.push_str(&format!(" {k}={v:?}"));
    }
    out.push('>');
    for c in &e.children {
        match c {
            Node::Text(t) if !t.trim().is_empty() => out.push_str(t.trim()),
            Node::Text(_) => {}
            Node::Element(c) => canon_el(c, out),
        }
    }
    out.push_str("</>");
}

struct Pair {
    base: &'static str,
    derived: wsus_server::fragments::DerivedFragments,
}

fn pairs() -> Vec<Pair> {
    REVISIONS
        .iter()
        .map(|base| {
            let doc = fixture(&format!("docs/{base}.xml"));
            let derived = derive(&doc, &PrefixMap::specified(), &limits())
                .unwrap_or_else(|e| panic!("{base}: {e}"));
            Pair { base, derived }
        })
        .collect()
}

#[test]
fn real_update_documents_parse_with_the_strict_document_parser() {
    for base in REVISIONS {
        let doc = fixture(&format!("docs/{base}.xml"));
        let raw = RawFragment::from_xml_text(
            Origin::new(FragmentSource::Other("real".into())),
            std::str::from_utf8(&doc).unwrap(),
        );
        let index = raw
            .index(&limits())
            .unwrap_or_else(|e| panic!("{base}: {e}"));
        assert_eq!(
            index.identity.to_string().to_lowercase(),
            base.replace("-r", "@"),
            "{base}"
        );
    }
}

#[test]
fn derived_core_equals_the_real_core_fragment() {
    for p in pairs() {
        let real = fixture(&format!("wusp-reference/{}.core.xml", p.base));
        assert_eq!(canon(&p.derived.core), canon(&real), "core of {}", p.base);
    }
}

#[test]
fn derived_extended_equals_the_real_extended_fragment() {
    for p in pairs() {
        let real = fixture(&format!("wusp-reference/{}.extended.xml", p.base));
        assert_eq!(
            canon(&p.derived.extended),
            canon(&real),
            "extended of {}",
            p.base
        );
    }
}

#[test]
fn derived_english_localized_properties_equal_the_real_fragment() {
    for p in pairs() {
        let real = fixture(&format!("wusp-reference/{}.localized-en.xml", p.base));
        let en = p
            .derived
            .localized
            .iter()
            .find(|l| l.language.as_deref() == Some("en"))
            .unwrap_or_else(|| panic!("{}: no en localized properties", p.base));
        assert_eq!(canon(&en.xml), canon(&real), "localized of {}", p.base);
    }
}

#[test]
fn derived_fragments_are_accepted_by_the_lenient_fragment_decoder_and_index() {
    for p in pairs() {
        for (name, bytes) in [("core", &p.derived.core), ("extended", &p.derived.extended)] {
            let raw = RawFragment::from_xml_text(
                Origin::new(FragmentSource::Other("derived".into())),
                std::str::from_utf8(bytes).unwrap(),
            );
            raw.fragment_index(&limits())
                .unwrap_or_else(|e| panic!("{} {name}: {e}", p.base));
        }
        let core = RawFragment::from_xml_text(
            Origin::new(FragmentSource::Other("derived".into())),
            std::str::from_utf8(&p.derived.core).unwrap(),
        );
        let ext = RawFragment::from_xml_text(
            Origin::new(FragmentSource::Other("derived".into())),
            std::str::from_utf8(&p.derived.extended).unwrap(),
        );
        let index = UpdateIndex::from_fragments(&[core, ext], Some(p.derived.identity), &limits())
            .unwrap_or_else(|e| panic!("{}: {e}", p.base));
        assert_eq!(index.identity, p.derived.identity, "{}", p.base);
    }
}

#[test]
fn the_bundle_core_keeps_every_bundled_alternative_group_and_the_leaf_extended_keeps_its_file_digests()
 {
    let bundle = pairs()
        .into_iter()
        .find(|p| p.base.starts_with("a2fef9b0"))
        .unwrap();
    let core = std::str::from_utf8(&bundle.derived.core).unwrap();
    assert_eq!(
        core.matches("<AtLeastOne>").count(),
        4,
        "four bundle groups"
    );
    assert_eq!(
        core.matches("RevisionNumber=\"200\"").count(),
        1 + 7 + 7 + 7 + 103
    );
    let leaf = pairs()
        .into_iter()
        .find(|p| p.base.starts_with("266f6222"))
        .unwrap();
    let ext = std::str::from_utf8(&leaf.derived.extended).unwrap();
    assert!(
        ext.contains("Digest=\"h/W9BGlYUAaqXTp30cZi/SiV3c0=\""),
        "{ext}"
    );
    assert!(
        ext.contains("<AdditionalDigest Algorithm=\"SHA256\">"),
        "{ext}"
    );
    assert!(ext.contains("<HandlerSpecificData type=\"cmd:CommandLineInstallation\">"));
}
