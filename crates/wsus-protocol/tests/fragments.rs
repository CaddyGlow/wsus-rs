mod common;

use common::*;
use wsus_protocol::ProtocolError;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::metadata::*;
use wsus_protocol::soap::{Limits, xml};

fn core() -> String {
    String::from_utf8(fixture("fragment_core.txt")).unwrap()
}
fn ext() -> String {
    String::from_utf8(fixture("fragment_extended.txt")).unwrap()
}
fn frag(text: &str) -> RawFragment {
    RawFragment::from_xml_text(FragmentOrigin::new(FragmentSource::Other("t".into())), text)
}

#[test]
fn fragments_are_not_well_formed_for_the_strict_parser() {
    assert!(xml::parse(core().as_bytes(), &Limits::default()).is_err());
    assert!(UpdateIndex::parse(core().as_bytes(), &Limits::default()).is_err());
    assert!(frag(&core()).index(&Limits::default()).is_err());
}

#[test]
fn core_fragment_parses_leniently_without_a_root() {
    let ix = frag(&core()).fragment_index(&Limits::default()).unwrap();
    assert_eq!(ix.identity.unwrap().revision.0, 204);
    assert_eq!(ix.properties.update_type, Some(UpdateType::Software));
    assert_eq!(ix.prerequisites.len(), 2);
    assert!(ix.prerequisites[1].is_category);
    assert_eq!(ix.bundled.len(), 1);
    assert!(ix.files.is_empty());
    // Applicability stays opaque, including b./m./d. names and an undeclared
    // `x:` attribute prefix.
    let rules = ix.applicability_rules.unwrap();
    let text = String::from_utf8(rules.to_bytes()).unwrap();
    assert!(text.contains("b.RegSzToVersion"), "{text}");
    assert!(text.contains("m.MsiProductInstalled"), "{text}");
    assert!(text.contains("x:y=\"1\""), "{text}");
}

#[test]
fn extended_fragment_has_no_identity_and_is_indexed() {
    let ix = frag(&ext()).fragment_index(&Limits::default()).unwrap();
    assert!(ix.identity.is_none());
    assert_eq!(ix.files.len(), 1);
    assert_eq!(ix.files[0].sha1().unwrap().bytes.len(), 20);
    assert!(ix.handler_specific_data.is_some());
    assert!(
        ix.properties
            .attributes
            .contains(&("MaxDownloadSize".into(), "1234".into()))
    );
    assert!(matches!(
        ix.into_update_index().unwrap_err(),
        ProtocolError::Metadata(_)
    ));
}

#[test]
fn core_and_extended_combine_without_injecting_identity() {
    let c = frag(&core());
    let e = frag(&ext());
    // Order does not matter.
    for pair in [[&c, &e], [&e, &c]] {
        let ix = UpdateIndex::from_fragments(pair, None, &Limits::default()).unwrap();
        assert_eq!(ix.identity.revision, Revision(204));
        assert_eq!(ix.files.len(), 1);
        assert_eq!(ix.prerequisites.len(), 2);
        assert!(
            ix.properties
                .attributes
                .iter()
                .any(|(k, _)| k == "MaxDownloadSize")
        );
        assert!(ix.properties.attributes.iter().any(|(k, _)| k == "EulaID"));
        assert!(
            ix.extensions
                .iter()
                .any(|x| x.element.name.local == "HandlerSpecificData")
        );
    }
}

#[test]
fn identity_hint_fills_a_lone_extended_fragment_and_must_match() {
    let id = UpdateRevision {
        id: UpdateId(guid(9)),
        revision: Revision(3),
    };
    let e = frag(&ext());
    let ix = UpdateIndex::from_fragments([&e], Some(id), &Limits::default()).unwrap();
    assert_eq!(ix.identity, id);
    let c = frag(&core());
    assert!(UpdateIndex::from_fragments([&c], Some(id), &Limits::default()).is_err());
    assert!(UpdateIndex::from_fragments([&e], None, &Limits::default()).is_err());
}

#[test]
fn raw_bytes_and_provenance_are_unchanged_by_lenient_parsing() {
    let text = core();
    let f = frag(&text);
    let before = f.clone();
    let _ = f.fragment_index(&Limits::default()).unwrap();
    assert_eq!(f, before);
    assert_eq!(f.xml(), text.as_bytes());
    assert_eq!(f.provenance, Provenance::of(text.as_bytes()));
}

#[test]
fn lenient_path_keeps_dtd_entity_and_limit_protection() {
    let l = Limits::default();
    assert_eq!(
        xml::parse_fragments(b"<!DOCTYPE a><a/>", &l).unwrap_err(),
        ProtocolError::DtdNotAllowed
    );
    assert!(matches!(
        xml::parse_fragments(b"<a>&xxe;</a>", &l).unwrap_err(),
        ProtocolError::UnsupportedEntity(_)
    ));
    let small = Limits {
        max_body_bytes: 10,
        ..Limits::default()
    };
    assert!(matches!(
        xml::parse_fragments(core().as_bytes(), &small).unwrap_err(),
        ProtocolError::BodyTooLarge { .. }
    ));
    let deep = Limits {
        max_depth: 2,
        ..Limits::default()
    };
    assert!(xml::parse_fragments(b"<a><b/></a>", &deep).is_ok());
    assert!(matches!(
        xml::parse_fragments(b"<a><b><c/></b></a>", &deep).unwrap_err(),
        ProtocolError::DepthExceeded { .. }
    ));
    // Breaking out of the wrapper or stray text is rejected.
    assert!(xml::parse_fragments(b"</wsus-fragment-wrapper><a/>", &l).is_err());
    assert!(xml::parse_fragments(b"<a/> stray", &l).is_err());
    assert!(xml::parse_fragments(b"<a><b></a>", &l).is_err());
}

#[test]
fn full_update_document_also_works_through_the_lenient_path() {
    let doc = fixture("metadata_update_core.xml");
    let ix = FragmentIndex::parse(&doc, &Limits::default()).unwrap();
    assert_eq!(ix.identity.unwrap().revision.0, 204);
    assert_eq!(ix.files.len(), 1);
}
