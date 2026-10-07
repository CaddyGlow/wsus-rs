//! Derivation of WUSP fragments from whole update documents.
//!
//! Spec-derived and hand-written inputs only; nothing here is checked against fragments
//! produced by a real WSUS server.
mod fragments_common;
use fragments_common::*;

use wsus_protocol::metadata::{FragmentOrigin as Origin, FragmentSource, RawFragment, UpdateIndex};
use wsus_protocol::soap::Limits;
use wsus_protocol::soap::xml::Element;
use wsus_server::fragments::{
    BASE_APPLICABILITY_NS, DeriveError, LanguageFragment, PrefixMap, derive, derive_if_whole,
    flatten, select_language,
};

fn limits() -> Limits {
    Limits::default()
}

fn text(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap()
}

fn raw(bytes: &[u8]) -> RawFragment {
    RawFragment::from_xml_text(
        Origin::new(FragmentSource::Other("derived".into())),
        text(bytes),
    )
}

fn sorted_debug<T: std::fmt::Debug>(v: impl IntoIterator<Item = T>) -> Vec<String> {
    let mut s: Vec<String> = v.into_iter().map(|x| format!("{x:?}")).collect();
    s.sort();
    s
}

#[test]
fn core_is_identity_reduced_properties_relationships_and_rules_without_namespaces() {
    let doc = whole_doc(1, 7);
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    let core = text(&d.core);
    assert!(core.starts_with(
        "<UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000001\" RevisionNumber=\"7\"/>\
         <Properties UpdateType=\"Software\" ExplicitlyDeployable=\"true\" \
         AutoSelectOnWebSites=\"true\" \
         EulaID=\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"/><Relationships>"
    ));
    assert!(!core.contains("xmlns"));
    assert!(!core.contains("<b:") && !core.contains("<m:") && !core.contains("<d:"));
    assert!(core.contains("<b.And><b.RegSzToVersion Key=\"HKLM\\SOFTWARE\\X\""));
    assert!(core.contains(
        "<m.MsiProductInstalled ProductCode=\"{00000000-0000-0000-0000-000000000000}\"/>"
    ));
    // QName-valued attribute values are copied verbatim: the prefix inside the value is not
    // rewritten (the declaration it referred to is gone, as in any fragment). The attribute
    // `xsi:type` itself is written `type`, as a real WSUS does (inventory 9.5).
    assert!(core.contains("<d.DriverCheck HardwareId=\"PCI\\VEN_8086\" type=\"d:Special\"/>"));
    // Everything else is absent from Core.
    for absent in [
        "<Files",
        "HandlerSpecificData",
        "MaxDownloadSize",
        "LocalizedProperties",
    ] {
        assert!(!core.contains(absent), "{absent} leaked into Core");
    }
}

#[test]
fn extended_holds_remaining_properties_files_handler_data_and_unknown_elements() {
    let doc = whole_doc(1, 7);
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    let ext = text(&d.extended);
    assert!(ext.starts_with(
        "<ExtendedProperties DefaultPropertiesLanguage=\"en\" MaxDownloadSize=\"1234\" \
         FutureAttribute=\"a &amp; &quot;b&quot;\">\
         <SupportUrl>http://example.invalid/?a=1&amp;b=2</SupportUrl></ExtendedProperties><Files>"
    ));
    assert!(
        !ext.contains("PublicationState"),
        "omitted like a real WSUS"
    );
    assert!(ext.contains("<HandlerSpecificData type=\"cbs:Handler\">"));
    assert!(ext.ends_with("<FutureTopLevel Z=\"1\"><X/></FutureTopLevel>"));
    assert!(!ext.contains("UpdateType") && !ext.contains("<UpdateIdentity"));
    // Namespaces that are not b/m/d are stripped, unprefixed, and reported.
    assert_eq!(
        d.unmapped_namespaces
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![CBS_NS]
    );
}

#[test]
fn localized_properties_are_one_fragment_per_language_with_selection() {
    let doc = whole_doc(1, 1);
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    assert_eq!(d.localized.len(), 2);
    assert_eq!(d.localized[0].language.as_deref(), Some("en"));
    assert_eq!(
        text(&d.localized[0].xml),
        "<LocalizedProperties><Language>en</Language><Title>Example update</Title>\
         <Description>Fixes &lt;things&gt;.</Description></LocalizedProperties>"
    );
    let pick = |locales: &[&str]| -> Vec<Option<String>> {
        let l: Vec<String> = locales.iter().map(|s| (*s).to_owned()).collect();
        select_language(&d.localized, &l, d.default_language.as_deref())
            .into_iter()
            .map(|f| f.language.clone())
            .collect()
    };
    assert_eq!(pick(&["de"]), vec![Some("de".to_string())]);
    assert_eq!(pick(&["EN-us"]), vec![Some("en".to_string())]);
    assert_eq!(pick(&["de", "en"]).len(), 2);
    // No match: the default properties language is the fallback.
    assert_eq!(pick(&["fr"]), vec![Some("en".to_string())]);
    // Language-less fragments always apply.
    let any = [LanguageFragment {
        language: None,
        xml: b"<E/>".to_vec(),
    }];
    assert_eq!(select_language(&any, &["fr".into()], None).len(), 1);
}

#[test]
fn eula_children_become_language_fragments() {
    let doc = whole_doc(1, 1).replace(
        "<FutureTopLevel",
        "<EulaFiles><EulaFile Language=\"en\" FileName=\"e.txt\"/><EulaFile><Language>de</Language></EulaFile></EulaFiles><FutureTopLevel",
    );
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    let langs: Vec<_> = d.eula.iter().map(|e| e.language.clone()).collect();
    assert_eq!(langs, vec![Some("en".to_string()), Some("de".to_string())]);
    assert!(!text(&d.extended).contains("Eula"));
}

/// Derive, parse the derived Core and Extended leniently through `wsus-protocol`, and compare
/// with the strict index of the original document. No rule is regenerated: the rule trees
/// must equal the flattened original trees.
#[test]
fn derived_fragments_round_trip_to_the_strict_index_of_the_original() {
    let doc = whole_doc(1, 7);
    let strict = UpdateIndex::parse(doc.as_bytes(), &limits()).unwrap();
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    let (core, ext) = (raw(&d.core), raw(&d.extended));
    let lenient = UpdateIndex::from_fragments([&core, &ext], None, &limits()).unwrap();

    assert_eq!(lenient.identity, strict.identity);
    assert_eq!(
        lenient.properties.update_type,
        strict.properties.update_type
    );
    // The Extended remainder is named `ExtendedProperties` (as in a real WSUS) and the
    // lenient index of `wsus-protocol` does not read that element as properties (reported
    // in the inventory, 9.5), so only the Core attributes round trip here. Defaulted and
    // publication attributes are omitted by design.
    let core_attrs: Vec<_> = strict
        .properties
        .attributes
        .iter()
        .filter(|(k, v)| {
            [
                "UpdateType",
                "ExplicitlyDeployable",
                "AutoSelectOnWebSites",
                "EulaID",
            ]
            .contains(&k.as_str())
                && !(k == "OSUpgrade" && v == "false")
        })
        .collect();
    assert_eq!(
        sorted_debug(&lenient.properties.attributes),
        sorted_debug(core_attrs),
        "the Core attributes of Properties round trip"
    );
    assert_eq!(lenient.prerequisites, strict.prerequisites);
    assert_eq!(lenient.bundled, strict.bundled);
    assert_eq!(lenient.superseded, strict.superseded);
    assert_eq!(lenient.files, strict.files);

    let mut unmapped = Default::default();
    let prefixes = PrefixMap::specified();
    let expected_rules = flatten(
        strict.applicability_rules.as_ref().unwrap(),
        &prefixes,
        &mut unmapped,
    )
    .unwrap();
    assert_eq!(lenient.applicability_rules.as_ref(), Some(&expected_rules));

    // Extensions: all of the original's except the localized collection, which moved to
    // LocalizedProperties fragments.
    let expected_ext = strict
        .extensions
        .iter()
        .filter(|e| e.element.name.local != "LocalizedPropertiesCollection")
        // Children of Properties travel inside `ExtendedProperties`, which the lenient index
        // does not read (see above).
        .filter(|e| e.parent_path != "/Update/Properties")
        .map(|e| {
            (
                e.parent_path.clone(),
                flatten(&e.element, &prefixes, &mut unmapped).unwrap(),
            )
        })
        .collect::<Vec<(String, Element)>>();
    assert_eq!(
        sorted_debug(
            lenient
                .extensions
                .iter()
                .filter(|e| e.element.name.local != "ExtendedProperties")
                .map(|e| (e.parent_path.clone(), e.element.clone()))
        ),
        sorted_debug(expected_ext)
    );
    assert_eq!(
        strict
            .extensions
            .iter()
            .filter(|e| e.element.name.local == "LocalizedPropertiesCollection")
            .count(),
        1
    );
}

#[test]
fn derivation_is_deterministic_and_does_not_touch_the_input() {
    let doc = whole_doc(2, 3);
    let before = doc.clone();
    let a = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    let b = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    assert_eq!(a, b);
    assert_eq!(doc, before);
}

#[test]
fn nothing_is_synthesized_for_missing_parts() {
    let doc = "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
               <UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000009\" RevisionNumber=\"1\"/></Update>";
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    assert_eq!(
        text(&d.core),
        "<UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000009\" RevisionNumber=\"1\"/>"
    );
    assert!(d.extended.is_empty() && d.localized.is_empty() && d.eula.is_empty());
}

#[test]
fn only_properties_with_extended_content_produce_an_extended_properties_element() {
    let doc = "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
               <UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000009\" RevisionNumber=\"1\"/>\
               <Properties UpdateType=\"Software\" EulaID=\"x\"/></Update>";
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    assert!(text(&d.core).contains("<Properties UpdateType=\"Software\" EulaID=\"x\"/>"));
    assert!(d.extended.is_empty());
}

#[test]
fn non_documents_are_left_alone_and_bad_documents_fail_loudly() {
    let p = PrefixMap::specified();
    // A WUSP-form Core fragment is not a document.
    let frag = br#"<UpdateIdentity UpdateID="11111111-1111-4111-8111-111111111111" RevisionNumber="1"/><Properties UpdateType="Software"/>"#;
    assert!(derive_if_whole(frag, &p, &limits()).unwrap().is_none());
    // A stub without an identity is not one either.
    assert!(
        derive_if_whole(b"<Update n=\"1\"/>", &p, &limits())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        derive(frag, &p, &limits()),
        Err(DeriveError::NotAnUpdateDocument)
    ));
    // Two identities are refused rather than guessed.
    let dup = "<Update><UpdateIdentity UpdateID=\"11111111-1111-4111-8111-111111111111\" RevisionNumber=\"1\"/>\
               <UpdateIdentity UpdateID=\"11111111-1111-4111-8111-111111111111\" RevisionNumber=\"2\"/></Update>";
    assert!(matches!(
        derive(dup.as_bytes(), &p, &limits()),
        Err(DeriveError::DuplicateIdentity)
    ));
}

#[test]
fn attribute_name_collisions_after_stripping_are_errors() {
    let doc = "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\" xmlns:p=\"urn:p\" xmlns:q=\"urn:q\">\
               <UpdateIdentity UpdateID=\"11111111-1111-4111-8111-111111111111\" RevisionNumber=\"1\"/>\
               <HandlerSpecificData p:a=\"1\" q:a=\"2\"/></Update>";
    assert!(matches!(
        derive(doc.as_bytes(), &PrefixMap::specified(), &limits()),
        Err(DeriveError::AttributeCollision { .. })
    ));
}

#[test]
fn prefix_map_is_configurable_for_other_namespaces() {
    let p = PrefixMap::specified().with(CBS_NS, "cbs");
    let d = derive(whole_doc(1, 1).as_bytes(), &p, &limits()).unwrap();
    assert!(text(&d.core).contains("<cbs.CbsPackage Id=\"Package_for_X\"/>"));
    assert!(d.unmapped_namespaces.is_empty());
    assert!(BASE_APPLICABILITY_NS.ends_with("BaseApplicabilityRules"));
}

/// OBSERVED on a real WSUS 10.0.26100 (a WiX-built `.msp` published through the SDK): the
/// `MsiPatch` element inside `m.MsiPatchMetadata` is written with a default-namespace declaration.
#[test]
fn msi_patch_metadata_keeps_its_default_namespace_declaration() {
    const PATCH_NS: &str = "http://www.microsoft.com/msi/patch_applicability.xsd";
    let doc = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Update xmlns="http://schemas.microsoft.com/msus/2002/12/Update" xmlns:m="{MSI_NS}">
  <UpdateIdentity UpdateID="00000000-0000-0000-0000-0000000000a1" RevisionNumber="1"/>
  <Properties UpdateType="Software"/>
  <ApplicabilityRules>
    <IsInstalled><m:MsiPatchInstalled/></IsInstalled>
    <Metadata><m:MsiPatchMetadata><MsiPatch xmlns="{PATCH_NS}" SchemaVersion="1.0.0.0" PatchGUID="{{7FF3F06A-EB31-4490-98F1-BDD5803E2C36}}"><TargetProduct><TargetProductCode Validate="true">{{A1B2C3D4-0007-4000-8000-000000000700}}</TargetProductCode></TargetProduct></MsiPatch></m:MsiPatchMetadata></Metadata>
  </ApplicabilityRules>
</Update>"#
    );
    let d = derive(doc.as_bytes(), &PrefixMap::specified(), &limits()).unwrap();
    let core = text(&d.core);
    // declared once, on the outermost element of that namespace, after the other attributes
    assert!(core.contains(&format!(
        "<MsiPatch SchemaVersion=\"1.0.0.0\" PatchGUID=\"{{7FF3F06A-EB31-4490-98F1-BDD5803E2C36}}\" xmlns=\"{PATCH_NS}\">"
    )), "{core}");
    assert_eq!(core.matches("xmlns").count(), 1, "{core}");
    assert!(core.contains("<m.MsiPatchInstalled/>"));
    assert!(core.contains("<TargetProduct><TargetProductCode Validate=\"true\">"));
    assert!(d.unmapped_namespaces.is_empty());
}
