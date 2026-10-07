//! WUSP handlers over a catalog populated the way the downstream importer populates it:
//! whole update documents in the Core slot. Also covers records stored in WUSP form.
//! In-process only; not validated against a native Windows Update client.
mod endpoints_common;
mod fragments_common;
use endpoints_common::*;
use fragments_common::*;

use sha2::{Digest, Sha256};
use wsus_protocol::metadata::{FragmentIndex, UpdateIndex};
use wsus_protocol::soap::Limits;
use wsus_protocol::wusp::XmlUpdateFragmentType::{self, *};
use wsus_server::catalog::FragmentImport;
use wsus_server::fragments::{PrefixMap, derive};

fn whole(n: u128, rev_no: u32) -> FragmentImport {
    // Exactly what the downstream importer stores: the document, no Extended slot.
    FragmentImport::new(rev(n, rev_no), "Software", whole_doc(n, rev_no).as_bytes())
}

fn wusp_form(n: u128) -> FragmentImport {
    let d = derive(
        whole_doc(n, 1).as_bytes(),
        &PrefixMap::specified(),
        &Limits::default(),
    )
    .unwrap();
    let mut f = FragmentImport::new(rev(n, 1), "Software", &d.core);
    f.extended_xml = Some(d.extended);
    f
}

fn ext(
    c: &Client,
    ids: Vec<i32>,
    types: Vec<XmlUpdateFragmentType>,
    loc: &str,
) -> wsus_protocol::wusp::GetExtendedUpdateInfo {
    wsus_protocol::wusp::GetExtendedUpdateInfo {
        cookie: wsus_protocol::soap::Presence::Value(c.cookie.clone()),
        revision_ids: wsus_protocol::soap::Presence::Value(ids),
        info_types: wsus_protocol::soap::Presence::Value(types),
        locales: wsus_protocol::soap::Presence::Value(vec![loc.into()]),
        geo_id: wsus_protocol::soap::Presence::Absent,
        caller_attributes: wsus_protocol::soap::Presence::Absent,
    }
}

fn expected(n: u128) -> wsus_server::fragments::DerivedFragments {
    derive(
        whole_doc(n, 1).as_bytes(),
        &PrefixMap::specified(),
        &Limits::default(),
    )
    .unwrap()
}

#[test]
fn sync_updates_serves_the_derived_core_fragment_and_leaves_the_stored_bytes_alone() {
    let env = setup();
    env.publish(&[whole(1, 1), wusp_form(3)]);
    env.approve(1);
    env.approve(3);
    let mut c = registered(&env, 100);
    let info = sync(&env, &mut c, &[], &[]);
    let updates = info.new_updates.value().unwrap();
    assert_eq!(updates.len(), 2);
    let by = |n: u128| updates.iter().find(|u| u.id == local(&env, n)).unwrap();

    // Whole document in the Core slot: the derived Core fragment is served.
    let served = by(1).xml.value().unwrap();
    assert_eq!(served.as_bytes(), expected(1).core.as_slice());
    assert!(served.starts_with("<UpdateIdentity "));
    assert!(!served.contains("xmlns") && !served.contains("<Update "));
    let idx = FragmentIndex::parse(served.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(idx.identity, Some(rev(1, 1)));
    assert!(idx.applicability_rules.is_some() && idx.files.is_empty());

    // Stored WUSP form is served untouched.
    assert_eq!(
        by(3).xml.value().unwrap().as_bytes(),
        expected(3).core.as_slice()
    );

    // The catalog still holds the original bytes and their hash.
    let snap = env.catalog.snapshot(env.source).unwrap().unwrap();
    let rec = snap.get(rev(1, 1)).unwrap().unwrap();
    assert_eq!(rec.core_xml, whole_doc(1, 1).as_bytes());
    assert_eq!(rec.extended_xml, None);
    let hash: String = Sha256::digest(&rec.core_xml)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(rec.core_sha256, hash);
    UpdateIndex::parse(&rec.core_xml, &Limits::default()).unwrap();
}

#[test]
fn extended_update_info_serves_derived_extended_localized_and_eula_fragments() {
    let env = setup();
    let eula_doc = whole_doc(1, 1).replace(
        "<FutureTopLevel",
        "<EulaFiles><EulaFile Language=\"en\" FileName=\"e.txt\"/></EulaFiles><FutureTopLevel",
    );
    env.publish(&[
        FragmentImport::new(rev(1, 1), "Software", eula_doc.as_bytes()),
        wusp_form(3),
    ]);
    env.approve(1);
    env.approve(3);
    let c = registered(&env, 100);
    let (l1, l3) = (local(&env, 1), local(&env, 3));
    let types = vec![Core, Extended, LocalizedProperties, Eula];
    let r = env
        .call(&ext(&c, vec![l1], types.clone(), "de"))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    let xml: Vec<&str> = r
        .updates
        .value()
        .unwrap()
        .iter()
        .map(|u| u.xml.value().unwrap().as_str())
        .collect();
    let d = derive(
        eula_doc.as_bytes(),
        &PrefixMap::specified(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        xml.len(),
        4,
        "core, extended, the German localized fragment and the EULA, which falls back to the default language"
    );
    assert_eq!(xml[0].as_bytes(), d.core.as_slice());
    assert_eq!(xml[1].as_bytes(), d.extended.as_slice());
    assert!(xml[2].contains("<Language>de</Language>") && !xml[2].contains("Example update"));
    assert!(xml[3].starts_with("<EulaFile "));

    // Requested locale en: localized en plus the en EULA fragment.
    let r = env
        .call(&ext(&c, vec![l1], vec![LocalizedProperties, Eula], "en-US"))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    let xml: Vec<&str> = r
        .updates
        .value()
        .unwrap()
        .iter()
        .map(|u| u.xml.value().unwrap().as_str())
        .collect();
    assert_eq!(xml.len(), 2);
    assert!(xml[0].contains("Example update"));
    assert!(xml[1].starts_with("<EulaFile "));

    // A record stored in WUSP form: Core and Extended as stored, nothing localized.
    let r = env
        .call(&ext(&c, vec![l3], types, "en"))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    let xml: Vec<&str> = r
        .updates
        .value()
        .unwrap()
        .iter()
        .map(|u| u.xml.value().unwrap().as_str())
        .collect();
    assert_eq!(xml.len(), 2);
    assert_eq!(xml[0].as_bytes(), expected(3).core.as_slice());
    assert_eq!(xml[1].as_bytes(), expected(3).extended.as_slice());
}

#[test]
fn legacy_stub_records_keep_working_next_to_whole_documents() {
    let env = setup();
    env.publish(&[frag(2), whole(1, 1)]);
    env.approve(1);
    env.approve(2);
    let mut c = registered(&env, 100);
    let info = sync(&env, &mut c, &[], &[]);
    let updates = info.new_updates.value().unwrap();
    let stub = updates.iter().find(|u| u.id == local(&env, 2)).unwrap();
    assert_eq!(stub.xml.value().unwrap(), "<Update n=\"2\"/>");
}

#[test]
fn a_whole_document_that_cannot_be_transformed_is_an_internal_error_not_a_guess() {
    let env = setup();
    let doc = "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\" xmlns:p=\"urn:p\" xmlns:q=\"urn:q\">\
               <UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000001\" RevisionNumber=\"1\"/>\
               <HandlerSpecificData p:a=\"1\" q:a=\"2\"/></Update>";
    env.publish(&[FragmentImport::new(rev(1, 1), "Software", doc.as_bytes())]);
    env.approve(1);
    let c = registered(&env, 100);
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &[], &[])),
        wsus_protocol::soap::ErrorCode::InternalServerError
    );
}
