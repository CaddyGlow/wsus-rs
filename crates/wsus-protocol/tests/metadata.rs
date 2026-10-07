mod common;

use common::*;
use sha2::{Digest, Sha256};
use wsus_protocol::ProtocolError;
use wsus_protocol::identity::{DigestAlgorithm, ServerId};
use wsus_protocol::metadata::*;
use wsus_protocol::soap::{Limits, Presence};
use wsus_protocol::wsusss::ServerSyncUpdateData;
use wsus_protocol::wusp::{UpdateInfo, XmlUpdateFragmentType};

fn core_text() -> String {
    String::from_utf8(fixture("metadata_update_core.xml")).unwrap()
}

#[test]
fn index_parses_identity_relationships_and_files() {
    let ix = UpdateIndex::parse(core_text().as_bytes(), &Limits::default()).unwrap();
    assert_eq!(ix.identity.revision.0, 204);
    assert_eq!(ix.properties.update_type, Some(UpdateType::Software));
    assert!(
        ix.properties
            .attributes
            .contains(&("FutureAttribute".into(), "kept".into()))
    );

    assert_eq!(ix.prerequisites.len(), 2);
    assert_eq!(ix.prerequisites[0].update_ids.len(), 1);
    assert!(!ix.prerequisites[0].is_category);
    assert_eq!(ix.prerequisites[1].update_ids.len(), 2);
    assert!(ix.prerequisites[1].is_category);

    assert_eq!(ix.bundled.len(), 2);
    assert_eq!(ix.bundled[0].revisions.len(), 1);
    assert_eq!(ix.bundled[1].revisions.len(), 2);
    assert_eq!(ix.bundled[1].revisions[1].revision.0, 3);

    assert_eq!(ix.superseded.len(), 1);

    assert_eq!(ix.files.len(), 1);
    let f = &ix.files[0];
    assert_eq!(f.file_name.as_deref(), Some("update.cab"));
    assert_eq!(f.size, Some(1234));
    assert_eq!(f.digests.len(), 2);
    assert_eq!(f.sha1().unwrap().bytes, (0u8..20).collect::<Vec<_>>());
    assert_eq!(f.digests[1].algorithm, DigestAlgorithm::Sha256);
    assert_eq!(f.digests[1].bytes.len(), 32);
    assert!(
        f.attributes
            .contains(&("PatchingType".into(), "None".into()))
    );
    assert_eq!(f.extensions.len(), 1);

    assert!(ix.applicability_rules.is_some());
}

#[test]
fn unknown_extensions_are_preserved_not_discarded() {
    let ix = UpdateIndex::parse(core_text().as_bytes(), &Limits::default()).unwrap();
    let paths: Vec<_> = ix
        .extensions
        .iter()
        .map(|e| (e.parent_path.as_str(), e.element.name.local.as_str()))
        .collect();
    assert!(paths.contains(&("/Update", "FutureTopLevel")), "{paths:?}");
    assert!(
        paths.contains(&("/Update/Relationships", "FutureRelationship")),
        "{paths:?}"
    );
    let fr = ix
        .extensions
        .iter()
        .find(|e| e.element.name.local == "FutureRelationship")
        .unwrap();
    assert_eq!(fr.element.attr("Foo"), Some("bar"));
    assert!(
        fr.element
            .child(fr.element.name.ns.as_deref(), "Child")
            .is_some()
    );
}

#[test]
fn unqualified_documents_are_accepted_and_foreign_namespaces_rejected() {
    let xml = r#"<Update><UpdateIdentity UpdateID="11111111-1111-4111-8111-111111111111" RevisionNumber="1"/></Update>"#;
    assert!(UpdateIndex::parse(xml.as_bytes(), &Limits::default()).is_ok());
    let foreign = r#"<Update xmlns="urn:other"><UpdateIdentity UpdateID="11111111-1111-4111-8111-111111111111" RevisionNumber="1"/></Update>"#;
    assert!(matches!(
        UpdateIndex::parse(foreign.as_bytes(), &Limits::default()).unwrap_err(),
        ProtocolError::Metadata(_)
    ));
}

#[test]
fn bad_metadata_is_rejected() {
    for bad in [
        "<Update/>",
        r#"<Update><UpdateIdentity UpdateID="zz" RevisionNumber="1"/></Update>"#,
        r#"<Update><UpdateIdentity UpdateID="11111111-1111-4111-8111-111111111111"/></Update>"#,
        r#"<Update><UpdateIdentity UpdateID="11111111-1111-4111-8111-111111111111" RevisionNumber="1"/><Files><File Digest="AAAA"/></Files></Update>"#,
        "<Other/>",
    ] {
        assert!(
            UpdateIndex::parse(bad.as_bytes(), &Limits::default()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn provenance_hash_covers_received_bytes() {
    let text = core_text();
    let origin = FragmentOrigin::new(FragmentSource::Other("test".into()));
    let f = RawFragment::from_xml_text(origin, &text);
    let expected: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    assert_eq!(f.provenance.sha256, expected);
    assert_eq!(f.provenance.received_len, text.len() as u64);
    assert_eq!(f.provenance.hex().len(), 64);
    assert_eq!(f.xml(), text.as_bytes());
    assert!(f.verify_provenance(text.as_bytes()).is_ok());
    assert!(f.verify_provenance(b"other").is_err());
    // Byte-different but semantically equal text yields a different hash.
    let g = RawFragment::from_xml_text(
        FragmentOrigin::new(FragmentSource::Other("test".into())),
        &format!("{text} "),
    );
    assert_ne!(f.provenance, g.provenance);
    assert!(f.index(&Limits::default()).is_ok());
}

#[test]
fn compressed_blob_hash_covers_compressed_bytes() {
    let compressed = [0x4D, 0x53, 0x43, 0x46, 1, 2, 3];
    let xml = core_text().into_bytes();
    let data = ServerSyncUpdateData {
        id: Presence::Absent,
        xml_update_blob: Presence::Absent,
        file_digest_list: Presence::Absent,
        xml_update_blob_compressed: Presence::Value(compressed.to_vec()),
    };
    let server = Some(ServerId(guid(1)));
    let frag = RawFragment::from_server_sync(server, &data, |c| {
        assert_eq!(c, compressed);
        Ok(xml.clone())
    })
    .unwrap()
    .unwrap();
    assert_eq!(frag.representation, Representation::Compressed);
    assert_eq!(frag.provenance, Provenance::of(&compressed));
    assert_eq!(frag.xml(), xml.as_slice());
    assert_eq!(frag.origin.source, FragmentSource::WsusssGetUpdateData);
    assert_eq!(frag.origin.server, server);

    let empty = ServerSyncUpdateData {
        id: Presence::Absent,
        xml_update_blob: Presence::Absent,
        file_digest_list: Presence::Absent,
        xml_update_blob_compressed: Presence::Absent,
    };
    assert!(
        RawFragment::from_server_sync(None, &empty, |_| unreachable!())
            .unwrap()
            .is_none()
    );
}

#[test]
fn origin_is_recorded_from_sync_updates() {
    let info = UpdateInfo {
        id: 77,
        deployment: Presence::Absent,
        is_leaf: true,
        xml: Presence::Value(core_text()),
    };
    let f = RawFragment::from_update_info(Some(ServerId(guid(2))), &info).unwrap();
    assert_eq!(f.origin.source, FragmentSource::WuspSyncUpdates);
    assert_eq!(f.origin.wire_revision.unwrap().0, 77);
    assert_eq!(f.origin.fragment_type, Some(XmlUpdateFragmentType::Core));
    let none = UpdateInfo {
        xml: Presence::Nil,
        ..info
    };
    assert!(RawFragment::from_update_info(None, &none).is_none());
}

#[test]
fn metadata_limits_apply() {
    let tight = Limits {
        max_depth: 2,
        ..Limits::default()
    };
    assert!(UpdateIndex::parse(core_text().as_bytes(), &tight).is_err());
}
