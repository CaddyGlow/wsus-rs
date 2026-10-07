mod common;

use common::*;
use wsus_protocol::ProtocolError;
use wsus_protocol::soap::xml::{self, Element, QName};
use wsus_protocol::soap::{
    Body, Envelope, ErrorCode, Limits, Presence, Recovery, SoapFault, SoapVersion,
    action_from_content_type, decode_request, decode_response, encode_fault, validate_action,
};
use wsus_protocol::wusp::{GetConfig, GetConfigResponse, GetCookie, GetCookieResponse};

#[test]
fn fault_v11_is_parsed_with_error_code() {
    let env = Envelope::decode(
        &fixture("fault_soap11_invalid_cookie.xml"),
        &Limits::default(),
    )
    .unwrap();
    let Body::Fault(f) = env.body else {
        panic!("expected fault")
    };
    assert_eq!(f.version, SoapVersion::V11);
    assert_eq!(f.code_local(), "Client");
    let w = f.wsus.as_ref().unwrap();
    assert_eq!(w.error_code, ErrorCode::InvalidCookie);
    assert_eq!(w.message.as_deref(), Some("cookie rejected"));
    assert_eq!(
        w.id.as_deref(),
        Some("6e8d0c3a-3f1e-4b66-9d3e-0a1b2c3d4e5f")
    );
    assert_eq!(
        w.error_code.wusp_recovery(),
        Recovery::RestartHandshakeWithRefreshCache
    );
}

#[test]
fn fault_is_reported_by_decode_response_without_any_http_status() {
    // decode_response takes only bytes: a fault inside a 200 response and a
    // fault inside a 500 response are indistinguishable and both surface.
    let err = decode_response::<GetConfigResponse>(
        &fixture("fault_soap11_invalid_cookie.xml"),
        &Limits::default(),
    )
    .unwrap_err();
    match err {
        ProtocolError::Fault(f) => {
            assert_eq!(f.wsus.unwrap().error_code, ErrorCode::InvalidCookie)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn fault_v12_with_unqualified_detail_is_parsed() {
    let env = Envelope::decode(
        &fixture("fault_soap12_wsusss_detail.xml"),
        &Limits::default(),
    )
    .unwrap();
    let Body::Fault(f) = env.body else { panic!() };
    assert_eq!(f.version, SoapVersion::V12);
    assert_eq!(f.reason, "bad digests");
    let w = f.wsus.unwrap();
    assert_eq!(w.error_code, ErrorCode::FileDigestsMissing);
    assert_eq!(w.message.as_deref(), Some("AAAA|BBBB"));
}

#[test]
fn fault_without_error_code_has_no_wsus_detail() {
    let env = Envelope::decode(
        &fixture("fault_soap11_no_errorcode.xml"),
        &Limits::default(),
    )
    .unwrap();
    let Body::Fault(f) = env.body else { panic!() };
    assert_eq!(f.reason, "boom");
    assert!(f.wsus.is_none());
}

#[test]
fn error_code_aliases_and_unknowns() {
    assert_eq!(
        ErrorCode::parse("FileLocationsChanged"),
        ErrorCode::FileLocationChanged
    );
    assert_eq!(
        ErrorCode::parse("InvalidParameter"),
        ErrorCode::InvalidParameters
    );
    assert_eq!(
        ErrorCode::parse("Weird"),
        ErrorCode::Unknown("Weird".into())
    );
    assert_eq!(
        ErrorCode::FileLocationChanged.as_str(),
        "FileLocationChanged"
    );
    assert_eq!(
        ErrorCode::CookieExpired.wusp_recovery(),
        Recovery::RenewCookie
    );
}

#[test]
fn faults_roundtrip_for_both_versions() {
    for v in [SoapVersion::V11, SoapVersion::V12] {
        let f = SoapFault::application(
            v,
            ErrorCode::ServerBusy,
            "busy",
            Some("try later"),
            Some(guid(1)),
            Some("SyncUpdates"),
        );
        let enc = encode_fault(&f);
        assert_eq!(enc.body, encode_fault(&f).body);
        let env = Envelope::decode(&enc.body, &Limits::default()).unwrap();
        let Body::Fault(g) = env.body else { panic!() };
        assert_eq!(g.version, v);
        assert_eq!(g.reason, "busy");
        assert_eq!(g.wsus.as_ref().unwrap().error_code, ErrorCode::ServerBusy);
        assert_eq!(
            g.wsus.as_ref().unwrap().method.as_deref(),
            Some("SyncUpdates")
        );
        assert_eq!(
            g.wsus.unwrap().id.as_deref(),
            Some(guid(1).hyphenated().to_string().as_str())
        );
    }
}

#[test]
fn mismatched_action_is_rejected() {
    let body = fixture("wusp_getcookie_request_soap12.xml");
    let wrong = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig";
    let err = decode_request::<GetCookie>(Some(wrong), &body, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, ProtocolError::ActionMismatch { .. }),
        "{err:?}"
    );
    let right = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie";
    assert!(decode_request::<GetCookie>(Some(right), &body, &Limits::default()).is_ok());
}

#[test]
fn body_of_wrong_message_is_rejected() {
    let err = decode_request::<GetConfig>(
        None,
        &fixture("wusp_getcookie_request_soap12.xml"),
        &Limits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, ProtocolError::UnexpectedBody { .. }),
        "{err:?}"
    );
    // Same local name in a different namespace is not the same message.
    let xml = br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><GetConfig xmlns="urn:other"/></s:Body></s:Envelope>"#;
    assert!(decode_request::<GetConfig>(None, xml, &Limits::default()).is_err());
}

#[test]
fn action_helpers() {
    let q = QName::new("urn:x", "Op");
    assert!(validate_action(Some(" \"urn:x/Op\" "), &q).is_ok());
    assert!(validate_action(Some("\"\""), &q).is_ok());
    assert!(validate_action(Some("urn:x/Other"), &q).is_err());
    assert_eq!(
        action_from_content_type("application/soap+xml; charset=utf-8; action=\"urn:x/Op\"")
            .as_deref(),
        Some("urn:x/Op")
    );
    assert_eq!(action_from_content_type("text/xml"), None);
}

#[test]
fn malformed_xml_is_rejected() {
    let err = Envelope::decode(&fixture("malformed_unclosed.xml"), &Limits::default()).unwrap_err();
    assert!(matches!(err, ProtocolError::MalformedXml(_)), "{err:?}");
    for bad in [
        "",
        "<a",
        "<a></b>",
        "<a/><b/>",
        "text",
        "<a xmlns:p='u'><p:b></a>",
        "<x:a/>",
    ] {
        assert!(
            xml::parse(bad.as_bytes(), &Limits::default()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn dtd_and_external_entities_are_rejected() {
    let err =
        Envelope::decode(&fixture("dtd_external_entity.xml"), &Limits::default()).unwrap_err();
    assert_eq!(err, ProtocolError::DtdNotAllowed);
    // Even an entity-free DOCTYPE is refused.
    assert_eq!(
        xml::parse(b"<!DOCTYPE a><a/>", &Limits::default()).unwrap_err(),
        ProtocolError::DtdNotAllowed
    );
    // Undefined entity references are refused too.
    assert!(matches!(
        xml::parse(b"<a>&xxe;</a>", &Limits::default()).unwrap_err(),
        ProtocolError::UnsupportedEntity(_)
    ));
    // Predefined and numeric references work.
    let e = xml::parse(b"<a>&lt;&#65;&amp;</a>", &Limits::default()).unwrap();
    assert_eq!(e.text(), "<A&");
}

#[test]
fn not_an_envelope() {
    assert!(matches!(
        Envelope::decode(b"<a/>", &Limits::default()).unwrap_err(),
        ProtocolError::NotSoapEnvelope(_)
    ));
    let no_body = br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"/>"#;
    assert!(matches!(
        Envelope::decode(no_body, &Limits::default()).unwrap_err(),
        ProtocolError::InvalidEnvelope(_)
    ));
}

#[test]
fn limits_are_enforced() {
    let doc = fixture("wusp_getconfig_response_soap11.xml");
    let small = Limits {
        max_body_bytes: 100,
        ..Limits::default()
    };
    assert!(matches!(
        Envelope::decode(&doc, &small).unwrap_err(),
        ProtocolError::BodyTooLarge { .. }
    ));
    let shallow = Limits {
        max_depth: 3,
        ..Limits::default()
    };
    assert!(matches!(
        Envelope::decode(&doc, &shallow).unwrap_err(),
        ProtocolError::DepthExceeded { .. }
    ));
    let few = Limits {
        max_elements: 5,
        ..Limits::default()
    };
    assert!(matches!(
        Envelope::decode(&doc, &few).unwrap_err(),
        ProtocolError::TooManyElements { .. }
    ));
    // Deep nesting does not overflow the stack: the parser is iterative and
    // stops at the limit.
    let deep = "<a>".repeat(10_000);
    assert!(matches!(
        xml::parse(deep.as_bytes(), &Limits::default()).unwrap_err(),
        ProtocolError::DepthExceeded { .. }
    ));
}

#[test]
fn oversized_arrays_are_rejected() {
    let mut items = String::new();
    for i in 0..50 {
        items.push_str(&format!("<int>{i}</int>"));
    }
    let xml = format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
        <GetConfigResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><GetConfigResult>
        <LastChange>2024-05-01T10:20:30Z</LastChange><IsRegistrationRequired>true</IsRegistrationRequired>
        <AllowedEventIds>{items}</AllowedEventIds>
        </GetConfigResult></GetConfigResponse></s:Body></s:Envelope>"#
    );
    let ok = Limits {
        max_array_len: 50,
        ..Limits::default()
    };
    assert!(decode_response::<GetConfigResponse>(xml.as_bytes(), &ok).is_ok());
    let tight = Limits {
        max_array_len: 49,
        ..Limits::default()
    };
    let err = decode_response::<GetConfigResponse>(xml.as_bytes(), &tight).unwrap_err();
    assert!(
        matches!(err, ProtocolError::ArrayTooLong { limit: 49, .. }),
        "{err:?}"
    );
}

#[test]
fn serializer_is_deterministic_and_prefix_independent() {
    let a = xml::parse(
        &fixture("wusp_getconfig_response_alt_prefix.xml"),
        &Limits::default(),
    )
    .unwrap();
    let b = xml::parse(
        &fixture("wusp_getconfig_response_alt_prefix.xml"),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
    // Reparsing serialized output yields an equal tree even though prefixes changed.
    let again = xml::parse(&a.to_bytes(), &Limits::default()).unwrap();
    assert_eq!(a, again);
    assert!(!String::from_utf8(a.to_bytes()).unwrap().contains("c:"));
}

#[test]
fn serializer_handles_unqualified_children_inside_default_namespace() {
    let e =
        Element::new("urn:a", "Root").with_child(Element::unqualified("plain").with_text("x<&>"));
    let bytes = e.to_bytes();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("xmlns=\"\""), "{text}");
    assert_eq!(xml::parse(&bytes, &Limits::default()).unwrap(), e);
}

#[test]
fn whitespace_text_and_cdata_are_preserved() {
    let e = xml::parse(
        b"<a><b>  </b><c><![CDATA[<x>]]></c></a>",
        &Limits::default(),
    )
    .unwrap();
    let b = e.child(None, "b").unwrap();
    assert_eq!(b.text(), "  ");
    assert_eq!(e.child(None, "c").unwrap().text(), "<x>");
}

#[test]
fn must_understand_headers_are_surfaced() {
    let xml = br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header>
        <h:Thing xmlns:h="urn:h" s:mustUnderstand="1"/></s:Header><s:Body><X xmlns="urn:x"/></s:Body></s:Envelope>"#;
    let env = Envelope::decode(xml, &Limits::default()).unwrap();
    assert_eq!(env.must_understand_headers().len(), 1);
    assert_eq!(env.headers.len(), 1);
}

#[test]
fn utf8_bom_is_accepted_and_utf16_rejected() {
    let mut doc = vec![0xEF, 0xBB, 0xBF];
    doc.extend_from_slice(&fixture("wusp_getconfig_response_soap11.xml"));
    assert!(decode_response::<GetConfigResponse>(&doc, &Limits::default()).is_ok());
    assert!(matches!(
        xml::parse(&[0xFF, 0xFE, b'<', 0], &Limits::default()).unwrap_err(),
        ProtocolError::UnsupportedEncoding(_)
    ));
    assert!(matches!(
        xml::parse(
            b"<?xml version=\"1.0\" encoding=\"utf-16\"?><a/>",
            &Limits::default()
        )
        .unwrap_err(),
        ProtocolError::UnsupportedEncoding(_)
    ));
}

#[test]
fn presence_helpers() {
    let p: Presence<i32> = 3.into();
    assert_eq!(p.value(), Some(&3));
    assert!(Presence::<i32>::Nil.is_nil());
    assert!(Presence::<i32>::default().is_absent());
    assert_eq!(Presence::Value(2).map(|v| v * 2), Presence::Value(4));
}

#[allow(dead_code)]
fn _unused(_: GetCookieResponse) {}

// ---- Regression tests for fuzzer findings --------------------------------

#[test]
fn xmlns_values_are_entity_decoded_and_stable_across_cycles() {
    let l = Limits::default();
    let e = xml::parse(
        br#"<a xmlns="x&amp;y"><b xmlns:p="u&lt;v" p:k="1"/></a>"#,
        &l,
    )
    .unwrap();
    assert_eq!(e.name.ns.as_deref(), Some("x&y"));
    let b = e.elements().next().unwrap();
    assert_eq!(b.attributes[0].name.ns.as_deref(), Some("u<v"));
    // parse -> serialize -> parse is a fixed point (no `&amp;amp;` growth).
    let once = e.to_bytes();
    let again = xml::parse(&once, &l).unwrap();
    assert_eq!(again, e);
    assert_eq!(again.to_bytes(), once);
    // Same through the lenient path.
    let f = xml::parse_fragments(br#"<a xmlns="x&amp;y"/>"#, &l).unwrap();
    assert_eq!(f[0].name.ns.as_deref(), Some("x&y"));
}

#[test]
fn empty_element_names_are_rejected() {
    let l = Limits::default();
    for bad in [
        "<a>< /></a>",
        "<a><:b/></a>",
        "<a><p:/></a>",
        "<a xmlns:p='u'><p:/></a>",
    ] {
        assert!(
            matches!(
                xml::parse(bad.as_bytes(), &l),
                Err(ProtocolError::MalformedXml(_))
            ),
            "{bad}"
        );
        assert!(xml::parse_fragments(bad.as_bytes(), &l).is_err(), "{bad}");
    }
}

#[test]
fn names_with_forbidden_characters_are_rejected() {
    let l = Limits::default();
    for bad in [
        "<a><b:!True/></a>",
        "<a xmlns:b='u'><b:!True/></a>",
        "<a><1b/></a>",
        "<a><b c$='1'/></a>",
        "<a><b.c:d:e/></a>",
        "<a><b\u{7f}/></a>",
    ] {
        assert!(xml::parse(bad.as_bytes(), &l).is_err(), "{bad}");
        assert!(xml::parse_fragments(bad.as_bytes(), &l).is_err(), "{bad}");
    }
    // Dotted `b.` names from MS-WUSP fragments stay valid.
    assert!(xml::parse_fragments(b"<b.True/><m.X a.b='1'/>", &l).is_ok());
}
