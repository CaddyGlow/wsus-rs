//! Transport and protocol failures are always SOAP faults with the right HTTP status.
mod endpoints_common;
use endpoints_common::*;

use wsus_protocol::soap::{ErrorCode, Presence, SoapVersion, encode_request};
use wsus_protocol::wusp::*;
use wsus_server::endpoints::HttpRequestParts;

fn xml_content_type() -> &'static str {
    "text/xml; charset=utf-8"
}

fn assert_soap_fault(
    resp: wsus_server::endpoints::HttpResponseParts,
    status: u16,
) -> wsus_protocol::soap::SoapFault {
    assert!(
        resp.header("Content-Type").unwrap().contains("xml"),
        "fault bodies are XML, never JSON"
    );
    let (s, f) = fault_of(resp);
    assert_eq!(s, status);
    f
}

#[test]
fn malformed_and_hostile_bodies_yield_client_faults() {
    let env = setup();
    let bodies: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"not xml".to_vec(),
        b"<a><b></a>".to_vec(),
        b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>".to_vec(),
        b"<Envelope xmlns=\"urn:wrong\"/>".to_vec(),
        vec![0xff, 0xfe, 0x00],
    ];
    for b in bodies {
        let r = env.post(CLIENT_PATH, SoapVersion::V11, b, xml_content_type(), None);
        let f = assert_soap_fault(r, 500);
        assert_eq!(f.code_local(), "Client");
    }
}

#[test]
fn wrong_method_media_type_path_and_size() {
    let env = setup();
    let get = env.server.handle(HttpRequestParts::new("GET", CLIENT_PATH));
    assert_eq!(get.header("Allow"), Some("POST"));
    assert_soap_fault(get, 405);
    let r = env.post(
        CLIENT_PATH,
        SoapVersion::V11,
        b"{}".to_vec(),
        "application/json",
        None,
    );
    assert_soap_fault(r, 415);
    let r = env
        .server
        .handle(HttpRequestParts::new("POST", "/nope").with_header("Content-Type", "text/xml"));
    assert_soap_fault(r, 404);
    let mut cfg = default_config();
    cfg.max_request_bytes = 1024;
    let small = setup_with(cfg);
    let r = small.post(
        CLIENT_PATH,
        SoapVersion::V11,
        vec![b' '; 1025],
        xml_content_type(),
        None,
    );
    assert_soap_fault(r, 413);
    // Exactly at the limit is parsed (and fails as malformed, not as too large).
    let r = small.post(
        CLIENT_PATH,
        SoapVersion::V11,
        vec![b' '; 1024],
        xml_content_type(),
        None,
    );
    assert_soap_fault(r, 500);
}

#[test]
fn xml_limits_are_enforced() {
    let mut cfg = default_config();
    cfg.max_xml_depth = 8;
    let env = setup_with(cfg);
    let mut deep =
        String::from("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>");
    for _ in 0..20 {
        deep.push_str("<a>");
    }
    for _ in 0..20 {
        deep.push_str("</a>");
    }
    deep.push_str("</s:Body></s:Envelope>");
    let r = env.post(
        CLIENT_PATH,
        SoapVersion::V11,
        deep.into_bytes(),
        xml_content_type(),
        None,
    );
    assert_soap_fault(r, 500);
}

#[test]
fn array_limit_in_requests_is_a_fault() {
    let mut cfg = default_config();
    cfg.max_array_len = 10;
    let env = setup_with(cfg);
    env.publish(&[frag(1)]);
    env.approve(1);
    let c = registered(&env, 5);
    let ids: Vec<i32> = (0..11).collect();
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &[], &ids)),
        ErrorCode::InvalidParameters
    );
}

#[test]
fn action_mismatch_unknown_operation_and_wrong_service_are_faults() {
    let env = setup();
    let enc = encode_request(
        SoapVersion::V11,
        &GetConfig {
            protocol_version: Presence::Absent,
        },
    );
    let r = env.post(
        CLIENT_PATH,
        SoapVersion::V11,
        enc.body.clone(),
        &enc.content_type,
        Some("\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie\""),
    );
    let f = assert_soap_fault(r, 500);
    assert_eq!(f.code_local(), "Client");
    // The right operation on the wrong service route.
    let r = env.post(
        AUTH_PATH,
        SoapVersion::V11,
        enc.body.clone(),
        &enc.content_type,
        enc.soap_action.as_deref(),
    );
    assert_soap_fault(r, 500);
    // Unimplemented operation.
    let body = b"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><StartCategoryScan xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\"/></s:Body></s:Envelope>".to_vec();
    let r = env.post(
        CLIENT_PATH,
        SoapVersion::V11,
        body,
        xml_content_type(),
        None,
    );
    assert_soap_fault(r, 500);
}

#[test]
fn schema_violations_are_invalid_parameters() {
    let env = setup();
    // GetCookie without the required lastChange/currentTime.
    let body = b"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><GetCookie xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\"/></s:Body></s:Envelope>".to_vec();
    let r = env.post(
        CLIENT_PATH,
        SoapVersion::V11,
        body,
        xml_content_type(),
        None,
    );
    let f = assert_soap_fault(r, 500);
    assert_eq!(f.wsus.unwrap().error_code, ErrorCode::InvalidParameters);
}

#[test]
fn must_understand_headers_are_refused() {
    let env = setup();
    let body = b"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Header><h xmlns=\"urn:x\" s:mustUnderstand=\"1\"/></s:Header><s:Body><GetConfig xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\"/></s:Body></s:Envelope>".to_vec();
    let r = env.post(
        CLIENT_PATH,
        SoapVersion::V11,
        body,
        xml_content_type(),
        None,
    );
    let f = assert_soap_fault(r, 500);
    assert_eq!(f.code_local(), "MustUnderstand");
}

#[test]
fn soap12_faults_use_400_for_sender_and_500_for_receiver() {
    let env = setup();
    let enc = encode_request(
        SoapVersion::V12,
        &GetConfig {
            protocol_version: Presence::Absent,
        },
    );
    // Sender fault: operation on the wrong route.
    let r = env.post(
        AUTH_PATH,
        SoapVersion::V12,
        enc.body.clone(),
        &enc.content_type,
        None,
    );
    let f = assert_soap_fault(r, 400);
    assert_eq!(f.version, SoapVersion::V12);
    // Application sender fault through the typed path.
    let resp = env.raw(
        SoapVersion::V12,
        &GetAuthorizationCookie {
            client_id: Presence::Absent,
            target_group_name: Presence::Absent,
            dns_name: Presence::Absent,
        },
    );
    let f = assert_soap_fault(resp, 400);
    assert_eq!(f.wsus.unwrap().error_code, ErrorCode::InvalidParameters);
}

#[test]
fn internal_failures_are_receiver_faults_without_detail_leakage() {
    let mut cfg = default_config();
    cfg.content_base_url = None; // no Host header either: cannot build a URL
    let env = setup_with(cfg);
    let data = b"x";
    env.publish(&[with_file(frag(1), "x.cab", data)]);
    env.approve(1);
    put_content(&env, "x.cab", data);
    let c = registered(&env, 6);
    let (status, f) = env
        .call(&GetFileLocations {
            cookie: Presence::Value(c.cookie.clone()),
            file_digests: Presence::Value(vec![sha1_of(data)]),
        })
        .err()
        .unwrap();
    assert_eq!(status, 500);
    assert_eq!(f.code_local(), "Server");
    let w = f.wsus.unwrap();
    assert_eq!(w.error_code, ErrorCode::InternalServerError);
    assert!(!f.reason.contains("sqlite") && !f.reason.contains("/"));
    assert!(w.id.is_some(), "fault instance id is present");
    assert!(w.method.unwrap().contains("GetFileLocations"));
}

#[test]
fn faults_carry_the_quoted_soap_action_as_method() {
    let env = setup();
    let (_, f) = env
        .call(&GetCookie {
            auth_cookies: Presence::Value(vec![]),
            old_cookie: Presence::Absent,
            last_change: xs("2026-01-01T00:00:00Z"),
            current_time: xs("2026-01-01T00:00:00Z"),
            protocol_version: Presence::Absent,
        })
        .err()
        .unwrap();
    assert!(f.wsus.unwrap().method.unwrap().ends_with("GetCookie\""));
}
