//! `Content-Encoding: xpress` on the SOAP services, request and response.
//! Hand-built native-style requests (header shapes as in inventory section
//! 9.3) plus this workspace's own codec. NOT verified: that a native Windows
//! Update Agent accepts the compressed responses produced here.
mod endpoints_common;
use endpoints_common::*;

use wsus_protocol::soap::{Limits, Presence, SoapVersion, decode_response, encode_request};
use wsus_protocol::wusp::*;
use wsus_protocol::xpress;
use wsus_server::endpoints::{HttpRequestParts, HttpResponseParts};

fn config_request(extra: &[(&str, &str)], xpress_body: bool) -> HttpRequestParts {
    let enc = encode_request(
        SoapVersion::V11,
        &GetConfig {
            protocol_version: Presence::Value("1.8".into()),
        },
    );
    let mut body = enc.body;
    let mut r = HttpRequestParts::new("POST", CLIENT_PATH)
        .with_header("Content-Type", &enc.content_type)
        .with_header("SOAPAction", enc.soap_action.as_deref().unwrap());
    if xpress_body {
        body = xpress::encode(&body).unwrap();
        r = r.with_header("Content-Encoding", "xpress");
    }
    for (k, v) in extra {
        r = r.with_header(k, v);
    }
    r.with_body(body)
}

fn decoded_config(resp: HttpResponseParts) -> GetConfigResponse {
    assert_eq!(resp.status, 200);
    let encoded = resp
        .header("Content-Encoding")
        .is_some_and(|v| v == "xpress");
    let mut body = resp.into_bytes().unwrap();
    if encoded {
        body = xpress::decode(&body, &xpress::Limits::default()).unwrap();
    }
    decode_response(&body, &Limits::default()).unwrap()
}

#[test]
fn xpress_is_used_when_requested_with_correct_headers() {
    let env = setup();
    let plain = env.server.handle(config_request(&[], false));
    assert_eq!(plain.header("Content-Encoding"), None);
    assert_eq!(plain.header("Vary"), Some("Accept-Encoding"));
    let plain_bytes = plain.into_bytes().unwrap();

    let resp = env
        .server
        .handle(config_request(&[("Accept-Encoding", "xpress")], false));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Encoding"), Some("xpress"));
    assert_eq!(resp.header("Vary"), Some("Accept-Encoding"));
    let declared: usize = resp.header("Content-Length").unwrap().parse().unwrap();
    let wire = resp.into_bytes().unwrap();
    assert_eq!(declared, wire.len());
    assert!(wire.len() < plain_bytes.len());
    let decoded = xpress::decode(&wire, &xpress::Limits::default()).unwrap();
    assert_eq!(
        decoded, plain_bytes,
        "same message, only the coding differs"
    );
}

#[test]
fn identity_only_or_refusing_clients_get_identity() {
    let env = setup();
    for value in ["identity", "gzip", "xpress;q=0", "*", ""] {
        let resp = env
            .server
            .handle(config_request(&[("Accept-Encoding", value)], false));
        assert_eq!(resp.header("Content-Encoding"), None, "{value}");
        assert!(decoded_config(resp).result.value().is_some());
    }
}

#[test]
fn switch_off_disables_response_compression_and_vary() {
    let mut cfg = default_config();
    cfg.xpress_responses = false;
    let env = setup_with(cfg);
    let resp = env
        .server
        .handle(config_request(&[("Accept-Encoding", "xpress")], false));
    assert_eq!(resp.header("Content-Encoding"), None);
    assert_eq!(resp.header("Vary"), None);
    assert!(decoded_config(resp).result.value().is_some());
}

#[test]
fn faults_are_compressed_consistently() {
    let env = setup();
    let mut req = config_request(&[("Accept-Encoding", "xpress")], false);
    req.body = vec![b'<'; 4000]; // malformed, produces a fault body
    let resp = env.server.handle(req);
    let declared: usize = resp.header("Content-Length").unwrap().parse().unwrap();
    let encoded = resp.header("Content-Encoding").is_some();
    let body = resp.into_bytes().unwrap();
    assert_eq!(declared, body.len());
    if encoded {
        let text = xpress::decode(&body, &xpress::Limits::default()).unwrap();
        assert!(String::from_utf8_lossy(&text).contains("Fault"));
    }
}

#[test]
fn content_downloads_are_never_compressed() {
    let env = setup();
    let data = vec![b'a'; 100_000];
    put_content(&env, "big.cab", &data);
    let hex = wsus_server::storage::hex_encode(&sha1_of(&data)).to_ascii_uppercase();
    let path = format!("/Content/{}/{hex}.cab", &hex[hex.len() - 2..]);
    let resp = env
        .server
        .handle(HttpRequestParts::new("GET", &path).with_header("Accept-Encoding", "xpress"));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Encoding"), None);
    assert_eq!(resp.header("Content-Length"), Some("100000"));
    assert_eq!(resp.into_bytes().unwrap(), data);
}

#[test]
fn xpress_request_bodies_are_accepted() {
    let env = setup();
    let resp = env.server.handle(config_request(&[], true));
    assert!(decoded_config(resp).result.value().is_some());
    // Both directions at once.
    let resp = env
        .server
        .handle(config_request(&[("Accept-Encoding", "xpress")], true));
    assert_eq!(resp.header("Content-Encoding"), Some("xpress"));
    assert!(decoded_config(resp).result.value().is_some());
}

#[test]
fn bad_request_encodings_are_rejected() {
    let mut cfg = default_config();
    cfg.max_request_bytes = 64 * 1024;
    let env = setup_with(cfg);
    // Unknown coding.
    let mut r = config_request(&[], false);
    r.headers.push(("Content-Encoding".into(), "gzip".into()));
    assert_eq!(env.server.handle(r).status, 415);
    // Corrupt xpress body.
    let mut r = config_request(&[], true);
    let n = r.body.len();
    r.body.truncate(n - 2);
    // Client faults are SOAP faults with HTTP 500, as for any malformed request.
    let resp = env.server.handle(r);
    assert_eq!(resp.status, 500);
    assert!(String::from_utf8_lossy(&resp.into_bytes().unwrap()).contains("Fault"));
    // Bomb: small on the wire, huge decoded; the decoded cap is max_request_bytes.
    let bomb = xpress::encode(&vec![b' '; 4 * 1024 * 1024]).unwrap();
    assert!(bomb.len() < 64 * 1024);
    let mut r = config_request(&[], false);
    r.headers.push(("Content-Encoding".into(), "xpress".into()));
    r.body = bomb;
    let resp = env.server.handle(r);
    assert_eq!(resp.status, 500);
}
