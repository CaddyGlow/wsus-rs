#![allow(dead_code)]
use std::fmt::Debug;
use std::path::PathBuf;

use uuid::Uuid;
use wsus_protocol::soap::{
    EncodedMessage, Limits, Presence, SoapMessage, SoapRequest, SoapVersion, XsDateTime,
    action_from_content_type, decode_request, decode_response, encode_request, encode_response,
};

pub fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

pub fn dt(s: &str) -> XsDateTime {
    XsDateTime::new(s).expect("valid dateTime")
}

pub fn guid(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

pub fn some<T>(v: T) -> Presence<T> {
    Presence::Value(v)
}

pub fn s(v: &str) -> Presence<String> {
    Presence::Value(v.to_owned())
}

fn action_of(m: &EncodedMessage) -> Option<String> {
    match &m.soap_action {
        Some(a) => Some(a.clone()),
        None => action_from_content_type(&m.content_type),
    }
}

/// Request roundtrip in both SOAP versions, plus encoder determinism and
/// action consistency.
pub fn roundtrip_request<R: SoapRequest + PartialEq + Debug>(req: &R) {
    let limits = Limits::default();
    for v in [SoapVersion::V11, SoapVersion::V12] {
        let enc = encode_request(v, req);
        assert_eq!(enc.body, encode_request(v, req).body, "deterministic");
        let action = action_of(&enc);
        assert_eq!(
            action.as_deref().map(|a| a.trim_matches('"')),
            Some(R::action().as_str())
        );
        let (got_v, got): (SoapVersion, R) =
            decode_request(action.as_deref(), &enc.body, &limits).expect("decode request");
        assert_eq!(got_v, v);
        assert_eq!(&got, req);
        // Re-encoding the decoded value is byte-identical.
        assert_eq!(encode_request(v, &got).body, enc.body);
    }
}

/// Response roundtrip in both SOAP versions.
pub fn roundtrip_response<M: SoapMessage + PartialEq + Debug>(msg: &M) {
    let limits = Limits::default();
    for v in [SoapVersion::V11, SoapVersion::V12] {
        let enc = encode_response(v, msg);
        assert_eq!(enc.body, encode_response(v, msg).body, "deterministic");
        let got: M = decode_response(&enc.body, &limits).expect("decode response");
        assert_eq!(&got, msg);
        assert_eq!(encode_response(v, &got).body, enc.body);
    }
}

/// Roundtrip a request and its response.
pub fn roundtrip_pair<R>(req: &R, resp: &R::Response)
where
    R: SoapRequest + PartialEq + Debug,
    R::Response: PartialEq + Debug,
{
    roundtrip_request(req);
    roundtrip_response(resp);
}
