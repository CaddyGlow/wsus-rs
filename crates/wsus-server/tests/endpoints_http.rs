//! The axum binding adapts the neutral handler; one smoke test of each response kind.
#![cfg(feature = "http")]
mod endpoints_common;
use endpoints_common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use wsus_protocol::soap::{Limits, Presence, SoapVersion, decode_response, encode_request};
use wsus_protocol::wusp::*;
use wsus_server::endpoints::http::router;
use wsus_server::storage::hex_encode;

#[tokio::test(flavor = "multi_thread")]
async fn soap_content_range_head_and_oversize_through_axum() {
    let mut cfg = default_config();
    cfg.max_request_bytes = 64 * 1024;
    let env = setup_with(cfg);
    let data: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
    put_content(&env, "big.cab", &data);
    let app = router(env.server.clone());

    // SOAP.
    let enc = encode_request(
        SoapVersion::V11,
        &GetConfig {
            protocol_version: Presence::Absent,
        },
    );
    let resp = app
        .clone()
        .oneshot(
            Request::post("/ClientWebService/client.asmx")
                .header("content-type", &enc.content_type)
                .header("soapaction", enc.soap_action.unwrap())
                .body(Body::from(enc.body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let cfg: GetConfigResponse = decode_response(&body, &Limits::default()).unwrap();
    assert!(cfg.result.value().unwrap().is_registration_required);

    // Streamed content, range and HEAD.
    let hex = hex_encode(&sha1_of(&data)).to_ascii_uppercase();
    let path = format!("/Content/{}/{hex}.cab", &hex[hex.len() - 2..]);
    let full = app
        .clone()
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::OK);
    let got = full.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got.as_ref(), data.as_slice());
    let part = app
        .clone()
        .oneshot(
            Request::get(&path)
                .header("range", "bytes=100000-100009")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(part.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        part.headers()["content-range"],
        "bytes 100000-100009/200000"
    );
    assert_eq!(
        part.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        &data[100000..100010]
    );
    let head = app
        .clone()
        .oneshot(Request::head(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(head.headers()["content-length"], "200000");
    assert!(
        head.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    let bad = app
        .clone()
        .oneshot(
            Request::get(&path)
                .header("range", "bytes=999999-")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::RANGE_NOT_SATISFIABLE);

    // Oversize bodies become SOAP faults, not framework errors.
    let big = app
        .clone()
        .oneshot(
            Request::post("/ClientWebService/client.asmx")
                .header("content-type", "text/xml")
                .body(Body::from(vec![b' '; 70 * 1024]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = big.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("Fault"));

    // Unknown paths are SOAP faults as well.
    let nf = app
        .oneshot(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(nf.status(), StatusCode::NOT_FOUND);
    assert!(
        String::from_utf8_lossy(&nf.into_body().collect().await.unwrap().to_bytes())
            .contains("Fault")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn xpress_response_and_request_through_axum() {
    use wsus_protocol::xpress;
    let env = setup();
    let app = router(env.server.clone());
    let enc = encode_request(
        SoapVersion::V11,
        &GetConfig {
            protocol_version: Presence::Absent,
        },
    );
    let resp = app
        .oneshot(
            Request::post("/ClientWebService/client.asmx")
                .header("content-type", &enc.content_type)
                .header("soapaction", enc.soap_action.unwrap())
                .header("accept-encoding", "xpress")
                .header("content-encoding", "xpress")
                .body(Body::from(xpress::encode(&enc.body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-encoding"], "xpress");
    assert_eq!(resp.headers()["vary"], "Accept-Encoding");
    let declared: usize = resp.headers()["content-length"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let wire = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(declared, wire.len());
    let body = xpress::decode(&wire, &xpress::Limits::default()).unwrap();
    let cfg: GetConfigResponse = decode_response(&body, &Limits::default()).unwrap();
    assert!(cfg.result.value().unwrap().is_registration_required);
}
