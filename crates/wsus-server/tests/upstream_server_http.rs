//! The MS-WSUSSS axum binding: SOAP, content and surface separation through the router.
//! Self-consistency only; no real downstream WSUS has been involved.
#![cfg(feature = "http")]
mod upstream_server_common;
use upstream_server_common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use wsus_protocol::soap::{Limits, SoapVersion, decode_response, encode_request};
use wsus_protocol::wsusss::*;
use wsus_server::endpoints::wsusss::Surface;
use wsus_server::endpoints::wsusss::http::router;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn services_and_content_surfaces_are_separate_listeners_over_one_server() {
    let f = fixture();
    let data: Vec<u8> = (0..150_000u32).map(|n| (n % 251) as u8).collect();
    f.publish(&[Doc::bare(1, 1).with_file("big.cab", &data)]);
    f.put_content("big.cab", &data);
    let services = router(f.server.clone(), Surface::Services);
    let content = router(f.server.clone(), Surface::Content);

    let enc = encode_request(SoapVersion::V11, &GetAuthConfig {});
    let soap = |app: axum::Router| {
        let enc = enc.clone();
        async move {
            app.oneshot(
                Request::post(SYNC_PATH)
                    .header("content-type", &enc.content_type)
                    .header("soapaction", enc.soap_action.unwrap())
                    .body(Body::from(enc.body))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let ok = soap(services.clone()).await;
    assert_eq!(ok.status(), StatusCode::OK);
    let body = ok.into_body().collect().await.unwrap().to_bytes();
    let cfg: GetAuthConfigResponse = decode_response(&body, &Limits::default()).unwrap();
    assert!(cfg.result.value().is_some());
    assert_eq!(soap(content.clone()).await.status(), StatusCode::NOT_FOUND);

    let h = hex(&sha1(&data));
    let path = format!("/Content/{}/{h}", &h[38..]);
    let full = content
        .clone()
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::OK);
    let got = full.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got.as_ref(), data.as_slice());
    let part = content
        .clone()
        .oneshot(
            Request::get(&path)
                .header("range", "bytes=10-19")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(part.status(), StatusCode::PARTIAL_CONTENT);
    let got = part.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got.as_ref(), &data[10..20]);
    let head = content
        .oneshot(Request::head(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(head.headers()["content-length"], "150000");
    // The services listener does not serve content.
    let r = services
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_bodies_are_refused_before_buffering() {
    let cfg = wsus_server::endpoints::wsusss::UpstreamServerConfig {
        max_request_bytes: 1024,
        ..config()
    };
    let f = fixture_with(cfg);
    let app = router(f.server.clone(), Surface::All);
    let r = app
        .oneshot(
            Request::post(SYNC_PATH)
                .header("content-type", "text/xml")
                .body(Body::from(vec![b' '; 4096]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
