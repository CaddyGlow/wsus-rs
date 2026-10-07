//! `Content-Encoding: xpress` handling of the MS-WUSP session, against the
//! in-process fake server (spec-derived) with its responses Xpress encoded by
//! `wsus_protocol::xpress`. The decode against a REAL server is
//! `real_wsus.rs` (ignored, needs the lab).

mod session_common;

use session_common::*;
use wsus_client::{
    session::{SessionConfig, WuspError},
    sync::SyncOptions,
    transport::{
        HttpResponse, ImmediateTimer, Method, RetryPolicy,
        mock::{MockStep, MockTransport},
    },
};
use wsus_protocol::xpress;

fn xpress_encoded(mut r: HttpResponse) -> HttpResponse {
    r.body = xpress::encode(&r.body).unwrap();
    r.headers.set("Content-Encoding", "xpress");
    r
}

fn harness() -> Harness {
    let h = Harness::with_response_encoding(xpress_encoded);
    h.fake().add(1, 1, true);
    h
}

#[tokio::test]
async fn soap_posts_ask_for_xpress_and_a_full_sync_decodes_it() {
    let h = harness();
    let mut e = h.engine();
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let requests = h.transport.requests();
    assert!(!requests.is_empty());
    for r in &requests {
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.headers.get("accept-encoding"), Some("xpress"));
    }
}

#[tokio::test]
async fn accept_xpress_off_sends_no_accept_encoding_and_gets_identity() {
    let h = harness();
    let mut c = h.config();
    c.accept_xpress = false;
    let mut e = h.engine_with(c);
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    for r in h.transport.requests() {
        assert_eq!(r.headers.get("accept-encoding"), None);
    }
}

#[tokio::test]
async fn unknown_content_encoding_is_rejected_clearly() {
    let h = Harness::with_response_encoding(|mut r| {
        r.headers.set("Content-Encoding", "gzip");
        r
    });
    let mut s = h.session();
    let err = s.handshake(false).await.unwrap_err();
    assert!(matches!(err, WuspError::UnsupportedEncoding), "{err:?}");
}

#[tokio::test]
async fn corrupt_xpress_body_is_a_typed_error() {
    let h = Harness::with_response_encoding(|mut r| {
        r.body = xpress::encode(&r.body).unwrap();
        let n = r.body.len();
        r.body.truncate(n - 3);
        r.headers.set("Content-Encoding", "xpress");
        r
    });
    let mut s = h.session();
    let err = s.handshake(false).await.unwrap_err();
    assert!(matches!(err, WuspError::Xpress(_)), "{err:?}");
}

#[tokio::test]
async fn max_response_bytes_applies_to_the_decoded_size() {
    let sizes = std::sync::Arc::new(std::sync::Mutex::new((0usize, 0usize)));
    let seen = sizes.clone();
    let h = Harness::with_response_encoding(move |r| {
        let wire = xpress_encoded(r.clone());
        let mut s = seen.lock().unwrap();
        if s.0 == 0 {
            *s = (wire.body.len(), r.body.len());
        }
        wire
    });
    // First learn the wire and decoded sizes of the GetConfig response.
    h.session().handshake(false).await.ok();
    let (wire, decoded) = *sizes.lock().unwrap();
    assert!(wire < decoded, "{wire} {decoded}");
    let h = Harness::with_response_encoding(xpress_encoded);
    let mut c: SessionConfig = h.config();
    // The mock transport enforces no wire limit, so only the decoded-size
    // check of the session can trip.
    c.max_response_bytes = wire + (decoded - wire) / 2;
    let mut s = h.session_with(c);
    let err = s.handshake(false).await.unwrap_err();
    assert!(
        matches!(
            err,
            WuspError::Xpress(xpress::XpressError::TotalTooLarge { .. })
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn xpress_encoded_fault_still_reports_the_fault() {
    let t = MockTransport::with_handler(|_| {
        let fault = wsus_protocol::soap::SoapFault::application(
            wsus_protocol::soap::SoapVersion::V11,
            wsus_protocol::soap::ErrorCode::InvalidCookie,
            "nope",
            None,
            None,
            Some("GetConfig"),
        );
        let body = xpress::encode(&wsus_protocol::soap::encode_fault(&fault).body).unwrap();
        let mut r = HttpResponse::new(500, body);
        r.headers.set("Content-Encoding", "xpress");
        MockStep::Respond(r)
    });
    let dir = tempfile::TempDir::new().unwrap();
    let store = wsus_client::state::StateStore::open(dir.path().join("s.json")).unwrap();
    let mut c = SessionConfig::new("http://wsus.test:8530", "client.test");
    c.retry = RetryPolicy::none();
    let mut s = wsus_client::session::WuspSession::new(
        t,
        ImmediateTimer,
        wsus_client::session::SystemClock,
        c,
        store,
    )
    .unwrap();
    let err = s.handshake(false).await.unwrap_err();
    assert!(matches!(err, WuspError::Fault(_)), "{err:?}");
}
