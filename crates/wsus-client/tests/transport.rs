mod common;

use common::{Behavior, StdTransport, TestServer, block_on};
use std::{sync::Mutex, time::Duration};
use wsus_client::transport::{
    ErrorKind, Failure, HttpRequest, HttpResponse, Idempotence, ImmediateTimer, RetryPolicy,
    SensitiveUrl, Transport, TransportError,
    mock::{MockStep, MockTransport},
    redact_url, scrub_urls, send_with_retry,
};

fn url(s: &str) -> SensitiveUrl {
    SensitiveUrl::parse(s).unwrap()
}

fn post(u: &str) -> HttpRequest {
    HttpRequest::soap_post(
        url(u),
        "http://x/Action",
        "application/soap+xml",
        b"<a/>".to_vec(),
        Duration::from_secs(5),
    )
}

fn status(code: u16) -> MockStep {
    MockStep::Respond(HttpResponse::new(code, Vec::new()))
}

#[test]
fn debug_output_hides_cookies_credentials_and_signed_urls() {
    let mut request =
        post("https://user:pw@wsus.test:8531/ClientWebService/client.asmx?token=SIGNED");
    request.headers.set("Cookie", "CookieSecret");
    request.headers.set("Authorization", "Basic Zm9v");
    let text = format!("{request:?}");
    for secret in ["SIGNED", "CookieSecret", "Zm9v", "pw", "ClientWebService"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(text.contains("wsus.test:8531"));
    let mut response = HttpResponse::new(200, b"<Cookie>secret</Cookie>".to_vec());
    response.headers.set("Set-Cookie", "session=abc");
    let text = format!("{response:?}");
    assert!(
        !text.contains("abc") && !text.contains("<Cookie>"),
        "{text}"
    );
    assert_eq!(redact_url("https://a:b@h:1/p?q#f"), "https://h:1/...");
    assert_eq!(redact_url("ftp://x"), "<redacted-url>");
    assert_eq!(
        scrub_urls("GET https://h.test/p?sig=1 failed (http://g.test/x)"),
        "GET https://h.test/... failed (http://g.test/...)"
    );
    let err = TransportError::io("error sending request for url (https://h.test/p?sig=SECRET)");
    assert!(!err.to_string().contains("SECRET"));
    assert!(SensitiveUrl::parse("file:///etc/passwd").is_err());
    assert!(SensitiveUrl::parse("https://").is_err());
    assert!(SensitiveUrl::parse("https://a b/").is_err());
}

#[test]
fn retry_decisions_follow_idempotence() {
    let p = RetryPolicy::default();
    let connect = TransportError::connect("refused");
    let reset = TransportError::io("reset");
    let t = |e| Failure::Transport(e);
    let s = |status, retry_after| Failure::Status {
        status,
        retry_after,
    };
    // Idempotent: retry transport errors and transient statuses.
    assert!(p.decide(Idempotence::Idempotent, 0, t(&reset)).is_some());
    assert!(p.decide(Idempotence::Idempotent, 0, s(503, None)).is_some());
    assert!(p.decide(Idempotence::Idempotent, 0, s(404, None)).is_none());
    assert!(p.decide(Idempotence::Idempotent, 3, t(&reset)).is_none());
    // Non-idempotent: only when the request provably was not processed.
    assert!(
        p.decide(Idempotence::NonIdempotent, 0, t(&connect))
            .is_some()
    );
    assert!(p.decide(Idempotence::NonIdempotent, 0, t(&reset)).is_none());
    assert!(
        p.decide(Idempotence::NonIdempotent, 0, t(&TransportError::timeout()))
            .is_none()
    );
    assert!(
        p.decide(Idempotence::NonIdempotent, 0, s(500, None))
            .is_none()
    );
    assert!(
        p.decide(Idempotence::NonIdempotent, 0, s(503, None))
            .is_none()
    );
    assert_eq!(
        p.decide(
            Idempotence::NonIdempotent,
            0,
            s(503, Some(Duration::from_secs(2)))
        ),
        Some(Duration::from_secs(2))
    );
    // Backoff is bounded.
    assert_eq!(
        p.decide(
            Idempotence::Idempotent,
            1,
            s(503, Some(Duration::from_secs(3600)))
        ),
        Some(p.max_delay)
    );
}

#[test]
fn post_is_not_replayed_after_server_error_but_get_is() {
    let t = MockTransport::scripted(vec![status(500), status(200)]);
    let r = block_on(send_with_retry(
        &t,
        &ImmediateTimer,
        &RetryPolicy::default(),
        &post("https://h.test/s"),
    ))
    .unwrap();
    assert_eq!(r.status, 500);
    assert_eq!(t.requests().len(), 1);

    let t = MockTransport::scripted(vec![status(500), status(200)]);
    let get = HttpRequest::get(url("https://h.test/f"), Duration::from_secs(5));
    let r = block_on(send_with_retry(
        &t,
        &ImmediateTimer,
        &RetryPolicy::default(),
        &get,
    ))
    .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(t.requests().len(), 2);

    // A read-only SOAP query may opt in.
    let t = MockTransport::scripted(vec![status(502), status(200)]);
    let r = block_on(send_with_retry(
        &t,
        &ImmediateTimer,
        &RetryPolicy::default(),
        &post("https://h.test/s").idempotent(),
    ))
    .unwrap();
    assert_eq!(r.status, 200);
}

#[test]
fn post_is_replayed_only_after_connect_failure() {
    let t = MockTransport::scripted(vec![
        MockStep::Fail(TransportError::connect("refused")),
        status(200),
    ]);
    let r = block_on(send_with_retry(
        &t,
        &ImmediateTimer,
        &RetryPolicy::default(),
        &post("https://h.test/s"),
    ))
    .unwrap();
    assert_eq!(r.status, 200);

    let t = MockTransport::scripted(vec![
        MockStep::Fail(TransportError::io("reset")),
        status(200),
    ]);
    let e = block_on(send_with_retry(
        &t,
        &ImmediateTimer,
        &RetryPolicy::default(),
        &post("https://h.test/s"),
    ))
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Io);
    assert_eq!(t.requests().len(), 1);
}

#[test]
fn retries_are_bounded() {
    let t = MockTransport::with_handler(|_| status(503));
    let r = block_on(send_with_retry(
        &t,
        &ImmediateTimer,
        &RetryPolicy::default(),
        &HttpRequest::get(url("https://h.test/"), Duration::from_secs(1)),
    ))
    .unwrap();
    assert_eq!(r.status, 503);
    assert_eq!(t.requests().len(), 4);
}

#[test]
fn retry_after_header_is_honored_and_sleep_recorded() {
    struct Rec(Mutex<Vec<Duration>>);
    impl wsus_client::transport::RetryTimer for Rec {
        async fn sleep(&self, d: Duration) {
            self.0.lock().unwrap().push(d);
        }
    }
    let mut busy = HttpResponse::new(503, Vec::new());
    busy.headers.set("Retry-After", "7");
    let t = MockTransport::scripted(vec![MockStep::Respond(busy), status(200)]);
    let timer = Rec(Mutex::default());
    let r = block_on(send_with_retry(
        &t,
        &timer,
        &RetryPolicy::default(),
        &post("https://h.test/s"),
    ))
    .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(*timer.0.lock().unwrap(), vec![Duration::from_secs(7)]);
}

#[test]
fn soap_post_and_ranged_get_over_tcp() {
    let server = TestServer::start((0..=255u8).collect());
    let mut request = post(&server.url("/ClientWebService/client.asmx"));
    request.headers.set("Cookie", "abc");
    let response = block_on(StdTransport.send(request)).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"<a/>");
    assert_eq!(
        response.headers.get("set-cookie"),
        Some("session=topsecret")
    );
    assert!(!format!("{response:?}").contains("topsecret"));

    let get =
        HttpRequest::get(url(&server.url("/f")), Duration::from_secs(5)).with_range(250, None);
    let response = block_on(StdTransport.send(get)).unwrap();
    assert_eq!(response.status, 206);
    assert_eq!(response.body, vec![250, 251, 252, 253, 254, 255]);
    let seen = server.seen();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].body, b"<a/>");
    assert_eq!(seen[1].range.as_deref(), Some("bytes=250-"));

    server.script(vec![Behavior::Status(500)]);
    let r = block_on(StdTransport.send(HttpRequest::get(
        url(&server.url("/f")),
        Duration::from_secs(5),
    )))
    .unwrap();
    assert_eq!(r.status, 500);
}

#[test]
fn buffered_responses_respect_size_limit() {
    let t = MockTransport::serving(vec![0; 100]);
    let mut get = HttpRequest::get(url("https://h.test/"), Duration::from_secs(1));
    get.max_response_bytes = 10;
    let e = block_on(t.send(get)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::TooLarge);
}

#[cfg(feature = "reqwest-async")]
#[tokio::test]
async fn reqwest_adapter_supports_post_and_range() {
    use wsus_client::transport::reqwest_backend::ReqwestTransport;
    let server = TestServer::start((0..=255u8).collect());
    let transport = ReqwestTransport::new().unwrap();
    let u = server.url("/svc");
    let response = transport.send(post(&u)).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"<a/>");
    assert_eq!(
        response.headers.get("set-cookie"),
        Some("session=topsecret")
    );
    let get =
        HttpRequest::get(url(&server.url("/f")), Duration::from_secs(5)).with_range(250, None);
    let response = transport.send(get).await.unwrap();
    assert_eq!(response.status, 206);
    assert_eq!(response.body, vec![250, 251, 252, 253, 254, 255]);
    let refused = SensitiveUrl::parse("http://127.0.0.1:1/x?sig=SECRET").unwrap();
    let e = transport
        .send(HttpRequest::get(refused, Duration::from_secs(2)))
        .await
        .unwrap_err();
    assert!(!e.to_string().contains("SECRET"), "{e}");
}
