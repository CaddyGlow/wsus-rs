mod common;

use common::{Behavior, StdTransport, TestServer, block_on, expected_for, sample};
use std::fs;
use tempfile::TempDir;
use wsus_client::{
    download::{
        DownloadError, DownloadLimits, DownloadOptions, Downloader, ExpectedFile, Location,
        validate_file_name,
    },
    transport::{
        HttpResponse, ImmediateTimer,
        mock::{MockStep, MockTransport},
    },
};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest};

const SIZE: usize = 100_000;

fn setup() -> (TempDir, Downloader) {
    let dir = TempDir::new().unwrap();
    let dl = Downloader::open(dir.path().join("dl"), DownloadLimits::default()).unwrap();
    (dir, dl)
}

fn loc() -> Location {
    Location::parse("https://download.example.test/content/f.cab?sig=SECRETSIG&exp=1").unwrap()
}

fn files_in(dir: &std::path::Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn opts() -> DownloadOptions {
    DownloadOptions {
        checkpoint_interval: 4096,
        ..DownloadOptions::default()
    }
}

#[test]
fn downloads_and_verifies_all_digests() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    let transport = MockTransport::serving(body.clone());
    let done = block_on(dl.download(&transport, &expected, &loc(), &opts())).unwrap();
    assert_eq!(fs::read(&done.path).unwrap(), body);
    assert_eq!(done.resumed_from, 0);
    assert!(!done.already_complete);
    assert!(files_in(&dir.path().join("dl/partial")).is_empty());
    // Second call reuses the verified object without any request.
    let again = block_on(dl.download(&transport, &expected, &loc(), &opts())).unwrap();
    assert!(again.already_complete);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn interrupted_download_resumes_with_range_over_tcp() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    let server = TestServer::start(body.clone());
    server.script(vec![Behavior::DropAfter(40_000)]);
    let location = Location::parse(&server.url("/f.cab?sig=abc")).unwrap();

    let err = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap_err();
    assert!(
        matches!(
            err,
            DownloadError::Transport(_) | DownloadError::Truncated { .. }
        ),
        "{err:?}"
    );
    // Never exposed as complete.
    assert!(!dl.complete_path(&expected).exists());
    assert!(files_in(&dir.path().join("dl/complete")).is_empty());
    assert!(dl.verified(&expected).unwrap().is_none());

    let done = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap();
    assert_eq!(done.resumed_from, 40_000);
    assert!(!done.restarted);
    assert_eq!(fs::read(&done.path).unwrap(), body);
    let seen = server.seen();
    assert_eq!(seen[0].range, None);
    assert_eq!(seen[1].range.as_deref(), Some("bytes=40000-"));
}

#[test]
fn retry_loop_resumes_after_mock_interruption() {
    let (_dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    let first = {
        let mut r = HttpResponse::new(200, body[..25_000].to_vec());
        r.headers.set("Content-Length", SIZE.to_string());
        r
    };
    let served = body.clone();
    let transport = MockTransport::scripted(vec![
        MockStep::Interrupt(first),
        MockStep::Respond({
            let mut r = HttpResponse::new(206, served[25_000..].to_vec());
            r.headers
                .set("Content-Range", format!("bytes 25000-{}/{SIZE}", SIZE - 1));
            r
        }),
    ]);
    let done =
        block_on(dl.download_with_retry(&transport, &ImmediateTimer, &expected, &loc(), &opts()))
            .unwrap();
    assert_eq!(done.resumed_from, 25_000);
    assert_eq!(fs::read(done.path).unwrap(), body);
    assert_eq!(
        transport.requests()[1].headers.get("range"),
        Some("bytes=25000-")
    );
}

#[test]
fn corrupted_content_is_rejected_and_not_promoted() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    let server = TestServer::start(body);
    server.script(vec![Behavior::Corrupt]);
    let location = Location::parse(&server.url("/f.cab")).unwrap();
    let err = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::DigestMismatch(_)), "{err:?}");
    assert!(files_in(&dir.path().join("dl/partial")).is_empty());
    assert!(files_in(&dir.path().join("dl/complete")).is_empty());
}

#[test]
fn every_digest_is_checked() {
    let (_dir, dl) = setup();
    let body = sample(2000);
    let good = expected_for("a.bin", &body);
    // Same sha1/sha256 as the real content but a wrong sha512.
    let mut digests = good.digests().to_vec();
    for d in &mut digests {
        if d.algorithm == DigestAlgorithm::Sha512 {
            d.bytes[0] ^= 1;
        }
    }
    let bad = ExpectedFile::new("a.bin", 2000, digests).unwrap();
    let transport = MockTransport::serving(body);
    let err = block_on(dl.download(&transport, &bad, &loc(), &opts())).unwrap_err();
    assert!(
        matches!(err, DownloadError::DigestMismatch(DigestAlgorithm::Sha512)),
        "{err:?}"
    );
}

#[test]
fn oversize_and_short_bodies_are_never_promoted() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    let server = TestServer::start(body);
    let location = Location::parse(&server.url("/f.cab")).unwrap();

    server.script(vec![Behavior::Oversize]);
    let err = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap_err();
    assert!(
        matches!(
            err,
            DownloadError::LengthMismatch { .. } | DownloadError::Overrun
        ),
        "{err:?}"
    );
    assert!(files_in(&dir.path().join("dl/complete")).is_empty());

    // Misdescribed length: the server sends fewer bytes than expected.
    let longer =
        ExpectedFile::new("update.cab", SIZE as u64 + 10, expected.digests().to_vec()).unwrap();
    let err = block_on(dl.download(&StdTransport, &longer, &location, &opts())).unwrap_err();
    assert!(
        matches!(err, DownloadError::LengthMismatch { .. }),
        "{err:?}"
    );
    assert!(files_in(&dir.path().join("dl/complete")).is_empty());
}

fn partial_with(dl: &Downloader, expected: &ExpectedFile, body: &[u8], n: usize) {
    let mut first = HttpResponse::new(200, body[..n].to_vec());
    first.headers.set("Content-Length", body.len().to_string());
    let t = MockTransport::scripted(vec![MockStep::Interrupt(first)]);
    let err = block_on(dl.download(&t, expected, &loc(), &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::Transport(_)));
}

#[test]
fn full_response_to_range_request_is_rejected_unless_restart_allowed() {
    let (_dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    partial_with(&dl, &expected, &body, 30_000);

    let server = TestServer::start(body.clone());
    let location = Location::parse(&server.url("/f.cab")).unwrap();
    server.script(vec![Behavior::IgnoreRange]);
    let err = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::RangeIgnored), "{err:?}");
    assert!(dl.verified(&expected).unwrap().is_none());

    // The partial object survives the rejection and can still be resumed.
    server.script(vec![Behavior::IgnoreRange]);
    let restart = DownloadOptions {
        allow_restart_on_full_response: true,
        ..opts()
    };
    let done = block_on(dl.download(&StdTransport, &expected, &location, &restart)).unwrap();
    assert!(done.restarted);
    assert_eq!(done.resumed_from, 0);
    assert_eq!(fs::read(done.path).unwrap(), body);
}

#[test]
fn wrong_content_range_is_rejected() {
    let (_dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    partial_with(&dl, &expected, &body, 30_000);
    let server = TestServer::start(body.clone());
    let location = Location::parse(&server.url("/f.cab")).unwrap();
    server.script(vec![Behavior::BadContentRange]);
    let err = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::RangeMismatch(_)), "{err:?}");
    // Retrying against a correct server still resumes.
    let done = block_on(dl.download(&StdTransport, &expected, &location, &opts())).unwrap();
    assert_eq!(done.resumed_from, 30_000);
}

#[test]
fn unsatisfiable_range_discards_partial_object() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    partial_with(&dl, &expected, &body, 30_000);
    let t = MockTransport::with_handler(|_| MockStep::Respond(HttpResponse::new(416, Vec::new())));
    let err = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::RangeNotSatisfiable), "{err:?}");
    assert!(files_in(&dir.path().join("dl/partial")).is_empty());
}

#[test]
fn partial_response_to_non_range_request_is_rejected() {
    let (_dir, dl) = setup();
    let body = sample(1000);
    let expected = expected_for("a.bin", &body);
    let t = MockTransport::with_handler(move |_| {
        let mut r = HttpResponse::new(206, vec![0; 10]);
        r.headers.set("Content-Range", "bytes 0-9/1000");
        MockStep::Respond(r)
    });
    let err = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::RangeMismatch(_)), "{err:?}");
}

#[test]
fn encoded_responses_and_error_statuses_are_rejected() {
    let (_dir, dl) = setup();
    let body = sample(1000);
    let expected = expected_for("a.bin", &body);
    let b = body.clone();
    let t = MockTransport::with_handler(move |_| {
        let mut r = HttpResponse::new(200, b.clone());
        r.headers.set("Content-Encoding", "gzip");
        MockStep::Respond(r)
    });
    let err = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err();
    assert!(matches!(err, DownloadError::UnexpectedEncoding), "{err:?}");
    let t = MockTransport::with_handler(|_| MockStep::Respond(HttpResponse::new(404, Vec::new())));
    let err = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err();
    assert!(
        matches!(err, DownloadError::HttpStatus { status: 404, .. }),
        "{err:?}"
    );
}

#[test]
fn tampered_partial_is_discarded_not_trusted() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    partial_with(&dl, &expected, &body, 30_000);
    let part = dir
        .path()
        .join("dl/partial")
        .join(format!("{}.part", expected.content_id()));
    let mut bytes = fs::read(&part).unwrap();
    bytes[10] ^= 0xff;
    fs::write(&part, bytes).unwrap();
    let t = MockTransport::serving(body.clone());
    let done = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap();
    assert!(done.restarted);
    assert_eq!(done.resumed_from, 0);
    assert_eq!(fs::read(done.path).unwrap(), body);
    assert_eq!(t.requests()[0].headers.get("range"), None);
}

#[test]
fn partial_without_matching_sidecar_is_discarded() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    partial_with(&dl, &expected, &body, 30_000);
    let side = dir
        .path()
        .join("dl/partial")
        .join(format!("{}.json", expected.content_id()));
    fs::write(&side, b"{ not json").unwrap();
    let t = MockTransport::serving(body.clone());
    let done = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap();
    assert!(done.restarted);
    assert_eq!(fs::read(done.path).unwrap(), body);
}

#[test]
fn urls_never_reach_disk_or_debug_output() {
    let (dir, dl) = setup();
    let body = sample(SIZE);
    let expected = expected_for("update.cab", &body);
    partial_with(&dl, &expected, &body, 30_000);
    for entry in fs::read_dir(dir.path().join("dl/partial")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = fs::read_to_string(path).unwrap();
            assert!(!text.contains("SECRETSIG") && !text.contains("download.example"));
        }
    }
    let debug = format!("{:?} {:?}", loc(), dl);
    assert!(!debug.contains("SECRETSIG"), "{debug}");
    let t = MockTransport::with_handler(|_| {
        MockStep::Fail(wsus_client::transport::TransportError::io(
            "failed GET https://h.test/p?sig=SECRETSIG",
        ))
    });
    let err = block_on(dl.download(&t, &expected_for("x.bin", b"x"), &loc(), &opts())).unwrap_err();
    assert!(!format!("{err} {err:?}").contains("SECRETSIG"));
    let req = format!("{:?}", t.requests()[0]);
    assert!(!req.contains("SECRETSIG"), "{req}");
}

#[test]
fn limits_are_enforced() {
    let dir = TempDir::new().unwrap();
    let body = sample(1000);
    let expected = expected_for("a.bin", &body);
    let t = MockTransport::serving(body);

    let dl = Downloader::open(
        dir.path().join("a"),
        DownloadLimits {
            max_file_size: 999,
            ..DownloadLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err(),
        DownloadError::TooLarge { .. }
    ));
    let dl = Downloader::open(
        dir.path().join("b"),
        DownloadLimits {
            max_concurrent: 0,
            ..DownloadLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err(),
        DownloadError::Busy
    ));
    let dl = Downloader::open(
        dir.path().join("c"),
        DownloadLimits {
            max_reserved_bytes: 10,
            ..DownloadLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap_err(),
        DownloadError::ReservationExceeded
    ));
    assert!(t.requests().is_empty());
}

#[test]
fn file_names_and_descriptors_are_validated() {
    for bad in [
        "", ".", "..", "a/b", "a\\b", "c:x", "x\0y", "trail.", "trail ", "CON", "nul.txt",
        "COM1.cab", "a*b", "a|b",
    ] {
        assert!(validate_file_name(bad).is_err(), "{bad:?}");
    }
    for good in [
        "windows11.0-kb5000-x64.cab",
        "COM0.cab",
        "a b.msu",
        "com10.cab",
    ] {
        assert!(validate_file_name(good).is_ok(), "{good:?}");
    }
    let d = |a, n| FileDigest {
        algorithm: a,
        bytes: vec![0; n],
    };
    assert!(ExpectedFile::new("a", 1, vec![]).is_err());
    assert!(ExpectedFile::new("a", 1, vec![d(DigestAlgorithm::Sha1, 19)]).is_err());
    assert!(
        ExpectedFile::new(
            "a",
            1,
            vec![d(DigestAlgorithm::Sha1, 20), d(DigestAlgorithm::Sha1, 20)]
        )
        .is_err()
    );
    assert!(ExpectedFile::new("a/b", 1, vec![d(DigestAlgorithm::Sha1, 20)]).is_err());
    let a = ExpectedFile::new(
        "a",
        1,
        vec![d(DigestAlgorithm::Sha1, 20), d(DigestAlgorithm::Sha256, 32)],
    )
    .unwrap();
    let b = ExpectedFile::new(
        "a",
        1,
        vec![d(DigestAlgorithm::Sha256, 32), d(DigestAlgorithm::Sha1, 20)],
    )
    .unwrap();
    assert_eq!(a.content_id(), b.content_id());
}

#[test]
fn zero_length_objects_verify() {
    let (_dir, dl) = setup();
    let expected = expected_for("empty.bin", b"");
    let t = MockTransport::serving(Vec::new());
    let done = block_on(dl.download(&t, &expected, &loc(), &opts())).unwrap();
    assert_eq!(fs::read(done.path).unwrap(), Vec::<u8>::new());
    assert!(t.requests().is_empty());
}
