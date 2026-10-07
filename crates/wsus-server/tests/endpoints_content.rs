//! Content route: identity validation, HEAD, ranges and validators.
mod endpoints_common;
use endpoints_common::*;

use wsus_server::endpoints::{HttpRequestParts, ResponseBody};
use wsus_server::storage::hex_encode;

const DATA: &[u8] = b"0123456789abcdefghij"; // 20 bytes

fn path_for(data: &[u8], ext: &str) -> String {
    let hex = hex_encode(&sha1_of(data)).to_ascii_uppercase();
    format!("/Content/{}/{hex}{ext}", &hex[hex.len() - 2..])
}

fn env_with_content() -> (Env, String) {
    let env = setup();
    put_content(&env, "a.cab", DATA);
    let p = path_for(DATA, ".cab");
    (env, p)
}

fn get_range(env: &Env, path: &str, range: &str) -> wsus_server::endpoints::HttpResponseParts {
    env.server
        .handle(HttpRequestParts::new("GET", path).with_header("Range", range))
}

#[test]
fn full_get_and_head_agree_on_headers() {
    let (env, p) = env_with_content();
    let r = env.get(&p);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("Content-Length"), Some("20"));
    assert_eq!(r.header("Accept-Ranges"), Some("bytes"));
    let etag = r.header("ETag").unwrap().to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    assert_eq!(r.into_bytes().unwrap(), DATA);

    let h = env.server.handle(HttpRequestParts::new("HEAD", &p));
    assert_eq!(h.status, 200);
    assert_eq!(h.header("Content-Length"), Some("20"));
    assert_eq!(h.header("ETag"), Some(etag.as_str()));
    assert!(matches!(h.body, ResponseBody::Empty));
}

#[test]
fn extension_and_case_of_the_route_are_irrelevant_to_identity() {
    let (env, p) = env_with_content();
    for variant in [
        path_for(DATA, ""),
        path_for(DATA, ".exe"),
        p.to_ascii_lowercase().replace("/content/", "/CONTENT/"),
        p.replace("/Content/", "/content/"),
    ] {
        assert_eq!(env.get(&variant).status, 200, "{variant}");
    }
}

#[test]
fn single_ranges() {
    let (env, p) = env_with_content();
    let cases: &[(&str, u16, &str, &[u8])] = &[
        ("bytes=0-4", 206, "bytes 0-4/20", b"01234"),
        ("bytes=5-", 206, "bytes 5-19/20", b"56789abcdefghij"),
        ("bytes=-5", 206, "bytes 15-19/20", b"fghij"),
        ("bytes=18-100", 206, "bytes 18-19/20", b"ij"),
        ("bytes=19-19", 206, "bytes 19-19/20", b"j"),
        ("bytes=0-0", 206, "bytes 0-0/20", b"0"),
        ("bytes=-100", 206, "bytes 0-19/20", DATA),
    ];
    for (hdr, status, cr, body) in cases {
        let r = get_range(&env, &p, hdr);
        assert_eq!(r.status, *status, "{hdr}");
        assert_eq!(r.header("Content-Range"), Some(*cr), "{hdr}");
        assert_eq!(
            r.header("Content-Length"),
            Some(body.len().to_string().as_str()),
            "{hdr}"
        );
        assert_eq!(r.into_bytes().unwrap(), *body, "{hdr}");
    }
}

#[test]
fn unsatisfiable_ranges_get_416_with_content_range() {
    let (env, p) = env_with_content();
    for hdr in ["bytes=20-", "bytes=20-30", "bytes=100-", "bytes=-0"] {
        let r = get_range(&env, &p, hdr);
        assert_eq!(r.status, 416, "{hdr}");
        assert_eq!(r.header("Content-Range"), Some("bytes */20"), "{hdr}");
        assert!(r.into_bytes().unwrap().is_empty());
    }
}

#[test]
fn malformed_unknown_unit_and_multi_range_fall_back_to_the_whole_object() {
    let (env, p) = env_with_content();
    for hdr in [
        "bytes=5-2",
        "bytes=abc",
        "items=0-3",
        "bytes=",
        "bytes=0-1,5-6",
        "garbage",
    ] {
        let r = get_range(&env, &p, hdr);
        assert_eq!(r.status, 200, "{hdr}");
        assert!(r.header("Content-Range").is_none());
        assert_eq!(r.into_bytes().unwrap(), DATA, "{hdr}");
    }
}

#[test]
fn head_with_range_reports_the_partial_headers_without_a_body() {
    let (env, p) = env_with_content();
    let h = env
        .server
        .handle(HttpRequestParts::new("HEAD", &p).with_header("Range", "bytes=2-4"));
    assert_eq!(h.status, 206);
    assert_eq!(h.header("Content-Length"), Some("3"));
    assert_eq!(h.header("Content-Range"), Some("bytes 2-4/20"));
    assert!(matches!(h.body, ResponseBody::Empty));
}

#[test]
fn conditional_requests() {
    let (env, p) = env_with_content();
    let etag = env.get(&p).header("ETag").unwrap().to_owned();
    let r = env
        .server
        .handle(HttpRequestParts::new("GET", &p).with_header("If-None-Match", &etag));
    assert_eq!(r.status, 304);
    assert!(r.into_bytes().unwrap().is_empty());
    // If-Range with the current validator honours the range, a stale one sends it all.
    let ok = env.server.handle(
        HttpRequestParts::new("GET", &p)
            .with_header("Range", "bytes=0-1")
            .with_header("If-Range", &etag),
    );
    assert_eq!(ok.status, 206);
    let stale = env.server.handle(
        HttpRequestParts::new("GET", &p)
            .with_header("Range", "bytes=0-1")
            .with_header("If-Range", "\"other\""),
    );
    assert_eq!(stale.status, 200);
    assert_eq!(stale.into_bytes().unwrap(), DATA);
}

#[test]
fn empty_object() {
    let env = setup();
    put_content(&env, "empty.bin", b"");
    let p = path_for(b"", ".bin");
    let r = env.get(&p);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("Content-Length"), Some("0"));
    assert!(r.into_bytes().unwrap().is_empty());
    assert_eq!(get_range(&env, &p, "bytes=0-").status, 416);
}

#[test]
fn only_validated_identities_resolve() {
    let (env, p) = env_with_content();
    let hex = hex_encode(&sha1_of(DATA)).to_ascii_uppercase();
    let wrong_xx = format!("/Content/00/{hex}.cab");
    let bad = [
        wrong_xx.as_str(),
        "/Content/",
        "/Content/ab",
        "/Content/ab/",
        "/Content/ab/xyz",
        "/Content/../etc/passwd",
        "/Content/ab/../../etc/passwd",
        "/Content/%2e%2e/%2e%2e/x",
        "/Content/zz/ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "/Content/ab/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB.cab", // unknown digest
        "/Content/ab/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/extra",
        "/Content//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    ];
    for b in bad {
        assert_eq!(env.get(b).status, 404, "{b}");
    }
    // Nothing outside the route resolves either.
    assert_eq!(env.get("/other").status, 404);
    // Methods other than GET/HEAD are refused with Allow.
    let post = env.server.handle(HttpRequestParts::new("POST", &p));
    assert_eq!(post.status, 405);
    assert_eq!(post.header("Allow"), Some("GET, HEAD"));
    assert_eq!(env.get(&p).status, 200);
}

#[test]
fn objects_that_are_not_verified_available_are_not_served() {
    let (env, p) = env_with_content();
    assert_eq!(env.get(&p).status, 200);
    // Remove the object file behind the store's back: the length check refuses it.
    let hex = hex_encode(&<sha2::Sha256 as sha2::Digest>::digest(DATA));
    let path = env
        .dir
        .path()
        .join("content/objects")
        .join(&hex[..2])
        .join(&hex[2..4])
        .join(&hex);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(env.get(&p).status, 404);
}

#[test]
fn dropping_a_streamed_body_releases_the_lease() {
    let (env, p) = env_with_content();
    let r = env.get(&p);
    assert!(matches!(r.body, ResponseBody::Stream { .. }));
    drop(r);
    // GC can now remove it (a held lease would be reported as skipped).
    let report = env.content.gc(std::time::Duration::from_secs(0)).unwrap();
    assert!(report.skipped_leased.is_empty());
}
