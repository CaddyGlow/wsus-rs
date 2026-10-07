//! Header facts of the native content download (Delivery Optimization user
//! agent) from the lab WSUS, recorded 2026-10-04.
//!
//! Provenance: `docs/fixtures/wsus-m0-native/content-headers/` holds four
//! sanitized request/response HEADER pairs (no bodies) of the 216 range `GET`s
//! made by the Windows 11 25H2 client (Windows Update Agent 1507.2601.30012.0,
//! content fetched by `Microsoft-Delivery-Optimization/10.1`) against the
//! Windows Server 2025 10.0.26100 WSUS. See that README and inventory 9.4.
//!
//! These tests parse the retained headers with std only and pin the facts the
//! inventory records. They do not validate downloading from this project's
//! server and say nothing about any other build.

use std::path::PathBuf;

const MIB: u64 = 1_048_576;
const SETS: [&str; 4] = [
    "whole-file-single-range",
    "first-range-by-offset",
    "middle-range",
    "final-range",
];

fn headers(set: &str, f: &str) -> Vec<(String, String)> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/fixtures/wsus-m0-native/content-headers")
        .join(set)
        .join(f);
    let t = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    t.lines()
        .skip(1)
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect()
}

fn get<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// `bytes a-b` or `bytes=a-b` to `(a, b)`.
fn span(v: &str) -> (u64, u64) {
    let v = v.trim_start_matches("bytes").trim_start_matches([' ', '=']);
    let v = v.split('/').next().expect("span");
    let (a, b) = v.split_once('-').expect("dash");
    (a.parse().expect("start"), b.parse().expect("end"))
}

#[test]
fn request_shape_is_a_range_get_with_the_delivery_optimization_agent() {
    for s in SETS {
        let h = headers(s, "request.headers");
        assert_eq!(
            get(&h, "user-agent"),
            Some("Microsoft-Delivery-Optimization/10.1")
        );
        assert_eq!(get(&h, "connection"), Some("Keep-Alive"));
        assert_eq!(get(&h, "accept"), Some("*/*"));
        assert_eq!(get(&h, "content-length"), Some("0"));
        assert!(get(&h, "range").is_some_and(|r| r.starts_with("bytes=")));
        for absent in ["if-range", "if-match", "if-none-match", "if-modified-since"] {
            assert_eq!(get(&h, absent), None, "{s}: {absent}");
        }
    }
}

#[test]
fn every_response_is_206_with_an_exact_content_range() {
    for s in SETS {
        let req = headers(s, "request.headers");
        let rsp = headers(s, "response.headers");
        let (a, b) = span(get(&req, "range").expect("range"));
        let cr = get(&rsp, "content-range").expect("content-range");
        assert_eq!(span(cr), (a, b), "{s}: Content-Range echoes the request");
        let total: u64 = cr.rsplit('/').next().expect("total").parse().expect("n");
        assert!(b < total, "{s}");
        assert_eq!(
            get(&rsp, "content-length").map(|v| v.parse::<u64>().expect("n")),
            Some(b - a + 1),
            "{s}: Content-Length is the range length"
        );
        assert_eq!(get(&rsp, "accept-ranges"), Some("bytes"));
        assert_eq!(get(&rsp, "content-type"), Some("application/octet-stream"));
        assert_eq!(get(&rsp, "cache-control"), None);
        assert_eq!(get(&rsp, "content-encoding"), None);
        assert!(get(&rsp, "etag").is_some_and(|e| e.starts_with('"') && e.ends_with(":0\"")));
        assert!(get(&rsp, "last-modified").is_some());
    }
}

#[test]
fn ranges_are_one_mebibyte_aligned_and_the_last_ends_at_size_minus_one() {
    let first = headers("first-range-by-offset", "response.headers");
    assert_eq!(
        span(get(&first, "content-range").expect("cr")),
        (0, MIB - 1)
    );
    let middle = headers("middle-range", "response.headers");
    let (a, b) = span(get(&middle, "content-range").expect("cr"));
    assert_eq!((a % MIB, b - a + 1), (0, MIB));
    let last = headers("final-range", "response.headers");
    let cr = get(&last, "content-range").expect("cr");
    let (a, b) = span(cr);
    let total: u64 = cr.rsplit('/').next().expect("t").parse().expect("n");
    assert_eq!((a, b, total), (195 * MIB, total - 1, 204_745_168));
    assert!(b - a + 1 < MIB, "the last range is the short remainder");
    // Files smaller than 1 MiB are requested whole, as one exact range.
    let small = headers("whole-file-single-range", "response.headers");
    assert_eq!(get(&small, "content-range"), Some("bytes 0-918943/918944"));
}

#[test]
fn validators_are_stable_across_ranges_of_one_file() {
    let a = headers("first-range-by-offset", "response.headers");
    let b = headers("middle-range", "response.headers");
    let c = headers("final-range", "response.headers");
    for n in ["etag", "last-modified"] {
        assert_eq!(get(&a, n), get(&b, n));
        assert_eq!(get(&b, n), get(&c, n));
    }
}
