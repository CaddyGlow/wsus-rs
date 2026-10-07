//! `Content-Encoding: xpress` for the SOAP services (MS-WUSP 2.1, 2.1.1).
//!
//! Evidence: the block framing is shared with the client through
//! `wsus_protocol::xpress` (Observed from the real WSUS 10.0.26100: it answers
//! clients that send `Accept-Encoding: xpress` with Xpress bodies). That a
//! native Windows Update Agent accepts the bodies THIS server produces is NOT
//! verified until a native client has been pointed at it. Request bodies with
//! `Content-Encoding: xpress` are accepted per the specification wording; the
//! native client was observed sending uncompressed requests, so that path is
//! exercised only by this crate's tests.
use std::borrow::Cow;

use wsus_protocol::xpress::{self, Limits};

use super::message::{HttpRequestParts, HttpResponseParts, ResponseBody};

/// Responses smaller than this are not worth compressing (the 8-byte block
/// header and the per-block flag words eat the gain).
pub(crate) const MIN_COMPRESS_BYTES: usize = 256;

/// True when the request's `Accept-Encoding` lists `xpress` with a non-zero
/// quality. `*` is deliberately not treated as consent: Xpress is a niche
/// coding and an unaware client that sends `*` would not be able to decode it.
pub(crate) fn accepts_xpress(req: &HttpRequestParts) -> bool {
    req.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        .flat_map(|(_, v)| v.split(','))
        .any(|item| {
            let mut parts = item.split(';');
            let token = parts.next().unwrap_or("").trim();
            if !token.eq_ignore_ascii_case("xpress") {
                return false;
            }
            parts
                .filter_map(|p| {
                    p.trim()
                        .strip_prefix("q=")
                        .or_else(|| p.trim().strip_prefix("Q="))
                })
                .all(|q| q.trim().parse::<f32>().map(|q| q > 0.0).unwrap_or(false))
        })
}

/// Outcome of inspecting a request body's `Content-Encoding`.
pub(crate) enum RequestEncoding<'a> {
    /// Body unchanged (or decoded in place).
    Ok(Cow<'a, [u8]>),
    /// A coding other than `identity` or `xpress`.
    Unsupported,
    /// Xpress body that is malformed or decodes beyond the bound.
    Malformed,
}

/// Applies the request `Content-Encoding`. Decoded size is bounded by
/// `max_bytes`.
pub(crate) fn decode_request_body(req: &HttpRequestParts, max_bytes: usize) -> RequestEncoding<'_> {
    match req.header("Content-Encoding").map(str::trim) {
        None | Some("") => RequestEncoding::Ok(Cow::Borrowed(&req.body)),
        Some(v) if v.eq_ignore_ascii_case("identity") => {
            RequestEncoding::Ok(Cow::Borrowed(&req.body))
        }
        Some(v) if v.eq_ignore_ascii_case("xpress") => {
            match xpress::decode(&req.body, &Limits::with_max_total(max_bytes)) {
                Ok(body) => RequestEncoding::Ok(Cow::Owned(body)),
                Err(_) => RequestEncoding::Malformed,
            }
        }
        Some(_) => RequestEncoding::Unsupported,
    }
}

/// Marks a SOAP response as varying on `Accept-Encoding` and, when the client
/// accepted Xpress, compresses a large enough in-memory body. Replaces
/// `Content-Length`; leaves bodies already encoded, streamed bodies and
/// bodies Xpress would not shrink alone.
pub(crate) fn encode_response(resp: &mut HttpResponseParts, client_accepts: bool) {
    if !resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("vary"))
    {
        resp.headers.push(("Vary".into(), "Accept-Encoding".into()));
    }
    if !client_accepts
        || resp
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
    {
        return;
    }
    let ResponseBody::Bytes(body) = &resp.body else {
        return;
    };
    if body.len() < MIN_COMPRESS_BYTES {
        return;
    }
    let Ok(encoded) = xpress::encode(body) else {
        return;
    };
    if encoded.len() >= body.len() {
        return;
    }
    for (k, v) in resp.headers.iter_mut() {
        if k.eq_ignore_ascii_case("content-length") {
            *v = encoded.len().to_string();
        }
    }
    resp.headers
        .push(("Content-Encoding".into(), "xpress".into()));
    resp.body = ResponseBody::Bytes(encoded);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(value: &str) -> HttpRequestParts {
        HttpRequestParts::new("POST", "/").with_header("Accept-Encoding", value)
    }

    #[test]
    fn accept_encoding_parsing() {
        assert!(accepts_xpress(&req("xpress")));
        assert!(accepts_xpress(&req("gzip, XPRESS")));
        assert!(accepts_xpress(&req("xpress;q=0.5")));
        assert!(!accepts_xpress(&req("xpress;q=0")));
        assert!(!accepts_xpress(&req("identity")));
        assert!(!accepts_xpress(&req("gzip, deflate")));
        assert!(!accepts_xpress(&req("*")));
        assert!(!accepts_xpress(&req("xpressy")));
        assert!(!accepts_xpress(&HttpRequestParts::new("POST", "/")));
    }
}
