//! Content route: `GET`/`HEAD` of `/Content/{xx}/{sha1}[.ext]` with `Range` support.
//!
//! The only identity accepted is a 40-digit SHA-1 (the digest clients receive from
//! `GetFileLocations`); `xx` must equal its last two digits, as in WSUS. The object is found
//! through the database, never by joining request text onto a filesystem path, and only
//! objects whose record is `available` with a matching on-disk length are served.
use rusqlite::OptionalExtension;

use super::message::{HttpRequestParts, HttpResponseParts, ResponseBody};
use crate::content::{ContentStore, ObjectId, RangeRequest, ServeOutcome, resolve_range};
use crate::storage::{Database, Result, hex_decode, hex_encode};

pub(crate) const CONTENT_PREFIX: &str = "/content/";

/// Parse the path below the `/Content/` prefix (matched case-insensitively by the router)
/// into a SHA-1 digest.
pub(crate) fn parse_content_path(path: &str) -> Option<[u8; 20]> {
    let rest = path.get(CONTENT_PREFIX.len()..)?;
    let (xx, name) = rest.split_once('/')?;
    if name.contains('/') || xx.len() != 2 {
        return None;
    }
    let stem = name.split('.').next()?;
    if stem.len() != 40 {
        return None;
    }
    let digest: [u8; 20] = hex_decode(stem)?.try_into().ok()?;
    let want = hex_encode(&digest[19..]);
    xx.eq_ignore_ascii_case(&want).then_some(digest)
}

/// Object with this SHA-1 whose record is available.
pub(crate) fn find_by_sha1(db: &Database, sha1: &[u8; 20]) -> Result<Option<ObjectId>> {
    let id: Option<String> = db.with_conn(|c| {
        Ok(c.query_row(
            "SELECT o.object_id FROM content_digests d JOIN content_objects o \
             ON o.object_id=d.object_id WHERE d.algorithm='sha1' AND d.digest=?1 \
             AND o.state='available' LIMIT 1",
            [sha1.as_slice()],
            |r| r.get(0),
        )
        .optional()?)
    })?;
    id.map(|s| ObjectId::parse(&s)).transpose()
}

fn text(status: u16) -> HttpResponseParts {
    HttpResponseParts::empty(status)
}

pub(crate) fn serve(
    db: &Database,
    store: &ContentStore,
    req: &HttpRequestParts,
) -> HttpResponseParts {
    let head = match req.method.as_str() {
        "GET" => false,
        "HEAD" => true,
        _ => return text(405).with("Allow", "GET, HEAD"),
    };
    let Some(sha1) = parse_content_path(&req.path) else {
        return text(404);
    };
    match serve_inner(db, store, req, &sha1, head) {
        Ok(r) => r,
        Err(_) => text(500),
    }
}

fn serve_inner(
    db: &Database,
    store: &ContentStore,
    req: &HttpRequestParts,
    sha1: &[u8; 20],
    head: bool,
) -> Result<HttpResponseParts> {
    let Some(id) = find_by_sha1(db, sha1)? else {
        return Ok(text(404));
    };
    let Some(info) = store.info(&id)? else {
        return Ok(text(404));
    };
    let etag = info.etag.clone();
    let validators =
        |r: HttpResponseParts| r.with("ETag", etag.clone()).with("Accept-Ranges", "bytes");
    if let Some(inm) = req.header("If-None-Match")
        && inm.split(',').any(|t| t.trim() == etag || t.trim() == "*")
    {
        return Ok(validators(text(304)));
    }
    let mut range = req.header("Range");
    if let Some(ir) = req.header("If-Range") {
        // Only a strong ETag comparison is supported; anything else means "send it all".
        if ir.trim() != etag {
            range = None;
        }
    }
    // Multiple ranges would need multipart/byteranges; RFC 9110 lets a server ignore Range.
    if let RangeRequest::Ranges(r) = resolve_range(range, info.size)
        && r.len() > 1
    {
        range = None;
    }
    let ctype = "application/octet-stream";
    Ok(match store.serve(&id, range)? {
        ServeOutcome::NotFound => text(404),
        ServeOutcome::Unsatisfiable { content_range, .. } => {
            validators(text(416)).with("Content-Range", content_range)
        }
        ServeOutcome::Full(reader) => {
            let len = reader.len();
            stream(validators(base(200, ctype, len)), reader, len, head)
        }
        ServeOutcome::Partial(mut parts) => {
            let (r, reader) = parts.remove(0);
            let len = reader.len();
            let resp =
                validators(base(206, ctype, len)).with("Content-Range", r.content_range(info.size));
            stream(resp, reader, len, head)
        }
    })
}

fn base(status: u16, ctype: &str, len: u64) -> HttpResponseParts {
    HttpResponseParts {
        status,
        headers: vec![
            ("Content-Type".into(), ctype.into()),
            ("Content-Length".into(), len.to_string()),
        ],
        body: ResponseBody::Empty,
    }
}

fn stream(
    mut resp: HttpResponseParts,
    reader: crate::content::ObjectReader,
    len: u64,
    head: bool,
) -> HttpResponseParts {
    if !head && len > 0 {
        resp.body = ResponseBody::Stream {
            reader: Box::new(reader),
            len,
        };
    }
    resp
}
