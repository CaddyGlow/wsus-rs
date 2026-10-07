//! HTTP byte-range resolution as a pure function (RFC 9110 section 14).

/// Inclusive byte range within an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// `Content-Range` header value for a 206 response.
    pub fn content_range(&self, total: u64) -> String {
        format!("bytes {}-{}/{}", self.start, self.end, total)
    }
}

/// `Content-Range` value for a 416 response.
pub fn unsatisfied_content_range(total: u64) -> String {
    format!("bytes */{total}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeRequest {
    /// Absent, non-`bytes`, malformed, or excessive: serve the full object with 200.
    Full,
    /// Well-formed but nothing overlaps the object: respond 416.
    Unsatisfiable,
    /// One or more satisfiable ranges, in request order: respond 206.
    Ranges(Vec<ByteRange>),
}

const MAX_RANGES: usize = 16;

/// Resolve a `Range` header value against an object of `size` bytes.
pub fn resolve_range(header: Option<&str>, size: u64) -> RangeRequest {
    let Some(header) = header else {
        return RangeRequest::Full;
    };
    let Some((unit, specs)) = header.split_once('=') else {
        return RangeRequest::Full;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return RangeRequest::Full;
    }
    let mut out = Vec::new();
    let mut seen = 0usize;
    for spec in specs.split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        seen += 1;
        if seen > MAX_RANGES {
            return RangeRequest::Full;
        }
        let Some((a, b)) = spec.split_once('-') else {
            return RangeRequest::Full;
        };
        let (a, b) = (a.trim(), b.trim());
        match (parse_num(a), parse_num(b)) {
            (Some(start), Some(end)) => {
                if start > end {
                    return RangeRequest::Full;
                }
                if start < size {
                    out.push(ByteRange {
                        start,
                        end: end.min(size - 1),
                    });
                }
            }
            (Some(start), None) if b.is_empty() => {
                if start < size {
                    out.push(ByteRange {
                        start,
                        end: size - 1,
                    });
                }
            }
            (None, Some(n)) if a.is_empty() => {
                if n > 0 && size > 0 {
                    out.push(ByteRange {
                        start: size.saturating_sub(n),
                        end: size - 1,
                    });
                }
            }
            _ => return RangeRequest::Full,
        }
    }
    if seen == 0 {
        return RangeRequest::Full;
    }
    if out.is_empty() {
        RangeRequest::Unsatisfiable
    } else {
        RangeRequest::Ranges(out)
    }
}

fn parse_num(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Overflowing values are treated as "very large", not as a syntax error.
    Some(s.parse::<u64>().unwrap_or(u64::MAX))
}
