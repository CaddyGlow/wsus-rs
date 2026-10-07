//! Framework-neutral HTTP request and response values.
use std::io::Read;

/// An HTTP request reduced to what the handlers need.
#[derive(Debug, Clone, Default)]
pub struct HttpRequestParts {
    /// Method, as received (`GET`, `POST`, ...); compared case-sensitively per RFC 9110.
    pub method: String,
    /// Absolute path without the query.
    pub path: String,
    pub query: Option<String>,
    /// Header name/value pairs; names are matched case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Entire request body (the transport enforces its own cap before buffering).
    pub body: Vec<u8>,
}

impl HttpRequestParts {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            ..Self::default()
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// First header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Response body.
pub enum ResponseBody {
    Empty,
    Bytes(Vec<u8>),
    /// Streamed from a blocking reader; `len` is the exact `Content-Length`. Dropping the
    /// reader (client cancellation) releases the content lease.
    Stream {
        reader: Box<dyn Read + Send>,
        len: u64,
    },
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Bytes(b) => write!(f, "Bytes({})", b.len()),
            Self::Stream { len, .. } => write!(f, "Stream({len})"),
        }
    }
}

/// An HTTP response. `Content-Length` is included in `headers` for every body kind.
#[derive(Debug)]
pub struct HttpResponseParts {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: ResponseBody,
}

impl HttpResponseParts {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn empty(status: u16) -> Self {
        Self {
            status,
            headers: vec![("Content-Length".into(), "0".into())],
            body: ResponseBody::Empty,
        }
    }

    pub(crate) fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![
                ("Content-Type".into(), content_type.to_owned()),
                ("Content-Length".into(), body.len().to_string()),
                ("Cache-Control".into(), "private, max-age=0".into()),
            ],
            body: ResponseBody::Bytes(body),
        }
    }

    pub(crate) fn with(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// Collect the body into memory (testing and small responses).
    pub fn into_bytes(self) -> std::io::Result<Vec<u8>> {
        match self.body {
            ResponseBody::Empty => Ok(Vec::new()),
            ResponseBody::Bytes(b) => Ok(b),
            ResponseBody::Stream { mut reader, .. } => {
                let mut v = Vec::new();
                reader.read_to_end(&mut v)?;
                Ok(v)
            }
        }
    }
}
