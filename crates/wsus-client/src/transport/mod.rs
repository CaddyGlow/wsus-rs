//! Backend-neutral HTTP transport for SOAP POST and ranged GET operations.
//!
//! Implement [`Transport`] (and [`RetryTimer`]) for another backend or runtime.
//! Futures are `Send`, no tasks are spawned, and dropping a future cancels the
//! request. The traits use static dispatch and are not meant for `dyn` use.

pub mod mock;
pub mod redact;
pub mod retry;

#[cfg(feature = "reqwest-async")]
pub mod reqwest_backend;

pub use redact::{
    InvalidUrl, Secret, SecretBytes, SensitiveUrl, is_sensitive_header, redact_header_value,
    redact_url, scrub_urls,
};
pub use retry::{Failure, Idempotence, ImmediateTimer, RetryPolicy, RetryTimer, send_with_retry};

use std::{fmt, future::Future, io, sync::Arc, time::Duration};

/// HTTP method; only the operations WSUS needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    /// Canonical upper-case token.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// Ordered, case-insensitive header list. `Debug` redacts sensitive values.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// Empty header list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a header, keeping any existing ones with the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }

    /// Replaces all headers with this name.
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.0.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.0.push((name.to_owned(), value.into()));
    }

    /// First value for a name, compared case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Iterates over all headers in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Number of headers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are no headers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (name, value) in &self.0 {
            map.entry(name, &redact_header_value(name, value));
        }
        map.finish()
    }
}

/// Default limit for buffered response bodies.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A fully specified HTTP request. `Debug` shows neither the URL path/query,
/// sensitive header values nor the body contents.
#[derive(Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: SensitiveUrl,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// Maximum duration for the whole request including the body.
    pub timeout: Duration,
    /// Limit for buffered [`Transport::send`] responses; streaming is unbounded.
    pub max_response_bytes: usize,
    /// Whether replaying the request is safe. See [`RetryPolicy`].
    pub idempotence: Idempotence,
}

impl HttpRequest {
    /// GET request, idempotent by definition.
    pub fn get(url: SensitiveUrl, timeout: Duration) -> Self {
        Self {
            method: Method::Get,
            url,
            headers: Headers::new(),
            body: Vec::new(),
            timeout,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            idempotence: Idempotence::Idempotent,
        }
    }

    /// SOAP POST. Non-idempotent unless the caller opts in with
    /// [`HttpRequest::idempotent`].
    pub fn soap_post(
        url: SensitiveUrl,
        soap_action: &str,
        content_type: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Self {
        let mut headers = Headers::new();
        headers.set("Content-Type", content_type);
        headers.set("SOAPAction", soap_action);
        Self {
            method: Method::Post,
            url,
            headers,
            body,
            timeout,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            idempotence: Idempotence::NonIdempotent,
        }
    }

    /// Marks the operation as safe to replay.
    pub fn idempotent(mut self) -> Self {
        self.idempotence = Idempotence::Idempotent;
        self
    }

    /// Sets `Range: bytes=start-` or `bytes=start-end` (inclusive).
    pub fn with_range(mut self, start: u64, end_inclusive: Option<u64>) -> Self {
        let value = match end_inclusive {
            Some(end) => format!("bytes={start}-{end}"),
            None => format!("bytes={start}-"),
        };
        self.headers.set("Range", value);
        self
    }

    /// Adds a header (builder style).
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.set(name, value);
        self
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .field("idempotence", &self.idempotence)
            .finish()
    }
}

/// Status and headers of a response.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Headers,
}

impl fmt::Debug for ResponseHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseHead")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish()
    }
}

/// A buffered response. Unsuccessful statuses are returned as responses, not
/// errors. `Debug` shows only the body length.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Builds a response without headers.
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body,
        }
    }

    /// Status and headers.
    pub fn head(&self) -> ResponseHead {
        ResponseHead {
            status: self.status,
            headers: self.headers.clone(),
        }
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Failure category of a transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Connect,
    Timeout,
    Io,
    Tls,
    TooLarge,
    /// The [`BodySink`] refused the body; not a network failure.
    Aborted,
    Other,
}

/// Whether the server may have received the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Failed before any request bytes were sent (DNS, connect, TLS).
    NotSent,
    /// The request may have reached the server.
    MaybeSent,
}

/// Failure to obtain a complete response. The message is scrubbed of URLs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("transport {kind:?} failure ({phase:?}): {message}")]
pub struct TransportError {
    pub kind: ErrorKind,
    pub phase: Phase,
    message: String,
}

impl TransportError {
    /// Creates an error; any URL in `message` is redacted.
    pub fn new(kind: ErrorKind, phase: Phase, message: &str) -> Self {
        Self {
            kind,
            phase,
            message: scrub_urls(message),
        }
    }

    /// Connection establishment failure; the request was never sent.
    pub fn connect(message: &str) -> Self {
        Self::new(ErrorKind::Connect, Phase::NotSent, message)
    }

    /// Timeout; the request may have been processed.
    pub fn timeout() -> Self {
        Self::new(ErrorKind::Timeout, Phase::MaybeSent, "request timed out")
    }

    /// I/O failure after the request may have been sent.
    pub fn io(message: &str) -> Self {
        Self::new(ErrorKind::Io, Phase::MaybeSent, message)
    }

    /// Body sink aborted the transfer.
    pub fn aborted() -> Self {
        Self::new(ErrorKind::Aborted, Phase::MaybeSent, "aborted by body sink")
    }

    /// Scrubbed message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Receives a streamed response body synchronously, in order.
pub trait BodySink {
    /// Called once with the response head. Return `Ok(false)` to skip the body.
    fn start(&mut self, head: &ResponseHead) -> io::Result<bool>;
    /// Called for each body chunk; an error aborts the transfer.
    fn write(&mut self, chunk: &[u8]) -> io::Result<()>;
}

/// Chunk size used when a buffered response is replayed into a sink.
pub const SINK_CHUNK: usize = 64 * 1024;

/// Asynchronous HTTP transport.
///
/// Implementations must honor [`HttpRequest::timeout`] and return HTTP error
/// statuses as responses. They must not follow redirects that change a signed
/// request's meaning silently, and must never include URLs in error messages
/// (use [`TransportError::new`], which scrubs them).
pub trait Transport: Sync {
    /// Sends a request and buffers the body, up to `max_response_bytes`.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, TransportError>> + Send;

    /// Sends a request and streams the body into `sink`. The default buffers
    /// via [`Transport::send`]; backends should override it to avoid buffering.
    fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> impl Future<Output = Result<ResponseHead, TransportError>> + Send + 'a {
        async move {
            let mut request = request;
            request.max_response_bytes = usize::MAX;
            let response = self.send(request).await?;
            let head = response.head();
            if sink.start(&head).map_err(|_| TransportError::aborted())? {
                for chunk in response.body.chunks(SINK_CHUNK) {
                    sink.write(chunk).map_err(|_| TransportError::aborted())?;
                }
            }
            Ok(head)
        }
    }
}

impl<T: Transport + Send + ?Sized> Transport for Arc<T> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.as_ref().send(request).await
    }

    fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> impl Future<Output = Result<ResponseHead, TransportError>> + Send + 'a {
        self.as_ref().send_streaming(request, sink)
    }
}

impl<T: Transport + ?Sized> Transport for &T {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        (*self).send(request).await
    }

    fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> impl Future<Output = Result<ResponseHead, TransportError>> + Send + 'a {
        (*self).send_streaming(request, sink)
    }
}
