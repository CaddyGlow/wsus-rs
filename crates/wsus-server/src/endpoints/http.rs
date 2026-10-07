//! axum binding (feature `http`): adapts the neutral [`WsusServer`] to hyper.
//!
//! This is deliberately thin. It buffers at most `max_request_bytes` of request body,
//! runs [`WsusServer::handle`] on a blocking thread (the isolated blocking boundary for the
//! synchronous repositories), and streams content bodies from a blocking reader through a
//! small channel so a slow or cancelled client never holds a runtime worker. When the
//! client disconnects, the channel closes, the reader is dropped and its content lease is
//! released.
//!
//! Plain HTTP only. WSUS clients use HTTP on 8530 by default; terminate TLS in front of
//! this service or add a TLS acceptor around [`router`] when 8531 is required.
use std::io::Read;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use futures_util::stream;

use super::{HttpRequestParts, HttpResponseParts, ResponseBody, WsusServer};

const CHUNK: usize = 64 * 1024;

/// A neutral request handler the axum binding can drive: [`WsusServer`] and the MS-WSUSSS
/// surfaces of [`super::wsusss::UpstreamServer`].
pub trait HttpService: Clone + Send + Sync + 'static {
    /// Largest request body the transport buffers.
    fn max_request_bytes(&self) -> usize;
    /// Handle one request. **Blocking** (the binding runs it on a blocking thread).
    fn handle(&self, req: HttpRequestParts) -> HttpResponseParts;
    /// Response for a body that exceeded [`Self::max_request_bytes`].
    fn too_large(&self, req: &HttpRequestParts) -> HttpResponseParts;
    /// Response for an unexpected failure outside the handler.
    fn internal_error(&self) -> HttpResponseParts;
}

impl HttpService for WsusServer {
    fn max_request_bytes(&self) -> usize {
        self.config().max_request_bytes
    }
    fn handle(&self, req: HttpRequestParts) -> HttpResponseParts {
        WsusServer::handle(self, req)
    }
    fn too_large(&self, req: &HttpRequestParts) -> HttpResponseParts {
        WsusServer::too_large(self, req)
    }
    fn internal_error(&self) -> HttpResponseParts {
        WsusServer::internal_error(self)
    }
}

/// A router that sends every request to the WSUS handler.
pub fn router<S: HttpService>(server: S) -> Router {
    Router::new().fallback(handle::<S>).with_state(server)
}

/// Serve on `listener` until the future is dropped.
pub async fn serve<S: HttpService>(
    listener: tokio::net::TcpListener,
    server: S,
) -> std::io::Result<()> {
    axum::serve(listener, router(server)).await
}

async fn handle<S: HttpService>(State(server): State<S>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let limit = server.max_request_bytes();
    let declared = parts
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let neutral = |body: Vec<u8>| HttpRequestParts {
        method: parts.method.as_str().to_owned(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().map(str::to_owned),
        headers: parts
            .headers
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect(),
        body,
    };
    let oversized = declared.is_some_and(|n| n > limit);
    let bytes = if oversized {
        None
    } else {
        axum::body::to_bytes(body, limit).await.ok()
    };
    let resp = match bytes {
        Some(b) => {
            let req = neutral(b.to_vec());
            let s = server.clone();
            match tokio::task::spawn_blocking(move || HttpService::handle(&s, req)).await {
                Ok(r) => r,
                Err(_) => server.internal_error(),
            }
        }
        None => server.too_large(&neutral(Vec::new())),
    };
    into_response(resp)
}

fn into_response(r: HttpResponseParts) -> Response {
    let mut b = Response::builder()
        .status(StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (k, v) in &r.headers {
        if let (Ok(k), Ok(v)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            b = b.header(k, v);
        }
    }
    let body = match r.body {
        ResponseBody::Empty => Body::empty(),
        ResponseBody::Bytes(v) => Body::from(v),
        ResponseBody::Stream { reader, .. } => Body::from_stream(chunks(reader)),
    };
    b.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .expect("static response")
    })
}

fn chunks(
    mut reader: Box<dyn Read + Send>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .blocking_send(Ok(Bytes::copy_from_slice(&buf[..n])))
                        .is_err()
                    {
                        break; // client went away; dropping `reader` releases the lease
                    }
                }
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });
    stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|i| (i, rx)) })
}
