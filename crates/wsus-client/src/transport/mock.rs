//! In-memory transport for tests: scripted or handler-driven responses plus a
//! request log.

use super::{
    BodySink, Headers, HttpRequest, HttpResponse, ResponseHead, Transport, TransportError,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// One scripted outcome.
#[derive(Debug, Clone)]
pub enum MockStep {
    /// Complete response.
    Respond(HttpResponse),
    /// Failure before a response.
    Fail(TransportError),
    /// Streams the response head and body, then fails with an I/O error, as a
    /// dropped connection would.
    Interrupt(HttpResponse),
}

type Handler = dyn Fn(&HttpRequest) -> MockStep + Send + Sync;

/// Records requests and answers them from a script or a handler.
#[derive(Clone)]
pub struct MockTransport {
    handler: Arc<Handler>,
    log: Arc<Mutex<Vec<HttpRequest>>>,
}

impl MockTransport {
    /// Answers every request with `handler`.
    pub fn with_handler(
        handler: impl Fn(&HttpRequest) -> MockStep + Send + Sync + 'static,
    ) -> Self {
        Self {
            handler: Arc::new(handler),
            log: Arc::default(),
        }
    }

    /// Answers requests in order; an exhausted script yields a 599 response.
    pub fn scripted(steps: Vec<MockStep>) -> Self {
        let queue = Mutex::new(VecDeque::from(steps));
        Self::with_handler(move |_| {
            queue
                .lock()
                .expect("script lock")
                .pop_front()
                .unwrap_or_else(|| {
                    MockStep::Respond(HttpResponse::new(599, b"script exhausted".to_vec()))
                })
        })
    }

    /// Serves `body` correctly: 200 for plain GET, 206 with `Content-Range`
    /// for `Range: bytes=N-[M]`, 416 when unsatisfiable.
    pub fn serving(body: Vec<u8>) -> Self {
        Self::with_handler(move |request| MockStep::Respond(serve(&body, request)))
    }

    /// Copies of all requests received so far (including `Range` headers).
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.log.lock().expect("log lock").clone()
    }

    fn step(&self, request: &HttpRequest) -> MockStep {
        self.log.lock().expect("log lock").push(request.clone());
        (self.handler)(request)
    }
}

impl std::fmt::Debug for MockTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockTransport").finish_non_exhaustive()
    }
}

fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()))
}

fn serve(body: &[u8], request: &HttpRequest) -> HttpResponse {
    let total = body.len() as u64;
    let Some((start, end)) = request.headers.get("range").and_then(parse_range) else {
        let mut response = HttpResponse::new(200, body.to_vec());
        response.headers.set("Content-Length", total.to_string());
        return response;
    };
    if start >= total {
        let mut response = HttpResponse::new(416, Vec::new());
        response
            .headers
            .set("Content-Range", format!("bytes */{total}"));
        return response;
    }
    let end = end.map_or(total - 1, |e| e.min(total - 1));
    let slice = body[start as usize..=end as usize].to_vec();
    let mut response = HttpResponse::new(206, slice);
    response
        .headers
        .set("Content-Range", format!("bytes {start}-{end}/{total}"));
    response
        .headers
        .set("Content-Length", (end - start + 1).to_string());
    response
}

impl Transport for MockTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let limit = request.max_response_bytes;
        match self.step(&request) {
            MockStep::Respond(response) => {
                if response.body.len() > limit {
                    Err(TransportError::new(
                        super::ErrorKind::TooLarge,
                        super::Phase::MaybeSent,
                        "response body exceeds limit",
                    ))
                } else {
                    Ok(response)
                }
            }
            MockStep::Fail(error) => Err(error),
            MockStep::Interrupt(_) => Err(TransportError::io("connection reset")),
        }
    }

    async fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> Result<ResponseHead, TransportError> {
        let (response, interrupted) = match self.step(&request) {
            MockStep::Respond(response) => (response, false),
            MockStep::Interrupt(response) => (response, true),
            MockStep::Fail(error) => return Err(error),
        };
        let head = ResponseHead {
            status: response.status,
            headers: Headers::clone(&response.headers),
        };
        if sink.start(&head).map_err(|_| TransportError::aborted())? {
            for chunk in response.body.chunks(1000) {
                sink.write(chunk).map_err(|_| TransportError::aborted())?;
            }
        }
        if interrupted {
            return Err(TransportError::io("connection reset"));
        }
        Ok(head)
    }
}
