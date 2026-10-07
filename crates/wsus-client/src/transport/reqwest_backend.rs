//! Reqwest transport and Tokio timer, enabled by the `reqwest-async` feature.

use super::{
    BodySink, ErrorKind, Headers, HttpRequest, HttpResponse, Method, Phase, ResponseHead,
    RetryTimer, Transport, TransportError,
};
use std::time::Duration;

/// Reqwest HTTP adapter; requires a Tokio runtime during requests.
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Creates an adapter with the platform's configured TLS backend.
    pub fn new() -> Result<Self, TransportError> {
        reqwest::Client::builder()
            .build()
            .map(|client| Self { client })
            .map_err(map_error)
    }

    /// Uses an existing client, including its proxy and TLS configuration.
    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    async fn start(&self, request: HttpRequest) -> Result<reqwest::Response, TransportError> {
        let url = request.url.expose().to_owned();
        let mut builder = match request.method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url).body(request.body),
        }
        .timeout(request.timeout);
        for (name, value) in request.headers.iter() {
            builder = builder.header(name, value);
        }
        builder.send().await.map_err(map_error)
    }
}

fn map_error(error: reqwest::Error) -> TransportError {
    let error = error.without_url();
    if error.is_timeout() {
        TransportError::timeout()
    } else if error.is_connect() {
        TransportError::connect(&error.to_string())
    } else {
        TransportError::new(ErrorKind::Io, Phase::MaybeSent, &error.to_string())
    }
}

fn head_of(response: &reqwest::Response) -> ResponseHead {
    let mut headers = Headers::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            headers.append(name.as_str(), value);
        }
    }
    ResponseHead {
        status: response.status().as_u16(),
        headers,
    }
}

impl Transport for ReqwestTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let limit = request.max_response_bytes;
        let mut response = self.start(request).await?;
        let head = head_of(&response);
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_error)? {
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(TransportError::new(
                    ErrorKind::TooLarge,
                    Phase::MaybeSent,
                    "response body exceeds limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status: head.status,
            headers: head.headers,
            body,
        })
    }

    async fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> Result<ResponseHead, TransportError> {
        let mut response = self.start(request).await?;
        let head = head_of(&response);
        if sink.start(&head).map_err(|_| TransportError::aborted())? {
            while let Some(chunk) = response.chunk().await.map_err(map_error)? {
                sink.write(&chunk).map_err(|_| TransportError::aborted())?;
            }
        }
        Ok(head)
    }
}

/// Retry timer backed by Tokio's time driver.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioTimer;

impl RetryTimer for TokioTimer {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}
