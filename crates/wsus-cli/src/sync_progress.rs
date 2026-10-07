//! Transfer counters without recording request URLs, cookies or body contents.

use std::{
    io,
    sync::Mutex,
    time::{Duration, Instant},
};
use wsus_client::transport::{
    BodySink, HttpRequest, HttpResponse, ResponseHead, Transport, TransportError,
};

struct Counters {
    started: Instant,
    last: Instant,
    bytes: u64,
    responses: u64,
}

/// Wraps the upstream transport; all progress goes to stderr.
pub struct ProgressTransport<T> {
    inner: T,
    enabled: bool,
    counters: Mutex<Counters>,
}

impl<T> ProgressTransport<T> {
    pub fn new(inner: T, enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            inner,
            enabled,
            counters: Mutex::new(Counters {
                started: now,
                last: now,
                bytes: 0,
                responses: 0,
            }),
        }
    }

    fn record(&self, bytes: usize, completed: bool) {
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        c.bytes = c.bytes.saturating_add(bytes as u64);
        c.responses += u64::from(completed);
        if self.enabled && (c.last.elapsed() >= Duration::from_secs(1) || completed) {
            let seconds = c.started.elapsed().as_secs_f64().max(0.001);
            eprintln!(
                "sync: {} responses, {:.2} MiB received, {:.2} MiB/s average, {:.1}s elapsed",
                c.responses,
                c.bytes as f64 / 1048576.0,
                c.bytes as f64 / 1048576.0 / seconds,
                seconds
            );
            c.last = Instant::now();
        }
    }
}

struct CountingSink<'a, T> {
    sink: &'a mut (dyn BodySink + Send),
    transport: &'a ProgressTransport<T>,
}

impl<T: Sync> BodySink for CountingSink<'_, T> {
    fn start(&mut self, head: &ResponseHead) -> io::Result<bool> {
        self.sink.start(head)
    }
    fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.transport.record(chunk.len(), false);
        self.sink.write(chunk)
    }
}

impl<T: Transport> Transport for ProgressTransport<T> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let response = self.inner.send(request).await?;
        self.record(response.body.len(), true);
        Ok(response)
    }

    async fn send_streaming<'a>(
        &'a self,
        request: HttpRequest,
        sink: &'a mut (dyn BodySink + Send),
    ) -> Result<ResponseHead, TransportError> {
        let mut counting = CountingSink {
            sink,
            transport: self,
        };
        let result = self.inner.send_streaming(request, &mut counting).await;
        self.record(0, result.is_ok());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsus_client::transport::{
        Headers, SensitiveUrl,
        mock::{MockStep, MockTransport},
    };

    struct Sink(Vec<u8>);
    impl BodySink for Sink {
        fn start(&mut self, _: &ResponseHead) -> io::Result<bool> {
            Ok(true)
        }
        fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }

    #[tokio::test]
    async fn counts_buffered_and_streamed_bodies_once_without_changing_delivery() {
        let mock = MockTransport::scripted(vec![
            MockStep::Respond(HttpResponse {
                status: 200,
                headers: Headers::new(),
                body: b"soap".to_vec(),
            }),
            MockStep::Respond(HttpResponse {
                status: 206,
                headers: Headers::new(),
                body: vec![7; 2500],
            }),
        ]);
        let progress = ProgressTransport::new(mock, false);
        let request = || {
            HttpRequest::get(
                SensitiveUrl::parse("https://example.test/file?token=secret").unwrap(),
                Duration::from_secs(1),
            )
        };
        assert_eq!(progress.send(request()).await.unwrap().body, b"soap");
        let mut sink = Sink(Vec::new());
        assert_eq!(
            progress
                .send_streaming(request(), &mut sink)
                .await
                .unwrap()
                .status,
            206
        );
        assert_eq!(sink.0, vec![7; 2500]);
        let counters = progress.counters.lock().unwrap();
        assert_eq!(counters.responses, 2);
        assert_eq!(counters.bytes, 2504);
    }
}
