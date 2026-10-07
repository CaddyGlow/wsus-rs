//! Retry classification by operation idempotence.

use super::{HttpRequest, HttpResponse, Phase, Transport, TransportError};
use std::{future::Future, sync::Arc, time::Duration};

/// Whether replaying an operation can duplicate side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotence {
    /// Safe to replay (GET, ranged GET, read-only SOAP queries).
    Idempotent,
    /// May change server state (registration, event reports). Replayed only
    /// when the server provably did not process the request.
    NonIdempotent,
}

/// Outcome that may warrant a retry.
#[derive(Debug, Clone, Copy)]
pub enum Failure<'a> {
    Transport(&'a TransportError),
    Status {
        status: u16,
        retry_after: Option<Duration>,
    },
}

/// Bounded exponential backoff without jitter (deterministic for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }
}

impl RetryPolicy {
    /// No retries.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }

    /// Returns the delay before retry number `attempt + 1`, or `None` to stop.
    ///
    /// Idempotent operations retry transport failures, 408, 429, 500, 502, 503
    /// and 504. Non-idempotent operations retry only failures where no request
    /// bytes were sent, and 429/503 responses that carry an explicit
    /// `Retry-After` (the server declined to process the request).
    pub fn decide(
        &self,
        idempotence: Idempotence,
        attempt: u32,
        failure: Failure<'_>,
    ) -> Option<Duration> {
        if attempt >= self.max_retries {
            return None;
        }
        let backoff = self
            .base_delay
            .saturating_mul(1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX))
            .min(self.max_delay);
        match (idempotence, failure) {
            (_, Failure::Transport(e)) if e.kind == super::ErrorKind::Aborted => None,
            (_, Failure::Transport(e)) if e.kind == super::ErrorKind::TooLarge => None,
            (Idempotence::Idempotent, Failure::Transport(_)) => Some(backoff),
            (Idempotence::NonIdempotent, Failure::Transport(e)) => {
                (e.phase == Phase::NotSent).then_some(backoff)
            }
            (
                Idempotence::Idempotent,
                Failure::Status {
                    status,
                    retry_after,
                },
            ) => matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
                .then(|| retry_after.map_or(backoff, |d| d.min(self.max_delay))),
            (
                Idempotence::NonIdempotent,
                Failure::Status {
                    status,
                    retry_after,
                },
            ) => match (status, retry_after) {
                (429 | 503, Some(d)) => Some(d.min(self.max_delay)),
                _ => None,
            },
        }
    }
}

/// Parses a `Retry-After` delay in seconds (HTTP-date form is ignored).
pub fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    value?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Runtime-specific, nonblocking retry timer.
pub trait RetryTimer: Sync {
    /// Waits before the next attempt; dropping the future cancels the wait.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

impl<S: RetryTimer + Send + ?Sized> RetryTimer for Arc<S> {
    async fn sleep(&self, duration: Duration) {
        self.as_ref().sleep(duration).await;
    }
}

impl<S: RetryTimer + ?Sized> RetryTimer for &S {
    async fn sleep(&self, duration: Duration) {
        (*self).sleep(duration).await;
    }
}

/// Timer that never waits; for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImmediateTimer;

impl RetryTimer for ImmediateTimer {
    async fn sleep(&self, _duration: Duration) {}
}

/// Sends a buffered request, retrying according to `policy` and the request's
/// idempotence. The last response is returned even if its status is retryable
/// but retries are exhausted.
pub async fn send_with_retry<T: Transport, S: RetryTimer>(
    transport: &T,
    timer: &S,
    policy: &RetryPolicy,
    request: &HttpRequest,
) -> Result<HttpResponse, TransportError> {
    let mut attempt = 0u32;
    loop {
        let delay = match transport.send(request.clone()).await {
            Ok(response) => {
                let retry_after = parse_retry_after(response.headers.get("retry-after"));
                match policy.decide(
                    request.idempotence,
                    attempt,
                    Failure::Status {
                        status: response.status,
                        retry_after,
                    },
                ) {
                    Some(delay) => delay,
                    None => return Ok(response),
                }
            }
            Err(error) => {
                match policy.decide(request.idempotence, attempt, Failure::Transport(&error)) {
                    Some(delay) => delay,
                    None => return Err(error),
                }
            }
        };
        timer.sleep(delay).await;
        attempt += 1;
    }
}
