//! Error taxonomy of the MS-WUSP client.
//!
//! Messages never include URLs, cookies or request bodies.

use crate::reporting::QueueError;
use crate::state::StateError;
use crate::transport::TransportError;
use std::{io, time::Duration};
use wsus_protocol::{ProtocolError, soap::ErrorCode};

/// Local storage failure (state file, revision store, event queue).
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("client state: {0}")]
    State(#[from] StateError),
    #[error("revision store I/O failure")]
    Io(#[from] io::Error),
    #[error("revision store record is unreadable")]
    Json(#[from] serde_json::Error),
    #[error("event queue: {0}")]
    Queue(#[from] QueueError),
}

/// A SOAP fault answered by the server, independent of the HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultInfo {
    /// Classified application error code; `Unknown` carries the SOAP code
    /// when the detail had none.
    pub code: ErrorCode,
    pub reason: String,
    pub message: Option<String>,
    pub method: Option<String>,
}

/// Every failure of a WUSP session operation, in five classes plus the
/// session's own recovery and configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum WuspError {
    /// No complete response was obtained.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A non-success HTTP status without a SOAP fault body.
    #[error("unexpected HTTP status {status}")]
    Http {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// The server answered with a SOAP fault.
    #[error("SOAP fault {}: {}", .0.code.as_str(), .0.reason)]
    Fault(FaultInfo),
    /// A response or metadata fragment could not be decoded or interpreted.
    #[error("metadata: {0}")]
    Metadata(#[from] ProtocolError),
    /// The response carries a `Content-Encoding` this client does not decode.
    #[error("unsupported response Content-Encoding")]
    UnsupportedEncoding,
    /// An Xpress encoded response body is malformed or exceeds the limits.
    #[error("xpress response body: {0}")]
    Xpress(#[from] wsus_protocol::xpress::XpressError),
    /// Local persistence failed.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    /// The bounded recovery budget was spent; `last` is the final failure.
    #[error("recovery budget exhausted during {operation}")]
    RecoveryExhausted {
        operation: &'static str,
        #[source]
        last: Box<WuspError>,
    },
    /// Invalid or insufficient configuration.
    #[error("configuration: {0}")]
    Config(&'static str),
}

impl WuspError {
    /// Fault code, if this is a SOAP fault.
    pub fn fault_code(&self) -> Option<&ErrorCode> {
        match self {
            Self::Fault(f) => Some(&f.code),
            Self::RecoveryExhausted { last, .. } => last.fault_code(),
            _ => None,
        }
    }
}

impl From<StateError> for WuspError {
    fn from(e: StateError) -> Self {
        Self::Storage(e.into())
    }
}

impl From<io::Error> for WuspError {
    fn from(e: io::Error) -> Self {
        Self::Storage(e.into())
    }
}

impl From<QueueError> for WuspError {
    fn from(e: QueueError) -> Self {
        Self::Storage(e.into())
    }
}
