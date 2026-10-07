//! Client errors. Messages never contain URLs or credentials.
use wsus_protocol::ProtocolError;
use wsus_protocol::soap::ErrorCode;

use crate::download::DownloadError;
use crate::transport::TransportError;

/// Failure of a MS-WSUSSS operation.
#[derive(Debug, thiserror::Error)]
pub enum WsusssError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("HTTP status {status} without a SOAP fault")]
    HttpStatus { status: u16 },
    #[error("protocol violation: {0}")]
    Protocol(ProtocolError),
    /// The upstream answered with a SOAP fault carrying a WSUS error code.
    #[error("upstream fault {}: {reason}", code.as_str())]
    Fault {
        code: ErrorCode,
        reason: String,
        message: Option<String>,
    },
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("response lacks {0}")]
    MissingResult(&'static str),
    #[error("limit violated: {0}")]
    Limit(String),
    #[error("metadata decompression failed: {0}")]
    Decompress(String),
    #[error("no content location available")]
    NoLocation,
    #[error("content download failed: {0}")]
    Download(#[from] DownloadError),
}

impl WsusssError {
    /// Fault code, when this is an upstream fault.
    pub fn fault_code(&self) -> Option<&ErrorCode> {
        match self {
            Self::Fault { code, .. } => Some(code),
            _ => None,
        }
    }

    /// True when a content download failed with HTTP 404.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Download(DownloadError::HttpStatus { status: 404, .. })
        )
    }

    /// True for `ServerChanged`: the caller must reset its anchors.
    pub fn is_server_changed(&self) -> bool {
        matches!(self.fault_code(), Some(ErrorCode::ServerChanged))
    }

    /// Digests (as sent by the upstream) named by a `FileDigestsMissing`
    /// fault; the message separates them with `|`.
    pub fn missing_digests(&self) -> Vec<String> {
        match self {
            Self::Fault {
                code: ErrorCode::FileDigestsMissing,
                message: Some(m),
                ..
            } => m
                .split('|')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }
}
