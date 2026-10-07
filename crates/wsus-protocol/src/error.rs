//! Error type shared by every codec in this crate.
use thiserror::Error;

use crate::soap::SoapFault;

/// Failure while decoding or validating a protocol message.
///
/// A SOAP fault received from the peer is reported as [`ProtocolError::Fault`]
/// so callers can match on it independently of any HTTP status code.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ProtocolError {
    /// The body is larger than [`crate::soap::Limits::max_body_bytes`].
    #[error("body of {size} bytes exceeds limit of {limit} bytes")]
    BodyTooLarge { size: usize, limit: usize },
    /// Element nesting is deeper than [`crate::soap::Limits::max_depth`].
    #[error("element nesting deeper than limit of {limit}")]
    DepthExceeded { limit: usize },
    /// More elements than [`crate::soap::Limits::max_elements`].
    #[error("document contains more than {limit} elements")]
    TooManyElements { limit: usize },
    /// An array holds more items than [`crate::soap::Limits::max_array_len`].
    #[error("array `{name}` has more than {limit} items")]
    ArrayTooLong { name: String, limit: usize },
    /// A `DOCTYPE` declaration was present. DTDs, and with them external and
    /// internal entities, are never accepted.
    #[error("DOCTYPE declarations (DTD, external entities) are not allowed")]
    DtdNotAllowed,
    /// An entity reference other than the five predefined ones or a numeric
    /// character reference.
    #[error("unsupported entity reference `&{0};`")]
    UnsupportedEntity(String),
    /// The input is not well-formed XML.
    #[error("malformed XML: {0}")]
    MalformedXml(String),
    /// The input uses an encoding other than UTF-8.
    #[error("unsupported document encoding: {0}")]
    UnsupportedEncoding(String),
    /// The root element is not a SOAP 1.1 or 1.2 envelope.
    #[error("not a SOAP envelope: {0}")]
    NotSoapEnvelope(String),
    /// The envelope structure violates SOAP rules.
    #[error("invalid SOAP envelope: {0}")]
    InvalidEnvelope(String),
    /// The transport action does not match the body element.
    #[error("action `{action}` does not match body element `{{{namespace}}}{name}`")]
    ActionMismatch {
        action: String,
        namespace: String,
        name: String,
    },
    /// The body element is not the expected message.
    #[error("expected body element `{{{expected_ns}}}{expected}`, found `{{{found_ns}}}{found}`")]
    UnexpectedBody {
        expected_ns: String,
        expected: String,
        found_ns: String,
        found: String,
    },
    /// A required element is missing.
    #[error("missing required element `{0}`")]
    MissingElement(String),
    /// A required element carries `xsi:nil="true"`.
    #[error("required element `{0}` is nil")]
    UnexpectedNil(String),
    /// An element that may occur once occurred repeatedly.
    #[error("element `{0}` occurs more than once")]
    DuplicateElement(String),
    /// Children of a sequence are not in schema order.
    #[error("element `{found}` is out of order inside `{parent}`")]
    OutOfOrder { parent: String, found: String },
    /// A text value does not match its schema type.
    #[error("invalid {kind} value `{value}` in `{element}`")]
    InvalidValue {
        element: String,
        kind: &'static str,
        value: String,
    },
    /// The peer answered with a SOAP fault.
    #[error("SOAP fault: {0}")]
    Fault(Box<SoapFault>),
    /// Update metadata could not be interpreted.
    #[error("invalid update metadata: {0}")]
    Metadata(String),
}

/// Result alias for this crate.
pub type Result<T, E = ProtocolError> = std::result::Result<T, E>;
