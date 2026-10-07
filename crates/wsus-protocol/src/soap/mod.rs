//! SOAP 1.1 / 1.2 transport-independent codec.
//!
//! * [`xml`]: namespace-aware tree, limit-enforcing parser (DTDs rejected),
//!   deterministic serializer.
//! * [`envelope`]: envelopes, action validation, request/response entry points.
//! * [`fault`]: SOAP faults and the WSUS `ErrorCode` detail.
//! * [`wire`]: absent/nil/value tracking, scalars, ordered field readers.
//! * [`message`]: [`SoapMessage`] and [`SoapRequest`].
pub mod envelope;
pub mod fault;
pub mod message;
pub mod wire;
pub mod xml;

pub use envelope::{
    Body, EncodedMessage, Envelope, SOAP11_NS, SOAP12_NS, SoapVersion, action_from_content_type,
    decode_payload, decode_request, decode_response, encode_fault, encode_request, encode_response,
    validate_action,
};
pub use fault::{ErrorCode, Recovery, SoapFault, WsusFaultDetail};
pub use message::{SoapMessage, SoapRequest};
pub use wire::{Ctx, Presence, Scalar, WireType, XsDateTime};
pub use xml::{Element, Limits};
