//! WSUS protocol types, SOAP codecs and metadata parsing (no I/O, no runtime,
//! no database).
//!
//! * [`soap`]: SOAP 1.1/1.2 envelopes, faults, namespace-aware XML.
//! * [`wusp`]: MS-WUSP client-server messages, both directions.
//! * [`wsusss`]: MS-WSUSSS server-server messages, both directions.
//! * [`applicability`]: typed, three-valued evaluation of update applicability rules.
//! * [`metadata`]: raw update-fragment preservation, provenance and index.
//! * [`identity`]: typed identities.
//! * [`xpress`]: the `Content-Encoding: xpress` block framing (MS-WUSP 2.1.1).
//!
//! Evidence labels used in documentation: "Specified" means read from the
//! pinned specification; "Implementation decision" marks where the
//! specification is ambiguous and this crate chose a behaviour. No message
//! here has been verified against a native server capture yet.
pub mod applicability;
pub mod common;
pub mod error;
pub mod identity;
mod macros;
pub mod metadata;
pub mod soap;
pub mod wsusss;
pub mod wusp;
pub mod xpress;

pub use error::{ProtocolError, Result};
