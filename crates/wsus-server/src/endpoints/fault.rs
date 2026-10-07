//! Protocol faults and their HTTP rendering.
use uuid::Uuid;
use wsus_protocol::soap::{ErrorCode, SoapFault, SoapVersion, encode_fault};

use super::message::HttpResponseParts;
use crate::session::CookieError;
use crate::storage;

/// Everything an operation can fail with. Every variant renders as a SOAP fault except
/// [`ApiError::Http`], which is for requests that never reached SOAP routing.
#[derive(Debug)]
pub(crate) enum ApiError {
    /// WSUS application fault (`ErrorCode` in the detail).
    Code(ErrorCode, &'static str),
    /// Plain SOAP client fault with no WSUS detail (malformed envelope, bad action).
    Client(String),
    /// `soap:MustUnderstand`: a mandatory header block this server does not implement.
    MustUnderstand,
    /// Unexpected server failure; the cause is not disclosed to the client.
    Internal,
    /// Transport-level refusal (404/405/413/415), still delivered as a SOAP fault.
    Http(u16, &'static str),
}

impl From<storage::Error> for ApiError {
    fn from(_: storage::Error) -> Self {
        Self::Internal
    }
}

impl From<CookieError> for ApiError {
    fn from(e: CookieError) -> Self {
        match e {
            CookieError::Invalid => Self::Code(ErrorCode::InvalidCookie, "invalid cookie"),
            CookieError::Expired => Self::Code(ErrorCode::CookieExpired, "cookie expired"),
            CookieError::ServerChanged => Self::Code(ErrorCode::ServerChanged, "server changed"),
            CookieError::ConfigChanged => {
                Self::Code(ErrorCode::ConfigChanged, "configuration changed")
            }
        }
    }
}

pub(crate) fn invalid(reason: &'static str) -> ApiError {
    ApiError::Code(ErrorCode::InvalidParameters, reason)
}

impl ApiError {
    /// Render as a SOAP fault response. `method` is the quoted SOAPAction when known.
    pub(crate) fn render(self, version: SoapVersion, method: Option<&str>) -> HttpResponseParts {
        let (mut fault, status) = match self {
            Self::Code(code, reason) => {
                let sender =
                    !matches!(code, ErrorCode::InternalServerError | ErrorCode::ServerBusy);
                let mut f = SoapFault::application(
                    version,
                    code,
                    reason,
                    None,
                    Some(Uuid::new_v4()),
                    method,
                );
                if !sender {
                    set_receiver(&mut f);
                }
                let s = status_for(&f);
                (f, s)
            }
            Self::Client(reason) => {
                let f = SoapFault {
                    version,
                    code: sender_code(version).into(),
                    subcodes: Vec::new(),
                    reason,
                    actor: None,
                    detail: None,
                    wsus: None,
                };
                let s = status_for(&f);
                (f, s)
            }
            Self::MustUnderstand => {
                let f = SoapFault {
                    version,
                    code: "MustUnderstand".into(),
                    subcodes: Vec::new(),
                    reason: "a mandatory header block is not understood".into(),
                    actor: None,
                    detail: None,
                    wsus: None,
                };
                let s = status_for(&f);
                (f, s)
            }
            Self::Internal => {
                let mut f = SoapFault::application(
                    version,
                    ErrorCode::InternalServerError,
                    "internal server error",
                    None,
                    Some(Uuid::new_v4()),
                    method,
                );
                set_receiver(&mut f);
                let s = status_for(&f);
                (f, s)
            }
            Self::Http(status, reason) => {
                let f = SoapFault {
                    version,
                    code: sender_code(version).into(),
                    subcodes: Vec::new(),
                    reason: reason.to_owned(),
                    actor: None,
                    detail: None,
                    wsus: None,
                };
                (f, status)
            }
        };
        fault.actor = None;
        let enc = encode_fault(&fault);
        HttpResponseParts::bytes(status, &enc.content_type, enc.body)
    }
}

fn sender_code(v: SoapVersion) -> &'static str {
    match v {
        SoapVersion::V11 => "Client",
        SoapVersion::V12 => "Sender",
    }
}

fn set_receiver(f: &mut SoapFault) {
    f.code = match f.version {
        SoapVersion::V11 => "Server".into(),
        SoapVersion::V12 => "Receiver".into(),
    };
}

/// SOAP 1.1 over HTTP: faults are 500 (ASMX does the same for client faults). SOAP 1.2:
/// sender faults 400, receiver faults 500.
fn status_for(f: &SoapFault) -> u16 {
    match f.version {
        SoapVersion::V11 => 500,
        SoapVersion::V12 => {
            if f.code_local() == "Sender" {
                400
            } else {
                500
            }
        }
    }
}
