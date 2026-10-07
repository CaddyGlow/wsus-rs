//! SOAP faults and the WSUS application-level fault detail.
use std::fmt;

use super::envelope::SoapVersion;
use super::xml::{Element, Node, XML_NS};

/// Application error carried in the `ErrorCode` element of a fault detail
/// (MS-WUSP 2.2.2.4, MS-WSUSSS 2.2.9.3).
///
/// Implementation decisions (inventory section 8, item 4): the decoder maps
/// `FileLocationsChanged` (operation prose) to
/// [`ErrorCode::FileLocationChanged`] (fault table) and `InvalidParameter`
/// (singular, `GetExtendedUpdateInfo` prose) to
/// [`ErrorCode::InvalidParameters`]; the encoder emits the fault-table
/// spelling. Values not in any table are kept as [`ErrorCode::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    InvalidCookie,
    ConfigChanged,
    RegistrationRequired,
    ServerChanged,
    InternalServerError,
    CookieExpired,
    InvalidParameters,
    InvalidAuthorizationCookie,
    RegistrationNotRequired,
    ServerBusy,
    FileLocationChanged,
    /// WSUSSS only.
    IncompatibleProtocolVersion,
    /// WSUSSS only.
    FileDigestsMissing,
    /// Appears only for GetDriverSetData in MS-WSUSSS; not in its common table.
    TooManyIds,
    /// Any other value, verbatim.
    Unknown(String),
}

/// What a client MUST/SHOULD do after a fault (MS-WUSP 2.2.2.4 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// Discard the cookie, then GetConfig, GetAuthorizationCookie, GetCookie, RefreshCache.
    RestartHandshakeWithRefreshCache,
    /// GetConfig, GetAuthorizationCookie, GetCookie.
    RenewConfigAndCookies,
    /// GetAuthorizationCookie, GetCookie.
    RenewCookie,
    /// RegisterComputer, then repeat the failed call.
    Register,
    /// Retry the operation later.
    RetryLater,
    /// Call GetFileLocations.
    RefreshFileLocations,
    /// Parameters were wrong; do not retry unchanged.
    FixParameters,
    /// No specified recovery.
    None,
}

impl ErrorCode {
    /// Parse the wire text.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "InvalidCookie" => Self::InvalidCookie,
            "ConfigChanged" => Self::ConfigChanged,
            "RegistrationRequired" => Self::RegistrationRequired,
            "ServerChanged" => Self::ServerChanged,
            "InternalServerError" => Self::InternalServerError,
            "CookieExpired" => Self::CookieExpired,
            "InvalidParameters" | "InvalidParameter" => Self::InvalidParameters,
            "InvalidAuthorizationCookie" => Self::InvalidAuthorizationCookie,
            "RegistrationNotRequired" => Self::RegistrationNotRequired,
            "ServerBusy" => Self::ServerBusy,
            "FileLocationChanged" | "FileLocationsChanged" => Self::FileLocationChanged,
            "IncompatibleProtocolVersion" => Self::IncompatibleProtocolVersion,
            "FileDigestsMissing" => Self::FileDigestsMissing,
            "TooManyIds" => Self::TooManyIds,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Wire text.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidCookie => "InvalidCookie",
            Self::ConfigChanged => "ConfigChanged",
            Self::RegistrationRequired => "RegistrationRequired",
            Self::ServerChanged => "ServerChanged",
            Self::InternalServerError => "InternalServerError",
            Self::CookieExpired => "CookieExpired",
            Self::InvalidParameters => "InvalidParameters",
            Self::InvalidAuthorizationCookie => "InvalidAuthorizationCookie",
            Self::RegistrationNotRequired => "RegistrationNotRequired",
            Self::ServerBusy => "ServerBusy",
            Self::FileLocationChanged => "FileLocationChanged",
            Self::IncompatibleProtocolVersion => "IncompatibleProtocolVersion",
            Self::FileDigestsMissing => "FileDigestsMissing",
            Self::TooManyIds => "TooManyIds",
            Self::Unknown(s) => s,
        }
    }

    /// MS-WUSP client recovery for this code.
    pub fn wusp_recovery(&self) -> Recovery {
        match self {
            Self::InvalidCookie | Self::ServerChanged => Recovery::RestartHandshakeWithRefreshCache,
            Self::ConfigChanged => Recovery::RenewConfigAndCookies,
            Self::CookieExpired => Recovery::RenewCookie,
            Self::RegistrationRequired => Recovery::Register,
            Self::InternalServerError | Self::ServerBusy => Recovery::RetryLater,
            Self::FileLocationChanged => Recovery::RefreshFileLocations,
            Self::InvalidParameters
            | Self::InvalidAuthorizationCookie
            | Self::RegistrationNotRequired => Recovery::FixParameters,
            _ => Recovery::None,
        }
    }
}

/// The `ErrorCode` / `Message` / `ID` / `Method` detail of a WSUS fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsusFaultDetail {
    /// Classified error code.
    pub error_code: ErrorCode,
    /// Optional human-readable message (for `FileDigestsMissing`, the missing
    /// digests separated by `|`).
    pub message: Option<String>,
    /// Fault instance GUID, as sent.
    pub id: Option<String>,
    /// Web method in which the fault occurred, as sent.
    pub method: Option<String>,
}

/// A SOAP fault of either version.
///
/// Decoded from the envelope body regardless of HTTP status. The raw detail
/// element is retained so unknown detail content is not discarded.
///
/// Implementation decisions (inventory section 4.3): the decoder accepts the
/// union of the SOAP 1.1 `detail` and the WSUSSS SOAP 1.2 unqualified
/// `Detail` shapes (and the standard `env:Detail`), looks for the WSUS
/// children in any namespace, and classifies on `ErrorCode` only. The
/// encoder follows the specifications: SOAP 1.1 `detail`, SOAP 1.2 an
/// unqualified `Detail` child (MS-WSUSSS 2.2.9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapFault {
    /// Envelope version the fault used.
    pub version: SoapVersion,
    /// `faultcode` (1.1) or `Code/Value` (1.2), verbatim (for example `soap:Client`).
    pub code: String,
    /// SOAP 1.2 `Subcode/Value` chain.
    pub subcodes: Vec<String>,
    /// `faultstring` (1.1) or first `Reason/Text` (1.2).
    pub reason: String,
    /// `faultactor` (1.1) or `Role` (1.2).
    pub actor: Option<String>,
    /// Raw detail element, if any.
    pub detail: Option<Element>,
    /// Parsed WSUS detail, if the detail carried an `ErrorCode`.
    pub wsus: Option<WsusFaultDetail>,
}

impl fmt::Display for SoapFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.wsus {
            Some(w) => write!(
                f,
                "{} ({}): {}",
                self.code,
                w.error_code.as_str(),
                self.reason
            ),
            None => write!(f, "{}: {}", self.code, self.reason),
        }
    }
}

fn find_any<'a>(el: &'a Element, names: &[&str]) -> Option<&'a Element> {
    el.elements()
        .find(|c| names.contains(&c.name.local.as_str()))
}

fn text_of(el: &Element, names: &[&str]) -> Option<String> {
    find_any(el, names).map(|c| c.text())
}

impl SoapFault {
    /// A fault carrying a WUSP/WSUSSS error code, ready to encode.
    pub fn application(
        version: SoapVersion,
        error_code: ErrorCode,
        reason: &str,
        message: Option<&str>,
        id: Option<uuid::Uuid>,
        method: Option<&str>,
    ) -> Self {
        let wsus = WsusFaultDetail {
            error_code,
            message: message.map(str::to_owned),
            id: id.map(|i| i.hyphenated().to_string()),
            method: method.map(str::to_owned),
        };
        Self {
            version,
            code: match version {
                SoapVersion::V11 => "Client".into(),
                SoapVersion::V12 => "Sender".into(),
            },
            subcodes: Vec::new(),
            reason: reason.to_owned(),
            actor: None,
            detail: None,
            wsus: Some(wsus),
        }
    }

    /// Local part of the fault code (`soap:Client` gives `Client`).
    pub fn code_local(&self) -> &str {
        self.code.rsplit(':').next().unwrap_or(&self.code)
    }

    /// Decode from a `Fault` element of the given envelope version.
    pub fn from_element(el: &Element, version: SoapVersion) -> Self {
        let (code, subcodes, reason, actor) = match version {
            SoapVersion::V11 => (
                text_of(el, &["faultcode"]).unwrap_or_default(),
                Vec::new(),
                text_of(el, &["faultstring"]).unwrap_or_default(),
                text_of(el, &["faultactor"]),
            ),
            SoapVersion::V12 => {
                let code_el = find_any(el, &["Code"]);
                let code = code_el
                    .and_then(|c| text_of(c, &["Value"]))
                    .unwrap_or_default();
                let mut subs = Vec::new();
                let mut cur = code_el.and_then(|c| find_any(c, &["Subcode"]));
                while let Some(s) = cur {
                    if let Some(v) = text_of(s, &["Value"]) {
                        subs.push(v);
                    }
                    cur = find_any(s, &["Subcode"]);
                }
                let reason = find_any(el, &["Reason"])
                    .and_then(|r| text_of(r, &["Text"]))
                    .unwrap_or_default();
                (code, subs, reason, text_of(el, &["Role"]))
            }
        };
        let detail = find_any(el, &["detail", "Detail"]).cloned();
        let wsus = detail.as_ref().and_then(|d| {
            let ec = find_any(d, &["ErrorCode"])?;
            Some(WsusFaultDetail {
                error_code: ErrorCode::parse(&ec.text()),
                message: text_of(d, &["Message"]),
                id: text_of(d, &["ID"]),
                method: text_of(d, &["Method"]),
            })
        });
        Self {
            version,
            code,
            subcodes,
            reason,
            actor,
            detail,
            wsus,
        }
    }

    /// Encode as a `Fault` element.
    pub fn to_element(&self) -> Element {
        let env = self.version.envelope_ns();
        let qualify = |c: &str| {
            if c.contains(':') {
                c.to_owned()
            } else {
                format!("soap:{c}")
            }
        };
        let detail = self.detail_element();
        match self.version {
            SoapVersion::V11 => {
                let mut f = Element::new(env, "Fault")
                    .with_child(Element::unqualified("faultcode").with_text(qualify(&self.code)))
                    .with_child(Element::unqualified("faultstring").with_text(&self.reason));
                if let Some(a) = &self.actor {
                    f.push(Element::unqualified("faultactor").with_text(a));
                }
                if let Some(mut d) = detail {
                    d.name = super::xml::QName::unqualified("detail");
                    f.push(d);
                }
                f
            }
            SoapVersion::V12 => {
                let mut code = Element::new(env, "Code")
                    .with_child(Element::new(env, "Value").with_text(qualify(&self.code)));
                if !self.subcodes.is_empty() {
                    let mut sub: Option<Element> = None;
                    for s in self.subcodes.iter().rev() {
                        let mut e = Element::new(env, "Subcode")
                            .with_child(Element::new(env, "Value").with_text(s));
                        if let Some(inner) = sub.take() {
                            e.push(inner);
                        }
                        sub = Some(e);
                    }
                    code.push(sub.expect("non-empty subcodes"));
                }
                let mut f = Element::new(env, "Fault").with_child(code).with_child(
                    Element::new(env, "Reason").with_child(
                        Element::new(env, "Text")
                            .with_ns_attr(XML_NS, "lang", "en")
                            .with_text(&self.reason),
                    ),
                );
                if let Some(a) = &self.actor {
                    f.push(Element::new(env, "Role").with_text(a));
                }
                if let Some(mut d) = detail {
                    d.name = super::xml::QName::unqualified("Detail");
                    f.push(d);
                }
                f
            }
        }
    }

    fn detail_element(&self) -> Option<Element> {
        if let Some(w) = &self.wsus {
            let mut d = Element::unqualified("detail")
                .with_child(Element::unqualified("ErrorCode").with_text(w.error_code.as_str()));
            if let Some(m) = &w.message {
                d.push(Element::unqualified("Message").with_text(m));
            }
            if let Some(i) = &w.id {
                d.push(Element::unqualified("ID").with_text(i));
            }
            if let Some(m) = &w.method {
                d.push(Element::unqualified("Method").with_text(m));
            }
            return Some(d);
        }
        self.detail.clone().map(|mut d| {
            d.children
                .retain(|n| matches!(n, Node::Element(_) | Node::Text(_)));
            d
        })
    }
}
