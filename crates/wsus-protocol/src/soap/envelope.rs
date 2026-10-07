//! SOAP 1.1 / 1.2 envelopes and the HTTP-facing encode/decode entry points.
use super::fault::SoapFault;
use super::message::{SoapMessage, SoapRequest};
use super::wire::Ctx;
use super::xml::{self, Element, Limits, Node, QName};
use crate::error::{ProtocolError, Result};

/// SOAP 1.1 envelope namespace.
pub const SOAP11_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// SOAP 1.2 envelope namespace.
pub const SOAP12_NS: &str = "http://www.w3.org/2003/05/soap-envelope";

/// SOAP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoapVersion {
    /// SOAP 1.1 (`text/xml` plus a `SOAPAction` header).
    V11,
    /// SOAP 1.2 (`application/soap+xml`, action as a content-type parameter).
    V12,
}

impl SoapVersion {
    /// Envelope namespace URI.
    pub fn envelope_ns(self) -> &'static str {
        match self {
            Self::V11 => SOAP11_NS,
            Self::V12 => SOAP12_NS,
        }
    }

    fn from_ns(ns: &str) -> Option<Self> {
        match ns {
            SOAP11_NS => Some(Self::V11),
            SOAP12_NS => Some(Self::V12),
            _ => None,
        }
    }
}

/// Envelope body: one payload element or a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// The message element.
    Payload(Element),
    /// A SOAP fault.
    Fault(SoapFault),
}

/// A SOAP envelope. Header blocks are preserved raw; none are interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: SoapVersion,
    pub headers: Vec<Element>,
    pub body: Body,
}

impl Envelope {
    /// Envelope around a payload element.
    pub fn payload(version: SoapVersion, payload: Element) -> Self {
        Self {
            version,
            headers: Vec::new(),
            body: Body::Payload(payload),
        }
    }

    /// Envelope around a fault.
    pub fn fault(fault: SoapFault) -> Self {
        Self {
            version: fault.version,
            headers: Vec::new(),
            body: Body::Fault(fault),
        }
    }

    /// Name of the payload element, if the body is not a fault.
    pub fn payload_name(&self) -> Option<&QName> {
        match &self.body {
            Body::Payload(p) => Some(&p.name),
            Body::Fault(_) => None,
        }
    }

    /// Header blocks flagged `mustUnderstand`. This crate understands no
    /// header, so a server must fault if this is non-empty.
    pub fn must_understand_headers(&self) -> Vec<&Element> {
        let ns = self.version.envelope_ns();
        self.headers
            .iter()
            .filter(|h| matches!(h.ns_attr(ns, "mustUnderstand"), Some("1" | "true")))
            .collect()
    }

    /// Deterministic serialization.
    pub fn encode(&self) -> Vec<u8> {
        let ns = self.version.envelope_ns();
        let mut root = Element::new(ns, "Envelope");
        if !self.headers.is_empty() {
            let mut h = Element::new(ns, "Header");
            for x in &self.headers {
                h.push(x.clone());
            }
            root.push(h);
        }
        let mut body = Element::new(ns, "Body");
        match &self.body {
            Body::Payload(p) => body.push(p.clone()),
            Body::Fault(f) => body.push(f.to_element()),
        }
        root.push(body);
        xml::serialize(&root, true)
    }

    /// Decode an envelope. A fault body is returned as [`Body::Fault`]; no
    /// HTTP status is involved.
    pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Self> {
        let root = xml::parse(bytes, limits)?;
        Self::from_element(&root)
    }

    /// Interpret a parsed root element as an envelope.
    pub fn from_element(root: &Element) -> Result<Self> {
        let version = root
            .name
            .ns
            .as_deref()
            .and_then(SoapVersion::from_ns)
            .ok_or_else(|| ProtocolError::NotSoapEnvelope(format!("root is {}", root.name)))?;
        if root.name.local != "Envelope" {
            return Err(ProtocolError::NotSoapEnvelope(format!(
                "root is {}",
                root.name
            )));
        }
        let ns = version.envelope_ns();
        let mut headers = Vec::new();
        let mut body_el: Option<&Element> = None;
        for c in root.elements() {
            if c.name.is(ns, "Header") {
                if body_el.is_some() {
                    return Err(ProtocolError::InvalidEnvelope("Header after Body".into()));
                }
                if !headers.is_empty() {
                    return Err(ProtocolError::InvalidEnvelope("duplicate Header".into()));
                }
                headers.extend(c.elements().cloned());
            } else if c.name.is(ns, "Body") {
                if body_el.is_some() {
                    return Err(ProtocolError::InvalidEnvelope("duplicate Body".into()));
                }
                body_el = Some(c);
            } else if version == SoapVersion::V12 {
                return Err(ProtocolError::InvalidEnvelope(format!(
                    "unexpected envelope child {}",
                    c.name
                )));
            }
        }
        if root
            .children
            .iter()
            .any(|n| matches!(n, Node::Text(t) if !t.trim().is_empty()))
        {
            return Err(ProtocolError::InvalidEnvelope("text in Envelope".into()));
        }
        let body_el =
            body_el.ok_or_else(|| ProtocolError::InvalidEnvelope("missing Body".into()))?;
        let mut kids = body_el.elements();
        let first = kids
            .next()
            .ok_or_else(|| ProtocolError::InvalidEnvelope("empty Body".into()))?;
        if kids.next().is_some() {
            return Err(ProtocolError::InvalidEnvelope(
                "Body holds more than one element".into(),
            ));
        }
        let body = if first.name.is(ns, "Fault") {
            Body::Fault(SoapFault::from_element(first, version))
        } else {
            Body::Payload(first.clone())
        };
        Ok(Self {
            version,
            headers,
            body,
        })
    }
}

/// Check a transport action against the body element.
///
/// WUSP and WSUSSS actions are `{namespace}/{local-name}` of the request
/// element, so the check is exact on both parts. Surrounding quotes and
/// whitespace (the `SOAPAction` header is quoted) are ignored. An absent or
/// empty action is accepted: SOAP 1.2 may carry none and a response has none.
pub fn validate_action(action: Option<&str>, body: &QName) -> Result<()> {
    let Some(action) = action else { return Ok(()) };
    let trimmed = action.trim().trim_matches('"').trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let ns = body.ns.as_deref().unwrap_or("");
    if trimmed == format!("{ns}/{}", body.local) {
        Ok(())
    } else {
        Err(ProtocolError::ActionMismatch {
            action: trimmed.to_owned(),
            namespace: ns.to_owned(),
            name: body.local.clone(),
        })
    }
}

/// Extract the `action` parameter of a SOAP 1.2 `Content-Type` value.
pub fn action_from_content_type(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k.trim().eq_ignore_ascii_case("action")).then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// An encoded message plus the HTTP metadata that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMessage {
    /// Entity body.
    pub body: Vec<u8>,
    /// `Content-Type` header value (for SOAP 1.2 includes `action` on requests).
    pub content_type: String,
    /// Value for the `SOAPAction` header (SOAP 1.1 requests only), including quotes.
    pub soap_action: Option<String>,
}

fn media(version: SoapVersion, action: Option<&str>) -> (String, Option<String>) {
    match version {
        SoapVersion::V11 => (
            "text/xml; charset=utf-8".into(),
            action.map(|a| format!("\"{a}\"")),
        ),
        SoapVersion::V12 => (
            match action {
                Some(a) => format!("application/soap+xml; charset=utf-8; action=\"{a}\""),
                None => "application/soap+xml; charset=utf-8".into(),
            },
            None,
        ),
    }
}

/// Encode a request with its action.
pub fn encode_request<R: SoapRequest>(version: SoapVersion, request: &R) -> EncodedMessage {
    let action = R::action();
    let (content_type, soap_action) = media(version, Some(&action));
    EncodedMessage {
        body: Envelope::payload(version, request.encode_body()).encode(),
        content_type,
        soap_action,
    }
}

/// Encode a response message (no action).
pub fn encode_response<M: SoapMessage>(version: SoapVersion, response: &M) -> EncodedMessage {
    let (content_type, soap_action) = media(version, None);
    EncodedMessage {
        body: Envelope::payload(version, response.encode_body()).encode(),
        content_type,
        soap_action,
    }
}

/// Encode a fault response.
pub fn encode_fault(fault: &SoapFault) -> EncodedMessage {
    let (content_type, soap_action) = media(fault.version, None);
    EncodedMessage {
        body: Envelope::fault(fault.clone()).encode(),
        content_type,
        soap_action,
    }
}

/// Decode a request: parse the envelope, check `action` against the body,
/// check the body is `R`, and decode it.
///
/// `action` is the `SOAPAction` header value or the SOAP 1.2 content-type
/// `action` parameter; pass `None` when neither was sent.
pub fn decode_request<R: SoapRequest>(
    action: Option<&str>,
    bytes: &[u8],
    limits: &Limits,
) -> Result<(SoapVersion, R)> {
    let env = Envelope::decode(bytes, limits)?;
    match env.body {
        Body::Fault(f) => Err(ProtocolError::Fault(Box::new(f))),
        Body::Payload(p) => {
            validate_action(action, &p.name)?;
            let msg = decode_payload::<R>(&p, limits)?;
            Ok((env.version, msg))
        }
    }
}

/// Decode a response. A fault body (with any HTTP status) yields
/// [`ProtocolError::Fault`].
pub fn decode_response<M: SoapMessage>(bytes: &[u8], limits: &Limits) -> Result<M> {
    let env = Envelope::decode(bytes, limits)?;
    match env.body {
        Body::Fault(f) => Err(ProtocolError::Fault(Box::new(f))),
        Body::Payload(p) => decode_payload::<M>(&p, limits),
    }
}

/// Decode a payload element as `M`, checking its name.
pub fn decode_payload<M: SoapMessage>(payload: &Element, limits: &Limits) -> Result<M> {
    if !payload.name.is(M::NAMESPACE, M::NAME) {
        return Err(ProtocolError::UnexpectedBody {
            expected_ns: M::NAMESPACE.into(),
            expected: M::NAME.into(),
            found_ns: payload.name.ns.clone().unwrap_or_default(),
            found: payload.name.local.clone(),
        });
    }
    M::decode_body(payload, &Ctx { limits })
}
