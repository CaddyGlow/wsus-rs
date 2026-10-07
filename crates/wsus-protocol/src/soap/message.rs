//! Message traits and the macros that derive them from [`WireType`].
use super::wire::Ctx;
use super::xml::Element;
use crate::error::Result;

/// A message that is the single child of a SOAP body.
pub trait SoapMessage: Sized {
    /// Namespace of the body element.
    const NAMESPACE: &'static str;
    /// Local name of the body element.
    const NAME: &'static str;
    /// Encode the body element.
    fn encode_body(&self) -> Element;
    /// Decode the body element (name already checked).
    fn decode_body(el: &Element, ctx: &Ctx<'_>) -> Result<Self>;
}

/// A request message and the response it is answered with.
pub trait SoapRequest: SoapMessage {
    /// Response message type.
    type Response: SoapMessage;

    /// SOAPAction of the operation: `{namespace}/{operation}`.
    fn action() -> String {
        format!("{}/{}", Self::NAMESPACE, Self::NAME)
    }
}

/// Implement [`SoapMessage`] for a type that implements `WireType`.
#[macro_export]
macro_rules! soap_message {
    ($ty:ty, $ns:expr, $name:literal) => {
        impl $crate::soap::SoapMessage for $ty {
            const NAMESPACE: &'static str = $ns;
            const NAME: &'static str = $name;
            fn encode_body(&self) -> $crate::soap::xml::Element {
                <Self as $crate::soap::wire::WireType>::to_xml(self, $ns, $name)
            }
            fn decode_body(
                el: &$crate::soap::xml::Element,
                ctx: &$crate::soap::wire::Ctx<'_>,
            ) -> $crate::error::Result<Self> {
                <Self as $crate::soap::wire::WireType>::from_xml(el, ctx)
            }
        }
    };
}

/// Implement [`SoapRequest`] pairing a request with its response.
#[macro_export]
macro_rules! soap_request {
    ($req:ty => $resp:ty) => {
        impl $crate::soap::SoapRequest for $req {
            type Response = $resp;
        }
    };
}
