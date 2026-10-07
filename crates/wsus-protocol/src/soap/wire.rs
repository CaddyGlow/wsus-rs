//! Schema-level helpers shared by every typed message: presence tracking
//! (absent / nil / value), scalar lexical forms, ordered field reading and
//! field writing.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;

use super::xml::{Element, Limits, Node, XSI_NS};
use crate::error::{ProtocolError, Result};

/// State of an optional element.
///
/// XML Schema distinguishes an element that is missing (`Absent`), present
/// with `xsi:nil="true"` (`Nil`) and present with content (`Value`). For
/// strings an empty element is `Value(String::new())`, for arrays an empty
/// wrapper element is `Value(vec![])`. Codecs preserve all three states.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Presence<T> {
    /// The element is not present.
    #[default]
    Absent,
    /// The element is present with `xsi:nil="true"`.
    Nil,
    /// The element is present with a value.
    Value(T),
}

impl<T> Presence<T> {
    /// Borrow the value, if any (`Absent` and `Nil` both give `None`).
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Value(v) => Some(v),
            _ => None,
        }
    }

    /// Take the value, if any.
    pub fn into_value(self) -> Option<T> {
        match self {
            Self::Value(v) => Some(v),
            _ => None,
        }
    }

    /// True for `Absent`.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// True for `Nil`.
    pub fn is_nil(&self) -> bool {
        matches!(self, Self::Nil)
    }

    /// True for `Value`.
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }

    /// Map the contained value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Presence<U> {
        match self {
            Self::Absent => Presence::Absent,
            Self::Nil => Presence::Nil,
            Self::Value(v) => Presence::Value(f(v)),
        }
    }
}

impl<T> From<T> for Presence<T> {
    fn from(v: T) -> Self {
        Self::Value(v)
    }
}

impl From<&str> for Presence<String> {
    fn from(v: &str) -> Self {
        Self::Value(v.to_owned())
    }
}

/// Decoding context.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    /// Limits in force.
    pub limits: &'a Limits,
}

/// Types with an XML representation inside a message.
pub trait WireType: Sized {
    /// Encode as an element `{ns}name`.
    fn to_xml(&self, ns: &str, name: &str) -> Element;
    /// Decode from an element; the element name is not checked here.
    fn from_xml(el: &Element, ctx: &Ctx<'_>) -> Result<Self>;
}

/// Scalar with a lexical text form.
pub trait Scalar: Sized {
    /// Human name of the schema type, for diagnostics.
    const KIND: &'static str;
    /// Parse the lexical form.
    fn parse(text: &str) -> Option<Self>;
    /// Canonical lexical form.
    fn format(&self) -> String;
}

impl<T: Scalar> WireType for T {
    fn to_xml(&self, ns: &str, name: &str) -> Element {
        Element::new(ns, name).with_text(self.format())
    }

    fn from_xml(el: &Element, _ctx: &Ctx<'_>) -> Result<Self> {
        let text = el.text();
        T::parse(&text).ok_or_else(|| ProtocolError::InvalidValue {
            element: el.name.local.clone(),
            kind: T::KIND,
            value: text,
        })
    }
}

impl Scalar for String {
    const KIND: &'static str = "string";
    fn parse(text: &str) -> Option<Self> {
        Some(text.to_owned())
    }
    fn format(&self) -> String {
        self.clone()
    }
}

impl Scalar for bool {
    const KIND: &'static str = "boolean";
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        }
    }
    fn format(&self) -> String {
        if *self { "true" } else { "false" }.to_owned()
    }
}

macro_rules! int_scalar {
    ($($t:ty => $k:literal),*) => {$(
        impl Scalar for $t {
            const KIND: &'static str = $k;
            fn parse(text: &str) -> Option<Self> { text.trim().parse().ok() }
            fn format(&self) -> String { self.to_string() }
        }
    )*};
}
int_scalar!(i16 => "short", i32 => "int", i64 => "long", u8 => "unsignedByte", u32 => "unsignedInt");

impl Scalar for Uuid {
    const KIND: &'static str = "guid";
    fn parse(text: &str) -> Option<Self> {
        let t = text.trim();
        // The schema pattern is exactly the 8-4-4-4-12 hyphenated form.
        if t.len() != 36 {
            return None;
        }
        Uuid::parse_str(t).ok()
    }
    fn format(&self) -> String {
        self.hyphenated().to_string()
    }
}

impl Scalar for Vec<u8> {
    const KIND: &'static str = "base64Binary";
    fn parse(text: &str) -> Option<Self> {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        STANDARD.decode(compact.as_bytes()).ok()
    }
    fn format(&self) -> String {
        STANDARD.encode(self)
    }
}

/// `xs:dateTime` lexical value, kept verbatim.
///
/// WSUS peers send values with and without a time-zone designator, so the
/// text is validated for shape and preserved rather than converted; callers
/// that need an instant convert it with the date-time library of their
/// choice.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XsDateTime(String);

impl XsDateTime {
    /// Validate and wrap a lexical value.
    pub fn new(text: &str) -> Option<Self> {
        Self::parse(text)
    }

    /// The lexical value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Scalar for XsDateTime {
    const KIND: &'static str = "dateTime";
    fn parse(text: &str) -> Option<Self> {
        let t = text.trim();
        let b = t.as_bytes();
        let mut i = 0;
        if b.first() == Some(&b'-') {
            i = 1;
        }
        let digits = |b: &[u8], from: usize, n: usize| -> bool {
            b.len() >= from + n && b[from..from + n].iter().all(u8::is_ascii_digit)
        };
        let ystart = i;
        while digits(b, i, 1) {
            i += 1;
        }
        if i - ystart < 4 {
            return None;
        }
        let pat = [(b'-', 2usize), (b'-', 2), (b'T', 2), (b':', 2), (b':', 2)];
        for (sep, n) in pat {
            if b.get(i) != Some(&sep) || !digits(b, i + 1, n) {
                return None;
            }
            i += 1 + n;
        }
        if b.get(i) == Some(&b'.') {
            let s = i + 1;
            i = s;
            while digits(b, i, 1) {
                i += 1;
            }
            if i == s {
                return None;
            }
        }
        match b.get(i) {
            None => {}
            Some(b'Z') if i + 1 == b.len() => {}
            Some(b'+' | b'-')
                if digits(b, i + 1, 2)
                    && b.get(i + 3) == Some(&b':')
                    && digits(b, i + 4, 2)
                    && i + 6 == b.len() => {}
            _ => return None,
        }
        Some(Self(t.to_owned()))
    }
    fn format(&self) -> String {
        self.0.clone()
    }
}

/// Build a nil element `{ns}name` (`xsi:nil="true"`).
pub fn nil_element(ns: &str, name: &str) -> Element {
    Element::new(ns, name).with_ns_attr(XSI_NS, "nil", "true")
}

/// Namespaces in which the WSDLs place WSUS operations and types.
///
/// Implementation decision (inventory section 8, item 3): the specification
/// puts `Cookie`, `AuthorizationCookie` and `UpdateIdentity` in
/// `http://www.microsoft.com/SoftwareDistribution` in prose but in the
/// operation namespace in the WSDL. Decoders therefore treat all of these
/// namespaces as interchangeable for the *children of a type element*;
/// encoders follow the WSDL and put every child in its parent's namespace.
pub const WSUS_NAMESPACES: [&str; 5] = [
    "http://www.microsoft.com/SoftwareDistribution",
    "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService",
    "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService",
    "http://www.microsoft.com/SoftwareDistribution/Server/DssAuthWebService",
    "http://www.microsoft.com/SoftwareDistribution/Server/IMonitorable",
];

/// SOAP 1.1 encoding namespace (for `soapenc:arrayType`).
pub const SOAPENC_NS: &str = "http://schemas.xmlsoap.org/soap/encoding/";

/// True when a child's namespace is acceptable inside `parent`.
fn same_family(parent: &Option<String>, child: &Option<String>) -> bool {
    if parent == child {
        return true;
    }
    match (parent.as_deref(), child.as_deref()) {
        (Some(p), Some(c)) => WSUS_NAMESPACES.contains(&p) && WSUS_NAMESPACES.contains(&c),
        _ => false,
    }
}

/// Child lookup within a parent: children share the parent's namespace, or
/// any other WSUS namespace (see [`WSUS_NAMESPACES`]). An exact-namespace
/// match wins.
fn child_of<'a>(parent: &'a Element, name: &str) -> Option<&'a Element> {
    parent.child(parent.name.ns.as_deref(), name).or_else(|| {
        parent
            .elements()
            .find(|c| c.name.local == name && same_family(&parent.name.ns, &c.name.ns))
    })
}

/// Opaque XML kept as a tree (for schema types the WSDL leaves empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opaque(pub Element);

impl WireType for Opaque {
    fn to_xml(&self, ns: &str, name: &str) -> Element {
        let mut e = self.0.clone();
        e.name = super::xml::QName::new(ns, name);
        e
    }
    fn from_xml(el: &Element, _ctx: &Ctx<'_>) -> Result<Self> {
        Ok(Self(el.clone()))
    }
}

/// Ordered reader for the children of one `xs:sequence` element.
pub struct Fields<'a> {
    el: &'a Element,
    ctx: &'a Ctx<'a>,
}

impl<'a> Fields<'a> {
    /// Start reading `el`. `order` lists the schema's child names in order;
    /// children of the same namespace that are not listed are ignored.
    /// Duplicates always fail; order is checked when
    /// [`Limits::strict_sequence_order`] is set.
    pub fn new(el: &'a Element, ctx: &'a Ctx<'a>, order: &[&str]) -> Result<Self> {
        let mut last: Option<usize> = None;
        let mut seen: Vec<usize> = Vec::new();
        for c in el.elements() {
            if !same_family(&el.name.ns, &c.name.ns) {
                continue;
            }
            let Some(idx) = order.iter().position(|n| *n == c.name.local) else {
                continue;
            };
            if seen.contains(&idx) {
                return Err(ProtocolError::DuplicateElement(c.name.local.clone()));
            }
            if ctx.limits.strict_sequence_order && last.is_some_and(|l| idx < l) {
                return Err(ProtocolError::OutOfOrder {
                    parent: el.name.local.clone(),
                    found: c.name.local.clone(),
                });
            }
            seen.push(idx);
            last = Some(last.map_or(idx, |l| l.max(idx)));
        }
        Ok(Self { el, ctx })
    }

    /// Required, non-nillable child.
    pub fn req<T: WireType>(&self, name: &str) -> Result<T> {
        match child_of(self.el, name) {
            None => Err(ProtocolError::MissingElement(name.to_owned())),
            Some(c) if c.is_nil() => Err(ProtocolError::UnexpectedNil(name.to_owned())),
            Some(c) => T::from_xml(c, self.ctx),
        }
    }

    /// Optional child preserving absent / nil / value.
    pub fn opt<T: WireType>(&self, name: &str) -> Result<Presence<T>> {
        match child_of(self.el, name) {
            None => Ok(Presence::Absent),
            Some(c) if c.is_nil() => Ok(Presence::Nil),
            Some(c) => Ok(Presence::Value(T::from_xml(c, self.ctx)?)),
        }
    }

    /// Optional wrapper element holding repeated `item` children.
    pub fn opt_array<T: WireType>(&self, name: &str, item: &str) -> Result<Presence<Vec<T>>> {
        match child_of(self.el, name) {
            None => Ok(Presence::Absent),
            Some(c) if c.is_nil() => Ok(Presence::Nil),
            Some(c) => Ok(Presence::Value(read_array(c, item, self.ctx)?)),
        }
    }

    /// Required wrapper element holding repeated `item` children.
    pub fn req_array<T: WireType>(&self, name: &str, item: &str) -> Result<Vec<T>> {
        match child_of(self.el, name) {
            None => Err(ProtocolError::MissingElement(name.to_owned())),
            Some(c) if c.is_nil() => Err(ProtocolError::UnexpectedNil(name.to_owned())),
            Some(c) => read_array(c, item, self.ctx),
        }
    }

    /// The raw child element, for hand-written decoding.
    pub fn raw(&self, name: &str) -> Option<&'a Element> {
        child_of(self.el, name)
    }
}

/// Read the `item` children of an array wrapper, enforcing the array limit.
///
/// Implementation decision (inventory section 8, item 7): the WSDL uses
/// literal sequences of `item` elements, the specification examples use
/// SOAP-encoded arrays (`soapenc:arrayType`). A wrapper carrying
/// `soapenc:arrayType` is read as "every child element is an item, whatever
/// its name"; otherwise only children named `item` are items. Encoders
/// always emit the literal form.
pub fn read_array<T: WireType>(wrapper: &Element, item: &str, ctx: &Ctx<'_>) -> Result<Vec<T>> {
    let mut out = Vec::new();
    let encoded = wrapper.ns_attr(SOAPENC_NS, "arrayType").is_some();
    for c in wrapper.elements() {
        let matches = if encoded {
            true
        } else {
            c.name.local == item && same_family(&wrapper.name.ns, &c.name.ns)
        };
        if !matches {
            continue;
        }
        if out.len() >= ctx.limits.max_array_len {
            return Err(ProtocolError::ArrayTooLong {
                name: wrapper.name.local.clone(),
                limit: ctx.limits.max_array_len,
            });
        }
        if c.is_nil() {
            return Err(ProtocolError::UnexpectedNil(item.to_owned()));
        }
        out.push(T::from_xml(c, ctx)?);
    }
    Ok(out)
}

/// Append a required child using the parent's namespace.
pub fn put<T: WireType>(parent: &mut Element, name: &str, v: &T) {
    let ns = parent.name.ns.clone().unwrap_or_default();
    parent.push(v.to_xml(&ns, name));
}

/// Append an optional child, honouring absent / nil / value.
pub fn put_opt<T: WireType>(parent: &mut Element, name: &str, v: &Presence<T>) {
    let ns = parent.name.ns.clone().unwrap_or_default();
    match v {
        Presence::Absent => {}
        Presence::Nil => parent.push(nil_element(&ns, name)),
        Presence::Value(v) => parent.push(v.to_xml(&ns, name)),
    }
}

/// Build an array wrapper element `{ns}name` holding `item` children.
pub fn array_element<T: WireType>(ns: &str, name: &str, item: &str, v: &[T]) -> Element {
    let mut w = Element::new(ns, name);
    for x in v {
        w.push(x.to_xml(ns, item));
    }
    w
}

/// Append an optional array wrapper child.
pub fn put_array<T: WireType>(parent: &mut Element, name: &str, item: &str, v: &Presence<Vec<T>>) {
    let ns = parent.name.ns.clone().unwrap_or_default();
    match v {
        Presence::Absent => {}
        Presence::Nil => parent.push(nil_element(&ns, name)),
        Presence::Value(items) => parent.push(array_element(&ns, name, item, items)),
    }
}

/// Append a required array wrapper child.
pub fn put_req_array<T: WireType>(parent: &mut Element, name: &str, item: &str, v: &[T]) {
    let ns = parent.name.ns.clone().unwrap_or_default();
    parent.push(array_element(&ns, name, item, v));
}

/// True if `node` is an element (helper for tests and decoders).
pub fn is_element(node: &Node) -> bool {
    matches!(node, Node::Element(_))
}
