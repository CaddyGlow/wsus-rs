//! Minimal namespace-aware XML tree, parser and deterministic serializer.
//!
//! Names are always compared by namespace URI and local name; prefixes are
//! resolved away at parse time and regenerated on output. The parser rejects
//! `DOCTYPE` (no DTDs, no external or internal entities) and enforces
//! [`Limits`].
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::error::{ProtocolError, Result};

/// Namespace of `xsi:nil` and friends.
pub const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";
/// Namespace bound to the reserved `xml` prefix.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Resource limits applied while decoding. All limits are enforced; none is
/// advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size in bytes of one XML document.
    pub max_body_bytes: usize,
    /// Maximum element nesting depth (the root has depth 1).
    pub max_depth: usize,
    /// Maximum number of items in any single array.
    pub max_array_len: usize,
    /// Maximum number of elements in one document.
    pub max_elements: usize,
    /// Enforce `xs:sequence` ordering of known child elements.
    pub strict_sequence_order: bool,
}

impl Limits {
    /// Limits for stored or imported update metadata documents (as opposed to request bodies).
    /// OBSERVED: a real Windows 11 catalog has Core documents of up to 47 MB (a CBS package manifest
    /// with millions of elements across the catalog), so these are far above the 32 MiB request limits.
    pub fn stored_documents() -> Self {
        Self {
            max_body_bytes: 256 * 1024 * 1024,
            max_elements: 50_000_000,
            ..Self::default()
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 32 * 1024 * 1024,
            max_depth: 64,
            max_array_len: 100_000,
            max_elements: 5_000_000,
            strict_sequence_order: true,
        }
    }
}

/// Namespace-qualified name. `ns == None` means "no namespace".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QName {
    pub ns: Option<String>,
    pub local: String,
}

impl QName {
    /// Name in namespace `ns`.
    pub fn new(ns: &str, local: &str) -> Self {
        Self {
            ns: Some(ns.to_owned()),
            local: local.to_owned(),
        }
    }

    /// Name with no namespace.
    pub fn unqualified(local: &str) -> Self {
        Self {
            ns: None,
            local: local.to_owned(),
        }
    }

    /// True when namespace URI and local name both match.
    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.ns.as_deref() == Some(ns) && self.local == local
    }
}

impl std::fmt::Display for QName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.ns {
            Some(ns) => write!(f, "{{{ns}}}{}", self.local),
            None => f.write_str(&self.local),
        }
    }
}

/// An attribute. Namespace declarations are not attributes and never appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: QName,
    pub value: String,
}

/// Child node of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
}

/// XML element with resolved names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub name: QName,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Node>,
}

impl Element {
    /// New empty element in namespace `ns`.
    pub fn new(ns: &str, local: &str) -> Self {
        Self {
            name: QName::new(ns, local),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// New empty element with no namespace.
    pub fn unqualified(local: &str) -> Self {
        Self {
            name: QName::unqualified(local),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Builder: add an unqualified attribute.
    pub fn with_attr(mut self, local: &str, value: impl Into<String>) -> Self {
        self.attributes.push(Attribute {
            name: QName::unqualified(local),
            value: value.into(),
        });
        self
    }

    /// Builder: add a namespace-qualified attribute.
    pub fn with_ns_attr(mut self, ns: &str, local: &str, value: impl Into<String>) -> Self {
        self.attributes.push(Attribute {
            name: QName::new(ns, local),
            value: value.into(),
        });
        self
    }

    /// Builder: append a child element.
    pub fn with_child(mut self, child: Element) -> Self {
        self.children.push(Node::Element(child));
        self
    }

    /// Builder: append a text node.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.children.push(Node::Text(text.into()));
        self
    }

    /// Append a child element.
    pub fn push(&mut self, child: Element) {
        self.children.push(Node::Element(child));
    }

    /// Value of the unqualified attribute `local`.
    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name.ns.is_none() && a.name.local == local)
            .map(|a| a.value.as_str())
    }

    /// Value of the attribute `{ns}local`.
    pub fn ns_attr(&self, ns: &str, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name.is(ns, local))
            .map(|a| a.value.as_str())
    }

    /// Iterator over child elements.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    /// First child element named `{ns}local`.
    pub fn child(&self, ns: Option<&str>, local: &str) -> Option<&Element> {
        self.elements()
            .find(|e| e.name.ns.as_deref() == ns && e.name.local == local)
    }

    /// Concatenated text content of direct text children.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                s.push_str(t);
            }
        }
        s
    }

    /// True when the element has `xsi:nil` equal to `true` or `1`.
    pub fn is_nil(&self) -> bool {
        matches!(self.ns_attr(XSI_NS, "nil"), Some("true" | "1"))
    }

    /// Serialize deterministically as UTF-8 without an XML declaration.
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(self, false)
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn malformed(e: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::MalformedXml(e.to_string())
}

/// XML 1.0 (5th ed.) NameStartChar, without `:`.
fn is_name_start(c: char) -> bool {
    matches!(c,
        'A'..='Z' | '_' | 'a'..='z'
        | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
        | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

/// XML 1.0 (5th ed.) NameChar, without `:`.
fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

/// True if `s` is a valid NCName (non-empty, no colon).
fn is_ncname(s: &str) -> bool {
    let mut it = s.chars();
    it.next().is_some_and(is_name_start) && it.all(is_name_char)
}

fn ncname<'a>(s: &'a str, what: &str) -> Result<&'a str> {
    if is_ncname(s) {
        Ok(s)
    } else {
        Err(malformed(format!("invalid {what} name `{s}`")))
    }
}

/// Split a raw qualified name into optional prefix and local part, validating both.
fn split_qname<'a>(raw: &'a str, what: &str) -> Result<(Option<&'a str>, &'a str)> {
    match raw.split_once(':') {
        None => Ok((None, ncname(raw, what)?)),
        Some((p, l)) => Ok((Some(ncname(p, what)?), ncname(l, what)?)),
    }
}

/// In-scope namespace declarations, one frame per open element.
#[derive(Default)]
struct NsScopes {
    frames: Vec<Vec<(Option<String>, String)>>,
}

impl NsScopes {
    fn lookup(&self, prefix: Option<&str>) -> Option<&str> {
        self.frames
            .iter()
            .rev()
            .flat_map(|f| f.iter().rev())
            .find(|(p, _)| p.as_deref() == prefix)
            .map(|(_, u)| u.as_str())
    }

    /// Resolve `prefix:local`. Returns (namespace, local name).
    fn resolve(
        &self,
        prefix: Option<&str>,
        local: &str,
        is_attr: bool,
        lenient: bool,
    ) -> Result<(Option<String>, String)> {
        match prefix {
            None if is_attr => Ok((None, local.to_owned())),
            None => Ok((
                self.lookup(None)
                    .filter(|u| !u.is_empty())
                    .map(str::to_owned),
                local.to_owned(),
            )),
            Some("xml") => Ok((Some(XML_NS.to_owned()), local.to_owned())),
            Some(p) => match self.lookup(Some(p)) {
                Some(u) => Ok((Some(u.to_owned()), local.to_owned())),
                None if lenient => Ok((None, format!("{p}:{local}"))),
                None => Err(malformed(format!(
                    "undeclared namespace prefix `{p}` on {}",
                    if is_attr { "attribute" } else { "element" }
                ))),
            },
        }
    }
}

/// Build an element from a start tag, pushing its namespace frame.
fn open_element(
    decoder: quick_xml::encoding::Decoder,
    start: &quick_xml::events::BytesStart<'_>,
    scopes: &mut NsScopes,
    lenient: bool,
) -> Result<Element> {
    let mut frame: Vec<(Option<String>, String)> = Vec::new();
    let mut raw_attrs: Vec<(String, String)> = Vec::new();
    for attr in start.attributes() {
        let attr = attr.map_err(malformed)?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|_| malformed("non-UTF-8 attribute name"))?
            .to_owned();
        let value = attr
            .decode_and_unescape_value(decoder)
            .map_err(|err| ProtocolError::UnsupportedEntity(format!("in attribute: {err}")))?
            .into_owned();
        if key == "xmlns" {
            frame.push((None, value));
        } else if let Some(p) = key.strip_prefix("xmlns:") {
            ncname(p, "namespace prefix")?;
            if p == "xmlns" || (p == "xml" && value != XML_NS) || value.is_empty() {
                return Err(malformed(format!("invalid declaration of prefix `{p}`")));
            }
            frame.push((Some(p.to_owned()), value));
        } else {
            raw_attrs.push((key, value));
        }
    }
    scopes.frames.push(frame);
    let raw_name = std::str::from_utf8(start.name().as_ref())
        .map_err(|_| malformed("non-UTF-8 element name"))?
        .to_owned();
    let (prefix, local) = split_qname(&raw_name, "element")?;
    let (ns, local) = scopes.resolve(prefix, local, false, lenient)?;
    let mut el = Element {
        name: QName { ns, local },
        attributes: Vec::new(),
        children: Vec::new(),
    };
    for (key, value) in raw_attrs {
        let (prefix, local) = split_qname(&key, "attribute")?;
        let (ns, local) = scopes.resolve(prefix, local, true, lenient)?;
        el.attributes.push(Attribute {
            name: QName { ns, local },
            value,
        });
    }
    Ok(el)
}

fn close_element(el: &mut Element) {
    // Whitespace-only text between child elements is formatting, not content.
    if el.elements().next().is_some() {
        el.children
            .retain(|n| !matches!(n, Node::Text(t) if t.trim().is_empty()));
    }
}

/// Parse one XML document into an [`Element`] tree, enforcing `limits`.
///
/// `DOCTYPE` declarations are rejected with [`ProtocolError::DtdNotAllowed`].
/// Only the five predefined entities and numeric character references are
/// accepted. The document must be UTF-8.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Element> {
    parse_impl(input, limits, false)
}

/// Parse a WSUS metadata *fragment sequence* leniently.
///
/// MS-WUSP 3.1.1.1 states that `Core`, `Extended`, `LocalizedProperties` and
/// `Eula` fragments are "not well-formed XML": several sibling elements with
/// no common root, all namespace declarations removed, and applicability
/// elements renamed with `b.`, `m.`, `d.` prefixes. This function accepts
/// that shape: the input is parsed as the content of a synthetic wrapper
/// element, undeclared `prefix:` qualifiers are kept verbatim as part of the
/// local name (no namespace), and the top-level elements are returned in
/// order. The caller keeps the original bytes untouched; nothing here
/// rewrites them.
///
/// Still enforced: body size, depth (the wrapper does not count), element
/// count, DOCTYPE/entity rejection, UTF-8. Top-level non-whitespace text is
/// an error. An XML declaration is tolerated only at the very start.
pub fn parse_fragments(input: &[u8], limits: &Limits) -> Result<Vec<Element>> {
    if input.len() > limits.max_body_bytes {
        return Err(ProtocolError::BodyTooLarge {
            size: input.len(),
            limit: limits.max_body_bytes,
        });
    }
    let mut body = match input {
        [0xEF, 0xBB, 0xBF, rest @ ..] => rest,
        other => other,
    };
    if body.starts_with(b"<?xml")
        && let Some(end) = body.windows(2).position(|w| w == b"?>")
    {
        body = &body[end + 2..];
    }
    const WRAP: &str = "wsus-fragment-wrapper";
    let mut wrapped = Vec::with_capacity(body.len() + 2 * WRAP.len() + 5);
    wrapped.push(b'<');
    wrapped.extend_from_slice(WRAP.as_bytes());
    wrapped.push(b'>');
    wrapped.extend_from_slice(body);
    wrapped.extend_from_slice(b"</");
    wrapped.extend_from_slice(WRAP.as_bytes());
    wrapped.push(b'>');
    let inner = Limits {
        max_depth: limits.max_depth.saturating_add(1),
        max_elements: limits.max_elements.saturating_add(1),
        max_body_bytes: usize::MAX,
        ..limits.clone()
    };
    let root = parse_impl(&wrapped, &inner, true)?;
    if root.name.local != WRAP || root.name.ns.is_some() {
        return Err(malformed("fragment escaped its wrapper"));
    }
    if root
        .children
        .iter()
        .any(|n| matches!(n, Node::Text(t) if !t.trim().is_empty()))
    {
        return Err(malformed("text outside fragment elements"));
    }
    Ok(root
        .children
        .into_iter()
        .filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
        .collect())
}

fn parse_impl(input: &[u8], limits: &Limits, lenient: bool) -> Result<Element> {
    if input.len() > limits.max_body_bytes {
        return Err(ProtocolError::BodyTooLarge {
            size: input.len(),
            limit: limits.max_body_bytes,
        });
    }
    let input = match input {
        [0xEF, 0xBB, 0xBF, rest @ ..] => rest,
        [0xFE, 0xFF, ..] | [0xFF, 0xFE, ..] => {
            return Err(ProtocolError::UnsupportedEncoding("UTF-16".into()));
        }
        other => other,
    };
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    let mut scopes = NsScopes::default();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut count = 0usize;

    loop {
        let event = reader.read_event().map_err(malformed)?;
        match event {
            Event::Start(e) => {
                count += 1;
                check_open(&stack, &root, count, limits)?;
                let el = open_element(reader.decoder(), &e, &mut scopes, lenient)?;
                stack.push(el);
                if stack.len() > limits.max_depth {
                    return Err(ProtocolError::DepthExceeded {
                        limit: limits.max_depth,
                    });
                }
            }
            Event::Empty(e) => {
                count += 1;
                check_open(&stack, &root, count, limits)?;
                if stack.len() + 1 > limits.max_depth {
                    return Err(ProtocolError::DepthExceeded {
                        limit: limits.max_depth,
                    });
                }
                let el = open_element(reader.decoder(), &e, &mut scopes, lenient)?;
                scopes.frames.pop();
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(el)),
                    None => root = Some(el),
                }
            }
            Event::End(_) => {
                let mut el = stack.pop().ok_or_else(|| malformed("unbalanced end tag"))?;
                scopes.frames.pop();
                close_element(&mut el);
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(el)),
                    None => root = Some(el),
                }
            }
            Event::Text(t) => {
                let text = t.decode().map_err(malformed)?;
                push_text(&mut stack, &text)?;
            }
            Event::CData(t) => {
                let text = t.decode().map_err(malformed)?;
                push_text(&mut stack, &text)?;
            }
            Event::GeneralRef(r) => {
                let ch = match r.resolve_char_ref().map_err(malformed)? {
                    Some(c) => c.to_string(),
                    None => {
                        let name = r.decode().map_err(malformed)?;
                        match resolve_predefined_entity(&name) {
                            Some(v) => v.to_owned(),
                            None => {
                                return Err(ProtocolError::UnsupportedEntity(name.into_owned()));
                            }
                        }
                    }
                };
                push_text(&mut stack, &ch)?;
            }
            Event::DocType(_) => return Err(ProtocolError::DtdNotAllowed),
            Event::Decl(d) => {
                if let Some(Ok(enc)) = d.encoding() {
                    let enc = String::from_utf8_lossy(enc.as_ref()).to_ascii_lowercase();
                    if enc != "utf-8" && enc != "utf8" {
                        return Err(ProtocolError::UnsupportedEncoding(enc));
                    }
                }
            }
            Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(malformed("unexpected end of document"));
    }
    root.ok_or_else(|| malformed("empty document"))
}

fn check_open(
    stack: &[Element],
    root: &Option<Element>,
    count: usize,
    limits: &Limits,
) -> Result<()> {
    if count > limits.max_elements {
        return Err(ProtocolError::TooManyElements {
            limit: limits.max_elements,
        });
    }
    if root.is_some() && stack.is_empty() {
        return Err(malformed("multiple root elements"));
    }
    Ok(())
}

fn push_text(stack: &mut [Element], text: &str) -> Result<()> {
    match stack.last_mut() {
        Some(el) => {
            if let Some(Node::Text(last)) = el.children.last_mut() {
                last.push_str(text);
            } else {
                el.children.push(Node::Text(text.to_owned()));
            }
            Ok(())
        }
        None if text.trim().is_empty() => Ok(()),
        None => Err(malformed("text outside the root element")),
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

fn preferred_prefix(uri: &str) -> Option<&'static str> {
    match uri {
        XSI_NS => Some("xsi"),
        "http://schemas.xmlsoap.org/soap/envelope/" | "http://www.w3.org/2003/05/soap-envelope" => {
            Some("soap")
        }
        "http://www.w3.org/2001/XMLSchema" => Some("xsd"),
        _ => None,
    }
}

struct Scope {
    default: Option<String>,
    prefixes: Vec<(String, String)>,
    generated: u32,
}

impl Scope {
    fn prefix_for(&self, uri: &str) -> Option<&str> {
        self.prefixes
            .iter()
            .rev()
            .find(|(_, u)| u == uri)
            .map(|(p, _)| p.as_str())
    }
}

fn escape_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

fn write_element(out: &mut String, el: &Element, scope: &mut Scope) {
    let saved_default = scope.default.clone();
    let saved_prefixes = scope.prefixes.len();
    let mut decls: Vec<(Option<String>, String)> = Vec::new();

    let elem_prefix: Option<String> = match &el.name.ns {
        None => {
            if scope.default.is_some() {
                scope.default = None;
                decls.push((None, String::new()));
            }
            None
        }
        Some(uri) => {
            if scope.default.as_deref() == Some(uri) {
                None
            } else if let Some(p) = scope.prefix_for(uri) {
                Some(p.to_owned())
            } else if let Some(p) = preferred_prefix(uri) {
                scope.prefixes.push((p.to_owned(), uri.clone()));
                decls.push((Some(p.to_owned()), uri.clone()));
                Some(p.to_owned())
            } else {
                scope.default = Some(uri.clone());
                decls.push((None, uri.clone()));
                None
            }
        }
    };

    let mut attrs: Vec<(String, &str)> = Vec::new();
    for a in &el.attributes {
        let qname = match &a.name.ns {
            None => a.name.local.clone(),
            Some(uri) if uri == XML_NS => format!("xml:{}", a.name.local),
            Some(uri) => {
                let prefix = if let Some(p) = scope.prefix_for(uri) {
                    p.to_owned()
                } else {
                    let p = match preferred_prefix(uri) {
                        Some(p) => p.to_owned(),
                        None => {
                            scope.generated += 1;
                            format!("ns{}", scope.generated)
                        }
                    };
                    scope.prefixes.push((p.clone(), uri.clone()));
                    decls.push((Some(p.clone()), uri.clone()));
                    p
                };
                format!("{prefix}:{}", a.name.local)
            }
        };
        attrs.push((qname, a.value.as_str()));
    }

    let qname = match &elem_prefix {
        Some(p) => format!("{p}:{}", el.name.local),
        None => el.name.local.clone(),
    };
    out.push('<');
    out.push_str(&qname);
    for (p, uri) in &decls {
        match p {
            None => out.push_str(" xmlns=\""),
            Some(p) => {
                out.push_str(" xmlns:");
                out.push_str(p);
                out.push_str("=\"");
            }
        }
        escape_attr(out, uri);
        out.push('"');
    }
    for (k, v) in attrs {
        out.push(' ');
        out.push_str(&k);
        out.push_str("=\"");
        escape_attr(out, v);
        out.push('"');
    }
    if el.children.is_empty() {
        out.push_str("/>");
    } else {
        out.push('>');
        for n in &el.children {
            match n {
                Node::Text(t) => escape_text(out, t),
                Node::Element(c) => write_element(out, c, scope),
            }
        }
        out.push_str("</");
        out.push_str(&qname);
        out.push('>');
    }
    scope.default = saved_default;
    scope.prefixes.truncate(saved_prefixes);
}

/// Serialize an element tree deterministically (UTF-8). The same tree always
/// yields the same bytes; prefixes are chosen by this serializer, never taken
/// from a previous parse.
pub fn serialize(el: &Element, xml_declaration: bool) -> Vec<u8> {
    let mut out = String::new();
    if xml_declaration {
        out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
    }
    let mut scope = Scope {
        default: None,
        prefixes: Vec::new(),
        generated: 0,
    };
    write_element(&mut out, el, &mut scope);
    out.into_bytes()
}
