//! Serializer for fragment trees.
//!
//! WUSP fragments carry no namespace declarations, so the generic serializer in
//! `wsus-protocol` (which declares every namespace it needs) cannot be used. Trees handed to
//! this writer are fully "flattened": every name is a plain local name that already holds
//! its `b.`/`m.`/`d.` prefix, and no name carries a namespace.
use wsus_protocol::soap::xml::{Element, Node};

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

fn write_element(out: &mut String, el: &Element) {
    debug_assert!(el.name.ns.is_none(), "fragment trees are namespace-free");
    out.push('<');
    out.push_str(&el.name.local);
    for a in &el.attributes {
        out.push(' ');
        out.push_str(&a.name.local);
        out.push_str("=\"");
        escape_attr(out, &a.value);
        out.push('"');
    }
    if el.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    for n in &el.children {
        match n {
            Node::Text(t) => escape_text(out, t),
            Node::Element(c) => write_element(out, c),
        }
    }
    out.push_str("</");
    out.push_str(&el.name.local);
    out.push('>');
}

/// Concatenate flattened elements with nothing between them (MS-WUSP: a fragment is the
/// concatenation of its elements).
pub(crate) fn write_sequence<'a>(elements: impl IntoIterator<Item = &'a Element>) -> Vec<u8> {
    let mut out = String::new();
    for e in elements {
        write_element(&mut out, e);
    }
    out.into_bytes()
}
