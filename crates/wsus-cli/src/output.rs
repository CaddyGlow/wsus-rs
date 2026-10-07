//! Command results: a JSON value plus a success flag, rendered as text or JSON.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::fmt::Write as _;
use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};

/// Result of a command. `ok == false` yields a non-zero exit status after the
/// value was printed (partial failure that still has data to show).
#[derive(Debug, Clone)]
pub struct Output {
    pub value: Value,
    pub ok: bool,
}

impl Output {
    pub fn ok(value: Value) -> Self {
        Self { value, ok: true }
    }

    pub fn with_ok(value: Value, ok: bool) -> Self {
        Self { value, ok }
    }
}

/// Renders a JSON value as indented `key: value` lines.
pub fn render_text(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("-".into()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn write_value(out: &mut String, value: &Value, depth: usize) {
    let pad = "  ".repeat(depth);
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                match scalar(v) {
                    Some(s) => {
                        let _ = writeln!(out, "{pad}{k}: {s}");
                    }
                    None if is_empty(v) => {
                        let _ = writeln!(out, "{pad}{k}: (none)");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}{k}:");
                        write_value(out, v, depth + 1);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match scalar(item) {
                    Some(s) => {
                        let _ = writeln!(out, "{pad}- {s}");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}-");
                        write_value(out, item, depth + 1);
                    }
                }
            }
        }
        other => {
            let _ = writeln!(out, "{pad}{}", scalar(other).unwrap_or_default());
        }
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// Parses `UUID` or `UUID@REVISION` (the display form of an identity).
pub fn parse_update_ref(text: &str) -> Result<(UpdateId, Option<Revision>)> {
    let (id, rev) = match text.split_once('@') {
        Some((id, rev)) => (id, Some(rev)),
        None => (text, None),
    };
    let uuid = Uuid::parse_str(id).with_context(|| format!("`{id}` is not an update GUID"))?;
    let revision = match rev {
        Some(r) => {
            Some(Revision(r.parse().with_context(|| {
                format!("`{r}` is not a revision number")
            })?))
        }
        None => None,
    };
    Ok((UpdateId(uuid), revision))
}

/// Parses a full `UUID@REVISION`.
pub fn parse_update_revision(text: &str) -> Result<UpdateRevision> {
    match parse_update_ref(text)? {
        (id, Some(revision)) => Ok(UpdateRevision { id, revision }),
        _ => bail!("`{text}` needs a revision: use UUID@REVISION"),
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
