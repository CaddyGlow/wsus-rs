//! Redaction helpers: cookies, credentials and signed URLs must never reach
//! `Debug`, `Display` or log output.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Wrapper whose `Debug` output never reveals the value. Serialization is
/// transparent so that protected stores can persist the value deliberately.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps a sensitive value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Explicitly exposes the value.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper and returns the value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Secret byte string persisted as lowercase hexadecimal.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps sensitive bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Explicitly exposes the bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::download::hex_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        crate::download::hex_decode(&text)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("invalid hexadecimal"))
    }
}

/// Error for URLs rejected by [`SensitiveUrl::parse`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid http(s) URL")]
pub struct InvalidUrl;

/// An absolute http(s) URL that may carry credentials or a signature. `Debug`
/// and `Display` print only `scheme://host[:port]/...`.
#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveUrl(String);

impl SensitiveUrl {
    /// Validates scheme, host and the absence of whitespace or control characters.
    pub fn parse(url: &str) -> Result<Self, InvalidUrl> {
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .ok_or(InvalidUrl)?;
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(InvalidUrl);
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = authority.rsplit('@').next().unwrap_or("");
        if host.is_empty() || host.starts_with(':') {
            return Err(InvalidUrl);
        }
        Ok(Self(url.to_owned()))
    }

    /// Explicitly exposes the full URL for use by a transport backend.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Redacted representation safe for logs.
    pub fn redacted(&self) -> String {
        redact_url(&self.0)
    }
}

impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl fmt::Display for SensitiveUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

/// Reduces a URL to `scheme://host[:port]/...`, dropping userinfo, path, query
/// and fragment. Text that is not an http(s) URL becomes `<redacted-url>`.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return "<redacted-url>".to_owned();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    format!("{scheme}://{host}/...")
}

/// Replaces every http(s) URL inside free text with its redacted form.
pub fn scrub_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = ["https://", "http://"]
        .iter()
        .filter_map(|p| rest.find(p))
        .min()
    {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | ']'))
            .unwrap_or(tail.len());
        out.push_str(&redact_url(&tail[..end]));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// True for header names whose values are credentials or session material.
pub fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cookie"
            | "set-cookie"
            | "authorization"
            | "proxy-authorization"
            | "www-authenticate"
            | "proxy-authenticate"
            | "x-api-key"
            | "location"
    )
}

/// Returns the value, or `<redacted>` when the header is sensitive.
pub fn redact_header_value<'a>(name: &str, value: &'a str) -> &'a str {
    if is_sensitive_header(name) {
        "<redacted>"
    } else {
        value
    }
}
