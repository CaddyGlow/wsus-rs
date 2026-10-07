//! Text sanitization applied to every log line, trace record, diagnostic file
//! and printed error.
//!
//! Defense in depth: the protocol crates already keep secrets out of their own
//! `Debug` and error output. This pass catches what slips through free text:
//! URLs (reduced to scheme and host), values of credential-like keys, and long
//! base64-looking blobs (cookie payloads, keys).

use wsus_client::transport::scrub_urls;

/// Marker substituted for removed values.
pub const REDACTED: &str = "<redacted>";

const SENSITIVE_KEYS: &[&str] = &[
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "sig",
    "signature",
    "key",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "encrypteddata",
    "encrypted_data",
    "decryptionkey",
    "decryption_key",
    "authorizationcookie",
    "accountguid",
    "account_guid",
];

fn is_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_blob_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn value_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len()
        && !matches!(
            bytes[i],
            b' ' | b'\t' | b'\r' | b'\n' | b'&' | b',' | b'"' | b';' | b'}' | b')' | b'\''
        )
    {
        i += 1;
    }
    i
}

/// Redacts the value following any sensitive key (`key=value`, `key: value`,
/// `"key":"value"`).
fn scrub_keys(text: &str) -> String {
    let bytes = text.as_bytes();
    let lower = text.to_ascii_lowercase();
    let lower = lower.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        if !is_key_char(bytes[i]) || (i > 0 && is_key_char(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let mut hit = None;
        for key in SENSITIVE_KEYS {
            let k = key.as_bytes();
            if lower[i..].starts_with(k) && !lower.get(i + k.len()).is_some_and(|b| is_key_char(*b))
            {
                hit = Some(k.len());
                break;
            }
        }
        let Some(len) = hit else {
            // Skip the rest of this word.
            while i < bytes.len() && is_key_char(bytes[i]) {
                i += 1;
            }
            continue;
        };
        let mut j = i + len;
        if bytes.get(j) == Some(&b'"') {
            j += 1;
        }
        while bytes.get(j) == Some(&b' ') {
            j += 1;
        }
        if !matches!(bytes.get(j), Some(b'=') | Some(b':')) {
            i += len;
            continue;
        }
        j += 1;
        while bytes.get(j) == Some(&b' ') {
            j += 1;
        }
        if bytes.get(j) == Some(&b'"') {
            j += 1;
        }
        let end = value_end(bytes, j);
        if end == j {
            i = j;
            continue;
        }
        out.push_str(&text[copied..j]);
        out.push_str(REDACTED);
        copied = end;
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// Replaces long base64-like runs that are not plain hexadecimal digests.
fn scrub_blobs(text: &str) -> String {
    const MIN: usize = 64;
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        if !is_blob_char(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_blob_char(bytes[i]) {
            i += 1;
        }
        let run = &bytes[start..i];
        if run.len() >= MIN && !run.iter().all(u8::is_ascii_hexdigit) {
            out.push_str(&text[copied..start]);
            out.push_str("<redacted-blob>");
            copied = i;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// Full sanitization of free text.
pub fn sanitize(text: &str) -> String {
    scrub_blobs(&scrub_keys(&scrub_urls(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_keys_and_blobs_are_removed() {
        let s = sanitize("GET https://h.example/a?sig=abc&x=1 Cookie: abc123 token=zzz ok=1");
        assert!(!s.contains("sig=abc") && !s.contains("abc123") && !s.contains("zzz"));
        assert!(s.contains("ok=1"));
        let blob = "A".repeat(10) + &"b+/".repeat(30);
        assert!(sanitize(&format!("data {blob} end")).contains("<redacted-blob>"));
        let digest = "0123456789abcdef".repeat(4);
        assert!(
            sanitize(&digest).contains(&digest),
            "hex digests are evidence"
        );
    }

    #[test]
    fn json_style_values_and_word_boundaries() {
        let s = sanitize(r#"{"cookie":"SECRETVALUE","monkey":"banana","dedup_key":"k1"}"#);
        assert!(!s.contains("SECRETVALUE"));
        assert!(s.contains("banana") && s.contains("k1"));
    }
}
