//! `XmlUpdateBlobCompressed` decoding.
//!
//! Observed 2026-10-04 against a real WSUS (Windows Server 2025 build
//! 10.0.26100, inventory section 9.5): the blob is a Microsoft Cabinet (`MSCF`)
//! holding exactly one folder compressed with LZX and exactly one member named
//! `blob`, whose bytes are the update document in UTF-16LE without a byte
//! order mark and without an XML declaration. [`CabMetadataDecompressor`] reads
//! that shape with `cabinet` and returns UTF-8, which is what the rest of the
//! workspace stores. The [`MetadataDecompressor`] trait stays so a caller can
//! inject another decoder.
use std::fmt;
use std::io::Cursor;

/// Upper bound on one decompressed update document (bytes of the UTF-16LE
/// member). Real Defender and Office documents were 7 to 15 KiB; a real Windows 11 catalog has Core
/// documents of up to 47 MB (94 MB as UTF-16LE), so the bound is 256 MiB.
pub const MAX_METADATA_BYTES: usize = 256 * 1024 * 1024;

/// Failure to decompress a metadata blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompressError(pub String);

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecompressError {}

/// Decompresses `XmlUpdateBlobCompressed` into the update XML document.
pub trait MetadataDecompressor: Send + Sync {
    /// Return the XML bytes.
    fn decompress(&self, compressed: &[u8]) -> Result<Vec<u8>, DecompressError>;
}

/// Refuses every blob with an explicit message (for tests and callers that
/// want metadata-only behaviour to fail loudly).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedDecompressor;

impl MetadataDecompressor for UnsupportedDecompressor {
    fn decompress(&self, _compressed: &[u8]) -> Result<Vec<u8>, DecompressError> {
        Err(DecompressError(
            "XmlUpdateBlobCompressed format is unverified and no decompressor is configured".into(),
        ))
    }
}

/// Decoder for the observed real-WSUS blob: a Cabinet with one member of
/// UTF-16LE XML. Output is bounded by `max_bytes`.
#[derive(Debug, Clone, Copy)]
pub struct CabMetadataDecompressor {
    /// Largest accepted decompressed member.
    pub max_bytes: usize,
}

impl Default for CabMetadataDecompressor {
    fn default() -> Self {
        Self {
            max_bytes: MAX_METADATA_BYTES,
        }
    }
}

fn utf16le_or_utf8(raw: Vec<u8>) -> Result<Vec<u8>, DecompressError> {
    let bad = |m: &str| DecompressError(m.to_owned());
    // UTF-8 (with or without BOM): the first byte is '<' followed by a
    // non-zero byte. Anything else is read as UTF-16LE, the observed form.
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Ok(raw[3..].to_vec());
    }
    if raw.len() >= 2 && raw[0] == b'<' && raw[1] != 0 {
        return Ok(raw);
    }
    let body = if raw.starts_with(&[0xFF, 0xFE]) {
        &raw[2..]
    } else {
        &raw[..]
    };
    if body.len() % 2 != 0 {
        return Err(bad("metadata member has an odd length for UTF-16LE"));
    }
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units)
        .map(String::into_bytes)
        .map_err(|_| bad("metadata member is not valid UTF-16LE"))
}

impl MetadataDecompressor for CabMetadataDecompressor {
    fn decompress(&self, compressed: &[u8]) -> Result<Vec<u8>, DecompressError> {
        let fail = |m: &str, e: &dyn fmt::Display| DecompressError(format!("{m}: {e}"));
        let mut cab = cabinet::Cabinet::new(Cursor::new(compressed))
            .map_err(|e| fail("blob is not a readable cabinet", &e))?;
        let entries = cab.entries();
        if entries.len() != 1 {
            return Err(DecompressError(format!(
                "cabinet holds {} members, expected exactly 1",
                entries.len()
            )));
        }
        let name = entries[0].name.clone();
        let raw = cab
            .read_file_bytes(&name, self.max_bytes)
            .map_err(|e| fail("cabinet member cannot be read", &e))?;
        utf16le_or_utf8(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_member_becomes_utf8() {
        let raw: Vec<u8> = "<a>\u{e9}</a>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(utf16le_or_utf8(raw).unwrap(), "<a>\u{e9}</a>".as_bytes());
    }

    #[test]
    fn utf8_member_is_kept_and_bad_input_is_rejected() {
        assert_eq!(utf16le_or_utf8(b"<a/>".to_vec()).unwrap(), b"<a/>");
        assert!(utf16le_or_utf8(vec![0x3c, 0x00, 0x61]).is_err());
        assert!(
            CabMetadataDecompressor::default()
                .decompress(b"not a cab")
                .is_err()
        );
    }
}
