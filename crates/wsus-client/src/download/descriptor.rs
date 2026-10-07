//! Expected content descriptor and file name validation.

use super::{DownloadError, digest::hex_encode};
use sha2::{Digest, Sha256};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest};

/// Expected digest length in bytes for an algorithm.
pub fn digest_len(algorithm: DigestAlgorithm) -> usize {
    match algorithm {
        DigestAlgorithm::Sha1 => 20,
        DigestAlgorithm::Sha256 => 32,
        DigestAlgorithm::Sha512 => 64,
    }
}

fn algorithm_tag(algorithm: DigestAlgorithm) -> u8 {
    match algorithm {
        DigestAlgorithm::Sha1 => 1,
        DigestAlgorithm::Sha256 => 2,
        DigestAlgorithm::Sha512 => 3,
    }
}

/// Validates a single path component supplied by a server.
///
/// Rejects empty names, separators, drive/stream colons, control characters,
/// `.`/`..`, trailing dots or spaces, Windows reserved device names and names
/// over 255 bytes, so a name is safe on both Linux and Windows.
pub fn validate_file_name(name: &str) -> Result<(), DownloadError> {
    let bad = |reason: &'static str| Err(DownloadError::InvalidFileName(reason));
    if name.is_empty() || name.len() > 255 {
        return bad("empty or too long");
    }
    if name == "." || name == ".." {
        return bad("dot component");
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return bad("forbidden character");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return bad("trailing dot or space");
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|p| {
            stem.strip_prefix(p)
                .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit() && n != "0")
        });
    if reserved {
        return bad("reserved device name");
    }
    Ok(())
}

/// What a download must produce: a validated name, exact length and digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFile {
    file_name: String,
    length: u64,
    digests: Vec<FileDigest>,
}

impl ExpectedFile {
    /// Validates the descriptor. At least one digest is required, digest sizes
    /// must match their algorithm and an algorithm may appear only once.
    pub fn new(
        file_name: &str,
        length: u64,
        mut digests: Vec<FileDigest>,
    ) -> Result<Self, DownloadError> {
        validate_file_name(file_name)?;
        if digests.is_empty() {
            return Err(DownloadError::InvalidDescriptor("no digest supplied"));
        }
        digests.sort_by_key(|d| algorithm_tag(d.algorithm));
        for pair in digests.windows(2) {
            if pair[0].algorithm == pair[1].algorithm {
                return Err(DownloadError::InvalidDescriptor(
                    "duplicate digest algorithm",
                ));
            }
        }
        if digests
            .iter()
            .any(|d| d.bytes.len() != digest_len(d.algorithm))
        {
            return Err(DownloadError::InvalidDescriptor("digest has wrong size"));
        }
        Ok(Self {
            file_name: file_name.to_owned(),
            length,
            digests,
        })
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    /// Digests sorted by algorithm.
    pub fn digests(&self) -> &[FileDigest] {
        &self.digests
    }

    /// Stable lowercase-hex identifier of the content (length and digests; not
    /// the file name), used for partial and complete object paths.
    pub fn content_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"wsus-content-v1\0");
        hasher.update(self.length.to_le_bytes());
        for digest in &self.digests {
            hasher.update([algorithm_tag(digest.algorithm)]);
            hasher.update(&digest.bytes);
        }
        hex_encode(&hasher.finalize())
    }
}
