//! Hex helpers and incremental multi-digest computation.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use wsus_protocol::identity::{DigestAlgorithm, FileDigest};

/// Lowercase hexadecimal encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

/// Decodes hexadecimal text of either case; `None` on odd length or bad digit.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// Computes every digest a descriptor requires in one pass.
#[derive(Clone)]
pub struct Hashers {
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
}

impl Hashers {
    pub fn for_digests(digests: &[FileDigest]) -> Self {
        let wants = |a| digests.iter().any(|d| d.algorithm == a);
        Self {
            sha1: wants(DigestAlgorithm::Sha1).then(Sha1::new),
            sha256: wants(DigestAlgorithm::Sha256).then(Sha256::new),
            sha512: wants(DigestAlgorithm::Sha512).then(Sha512::new),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if let Some(h) = &mut self.sha1 {
            h.update(data);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(data);
        }
        if let Some(h) = &mut self.sha512 {
            h.update(data);
        }
    }

    /// Returns the first expected digest that does not match, if any.
    pub fn mismatch(self, expected: &[FileDigest]) -> Option<DigestAlgorithm> {
        let sha1 = self.sha1.map(|h| h.finalize().to_vec());
        let sha256 = self.sha256.map(|h| h.finalize().to_vec());
        let sha512 = self.sha512.map(|h| h.finalize().to_vec());
        expected.iter().find_map(|d| {
            let actual = match d.algorithm {
                DigestAlgorithm::Sha1 => &sha1,
                DigestAlgorithm::Sha256 => &sha256,
                DigestAlgorithm::Sha512 => &sha512,
            };
            (actual.as_deref() != Some(d.bytes.as_slice())).then_some(d.algorithm)
        })
    }
}
