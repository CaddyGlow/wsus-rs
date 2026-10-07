//! `Content-Encoding: xpress` body framing (MS-WUSP 2.1, 2.1.1) over plain
//! XPRESS (MS-XCA LZ77, `ms_compress::xpress_plain`).
//!
//! Wire format: a body is zero or more blocks, each
//! `[u32 LE uncompressed length][u32 LE compressed length][compressed bytes]`,
//! the compressed bytes being one plain XPRESS stream that decodes to exactly
//! the stated uncompressed length.
//!
//! Evidence labels:
//! * Specified: blocks of at most 65535 uncompressed bytes, two little-endian
//!   int32 header fields (WUSP 2.1.1).
//! * Observed (2026-10-04, Windows Server 2025 WSUS 10.0.26100 answering a
//!   native WUA, and answering this crate's client): the layout above, with
//!   16352-byte blocks (20302 bytes became 16352 + 3950 uncompressed, 2791 +
//!   1624 compressed, no trailing bytes). No stored (uncompressed) block was
//!   seen.
//! * Observed (2026-10-04, same server answering this crate's client in a full
//!   multi-page SyncUpdates run): a block whose compressed length EQUALS its
//!   uncompressed length is stored, its bytes being the plain message tail (a
//!   184-byte final block ending in `</s:Envelope>`), not an XPRESS stream. So
//!   [`decode`] copies such a block verbatim and [`encode`] emits a stored
//!   block when XPRESS output would not be strictly smaller. Not verified: a
//!   block whose compressed length is GREATER than its uncompressed length
//!   (the real server stored instead); [`decode`] feeds it to the XPRESS
//!   decoder rather than rejecting it.
//! * Not verified: that a native WUA accepts bodies produced by [`encode`]
//!   (inventory section 9).
use ms_compress::xpress_plain;
use thiserror::Error;

/// Largest uncompressed block the specification allows.
pub const MAX_BLOCK_BYTES: usize = 65535;

/// Uncompressed size of the blocks [`encode`] emits.
///
/// Observed: the real server (WS2025 10.0.26100) cut a 20302-byte message into
/// a 16352-byte block followed by the remainder. [`encode`] uses the same
/// size so that our blocks match what that server produced, which is the only
/// evidence of a block size a native client has been seen to consume (as a
/// receiver of the server's output, not of ours). It is not claimed to be a
/// protocol constant.
pub const ENCODE_BLOCK_BYTES: usize = 16352;

const HEADER: usize = 8;

/// Bounds applied while decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest accepted block uncompressed length (default 65535, the
    /// specified maximum).
    pub max_block_bytes: usize,
    /// Largest accepted total decoded size; the decompression-bomb cap.
    pub max_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_block_bytes: MAX_BLOCK_BYTES,
            max_total_bytes: 32 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Default block size with a custom total cap.
    pub fn with_max_total(max_total_bytes: usize) -> Self {
        Self {
            max_total_bytes,
            ..Self::default()
        }
    }
}

/// Failure to decode or encode an Xpress body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum XpressError {
    #[error("block header at offset {offset} is truncated")]
    TruncatedHeader { offset: usize },
    #[error("block at offset {offset} declares a zero uncompressed length")]
    ZeroUncompressed { offset: usize },
    #[error("block at offset {offset} declares a zero compressed length")]
    ZeroCompressed { offset: usize },
    #[error(
        "block at offset {offset} declares {size} uncompressed bytes, above the limit of {limit}"
    )]
    BlockTooLarge {
        offset: usize,
        size: usize,
        limit: usize,
    },
    #[error(
        "block at offset {offset} declares {size} compressed bytes but only {available} remain"
    )]
    CompressedBeyondBody {
        offset: usize,
        size: usize,
        available: usize,
    },
    #[error("decoded size would exceed the limit of {limit} bytes")]
    TotalTooLarge { limit: usize },
    #[error("block at offset {offset} is not valid XPRESS data: {reason}")]
    Corrupt { offset: usize, reason: &'static str },
    #[error("block at offset {offset} decoded to {actual} bytes, header says {expected}")]
    LengthMismatch {
        offset: usize,
        expected: usize,
        actual: usize,
    },
    #[error("XPRESS compression failed: {0}")]
    Encode(&'static str),
}

fn reason(error: xpress_plain::Error) -> &'static str {
    use xpress_plain::Error as E;
    match error {
        E::TruncatedInput => "truncated input",
        E::InvalidData => "invalid data",
        E::InvalidOffset => "match offset before start of block",
        E::OutputTooSmall => "output exceeds declared uncompressed length",
        E::AllocationFailed => "allocation failed",
    }
}

fn u32_at(body: &[u8], at: usize) -> usize {
    let bytes = [body[at], body[at + 1], body[at + 2], body[at + 3]];
    // u32 always fits usize on supported (>= 32-bit) targets.
    u32::from_le_bytes(bytes) as usize
}

/// Decodes a complete `Content-Encoding: xpress` body.
///
/// Validation is strict: every block header must be complete, both lengths
/// non-zero (a block whose two lengths are equal is stored and copied as is),
/// the uncompressed length at most `limits.max_block_bytes`, the
/// compressed bytes inside the body, the cumulative decoded size at most
/// `limits.max_total_bytes`, each block must decode to exactly its stated
/// length, and nothing may follow the last block. An empty body decodes to an
/// empty output. Memory use is bounded by one block plus the output.
pub fn decode(body: &[u8], limits: &Limits) -> Result<Vec<u8>, XpressError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < HEADER {
            return Err(XpressError::TruncatedHeader { offset: pos });
        }
        let ulen = u32_at(body, pos);
        let clen = u32_at(body, pos + 4);
        if ulen == 0 {
            return Err(XpressError::ZeroUncompressed { offset: pos });
        }
        if clen == 0 {
            return Err(XpressError::ZeroCompressed { offset: pos });
        }
        if ulen > limits.max_block_bytes {
            return Err(XpressError::BlockTooLarge {
                offset: pos,
                size: ulen,
                limit: limits.max_block_bytes,
            });
        }
        if out.len().saturating_add(ulen) > limits.max_total_bytes {
            return Err(XpressError::TotalTooLarge {
                limit: limits.max_total_bytes,
            });
        }
        let start = pos + HEADER;
        let available = body.len() - start;
        if clen > available {
            return Err(XpressError::CompressedBeyondBody {
                offset: pos,
                size: clen,
                available,
            });
        }
        let payload = &body[start..start + clen];
        if clen == ulen {
            // Observed: stored block (compression did not shrink it).
            out.extend_from_slice(payload);
            pos = start + clen;
            continue;
        }
        let mut block = vec![0u8; ulen];
        let written =
            xpress_plain::decompress(payload, &mut block).map_err(|e| XpressError::Corrupt {
                offset: pos,
                reason: reason(e),
            })?;
        if written != ulen {
            return Err(XpressError::LengthMismatch {
                offset: pos,
                expected: ulen,
                actual: written,
            });
        }
        out.extend_from_slice(&block);
        pos = start + clen;
    }
    Ok(out)
}

/// Encodes `body` as `Content-Encoding: xpress` blocks of
/// [`ENCODE_BLOCK_BYTES`] uncompressed bytes (the last block holds the
/// remainder). A block whose XPRESS form is not strictly smaller is emitted
/// stored (equal lengths, raw bytes), as the real server does. Empty input
/// yields an empty body. Deterministic.
pub fn encode(body: &[u8]) -> Result<Vec<u8>, XpressError> {
    let mut out = Vec::with_capacity(body.len() / 2 + HEADER);
    for chunk in body.chunks(ENCODE_BLOCK_BYTES) {
        let compressed =
            xpress_plain::compress(chunk).map_err(|e| XpressError::Encode(reason(e)))?;
        let payload = if compressed.len() >= chunk.len() {
            chunk
        } else {
            compressed.as_slice()
        };
        let ulen =
            u32::try_from(chunk.len()).map_err(|_| XpressError::Encode("block too large"))?;
        let clen =
            u32::try_from(payload.len()).map_err(|_| XpressError::Encode("block too large"))?;
        out.extend_from_slice(&ulen.to_le_bytes());
        out.extend_from_slice(&clen.to_le_bytes());
        out.extend_from_slice(payload);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        // Mixed compressible and pseudo-random content, deterministic.
        let mut state = 0x1234_5678_u32;
        (0..n)
            .map(|i| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if (i / 97) % 3 == 0 {
                    (state >> 24) as u8
                } else {
                    b"<xml a=\"b\">"[i % 11]
                }
            })
            .collect()
    }

    #[test]
    fn roundtrip_across_sizes() {
        for n in [0, 1, 16351, 16352, 16353, 65535, 65536, 1_000_000] {
            let data = sample(n);
            let wire = encode(&data).expect("encode");
            assert_eq!(
                decode(&wire, &Limits::default()).expect("decode"),
                data,
                "{n}"
            );
            assert_eq!(wire, encode(&data).unwrap(), "deterministic");
        }
    }

    #[test]
    fn empty_roundtrips_to_empty_body() {
        assert!(encode(&[]).unwrap().is_empty());
        assert!(decode(&[], &Limits::default()).unwrap().is_empty());
    }

    #[test]
    fn block_boundaries_match_observed_size() {
        let wire = encode(&sample(ENCODE_BLOCK_BYTES + 1)).unwrap();
        assert_eq!(u32_at(&wire, 0), ENCODE_BLOCK_BYTES);
        let second = HEADER + u32_at(&wire, 4);
        assert_eq!(u32_at(&wire, second), 1);
    }

    #[test]
    fn matches_ms_compress_directly() {
        let data = sample(20302);
        let wire = encode(&data).unwrap();
        let mut pos = 0;
        let mut rebuilt = Vec::new();
        for chunk in data.chunks(ENCODE_BLOCK_BYTES) {
            let ulen = u32_at(&wire, pos);
            let clen = u32_at(&wire, pos + 4);
            assert_eq!(ulen, chunk.len());
            let payload = &wire[pos + 8..pos + 8 + clen];
            assert_eq!(payload, xpress_plain::compress(chunk).unwrap().as_slice());
            let mut out = vec![0; ulen];
            assert_eq!(xpress_plain::decompress(payload, &mut out).unwrap(), ulen);
            rebuilt.extend_from_slice(&out);
            pos += 8 + clen;
        }
        assert_eq!(pos, wire.len());
        assert_eq!(rebuilt, data);
    }

    /// Hand-built: one block holding six literals. The XPRESS stream is a flag
    /// dword (bits MSB first: six literal zeros, then a set bit that, with no
    /// input left, terminates the stream) followed by the six literal bytes.
    #[test]
    fn hand_built_vector_decodes() {
        let flags: u32 = 1 << (31 - 6);
        let mut stream = flags.to_le_bytes().to_vec();
        stream.extend_from_slice(b"abcdef");
        let mut wire = Vec::new();
        wire.extend_from_slice(&6u32.to_le_bytes());
        wire.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        wire.extend_from_slice(&stream);
        assert_eq!(decode(&wire, &Limits::default()).unwrap(), b"abcdef");
    }

    #[test]
    fn incompressible_block_is_stored_and_stored_block_decodes() {
        let mut state = 0xdead_beef_u32;
        let data: Vec<u8> = (0..1000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 8) as u8
            })
            .collect();
        let wire = encode(&data).unwrap();
        assert_eq!(u32_at(&wire, 0), 1000);
        assert_eq!(u32_at(&wire, 4), 1000, "stored block has equal lengths");
        assert_eq!(&wire[8..], data.as_slice());
        assert_eq!(decode(&wire, &Limits::default()).unwrap(), data);
        // Real-server shape: compressed blocks followed by a stored tail.
        let mut mixed = encode(&vec![b'a'; ENCODE_BLOCK_BYTES]).unwrap();
        mixed.extend_from_slice(&block(5, 5, b"tail!"));
        let out = decode(&mixed, &Limits::default()).unwrap();
        assert_eq!(&out[ENCODE_BLOCK_BYTES..], b"tail!");
    }

    fn block(ulen: u32, clen: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = ulen.to_le_bytes().to_vec();
        v.extend_from_slice(&clen.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn malformed_inputs_are_typed_errors() {
        let l = Limits::default();
        let good = encode(b"hello hello hello hello").unwrap();
        assert!(matches!(
            decode(&good[..5], &l),
            Err(XpressError::TruncatedHeader { offset: 0 })
        ));
        assert!(matches!(
            decode(&good[..good.len() - 1], &l),
            Err(XpressError::CompressedBeyondBody { .. })
        ));
        assert!(matches!(
            decode(&block(0, 4, &[0; 4]), &l),
            Err(XpressError::ZeroUncompressed { .. })
        ));
        assert!(matches!(
            decode(&block(4, 0, &[]), &l),
            Err(XpressError::ZeroCompressed { .. })
        ));
        assert!(matches!(
            decode(&block(65536, 4, &[0; 4]), &l),
            Err(XpressError::BlockTooLarge { size: 65536, .. })
        ));
        let mut trailing = good.clone();
        trailing.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(
            decode(&trailing, &l),
            Err(XpressError::TruncatedHeader { .. })
        ));
        let mut trailing8 = good.clone();
        trailing8.extend_from_slice(&[0; 8]);
        assert!(matches!(
            decode(&trailing8, &l),
            Err(XpressError::ZeroUncompressed { .. })
        ));
        // Declared length longer than the data decodes to.
        let mut wrong = good.clone();
        wrong[0..4].copy_from_slice(&1000u32.to_le_bytes());
        assert!(decode(&wrong, &l).is_err());
        // Declared length shorter than the data decodes to.
        let mut short = good.clone();
        short[0..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode(&short, &l).is_err());
        // Garbage payload.
        assert!(decode(&block(100, 4, &[0xff; 4]), &l).is_err());
        // u32::MAX lengths must not overflow or allocate.
        assert!(matches!(
            decode(&block(u32::MAX, u32::MAX, &[]), &l),
            Err(XpressError::BlockTooLarge { .. })
        ));
        assert!(matches!(
            decode(&block(4, u32::MAX, &[]), &l),
            Err(XpressError::CompressedBeyondBody { .. })
        ));
    }

    #[test]
    fn total_size_cap_defeats_bombs() {
        // 10 MiB of zeros compresses to a tiny body.
        let data = vec![0u8; 10 * 1024 * 1024];
        let wire = encode(&data).unwrap();
        assert!(wire.len() < data.len() / 10);
        let capped = Limits::with_max_total(1024 * 1024);
        assert!(matches!(
            decode(&wire, &capped),
            Err(XpressError::TotalTooLarge { .. })
        ));
        assert_eq!(
            decode(&wire, &Limits::with_max_total(data.len()))
                .unwrap()
                .len(),
            data.len()
        );
        // The cap applies before the block that would cross it is decoded.
        let one = encode(&data[..ENCODE_BLOCK_BYTES]).unwrap();
        assert!(matches!(
            decode(&one, &Limits::with_max_total(ENCODE_BLOCK_BYTES - 1)),
            Err(XpressError::TotalTooLarge { .. })
        ));
    }

    #[test]
    fn configured_block_limit_is_enforced() {
        let wire = encode(&sample(ENCODE_BLOCK_BYTES)).unwrap();
        let limits = Limits {
            max_block_bytes: 1000,
            ..Limits::default()
        };
        assert!(matches!(
            decode(&wire, &limits),
            Err(XpressError::BlockTooLarge { .. })
        ));
    }

    /// Gated: decodes a raw captured body (contains cookies; local only) and
    /// compares it with the independently decoded form. Set WSUS_XPRESS_RAW and
    /// WSUS_XPRESS_DEC.
    #[test]
    #[ignore = "needs WSUS_XPRESS_RAW and WSUS_XPRESS_DEC local capture files"]
    fn real_capture_decodes_byte_for_byte() {
        let raw = std::fs::read(std::env::var("WSUS_XPRESS_RAW").expect("WSUS_XPRESS_RAW"))
            .expect("raw capture");
        let dec = std::fs::read(std::env::var("WSUS_XPRESS_DEC").expect("WSUS_XPRESS_DEC"))
            .expect("decoded capture");
        let out = decode(&raw, &Limits::default()).expect("decode");
        assert_eq!(out, dec);
    }
}
