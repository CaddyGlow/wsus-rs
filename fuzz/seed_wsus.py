#!/usr/bin/env python3
"""Seed the wsus-protocol honggfuzz corpora from the crate's test fixtures.

Every wsus input is one flags byte followed by the document (see
src/wsus.rs). Message and roundtrip targets get one seed per selector so each
message type starts from every fixture.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fuzz" / "corpus"
FIXTURES = sorted((ROOT / "crates/wsus-protocol/tests/fixtures").iterdir())
FIXTURES = [f for f in FIXTURES if f.suffix in (".xml", ".txt")]


def flags_for(target):
    if target in ("wsus_wusp", "wsus_wsusss"):
        return [sel << 1 for sel in range(10)]
    if target == "wsus_roundtrip":
        # bits 1..2 pick area; bit 3 SOAP version; bits 4.. message type
        flags = [0 << 1, 1 << 1]
        flags += [(2 << 1) | (pick << 4) for pick in range(10)]
        flags += [(3 << 1) | (pick << 4) for pick in range(10)]
        return flags
    if target == "wsus_xpress":
        return [0, 1, 2, 3]  # bit 0 small block cap, bit 1 small total cap
    if target == "wsus_applicability":
        # bit 1: strict document parse; bit 2: also load the bytes as a facts snapshot
        return [0, 2, 4, 6]
    return [0, 1]  # strict and lenient sequence order


def xpress_seeds():
    """Hand-built Xpress bodies: [u32 ulen][u32 clen][payload] blocks."""
    import struct

    def block(ulen, clen, payload):
        return struct.pack("<II", ulen, clen) + payload

    # Six literals then a terminal flag bit (see wsus-protocol xpress tests).
    literal = struct.pack("<I", 1 << (31 - 6)) + b"abcdef"
    return {
        "literal-block": block(6, len(literal), literal),
        "stored-block": block(5, 5, b"hello"),
        "two-blocks": block(6, len(literal), literal) + block(5, 5, b"hello"),
        "truncated-header": b"\x06\x00\x00",
        "zero-lengths": block(0, 0, b""),
        "huge-lengths": block(0xFFFFFFFF, 0xFFFFFFFF, b""),
    }


for target in (
    "wsus_envelope",
    "wsus_fault",
    "wsus_xml",
    "wsus_wusp",
    "wsus_wsusss",
    "wsus_metadata",
    "wsus_applicability",
    "wsus_roundtrip",
    "wsus_xpress",
):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / "empty").write_bytes(b"")
    if target == "wsus_xpress":
        for name, data in xpress_seeds().items():
            for flags in flags_for(target):
                (d / f"{name}.{flags:02x}").write_bytes(bytes([flags]) + data)
    seeds = list(FIXTURES)
    if target == "wsus_applicability":
        seeds += [f for f in sorted((ROOT / "crates/wsus-protocol/tests/fixtures").iterdir())
                  if f.suffix == ".json"]
    for f in seeds:
        data = f.read_bytes()
        if len(data) > 32 * 1024:
            continue
        for flags in flags_for(target):
            (d / f"{f.stem}.{flags:02x}").write_bytes(bytes([flags]) + data)
