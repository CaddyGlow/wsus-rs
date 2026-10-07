# Native content download: sanitized HTTP header pairs

Provenance: REAL exchanges, not authored by this project. The native Windows
Update Agent (1507.2601.30012.0, Windows 11 25H2, OS 10.0.26200) downloaded the
approved update KB2267602 (update id `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`,
revision 200) from the lab WSUS (Windows Server 2025, 10.0.26100, IIS/10.0)
over plain HTTP, port 8530, on 2026-10-04. The content requests were sent by
the Delivery Optimization component (`Microsoft-Delivery-Optimization/10.1`).
Raw capture (local only, never committed): `~/vm-lab/wsus-m0/captures/native6/flow.pcap`,
224,569,614 bytes, SHA-256
`3b34449d8ae0cba3c7456207e820e759ae4f6d82ba8747b3da3d2c2abad8177d`, 5810
frames, tcp port 8530 on the guest tap interface. Headers were read with
tshark 4.6.8 (`-o http.decompress_body:FALSE`).

This directory holds HEADERS ONLY: no request or response bodies, no payload
bytes, no pcap. The 4 pairs were chosen from the 216 range `GET`s of that
capture:

| Directory | Pcap frames (request, response) | Range | Why |
| --- | --- | --- | --- |
| `whole-file-single-range` | 23, 54 | `bytes=0-918943` of a 918,944 byte file | The first content request in time; a file below 1 MiB is fetched as one exact range |
| `first-range-by-offset` | 2090, 2108 | `bytes=0-1048575` of a 204,745,168 byte file | Offset 0 of the large file (not the first one the client issued: it asked in shuffled order) |
| `middle-range` | 3619, 3642 | `bytes=102760448-103809023` (piece 98 of 196) | A representative full 1 MiB range |
| `final-range` | 4023, 4028 | `bytes=204472320-204745167` (piece 195, 272,848 bytes) | The short last piece; the end is size minus 1, not a 1 MiB boundary |

There is NO non-206 exchange: all 216 content responses of the capture were
`206 Partial Content`. The only `200` responses are the 4 SOAP POSTs (2
`SyncUpdates`, 2 `ReportEventBatch`). No `HEAD`, no conditional request, no
`416`. See `docs/wsus-protocol-inventory.md` section 9.4.

## Layout

Per directory: `request.headers` (request line and headers, as on the wire,
CRLF), `response.headers` (status line and headers), `meta.json` (frame
numbers, method, path, status; the bodies are not retained). Header order is
the wire order. `sanitize-manifest.json` has the SHA-256 and sizes of the
original and sanitized header files and `"residual": []`.

## Redaction

Produced with `scripts/wsus/sanitize-capture.py` on a temporary directory
outside the repository, with `--redact` for the server IPv4 address and the
guest IPv4 address. In the files the server appears as `192.0.2.1` (the `Host`
header). The `Date` header, `ETag`, `Last-Modified` and the `MS-CV`
correlation vector were NOT redacted (no cookie, credential or signed URL
exists in these requests). Not redacted either: the content URLs, which carry
only the public update-file SHA-1 digest. Content-Length and Content-Range
values are the real ones.

Residual scan: the manifest reports `"residual": []`, and a case-insensitive
grep over this directory for the lab address prefix and the host user name
found nothing.

## Use

`crates/wsus-protocol/tests/real_native_content.rs` parses these files and pins
the header facts recorded in the inventory. The evidence is limited to one
native client build against one real WSUS build and one update.
