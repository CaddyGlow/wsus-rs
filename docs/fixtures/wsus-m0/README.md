# WSUS M0 fixtures: real capture, run 1

Provenance: REAL exchanges, not authored by this project. Captured on
2026-10-04 with `scripts/wsus/capture-proxy.py` between this project's client
(a plain SOAP 1.1 POST driver using this workspace's `wsus-protocol` types,
sending `protocolVersion` 1.8) and a real WSUS role on Windows Server 2025,
build 10.0.26100 (IIS/10.0, ASP.NET 4.0.30319), lab network. The server
reported `ProtocolVersion` 3.2. The original run holds 141 exchanges
(`~/vm-lab/wsus-m0/captures/run1`, kept local, never committed); this
directory holds a selected subset of 8.

| Exchange | Operation | Why selected |
| --- | --- | --- |
| 000001 | GetConfig | Handshake, property set, auth plug-in |
| 000002 | GetAuthorizationCookie (SimpleAuth) | Handshake |
| 000003 | GetCookie | Handshake |
| 000004 | RegisterComputer | Registration was required |
| 000005 | SyncUpdates, first page | Empty cache arrays, 30 updates, truncated |
| 000070 | SyncUpdates, middle page | Mid-run page (30 updates, 266 installed / 1684 other cached ids) |
| 000140 | SyncUpdates, last successful page | 398 installed / 3652 other cached ids; 30 updates; still truncated |
| 000141 | SyncUpdates, fault | HTTP 500, `InvalidParameters`: 401 installed non-leaf ids sent |

Smaller pages were chosen where the selection allowed it; 000140 and 000141
are about 65 KB each because their requests carry thousands of cached ids.
Nothing was trimmed: every committed body is the complete sanitized body.

## Redaction

Produced with `scripts/wsus/sanitize-capture.py` on a temporary copy of only
the selected exchanges, with `--redact` for: the server computer name, the
server IPv4 address, the client DNS name and the proxy listen address with
port. The tool also redacted by default: the text of every `EncryptedData`
and `CookieData` element (replaced by `A` runs of the same base64 length, so
these decode to zero bytes), header values for cookies and authorization, and
the client address in `meta.json`. In the sanitized files the redacted values
appear as `hostN.invalid`, `REDACTEDN` (for example the share name inside
`PackageServerShare`) or `192.0.2.N`.

Not redacted, deliberately: the random client id GUID sent by the driver, the
server-local revision ids and deployment ids, the update GUIDs (public
catalog data), timestamps, and the lab-wide values of the configuration
properties. `GetCookie`/`SyncUpdates` cookie expirations are kept; they say
nothing about the cookie key.

Residual scan: `sanitize-manifest.json` has `"residual": []` (the tool scans
every output file for the `--redact` values in plain, UTF-16LE and
URL-encoded form), and an independent case-insensitive grep over this
directory for the computer name, IP address, DNS name, port and `127.0.0.1`
found nothing. The manifest holds the sha256 and size of every ORIGINAL and
sanitized file; it never contains the redacted values.

Each exchange directory has `request.headers`, `request.body`,
`response.headers`, `response.body` and `meta.json` as written by the capture
proxy (header names of the request are lower-case as sent by the driver).
Because redaction rewrites bodies, the sanitized hashes in `meta.json` differ
from the raw ones; the raw ones are in the manifest.

## Use

`crates/wsus-protocol/tests/real_captures.rs` decodes every fixture here. The
evidence is limited to our client versus one real WSUS on one build; see
`docs/wsus-validation.md`.
