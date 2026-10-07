# WSUS M0 fixtures: real native Windows Update Agent captures

Provenance: REAL exchanges, requests AND responses not authored by this
project. An unmodified Windows Update Agent (client 1507.2601.30012.0,
`Client-Protocol/2.90`) on Windows 11 25H2 (OS 10.0.26200.8037, QEMU guest)
talked plain HTTP (port 8530) to the lab WSUS: Windows Server 2025, build
10.0.26100, WSUS role (IIS/10.0, ASP.NET 4.0.30319), `ProtocolVersion` 3.2.
Captured on 2026-10-04 with tcpdump on the lab network; extracted with
`tshark` (4.6.8) and sanitized with `scripts/wsus/sanitize-capture.py`. The raw
pcaps and the raw bodies stay local and are never committed. Raw capture
SHA-256:

| Capture | File (local, `~/vm-lab/wsus-m0/captures/`) | SHA-256 |
| --- | --- | --- |
| `scan` | `native1/scan.pcap` | `868d30c14d77ade2b6879ac1a0939970284fe5fcc700f3a55e0bfbbf6809955f` |
| `flow` | `native3/flow.pcap` | `9e2ddfc3fadd4e56a29cd9e5ce7b1ae0205bf76761cc998d4987328d62dff2e6` |

Differences from `docs/fixtures/wsus-m0/` (this project's own driver): here
the client is Microsoft's, so these are the first native request shapes. No
approvals existed during `scan`; one approval (below) existed during `flow`.

## Layout and the Xpress note

Each set has per exchange `request.headers`, `request.body`,
`response.headers`, `response.body` and `meta.json` plus
`sanitize-manifest.json` (hashes and sizes of the ORIGINAL and sanitized files,
redaction counts, `"residual": []`). Exchange numbers are positions inside the
whole capture (`scan`: 10 exchanges, all kept; `flow`: 18 exchanges, 9 kept).

IMPORTANT: the server answered every request with `Content-Encoding: xpress`
(the client sent `Accept-Encoding: xpress`). tshark decodes Xpress, and the
`response.body` files hold the DECODED XML. Consequently `response.headers`
omits `Content-Encoding`, carries the decoded `Content-Length`, and
`meta.json` records `wire_response_content_encoding` and
`wire_response_content_length` (the on-wire size). Request bodies were not
compressed. The raw Xpress bytes are not retained, and this repository has no
Xpress codec.

## `scan/` (capture native1): first scan after boot, no approvals

Caller (`CallerAttributes` `Id`): `OOBE ZDP`, a category-filtered scan
(category `dd78b8a1-0b20-45c1-add6-4da72e9364cf`). Server time about 15:03:36Z.

| Exchange | Operation | Why selected |
| --- | --- | --- |
| 000001 | GetConfig | `protocolVersion` 2.90; same answer as for our driver |
| 000002 | GetAuthorizationCookie (SimpleAuth) | Native handshake |
| 000003 | GetCookie | Native sends `oldCookie` with only `Expiration` |
| 000004 | RegisterComputer | Native `ComputerInfo` of a Windows 11 25H2 client |
| 000005 | StartCategoryScan | Not implemented by `wsus-protocol`; retained as shape evidence |
| 000006 | SyncUpdates, first | No cached-id arrays at all (omitted, not empty) |
| 000007 | SyncUpdates, second | 1 installed non-leaf id |
| 000008 | SyncUpdates, third | 2 installed non-leaf ids; leaf returned |
| 000009 | SyncUpdates, driver pass | `SkipSoftwareSync` true, `SystemSpec` with 70 devices, `FeatureScoreMatchingKey` |
| 000010 | GetExtendedUpdateInfo | Category revisions; no `FileLocations` |

## `flow/` (capture native3): scan with one approved update, then reports

Caller: `<<PROCESS>>: powershell.exe` (WUA used through its API), no category
filter, `AlsoPerformRegularSync` true. The capture starts with a `SyncUpdates`
that reuses the cookie from the earlier scan (no handshake in this capture; the
cookie expiration `2026-10-04T16:03:35.9967236Z` is unchanged). Server time
about 15:20:46Z. One update was approved: KB2267602 (Security Intelligence
Update for Microsoft Defender Antivirus, version 1.459.547.0), update id
`a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`, revision 200, server-local revision id
200996.

| Exchange | Operation | Why selected |
| --- | --- | --- |
| 000001 | SyncUpdates, first of 13 software pages | 87 installed and 1029 other cached ids sent; 6 updates, not truncated |
| 000003 | SyncUpdates, first full page | 30 updates, `Truncated` true; 94 and 1037 cached ids |
| 000012 | SyncUpdates | The page carrying the approved update (the only `Action` `Install`) |
| 000013 | SyncUpdates, last software page | 30 updates, `Truncated` false; 94 and 1337 cached ids |
| 000014 | SyncUpdates, driver pass | `SkipSoftwareSync` true, 75 devices, `DriverSyncNotNeeded` true |
| 000015 | GetExtendedUpdateInfo | 18 revision ids; response with 9 `FileLocations` |
| 000016 to 000018 | ReportEventBatch (Reporting service) | 4, 9 and 2 events: the observed event id table |

Not retained: `flow` exchanges 000002, 000004 to 000011 (the intermediate
software pages) and nothing after 000018. The `flow` capture contains no content
`GET`: that earlier native download failed before any transfer; the cause is
resolved (inventory 9.4) and a later capture of the successful download is in
`content-headers/`.

## `content-headers/` (capture native6): the native download

Sanitized HTTP header pairs (no bodies) of 4 of the 216 content range `GET`s
the native client made after the lab Delivery Optimization service was fixed
and the download and install of KB2267602 succeeded. Raw pcap
`~/vm-lab/wsus-m0/captures/native6/flow.pcap` (local only), SHA-256
`3b34449d8ae0cba3c7456207e820e759ae4f6d82ba8747b3da3d2c2abad8177d`. See
`content-headers/README.md` for provenance, selection and redaction, and
inventory section 9.4 for the observations. The `scan` and `flow` sets above
are unchanged.

## Redaction

Run on a temporary directory outside the repository, once per capture, with
`--redact` for: the server IPv4 address, the client IPv4 address, the server
computer name, both client computer names (only one of them occurs, in the `dnsName` and
`DnsName` elements), and the lab DNS suffix, plus `--keep-query-param LinkId`
and `--keep-query-param linkid` (the public Microsoft `fwlink` ids inside
`SupportUrl` and `MoreInfoUrl`). The tool also redacted by default: the text of
every `EncryptedData` and `CookieData` element (replaced by `A` runs of the
same base64 length, so they decode to zero bytes), header values for cookies
and authorization, and the client address in `meta.json`. In the sanitized
files the server address appears as `192.0.2.1` (including `Host` headers,
`UpdateServiceUrl=` inside `DeviceAttributes`, and every `FileLocation` `Url`),
and the computer names as `REDACTEDN` (for example the `dnsName` and
`DnsName` elements and the `PackageServerShare` UNC path).

Not redacted, deliberately: the random client id GUID (also the reporting
`TargetID/Sid`), `MS-CV` correlation vectors, server-local revision ids and
deployment ids, update GUIDs and digests (public catalog data), timestamps,
cookie expirations, the guest's hardware and OS description (QEMU Q35 virtual
machine, CPU model of the lab host, install date), device lists of the driver
pass, and the event data (titles of Defender updates). No domain SIDs or user
names appear in these captures.

Residual scan: `sanitize-manifest.json` has `"residual": []` for both sets, and
an independent case-insensitive grep over this directory for the server and
client IPs, the three computer names, the lab DNS suffix and the host
user name found nothing.

Because redaction rewrites bodies, the sanitized hashes in `meta.json` differ
from the raw ones; the raw ones are in the manifest. The decoded-body hashes in
the manifest are hashes of the tshark output, not of the on-wire Xpress bytes.

## Use

`crates/wsus-protocol/tests/real_native_captures.rs` decodes every fixture here
(all but `scan/000005`, which has no codec) with the `wsus-protocol` decoders and
asserts the facts recorded in `docs/wsus-protocol-inventory.md` section 9.3;
`crates/wsus-protocol/tests/real_native_content.rs` does the same for
`content-headers/` (section 9.4).
The evidence is limited to one native client build against one real WSUS build;
see `docs/wsus-validation.md`.
