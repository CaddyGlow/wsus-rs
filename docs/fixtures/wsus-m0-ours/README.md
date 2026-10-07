# WSUS M0 fixtures: a real native Windows Update Agent against THIS project's server

Provenance: REAL exchanges, requests authored by Microsoft's client, responses
authored by this project's server (`wsus-cli` `server run`). On 2026-10-04 an
unmodified Windows Update Agent 1507.2601.30012.0 (`Client-Protocol/2.90`) on
Windows 11 25H2 (OS 10.0.26200.8037, QEMU guest, a lab base image modified as
listed in inventory 9.7) was pointed at the server over plain HTTP (port 18540)
and found, downloaded and installed the approved Microsoft Defender definitions
bundle KB2267602 version 1.459.547.0 (update id
`a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`, revision 200, server-local revision id
4555 in this server's catalog). The result is in inventory 9.7 and validation
ledger row C31; this directory holds only the wire-level evidence.

Server build: commit `fd2a126` plus the uncommitted staged-delivery work in the
working tree. The exact tree is NOT recorded. Two runs, same guest image and
catalog, only `[server] sync_delivery` differing: `staged` (default) and
`closure`.

Raw captures (LOCAL ONLY, never committed): tcpdump on the host bridge, filter
`tcp port 18540`, on the guest's tap interface of the lab host.
Extracted with tshark 4.6.8 (`-d tcp.port==18540,http`; the Xpress bodies
decoded by tshark, the wire encoding read with `-o http.decompress_body:FALSE`)
and sanitized with `scripts/wsus/sanitize-capture.py`.

| Set | Raw file (local, `~/vm-lab/wsus-m0/captures/`) | Bytes | Packets | Duration | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `staged/` | `staged1/flow.pcap` | 223,937,627 | 7,726 | 48.4 s | `db7893c61072f4282d39d3d7063a933efa6e289ef40686e3df46989fd814c899` |
| `closure/` | `closure1/flow.pcap` | 224,087,767 | 7,502 | 75.1 s | `69a0a437f2b7e6ed6bae2d92a51fb9ade6f082bd017492f431d2dcafbb60f5b7` |

Each pcap holds 233 (`staged`) and 226 (`closure`) HTTP exchanges on TCP
streams that start at the guest's first `GetConfig`: 18 and 11 SOAP POSTs and
215 content `GET`s each. The server logs (`~/vm-lab/wsus-m0/ours/server.log`
and `server-closure.log`, local) count the same requests plus one `GET` of the
client route answered `405` before the guest started (not in the pcap).

## Layout and the Xpress note

Same layout as `docs/fixtures/wsus-m0-native/`: per exchange `request.headers`,
`request.body`, `response.headers`, `response.body`, `meta.json`, and one
`sanitize-manifest.json` per set (hashes and sizes of the ORIGINAL and
sanitized files, redaction counts, `"residual": []`). The exchange directory
number is the position of the exchange in the whole capture (request order),
so the gaps are the exchanges that were not kept.

The client sent `Accept-Encoding: xpress` on every SOAP request. The server
answered with `Content-Encoding: xpress` on every SOAP response except the
252-byte `RegisterComputer` answer (identity, below the server's compression
threshold). The `response.body` files hold the BODIES AS DECODED BY TSHARK;
`response.headers` drops `Content-Encoding` and carries the decoded
`Content-Length`; `meta.json` records `wire_response_content_encoding` and
`wire_response_content_length` (the bytes on the wire). The raw Xpress bytes are
not retained. Content responses were never encoded. The meta fields
`tcp_stream`, `t_request_s`, `t_response_s` (seconds since the first packet)
and `content_exchange` were added by the extraction script; `t_response_s` is
the time of the frame that completed the response, not of its first byte.

Header case: the server's response header names are lower case (as sent);
request headers are the client's.

## `staged/` (`sync_delivery = "staged"`)

| Exchange | Operation | Why selected |
| --- | --- | --- |
| 000001 to 000003 | GetConfig, GetAuthorizationCookie, GetCookie | Handshake. `ProtocolVersion` 3.2 |
| 000004 | RegisterComputer | Identity response (252 bytes) |
| 000005 | SyncUpdates, first of 11 | No cached-id arrays; 6 updates, all non-leaf |
| 000008 | SyncUpdates, 4th | 30 updates (28 leaf, 2 non-leaf), `Truncated` false; 5 installed and 3 other cached ids sent |
| 000010 | SyncUpdates, 6th | 30 leaves, `Truncated` true; carries the approved bundle (`Install`); 8 and 31 ids sent |
| 000014 | SyncUpdates, 10th | Last software page: 11 leaves, `Truncated` false; 8 and 151 ids sent |
| 000015 | SyncUpdates, 11th | Driver pass (`SkipSoftwareSync` true, 8 installed ids); a 50,024 byte request |
| 000016 | GetExtendedUpdateInfo | 24 revision ids; 4 `FileLocations` |
| 000017, 000124, 000134 | content `GET`, HEADERS ONLY | First request by time (`AM_Engine.exe`, `bytes=4194304-5242879`), a middle 1 MiB range of `AM_Base.exe`, the final short range of `AM_Base.exe` (`bytes=204472320-204745167`) |
| 000232, 000233 | ReportEventBatch | 5 and 1 events |

Not retained: `SyncUpdates` 000006, 000007, 000009, 000011 to 000013 (intermediate
rounds, 1 to 30 updates each) and 212 content exchanges.

## `closure/` (`sync_delivery = "closure"`)

| Exchange | Operation | Why selected |
| --- | --- | --- |
| 000001 to 000004 | handshake and RegisterComputer | `ProtocolVersion` 3.0 |
| 000005, 000006 | SyncUpdates rounds 1 and 2 | REQUEST and response HEADERS only. The response bodies (decoded 851,505 and 1,125,833 bytes, 200 updates each, `Truncated` true) are omitted for size: `response.body` is empty and `meta.json` carries `response_body_omitted`, `response_body_original_size` and the original sha256 |
| 000007 | SyncUpdates round 3 | Final software page: 44 updates, `Truncated` false |
| 000008 | SyncUpdates round 4 | Driver pass |
| 000009 | GetExtendedUpdateInfo | 24 revision ids; 4 `FileLocations` |
| 000010, 000117, 000047 | content `GET`, HEADERS ONLY | First by time (`AM_Engine.exe`, `bytes=1048576-2097151`), a middle 1 MiB range of `AM_Base.exe`, the final short range of `AM_Base.exe` |
| 000225, 000226 | ReportEventBatch | 5 and 1 events |

## What neither capture contains

- NO `StartCategoryScan` in either pcap (and none in the server logs). The
  guest log of the earlier failed runs recorded a failed `StartCategoryScan`
  against protocol version 3.0; why this run made no such call is not
  established.
- No `GetFileLocations`, no `HEAD`, no conditional request, no `416`, no `200`
  for a content `GET`: all 215 content responses of each capture are `206`.
- Install evidence. The pcaps stop after two `ReportEventBatch` posts; the
  install result (COM `ResultCode` 2, `Get-MpComputerStatus`) is the lead's
  and the operator's, not in the repository.

## Redaction

`scripts/wsus/sanitize-capture.py` on a temporary directory outside the
repository, once per set, with `--redact` for the four lab IPv4 addresses (this server's address on the
host bridge, the real WSUS, and the guest addresses), the three lab host
names, and the lab DNS suffix, plus `--keep-query-param LinkId` and `linkid`. Tool
defaults also applied: `EncryptedData` and `CookieData` text replaced by `A`
runs of the same length, cookie and authorization header values, the client
address in `meta.json`. In the files the server appears as `192.0.2.1` (the
`Host` header, `FileLocation` URLs) and the guest's DNS name as `REDACTED2`.

Not redacted, deliberately: the random client id GUID, `MS-CV` correlation
vectors, server-local revision and deployment ids, update GUIDs, file SHA-1
digests and the strong `ETag` (a SHA-256 hex of the public payload), timestamps
and cookie expirations, the QEMU hardware and OS description of the guest.
No payload bytes and no pcap are in this directory.

Residual scan: both manifests report `"residual": []`, and an independent
case-insensitive search over the 147 fixture files for the lab address prefix,
the three host names and their stems, the lab suffix, the host user name and
home paths found nothing.

## Use

`crates/wsus-server/tests/real_native_vs_ours.rs` decodes these fixtures with
the `wsus-protocol` decoders and pins their shapes (a `Deployment` on every
`UpdateInfo`, date-only `LastChangeTime`, page sizes, the advertised
`ProtocolVersion`, the `206` and `Content-Range` contract, the report event ids
and our `true` answers). It does not start the server. The evidence is limited
to one client build, one image, one update, plain HTTP and one client.
