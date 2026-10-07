# WSUS M5 fixtures: MS-WSUSSS against a real upstream, plus real update documents

Provenance: REAL data, recorded on 2026-10-04 from the lab WSUS (Windows
Server 2025 build 10.0.26100, WSUS role, IIS/10.0, plain HTTP on 8530, anonymous)
acting as an UPSTREAM server (MS-WSUSSS), with `scripts/wsus/capture-proxy.py` in
front of it. The server hosts only the Microsoft Defender Antivirus product,
`LazySync` true, update KB2267602 revision 200 (id
`a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`) approved and downloaded. Raw captures stay
local (`~/vm-lab/wsus-m0/captures/m5a`, `m5b`) and are never committed. See
inventory section 9.5 and validation rows C15 to C18 and C30.

## Layout

| Directory | Content | Client that produced the requests |
| --- | --- | --- |
| `exchanges/` | 19 exchanges, `000001` to `000019` | `scripts/wsus/probe-wsusss.py`-style plain SOAP 1.1 POSTs (Python urllib), through the proxy `m5b` |
| `exchanges-client/` | 16 exchanges, original numbers kept (`000001` to `000006`, `000013`, `000623` to `000625`, `001041` to `001046`) | this project's downstream importer (`wsus admin sync start`, `WsusssClient`), through the proxy `m5a` |
| `docs/` | 9 update documents, `<update id>-r<revision>.xml` | decoded from the real `XmlUpdateBlobCompressed` / `XmlUpdateBlob` of `GetUpdateData` (Cabinet member `blob`, UTF-16LE converted to UTF-8). Public Microsoft catalog data, not sanitized |
| `wusp-reference/` | `<id>-r<rev>.core.xml`, `.extended.xml`, `.localized-en.xml` for the same 9 revisions | the MS-WUSP fragments the SAME server sent a native Windows Update Agent, extracted from `docs/fixtures/wsus-m0-native/` (already sanitized there: `LinkId=REDACTED` in the localized `SupportUrl`) |

`exchanges/` selection (what each shows):

| Exchange | Operation | Shows |
| --- | --- | --- |
| 000001 | GetAuthConfig | `DssTargeting`, relative `ServiceUrl` |
| 000002 | DSS GetAuthorizationCookie | DSS auth namespace, anonymous |
| 000003 | GetCookie | `protocolVersion` 1.20, 240 minute cookie |
| 000004 | GetConfigData with `configAnchor` | short answer |
| 000005 | GetConfigData | limits, `LazySync`, language list, anchor |
| 000006 | GetRevisionIdList `GetConfig` true | categories (trimmed to 30 of 4275) |
| 000007 | GetRevisionIdList, product only | 0 revisions |
| 000008 | GetRevisionIdList, product + Security Updates | 0 revisions |
| 000009 | GetRevisionIdList, product + classification | all revisions (trimmed to 30 of 24,509) |
| 000010 | same with an anchor, `Delta` false | all again (trimmed to 30 of 24,509) |
| 000011 | same with an anchor, `Delta` true | 0 revisions |
| 000012 | unfiltered with an anchor | 0 revisions |
| 000013 to 000016 | GetUpdateData | bundle, leaf with a file, small uncompressed leaf, category |
| 000017 | GetUpdateData unknown id | `InternalServerError` fault |
| 000018 | GetRevisionIdList bad anchor | `InvalidParameters`, `Message` `filter` |
| 000019 | GetRevisionIdList without a cookie | `InvalidCookie` |

`exchanges-client/`: `000001` to `000004` the importer's handshake (`000004` is
the full `GetConfigData`), `000005` and `000006` its initial lists (trimmed),
`000013` its filtered initial list, `000623` to `000625` the incremental run BEFORE the
`Delta` fix (`000625`: `Delta` false, all revisions again, trimmed), `001041` to
`001046` the incremental run AFTER the fix (all three lists empty).

## Trimming and redaction

Four of the answers are very long (a single `GetRevisionIdList` body of 539,053 or
3,088,614 bytes). Before sanitizing they were cut after their 30th
`UpdateIdentity` and closed with the matching end tags, and `Content-Length` and
the sizes in `meta.json` were adjusted. The hashes in each `sanitize-manifest.json`
are therefore those of the TRIMMED input. The untrimmed originals (counts are the
revision counts of the real answers):

| Exchange (set) | Original bytes | Original SHA-256 | Revisions |
| --- | --- | --- | --- |
| `exchanges` 000006 | 539,053 | `d314a1effcaeecee37ce82c38a442a721ddd5ad05cd172dc666b42dc694c821f` | 4275 |
| `exchanges` 000009 | 3,088,614 | `452091700837a64a6a43b16de11320a53c188759c5f7703e170a8180823b249c` | 24,509 |
| `exchanges` 000010 | 3,088,614 | `82ec0475f51d3134028e3c44f107ea5726910d9f967064bc02109afac97aaebd` | 24,509 |
| `exchanges-client` 000005 | 539,053 | `c59626940f93a85bf02b31c687c5cfd0d4c2dfa4e0c04861965282f062014536` | 4275 |
| `exchanges-client` 000006 | 3,088,614 | `17d5cdc1b2e5d6de0a4dd89458a985c9614d7fdf1a73f1919c136172fc5628dc` | 24,509 |
| `exchanges-client` 000013 | 3,088,614 | `7f7cbfff516e2e4a7f8ec32cbc1a9a32500c4295e285e7764e3fb4039d585de8` | 24,509 |
| `exchanges-client` 000625 | 3,088,614 | `33ba8a08c8afb5e54498d8bce06a214809a1de297228a3e3da316ccfdf126464` | 24,509 |

Sanitized with `scripts/wsus/sanitize-capture.py` (`--redact` for the lab server
address, the bridge host address and the guest address). The text of every
`EncryptedData` and `CookieData` element is replaced by base64 `A` runs of the same
length (they decode to zero bytes). Not redacted, deliberately: the synthetic
account names and GUIDs the clients presented (`probe.lab.invalid`, `m5.lab.invalid`),
update GUIDs and the Microsoft download URLs in `MUUrl` (public catalog data),
timestamps, and the anchors. `faultactor` shows the server's own binding
(`127.0.0.1:8530`), not a lab address. The residual scan in each manifest is empty
and a case-insensitive grep for the lab network prefix over the exchange directories found nothing.

The documents in `docs/` and the reference fragments are not secret and were not
altered, with these exceptions in `wusp-reference/`: the localized `SupportUrl` has
`LinkId=REDACTED` (inherited from the sanitized native fixtures); tests compare modulo
that value.

## Use

- `crates/wsus-protocol/tests/real_wsusss.rs` decodes the exchanges with the shared
  message types and pins the facts of inventory 9.5.
- `crates/wsus-client/tests/real_wsusss_fixtures.rs` replays the recorded responses
  through `WsusssClient` and decodes the Cabinet blobs to the files in `docs/`.
- `crates/wsus-server/tests/fragments_real.rs` compares the derived MS-WUSP fragments of
  `docs/` with `wusp-reference/`.
- Live, ignored: `crates/wsus-client/tests/real_wsusss.rs` and
  `crates/wsus-cli/tests/real_upstream.rs` (need `WSUS_REAL_ORIGIN`).
