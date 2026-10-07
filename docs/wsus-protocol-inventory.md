# WSUS protocol inventory (MS-WUSP and MS-WSUSSS)

Status: milestone M0 deliverable of [the WSUS implementation plan](wsus-implementation-plan.md).
Compiled on 2026-10-04 from the pinned documents below. The real-server
evidence so far is one capture of this project's client against one WSUS
(Windows Server 2025 build 10.0.26100, WSUS role, ProtocolVersion 3.2), section
9.1, captures of an unmodified native Windows Update Agent (Windows 11
25H2, 10.0.26200) against the same server, sections 9.3 and 9.4 (a scan, and
then a successful download and install of one Defender definition update), and
(section 9.5, M5) this project's downstream importer and a probe script
against the same server acting as an UPSTREAM (MS-WSUSSS), with the content it
hosts. Section 9.7 records the first run of the native client against this
project's server (both `SyncUpdates` delivery modes, one update). Everything
else is specification text or sample code. See [the validation ledger](wsus-validation.md).

## 1. How to read this document

Every fact carries one label.

- **Specified**: stated by the pinned Microsoft Open Specifications text or
  its normative WSDL. A "Specified (example)" tag marks an informative message
  sample from the specification's section 4, which is weaker than normative text.
- **Observed**: seen in the Microsoft sample reference code (section 2.3), in
  a specification example, or (section 9.1 only) in a dated capture from a
  real WSUS with the build named. Observed behavior in the sample code is
  supporting evidence only and often disagrees with the specification
  (section 8). Observed behavior from a real server describes that one server
  build and the requests our client sent; it does not generalize to other
  builds, native clients or server configurations.
- **Implementation decision**: a choice this project makes; it is not a claim
  about WSUS.
- **Implementation requirement**: a rule this project's server or client
  must follow, derived from named Observed rows (section 9.4). It binds this
  project's implementation; it is not a claim about WSUS or about other builds.
- **Unverified**: not found in the fetched material, or contradicted by it, so
  it must be resolved by a native capture before a codec relies on it.

Section numbers such as "WUSP 3.1.5.7" refer to the pinned specification.

## 2. Pinned references

### 2.1 Specifications

All pages were fetched from learn.microsoft.com on 2026-10-04. The page
`git_commit_id` values are commits of MicrosoftDocs/open_specs_windows.

| Document | Pinned revision | Page front matter | Notes |
| --- | --- | --- | --- |
| MS-WUSP (client-server) | 38.0, Major, published 2026-02-09 | `updated_at` 2026-02-06; commit `4551887e00f4ecb4dc51bdd09b6fc2b68b12b5b6` | Section 3.1.1 and the content pages carry older per-page dates (for example 2023-04-11). The revision number is the document revision, not a per-page revision. |
| MS-WSUSSS (server-server) | 17.0, Major, published 2026-07-14 | `updated_at` 2026-07-15; commit `902ade03ba8543eb447ad45b5ebbdfa8b0b9b89b` | Revision 16.0 dated 2024-04-23 preceded it. The two sample repositories pre-date this revision. |
| MS-WSUSOD (overview) | Revision number Unverified | `updated_at` 2024-10-30; commit `817392bbb417d3771ef4fdfbbc11e4226d76470f` | The fetched page names the two protocols and their purpose only. No ports, paths or ordering are given there. |

Section 3.1.1.1 of MS-WUSP and the WSDL appendices were fetched as the pages
listed in the table of contents on the pinned revision. Local text copies live
only in the scratchpad and are not part of the repository.

The specification text grants copying for implementation purposes and states
that Microsoft may hold patents; the Open Specifications Promise or Community
Promise may apply per document. This project has not reviewed which promise
covers MS-WUSP and MS-WSUSSS. Treat patent coverage as Unverified.

### 2.2 Protocol version numbers

- Specified: MS-WUSP client protocol versions seen in the specification:
  1.0, 1.6, 1.8 (WSUS 3.0 SP2), 1.9, 2.0, 2.3, 2.4 (Windows 10 1809 through 20H2). The client SHOULD pass `1.8` in
  `GetConfig` and `GetCookie`.
- Specified: MS-WUSP server protocol versions: not returned (WSUS 2.0),
  3.0, 3.1, 3.2 (WSUS 3.0 SP2). The server SHOULD return `3.2` as the
  `ProtocolVersion` configuration property.
- Specified: MS-WSUSSS protocol versions 1.1, 1.2, 1.3, 1.6, 1.8, 1.20
  (WSUS 10.0). Version 1.3 and later perform reporting data synchronization.
  The USS requires the major version to be `1`; otherwise it faults with
  `IncompatibleProtocolVersion`.
- Observed 2026-10-04 (WS2025 build 10.0.26100, section 9.1): a `GetConfig`
  and `GetCookie` request with `protocolVersion` 1.8 was accepted and the
  server reported `ProtocolVersion` 3.2.
- Unverified: behavior of client versions above 1.8 beyond what the
  specification states. The matching Windows build for 2.4+ clients is
  Unverified.

### 2.3 Microsoft sample reference code (supporting evidence only)

| Repository | Commit pinned | Commit date | License | Role |
| --- | --- | --- | --- | --- |
| [microsoft/update-client-server-sync](https://github.com/microsoft/update-client-server-sync) | `a17fb38c26d7c7eff57971d9f97cd410869a42dd` (branch `master`) | 2023-06-12 | MIT | C# .NET Core library implementing the **server** side of MS-WUSP for an ASP.NET host (SoapCore). Despite the name it is not a client. |
| [microsoft/update-server-server-sync](https://github.com/microsoft/update-server-server-sync) | `e63f20dd7398b4919f6d87e545a595b24848b190` (branch `master`) | 2023-06-12 | MIT | C# library with a DSS client (`UpstreamServerClient`) and a USS server (`UpstreamServerStartup`), plus the `upsync` tool. |

Implementation decision: the MIT license permits adaptation with notice
retention, but this project writes its own codecs from the specification and
uses the samples only to cross-check. If any source text is adapted, add the
copyright notice under `docs/licenses/` first. Neither repository has been
built or run; their behavior is read from source only, and they have not
changed since 2023, so they pre-date MS-WUSP 36.0 through 38.0 and
MS-WSUSSS 15.0 through 17.0.

## 3. Transport, ports and path conventions

### 3.1 MS-WUSP

| Item | Value | Label |
| --- | --- | --- |
| Transport | SOAP 1.1 over HTTP; each web service SHOULD support HTTPS | Specified (WUSP 2.1) |
| SOAP style | `style="document"`, `use="literal"`, no `soap:header` | Specified (WUSP 2.2) |
| Actual SOAP version in examples | SOAP 1.1 envelope (`http://schemas.xmlsoap.org/soap/envelope/`) | Specified (example) |
| SOAP 1.2 | The WSDLs define `soap12` bindings, but the prose names only SOAP 1.1 as required | Specified (WSDL), prose Unverified |
| `commonPort` | Used for self-update and the web services | Specified |
| `contentPort` | Used by the content virtual directory | Specified |
| Default ports (Windows) | `contentPort` 80 or 8530 (non-SSL); non-SSL commonPort equals contentPort; SSL commonPort 443 if contentPort is 80, else contentPort+1 (8531 for 8530) | Specified (product behavior note) |
| Content directory | `http://serverUrl:[contentPort]/Content` | Specified |
| Self-update directory | `http://serverUrl:[commonPort]/SelfUpdate` | Specified |
| SimpleAuth service | `http[s]://serverUrl:[commonPort]/SimpleAuthWebService/SimpleAuth.asmx` | Specified |
| Client service | `http[s]://serverUrl:[commonPort]/ClientWebService/Client.asmx` | Specified |
| Reporting service | `.../ReportingWebService/ReportingWebService.asmx` in prose; `.../ReportingWebService/WebService.asmx` in the WSDL service address and in the sample code | Specified, conflicting (section 8) |
| Content methods | `GET` and `HEAD`, with range requests, on the content and self-update directories | Specified (WUSP 2.2.2.5) |
| Compression | Client SHOULD send `Accept-Encoding: xpress`; server SHOULD respond with Xpress (Win2k3 LZ77 + DIRECT2, blocks of at most 65535 bytes, each prefixed by little-endian int32 original size and int32 compressed size) | Specified (WUSP 2.1, 2.1.1). Observed on WS2025 10.0.26100 for a native WUA and for this project's client: plain XPRESS blocks, 16352-byte blocks, and a block whose compressed length equals its uncompressed length is stored raw (see the 2026-10-04 Xpress note in 9.3). Implemented in `wsus_protocol::xpress`; client decode verified against that server, server-side encode not yet consumed by a native client |
| Other compression | Client MAY request other encodings; server MAY honor | Specified |
| Legacy 0.9 | Requires commonPort 80 and an extra root virtual directory for self-update configuration | Specified |
| Content file path | Windows WSUS stores files at a relative path derived from the SHA-1: last two "bytes" of the Binhex string as subdirectory, full string as file name | Specified (product behavior note), exact case and byte/character meaning Unverified |
| Content URL values | Transmitted in `FileLocation.Url`; the layout is "implementation specific" | Specified |
| HTTPS certificates | Authenticity of content is by SHA-1 and Microsoft-signed content; WUA accepts only Microsoft-signed install binaries | Specified (WUSP 5.1) |

### 3.2 MS-WSUSSS

| Item | Value | Label |
| --- | --- | --- |
| Transport | SOAP 1.1 or SOAP 1.2 over HTTP/HTTPS; the choice is a configuration that must match on both ends, not negotiated | Specified (WSUSSS 1.7, 2.1) |
| Examples | SOAP 1.1 envelope | Specified (example) |
| Server Sync service | `http://<server>:<port>/ServerSyncWebService/ServerSyncWebService.asmx` | Specified; WSDL service address says `serversyncwebservice/ServerSyncProxy.asmx` (section 8). Observed 2026-10-04 (9.5): the prose path answers 200 in any letter case, `ServerSyncProxy.asmx` answers 404 |
| DSS Authorization service | `http://<server>:<port>/dssauthWebService/dssauthWebService.asmx` | Specified; `GetAuthConfig` returns `DssAuthWebService/DssAuthWebService.asmx` (case differs). Observed (9.5): every letter case answers 200, the returned (relative) `ServiceUrl` was used |
| Reporting service | `http://<server>:<port>/ReportingWebService/ReportingWebService.asmx` | Specified; the WSDL address differs (section 8) |
| Content download | `http://<server>:<port>/Content/<folder>/<file name>` | Specified. Observed (9.5): `<folder>` the last two hex digits and `<file name>` the full SHA-1 hex plus the file's own extension (`.exe`), any letter case; on port 8530 only (port 80 answered 404) |
| `<folder>` | "last two hexadecimal digits of the SHA1 hash" (2.1); "last two characters of the FileDigest represented in Base64" (3.2.4.4) | Specified, conflicting (section 8) |
| Content port, services over HTTP | Content uses HTTP on TCP port 80 | Specified (note: this fixes the content port even when the web services use a non-default port; behavior vs product note Unverified) |
| Content port, services over HTTPS 443 | HTTP on 80 | Specified |
| Content port, services over HTTPS N != 443 | HTTP on N-1 | Specified |
| Range requests | USS content SHOULD support HTTP/1.1 byte ranges; Windows does | Specified |
| Compression | DSS MAY request; Windows DSS sends `xpress`, expecting the Win2k3 algorithm of MS-DRSR; USS SHOULD comply | Specified |
| Windows port setup | Ports are administratively configured at USS setup | Specified (product behavior) |
| Authentication | Not required of a DSS by the protocol; a USS MAY require it, with scheme learned out of band | Specified (WSUSSS 1.5) |
| Certificate trust | A DSS needs an out-of-band way to learn the root certificate if the USS requires HTTPS | Specified |

Implementation decision: configuration defines `commonPort`, `contentPort` and
the advertised content base URL separately and never infers the content port
from the web-service port. Content file layout is an implementation choice
behind advertised URLs, except where a downstream WSUS must derive the URL
itself (WSUSSS 3.2.4.4), in which case it must follow the `Content/<folder>/<file>`
layout and the exact folder rule resolved from a native capture.

## 4. Common message rules

### 4.1 Namespaces

| Use | Namespace | Label |
| --- | --- | --- |
| Client service operations and their types | `http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService` | Specified (WSDL, examples) |
| SimpleAuth operations and types | `http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService` | Specified |
| Reporting (WUSP) and Server Sync (WSUSSS) operations and types | `http://www.microsoft.com/SoftwareDistribution` | Specified |
| DSS authorization operations and types | `http://www.microsoft.com/SoftwareDistribution/Server/DssAuthWebService` | Specified |
| GUID type | `http://microsoft.com/wsdl/types/` simple type `guid` (pattern `[0-9a-fA-F]{8}-...-[0-9a-fA-F]{12}`) | Specified |
| Ping (unused) | `http://www.microsoft.com/SoftwareDistribution/Server/IMonitorable` | Specified |
| Update metadata | `http://schemas.microsoft.com/msus/2002/12/Update` and applicability namespaces `.../BaseApplicabilityRules`, `.../MsiApplicabilityRules`, `.../UpdateHandlers/WindowsDriver` | Specified (WUSP 3.1.1.1, 5.3 note) |

All WSDL schemas use `elementFormDefault="qualified"`. Child elements therefore
inherit the operation's namespace; in the specification examples the operation
element sets a default namespace and children are unprefixed.

### 4.2 SOAPAction values

| Service | SOAPAction | Label |
| --- | --- | --- |
| SimpleAuth | `http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie` | Specified |
| Client | `http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/<Operation>` for GetConfig, GetCookie, RegisterComputer, StartCategoryScan, SyncUpdates, SyncPrinterCatalog, RefreshCache, GetExtendedUpdateInfo, GetExtendedUpdateInfo2, GetFileLocations | Specified (WSDL); prose of SyncPrinterCatalog says `.../SyncUpdates`, WSDL says `.../SyncPrinterCatalog` |
| Reporting | `http://www.microsoft.com/SoftwareDistribution/<Operation>` for ReportEventBatch, ReportEventBatch2, GetRequiredInventoryType, ReportInventory, and the rollup methods | Specified |
| Server Sync (WSUSSS) | `http://www.microsoft.com/SoftwareDistribution/<Operation>` | Specified |
| DSS authorization | `http://www.microsoft.com/SoftwareDistribution/Server/DssAuthWebService/GetAuthorizationCookie` | Specified |

### 4.3 SOAP faults

WUSP (2.2.2.4), Specified: application faults are SOAP 1.1 faults whose
`detail` element contains unqualified `ErrorCode`, `Message` (optional), `ID`
(GUID of this fault instance) and `Method` (optional). Specified (example):
`faultcode` is `soap:Client`; `faultstring` carries a .NET stack trace;
`faultactor` carries the service URL; `Method` carries the quoted SOAPAction.

WSUSSS (2.2.9), Specified: SOAP 1.1 faults carry `ErrorCode`, `Message`, `ID`
under `Detail`, unqualified; SOAP 1.2 faults carry a child element named
`Detail` (unqualified, distinct from the SOAP 1.2 `Detail`) containing the same
three elements. A fault without `ErrorCode` stops the protocol.

Implementation decision: the decoder accepts the union (`detail`/`Detail`,
optional `Method`), classifies on `ErrorCode` only, and preserves the raw fault
for evidence with the stack trace redacted from logs.

#### WUSP ErrorCode table (Specified)

| ErrorCode | Required client reaction |
| --- | --- |
| InvalidCookie | Discard cookie; GetConfig, GetAuthorizationCookie, GetCookie, RefreshCache |
| ServerChanged | Discard cookie; GetConfig, GetAuthorizationCookie, GetCookie, RefreshCache |
| ConfigChanged | GetConfig, GetAuthorizationCookie, GetCookie |
| CookieExpired | GetAuthorizationCookie, GetCookie |
| RegistrationRequired | RegisterComputer, then SyncUpdates again (SHOULD) |
| RegistrationNotRequired | Client called RegisterComputer although GetConfig said not to |
| InvalidAuthorizationCookie | Authorization cookie passed to GetCookie is invalid |
| InvalidParameters | Message names the parameter; do not retry unchanged |
| InternalServerError | SHOULD retry the failed operation later |
| ServerBusy | SHOULD retry later |
| FileLocationChanged | Call GetFileLocations; the operation text (3.1.5.10) calls this `FileLocationsChanged` (section 8) |

#### WSUSSS ErrorCode table (Specified)

| ErrorCode | Required DSS reaction |
| --- | --- |
| InvalidParameters | MAY retry with valid parameters, else stop |
| InvalidCookie | Restart the protocol from the beginning |
| InternalServerError | Stop |
| IncompatibleProtocolVersion | Stop |
| InvalidAuthorizationCookie | Restart from the beginning |
| FileDigestsMissing | Unknown digests; per DownloadFiles, restart from the beginning; `Message` carries missing digests separated by `|` |
| ServerChanged | Reset ConfigAnchor, SyncAnchor and DeploymentAnchor and continue |
| ServerBusy | MAY back off and retry later, else stop |
| TooManyIds | Appears only in GetDriverSetData; not in the 2.2.9.3 table (Unverified status) |

Windows behavior notes (Specified, product behavior): Windows DSS aborts on
`InvalidParameters` and stops on `ServerBusy` without automatic retry. The
Windows USS reports the wrong parameter name `machineName` instead of
`accountName` for an invalid account name in GetAuthorizationCookie.

Implementation decision: retries and recovery are bounded (plan section 6.1).
A POST is replayed only when the operation is idempotent by specification
(read operations) or the protocol directs it; `ReportEventBatch` replay relies
on the per-event `EventInstanceID` and is marked Unverified for server-side
deduplication.

## 5. MS-WUSP operations

### 5.1 Ordering

Specified (WUSP 3.1.5 and 3.2.5): self-update, authorization and metadata
synchronization MUST occur in order; content download and reporting SHOULD be
asynchronous.

1. Self-update (optional; client SHOULD check, files are implementation
   specific; Windows self-update exists only up to Windows 8.1).
2. `GetConfig` (MUST be first; cache the result).
3. `GetAuthorizationCookie` on SimpleAuth, at the `ServiceUrl` returned by
   `GetConfig` (the client MUST use only that URL).
4. `GetCookie`.
5. `RegisterComputer` if `IsRegistrationRequired` was true.
6. `StartCategoryScan` only for a category-limited scan and only if server
   `ProtocolVersion` is at least 3.2.
7. `SyncUpdates` software loop, then one driver pass (`SkipSoftwareSync=true`).
8. `GetExtendedUpdateInfo` and/or `GetExtendedUpdateInfo2`, `GetFileLocations`.
9. Content download over HTTP (BITS permitted), asynchronously.
10. `ReportEventBatch`, asynchronously.

Specified optimizations: cache `GetConfig`; reuse the cookie and skip
`GetAuthorizationCookie`/`GetCookie` until `CookieExpired` or the clear-text
`Expiration` passes; skip `RegisterComputer` unless registration data changed
or `RegistrationRequired` is thrown.

### 5.2 Operation table

All operations below are on the Client service unless noted. "Cookie" means a
`Cookie` obtained from GetCookie, GetFileLocations or SyncUpdates. Pagination
is "none" unless stated.

| Operation | Request (parameters) | Response | Preconditions | State changes | Limits | Faults | Labels |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GetAuthorizationCookie (SimpleAuth) | `clientId`, `targetGroupName`, `dnsName` (all optional in WSDL; `clientId` and `dnsName` MUST be present; `dnsName` must equal the one in RegisterComputer) | `AuthorizationCookie` { `PlugInId`, `CookieData` base64 } | `GetConfig` done | Server SHOULD persist client info and add it to the requested target group; MAY ignore | `clientId` is a ClientIdString (grammar Unverified, not fetched) | InvalidParameters or InternalServerError (WSUS returns InternalServerError) | Specified |
| GetConfig | `protocolVersion` string, SHOULD be `1.8` | `Config`: `LastChange` dateTime, `IsRegistrationRequired` bool, `AuthInfo` (exactly one `AuthPlugInInfo`: `PlugInID`="SimpleTargeting", `ServiceUrl` partial URL, no `Parameter`), `AllowedEventIds` int array, `Properties` name/value list | none; MUST be the first call | none | Properties: `MaxExtendedUpdatesPerRequest` (MUST), `PackageServerShare`, `ProtocolVersion` (SHOULD be 3.2), `IsInventoryRequired` (MUST be 0), `ClientReportingLevel` (SHOULD be 2). Properties other than `MaxExtendedUpdatesPerRequest` MUST NOT appear below server protocol 3.0. | InvalidParameters (MAY) | Specified. Example shows `MaxExtendedUpdatesPerRequest`=50, ProtocolVersion 3.0 (Specified example) |
| GetCookie | `authCookies` (exactly one AuthorizationCookie), `oldCookie` (optional), `lastChange` dateTime (from GetConfig), `currentTime`, `protocolVersion` | `Cookie` { `Expiration` dateTime, `EncryptedData` base64 } | GetConfig and GetAuthorizationCookie done | Server SHOULD copy state from `oldCookie` if issued by it; MAY ignore | cookie body opaque | InvalidAuthorizationCookie, InvalidCookie, ServerChanged, ConfigChanged, InvalidParameters | Specified |
| RegisterComputer | `cookie`, `computerInfo` (DnsName, OSMajorVersion, OSMinorVersion, OSBuildNumber, OSServicePackMajorNumber, OSServicePackMinorNumber, OSLocale, ComputerManufacturer, ComputerModel, BiosVersion, BiosName, BiosReleaseDate, ProcessorArchitecture, SuiteMask, OldProductType, NewProductType, SystemMetrics, ClientVersion Major/Minor/Build/Qfe, plus OSDescription, OEM, DeviceType, FirmwareVersion, MobileOperator) | empty `RegisterComputerResponse` | MUST be called when `IsRegistrationRequired` was true on the latest GetConfig | Server SHOULD store the info; validation optional | none | InvalidCookie, ServerChanged, CookieExpired, InvalidParameters, RegistrationNotRequired | Specified |
| StartCategoryScan | `requestedCategories`: list of {`IndexOfAndGroup` int, `CategoryId` guid}, a DNF (AND groups ORed) | `preferredCategoryIds` guid[], `requestedCategoryIdsInError` guid[] | Server `ProtocolVersion` >= 3.2 and a category scan intended; client MUST NOT call otherwise | none | WSUS 3.0 SP2 rejects 200 or more categories with InvalidParameters | InvalidParameters | Specified. Implemented in `wsus-protocol` and answered by `wsus-server` (section 9.6); Observed: the native client sends it WITHOUT a cookie |
| SyncUpdates | `cookie`, `parameters`: `ExpressQuery` (absent or false), `InstalledNonLeafUpdateIDs`, `OtherCachedUpdateIDs`, `SystemSpec` (devices), `CachedDriverIDs`, `SkipSoftwareSync`, `FilterCategoryIds`, `NeedTwoGroupOutOfScopeUpdates`, `ComputerSpec`, `FeatureScoreMatchingKey` | `SyncInfo`: `NewUpdates` (UpdateInfo: `ID` int revision id, `Deployment`, `IsLeaf`, `Xml` core fragment), `OutOfScopeRevisionIDs`, `ChangedUpdates`, `Truncated`, `NewCookie`, `DeployedOutOfScopeRevisionIds`, `DriverSyncNotNeeded` | valid unexpired cookie; if `SystemSpec` is present then `SkipSoftwareSync` must be true; client sends `FilterCategoryIds`/`NeedTwoGroupOutOfScopeUpdates` only when it sent protocol >= 1.7 and server is >= 3.2 | Server updates cookie with the highest deployment `LastChangeTime`; the client replaces its cookie with `NewCookie` | Truncation: server MAY return a subset and MUST then set `Truncated=true`; at most one revision per update. Observed on WS2025 10.0.26100: 30 `NewUpdates` per page (sections 9.1 and 9.3; the earlier figure of 200 was unsourced and is wrong for this build); `InstalledNonLeafUpdateIDs` is capped at 400 entries (401 gives `InvalidParameters`); `OtherCachedUpdateIDs` accepted 3679 | ConfigChanged (MUST if configuration changed), RegistrationRequired, InvalidCookie, ServerChanged, CookieExpired, InvalidParameters | Specified |
| RefreshCache | `cookie`, `globalIDs` (UpdateIdentity list: `UpdateID` guid, `RevisionNumber` int) | list of {`RevisionID`, `GlobalID`, `IsLeaf`, `Deployment`} | Only after ServerChanged or InvalidCookie, in the handshake sequence | Client re-maps cached revision ids | no stated limit | InvalidParameters, cookie faults | Specified |
| GetExtendedUpdateInfo | `cookie`, `revisionIDs`, `infoTypes` (Published, Core, Extended, VerificationRule, LocalizedProperties, Eula), `locales`, `GeoId`, `callerAttributes` | `ExtendedUpdateInfo`: `Updates` {`ID`, `Xml`}, `FileLocations` {`FileDigest` SHA-1 base64, `Url`}, `OutOfScopeRevisionIDs` | `locales` required when infoTypes has Eula or LocalizedProperties; service SHOULD always return EN | none | `revisionIDs` count MUST be below `MaxExtendedUpdatesPerRequest` (boundary inclusive/exclusive Unverified) | InvalidParameter(s), cookie faults | Specified. WUA on Windows 8+ requires the extended fragment to carry a `Files` element with SHA1 digests (WUSP footnote 26) |
| GetExtendedUpdateInfo2 | `cookie`, `updateIDs` (UpdateIdentity list, **not** revision ints), `infoTypes` (adds FileUrl, FileDecryption), `locales`, `callerAttributes` | `ExtendedUpdateInfo2`: `Updates`, `FileLocations` (adds `PiecesHashUrl`, `BlockMapUrl`, `DecryptionInformation` JSON, `FileDigestAlgorithm`, `EncryptedFileDigest`, `EncryptedFileDigestAlgorithm`), `FileDecryptionData`, `FileDecryptionData2`, `UpdateEncryptionDetails` | Not on Windows 2000 through Server 2008 R2 | none | none stated | not stated | Specified; `FileDigestAlgorithm` is "SHA1" in Windows 11 24H2 / Server 2025 |
| GetFileLocations | `cookie`, `fileDigests` (each exactly 20 bytes, SHA-1) | `FileLocations` list plus `NewCookie` | Client MUST call after a FileLocationChanged fault; MAY call otherwise | Cookie renewal | digest length 20 | InvalidParameters, cookie faults | Specified |
| SyncPrinterCatalog | `cookie`, `installedNonLeafUpdateIDs`, `printerUpdateIDs` | `SyncInfo` (as SyncUpdates) | Used only by the Add Printer wizard | as SyncUpdates | as SyncUpdates | as SyncUpdates | Specified |
| ReportEventBatch (Reporting) | `cookie`, `clientTime` (UTC), `eventBatch`: ReportingEvent {`BasicData`, `ExtendedData`, `PrivateData`} | `ReportEventBatchResult` bool, true when received | Valid cookie | Server stores events (implementation specific) | Event queue timing is client policy (random 0 to 5 minutes, WUA) | InvalidCookie, ServerChanged, CookieExpired, InvalidParameters (MAY) | Specified |
| ReportEventBatch2, GetRequiredInventoryType, ReportInventory | in the WSDL only | Unverified | Unverified | Unverified | Unverified | Unverified | Specified (WSDL), prose not found |

Event reporting details (Specified, WUSP 2.2.2.3.1): `NamespaceID` MUST be 1;
`SequenceNumber` MUST be 0; `EventInstanceID` is a client-generated GUID;
`TargetID.Sid` MUST equal the `clientId` used in GetAuthorizationCookie;
`UpdateID` is the zero GUID when no update applies; `PrivateData` MUST be
present and empty with zero-length strings; `ExtendedData.ProcessorArchitecture`
is the enumeration Unknown, X86Compatible, IA64Compatible, Amd64Compatible,
unlike RegisterComputer's free string. The EventID table covers detection
(for example 141 started, 147 finished, 148 failed), download and install
events; the full table was fetched but is not duplicated here. The ids a native
WUA actually sent in one run are in the Observed table in section 9.3 (147,
148, 156, 161, 181, 182); the names of those events remain Unverified.

### 5.3 SyncUpdates sequence

Specified (WUSP 3.1.5.7):

1. First call: `InstalledNonLeafUpdateIDs` empty, `SkipSoftwareSync=false`.
2. If `NewUpdates` is empty, software synchronization is complete.
3. Otherwise evaluate applicability of each update from its core fragment
   (implementation specific).
4. Append ids of updates that evaluated installed and are non-leaf
   (`IsLeaf=false`) to `InstalledNonLeafUpdateIDs`; append driver ids to
   `CachedDriverIDs`; append the rest to `OtherCachedUpdateIDs`. Call again.
   Observed (sections 9.1 and 9.3, WS2025 10.0.26100): the server treats a
   prerequisite as satisfied only when its revision id is in
   `InstalledNonLeafUpdateIDs` (updates whose prerequisite is not listed are
   answered in `OutOfScopeRevisionIDs` and not delivered again until it is
   listed; lab observation on run 1, raw exchange kept local), and that list
   is capped at 400 entries. A native WUA keeps it small because it lists only
   non-leaf revisions it evaluated as installed (87 to 94 entries in the
   `flow` capture) and puts every other returned revision, leaves included,
   into `OtherCachedUpdateIDs` (1029 growing to 1337 entries, 30 per full
   page). `wsus-client` has no installed-software inventory, so it uses the
   list as "non-leaf revisions cached" (`SessionConfig::installed_non_leaf_limit`,
   default 400). While the cached non-leaf revisions fit under the limit all
   are listed; beyond it `crates/wsus-client/src/sync/engine.rs` (`split_cached`)
   ranks them by how many stored software revisions depend on them, directly
   or through other non-leaf revisions (more first), then by prerequisite
   depth, then by server-local id, lists the first `limit` and sends the rest
   in `OtherCachedUpdateIDs`; leaves go to `OtherCachedUpdateIDs` and drivers to
   `CachedDriverIDs`. Ranking by depth alone withheld the prerequisites of 780
   of 808 software revisions at 473 non-leaf revisions and limit 400. Ranking by
   known dependents still withheld a prerequisite of the approved bundle (section
   9.9), so at the end of a run the client also sends probe requests that list
   each withheld chunk (implementation decision, tested against this project's
   own server only).
5. Then perform exactly one driver pass with `SkipSoftwareSync=true` and
   `SystemSpec`.

`Truncated=true` means the client SHOULD call again; `Truncated=false` means
call again only if the response had an `IsLeaf=false` update. There is no
cursor parameter: progress is carried by the cached-id arrays and the cookie.
Implementation decision: persist the three id arrays after each successfully
committed page; do not treat a page as committed until its core fragments are
durably stored.

This project's server implements the server half of this loop as `staged`
delivery (rules and their evidence labels: section 9.6).

Server-side scoping rules for a future server (Specified): restrict to
revisions deployed to the client's target group plus prerequisite and bundle
dependencies; keep those whose prerequisites are satisfied by
`InstalledNonLeafUpdateIDs`; software pass returns only `UpdateType=Software`;
driver pass applies the ranking rules (computer hardware id specificity,
feature score lower is better, hardware id order, newer driver date, higher
version). `Deployment.Action` is `Evaluate` for dependencies not explicitly
deployed; `Block` is sent as `PreDeploymentCheck` or omitted.

### 5.4 Metadata fragments

Specified (WUSP 3.1.1.1): the server derives per revision one `Core`, one
`Extended`, one or more `LocalizedProperties` and zero or more `Eula`
fragments from the update XML. Fragments are not well-formed XML: namespace
declarations are removed and elements in the Base, Msi and WindowsDriver
applicability namespaces are prefixed `b.`, `m.` and `d.`. The Core fragment
keeps `UpdateIdentity`, `Properties` (attributes UpdateType,
ExplicitlyDeployable, AutoSelectOnWebSites, OSUpgrade, EulaID only),
`Relationships` and `ApplicabilityRules`. The Extended fragment holds
`Properties` (minus a list of attributes), `Files` and `HandlerSpecificData`.
Implementation decision: store the original update XML and derive fragments
only for the server role; the client stores received fragments verbatim.

Specified: prerequisites are conjunctive normal form; `AtLeastOne` groups
share a `ClauseID`; a prerequisite names an UpdateID only and implicitly means
the highest revision. Bundles are keyed by revision. Revision ids are assigned
by each server and are valid only for that server, which is why RefreshCache
exists.

## 6. MS-WSUSSS operations

### 6.1 Ordering

Specified (WSUSSS 3.2.4): a DSS performs these phases every synchronization.

1. Authorization: `GetAuthConfig`, `GetAuthorizationCookie` at the returned
   `ServiceUrl`, `GetCookie` (pass the previous cookie as `oldCookie`).
2. Metadata synchronization: `GetConfigData`; `GetRevisionIdList` with
   `GetConfig=true` (categories, classifications, detectoids); `GetUpdateData`
   in batches; classify by `UpdateType` and `CategoryType`;
   `GetRevisionIdList` with `GetConfig=false` (software and driver revisions);
   `GetUpdateData` in batches; extract files, EULA ids, FragmentType,
   IsEncrypted; `GetUpdateDecryptionData` for `FileDecryption` updates.
3. Deployments synchronization: replica DSS only (`GetDeployments`).
4. Content synchronization: asynchronous HTTP downloads; skipped when
   `CatalogOnlySync` is true; `DownloadFiles` after a not-found.
5. Reporting data synchronization: only when both ends are 1.3 or later;
   may run before or parallel to content, or alone.

An expired cookie MUST NOT be used. Reporting calls use a fixed cookie
(`Expiration` 9999-12-31 23:59:59.9999999, zero-length `EncryptedData`).

### 6.2 Operation table

Server Sync service unless noted. Cookie validity errors: absent or empty or
unreadable cookie gives `InvalidCookie`; cookie `protocolVersion` not `x.y`
gives `InvalidParameters`; major version not 1 gives
`IncompatibleProtocolVersion`.

| Operation | Request | Response | Preconditions | State changes | Limits and pagination | Faults | Labels |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GetAuthConfig (Server Sync) | none | `ServerAuthConfig` {`LastChange`, `AuthInfo` one `AuthPlugInInfo` with PlugInID "DssTargeting" and ServiceUrl "DssAuthWebService/DssAuthWebService.asmx", `AllowedEventIds`} | none | none | none | InternalServerError | Specified |
| GetAuthorizationCookie (DSS auth) | `accountName` (FQDN-valid), `accountGuid` (GUID) | `AuthorizationCookie` {PlugInId "DssTargeting", CookieData} | none | USS inserts a DSS Table entry on first contact | none | InvalidParameters, InternalServerError | Specified |
| GetCookie | `authCookies` (exactly one), `oldCookie`, `protocolVersion` "x.y" | `Cookie` | valid auth cookie | none | Windows expiry: 240 minutes or the auth cookie expiry, whichever is lower (product note) | InvalidParameters, InvalidAuthorizationCookie, IncompatibleProtocolVersion, InternalServerError | Specified |
| GetConfigData | `cookie`, `configAnchor` | `ServerSyncConfigData`: CatalogOnlySync, LazySync, ServerHostsPsfFiles, MaxNumberOfComputerIdsInRequest, MaxNumberOfDriverSetsPerRequest, MaxNumberOfPnpHardwareIdsInRequest, MaxNumberOfUpdatesPerRequest, NewConfigAnchor, ProtocolVersion, LanguageUpdateList, MaxUpdatesPerRequestInGetUpdateDecryptionData | cookie | none; DSS stores the values and the new anchor | Language entry LanguageID 0 "all" summarizes All Languages; actual numeric limits Unverified except the ones below | cookie faults | Specified |
| GetRevisionIdList | `cookie`, `filter`: DssProtocolVersion, `Anchor`, `GetConfig`, `Get63LanguageOnly`, `Categories`, `Classifications`, `Languages` (each id with `Delta` bool) | `RevisionIdList`: `Anchor`, `NewRevisions` (UpdateIdentity list) | anchor valid or null/empty | USS returns entries changed after the anchor; one entry per GUID, highest revision | **No paging**: the whole new set is returned; DSS batches later calls | InvalidParameters (bad anchor), cookie faults | Specified. Filter and `Delta` semantics: Observed on one build, section 9.5 (an update needs one listed product AND one listed classification; `Delta` false repeats everything, true sends only the changes since the anchor; the timestamp of the anchor decides). `Languages` and `Get63LanguageOnly` unexercised |
| GetUpdateData | `cookie`, `updateIds` (UpdateIdentity list) | `ServerUpdateData`: `updates` {`Id`, `XmlUpdateBlob`, `FileDigestList`, `XmlUpdateBlobCompressed`}, `fileUrls` {`FileDigest`, `MUUrl`, `UssUrl`, `DecryptionKey`} | ids known | none | Count MUST NOT exceed `MaxNumberOfUpdatesPerRequest`; Windows responses limited to 2,000,000 bytes; Windows uses `XmlUpdateBlobCompressed` for metadata over 5,120 bytes | InvalidParameters, cookie faults | Specified. `XmlUpdateBlobCompressed` is a Cabinet with one LZX member `blob` of UTF-16LE XML, Observed on one build (9.5). Observed limits: 100 ids accepted, 101 `InvalidParameters`; an unknown id gives `InternalServerError` |
| GetUpdateDecryptionData | `cookie`, `updateIds` | `UpdateFileDecryptionData` {UpdateId, {FileDigest, DecryptionKey (may be null)}} | not on Server 2003 through 2008 R2 | none | count limited by `MaxUpdatesPerRequestInGetUpdateDecryptionData` | InvalidParameters, cookie faults | Specified |
| GetDriverIdList, GetDriverSetData | driver filter ids | driver ids and driver-set XML | Called only when a USS syncs with Microsoft Update; not on Server 2003 through 2012 R2 | none | MaxNumberOfComputerIdsInRequest, MaxNumberOfPnpHardwareIdsInRequest, MaxNumberOfDriverSetsPerRequest | InvalidParameters, TooManyIds | Specified; request and response schemas not recorded here (Unverified) |
| GetDeployments | `cookie`, `deploymentAnchor`, `syncAnchor` | `ServerSyncDeploymentResult`: `Anchor`, `Groups`, `Deployments`, `DeadDeployments`, `HiddenUpdates`, `AcceptedEulas` | DSS is a replica; `syncAnchor` non-empty | USS reports target groups, new or changed deployments between the anchors, deleted deployments, hidden updates, accepted EULAs; replica DSS applies and records history | none stated | InvalidParameters, cookie faults | Specified |
| DownloadFiles | `cookie`, `fileDigestList` | empty | A previous HTTP content fetch failed with not-found | USS fetches the files from its own parent and stores those whose SHA-1 verifies; silently ignores download failures | At most 100 digests | InvalidParameters, FileDigestsMissing | Specified |
| GetRollupConfiguration (Reporting) | `cookie` (fixed) | `DoDetailedRollup`, `RollupResetGuid`, `ServerId`, `RollupDownstreamServersMaxBatchSize`, `RollupComputersMaxBatchSize`, `GetOutOfSyncComputersMaxBatchSize`, `RollupComputerStatusMaxBatchSize` | none | none | Windows values 5,000, 1,500, 20,000, 500 respectively | any fault stops the protocol | Specified |
| RollupDownstreamServers, RollupComputers, GetOutOfSyncComputers, RollupComputerStatus | rollup structures | acknowledgements | `DoDetailedRollup` true for the computer operations | Update DSS, client and status tables | Batch sizes above; parent-before-child ordering; `RollupComputerStatus` may return false under load | InternalServerError, stop | Specified; field-level schemas not recorded (Unverified) |
| Ping, GetRelatedRevisionsForUpdates | none | none | Unused | none | none | none | Specified (unused; server MUST ignore) |

Anchors are opaque to the protocol. Windows format: `nnnn,yyyy-MM-dd HH:mm:ss.fff`
with `nnnn` an integer from 1 to 2,147,483,647 incremented on deployment
create or delete (Specified, product behavior, and Specified example
`14030,2006-06-08 15:38:16.022`). The same Windows rule requires anchors from
this format on GetRevisionIdList and GetDeployments. Observed 2026-10-04 (9.5): a
real upstream returned anchors of exactly that form from `GetConfigData` and
`GetRevisionIdList` (the counter constant, the timestamp the time of the call) and
used the timestamp part to decide which revisions to return.

Content fetch rules for a DSS (Specified, 3.2.4.4): download only when
`CatalogOnlySync` is false, the file is absent, and either `LazySync` is false,
or an Install deployment exists, or a DownloadFiles request names it, or the
preferred patching type is Express and `ServerHostsPsfFiles` is true. With
`CatalogOnlySync` true the DSS uses `MUUrl`. HTTP errors other than not-found
use implementation-specific recovery.

## 7. Recovery sequences

### 7.1 WUSP client (Specified table 4.3; bounded per plan 6.1)

- InvalidCookie or ServerChanged: GetConfig, GetAuthorizationCookie, GetCookie,
  RefreshCache over every cached revision's `UpdateIdentity`, then resume.
- ConfigChanged: GetConfig, GetAuthorizationCookie, GetCookie.
- CookieExpired: GetAuthorizationCookie, GetCookie.
- RegistrationRequired: RegisterComputer then SyncUpdates.
- FileLocationChanged: GetFileLocations for the affected SHA-1 digests.
- ServerBusy or InternalServerError: later retry. Back-off intervals are an
  Implementation decision.

### 7.2 WSUSSS DSS (Specified table 4.3)

- InvalidCookie or InvalidAuthorizationCookie: restart from authorization.
- ServerChanged: reset the three anchors and continue.
- FileDigestsMissing: restart from the beginning.
- IncompatibleProtocolVersion, InternalServerError, plain faults: stop.
- Cancellation: finish the in-flight SOAP call, then stop (Windows behavior).
- Windows DSS history rule: synchronization history entries are retained at
  least 15 days (Windows default removal after 90 days).

Interrupted paging: GetRevisionIdList has no paging, so the unit of recovery
is the DSS batch of GetUpdateData. Implementation decision: commit batches
atomically, record the anchor as pending, and promote it to "Last SyncAnchor"
only after the entire phase commits. The specification says the anchor is
stored when the operation returns; this decision is stricter. Its interaction
with USS anchor rules is Unverified.

## 8. Specification ambiguities that affect wire codecs

Each item must be decided by a native capture before the corresponding codec
is called conformant.

1. **WSUSSS content folder**: 2.1 says the last two hexadecimal digits of the
   SHA-1; 3.2.4.4 says the last two characters of the Base64 FileDigest; WUSP
   product note says the last two "bytes" of the Binhex string. By this
   project's inference (not stated by the specification) the Base64 reading
   cannot yield a valid directory name in all cases because Base64 includes `/`. Case of hex digits
   is not stated. The sample client-sync code lower-cases hex and formats the
   final byte with `{0:X}`, which would drop a leading zero (observed bug
   candidate).
   **Observed 2026-10-04 (section 9.3, WS2025 10.0.26100, 9 of 9 file
   locations):** `Content/<last two hex digits of the SHA-1, upper case>/<full
   SHA-1 hex, upper case>.exe`. This matches the first candidate reading (2.1:
   last two hexadecimal digits, that is the last digest byte) and, if
   "bytes" in the third reading means characters of the hex string, the third
   as well; it excludes the Base64 reading (for example the Base64 digests
   ended in `k=` and `4=` while the directories were `49` and `8E`) and any
   reading using the last two digest bytes (four hex characters). Upper case
   is the observed case. Leading-zero handling is NOT resolved: none of the 9
   directory names started with `0`, so the `{0:X}` truncation question stays
   open for this build.
2. **Reporting service URL**: prose `ReportingWebService.asmx` versus WSDL and
   sample `WebService.asmx`; WSUSSS example `faultactor` shows
   `serversyncWebService.asmx`; Server Sync WSDL service address says
   `ServerSyncProxy.asmx`. DSS auth is spelled `dssauthWebService` in the
   transport table and `DssAuthWebService` in `ServiceUrl` and in the sample.
   **Reporting path observed 2026-10-04 (section 9.3):** a native WUA posted
   `ReportEventBatch` to `/ReportingWebService/ReportingWebService.asmx` and the
   server answered 200 (the prose spelling works on this build; the WSDL
   spelling `WebService.asmx` was not tried against the real server).
3. **Type namespace** (partly observed, section 9.1): on the captured
   WS2025 build, `Cookie` children (`Expiration`, `EncryptedData`) and
   `AuthorizationCookie` children (`PlugInId`, `CookieData`) appear in the
   default namespace of the operation (`ClientWebService` and
   `SimpleAuthWebService` respectively), so the examples' placement is what a
   real server does. WUSP 2.2.3 says `Cookie`, `AuthorizationCookie` and
   `UpdateIdentity` are defined in `http://www.microsoft.com/SoftwareDistribution`,
   but the Client WSDL defines them in `.../Server/ClientWebService`, and the
   examples place their children in the operation namespace.
4. **Fault name** (partly observed, section 9.1: `InvalidParameters` plural
   spelling, from a `SyncUpdates` fault; the file-location fault was not
   triggered): `FileLocationChanged` (fault table) versus
   `FileLocationsChanged` (3.1.5.10). `GetExtendedUpdateInfo` validation names
   `InvalidParameter` (singular) while the table says `InvalidParameters`.
5. **SyncPrinterCatalog SOAPAction**: prose `.../SyncUpdates`, WSDL
   `.../SyncPrinterCatalog`. Parameter casing also differs between the prose
   description (`InstalledNonLeafUpdateIDs`) and the request schema
   (`installedNonLeafUpdateIDs`); element names are case-sensitive on the wire.
6. **SOAP 1.2 gaps**: the Client WSDL `soap12` binding omits
   `GetExtendedUpdateInfo2`; the prose requires only SOAP 1.1. WSUSSS allows
   SOAP 1.2 with a differently shaped fault `Detail`.
7. **Array encoding** (observed 2026-10-04, section 9.1): the real server and
   our client both used plain literal arrays, empty arrays as `<Name/>`; no
   `arrayType` appeared in 141 exchanges. The specification examples use SOAP-encoded `arrayType`
   attributes and `xsi:nil`; the WSDL uses plain literal sequences. Codecs must
   accept both and emit the literal form unless a capture shows otherwise.
8. **Weak typing in WSDL** (partly observed, section 9.1: `LastChangeTime`
   was date only, `Expiration` and `LastChange` were dateTime with `Z` and
   2 to 7 fractional digits; `GeoId` and `Deadline` were not exercised):
   `GeoId` is typed `s1:String` (a type not otherwise
   defined) and `Deployment.LastChangeTime` is `s:string` while the prose says
   `s:date`; `Deadline` is a string described as dateTime. Time formats on the
   wire are unspecified (examples use `Z` and variable fractional seconds).
9. **Ids**: GetUpdateData and GetUpdateDecryptionData describe "revision IDs"
   in the ADM and 3.2.4.2 prose but the WSDL takes `UpdateIdentity`
   (GUID plus revision number). GetExtendedUpdateInfo takes integer revision
   ids while GetExtendedUpdateInfo2 takes UpdateIdentity.
10. **GetRevisionIdList filter**: `Categories`, `Classifications`, `Languages`
    (with `Delta`) and `DssProtocolVersion` (typed as an empty complex type
    `Version`) exist in the WSDL but have no processing rules in the fetched
    prose. A USS role cannot honor them without a capture. Observed for one
    real build (9.5): `Categories` and `Classifications` select revisions that
    match one listed id of EACH list (a list that is absent or empty selects
    nothing once the other is present, both absent selects everything), and
    `Delta` is a per-id flag: false returns all revisions of the id again even
    with an anchor, true returns only those changed since the anchor.
    `Languages`, `Get63LanguageOnly` and `DssProtocolVersion` unexercised.
11. **Compression**: `XmlUpdateBlobCompressed` has no documented compression
    format in the fetched pages. Observed 2026-10-04 (9.5): a Cabinet
    (`MSCF`), one folder LZX with a 2 MiB window, one member `blob` holding the
    update document as UTF-16LE without byte order mark (the sample code's
    reading of the blob as a Cabinet was right). The transport compression says `xpress`
    (Win2k3) for HTTP, a separate matter. Observed
    2026-10-04 (section 9.3): a native WUA sends `Accept-Encoding: xpress` and
    the real server answers every response with `Content-Encoding: xpress`
    (HTTP transport only; blob compression is a separate, still unobserved,
    question).
12. **Footnote numbering**: the WUSP product notes attached to port text
    (notes 4 and 5) do not align with the section 2.1 text they reference, so
    the port rules are read from note 5 content.
13. **Reporting summaries**: the WSUSSS reporting algorithm lists
    `ApprovedUpdateCount` twice; the second occurrence appears to be
    `UpdatesWithStaleUpdateApprovalsCount`. Not verified.
14. **GetDriverSetData** returns `TooManyIds`, which the common ErrorCode table
    omits; `FileDigestsMissing` reaction differs between the common table (no
    stated action) and DownloadFiles (restart).
15. **Unreferenced clause**: product behavior notes cite sections 3.1.4.4.3.1,
    3.1.4.5.3.1 and 3.1.4.6.2.1 which are not in the pinned table of contents;
    their content was read from the notes only.
16. **Cookie semantics**: a GetCookie `oldCookie` must come from a previous
    GetCookie, GetFileLocations or SyncUpdates, but a SyncPrinterCatalog
    cookie is not listed.

## 9. Observed behavior

### 9.1 Real WSUS capture (2026-10-04)

Source: capture run 1 of this project's client against a real WSUS, Windows
Server 2025 build 10.0.26100, WSUS role (IIS/10.0, ASP.NET 4.0.30319), lab
network, 141 exchanges, all SOAP 1.1 over HTTP. Sanitized subset:
`docs/fixtures/wsus-m0/` (exchanges 1 to 5, 70, 140, 141; see its README for
redaction and provenance). Decode tests:
`crates/wsus-protocol/tests/real_captures.rs`. The requests were sent by this
project's driver, not by Windows Update Agent, so request shape is what our
client chose and the server accepted. Every row below is Observed on that
build only; "fixture" means a retained sanitized exchange, "run1" means a
raw exchange that is kept locally but is not committed.

| Observation (2026-10-04, WS2025 10.0.26100) | Evidence | Note |
| --- | --- | --- |
| `GetConfig` with `protocolVersion` 1.8 is answered. `ProtocolVersion` property is `3.2`, `MaxExtendedUpdatesPerRequest` 50, `IsInventoryRequired` 0, `ClientReportingLevel` 2, plus `PackageServerShare` (a UNC path naming the server, redacted in the fixture). Property order: `MaxExtendedUpdatesPerRequest`, `PackageServerShare`, `ProtocolVersion`, `IsInventoryRequired`, `ClientReportingLevel` | fixture 000001 | Agrees with the specification example for `MaxExtendedUpdatesPerRequest`, `IsInventoryRequired` and `ClientReportingLevel`; the example reports `ProtocolVersion` 3.0, this build 3.2. `PackageServerShare` is not in the specification example. No `AllowedEventIds` element was returned |
| `GetConfigResult` element order is `LastChange`, `IsRegistrationRequired`, `AuthInfo`, `Properties`; `LastChange` is `2026-10-04T13:17:07.59Z` (two fractional digits) | fixture 000001 | Matches the codec's ordered decode |
| `IsRegistrationRequired` is `true` on this server | fixture 000001 | Unlike the sample code, which returns false. `RegisterComputer` was then required in the run and answered with an empty `RegisterComputerResponse` element (HTTP 200) | 
| `AuthInfo` holds a single `AuthPlugInInfo` with `PlugInID` `SimpleTargeting`, an empty `Parameter` element and a RELATIVE `ServiceUrl` of `SimpleAuthWebService/SimpleAuth.asmx` (no scheme, host or leading slash) | fixture 000001 | The specification does not say whether `ServiceUrl` may be relative; a client must resolve it against the configuration service URL. The sample code returns an empty `ServiceUrl` and two plug-ins instead |
| The SimpleTargeting plug-in is the one in use: `GetAuthorizationCookie` (SimpleAuth namespace) with `clientId` and `dnsName` and without `targetGroupName` is accepted and returns `PlugInId` `SimpleTargeting` plus a 496-byte `CookieData` blob | fixtures 000002, 000003 | The `PlugInId` element name differs in case from `PlugInID` in `AuthPlugInInfo`. Absence of `targetGroupName` accepted on this server |
| Paths used and accepted: `/ClientWebService/Client.asmx` and `/SimpleAuthWebService/SimpleAuth.asmx` with `SOAPAction` quoted and equal to the WSDL action | all fixtures | Only the casing our client sent was exercised, and IIS paths are case-insensitive by default, so this does not establish that the server is case-sensitive or insensitive. The sample code serves lowercase `client.asmx` |
| The exchange order that worked is `GetConfig`, `GetAuthorizationCookie`, `GetCookie`, `RegisterComputer`, then repeated `SyncUpdates` | run1 exchanges 1 to 5 | Registration was after `GetCookie` and used the cookie returned by `GetCookie` |
| `GetCookie` response `Expiration` is `2026-10-04T15:49:04.9425733Z`, one hour after the request (`currentTime` 14:49:05Z), with seven fractional digits (.NET round trip format). Every later `NewCookie` in `SyncUpdates` kept the same `Expiration` while `EncryptedData` changed on each page | fixtures 000003, 000005, 000070, 000140 | The cookie must be replaced from each `NewCookie`; its lifetime is not extended by use (observed over about two minutes) |
| Time formats: `Expiration` and `LastChange` are `xs:dateTime` with `Z` and variable fractional digits; `Deployment.LastChangeTime` is date only (`2026-10-04`) | fixtures 000001, 000003, 000005 | The WSDL types `LastChangeTime` as `s:string` and the prose says `s:date`; the date-only form matches the prose |
| Response framing: `Content-Type: text/xml; charset=utf-8`, `Content-Length` (no chunking), no `Content-Encoding` because our client sent no `Accept-Encoding` in that run (it now does by default; see the Xpress note in 9.3). Response envelope uses the `s:` prefix with `xmlns:xsi` and `xmlns:xsd` declared on `Body`, no XML declaration (the SimpleAuth response instead has a declaration and the `soap:` prefix). Array elements are literal (no `arrayType`), empty arrays are `<Name/>` | fixtures | The Xpress behavior (WUSP 2.1.1) was not exercised in this run; it was in section 9.3. Different services of the same server use different serializer output, so decoders must stay prefix independent |
| `SyncUpdates` with empty `InstalledNonLeafUpdateIDs`, `OtherCachedUpdateIDs`, `CachedDriverIDs` and `SkipSoftwareSync` false returns exactly 30 `NewUpdates` (136 successful pages of 30, 4080 updates in total in run1), `Truncated` true on every successful page, `DriverSyncNotNeeded` `false`, and no `ChangedUpdates`, `OutOfScopeRevisionIDs` or `DeployedOutOfScopeRevisionIds` elements | fixtures 000005, 000070, 000140; run1 | CONTRADICTS section 9.2, which records the sample server cutting at 50 and a WSUS cut at 200: this build (WS2025 10.0.26100) pages at 30 updates per response. The specified `MaxExtendedUpdatesPerRequest` of 50 applies to `GetExtendedUpdateInfo`, not to `SyncUpdates`. The 200 figure is unsourced here and is not what this build does; treat page size as a server-chosen value, never a constant. The run did not reach `Truncated` false (see the next row) |
| Hard cap on `InstalledNonLeafUpdateIDs`: 400 ids accepted, 401 rejected with HTTP 500 and `InvalidParameters`, `Message` `parameters.InstalledNonLeafUpdateIDs`. `OtherCachedUpdateIDs` accepted 3679 ids in the same request | fixture 000141 (401 rejected, 3679 other ids); 400 accepted was determined by bisection in the lab run and is not retained in the fixtures | The cap is not in the specification. Run1 reached exactly 401 non-leaf ids (4080 updates = 401 non-leaf + 3679 leaf) when it cached every returned revision, so a client that declares every non-leaf revision installed cannot finish a full catalog sync on this build. Whether non-leaf ids may instead go to `OtherCachedUpdateIDs`: yes, observed in 9.9 (the same ids sent as other ids were accepted); whether the cap depends on build or configuration is Unverified (one build, 9.9) |
| Fault shape: HTTP 500 `text/xml; charset=utf-8`; SOAP 1.1 `s:Fault` with `faultcode` `s:Client` (prefix `s`, not `soap`), `faultstring` `Fault occurred`, no `faultactor`, and an unqualified `detail` with children `ErrorCode` `InvalidParameters`, `Message`, `ID` (GUID) and `Method` (the quoted SOAPAction) | fixture 000141 | Differs from the specification example (`soap:Client`, .NET stack trace in `faultstring`, `faultactor` present). `ErrorCode` text matches the fault table spelling `InvalidParameters`. `Message` named the offending parameter path rather than free text |
| `SyncUpdates` item shape: `ID`, `Deployment` (`ID`, `Action`, `IsAssigned` true, `LastChangeTime`, `AutoSelect` 0, `AutoDownload` 0, `SupersedenceBehavior` 0), `IsLeaf`, `Xml` (escaped Core fragment). Over run1: `Action` was `Evaluate` for 3442 updates, `Bundle` for 632 and `PreDeploymentCheck` for 6; 401 items were non-leaf. No `Deadline`, `DownloadPriority`, `HardwareIds`, `FlagBitmask` or `ClientBehaviors` elements | fixtures 000005, 000070, 000140; run1 counts | Consistent with the codec's `UpdateInfo` and `Deployment` types. `Bundle` actions in this catalog came with `UpdateType="Software"` |
| Core fragments: begin with `UpdateIdentity` (`UpdateID` in mixed or lower case, `RevisionNumber`), then `Properties` carrying only `UpdateType` (`Category`, `Detectoid` or `Software` seen), then optional `Relationships` and `ApplicabilityRules`; no `Files`, no `HandlerSpecificData`, no namespace declarations; applicability uses `b.` and `m.` prefixes (also `IsInstallable` next to `IsInstalled`, `b.WmiQuery`, `b.LicenseDword`, `b.MuiInstalled`). `Relationships` may hold `SupersededUpdates` (up to 9 ids in the sampled pages) before `Prerequisites`, and `Prerequisites` may mix bare `UpdateIdentity` children with `AtLeastOne` groups that carry no `IsCategory` attribute | fixtures 000005, 000070, 000140 | Fragments with several top-level elements are not well-formed documents: the lenient fragment parser decoded all 90 sampled fragments, the strict document parser refused all of them. `SupersededUpdates` inside the Core fragment is an Observed fact here; the specification listing of the Core fragment does not name it |
| `Properties/@UpdateType` is the only Properties attribute in every sampled Core fragment (none of `ExplicitlyDeployable`, `AutoSelectOnWebSites`, `OSUpgrade`, `EulaID` appeared) | fixtures | Absence in a sample of 90 fragments of mostly categories and detectoids; not evidence about Software fragments with an EULA |
| The first page (30 updates) started with the root Category `5C9376AB-8CE6-464a-B136-22113DD69801` revision 2 and server-local revision id 18 | fixture 000005 | Order is server-chosen, not sorted by id |

Not observed in this capture (still Unverified or Specified only):
`GetExtendedUpdateInfo2`, `GetFileLocations`, `RefreshCache`, any content GET
(the native client's content GETs are in section 9.4), and every MS-WSUSSS
operation (those are in section 9.5). `GetExtendedUpdateInfo`, `ReportEventBatch`, the
Reporting URL, the Xpress `Accept-Encoding` path and the driver pass were
observed afterwards from a native client (section 9.3).

### 9.2 Reference code only

The following is read from the pinned sample code and must be re-observed
against a real WSUS before it is relied on. One row is contradicted by section
9.1 (marked).

| Observation | Source | Note |
| --- | --- | --- |
| Client-sync sample serves `/ClientWebService/client.asmx`, `/SimpleAuthWebService/SimpleAuth.asmx` and `/ReportingWebService/WebService.asmx` using `BasicHttpBinding` (SOAP 1.1) via SoapCore | `UpdateServerStartup.cs` | Lowercase `client.asmx`; reporting path matches the WSDL, not the prose |
| Content route `Content/{directory}/{name}`; directory is the last digest byte in hex via `{0:X}` then lower-cased; name is the lower-case hex SHA-1 | `ClientSyncContentController.cs` | Marked as a hack by the authors. Leading zeros are not padded |
| `GetConfig` returns `IsRegistrationRequired=false`, auth plugins "PidValidator" and "Anonymous" with empty `ServiceUrl` | `ClientSync.cs` | Differs from the specified single `SimpleTargeting` plugin |
| `GetCookie` returns a 12-byte `EncryptedData` with a five-day expiry for every caller | `ClientSync.cs` | No cookie validation |
| `SyncUpdates` returns at most 50 updates and sets `Truncated` when more exist | `ClientSync.cs`, `ClientSync_Software.cs` | A WSUS truncation figure of 200 was recorded here earlier without a source; CONTRADICTED by section 9.1: Windows Server 2025 build 10.0.26100 returned 30 updates per page (2026-10-04) |
| Errors raised as bare `FaultException` | `ClientSync.cs` | Does not emit the specified `ErrorCode` detail |
| Reporting service is a placeholder | `ReportingService.cs` | |
| Upstream sample serves `/ServerSyncWebService/ServerSyncWebService.asmx`, `/DssAuthWebService/DssAuthWebService.asmx`, `/ReportingWebService/ReportingWebService.asmx` | `UpstreamServerStartup.cs` | Matches the specification prose |
| Upstream sample serves content at `microsoftupdate/content/{contentHash}`, accepting 20-byte (SHA-1) or 32-byte (SHA-256) hashes | `UpstreamServerStartup.cs`, `MicrosoftUpdateContentController.cs` | Not the `Content/<folder>/<file>` layout that WSUSSS requires |
| Upstream sample `GetCookie` returns a 12-byte cookie with a five-day expiry; anchor is `DateTime.Now.ToString()` | `ServerSyncAspNetCore.cs` | Not the Windows anchor format |
| DSS client batches `GetUpdateData` by `MaxNumberOfUpdatesPerRequest`, retrying on timeout | `UpstreamServerClient.cs` | |
| Specification section 4 shows a GetConfig response example with `MaxExtendedUpdatesPerRequest` 50, `ProtocolVersion` 3.0, `IsInventoryRequired` 0, `ClientReportingLevel` 2 | WUSP section 4 | Specified (example) |

### 9.3 Native Windows Update Agent capture (2026-10-04)

Source: two captures of an unmodified Windows Update Agent, client
1507.2601.30012.0 (`Client-Protocol/2.90`), Windows 11 25H2 (OS
10.0.26200.8037, QEMU guest), against the same lab WSUS as section 9.1
(Windows Server 2025 10.0.26100, ProtocolVersion 3.2), plain HTTP on port
8530. `scan` (native1): first scan after boot, caller `OOBE ZDP`, category
filtered, no approvals, 10 exchanges. `flow` (native3): API scan from
`powershell.exe` after one approval (KB2267602, Defender security
intelligence, revision 200), 18 exchanges, the cookie from the earlier scan
reused. Sanitized subset (10 and 9 exchanges): `docs/fixtures/wsus-m0-native/`
(README: provenance, redaction, raw SHA-256). Decode tests:
`crates/wsus-protocol/tests/real_native_captures.rs`. Every row is Observed
on that client/server pair only. The server's responses were Xpress
compressed on the wire; fixtures hold the decoded bodies.

Observed 2026-10-04 (same build pair, `native3/flow.pcap` frame 10, a 4431-byte
response body): the Xpress body is a sequence of blocks, each an 8-byte header
(little-endian uint32 uncompressed length, little-endian uint32 compressed
length) followed by that many compressed bytes; the first block here was
16352 uncompressed bytes in 2791 compressed, the second (final) block 3950 in
1624, with no trailing bytes. The block payload is plain XPRESS (MS-XCA LZ77:
32-bit flag words, the first one `00000000` followed by literals). Each block
decoded with `ms_compress::xpress_plain::decompress` (CLI: `ms-compress
rtldecompress --format xpress --output-size <uncompressed length>`) and the
concatenation was byte-identical to the body tshark 4.6.8 decodes. The 16352
block size is what this build produced; it is below the 65535 maximum in the
Specified row and should not be assumed to be fixed. Request bodies from the
native client were not compressed.

Observed 2026-10-04 (this project's client, `Accept-Encoding: xpress`, against
the same WS2025 server, a full multi-page SyncUpdates run, 177 responses, every
one `Content-Encoding: xpress`): all 177 bodies decode with
`wsus_protocol::xpress::decode`, 2,410,020 bytes on the wire against
13,446,647 decoded (5.6 times), and the decoded total equals the byte total of
the same run without `Accept-Encoding`. New fact from this run: the final
block of a multi-block body may be STORED. A block whose compressed length
equals its uncompressed length carries the raw bytes (a 184-byte tail ending in
`</s:Envelope>`, not an XPRESS stream); feeding it to the XPRESS decoder fails
("match offset before start of block"). The first single capture above had no
stored block, which is why it was not seen earlier. Not observed: a block whose
compressed length exceeds its uncompressed length (the server stored instead),
and whether the server stores only when XPRESS does not shrink the block (this
crate's encoder does so; the real server's rule is inferred, not observed).

Status of the Xpress codec in this workspace:

| Item | Status |
| --- | --- |
| Client decodes `Content-Encoding: xpress` responses from the real WS2025 WSUS | Verified (lab run above; `crates/wsus-client/tests/real_wsus.rs`, ignored, needs `WSUS_REAL_ORIGIN`) |
| Raw captured body decodes byte for byte to the tshark-decoded form | Verified (`wsus_protocol::xpress` test, ignored, needs `WSUS_XPRESS_RAW` and `WSUS_XPRESS_DEC`; the raw capture holds cookies and is not in the repository) |
| Client sends `Accept-Encoding: xpress` on SOAP POSTs by default, never on content GETs | Implemented, host-tested; accepted by the real server (it answered with Xpress) |
| Server compresses SOAP responses for clients that list `xpress`, accepts xpress request bodies, never compresses content | Implemented, host-tested against this workspace's own client and hand-built native-style requests |
| A native WUA accepts Xpress bodies produced by this server | Observed once (9.7, 2026-10-04): 17 of 18 (staged) and 10 of 11 (closure) SOAP responses were Xpress, up to 1,125,833 decoded bytes, and the client proceeded after each. One client build, plain HTTP; the guest's own decode messages are not retained |
| A real WSUS accepts Xpress request bodies | NOT verified (the native client sent uncompressed requests; this client sends uncompressed requests) |

Request shapes of the native client, and where they differ from our driver
(section 9.1):

| Observation (2026-10-04, WUA 1507.2601.30012.0 to WS2025 10.0.26100) | Evidence | Note |
| --- | --- | --- |
| Client service path is `/ClientWebService/client.asmx` (lowercase `c`); SimpleAuth `/SimpleAuthWebService/SimpleAuth.asmx`; Reporting `/ReportingWebService/ReportingWebService.asmx`. All answered 200 | scan 000001 to 000010, flow 000016 to 000018 | Our client's default is `Client.asmx` and it was also answered (IIS paths are case-insensitive by default); the native casing matches the sample code. The Reporting path is the prose spelling (inventory 8 item 2) |
| HTTP request headers: `Cache-Control: no-cache`, `Connection: Keep-Alive`, `Pragma: no-cache`, `Content-Type: text/xml; charset=utf-8`, `Accept-Encoding: xpress`, `User-Agent: Windows-Update-Agent/1507.2601.30012.0 Client-Protocol/2.90`, quoted `SOAPAction`, `MS-CV: <base64 id>.<n>.<n>.<n>.<n>.<seq>` (Client service only; absent on Reporting), `Content-Length`, `Host: <server ip>:8530` | all | The server did not require any of them (our driver sent fewer). `MS-CV` is a Microsoft correlation vector; the server's use of it is unknown |
| SOAP 1.1 envelope with `s:` prefix and no XML declaration, operation element in the operation namespace | all | Same as our driver |
| `GetConfig` and `GetCookie` carry `protocolVersion` `2.90` (not the specified `1.8`); the server answered with the same `Config` as for 1.8 (same five properties in the same order, `ProtocolVersion` 3.2, no `AllowedEventIds`) | scan 000001, 000003 | The specified value SHOULD be 1.8; the server is lenient on this build. The native client advertises its own client protocol 2.90 |
| Call order in `scan`: `GetConfig`, `GetAuthorizationCookie` (SimpleAuth), `GetCookie`, `RegisterComputer`, `StartCategoryScan`, `SyncUpdates` software loop (3 calls), `SyncUpdates` driver pass, `GetExtendedUpdateInfo` | scan 000001 to 000010 | `StartCategoryScan` was sent because the scan was category filtered (OOBE ZDP) and the server is 3.2; the server answered with `preferredCategoryIds` echoing the requested category and no `requestedCategoryIdsInError`. `wsus-protocol` now implements `StartCategoryScan` (request and response, both directions; section 9.6) |
| In `flow` no handshake appears: the client reused the earlier cookie (`Expiration` `2026-10-04T16:03:35.9967236Z`, unchanged for the whole capture) and went straight to `SyncUpdates`; `NewCookie` values replaced the cookie on every page | flow 000001 onward | Matches the specified cookie reuse; the cookie lifetime again was not extended by use |
| `GetCookie` sends `oldCookie` on the very first call, holding only `Expiration` (equal to `currentTime`) and no `EncryptedData` | scan 000003 | Our driver omitted `oldCookie`. Both accepted |
| `GetAuthorizationCookie` sends `clientId` (random GUID) and `dnsName`, no `targetGroupName`; the response `CookieData` was 496 bytes | scan 000002 | Same as our driver |
| `RegisterComputer` `ComputerInfo`: `OSMajorVersion` 10, `OSMinorVersion` 0, `OSBuildNumber` 26200, `OSLocale` en-US, `ComputerManufacturer` and `OEM` QEMU, `ProcessorArchitecture` the string `AMD64` (our driver sent `9`), `SuiteMask` 256, `OldProductType` 1, `NewProductType` 48, `SystemMetrics` 0, client version 1507.2601.30012.0, `OSDescription` `Windows 10 Pro` (this is Windows 11), `MobileOperator` `Not Present`, `BiosVersion` and `BiosName` `unknown`; response is the empty `RegisterComputerResponse` | scan 000004 | Free-string architecture differs from the Reporting enumeration (`Amd64Compatible`, see below) |
| `SyncUpdates` parameters element order: `ExpressQuery`, `InstalledNonLeafUpdateIDs`, `OtherCachedUpdateIDs`, `SystemSpec` (driver pass), `SkipSoftwareSync`, `FilterCategoryIds` (only the OOBE scan), `NeedTwoGroupOutOfScopeUpdates` (true), `AlsoPerformRegularSync`, `ComputerSpec`, `FeatureScoreMatchingKey` (driver pass), `ProductsParameters` (`SyncCurrentVersionOnly` false, `DeviceAttributes`, `CallerAttributes`, `Products`) | scan 000006 to 000009, flow | `AlsoPerformRegularSync` (false in the OOBE scan, true from the API) and `ProductsParameters` are not in the MS-WUSP WSDL appendices used for `wsus-protocol`; the decoder ignores them and decoded every native request. `DeviceAttributes` is a long `Key=Value;` string (OS, hardware, Defender and update-service attributes, `UpdateServiceUrl=` naming the server); `CallerAttributes` is `Interactive=0;SheddingAware=1;Id=<caller>;AADDeviceTokenState=...` |
| Cached lists: the first call of a scan OMITS `InstalledNonLeafUpdateIDs`, `OtherCachedUpdateIDs` and `CachedDriverIDs` altogether (our driver sent empty elements). Later calls send `InstalledNonLeafUpdateIDs` (1 then 2 ids in `scan`; 87 growing to 94 in `flow`) and `OtherCachedUpdateIDs` (absent in `scan`'s later calls, 1029 growing by the leaves returned, 30 per full page, to 1337 in `flow`); `CachedDriverIDs` was never sent | scan 000006 to 000009, flow 000001, 000003, 000012, 000013 | The native client does not send "every non-leaf revision" as installed: only those it evaluated as installed, so it never approaches the 400-entry cap. The driver pass repeats `InstalledNonLeafUpdateIDs` (94) and drops `OtherCachedUpdateIDs` |
| Driver pass: `SkipSoftwareSync` true, `SystemSpec` with 70 (`scan`) or 75 (`flow`) `Device` entries (one `extensionDriver`, 29 `CompatibleIDs` lists in `flow`), `ComputerSpec` with 6 hardware id GUIDs, `FeatureScoreMatchingKey` `AMD64.10.0`; response has no `NewUpdates` and `DriverSyncNotNeeded` true | scan 000009, flow 000014 | The software-pass responses carried `DriverSyncNotNeeded` true in `scan` and false in `flow`. No driver was ever offered |
| `SyncUpdates` software pages: `flow` returned 6, 9 (not retained), then 30 per page for 10 pages with `Truncated` true, and the 13th page (30 updates) with `Truncated` false; the client then made one driver call. `scan` returned 1 update per call, `Truncated` false each time, and continued because the response held a non-leaf update | flow 000001, 000003, 000013, scan 000006 to 000008 | Confirms the page size 30 of section 9.1 for a native client. A full page with `Truncated` false occurred, so a page's size is not an end marker. Actions seen: `Evaluate`, `Bundle`, `PreDeploymentCheck`; the approved update was `Install` |
| Approved update: update `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe` revision 200, server-local revision id 200996, `IsLeaf` true, `Deployment` `Action` `Install`, `IsAssigned` true, `AutoSelect` 0, `AutoDownload` 0, no `Deadline`; its Core fragment `Properties` carries `UpdateType="Software" ExplicitlyDeployable="true" AutoSelectOnWebSites="true"` | flow 000012 | The first observation of attributes beyond `UpdateType` in a Core fragment (section 9.1 saw only `UpdateType`) |
| `GetExtendedUpdateInfo` request: `revisionIDs` (3 in `scan`; 18 ascending in `flow`, below `MaxExtendedUpdatesPerRequest` 50), `infoTypes` exactly `Extended` and `LocalizedProperties`, `locales` `en-US` then `en`, an extra `deviceAttributes` element between `locales` and `GeoId`, `GeoId` `USA`, `callerAttributes`. No file-URL info type is requested | scan 000010, flow 000015 | `FileLocations` come back with the `Extended` info type. `deviceAttributes` is not modelled by `wsus-protocol` and is ignored when decoding. `GeoId` is the three-letter string `USA` (inventory 8 item 8) |
| `GetExtendedUpdateInfo` response: `Updates` holds one `Extended` and one `LocalizedProperties` `Update` per revision (36 for 18 revisions; the Extended fragment has `ExtendedProperties` with `Handler`, `MaxDownloadSize`, `Files/File` with `Digest` (base64 SHA-1), `DigestAlgorithm` `SHA1`, `FileName`, `Size`, `Modified` and `AdditionalDigest` `SHA256`, `HandlerSpecificData` `cmd:CommandLineInstallation`); `FileLocations` holds 9 `FileLocation` (`FileDigest`, `Url`) for 9 distinct files; no `PiecesHashUrl`, `BlockMapUrl`, `DecryptionInformation` or `FileDigestAlgorithm` children; no `OutOfScopeRevisionIDs`. For the three category revisions in `scan` the fragment has `HandlerSpecificData type="cat:Category"` and no `FileLocations` | scan 000010, flow 000015 | Confirms the WUA expectation (WUSP footnote 26) that the Extended fragment carries a `Files` element with SHA-1 digests. Every `File Digest` had a `FileLocation` |
| `FileLocation` URL rule: `http://<server-ip>:8530/Content/<last two hex chars, upper case, of the SHA-1>/<SHA-1 hex, upper case>.exe` for all 9 files, for example `Content/49/A379D5526FB3A7A0423DA1CD7FC3182A8D448449.exe`; scheme `http`, explicit port 8530, host identical to the `Host` header of the request (the client reached the server only by IP address, so Host-derived and server-address-derived hosts were not distinguished); the extension is `.exe` for these `CommandLineInstallation` files | flow 000015 | Resolves ambiguity item 1 for this build (section 8): matches the 2.1 hex reading, excludes the Base64 reading; leading-zero padding unresolved (no directory began with `0`). The extension rule for other file types is unobserved. No `GET` of these URLs occurred in the `flow` capture; the later capture of section 9.4 requested 4 of the 9 URLs with exactly this URL shape |
| `ReportEventBatch` (SOAPAction `http://www.microsoft.com/SoftwareDistribution/ReportEventBatch`, namespace `http://www.microsoft.com/SoftwareDistribution`): the cookie, `clientTime`, `eventBatch`. Three posts 1.0 to 1.3 s after the `GetExtendedUpdateInfo` request (capture times 2.64, 2.74 and 2.92 s), 4, 9 and 2 events; response `ReportEventBatchResult` true, soap prefix and XML declaration as for SimpleAuth. Every event: `NamespaceID` 1, `SequenceNumber` 0, `SourceID` 101, `TargetID/Sid` equal to the client id GUID, a fresh `EventInstanceID`, `PrivateData` present and empty, `ExtendedData` with `ComputerBrand`, `ComputerModel`, `BiosRevision`, `ProcessorArchitecture` `Amd64Compatible`, `OSVersion` 10.0.26200 revision 65792, `OSLocaleID` 1033, and a `MiscData` list of `Key=Value` strings | flow 000016 to 000018 | The constants of WUSP 2.2.2.3.1 hold as specified. `Win32HResult` is a signed int32 |

Event ids observed in the `ReportEventBatch` calls of `flow` (Observed; the
names of the events are Unverified, only ids, hresults, update ids and strings
were seen; AppName is on the first events only):

| Event id | Win32HResult | `UpdateID` | `ReplacementStrings` | Count and context |
| --- | --- | --- | --- | --- |
| 147 | 0 | zero GUID, revision 0 | `0` or `1` | 3 (one with AppName `OOBE ZDP`) |
| 148 | `0x80240438` (-2145123272) | zero GUID | `0x80240438` | 5 (the first two with AppName `Appraiser Driver Scan`) |
| 156 | 0 | zero GUID | none | 2 |
| 161 | `0x80004002` (-2147467262) | the update, revision 200 | the update title | 2: MpSigStub (`0daf8592-9e3f-4a8a-9141-d83fafebd09f`) and KB2267602 (`a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`) |
| 181 | 0 | KB2267602, revision 200 | the update title | 1, sent after the two 161 events |
| 182 | `0x80246007` (-2145099769) | MpSigStub, then KB2267602, revision 200 | none for MpSigStub; for KB2267602 `0x80246007` then the title | 2, in the last batch |

The two 161 events carry `0x80004002` and the two 182 events `0x80246007`, which
coincide with the earlier download failure (root cause in section 9.4). No
installation event was sent in that run; the successful run is in section 9.4. Our client's own event id set and the server's `AllowedEventIds` are not
derived from this table (the real `GetConfig` returned no `AllowedEventIds`).

### 9.4 Native download and install of the approved update (RESOLVED, 2026-10-04)

Status: the native download failure recorded earlier in this section
(`0x80240022` with inner `0x80004002`, later `0x80246008` with extended
`0x80070422`) is RESOLVED. The same unmodified Windows Update Agent
(1507.2601.30012.0, Windows 11 25H2, OS 10.0.26200) downloaded and installed
the approved update from the same lab WSUS (Windows Server 2025 10.0.26100,
`10.83.20.149:8530`, plain HTTP) after the lab guest's Delivery Optimization
service was made startable. The server was the real WSUS in every case; this
project's server was not involved. Sources, kept apart:

- PCAP: `~/vm-lab/wsus-m0/captures/native6/flow.pcap` (local only, 224,569,614
  bytes, 5810 frames, 76.12 s, SHA-256
  `3b34449d8ae0cba3c7456207e820e759ae4f6d82ba8747b3da3d2c2abad8177d`),
  tshark 4.6.8 with `-o http.decompress_body:FALSE`. Sanitized header pairs
  (no bodies) for 4 content exchanges:
  `docs/fixtures/wsus-m0-native/content-headers/`; tests
  `crates/wsus-protocol/tests/real_native_content.rs`. Frame numbers below are
  frames of this pcap.
- OPERATOR: results the lab operator reported from the guest (COM result codes,
  `WindowsUpdate.log` lines, service state, `Get-MpComputerStatus`). They are
  not in the repository and not evidenced by the pcap; they are as reliable as
  that report.
- INFERRED: reasoning from the two sources above. Labelled as such.

#### Root cause (the failure)

| Fact | Source | Label |
| --- | --- | --- |
| WUA fetches update content through the Delivery Optimization service (DoSvc), even with `DODownloadMode` 0 (HTTP only). With DoSvc unreachable the download fails: `WindowsUpdate.log` showed `*FAILED* [80070422] Connect to the DO service`, then `Exit Code: 0x80246008, Extended Code: 0x80070422`, then `E_NOINTERFACE` (`0x80004002`) bubbling up from `DownloadManagerDownloadJob.cpp`. `0x80070422` is `ERROR_SERVICE_DISABLED` | OPERATOR (log lines, as reported); the error-code name is a Windows constant | Observed in the guest log; the pcap shows only the absence of content requests in the failed runs (`flow`, 109 packets, POSTs only) |
| The lab base image disables DoSvc: `C:\vm\disable-windows-update.ps1` lists DoSvc among the services it disables (also UsoSvc and WaaSMedicSvc) | OPERATOR | Observed in the image script |
| After `Set-Service` and the registry changed DoSvc to Manual, the service control manager still refused to start it (`sc start` error 1058, service cannot be started because it is disabled or has no enabled devices) until the guest was REBOOTED. After the reboot DoSvc ran and the download succeeded | OPERATOR | Observed |
| WHY the SCM needed a reboot (a stale in-memory disabled state, a protected trigger or policy that is evaluated at boot, or the WaaSMedicSvc or the base's startup task re-applying settings) | none | INFERRED, not established. The captured evidence neither shows nor excludes any of these; the earlier hypotheses (missing content on the server, `0x80004002` inside BITS) are withdrawn: the server served the content without any server-side change |
| The earlier operator note that the failed download "created a BITS job" is superseded: the content transport is Delivery Optimization (HTTP user agent `Microsoft-Delivery-Optimization/10.1`) | pcap (user agent on every content request) | Observed |

Other lab-image hazards recorded with this run (OPERATOR): the scheduled task
`VMBase-DisableWindowsUpdate` re-applies `WUServer=http://127.0.0.1` at every
boot (disabled for this instance); UsoSvc, DoSvc and WaaSMedicSvc are disabled
by the image; Defender is disabled by policy (`DisableAntiVirus` survives the
base's own `-Enable` restore script), so Defender definition updates were not
offered until Defender was re-enabled. A guest booted from this image needs
all of these undone, and a reboot after enabling DoSvc, before any native
download against any server, ours included.

#### Outcome (OPERATOR, with the pcap cross-checks marked)

- COM `Download` `ResultCode` 2 (`orcSucceeded`), `hr` 0; COM `Install`
  `ResultCode` 2, `hr` 0 (OPERATOR).
- Afterwards `Get-MpComputerStatus` reported `AntivirusSignatureVersion`
  1.459.547.0, which is the approved update (KB2267602, update id
  `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`, revision 200; a bundle of 7 child
  updates) (OPERATOR). The pcap holds no installation evidence by itself; it
  shows the download and the event reports below.

#### Content delivery as seen on the wire (PCAP; all Observed)

Capture contents: 220 HTTP request/response pairs on 8 TCP connections
(streams 0 to 7): 4 `POST` (frames 7, 14, 5778, 5783; all answered `200`) and
216 `GET` (all answered `206 Partial Content`). No other method: no `HEAD`
(count 0), no `GET` without `Range` (0), no conditional header (`If-Range`,
`If-Match`, `If-None-Match`, `If-Modified-Since`: 0), no `416`, no other
status. No TCP reset and no TCP retransmission in the capture (tshark
`tcp.analysis.retransmission || tcp.flags.reset==1`: 0 frames).

| Observation | Frames and derivation |
| --- | --- |
| Before the downloads the client made two `SyncUpdates` POSTs on the first connection (stream 0), reusing the cookie `Expiration` `2026-10-04T16:03:35.9967236Z`: a software pass (request 7: `InstalledNonLeafUpdateIDs` 94, `OtherCachedUpdateIDs` 1367, `SkipSoftwareSync` false, `AlsoPerformRegularSync` true; response 10: `Truncated` false, `DriverSyncNotNeeded` false, no updates) and a driver pass (request 14: `SkipSoftwareSync` true; response 18: `DriverSyncNotNeeded` true). The capture holds NO `GetExtendedUpdateInfo`: the file locations had been fetched before the capture started (the 9 `FileLocations` of section 9.3). The first content `GET` followed the second `SyncUpdates` response by 0.79 s (frame 23 at 0.8135 s; frame 18 at about 0.03 s) | frames 7, 10, 14, 18, 23; request XML parsed with a script, responses as decoded by tshark |
| Which files: 4 distinct files, all by `Content/<last two hex chars of SHA-1, upper case>/<SHA-1 hex, upper case>.exe` URLs of the same shape as section 9.3 (the digest of each equals a `FileLocation` of the earlier `flow` capture, whose Extended fragment gives the names and sizes shown): `Content/F8/6103D9F6...42F8.exe` (`MpSigStub.exe`, 918,944 bytes, 1 range), `Content/C9/BD789D42...6DC4C9.exe` (`AM_Engine.exe`, 6,662,560 bytes, 7 ranges), `Content/AB/2F88DF42...D154AB.exe` (`AM_Base.exe`, 204,745,168 bytes, 196 ranges), `Content/CD/87F5BD04...2895DDCD.exe` (an `AM_Delta.exe`, 11,606,440 bytes, 12 ranges). 4 of the 9 `FileLocations` were requested; the other 5 (all `AM_Delta.exe`, 11,606,432 to 11,618,768 bytes) were never requested | `GET` counts per URL from the 216 requests; names and sizes from `docs/fixtures/wsus-m0-native/flow/000015` (the `Extended` fragment `File` elements) joined on the SHA-1 |
| Totals: the 216 ranges cover each of the 4 files exactly once (no gap, no overlap, no duplicate range, 0 re-requests, 0 retries). The `Content-Range` totals equal the Extended `Size` of each file, and their sum is 223,933,112 bytes (918,944 + 6,662,560 + 204,745,168 + 11,606,440), which is also the `B=223933112` value in the reporting event 162 below | per-file contiguity and coverage check on the 216 request/response pairs |
| Range shape: every request is a closed range `bytes=<start>-<end>`; every range except the last of each file is exactly 1,048,576 bytes (1 MiB) starting at a multiple of 1,048,576 (195 + 6 + 11 full ranges of 1 MiB, then 4 short ones); the last range of a file ends at exactly `size - 1` (`bytes=204472320-204745167` for the 204,745,168 byte file, 272,848 bytes; `bytes=6291456-6662559`; `bytes=11534336-11606439`); a file smaller than 1 MiB is requested whole (`bytes=0-918943`) in one range. The client takes the size from the metadata: the first request for each file is a ranged `GET`, there is no `HEAD` or probe | `Range` and `Content-Range` of all 216 pairs; frames 23/54, 125, 650, 4023/4028 |
| Order: ranges are NOT requested in offset order. Within a file they follow a shuffled order of the 1 MiB pieces (for `AM_Base.exe`, the first requests on one connection were pieces 7, 42, 168, 36, 19 ...; the piece 0 range was requested at 1.742 s and the final piece, 195, at 2.9615 s, the 130th of 196 requests by `MS-CV` counter, while the capture's last response for this file completed at 3.994 s) | request frames per connection |
| Connections: 7 content connections plus the SOAP connection. They were opened on demand, each SYN less than 1 ms before its first `GET`: one for `MpSigStub.exe` (stream 1, SYN at 0.8129 s), one for `AM_Engine.exe` (stream 2, 0.9127 s), three for `AM_Base.exe` (streams 3, 4, 5; 0.9444, 0.9535, 0.9663 s; 66, 65 and 65 requests), two for the `AM_Delta.exe` (streams 6, 7; 0.9680, 0.9815 s; 6 requests each). All files were fetched at the same time, from about 0.81 s to 3.99 s. Each connection carried one request at a time (no pipelining: 0 overlapping requests within any connection) and was reused for all of its requests (`Connection: Keep-Alive` on every request; no `Connection: close`). The SOAP connection (stream 0) was reused for the two `ReportEventBatch` POSTs at 5.67 s and 16.12 s | TCP SYN frames 1, 20, 56, 134, 170, 250, 291, 400; per-stream request intervals |
| Requests in flight: at most 4 at any instant by interval overlap (request frame time to the completion time of its response), at most 7 connections open for content; aggregate rate about 70 MB/s (223,933,112 bytes in 3.18 s, 0.8135 to 3.9936 s) on the lab network. This peak was computed from tshark frame times and `http.time`; a timing error of one request could move it to 5, so read it as "4 to 5, with 7 connections" | per-request intervals |
| Connection end: the client closed every connection (client FIN first): the 7 content connections at 31.08 to 31.26 s (27.2 to 30.3 s after their last response), the SOAP connection at 76.12 s. The server never closed a connection first. The reason for the 27 to 30 s lingering is unknown | FIN frames 5787 to 5809 |
| Request headers, identical in shape on all 216 `GET`s, wire order: `Connection: Keep-Alive`, `Accept: */*`, `Range: bytes=...`, `User-Agent: Microsoft-Delivery-Optimization/10.1`, `MS-CV: e8u3dmxOhkGW0Ilt.2.0.0.<n>.1.1.3.1.1.<k>`, `Content-Length: 0` (on a `GET`), `Host: <server ip>:8530`. No `Accept-Encoding`, no `Pragma`, no `Cache-Control`, no cookie. The `MS-CV` base is the same as that of the SOAP POSTs of the same session; `<n>` is 2, 5, 8, 11 for the four files and `<k>` counts the requests of the file (1 to 196 for `AM_Base.exe`, spread across its 3 connections in turn) | `docs/fixtures/wsus-m0-native/content-headers/*/request.headers`; all 216 header sets compared by shape |
| Response headers, wire order, identical in shape on all 216: `HTTP/1.1 206 Partial Content`, `Content-Type: application/octet-stream`, `Last-Modified`, `Accept-Ranges: bytes`, `ETag`, `Server: Microsoft-IIS/10.0`, `X-Powered-By: ASP.NET`, `Date`, `Content-Length` (the range length), `Content-Range: bytes <a>-<b>/<size>`. No `Cache-Control`, no `Content-Encoding` (content was never compressed, unlike the SOAP responses), no `Transfer-Encoding`, no `Connection`, no `Vary`. `Content-Range` always equals the requested range and `Content-Length` equals `b - a + 1` (0 mismatches in 216) | `docs/fixtures/wsus-m0-native/content-headers/*/response.headers`; all 216 compared |
| Validators: `ETag` and `Last-Modified` are constant for all ranges of one file and differ per file (IIS form `"<hex>:0"`, quoted, not marked `W/`): `MpSigStub.exe` `Last-Modified` Thu, 11 Jan 2024 20:39:44 GMT; `AM_Engine.exe` Tue, 18 Aug 2026 00:52:18 GMT; `AM_Base.exe` Wed, 02 Sep 2026 08:30:53 GMT; the delta Sun, 04 Oct 2026 09:48:54 GMT. The client never re-validated: no `If-Range`, no conditional request, and no `HEAD` | response header sets per file |
| SOAP responses on this capture: the `SyncUpdates` responses (frames 10, 18) carried `Cache-Control: private`, the `ReportEventBatch` responses (frames 5780, 5785) `Cache-Control: private, max-age=0`; all four `Content-Encoding: xpress`. `ReportEventBatchResult` true in both reports | frames 10, 18, 5780, 5785 |

#### Native `ReportEventBatch` after the download (PCAP, decoded with a script)

Two POSTs to `/ReportingWebService/ReportingWebService.asmx` on the original
connection, with the cookie of the earlier scan: frame 5778 at 5.67 s (client
time 15:55:46.345Z, 9673 bytes, 5 events) and frame 5783 at 16.12 s (client
time 15:55:56.776Z, 2473 bytes, 1 event). Both answered `200` with
`ReportEventBatchResult` true. Every event: `NamespaceID` 1, `SequenceNumber`
0, `SourceID` 101, `AppName=<<PROCESS>>: powershell.exe` in `MiscData`, `TargetID/Sid` the client id, `PrivateData` empty, and
`Win32HResult` 0.

| Frame | Event id | `Win32HResult` | `UpdateID` | `ReplacementStrings` (first) and notable `MiscData` |
| --- | --- | --- | --- | --- |
| 5778 | 147 | 0 | zero GUID, revision 0 | `1`; `B=761`, `C=2` (`Q=1`) |
| 5778 | 156 | 0 | zero GUID, revision 0 | none; `U=` a list of 5 GUIDs separated by `;` |
| 5778 | 167 | 0 | KB2267602 update id, revision 200 | the update title; `Q=2` |
| 5778 | 162 | 0 | KB2267602, revision 200 | the update title; `B=223933112` |
| 5778 | 181 | 0 | KB2267602, revision 200 | the update title |
| 5783 | 183 | 0 | KB2267602, revision 200 | the update title; `D=1` |

Cross-checks (the event names are now read from the real server's own event table, section 9.10): the failure run of section 9.3 sent 161 (`0x80004002`) and 182
(`0x80246007`) for the same update; this run sent 162, 167, 181 and 183, all
with `Win32HResult` 0. `B=223933112` in event 162 equals the byte total of the
216 ranges above (Observed). The event NAMES are not established (the
specification names only some ids): reading 161 to 162 as "download failed" to
"download completed" and 182 to 183 as "install failed" to "install completed"
is INFERRED from the pairing, the hresults and the matching byte total, not
Observed. A success marker in a report is not install evidence; the install
claim rests on the OPERATOR results above.

#### Implementation requirements for this project's content server

Derived from the Observed rows above; each names the evidence it rests on. They
are requirements this project places on `wsus-server` for the native client
profile of this build pair, not statements about WSUS in general. Where the
wire is silent they say so.

| ID | Requirement | Rests on |
| --- | --- | --- |
| IR-1 | Serve `GET /Content/<last two hex chars of the SHA-1, upper case>/<SHA-1 hex, upper case>.<ext>` at exactly the URL the server emitted in `FileLocation` (scheme, host or IP, and port 8530 as emitted); the client requests that URL verbatim, upper case. Treat the path case-insensitively as IIS does, but emit upper case | request URLs of the 216 `GET`s; section 9.3 URL rule |
| IR-2 | Answer a closed `Range: bytes=a-b` with `206 Partial Content`, a `Content-Range: bytes a-b/<size>` that equals the request exactly, and `Content-Length: b-a+1`. The final range of a file ends at `size - 1`, so no clamping was exercised; clamp an over-long end to `size - 1` per HTTP semantics (Implementation decision, UNOBSERVED) | 216 of 216 pairs, 0 mismatches; frames 4023/4028 |
| IR-3 | The reported size is part of the contract: the `Size` of the `File` in the Extended fragment, the real byte length of the served file, and the total in `Content-Range` must be identical. The client issues `bytes=0-<Size-1>` for a small file with no preceding `HEAD`, so it relies on the metadata size | frame 23 and the equality of all four totals with `Size` |
| IR-4 | Support random-access ranges: arbitrary 1 MiB pieces of one file in shuffled order, on several connections at once (3 connections for one 204,745,168 byte file), with no per-client sequential state. Reads must be seekable (no stream-only content store) | request order of `AM_Base.exe` |
| IR-5 | Accept at least 7 concurrent connections from one client, each strictly request-after-response (no pipelining was observed, so pipelining support is not required) with keep-alive, and keep an idle connection open at least 31 s (the client closed its own after 27 to 30 s idle). A server that closes idle connections earlier is UNOBSERVED against this client | the 8 connection timeline; FIN frames |
| IR-6 | Send the response headers shown (`Content-Type: application/octet-stream`, `Accept-Ranges: bytes`, `ETag` and `Last-Modified` stable per file across ranges and across connections, `Content-Length`, `Content-Range`), and no `Content-Encoding` and no compression of content (the request had no `Accept-Encoding`). `Server`, `X-Powered-By` and `Cache-Control` were not needed to be reproduced: whether the client needs any of them is UNOBSERVED (it sent no conditional request, so `ETag` and `Last-Modified` were never used by the client in this run) | response header shape; no conditional requests in 216 requests |
| IR-7 | `HEAD`, conditional requests (`If-Range`, `If-None-Match`, `If-Modified-Since`), `416` and a full-body `200` for a `GET` without `Range` were never exercised by this client: none is required by the evidence. Implement them per HTTP semantics anyway (`Specified` by the HTTP RFCs and WSUSSS section on content, not by these captures) and mark them UNOBSERVED in the validation ledger | counts of 0 in the capture |
| IR-8 | Serve the content of every file referenced by `FileLocation` for an approved update, including files the client will not request (5 of the 9 files here were never requested: the client picked 4). A server must not assume that all listed files are downloaded | 4 of 9 files |
| IR-9 | Report events: accept the `ReportEventBatch` shapes of the table above and answer `true`; do not require any event id to appear. Install state must be verified from the guest, not from these events | events 147, 156, 162, 167, 181, 183 |
| IR-10 | Guest preconditions for any native test against this project's server (not a server requirement): DoSvc enabled and running (a guest reboot after enabling it), `WUServer` pointing at the server and not reset by the base's startup task, Defender enabled if the update is a Defender definition | root cause table above |

Not established by this capture or the operator report: why the SCM required a
reboot (inferred only); whether `DODownloadMode` 0 is the setting that
produced a pure-HTTP, non-peer download here (the pcap shows only HTTP to the
server, and one `Microsoft-Delivery-Optimization/10.1` user agent); how the
client verifies the downloaded SHA-1 (not visible on the wire); behavior against
any server other than this WS2025 WSUS, including on a `Range` it cannot
satisfy or a mid-download connection loss (no failure occurred); the
installation steps themselves (no install traffic exists; the result is the
operator's); whether other file types or update classes use the same ranges;
and whether the 1 MiB piece size is fixed (observed on 4 files of one update).

### 9.5 MS-WSUSSS against the real WSUS as upstream (2026-10-04, milestone M5)

Source and scope. Two kinds of client talked to the lab WSUS (Windows Server 2025
build 10.0.26100, WSUS role, IIS/10.0, plain HTTP on 8530, anonymous, no
authentication header sent) in its role as an UPSTREAM server: this project's
downstream importer (`wsus admin sync start`, `UpstreamSync` and `WsusssClient`,
reqwest backend) and the probe script `scripts/wsus/probe-wsusss.py` (plain SOAP
1.1 POSTs). Both ran through `scripts/wsus/capture-proxy.py` (raw captures are
local only, under `~/vm-lab/wsus-m0/captures/m5a` and `m5b`). Sanitized, partly
trimmed subsets: `docs/fixtures/wsus-m0-wsusss/` (README: provenance, trimming,
original hashes); decode tests `crates/wsus-protocol/tests/real_wsusss.rs`,
replay tests `crates/wsus-client/tests/real_wsusss_fixtures.rs`, fragment
comparison `crates/wsus-server/tests/fragments_real.rs`, ignored live tests
`crates/wsus-client/tests/real_wsusss.rs` and
`crates/wsus-cli/tests/real_upstream.rs` (need `WSUS_REAL_ORIGIN`). The server
was not a downstream-capable pair: no real downstream WSUS and no native
Windows client took part, so everything below describes what this ONE server
did for these requests. The lab catalog is the Microsoft Defender Antivirus
product only (plus every category and detectoid), `LazySync` true.

| Observation (2026-10-04, WS2025 10.0.26100 as upstream) | Evidence | Note |
| --- | --- | --- |
| Authorization: `GetAuthConfig` (Server Sync service, no cookie) returns `LastChange`, one `AuthPlugInInfo` with `PlugInID` `DssTargeting`, an empty `Parameter` and the RELATIVE `ServiceUrl` `DssAuthWebService/DssAuthWebService.asmx`; no `AllowedEventIds`. `GetAuthorizationCookie` (DSS auth namespace) with an arbitrary FQDN-valid `accountName` and an arbitrary GUID `accountGuid` and no `programKeys` answered 200 with `PlugInId` `DssTargeting` and a 496-byte `CookieData`; `GetCookie` with `protocolVersion` `1.20`, no `oldCookie`, answered 200 with a cookie that expires 240 minutes later (`Expiration` with seven fractional digits). No authentication, no registration of the downstream beforehand: anonymous access works, for two different account names and GUIDs | exchanges 000001 to 000003 | Matches the specified 240 minute Windows expiry. Whether the upstream recorded the account as a DSS table entry was not looked at. Authenticated or HTTPS deployments unobserved (port 8531 accepted a TCP connection; no request was sent to it) |
| Paths: the Server Sync and DSS auth paths answered in every letter case tried (`ServerSyncWebService/ServerSyncWebService.asmx`, all lower case, and `dssauthWebService/dssauthWebService.asmx`, `DssAuthWebService/DssAuthWebService.asmx`, all lower case). `ServerSyncWebService/ServerSyncProxy.asmx` (the WSDL address) answered 404. The same `GetAuthConfig` as a SOAP 1.2 envelope (`application/soap+xml`) was answered with a SOAP 1.2 response | direct probes of 2026-10-04 (not retained as fixtures) | The specification says the SOAP version is a configuration choice, not negotiated; this build answered both for this one call. Only `GetAuthConfig` was tried in SOAP 1.2 |
| Framing: responses `text/xml; charset=utf-8`, `Content-Length`, `Cache-Control: private, max-age=0`, XML declaration and `soap:` prefix. A client sending `Accept-Encoding: xpress` got `Content-Encoding: xpress` (a 539,053-byte `GetRevisionIdList` body arrived as 148,834 bytes). This project's `WsusssClient` does not send `Accept-Encoding` (it received identity bodies of up to 3,088,614 bytes) | exchanges, direct probe | Xpress for WSUSSS is not implemented in the client (the WUSP client has it, 9.3) |
| `GetConfigData` (no anchor and with the anchor of an earlier call) returns `CatalogOnlySync` false, `LazySync` true, `ServerHostsPsfFiles` false, `MaxNumberOfComputerIdsInRequest`, `MaxNumberOfDriverSetsPerRequest` and `MaxNumberOfPnpHardwareIdsInRequest` 0, `MaxNumberOfUpdatesPerRequest` 100, `ProtocolVersion` `1.20`, 39 `LanguageUpdateList` entries (`LanguageID` 0 `all`; only `en` enabled), `NewConfigAnchor` and `MaxUpdatesPerRequestInGetUpdateDecryptionData` 100. With an anchor the answer is short (999 bytes, no language list) | exchanges 000004, 000005 | The anchor form is `<counter>,<yyyy-MM-dd HH:mm:ss.fff>` as in the specification: the counter stayed `9438` for the whole session and the timestamp is the time of the call (so the anchor differs on every call even when nothing changed) |
| `GetRevisionIdList` with `GetConfig` true returned 4275 revisions (4233 distinct update ids: some categories list revisions 1 and 100 or 101 for the same id) of 295 `Category` documents without `CategoryType` (the roots and subcategories), 148 `Product`, 19 `UpdateClassification`, 5 `ProductFamily`, 3 `Company` and 3805 `Detectoid`. With `GetConfig` false it returned 24,509 revisions, all `UpdateType` `Software` and all Defender (280 bundles whose prerequisites carry the product and the classification as `IsCategory` clauses, 49 hidden intermediate bundles that name the same two ids in plain `AtLeastOne` clauses, 24,180 file-carrying leaves) | full decode of both lists in the local capture; fixtures hold the first 30 entries (README) | The specification says one entry per GUID; the category list repeats ids with different revisions. No paging: 539 KB and 3.1 MB single bodies. Categories were discovered from real data: product `8c3fcc84-7410-4a95-8b89-a166a0190486` "Microsoft Defender Antivirus" and classification `e0789628-ce08-4437-be74-2495b842f43b` "Definition Updates" (`CategoryType` `Product` and `UpdateClassification` in the `cat:CategoryInformation` of their documents) |
| Filter semantics (`GetConfig` false, no anchor): product list only, classification list only, product plus another real classification (Security Updates), another product plus the Defender classification: 0 revisions each; product AND classification, with Delta true or false, with or without `Languages` and `Get63LanguageOnly`: 24,509 (all of them); an empty `Categories` element with a classification: 0; a second, unrelated product next to the Defender product: 24,509; no filter at all: 24,509 | exchanges 000007 to 000009; direct probes | A listed id matches an update when it is one of its category ids; both lists are required once either is present. Because this catalog holds only Defender updates, a filter cannot be told from no filter by count here except through the zero cases; whether the match uses the `IsCategory` prerequisites or the plain `AtLeastOne` clause the leaves use is not distinguished |
| Anchor and `Delta`: with an anchor from an earlier call, an unfiltered `GetConfig` false call returns 0 revisions; the same call with product and classification listed with `Delta` false returns all 24,509 again; with `Delta` true returns 0. An anchor with an older timestamp (`1,2006-10-04 16:09:27.371`) returns all revisions; an anchor with a recent timestamp and counter 9437 or 9439 returns 0 (the counter is ignored by this call, the timestamp decides); a future timestamp returns 0; `garbage` is refused with `InvalidParameters` and `Message` `filter` | exchanges 000010 to 000012, 000018; client exchanges 000625 and 001046 | This project's client sent `Delta` false on every call, so every incremental run refetched all 24,509 ids (the `wsus-client` fix: `Delta` true exactly when an anchor is sent). `GetConfigData` and the category list with the old anchors returned 0 revisions as expected |
| `GetUpdateData`: 100 ids in one request were answered (302 KB, up to 1.5 MB in other batches of this run), 101 ids with `InvalidParameters` and `Message` `updateIds`; a duplicate id returns two items; an id the upstream does not hold, and a known id with a wrong revision number, return `InternalServerError` (HTTP 500, `soap:Server`, empty `Message`). Each item holds `Id`, optionally `FileDigestList` (one `base64Binary` SHA-1 per file) and either `XmlUpdateBlob` or `XmlUpdateBlobCompressed`; `fileUrls` holds one `ServerSyncUrlData` per file | exchanges 000013 to 000017 | Unknown ids are not reported per item: the whole call faults, which is why the importer's `MissingUpdateData` must stay an error |
| `XmlUpdateBlobCompressed` is a Cabinet: `MSCF` magic, one folder with LZX (window order 21, a 2 MiB window), one member named `blob`; the member is the whole `upd:Update` document as UTF-16LE without byte order mark and without XML declaration (for example 14,684 bytes for a 7,342 character document). It decodes with `caby` (`Cabinet::new`, `read_file_bytes`) and converts with the UTF-16LE rule to UTF-8 (`CabMetadataDecompressor`). Small documents arrive as `XmlUpdateBlob` text: over the whole lab catalog the 28 uncompressed documents were at most 2,469 characters (4,938 bytes as UTF-16) and the smallest of 24,481 compressed ones 2,700 characters (5,400 bytes) | exchanges 000013 to 000016; the whole catalog, decoded locally | Consistent with the specified 5,120 byte threshold measured on the UTF-16 text. The Microsoft sample's reading (a Cabinet holding the update XML) was right; the UTF-16LE detail is not in the sample notes. The two possible alternatives named in the task (Xpress, LZNT1) were not what the bytes were |
| Document shape: root `upd:Update` declaring `pub`, `upd` and the handler or applicability prefixes in use (`bar`, `lar`, `cat`, `cmd`) on the root and again on nested elements (`xmlns:lar=` on `lar:And`, `xmlns:bar=` on every `bar:` rule, `xmlns:cmd=` on `cmd:InstallCommand`, `xmlns:xsi=` on `HandlerSpecificData`); top-level children in the order `UpdateIdentity`, `Properties`, `LocalizedPropertiesCollection`, `Relationships`, `ApplicabilityRules`, `Files`, `HandlerSpecificData`; `Properties` attributes `UpdateType`, `DefaultPropertiesLanguage`, `Handler`, `MaxDownloadSize`, `MinDownloadSize`, `PublicationState`, `CreationDate`, `PublisherID` (and `AutoSelectOnWebSites` plus `ExplicitlyDeployable` on 280 bundles; `IsPublic`, `PerUser` on categories). `PublicationState` was `Published` or `Expired` (267 of the imported revisions were `Expired`). 433 revisions form the closure of the approved bundle: the bundle (`BundledUpdates` with four `AtLeastOne` groups of 7, 7, 7 and 103 alternatives), 124 hidden children (one group of 4 alternatives each) and 308 leaves; the leaves carry the files, the bundle none | full-catalog decode, fixtures `docs/` | `Expired` revisions are listed by `GetRevisionIdList` and served by `GetUpdateData`; this is the first Observed support for the importer's `PublicationState` rule |
| Importer result against this upstream: filtered synchronization (product AND classification) listed 28,784 revisions, staged 5,581 (4,275 categories and detectoids, 280 matching bundles, 1,026 bundled revisions pulled by dependency), excluded 24,229 by the local filter, activated in 24 s (release build), then a second run reported no change. Before the `Delta` fix the second run refetched everything | `wsus admin sync start` runs of 2026-10-04 | The local filter matches `IsCategory` prerequisite clauses; the 24,180 leaves carry the product only in a plain `AtLeastOne` and are therefore found through the bundles, not through the filter |
| Content: `LazySync` true and the bundle approved on the upstream: the importer's `--content approved` fetched all 155 distinct files of the bundle's 433 revisions (1.2 GiB, 155 of 155, no failure, no `DownloadFiles`), each verified by size, SHA-1 and SHA-256 against the metadata, URLs `Content/<last two hex, upper case>/<SHA-1 hex, upper case>.exe`; `GetUpdateData` left `UssUrl` empty and listed an `MUUrl` of the form `http://download.windowsupdate.com/<c or d>/msdownload/update/software/defu/2026/10/<name>_<sha1 lower>.exe` (no query string). Of the 9 `FileLocation`s the native client received for 18 revisions (section 9.3) 4 are in the approved bundle's closure and exist (the 4 the native client downloaded; byte for byte equal in a separate GET); the other 5 (`AM_Delta.exe`, of revisions that are not in the approved bundle's closure; three of them lie in the closures of the three superseded bundles the native client also asked about) answer 404 on the upstream | stored objects, direct GETs and HEADs of 2026-10-04 | "The update has 9 files" was the file-location count for 18 revisions; the approved update itself has 155. File locations are returned for files the upstream does not hold, so a `FileLocation` is not evidence of availability. Content is served on 8530, not on 80 |
| Content URL tolerance: path and hex case do not matter (`/content/ab/..hex lower..exe`, `.EXE`), a missing extension answered 403, a wrong folder or no folder 404, `HEAD` answers 200 with `Content-Length`, a `HEAD` carrying `Range` answered 416 | direct probes | Only for this build and the one file |

Faults seen: `InternalServerError` (unknown id, `soap:Server`), `InvalidParameters`
(bad anchor, too many ids: `Message` names the element), `InvalidCookie` (no
cookie); `faultstring` was always `Fault occurred` and the `detail` held
`ErrorCode`, `Message`, `ID` and `Method` (the quoted SOAPAction), `faultactor` the
service URL with the server's own port. Not observed: `ServerChanged`,
`FileDigestsMissing`, `ServerBusy`, `IncompatibleProtocolVersion`, an expired cookie
(the cookie lived 240 minutes and the runs were shorter), `DownloadFiles` (never
called: the fallback was switched off so the upstream stayed untouched), `GetDeployments`,
`GetUpdateDecryptionData`, reporting and driver operations.

Derived WUSP fragments against the real ones (nine revisions, section 9.3 for the
native side): a downstream server that keeps the whole `Update` document and derives
the MS-WUSP fragments (`wsus-server` `fragments`) differed from the real fragments in
these ways, all fixed in `fragments/derive.rs` and pinned by
`crates/wsus-server/tests/fragments_real.rs`:

- the Extended fragment names the remainder of `Properties` `ExtendedProperties`;
- `PublicationState`, `CreationDate` and `PublisherID` appear in neither fragment;
  attributes that equal their default (`ExplicitlyDeployable="false"`, `PerUser="false"`,
  `IsPublic="true"`) are dropped from both (`AutoSelectOnWebSites="false"` and
  `OSUpgrade="false"` are dropped by analogy, Unverified);
- `xsi:type` becomes `type` (`<HandlerSpecificData type="cmd:CommandLineInstallation">`;
  the prefix inside the value is kept; observed on `HandlerSpecificData` only);
- the Core `Properties` attributes follow the order `UpdateType`, `ExplicitlyDeployable`,
  `AutoSelectOnWebSites` (not significant in XML, now identical to the real text).

After the fix, Core, Extended and the `en` `LocalizedProperties` of the nine revisions
(a Defender bundle, five software leaves with files and handler data, three categories)
equal the real fragments modulo attribute order and the redacted `LinkId` query value of
the sanitized native fixtures, and the lenient fragment parser and `UpdateIndex` accept
them. Unchanged and already equal: namespace removal, the `b.`, `m.` and `d.` prefixes
(`lar:`, `cmd:`, `cat:` and the other handler namespaces carry no prefix, as in the real
fragments), the `Files` element with `Digest`, `DigestAlgorithm`, `FileName`, `Size`,
`Modified` and `AdditionalDigest`, `Relationships` (including four `BundledUpdates`
groups), `ApplicabilityRules` and `LocalizedProperties`. Not covered by evidence: Eula
fragments (the lab updates have none), drivers, other handlers (MSI, CBS), `IsCategory`
variants beyond those seen, and the `wsus-protocol` lenient index does not read the
element name `ExtendedProperties` as properties (it reports it as an extension), which is
a gap in `wsus-protocol` itself, not fixed here.

Importer defects found by this run and fixed (own code, not specification facts): the
blob decompressor was a stub; the wire filter was sent with one list only (selects
nothing) and with `Delta` always false (refetches everything on each run);
`ContentSelection::Updates` looked at the approved update's own files only (a bundle has
none; it now follows the prerequisite and bundle closure, like the WUSP server); the
convention URL used lower case without extension; missing files were requested with one
`DownloadFiles` and a 5 s wait per file (now one batch, and switchable); catalog
validation and closure queries scanned every fragment per relationship (hours on 24,509
revisions, now seconds).

### 9.6 Staged SyncUpdates in this project's server (implementation, 2026-10-04)

Provenance of the statements below: the MS-WUSP prose was NOT re-fetched for this
change (no network access); "Specified" means the text recorded in sections 2, 5.2
and 5.3 from the pinned fetch. "Observed" means the recorded real-WSUS dialogue
(`docs/fixtures/wsus-m0-native/{scan,flow}`, `docs/fixtures/wsus-m0`) or the
guest's WindowsUpdate.log against this server. "Decision" is this project's
choice, not backed by an observation. "Lab note" is a statement of the client
wire agent whose raw exchange is not retained. The first native run
against this server is section 9.7 (ledger C31, `Partially validated`); the
statements below were written BEFORE it, and where it contradicts them they are
corrected in place.

Why the first implementation failed (Observed, guest against this server): the
whole closure was delivered at once; the agent logged "Service protocol version
lower than what is required for fast AppCatSan" (we advertised 3.0, the real
server 3.2), "StartCategoryScan failed" (not implemented), then "Found 0 updates
and 1 categories; evaluated appl. rules of 5 out of 442 deployed entities" and
reported two non-leaf ids installed ([50, 4064]). Offline reproduction
(`native_sim.rs`, closure mode, real-derived catalog): exactly the five entities
that have no prerequisite clause (categories e0789628 and, after the category
edge fix, 56309036; detectoids for processor architectures 0, 5, 9 and 12) can
be evaluated when the request that carried them listed no installed id, and of
those only the AMD64 detectoid (id 4064) and the True categories (50, and 9)
evaluate as installed. That is what the guest reported.

That first failure had several causes, not only the delivery mode; the five root
causes found from the guest log are in 9.7, together with the result that followed
their fixes. The offline reproduction above is a statement about the model.

| Topic | MS-WUSP (Specified) | Real WSUS (Observed) | This server (Decision) |
| --- | --- | --- | --- |
| Prerequisite satisfaction | 3.1.5.7: the server keeps updates whose prerequisites are satisfied by `InstalledNonLeafUpdateIDs`; a clause is an `AtLeastOne` OR, clauses are ANDed, a bare `UpdateIdentity` is a clause of one; an id names the update, implicitly its highest revision | A prerequisite is satisfied only when its id is in `InstalledNonLeafUpdateIDs` (lab note); `IsCategory` clauses behave the same: in `scan` the category chain 56309036, 6964AAB4, dd78b8a1 is delivered one level per round after the previous id was reported installed | Staged: deliverable = not cached AND every clause has an alternative among the in-scope updates whose server-local id is in the installed list. Clauses are parsed from the stored or derived Core fragment (the `relationships` table flattens the AND of ORs and prunes alternatives unknown at import); when the fragment has no `Prerequisites` the table rows are used, each as a clause of one. Only the newest in-scope revision satisfies a clause |
| Clause with no alternative in the served catalog | n/a | n/a | Decision (guess): counts as satisfied, because no client could ever evaluate it and it would hide an approved update forever; the importer already rejects such catalogs |
| Delivery order and paging | Server MAY return a subset and MUST set `Truncated` | 30 per page; a full page with `Truncated` false occurs; mixed leaf and non-leaf in one response occurs (`flow` 000001: 6 updates, 1 leaf); `scan` delivered one update per round | Non-leaf first, then by server-local id; page size `max_sync_new_updates` (default 30); `Truncated` only when more deliverable revisions remain, never with an empty page |
| Extra request after non-leaf delivery | 3.1.5.7: call again if the response held an `IsLeaf=false` update | The native client does (`scan` 000006 to 000008) | The pinned catalog generation lives through such a sequence, not just through truncation; released on the final response |
| First call | Empty `InstalledNonLeafUpdateIDs` | The first call OMITS all three lists (`scan` 000006) | Empty and absent are the same; first round delivers revisions with no prerequisite |
| Cached ids no longer valid | `OutOfScopeRevisionIDs`: revisions the client holds that are out of scope | Not seen in the retained fixtures. Lab note: a cached revision whose prerequisite is not in the installed list is answered there | Out of scope = cached and not in the client's scope, plus (config `out_of_scope_unsatisfied`, default on, staged only) cached and in scope with an unsatisfied clause. The second rule rests on the lab note only |
| `IsLeaf` | Non-leaf means other updates depend on it | False for every prerequisite target in the whole generation, bundle members are leaves | Unchanged shared rule, plus targets of `IsCategory` clauses (`category` relationships), which are prerequisites too (the middle category of the `scan` chain is non-leaf). The approved-update closure now follows `category` edges as well (it used to skip them, which left the middle of the Defender category chain, 6964AAB4 and 56309036, out of reach) |
| `InstalledNonLeafUpdateIDs` size | Not specified | 400 accepted, 401 `InvalidParameters`, message `parameters.InstalledNonLeafUpdateIDs` | Same, staged only (`max_installed_non_leaf_ids`, 0 disables). `OtherCachedUpdateIDs` is not capped. Counts list entries (`Vec` length), like the real one: 401 entries with a repeated id and 400 non-leaf ids plus a leaf id are rejected, host tests `installed_non_leaf_cap_counts_list_entries_not_distinct_or_non_leaf_ids` (9.9). Closure mode ignores the list and does not enforce the cap (no real-server observation for closure) |
| `DriverSyncNotNeeded` | Boolean in `SyncInfo` | Software passes: `false` in `flow`, `true` in the category-filtered `scan`; driver pass (`SkipSoftwareSync`): `true`, no `NewUpdates` element | Driver pass true and nothing else (no driver catalog). Software pass false, true when `FilterCategoryIds` is present (the only request difference between `flow` and `scan` we can name; Decision) |
| `ProtocolVersion` | 3.2 SHOULD be returned; client MUST NOT call `StartCategoryScan` below 3.2 | 3.2; WUA logs a "fast AppCatSan" fallback when the version is lower | Staged advertises 3.2 (config `protocol_version` overrides) because staged now supports what a 3.2 client expects from this project's scope: `StartCategoryScan`, installed-list driven delivery, the 400 cap. Fast AppCatSan itself is not implemented or verified. Closure advertises 3.0 (the native agent completed against 3.0 in closure mode and against 3.2 in staged mode, 9.7; neither captured run sent a `StartCategoryScan`, so the fast AppCatSan path is still unverified) |
| `StartCategoryScan` | `requestedCategories` is a DNF: `IndexOfAndGroup` ANDs, groups OR; response `preferredCategoryIds`, `requestedCategoryIdsInError`; 200 or more categories is `InvalidParameters` | Request has no cookie; one category echoed in `preferredCategoryIds`, no error list | Preferred = requested categories that exist (any revision, `Present`) in the served catalog, order of first appearance, deduplicated; the others go to `requestedCategoryIdsInError` (Decision: the real server's rule for unknown categories is unobserved; the real server had the full catalog, ours is filtered). The DNF is validated, not interpreted; `FilterCategoryIds` of `SyncUpdates` is accepted and ignored (we deliver the approved closure, not a category scan). Native, against this server (9.7): the guest sent NO `StartCategoryScan` in either captured run, so this answer was not exercised by a native agent |
| `Deployment` | n/a | Every `UpdateInfo` has one; `Evaluate`, `Bundle`, `PreDeploymentCheck`, `Install` | Unchanged (shared by both modes) |

Delivery modes (`ServerConfig::sync_delivery`, `[server] sync_delivery`): `staged`
(default) as above, and `closure` (the earlier behavior: the whole approved closure,
installed list ignored, 200 per page when unset, `ProtocolVersion` 3.0). Both keep the
shared pieces identical (`Deployment` on every `UpdateInfo`, `IsLeaf`, the category
edges of the closure). Both were run with a native agent on 2026-10-04 (9.7): in both
the agent found, downloaded and installed the Defender bundle. An earlier version of
this paragraph said `closure` was expected to fail for the bundle and that a test
asserted that on purpose; the real agent contradicted that, so the claim is withdrawn.
Which of the two fixes (the category chain, staged delivery) closure mode needed is not
isolated (9.7).

What the offline model (`crates/wsus-server/tests/native_sim.rs`) does and does not
show. It is a model written by this project from the same observations as the server,
not WUA. Under its rules (an agent that evaluates only entities whose prerequisites
were in the installed list when it sent the request, and never re-evaluates), staged
delivery converges on a synthetic Defender-shaped catalog and on a copy of the lab
database (bundle a2fef9b0 revision 200 delivered with `Install` and its children with
`Bundle`), and the recorded `scan` dialogue replays request by request with the same
counts of leaf/non-leaf, `Truncated` and `DriverSyncNotNeeded`. Under the same rules the
closure delivery does not find the bundle; THAT PREDICTION WAS WRONG for the real agent
(9.7), so the model is more conservative than WUA and its closure-mode tests are
model-only assertions, kept to document the model, not the product. What the model does
NOT prove: that the real agent evaluates the same way (it demonstrably does not, for
closure), that it re-evaluates nothing when its installed set grows, leaf applicability
(`IsInstallable`, file versions, MSI), the fast AppCatSan path, content, install or
reporting.

### 9.7 Native WUA against this project's server (first success, 2026-10-04)

Status: a native Windows Update Agent found, downloaded and installed the
approved Defender definitions bundle from THIS project's server, in both
delivery modes. This is one client build, one lab-modified image, one update,
plain HTTP, one client at a time. Sources, kept apart:

- PCAP (all Observed): `~/vm-lab/wsus-m0/captures/staged1/flow.pcap` (SHA-256
  `db7893c61072f4282d39d3d7063a933efa6e289ef40686e3df46989fd814c899`) and
  `closure1/flow.pcap` (`69a0a437f2b7e6ed6bae2d92a51fb9ade6f082bd017492f431d2dcafbb60f5b7`),
  local only, tcp port 18540, tshark 4.6.8 (`-o http.decompress_body:FALSE` for
  the wire encoding, decoded bodies for the XML). Sanitized subsets:
  `docs/fixtures/wsus-m0-ours/`; shape tests
  `crates/wsus-server/tests/real_native_vs_ours.rs`. Everything numbered below
  was computed from the whole pcaps, not only from the retained subsets.
- SERVER LOG (Observed): `~/vm-lab/wsus-m0/ours/server.log` (staged) and
  `server-closure.log`, local only. Their request counts equal the pcaps.
- LEAD/OPERATOR (verified by the lead, not retained in the repository, not
  evidenced by the pcaps): the COM results, the guest's `WindowsUpdate.log`
  lines quoted below, `Get-MpComputerStatus`, the server database and the
  content store checks. They are as reliable as that report.
- Server build: commit `fd2a126` plus the uncommitted staged-delivery work of the
  working tree (exact tree NOT recorded). Client: Windows Update Agent
  1507.2601.30012.0 (`Client-Protocol/2.90`), Windows 11 25H2, OS
  10.0.26200.8037, Defender platform 4.18.25080.5, QEMU guest.

#### Result (LEAD/OPERATOR, with the pcap cross-checks marked)

| Fact | Source | Label |
| --- | --- | --- |
| COM search `ResultCode` 2, `Count` 1; download `ResultCode` 2, `hr` 0; install `ResultCode` 2, `hr` 0 (the bundle KB2267602 version 1.459.547.0, update id `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`, revision 200) | LEAD | Observed (guest) |
| `Get-MpComputerStatus` `AntivirusSignatureVersion` went `0.0.0.0` to `1.459.547.0`; the definitions had been removed beforehand with `MpCmdRun -RemoveDefinitions -All`. This, not any event or result code of a report, is the install evidence | LEAD | Observed (guest); the pcaps show no install traffic |
| The same outcome in `closure` mode (`sync_delivery = "closure"`) as in `staged` | LEAD; pcap `closure1` shows the download (215 `206`s) and the report events | Observed. Whether the signature version was reset between the two runs is the lead's procedure and is not captured |
| Our server's database recorded the native computer with a `last_report` time | LEAD | Observed (server store) |
| Content store after the runs: 155 files of the bundle, `wsus admin content verify --deep` 0 corrupt, 0 missing | LEAD | Observed (server store) |
| Server log counts, staged run: 11 `SyncUpdates`, 1 `RegisterComputer`, 1 `GetExtendedUpdateInfo`, 215 content `GET`s all `206`, 2 `ReportEventBatch` `200`, plus `GetConfig`, `GetAuthorizationCookie`, `GetCookie` (all `200`); one `GET` of the client route answered `405` before the guest started (not in the pcap). Closure run: 4 `SyncUpdates` and otherwise the same | SERVER LOG; equals the pcaps (18 and 11 SOAP POSTs, 215 `GET`s each) | Observed |

Numbers that differ from the first summary of the run, or that the pcaps do not
reproduce: the staged and closure pcaps show 3 distinct content files, not 4
(`MpSigStub.exe`, 918,944 bytes, was never requested from this server), and the
server returned 4 `FileLocation`s for the 24 revision ids the client asked about,
not 9 (the 9 belong to the real WSUS capture, 9.3, which asked about 18). The
"4 of 9 files fetched" figure is therefore NOT established from the pcaps; what the
pcaps establish is 3 of the 4 returned locations were fetched. The 155 files of
the bundle in the store are the importer's work (9.5), unrelated to what the client
requested. Why `MpSigStub.exe` was not requested (already present on the guest from
earlier attempts, or not needed) is not established.

#### Dialogue, staged mode (PCAP; Observed)

Handshake: `GetConfig` (`ProtocolVersion` 3.2), `GetAuthorizationCookie`,
`GetCookie`, `RegisterComputer` (identity-encoded answer, 252 bytes), then 11
`SyncUpdates`, all on the first connection, then `GetExtendedUpdateInfo` at 0.98 s,
the first content `GET` at 1.86 s, the last content response at 4.97 s, the two
`ReportEventBatch` posts at 6.89 s and 15.81 s. No `StartCategoryScan` was sent.
Rounds (installed = `InstalledNonLeafUpdateIDs` count and other = `OtherCachedUpdateIDs`
count of the REQUEST; `-` = array omitted):

| Round | Installed | Other | New updates | Leaf | `Truncated` | `Deployment.Action` of the new updates | Response wire / decoded bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | - | - | 6 | 0 | false | Evaluate 6 | 1,366 / 4,080 |
| 2 | 3 | 3 | 1 | 0 | false | Evaluate 1 | 1,008 / 1,445 |
| 3 | 4 | 3 | 1 | 0 | false | Evaluate 1 | 1,290 / 2,079 |
| 4 | 5 | 3 | 30 | 28 | false | Evaluate 2, Bundle 28 | 17,117 / 57,668 |
| 5 | 7 | 31 | 1 | 0 | false | Evaluate 1 | 1,128 / 1,717 |
| 6 | 8 | 31 | 30 | 30 | true | Install 1 (the bundle, server-local id 4555), Bundle 29 | 19,749 / 137,018 |
| 7 | 8 | 61 | 30 | 30 | true | Bundle 30 | 24,591 / 170,579 |
| 8 | 8 | 91 | 30 | 30 | true | Bundle 30 | 23,612 / 162,500 |
| 9 | 8 | 121 | 30 | 30 | true | Bundle 30 | 24,813 / 170,953 |
| 10 | 8 | 151 | 11 | 11 | false | Bundle 11 | 8,554 / 64,483 |
| driver pass | 8 | - | 0 | 0 | false | none (`SkipSoftwareSync` true, `DriverSyncNotNeeded` true) | 536 / 665 |

Total 170 `UpdateInfo`: 159 Software (the bundle and 158 members), 4 Category, 7
Detectoid; 11 non-leaf (all Category and Detectoid, all `Evaluate`); every one has a
`Deployment`, with `LastChangeTime` `2026-10-04` (date only). The pages never exceed
30; a full page with `Truncated` false occurs (round 4). The last request (the
driver pass) is 50,024 bytes, the others 4,330 to 6,808.

#### Dialogue, closure mode (PCAP; Observed)

Same handshake (`ProtocolVersion` 3.0), 4 `SyncUpdates`, `GetExtendedUpdateInfo` at
0.91 s, the first content `GET` at 1.41 s, the last response at 4.72 s, the report
posts at 6.43 s and 15.12 s. No `StartCategoryScan`.

| Round | Installed | Other | New updates | Leaf | `Truncated` | Actions | Response wire / decoded bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | - | - | 200 | 189 | true | Evaluate 11, Install 1 (bundle, id 4555), Bundle 188 | 126,524 / 851,505 |
| 2 | 8 | 192 | 200 | 200 | true | Bundle 200 | 163,103 / 1,125,833 |
| 3 | 8 | 392 | 44 | 44 | false | Bundle 44 | 34,183 / 250,989 |
| driver pass | 8 | - | 0 | 0 | false | none | 533 / 665 |

Total 444 `UpdateInfo` (433 Software: the bundle and 432 members; 4 Category; 7
Detectoid; 11 non-leaf), every one with a `Deployment`. The lead's figure for
the real WSUS is 159 `UpdateInfo` in its dialogue; this server's staged run delivered
159 Software revisions (170 `UpdateInfo` with the categories and detectoids) and the
closure run 433 Software revisions. Whether the two 159s are the same set was not
compared. The bundle arrived in round 1 (closure) or round 6 (staged).

In both modes the client reported 8 installed non-leaf ids at its final request;
against the real WSUS it reported 87 to 94 (9.3). The catalogs delivered differ
(this server served the Defender product only and fewer entities), so the
difference is not by itself an error; it was not investigated.

#### Content and reports (PCAP; Observed, both modes)

- 215 `GET` and nothing else (no `HEAD`, no conditional request, no `416`, no `200`
  for content), every response `206` with `Content-Range` equal to the requested
  range and `Content-Length` `b - a + 1` (0 mismatches in 430 pairs). 3 files:
  `AM_Engine.exe` 6,662,560 bytes (7 ranges), `AM_Base.exe` 204,745,168 bytes
  (196 ranges), an `AM_Delta.exe` 11,606,440 bytes (12 ranges); names and sizes as
  in 9.4. The ranges of each file cover it exactly once (no gap, no overlap, no
  repeat), 212 are exactly 1 MiB and the last of each file is short (371,104;
  272,848; 72,104 bytes, ending at `size - 1`). Byte total 223,014,168. Requested
  in shuffled order, as in 9.4.
- Connections: `staged` used 5 content connections (`AM_Engine.exe` 7 requests,
  `AM_Base.exe` 108 and 88, the delta 9 and 3), `closure` used 3 (7, 196, 12),
  against 7 against the real WSUS (9.4); the SYNs were within 0.3 s of the first
  `GET`. At most 3 requests in flight by interval overlap (response frame time as
  the end of an interval; the same caveat as 9.4). The reason for 5 and 3
  connections against 7 is not established. No TCP retransmission or reset in either
  pcap. The client closed every content connection first (31.84 to 32.42 s); the
  SOAP connection ended at 48.45 s (staged, the server's `FIN` first) and 75.13 s
  (closure, the client first).
- Request headers identical in shape to 9.4 (`Connection`, `Accept`, `Range`,
  `User-Agent: Microsoft-Delivery-Optimization/10.1`, `MS-CV`, `Content-Length: 0`,
  `Host`); no `Accept-Encoding`. Our response headers, wire order, identical on all
  430: `content-type: application/octet-stream`, `content-length`, `etag` (a quoted
  strong tag, 64 hex digits, constant per file), `accept-ranges: bytes`,
  `content-range`, `date`. Compared with the real WSUS (9.4) there is no
  `Last-Modified`, `Server`, `X-Powered-By`; the client did not need them (it sent
  no conditional request, so the `ETag` was never used by it). The client ran
  to completion against this behavior, so none of IR-1 to IR-6, IR-8 and IR-9 of 9.4
  was contradicted; IR-7, the clamp of IR-2, 7 concurrent connections and the
  idle-timeout part of IR-5 were not exercised.
- Reports: two `ReportEventBatch` posts per run, both answered `200` with
  `ReportEventBatchResult` true. Events, in order: 147, 156, 167, 162, 181 (first
  post, 9,360 bytes) and 183 (second post, 2,341 bytes), every `Win32HResult` 0, the
  same ids in the same order as the native client sent to the real WSUS in 9.4. The
  `B=` datum of event 162 is 223,014,168 = the byte total of the 215 ranges above. The
  server's derived status for the computer from these events was NOT verified; only
  that the batches were accepted and a `last_report` time recorded (LEAD). Event
  names are still not established.
- Xpress (Observed): the client sent `Accept-Encoding: xpress` on every SOAP request
  and its request bodies were uncompressed. The server answered with
  `Content-Encoding: xpress` on 17 of 18 SOAP responses (staged) and 10 of 11
  (closure); the exception is the 252-byte `RegisterComputer` answer, sent identity
  (below the server's threshold). The largest were the closure rounds 1 and 2
  (851,505 and 1,125,833 bytes decoded, 126,524 and 163,103 on the wire). After every
  one of them the client proceeded to its next request, which is the acceptance
  evidence; the guest's own decode messages are not retained. Content was never
  compressed. This moves the "native WUA accepts Xpress bodies produced by this
  server" item of 9.3 from NOT verified to Observed once, for this build pair; a
  failed decode would have been expected to stop the scan.

#### Failures that preceded the success, each root-caused from the guest's `WindowsUpdate.log` (LEAD; Observed in the guest log)

| # | Symptom and the log lines as reported | Cause | Fix and evidence label |
| --- | --- | --- | --- |
| 1 | The guest never reached this server, or WU backed off (`0x80240438`) | The lab image, see the checklist below | Image changes; Observed (guest), not a server defect |
| 2 | `*FAILED* [80070057] timeutil.cpp @285 ... PopulateDataStore failed` right after the `SyncUpdates` response | The server omitted `Deployment` on UpdateInfo that was not approved (only the approved one had it). The real server sends a `Deployment` on 159 of 159 `UpdateInfo` with the 7-field shape (`ID`, `Action`, `IsAssigned`, `LastChangeTime`, `AutoSelect`, `AutoDownload`, `SupersedenceBehavior`) and a date-only `LastChangeTime` | Every `UpdateInfo` now has one; now Observed in both pcaps (all 170 of the staged run and all 444 of the closure run have one; the retained subset of 121 is tested in `real_native_vs_ours.rs`). The decoder marks `Deployment` optional; whether the specification requires it was not re-checked (no network). Observed (real WSUS, guest log), Implementation decision (the shape) |
| 3 | The client reported 2 installed non-leaf ids instead of 87 to 94 and logged `evaluated appl. rules of 5 out of 442 deployed entities` | `IsLeaf` was computed wrongly: bundle members were non-leaf. Real: non-leaf only for prerequisite targets anywhere in the catalog | Rule fixed (9.6 `IsLeaf` row); Observed (real WSUS leaf pattern, 9.3 and the guest log), Implementation decision (the rule) |
| 4 | The Defender category chain (`6964AAB4`, `56309036`) was never delivered | The approved-update closure skipped `IsCategory` relationships, and `IsLeaf` ignored `IsCategory` targets | Both fixed by the staged-delivery work; Observed (the `scan` capture delivers the chain one level per round, 9.3), Implementation decision |
| 5 | `Service protocol version lower than what is required for fast AppCatSan-- assuming full scan required`, then `StartCategoryScan failed [80240436]` | The server advertised `ProtocolVersion` 3.0 and `StartCategoryScan` was not implemented | `ProtocolVersion` 3.2 in staged mode (Specified: 3.2 SHOULD be returned and a client MUST NOT call `StartCategoryScan` below 3.2, per 5.2 as recorded; Observed: the log lines), implementation Decision. NOTE: neither pcap of the successful runs contains a `StartCategoryScan`, so this server's answer to one was not exercised natively, and whether 3.2 is what removed the failure (closure mode advertised 3.0 and also succeeded) is not isolated |

#### Which change mattered for closure mode: not isolated

Both modes contain the `Deployment` fix, the `IsLeaf` fix and the category-chain fix
(rows 2 to 4); only the delivery differs (and `ProtocolVersion`, 3.0 against 3.2).
The record therefore does not say which of "category chain" and "staged delivery"
was necessary for closure mode to work; closure mode WITHOUT rows 2 to 4 was not
re-run. What is established is the reverse of the earlier prediction: the offline
simulator `crates/wsus-server/tests/native_sim.rs` predicted that closure mode would
NOT find the bundle (an agent that evaluates only entities whose prerequisites are in
the installed list it had when it sent the request, and never re-evaluates) and the
real agent DID find, download and install it in closure mode. The model is therefore
more conservative than the real agent; it was built from the same observations as the
server, is not evidence of native behavior, and its closure-mode "known limitation"
test is relabeled model-only (inventory 9.6 and the test file). How the real agent
reached it (for example by re-evaluating entities when its installed set grew:
installed 8 after round 1, `Install` and the members in the same response) is not
visible on the wire and is not established.

#### Lab-image hazards (checklist for reproducing; LEAD, Observed in the guest)

- [ ] The base scheduled task `VMBase-DisableWindowsUpdate` re-registers and resets
  `WUServer` to `http://127.0.0.1` on a fresh instance's first-boot provisioning, so
  the tasks must be UNREGISTERED, not only disabled (9.4 recorded the task as
  disabled for its instance; on a fresh instance that was not enough).
- [ ] The Delivery Optimization service (`DoSvc`) is disabled by the image and must be
  enabled; the service manager needs a reboot before it starts (9.4, IR-10). UsoSvc
  and WaaSMedicSvc stay disabled in this procedure.
- [ ] The Defender policy `DisableAntiVirus` must be removed (it survives the base's
  own restore script), or the definitions are not offered.
- [ ] After failed attempts WU backs off (`0x80240438`) until its datastore is reset:
  rename `C:\Windows\SoftwareDistribution` (and let it be recreated).
- [ ] For a repeat run: remove the definitions first with `MpCmdRun -RemoveDefinitions
  -All`, check `Get-MpComputerStatus` reads `0.0.0.0`, then scan, download and install
  and read the version afterwards.
- [ ] Point `WUServer` and `WUStatusServer` at this server's `advertised_content_url`
  origin (plain HTTP port 18540 here).

#### What is and is not established by 9.7

Established for one run pair: the dialogue above, the content and report shapes, Xpress
acceptance, and (LEAD) the install by signature version. NOT established: TLS; more than
one client or any concurrent clients; approval removal, decline or deadline; uninstall;
restart or cookie-key rotation under a native client; any update other than this one
bundle; drivers; cumulative updates; a client build other than 1507.2601.30012.0; an
unmodified lab image; the fast AppCatSan path (never named in the successful runs'
captures); this server's `StartCategoryScan` answer under a native client; the derived
computer status from reports; resume after an interrupted download; `HEAD`, conditional
requests and `416` against a native client; and which of the two runs' working tree
was exactly built.

### 9.8 This project's WUSP client against the real WSUS (OBSERVED 2026-10-05)

Same lab WSUS as 9.1 to 9.5 (Windows Server 2025 10.0.26100, protocol 3.2, plain HTTP). The client ran through a
recording proxy and through a fault-injecting proxy; the evidence for each ledger row (C4 to C8) is in
`docs/wsus-validation.md`. What is new on the wire:

- **Content URLs follow the request's `Host` header.** `GetFileLocations` answers with `http://<host>:8530/Content/<XX>/<SHA1>.<ext>`
  where `<host>` is the hostname of the `Host` header the SOAP request carried and `8530` is the server's own port. A proxy that
  rewrites `Host` (or listens on another port while keeping the hostname) therefore produces content URLs that bypass it or
  point at a closed port. The path component is the file's uppercase SHA-1, which gives an independent check of downloaded
  bytes (`<XX>` is its last two hex digits).
- **Counts for one full client sync** (fresh state, no filter): 1 `GetConfig`, 1 `GetAuthorizationCookie`, 1 `GetCookie`, 1
  `RegisterComputer`, 180 `SyncUpdates` pages (5,377 revisions delivered, 112 of them later removed, 5,265 visible), then 24
  `GetExtendedUpdateInfo` requests for 1,166 in-scope revisions that carry files (up to 50 per request). A repeat sync with nothing
  changed is one `SyncUpdates`. The id lists in the requests grow with every page (5,261 ids across `InstalledNonLeafUpdateIDs` and
  `OtherCachedUpdateIDs` in the last page request) and the real server accepted them.
- **`RefreshCache` after `InvalidCookie`/`ServerChanged`.** The client re-resolves all 5,265 cached revisions in batches of 200 (27
  requests, `200`). The server returned a local id for 4,349 of them; the 916 it left out were exactly the revisions whose
  deployment action is `Bundle` (the leaf updates that carry files). A client that drops what the server does not return, as this
  one does, must fetch those again (31 `SyncUpdates` pages, 916 revisions, 1.4 MB in the first response); the end state was
  byte-identical to the original.
- **Content `GET`s.** Plain `GET` with `Accept-Encoding: identity`, `200` and `Content-Length` for full requests; `Range: bytes=N-`
  requests answer `206` (`Content-Length` = remaining bytes). All 155 files of the approved Defender bundle (1,218,839,376 bytes) were
  fetched in 11 s over loopback with 4 concurrent downloads.
- **`GetFileLocations`** takes SHA-1 digests (batches of 100 in this client) and answered `200` with one location per digest;
  **`GetExtendedUpdateInfo2`** answered `200` for the `Extended` and `FileUrl` fragment types (the second returned the location).
- **`ReportEventBatch`.** The server answers `200`, stores the event asynchronously (visible in `SUSDB.dbo.tbEventInstance` a few
  seconds later, `ComputerID` = the client's `TargetID` GUID), and keeps one row per (computer, event type): a later event
  instance of the same type replaced the earlier one (table count unchanged); a redelivered batch with the same instance id was
  accepted and left one row.
- **Not produced by the real server in these runs:** any SOAP fault. The fault handling rows were exercised by injecting
  faults in the real fault envelope format (see C6).
- **Lab note.** Host disk contention (journal commits blocked for tens of seconds under heavy VM I/O) made the fsync-heavy client state
  writes look like 120 s server stalls; the tests that matter ran with the state directory on tmpfs.

### 9.9 This project's client against this project's server (P3, OBSERVED 2026-10-06)

Status: one session of the P3 pair (ledger C14 and C52 to C58, `Partially validated`). Both halves are this project's own
code, written from the same specification text; agreement here is NOT evidence about any Microsoft software. The
server was `wsus server run` on the host (plain HTTP, loopback), working on a COPY of the catalog and content of the C31
setup (5,581 revisions, one approval, 155 content objects, 1,218,839,376 bytes); the lab WSUS was neither contacted nor
written. Builds: commit `cda13ef` from a clean worktree (host `wsus` SHA-256 `b600622c...c659`, Windows `wsus.exe`
SHA-256 `61fdf1b5...2d36f`, full values in the ledger's reference environment). Logs and guest outputs stay local under
`/data/cache/osi-p3/`. What was true before the session: this project's client had already run against this project's
server in three earlier places (the host client against the lab instance, inventory 9.8 and ledger S4; the guest installs of
`docs/wsus-install.md` rounds 1 and 2; the `wusa` run of C51 against a one-update synthetic catalog), but never as a P3
session with injected faults, restarts and stated limits.

**Sync matrix** (fresh host client per row, Xpress accepted, then `client download` of the approved bundle):

| `sync_delivery` | `delivery_scope` | Pages | New revisions | Extended fragments | Visible | Seconds | Bundle download |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `staged` | `approved` | 19 | 444 | 433 | 444 | 10.6 to 12.2 (3 runs) | 155 of 155 |
| `closure` | `approved` | 3 | 444 | 433 | 444 | 9.5 | 155 of 155 |
| `staged` | `all_non_declined` | 139 | 4,157 (4 later removed) | 59 | 4,153 | 48.2 | refused at `cda13ef`: the bundle is not in the client's scope (fixed, see the follow-up) |
| `closure` | `all_non_declined` | 27 | 5,273 | 1,045 | 5,273 | 66.7 (index build included) | 155 of 155 |

Deployment actions delivered: `approved` 432 `Bundle`, 11 `Evaluate`, 1 `Install`; `all_non_declined` closure 4,228
`Evaluate`, 1,026 `Bundle`, 18 `PreDeploymentCheck`, 1 `Install`; `all_non_declined` staged 4,094 `Evaluate`, 52 `Bundle`, 7
`PreDeploymentCheck`. In `staged`/`all_non_declined` the bundle did not arrive at `cda13ef`. The guest client got the same result (139 pages, `scan`,
`plan` and `install` exit 1). A real client sends only revisions it evaluated as installed, so this says something about this
client's cache policy, not about a native one.

**Follow-up on the host (2026-10-06, commit `84a1b95`, host only, fresh copy of the same store, port 18770).** Cause: once the
client cached more than 400 non-leaf revisions (431 held at the end) it listed 400 in `InstalledNonLeafUpdateIDs` and sent the rest
in `OtherCachedUpdateIDs`; the server delivers a revision only when every prerequisite clause has a listed alternative
(`scope::staged`, unchanged), and the bundle's prerequisite `be4048db-...` (local id 3817; its other three prerequisites were
listed) was never in the installed list, because the client ranks by known dependents and only the undelivered bundle depended on
it (probe output over 125 requests with 400 listed: 3817 absent in all of them; 3816 and 3815 absent in 2 early ones). No
per-request limit other than the one already recorded was found: the real WSUS accepts 400 installed ids and 3,679 other ids in
one request, a native client lists 87 to 94 installed ids (only what it evaluated as installed), our server has the same 400 cap
(`max_installed_non_leaf_ids`, staged only) and treats `OtherCachedUpdateIDs` as held but not as satisfying a prerequisite;
`ExpressQuery` is sent as false by this client and our server rejects it when true, so it is not involved. What a real WSUS does
with a list above 400 entries is in the subsection "Above the 400-entry cap on the real WSUS" below. Fix (client only): at the end of a
run with non-leaf ids withheld the client sends probe requests listing each withheld chunk (at most 200 ids) with the best-ranked
ids (front and back fill), returns to the ranked list when a probe delivers anything, and keeps a cached revision whose
out-of-scope answer is explained by a withheld prerequisite id. Re-run, fresh client per combination: `staged`/`all_non_declined`
185 pages, 5,273 revisions (484 non-leaf), 0 removed, 1,045 extended fragments, repeat sync 3 pages `unchanged`;
`closure`/`all_non_declined` 29 pages, 5,273, 1,045, repeat 3 pages; `staged`/`approved` 19 pages, 444, repeat 1 page;
`closure`/`approved` 3 pages, 444, repeat 1 page. The bundle downloaded 155 of 155 files (1,218,839,376 bytes) in all four, and
each file's SHA-256 recomputed by a separate script equals the name of a store object. Remaining limits: probes are this
project's behavior and unknown to the real WSUS; with ids withheld a repeat sync costs `2 * ceil(withheld / 200)` extra requests;
a revision needing a withheld id together with an id a probe's fill leaves out would still be missed (not constructed); the
guest was not re-run.

**Content.** 155 files and 1,218,839,376 bytes per client in 9.4 s on the host. For six clients a separate script recomputed the
SHA-256 of every completed file: the set of (SHA-256, size) pairs equals the server's store object names and sizes, 155 of
155 each. Injected faults, each followed by a rerun of the same command:

- Response cut after 50,000,000 bytes by a relay (one request per connection; `max_retries = 0`): 6 of 6 files over 50 MB failed
  (`transport Io failure ... error decoding response body`, exit 2); the rerun resumed all 6 from offset 49,999,762 and finished
  155 of 155. A first relay applied the limit per connection and cut keep-alive neighbours too; those runs are not counted.
- Location change: the server restarted with another `advertised_content_url` between the runs; the resume went to the new
  origin directly (6 content `GET`s answered `206` by the server, none through the relay).
- Client SIGKILL at 4 s: 46 files complete, one partial (96,206,098 bytes on disk, sidecar `validated_len` 87,432,466); the
  rerun resumed from 87,432,466 (the prefix hash was checked) and completed 155. An earlier kill at 2.5 s left 34 complete files and one empty partial.
- Server SIGKILL at 3 s (44 files complete) and restart 3 s later (`startup_recovery`: completed promotions 0, quarantined 0, missing 0,
  discarded partials 0): the same client process (default `max_retries` 3) finished, exit 0, with one resume from 50,945,555.

**Sync recovery.** Client SIGKILL at 5 s of a staged sync: 399 revisions cached, anchor `cache:399:613e05034c3a076a`; the rerun
took 2 pages and 45 new revisions plus 433 extended fragments, no handshake, and ended at 444 revisions with the anchor
`cache:444:36a63b1964a21f17`, identical to an uninterrupted run.

**Faults produced by the server and recovered by the client.**

- Cookie lifetimes of 4 s (`cookie_ttl_secs`, `auth_cookie_ttl_secs`): one full sync made 27 renewals (29 `GetCookie`, 29
  `GetAuthorizationCookie`); a second sync 6 s later made 1 handshake, 1 page, `changed_revisions` 1, 0 new.
- Server-side `CookieExpired`: a relay rewrote `Expiration` to 2099 in the cookie answers (test device, `accept_xpress = false`),
  so the client held a cookie the server had expired; one `GetExtendedUpdateInfo` was answered `500`, server log
  `fault_code=CookieExpired`; client: 1 recovery, 1 renewal, sync completed (444, 433).
- `ConfigChanged`: restart with `max_extended_updates_per_request = 40`; the next `SyncUpdates` of a client holding a valid
  cookie was answered `500` `ConfigChanged`; client: 1 handshake, 1 recovery, `config_changes` 1, `changed_revisions` 1.
- Unchanged restart: 0 handshakes, `unchanged` true (the cookie signing key lives in the database).
- **Defect found:** with `Accept-Encoding: xpress` negotiated the server's fault bodies are Xpress-compressed and the access
  log read the compressed bytes, logging an empty `fault_code` (`status=500 fault_code=`). Fixed in `cda13ef`
  (`fault_code_in_encoded`, regression test `fault_code_is_read_from_xpress_encoded_fault_bodies`). The wire behavior was
  not changed; whether a real WSUS compresses faults is not known.

**Windows guest** (clone `osi-p3-1` of `osi-gold`, Windows 11 25H2 UBR 8037; policy pointed at the host server while the guest had
no NIC; user networking afterwards; `AntivirusSignatureVersion` 1.459.561.0 at clone time, 0.0.0.0 after
`MpCmdRun -RemoveDefinitions -All`): `staged`/`approved`: sync 19 pages (3.5 s), `scan` 1 applicable (29 queries), `plan`
`install` with 3 steps (433 decisions), `install --yes` `succeeded` in 11 s, 3 content `GET`s answered `200` (no `Range`,
223,014,168 bytes, the same three files and bytes the native agent fetched in C31 with 215 range `GET`s), all steps exit 0,
signer Microsoft Corporation, post-check converged, signature 0.0.0.0 to 1.459.547.0 (`AMProductVersion` 4.18.26080.4), rerun
`no_action`. `closure`/`approved` and `closure`/`all_non_declined`: same result, 11 s each. Client killed at 3.5 s of
`install --yes`: job record `running` with step 0 finished and step 1 started; the rerun reported the job in
`recovered_interrupted_jobs`, ran the three steps (exit 0), converged after 121 s, signature 1.459.547.0.

**Reports.** Host: 1 event delivered, the same instance id again answered `already_delivered` by the client without a request,
a second event delivered through the queue; guest: 1 delivered. The server stored them (`events` rows, kind `other`, with the
update id); `update_status` stayed empty, so no derived client status was produced.

**Not observed in this session:** corrupt bytes served, approval removal or decline under a client, TLS, concurrent clients,
deadline and uninstall, a server restart in the middle of a client sync, resending an event instance id to the server,
`StartCategoryScan` from this client, any `Cbs` or `OSInstaller` update.


#### Above the 400-entry cap on the real WSUS (OBSERVED 2026-10-06, ledger row C59)

The question left open above: what the real lab WSUS (wsus-srv, Windows Server 2025, WSUS 10.0.26100.32230, protocol 3.2, plain
HTTP, port 8530) does with a `SyncUpdates` listing more than 400 ids in `InstalledNonLeafUpdateIDs`. Driver: the ignored test
`crates/wsus-client/tests/real_wsus_cap.rs` (commit `ac38511`), through the recording proxy (`scripts/wsus/capture-proxy.py`;
raw exchanges and `results.json` under `/data/cache/wsus400`, not committed, they hold cookies). One synthetic computer
(`w400-probe-511c5c.lab.invalid`) registered by the run and deleted by id afterwards; nothing else on the server was written.
The driver does the handshake, syncs the catalog with this project's engine (never above 400 installed ids) to learn the real
server-local ids (541 non-leaf, 4,796 leaf, no driver revisions, 5,337 revisions held), then sends hand-built requests that
reuse a saved cookie: a fresh one and one saved after 60 pages. The list is every real non-leaf id ascending, then real leaf
ids ascending as padding, so lists above 541 contain leaf ids too.

| Request (60 requests, each of 15 list shapes twice at each of two anchors) | HTTP | Answer |
|---|---|---|
| Installed 399, other empty (`I399`) | 200 | 30 `NewUpdates` (30 `Evaluate`, 1 non-leaf), `Truncated` true, 104 out-of-scope ids; `GetExtendedUpdateInfo` for the 30 returned 30 fragments |
| Installed 400, other empty (`I400`) | 200 | the same 30 ids as `I399`, 105 out-of-scope ids, `Truncated` true, 30 of 30 fragments |
| Installed 400, other 4,937 (`IL400`, all other known ids) | 200 | 0 `NewUpdates`, 1,816 out-of-scope ids, `Truncated` false |
| Installed 401 (`I401`), 450, 600, 1,000, other empty | 500 | SOAP fault `InvalidParameters`, `Message` `parameters.InstalledNonLeafUpdateIDs`, nothing else |
| Installed 401 and 1,000 with every other known id as other (`IL401`: 4,936, `IL1000`: 4,337) | 500 | the same fault |
| 401 entries with a repeated id (`D401`, 400 distinct) and 400 non-leaf ids plus one leaf id (`R401`) | 500 | the same fault |
| Installed 400 plus 1, 50, 200, 600 more ids as `OtherCachedUpdateIDs` (`O401`, `O450`, `O600`, `O1000`) | 200 | 30 `NewUpdates`, `Truncated` true, out-of-scope 106, 141, 206, 214; the 30 ids equal `I400`'s for 1 and 50 extra, differ for 200 and 600 extra |

The fault is the shape recorded in 9.1: HTTP 500, `text/xml; charset=utf-8`, `s:Client`, `faultstring` `Fault occurred`, 442 bytes,
`Connection: close`. Observations that follow from the table and nothing more: the real server counts entries of the list (a
repeated id and a leaf id each count), the rejection happens before any delivery (no truncation, no partial page, no different
delivery), `OtherCachedUpdateIDs` has no such limit in this range (4,937 ids accepted, 3,679 in 9.1), and moving the extra ids to
`OtherCachedUpdateIDs` is accepted. The repetitions agreed on status, counts and id digests (response sizes differed by a few
bytes). The two anchors gave the same `NewUpdates` and out-of-scope ids and differed in `ChangedUpdates` (295 at the fresh anchor,
0 at the page-60 anchor for `I400`). The request cookie anchor did not change what was rejected.

During the catalog sync the engine at `84a1b95` sent 876 `SyncUpdates` requests for 5,337 held revisions (541 non-leaf, so 141
non-leaf ids withheld from the installed list; the lists reached 400 installed and about 4,900 other ids), all answered `200`
except one `InvalidCookie` fault at request 657 from which it recovered; the last 14 requests alternate small and larger responses (probable probe requests, not decoded). C7 recorded 180
pages for 5,377 revisions with the pre-fix client. Why the count is higher: see "Why 876 requests" below.

**Why 876 requests (offline analysis of the C59 capture, plus a host reproduction, 2026-10-06; no server was contacted).** The
recorded exchanges under `/data/cache/wsus400/proxy` hold the engine's catalog sync (first 876 `SyncUpdates`; the request lists
were parsed, the Xpress responses decoded with this project's decoder). Result: the probes are not the cause. Probe requests
occur only after a response with `Truncated` false, and only 12 responses in the whole engine phase were not truncated (request
657, the `InvalidCookie` fault, and the last 11 requests, 897 to 910, which are the probe tail: about 14 requests). The other
~860 requests were ranked-list pages. Their yield on the real WSUS was low: 573 of the 876 responses delivered exactly one new
update (294 delivered two or more, 9 none), most of them at requests 150 to 656 with the installed list fixed at 400 and the
out-of-scope list at about 150; after the cookie recovery at request 657 the same ranked list was answered with 30 new updates
per page (first response after the new handshake: 4,459 updates, 4,429 of them `ChangedUpdates`). Why the real server gave one
update per page before the recovery is NOT known (not an effect of the client lists as far as the parsed requests show: the
sets were identical across many of those requests; the cookie or server-side session state is a candidate, untested).
Host reproduction against this project's server (fresh copy of the C31 store under `/data/cache/syncreq`, release build with a
temporary request counter that was reverted, ports 18790 to 18793, first sync of a fresh client; counts by kind from the
client's own view because the access log does not record list shapes): `staged`/`all_non_declined` 185 pages = 176 ranked
pages + 9 probe requests (2 of the probes delivered something), 188 `SyncUpdates` in the access log including the repeat sync,
all `200`; `closure`/`all_non_declined` 29 pages = 27 + 2 probes (none delivered); `staged`/`approved` 19 pages, no probe;
`closure`/`approved` 3 pages, no probe; repeat sync 1 request (`approved`) or 3 (`all_non_declined`, 2 probes). No recovery
request occurred on our server (no cookie fault was injected). So on our server the probes cost 9 of 185 requests (about 5
percent) and on the real WSUS about 14 of 876 (about 1.6 percent). Decision: a cheaper probe design (probe only when a withheld
id is referenced by a cached revision's prerequisite clause, or stop after a pass that delivers nothing) is not justified by
these numbers, and no client code was changed; it would also not reduce the real-server count, which comes from the page yield.

Not observed: the limit on other lists (`CachedDriverIDs`, `FilterCategoryIds`) or on the other methods; whether the limit depends
on build, configuration or protocol version (one build); a native client above 400; `ExpressQuery` true; whether the real server's
count is of entries after some normalization other than the repeat and leaf case tried; what the probes of `84a1b95` delivered on the
real server.

Consequences, stated as comparisons and recommendations only (nothing was changed):

- The client's 400-entry `installed_non_leaf_limit` equals the real server's limit, and the withheld ids go to
  `OtherCachedUpdateIDs`, which the real server accepts; the engine never sends 401 entries (the probe requests list at most 400
  installed ids), so no request of this client is rejected by the real server for this reason. The real server did not truncate or
  deliver differently above 400, it refused, so there is no real behavior to copy beyond the refusal; the probe design is this
  project's own and its effect on a real server is not established.
- Our server's staged cap (400 accepted, 401 `InvalidParameters`, same message) matches what was observed for plain lists. Checked
  on the host afterwards (2026-10-06): our server already counts list entries (`installed.len()`), so the `D401` shape (400 distinct
  ids plus a repeat) and the `R401` shape (400 ids plus a leaf id) are rejected with the same fault as a plain 401; no server change
  was needed, only the regression test `installed_non_leaf_cap_counts_list_entries_not_distinct_or_non_leaf_ids` was added (it also
  checks that 400 entries containing a repeat are accepted). The fault code is asserted in that test; the HTTP 500 status and the
  `Message` use the same error path as the plain 401 and were not asserted separately. Other list-size limits recorded for the real
  server: only `StartCategoryScan` (200 or more categories is `InvalidParameters`, from the specification, not observed) and
  `OtherCachedUpdateIDs` (no cap observed up to 4,937 ids); our server does not cap `OtherCachedUpdateIDs` and applies its own
  `max_array_len` (50,000) to every array, which the real server's behavior was not compared with. No
  divergence was observed in the cap value, the status, the fault shape or the message.

### 9.10 Install reporting: what a native agent sends and what the real WSUS stores (OBSERVED 2026-10-06)

Status: one guest, one native client build, one real WSUS build, one run of each case below (ledger C61). The question was what a
Windows Update Agent reports after it installs an update, after a failure and when a restart is pending, so that this project's
client can send the same events. The native client was driven through COM (`IUpdateSearcher`, `IUpdateDownloader`,
`IUpdateInstaller`, `ClientApplicationID` `osi-rep-native`) on a disposable clone of `osi-gold` (Windows 11 25H2,
10.0.26200, UBR 8037, WUA 1507.2601.30012.0), pointed at the real lab WSUS (`wsus-srv`, WSUS 10.0.26100.32230) through the
recording proxy (`scripts/wsus/capture-proxy.py`, `--upstream-host` so that the file URLs name the WSUS itself). The server
side was read in the WSUS database with SELECT statements only (`SUSDB.dbo.tbEventInstance`, `tbEvent`,
`tbEventMessageTemplate`, `tbUpdateStatusPerComputer`) and through the administration API
(`IComputerTarget.GetUpdateInstallationInfoPerUpdate`, `GetUpdateInstallationSummary`). The decoded events are in
[`docs/fixtures/wsus-m0-reports/native-install-events.json`](fixtures/wsus-m0-reports/native-install-events.json) (client id,
cookies and addresses removed; the `U` and `V` lists reduced to their sizes); the real server's own event table in
[`susdb-client-event-table.csv`](fixtures/wsus-m0-reports/susdb-client-event-table.csv). Raw captures stay local.

**The real server's event table (a witness for the names).** `tbEvent` with `tbEventMessageTemplate` (language `en`) names the
client events of namespace 1 (`MSUS 2.0 Client Event Namespace`; namespace 2 is the server's): `147` "successfully detected %1
updates", `148` "failed to detect with error %1", `156` "Reporting client status", `161` "Download failed", `162` "Download
succeeded", `167` "Download started", `168` "Download queued", `181` "Installation Started: ... %1", `182` "Installation
Failure: ... error %1: %2", `183` "Installation Successful", `184` "Installation successful and restart required", `190`/`191`
and `197` to `199` variants of the same, `193`/`194` "Restart Required", `201` "Installation pending", `202` "Reboot
completed", `203` "Installation succeeded Post Reboot", `204` "Installation Failure Post Reboot", `221` to `226`
uninstallation (`226` started, `222` successful, `224` successful and restart required, `221` failure, `223` cancelled, `225`
killed). Sources of namespace 1: `101` Client Agent, `102` Automatic Update component, `103` Client Server Protocol Talker,
`104` Inventory component, `105` Update handler, `106` CBS, `107` DPX. This settles the names the earlier sections left as
inferred (161 "download failed", 162 "download succeeded", 182 "installation failure", 183 "installation successful").

**Native events, an update that needs a restart (KB5126052, the `.NET` cumulative update, revision 100, exchanges 79 and 80 of
the capture).** Every event: `NamespaceID` 1, `SourceID` 101, `SequenceNumber` 0, `TargetID/Sid` the client id, a fresh
`EventInstanceID`, `UpdateID` the deployed update (the bundle root `88661612-7dd9-49d4-bb34-1e54802c99b9`, revision 100; for
events without an update the zero GUID and revision 0), `AppName` in `BasicData` and `AppName=` in `MiscData` the
`ClientApplicationID` (`<<PROCESS>>: powershell.exe` when none is set), `ExtendedData` (`ComputerBrand` `QEMU`, `ComputerModel`
`Standard PC (Q35 + ICH9, 2009)`, `BiosRevision` `unknown`, `ProcessorArchitecture` `Amd64Compatible`, `OSVersion` 10.0.26200
revision 65792 as in section 9.3, `OSLocaleID` 1033) and an empty `PrivateData` element. Post one (download and install begin, 14:56:40): `147`
(`ReplacementStrings` the number of updates found, `MiscData` `B=782`, `C=1`, `Q=1`), `156` (client status, `U` 22 and `V` 38
update ids), `167` (download started, `ReplacementStrings` the title, `Q=2`), `162` (download succeeded, `B=96660271`, which is the
two declared files, 96,649,380 plus 10,891 bytes), `181` (installation started, `Q=2`), all `Win32HResult` 0. Post two (the install
returned, 14:57:39, 59 s after): ONE event, `201` ("Installation pending") with `Win32HResult` 2359301 = `0x00240005`
(`WU_S_REBOOT_REQUIRED`), `ReplacementStrings` the title, `MiscData` `D=1`, `Q=2`. The COM `Install` result was `ResultCode` 2,
`HResult` 0, `RebootRequired` true. The Defender run of section 9.4 (no restart) sent `181` then `183` (`Win32HResult` 0,
`D=1`); `184`, `190`, `191`, `193` were not sent by either.

**Native events, a failure.** Two Windows Installer test updates of the lab catalog were offered to the clone and installed
through COM; both failed before any installer ran (the download result `0x800B0109` is a certificate-chain error: the clone not trusting the lab's signing certificate is INFERRED from it, not checked): `167` (download started,
`MiscData` `l=1`, `csiComponent` the server address), `161` (download failed, `Win32HResult` -2146762487 = `0x800B0109`,
`B=` the size, `CsiErrorType=1`), `181` (installation started, `F=-2145124299`), then in a second post `182` (installation
failure) with `Win32HResult` -2145099769 = `0x80246007` (`WU_E_DM_NOTDOWNLOADED`), `ReplacementStrings` `["0x80246007",
<title>]` and `MiscData` `C=1`, `F=-2145099769`. The COM results were `Download` `ResultCode` 4 `0x80240022` and
`Install` per-update `0x80246007`. A failure of an installer itself (an MSI or servicing result) was NOT captured: no
installable-and-failing update was available, so the code the native agent puts in `182` for an installer failure is
unobserved (only the shape).

**After the restart (what was NOT seen).** After the restart the clone reported nothing about the install by itself in the
minutes it was watched: the first scan after the restart (cached) sent no report; a scan after the agent's datastore
was cleared sent `147` and `156` only, and the client's `156` then listed the update among the installed ones (`V` 39, `U`
15). Events `202` and `203` ("Reboot completed", "Installation succeeded Post Reboot") were not seen. The datastore was
cleared before the post-restart report could have been sent, so "the native agent sends no `203`" is NOT established; only that
it did not within the observation.

**What the real WSUS stored.** One `tbEventInstance` row per received event that names an update, including repeats of the
same kind (two `167`, two `181`, two `182` for one update after two attempts), with `EventInstanceID`, `EventID`,
`EventNamespaceID`, `EventSourceID`, `TimeAtTarget`, `TimeAtServer` (2 to 3 s later), `Win32HResult`, `AppName`, `MiscData` and
`ReplacementStrings` (both as `ArrayOfString` XML), `ComputerID` (the client id as text), `UpdateID`, `RevisionNumber`. For
events without an update id there is one row per computer and event id, the latest (`147` once, though ten or more were received); `156` is
not stored at all. Derived status (`tbUpdateStatusPerComputer.SummarizationState`, admin API `UpdateInstallationState`):
the first scan with the approval made the update `NotInstalled` (2) (an unchanged row); `181`, `167`, `162` and the
restart-required `201` left it `NotInstalled` (summary `pendingReboot` 0, 14:57 to 15:01, before and after the restart); the
two `182` made the two failed updates `Failed` (5) within the same second (`LastChangeTime` matches the `182` event time to the second, not the `161` before it, which is how the two were told apart) and the summary said `failed=2`; after the restart, at the post-restart status event `156`, whose `U`
list no longer held the update and whose `V` list did, the update became `Installed` (4) (`LastChangeTime` the event time) and
the summary counts followed (`installed` 38 to 39). The sizes of the two lists equal the server's `NotInstalled` and
`Installed` counts for the computer (`U` 22 and `V` 38 against 22 and 38 before; 15 and 39 after). So on the real WSUS
the installed and not-installed states come from the client's `156` inventory lists, failure from `182`, and the restart
-required `201` produced NO `InstalledPendingReboot` (6) state in this run.

**What this project's client sent, and what the real WSUS did with it (this client against the real WSUS, one guest).** The
Windows `wsus.exe` was built from a worktree of `f8d6e24` with the files of the reporting change copied in (the tree at
`c7fb778` did not build for Windows: `windows-csi`, another change), with `[install] report_events` and
`report_uninstall_events` on, on the same clone, registered as its own computer (a second record, in the same throwaway
group). (1) `client uninstall --allow-undeclared --yes` of the `.NET` installer child (`b5f388e1-...@100`, DISM backend):
job `reboot_required` (exit 3010, oracles `agree_removed`), two events queued by the hook, none sent (an uninstall has no
engine); `client report --flush-only` delivered 2 of 2: `226` (`Win32HResult` 0) and `224` (`Win32HResult` 2359301, `D=1`), the
real WSUS stored both (`tbEventInstance`, `UpdateID` the child). (2) After the restart `client install --yes` of the update
(`88661612-...@100`): job `reboot_required` (3010, oracles `agree_pending`, DISM listing 9347.1 `Install Pending`), two events
queued and delivered by the install command itself: `181` (`Win32HResult` 0) and `201` (`Win32HResult` 2359301, `D=1`). Stored
by the real WSUS with the same `EventID`, `EventNamespaceID` 1, `EventSourceID` 101, `Win32HResult`, `UpdateID` and
`RevisionNumber` as the native rows of the same update; the native rows of that update from three earlier clones (5 October) have
the identical `201`/`2359301`/`D=1` pair. Differences: `AppName` (`wsus-client`), `MiscData` holds only `D=1` and `AppName=`
(the native agent's `G`, `J`, `K`, `L`, `Q`, `T` and numeric flags are not sent: their meaning is unknown), `OSVersion` revision
0 where the native agent sent 65792, `ComputerBrand`, `ComputerModel`, `BiosRevision` absent, and `ReplacementStrings` the
update identity instead of the title in that run (the client had stored no `LocalizedProperties`). The client now fetches the
`LocalizedProperties` fragment of the reported update before the install and uses the title (checked once by sending a copy
of the install job record under another job id, `client report --job`: the title of the real WSUS was sent). A restart
followed (DISM: 9347.1 `Installed`, 9321.3 `Superseded`, as for the native install). The administration API then said for the
client's computer: update `Unknown`, summary `unknown` 564, `installed` 0, `pendingReboot` 0, and `LastReportedStatusTime` unset,
while the native client's computer said `NotInstalled` before and `Installed` after its `156` lists. So the events were accepted
and stored like the native ones, but this client's update status on the real WSUS is NOT installed or pending: that status is
driven by the `156` inventory lists, which this client does not send. Not run: this client's `182` or `183` against the real
WSUS, an uninstall `222` or `221`, a failure of an installer.

**This project's server with the same events (P3, host, a working copy of the C31 store).** The two real job records were
copied to a host client's state directory and sent with `client report --job` to `wsus server run` (port 18820): 4 events
stored, `kind` `other`, `Win32HResult` 0 and 2359301 kept, the raw payload holding the replacement strings and `MiscData`, no
derived status (`update_status` empty): the same outcome as the real server for `181` and `201`. With the default mapping
`182` to `install_failed` (commit `6ccb700`) a native-shaped `182` derives `install_failed` with the `Win32HResult` as the
result code (host tests: `default_event_kinds_derive_failed_from_182_and_nothing_from_the_pending_sequence`,
`a_recorded_failed_job_is_reported_once_and_the_server_derives_failed`). Installed, not-installed and pending-reboot status are NOT
derived: the evidence of the real server is that they come from the client's `156` lists (an inference from the equality of the list
sizes with the server's counts and from the one update that moved between the lists), not from `183` or `201`.

**SUSDB history, for what was never seen.** Across all 4,939 stored `tbEventInstance` rows of this WSUS (9 computers, the
lab's runs of 4 to 6 October): `147` 10, `161` 26, `162` 9, `167` 30, `181` 15, `182` 10, `183` 2, `201` 6, `224` 1 and `226`
1 (this client's), and the server's own `361`, `363`, `366`, `382`, `384`, `389`; no `184`, `190`, `191`, `193`, `194`,
`202`, `203` or `204` ever.

**Decisions taken from this section.** (a) The install events of this client are `181` then `183`, `201` or `182`; `201` is sent
for a restart-required install because that is what the native agent sent for exactly that case, not `184`, which the table
names "Installation successful and restart required". (b) The uninstall events (`226`, `222`, `224`, `221`) are the ids of the
server's table; they are queued only behind their own switch and are not claimed to match a native agent. (c) No post-restart
event is sent. (d) The server derives only `182`. (e) A client that wants the real WSUS to show an update as installed or pending
has to send the `156` status event with its `U` and `V` lists; this client did not when this section was written, it does now (open item closed in 9.11).

### 9.11 The client status event 156 (the `U` and `V` lists): wire shape, what the real WSUS does with it, this client and this server (OBSERVED 2026-10-06)

Status: one guest image (the clone of `osi-gold`, Windows 11 25H2 10.0.26200, UBR 8037, WUA 1507.2601.30012.0), one real WSUS
(`wsus-srv`, WSUS 10.0.26100.32230), recording proxy, SUSDB read with `SELECT` only and the administration API (ledger C77 to
C79). Section 9.10 found that on the real WSUS Installed and NotInstalled come from this event; this section records its shape
and closes the open item (e) of 9.10. The decoded lists and the comparison are in
[`docs/fixtures/wsus-m0-reports/native-156-lists.json`](fixtures/wsus-m0-reports/native-156-lists.json).

**Wire shape of the native event (OBSERVED in the captures of three native runs of 6 October and two of 4 October).** `NamespaceID` 1, `EventID` 156,
`SourceID` 101, `SequenceNumber` 0, `Win32HResult` 0, a fresh `EventInstanceID`, `UpdateID` the zero GUID at revision 0,
`AppName` the `ClientApplicationID` (`<<PROCESS>>: powershell.exe` without one; `MoUpdateOrchestrator` from the orchestrator's own
scans), `ReplacementStrings` absent, `ExtendedData` and an empty `PrivateData` as for every native event (9.10). `MiscData` keys in
the order seen (ASCII order): `G`, `J`, `K`, `L`, `Q`, `T`, then `U`, then `V`, then `AppName`, `CsiErrorType`, `c`, `m`, `n`, `o`, `p`,
`q`, `r`, `w`, `x`, `dd`, `ff`, `WUfBOn`, `WUfBDS`, `DisableDS`, `PauseQU`, `PauseFU` (and `cc`, `g` in some). `U` and `V` are ONE
string each: `U=<id>;<id>;...`, upper-case hyphenated GUIDs joined by `;`, the key absent when the list is empty (a scan with
no listed update sent neither key; an earlier capture sent `U` with 6 ids and no `V`). The ids are UPDATE ids (not revision ids,
not `LocalUpdateID`s) of LEAF software updates only: all 60 ids of the one full pair resolved in SUSDB (`tbUpdate`, `tbRevision`) to
leaf updates of the software type; the bundled installer children are never listed (the update `88661612` is listed, its child
`b5f388e1` is not). `U` is the updates evaluated applicable and not installed, `V` those evaluated installed. Largest list seen:
39 ids (1.4 KB); NOT observed: a long list, whether the agent splits it over several strings or events, or any size limit (no clone
of the lab has more than 60 relevant updates).

**When the native agent sends it (OBSERVED, partial).** Always in the same batch as event `147` ("detected N updates", the two with
the same `TimeAtTarget` within 2 ms), never alone, and only after a scan that reached the server: 20 s to 2 min after the last
`SyncUpdates` of a search (a search at 19:30:04 UTC, the batch at 19:31:57; a first search 14:56:19 and the batch at 14:56:40). A
scan answered from the datastore without a server call sent none (9.10). Several scans in a row queue one pair each and the batch
carries all of them (four pairs in one post). It is NOT sent by the install itself: the post-install post carried `201` only; the
update moved to `V` in the first pair after the restart (9.10).

**What the real WSUS does with it (OBSERVED, a new computer record `e2a135b1`, then this client's record).** Event `156` is not stored
as a `tbEventInstance` row (9.10), only `147` is. A new computer that had sent nothing but `SyncUpdates` and `RegisterComputer` had NO
`tbUpdateStatusPerComputer` row; after the event it had exactly 60 rows, 22 with `SummarizationState` 2 (NotInstalled) and 38 with 4
(Installed), the same ids as the lists, `LastChangeTime` the event's `TimeAtTarget` and `LastChangeTimeOnServer` three seconds
later, and `LastReportedStatusTime` was set. For this project's client's record the admin API's `GetUpdateInstallationSummary` matched
the lists it had sent (installed 35, notInstalled 21 after a 21 and 35 event). A later event that LISTED FEWER updates (this
project's client, 312 listed, then 56) left exactly the rows of the listed ones: the rows of the updates it no longer named
disappeared, and the summary counted the other 508 of the computer's 564 updates as `notApplicable` (a client that never sent a
`156` had them all as unknown, 9.10). A row whose state did not change kept its `LastChangeTime` across two later
events. After the install and the restart the update moved from the `U` list to the `V` list and the admin API read
`UpdateInstallationState` `Installed` (4) for this client's computer (the native computer did the same in 9.10). After a removal of
the installer child the next event listed the update in `U` again and the API read `NotInstalled` (2) with the restart still
pending: this WSUS has no state for "installed, restart pending" in this path (`pendingReboot` stayed 0, 9.10). NOT observed:
whether a `156` overrides a `Failed` row set by `182`; whether the order of events in a batch matters; what a list naming an
update id the server does not know does.

**This project's client sends it (OBSERVED, ledger C78).** `[install] report_inventory = true` queues the event after `client sync`
and after an install or uninstall job, `client report --inventory [--force] [--facts-file F]` emits it on demand; `U` and `V` come
from the evaluator's verdicts (`client scan`): `Install` is `U`, `AlreadyInstalled` is `V`, not applicable, superseded and
Unknown are left out (Unknown is never guessed). The scope was fitted to the native lists of the same machine, in three
measured steps: every leaf software update gave 24 and 288 (native 22 and 38); excluding the 564 `Bundle` deployments
(the updates other deployed updates bundle; no native list held one) gave 21 and 144; excluding an installed update that an installed
update supersedes (108 of the 110 installed older cumulative updates were absent from the native `V`) gave 21 and 35. Against the
native lists: `U` 21 of 22 the same, `V` 32 of 38 the same; the differences are three Defender updates the stored catalog of this client
does not hold (they are not in its `client scan --all`), two `PreDeploymentCheck` updates this client evaluates not applicable, one superseded update the native agent
lists, and one cumulative update (2026-03, 25H2) the native agent lists as not installed and this client as installed (cause not
investigated). The rule is a fit to ONE machine, not a derivation of the native agent's algorithm. The event is built with a
deterministic instance id from the lists and an epoch that advances only when they change (remembered in the queue
directory), so an unchanged inventory is queued once and a return to an earlier one is a new event; an install job's own
post-check decides for the updates it executed (an install that needs a restart stays on `U` until the evaluation after the
restart says installed, as the native agent kept it). Observed on the real WSUS with the real `.NET` update KB5126052 in `dism` mode: before
the install `NotInstalled`; after the install (job `reboot_required`, `181`, `201` and a `156` with the update still in `U`)
`NotInstalled`; after the restart and `client sync` (a `156` with the update in `V`) `Installed`, `LastChangeTime` the event time;
after `client uninstall` of the installer child and `client report --flush-only` `NotInstalled`. One event alone (no `147`) was
enough. Not observed: a client on another OS image, a failed install's effect on the lists, lists above 312 ids (one event of 312
ids, 11.5 KB, was accepted), the cost on a slow machine (a `client report --inventory` run, evaluation of about 1,100 updates included, took 69 s on the guest).

**This project's server (P3, host, a working copy of the C31 store, ledger C79).** Before this change event `156` was stored raw
(kind `other`) and derived nothing. Now the default event table maps `156` to `client_status` and the server derives `Installed` (`V`)
and `NotInstalled` (`U`) per computer and update, resolved to the latest present revision in the active catalog (an id the catalog
does not hold is skipped), removes the rows an earlier client status event derived for updates the new lists omit, keeps the
change time of an unchanged row, and leaves statuses from other events (`182`) alone. It is the observed behaviour of the real
server and nothing more: the real server's behaviour for a `156` against a `Failed` row is unknown and the rule here
(a newer event replaces an older status) is a decision. Host client against `wsus server run` with the C31 store copy: the
inventory event of one deployed update derived `not_installed` at revision 200.

## 10. Implementation decisions recorded so far

- Pin MS-WUSP 38.0 and MS-WSUSSS 17.0 and re-run this inventory whenever the
  pinned revision changes.
- Treat the sample repositories as cross-checks only; where they disagree with
  the specification, follow the specification and queue a capture.
- Codecs accept SOAP 1.1 documents with either literal or SOAP-encoded arrays,
  with strict bounds on size, depth and element counts; emit SOAP 1.1 literal.
- A partial implementation advertises its profile: unsupported operations
  (`SyncPrinterCatalog`, driver operations, `GetExtendedUpdateInfo2`
  decryption, rollup methods) are listed as unsupported rather than faulting
  silently.
- `SyncUpdates` delivery is selectable (`staged` default, `closure`); section 9.6 labels each rule Specified, Observed or Decision. Both modes were run with a native Windows Update Agent and both installed the Defender bundle (9.7); the earlier statement that a native agent cannot find the bundle in `closure` mode is withdrawn. `staged` stays the default because it matches the recorded real-WSUS dialogue (page size, installed-list driven order, `ProtocolVersion` 3.2), not because `closure` was shown to fail. `closure` is kept as the simpler fallback; it ships the whole closure (444 revisions, 1.1 MB per page) and ignores the 400-id cap.
- The server never invents `Deployment` data or fragments; it serves
  genuine metadata only (plan section 10).

## 11. Capture and verification tasks (M0)

Needed to close every Unverified and conflict above.

- Done in part (2026-10-04, section 9.1): our client against a real WSUS
  covering the session handshake, registration and `SyncUpdates` paging.
  Still open from that capture: `GetFileLocations`, content, and the real
  cause and recovery for the 400-id `InstalledNonLeafUpdateIDs` cap (the
  native client avoids the cap by listing only revisions it evaluated as
  installed; section 9.3).
- Done in part (2026-10-04, section 9.3): a native WUA scan and flow against
  real WSUS (SOAP version, headers, body shape, `GeoId`, time formats,
  `Accept-Encoding: xpress`, Reporting URL, `GetExtendedUpdateInfo` with
  file locations, `ReportEventBatch`). Done in part (section 9.4): native
  content download and install of one update from the real WSUS (range
  `GET`s, `206` headers, 8 connections, post-install reports). Still open:
  `GetFileLocations`, `GetExtendedUpdateInfo2`,
  `RefreshCache`, and any fault other than `InvalidParameters`.
- Done in part (2026-10-04, section 9.7): a native WUA against THIS project's
  server, both delivery modes, one Defender bundle (found, downloaded, installed,
  reported). Still open: TLS, several clients, approval removal and decline, deadline
  and uninstall, restart and key rotation under a native client, drivers,
  cumulative updates, an unmodified image, a native `StartCategoryScan` against this
  server, and a run that isolates which fix closure mode needs.
- Done in part (2026-10-04, section 9.5): this project's importer and a probe
  against a real upstream (authorization, filter and `Delta` semantics, anchor
  behavior, `XmlUpdateBlobCompressed`, content URL rule, content download).
  Still open: a REAL downstream WSUS synchronizing from a real upstream (what a
  Windows downstream sends: `Languages`, `Get63LanguageOnly`, protocol version,
  `DownloadFiles`, `GetDeployments`), `ServerChanged`, `FileDigestsMissing`,
  cookie expiry, HTTPS and authenticated upstreams.
- Inspect a real WSUS content tree for the folder rule and hex case.
- Fixture provenance, sanitization and hashes are recorded alongside each
  capture; signed or tokenized URLs and cookies are redacted.


## 12. Applicability rules

Status: written 2026-10-04 with the evaluator in `crates/wsus-protocol/src/applicability/`
(plan section 7, first step toward an installing client). Everything here is
Specified (public Microsoft documentation, cited per row), Observed (the stored
real catalog, described below) or an Implementation decision; the evaluator
has NOT been compared with a native client (validation rows C32 to C35 are
`Not validated`). The portable client still must not invent installed-update
inventory (plan section 7): the evaluator answers `True`, `False` or `Unknown`
from facts a caller supplies, and `Unknown` is a first-class answer.

### 12.1 Sources

- Specified, public documentation on learn.microsoft.com (the WSUS SDK pages
  are archived "previous versions"): [BaseApplicabilityRules Schema](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb972749(v=vs.85)),
  [BaseTypes Schema](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb972756(v=vs.85)),
  [MsiApplicabilityRules Schema](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb972757(v=vs.85)),
  [Detection Methods](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902481(v=vs.85)),
  [Version Detection Logic](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902489(v=vs.85)),
  [VerifyVersionInfo](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfoa) and
  [VerSetConditionMask](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-versetconditionmask).
  MS-WUSP 3.1.1.1 only says that the applicability elements of the Core
  fragment carry `b.`, `m.` and `d.` prefixes; it defines no rule semantics.
  The pages above describe rule authoring for WSUS publishers, not the Windows
  Update Agent's code: where they are silent the evaluator says so.
- Observed: the 5168 revision files stored by this project's WUSP client from
  the real WSUS (WS2025 10.0.26100; `~/vm-lab/wsus-m0/client-run5/state/meta/revisions`,
  one JSON file per revision with the Core fragment text; the task statement
  said 5158, the directory holds 5168 and all 5168 were used). 5127 of them
  have `ApplicabilityRules`. The `deployment.id` in these files is NOT a usable
  server-local id for comparing with another run: see 12.7 (retraction).
- Observed: a native WUA scan of 2026-10-04 (bodies
  Xpress-decoded, kept by the lead under `~/vm-lab/wsus-m0/diff/native-diff/scan/`)
  and the facts collected on the same guest (12.7).

### 12.2 Shape in the real data

- `ApplicabilityRules` holds `IsInstalled` (5127 revisions) and `IsInstallable`
  (917 revisions). No `IsSuperseded`, no `Metadata`, no driver (`d.`) element
  occurs. Every section holds exactly one child expression. 41 revisions have
  no `ApplicabilityRules` at all.
- Names: the base operators carry `b.`, the Windows Installer operators `m.`;
  `And`, `Or`, `Not`, `True`, `False`, `CbsPackageInstalledByIdentity` and
  `ProductReleaseVersion` are unprefixed. The `m.` helper children are
  `m.Product`, `m.Feature`, `m.Component` (text content). Full documents from
  MS-WSUSSS (9.5) use `bar:` and `lar:` prefixes bound to
  `http://schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules` and
  `.../LogicalApplicabilityRules`.
- 32 operator names occur (table below), 10 more are in the public schema pages
  and never occur.
- Value shapes (all revisions): `Key` is `HKEY_LOCAL_MACHINE` (all but 5
  `HKEY_LOOP_TARGET`); `RegType32` is `true` or `false` where present;
  `Comparison` is one of the five `ScalarComparison` tokens exactly cased,
  except `greaterthan` on `ProductReleaseVersion`; string comparisons use
  `EqualTo` (1180 of 1252 `RegSz`), `Contains`, `BeginsWith`; `RegDword/@Data`
  is decimal; `RegValueExists/@Type` is `REG_DWORD` (1949), `REG_BINARY` (945),
  `REG_SZ` (78) although the public `RegistryValueType` enumeration has no
  `REG_BINARY`; `Csidl` is 35, 36, 37, 38, 41, 42, 43 or 44; `Processor/@Architecture`
  is 9 (262), 0 (109), 12 (47), 5 (7), 6 (1); `WindowsVersion/@MajorVersion` is
  10, 6, 5, 11 or 1, `ProductType` 1, 2, 3 or 95; `Modified` and `Created` are
  `yyyy-mm-ddThh:mm:ss.fffffffZ`; `WmiQuery/@Namespace` is `root\cimv2` (61),
  `root/cimv2` (3), `ROOT\cimv2` (1), `root\wmi` (1);
  `MsiProductInstalled/@ProductCode` is always a braced GUID (case varies),
  `ExcludeVersionMax` occurs without `VersionMax` on 133 uses and
  `ExcludeVersionMin` without `VersionMin` on 55.
- `FileVersionPrependRegSz` alone is 7191 uses (943 revisions): a file version
  under a base path read from the registry; the uses sampled are Defender
  signature files.

### 12.3 Operator table (real catalog counts, implementation status, evidence)

"Uses" counts element occurrences in all `ApplicabilityRules`, "Updates" the
revisions that contain one. Regenerate with
`cargo test -p wsus-protocol --test applicability_real inventory_operator_table_markdown -- --nocapture`.
"Evaluated: no" means the parser keeps the element as an `Unsupported` node and
any result that depends on it is `Unknown`.

| Operator | Uses | Updates | Evaluated | Semantics and evidence |
| --- | ---: | ---: | --- | --- |
| `MsiProductInstalled` | 49986 | 2136 | yes | Specified: the product is installed; VersionMin/VersionMax bound the version, ExcludeVersionMin/Max make the bound exclusive and are valid only with their bound; Language filters; Observed: ExcludeVersionMax occurs without VersionMax on 133 uses and ExcludeVersionMin without VersionMin on 55; Implementation decision: Exclude without a bound is ignored; missing numeric parts compare as zero; installed means MsiQueryProductState is local, source or default |
| `RegDword` | 8531 | 1418 | yes | Specified: compares a REG_DWORD value with Data (unsigned 32-bit) using ScalarComparison; Specified: operand order observed value <op> Data (by the FileVersion example); Observed: Data is decimal in every occurrence; Implementation decision: missing key or value is false (the Not(RegDword ...) guards in the Defender rules rely on it); Unverified: a value of another registry type is Unknown, not false |
| `Not` | 7373 | 1241 | yes | Specified: logical negation; Implementation decision: exactly one operand, else unsupported; Not Unknown is Unknown |
| `FileVersionPrependRegSz` | 7191 | 943 | yes | Specified: as FileVersion with the REG_SZ value prepended; Implementation decision: as FileExistsPrependRegSz and FileVersion |
| `And` | 6559 | 1778 | yes | Specified: logical conjunction; Implementation decision: n-ary; Kleene strong logic; no operands is unsupported |
| `Or` | 3201 | 1590 | yes | Specified: logical disjunction; Implementation decision: n-ary; Kleene strong logic; no operands is unsupported |
| `RegValueExists` | 3001 | 1145 | yes | Specified: existence of the value; the default value when Value is omitted; with Type the value must have that type; Observed: Type REG_BINARY occurs (945 times) although the public RegistryValueType enumeration lacks it; Value is present on every occurrence; Implementation decision: a present value of another type is false; Value="" is the default value |
| `RegSz` | 1252 | 492 | yes | Specified: compares a REG_SZ value with Data using StringComparison (EqualTo, BeginsWith, Contains, EndsWith); Observed: EqualTo, Contains and BeginsWith occur; Implementation decision: missing value is false; a value of another type is Unknown; Unverified: case sensitivity: both ordinal and case-folded comparison are computed and the result is Unknown when they differ |
| `WindowsVersion` | 920 | 436 | yes | Specified: implemented with VerifyVersionInfo; Comparison applies to MajorVersion, MinorVersion, BuildNumber, ServicePackMajor and ServicePackMinor and defaults to EqualTo; Specified: VerifyVersionInfo tests major, minor and service pack hierarchically (lexicographically, stopping at the first unequal field); Specified: SuiteMask: all suites with AllSuitesMustBePresent=true, otherwise at least one (VER_AND / VER_OR); Implementation decision: major, minor, SP major, SP minor compare as one lexicographic tuple over the fields present; Unverified: BuildNumber is a separate test with the same Comparison (VerifyVersionInfo does not put the build number in the hierarchy; equivalent on real builds that increase with version); the facts are RtlGetVersion values |
| `RegKeyExists` | 819 | 338 | yes | Specified: true when HKLM\Subkey exists; Key is HKEY_LOCAL_MACHINE or HKEY_LOOP_TARGET only; Specified: RegType32 is a boolean, default false; Implementation decision: RegType32=true is the 32-bit view (KEY_WOW64_32KEY), false is the native view; names compare case-insensitively |
| `LicenseDword` | 750 | 703 | yes | Observed: Value (a licensing name or GUID), Comparison, Data; 750 uses, not in the public schema pages; Unverified: read as SLGetWindowsInformationDWORD(Value) <op> Data; a name the licensing service does not know is false |
| `RegSzToVersion` | 552 | 262 | yes | Specified: compares a REG_SZ value, read as a four-part version, with Data (bt:Version) using ScalarComparison; Implementation decision: numeric per-part ordering; missing value is false; Observed: the registry string may have fewer than four parts: Windows CurrentVersion is `6.3` and rules compare it with 6.1.0.0; one to four parts are accepted, missing parts are zero. Evidence: the 27 Office updates the native search reports installed only evaluate True with that reading (one machine, one rule family); Unverified: a string that is not a numeric version (or a non-REG_SZ value) is Unknown; the client may treat it as false |
| `Processor` | 426 | 262 | yes | Specified: the processor architecture equals Architecture (SYSTEM_INFO.wProcessorArchitecture); optional Level and Revision; Observed: Architecture 0, 5, 6, 9, 12 occur; Level and Revision never; Implementation decision: the native architecture (GetNativeSystemInfo); Level or Revision make the operator unsupported |
| `FileVersion` | 259 | 113 | yes | Specified: compares the file's version with a four-part version using ScalarComparison; the version check implies the file exists (Version Detection Logic); Implementation decision: missing file is false; numeric per-part ordering; the version is the fixed file version (VS_FIXEDFILEINFO); Unverified: an existing file without a recorded version is Unknown |
| `True` | 138 | 138 | yes | Specified: constant true (LogicalApplicabilityRules) |
| `WindowsLanguage` | 135 | 114 | yes | Specified: true if the OS is localized to Language; always false if MUI is installed; Implementation decision: case-insensitive tag equality is true; a different language is false; Unverified: a neutral tag (en) against a specific OS tag (en-US) is Unknown |
| `FileExists` | 134 | 51 | yes | Specified: existence of the file; when Version or Size are given all must match; Csidl is resolved with SHGetFolderPath and prepended; duplicate backslashes are removed; Observed: Csidl 35, 36, 37, 38, 41, 42, 43 occur; Size occurs on 5 uses; Version, Created, Modified, Language never; Implementation decision: Created, Modified and Language attributes make the operator unsupported; Version and Size compare for equality |
| `CbsPackageInstalledByIdentity` | 68 | 24 | yes | Observed: PackageIdentity is a CBS package identity string; 68 uses; not in the public schema pages; Unverified: read as CurrentState 112 (0x70, installed) of the identity's key under Component Based Servicing\Packages; other states are Unknown |
| `WmiQuery` | 66 | 49 | yes | Specified: executes the WQL query, true for one or more rows, false for none; Implementation decision: Namespace defaults to root\cimv2; a query that cannot be run is Unavailable |
| `RegExpandSz` | 22 | 22 | yes | Specified: compares a REG_EXPAND_SZ value with Data using StringComparison; Implementation decision: the unexpanded data is compared; data containing % is Unknown (whether the client expands is unverified); case rule as RegSz |
| `ProductReleaseVersion` | 17 | 17 | no (Unknown) | Observed: Name, Version and Comparison (lower-case greaterthan); 17 uses; not in the public schema pages; Unverified: the source of the release version is unknown; always unsupported |
| `SystemMetric` | 13 | 10 | yes | Specified: GetSystemMetrics(Index) compared with Value using ScalarComparison; Observed: indices 86 and 87 only |
| `MsiComponentInstalledForProduct` | 11 | 8 | yes | Specified: the components are installed for one (all with AllProductsRequired) of the products; Implementation decision: as MsiFeatureInstalledForProduct with AllComponentsRequired |
| `MsiFeatureInstalledForProduct` | 9 | 6 | yes | Specified: the features are installed for one (all with AllProductsRequired) of the products; Implementation decision: AllFeaturesRequired selects all-of or any-of the listed features; Kleene combination |
| `FileExistsPrependRegSz` | 7 | 7 | yes | Specified: as FileExists with the REG_SZ value prepended instead of a CSIDL; Implementation decision: base and path are joined with exactly one backslash; a missing base value is false; Unverified: the client may concatenate without inserting a separator |
| `FileModified` | 7 | 2 | yes | Specified: compares the file's modification date with Modified using ScalarComparison; Implementation decision: as FileCreated |
| `False` | 6 | 6 | yes | Specified: constant false |
| `RegKeyLoop` | 5 | 5 | yes | Specified: evaluates the body against every sub-key of the key; TrueIf is Any, All or None; HKEY_LOOP_TARGET names the current sub-key; Implementation decision: Any is Or over the iterations, None is Not Any; the body's registry operators use the loop key's view; Unverified: a missing loop key behaves as no sub-keys (Any false, None true); All over zero sub-keys is Unknown |
| `FileCreatedPrependRegSz` | 4 | 4 | yes | Specified: as FileCreated with the REG_SZ value prepended; Implementation decision: see FileExistsPrependRegSz |
| `MsiPatchInstalledForProduct` | 3 | 3 | yes | Specified: the patch is installed for the product; VersionMin/VersionMax/Language also exist in the schema; Implementation decision: those extra attributes make the operator unsupported (never seen) |
| `Platform` | 3 | 3 | no (Unknown) | Observed: PlatformID="Windows" on 3 uses; not in the public schema pages; Unverified: probably true on every Windows client, but that is a guess; always unsupported |
| `MuiInstalled` | 1 | 1 | yes | Specified: true if the Multilingual User Interface is installed |
| `FileCreated` | 0 | 0 | yes | Specified: compares the file's creation date with Created (xs:dateTime) using ScalarComparison; Implementation decision: UTC instants compared at 100 ns; a missing file is false; a dateTime without time zone is malformed |
| `FileModifiedPrependRegSz` | 0 | 0 | yes | Specified: as FileModified with the REG_SZ value prepended; Implementation decision: see FileExistsPrependRegSz |
| `FileSize` | 0 | 0 | yes | Specified: compares the file size with Size using ScalarComparison; Implementation decision: a missing file is false |
| `FileSizePrependRegSz` | 0 | 0 | yes | Specified: as FileSize with the REG_SZ value prepended; Implementation decision: see FileExistsPrependRegSz |
| `NumberOfProcessors` | 0 | 0 | no (Unknown) | Specified: documented, never seen; no fact source |
| `ClusteredOS` | 0 | 0 | no (Unknown) | Specified: documented, never seen; no fact source |
| `ClusterResourceOwner` | 0 | 0 | no (Unknown) | Specified: documented, never seen; no fact source |
| `MuiLanguageInstalled` | 0 | 0 | no (Unknown) | Specified: documented, never seen; no fact source |
| `InstalledOnce` | 0 | 0 | no (Unknown) | Specified: documented, never seen; needs the client's installation history |
| `GenericQuery` | 0 | 0 | no (Unknown) | Specified: documented, never seen; vendor-defined |

Sections: `IsInstalled` (5127 revisions) and `IsInstallable` (917) are the only
section elements seen. Specified ("Version Detection Logic"): a section holding
several expressions is their conjunction (the SDK's own example lists two
sibling rules in `IsInstallable`); a client reports Installed when `IsInstalled`
holds, Not installed but applicable when `IsInstallable` holds, otherwise Not
applicable. Implementation decisions: a missing section is `Unknown` (the pages
do not define it); an empty section is unsupported; `IsInstallable` and
`IsSuperseded` can be evaluated like `IsInstalled`, but prerequisites,
supersedence and bundle semantics are NOT part of this evaluator.

### 12.4 Evaluation rules that apply to every operator

- Three values (Kleene strong logic): `False and x` is False, `True or x` is True,
  `Not Unknown` is Unknown, and nothing else turns Unknown into a definite
  value. Implementation decision, verified by tests only.
- A rule that contains an unsupported element evaluates to Unknown unless a
  definite `False` (in `And`) or `True` (in `Or`) decides it. The result lists
  the blockers: unsupported operators, unavailable facts and undecidable
  comparisons. A definite result carries none.
- Each fact answer is Known, Absent or Unavailable. Absent is definite
  (a missing registry value makes `RegDword` false; the Defender rules use
  `Not(RegDword ... > 0)` guards that need this), Unavailable makes the
  operator Unknown. Implementation decision.
- Registry names compare case-insensitively (the Windows registry; not restated
  by the rule pages). `RegType32="true"` is read as the 32-bit view, anything
  else as the native view (Specified: attribute, boolean, default false;
  Implementation decision: the mapping to the WOW64 views). The registry
  hive is always `HKEY_LOCAL_MACHINE` (Specified: Detection Methods: "All
  registry keys used by detection methods must be written under
  HKEY_LOCAL_MACHINE"); `HKEY_LOOP_TARGET` is valid inside `RegKeyLoop` only.
- Operand order is observed value `<op>` rule value. Specified by example (the
  FileVersion example of "Version Detection Logic": `GreaterThanOrEqualTo
  9.0.0.3344` means the file has the fix).
- `bt:Version` values are four numeric parts compared part by part (so `1.9`
  sorts below `1.10`); a registry string read by `RegSzToVersion` and MSI versions
  allow one to four parts, missing parts are zero (the first version of this evaluator
  required four parts and returned Unknown for `CurrentVersion` = `6.3`; see 12.8).
- String comparisons are computed both ordinally and case-folded; if the two
  differ the result is Unknown (the pages do not say). Registry strings that
  contain `%` are not expanded: `RegExpandSz` on such data is Unknown.
- Files: the path is joined by the provider; duplicate backslashes are removed
  (Specified for `FileExists`); `PrependRegSz` base and path join with exactly
  one backslash (Implementation decision, Unverified); a missing base value
  is false; a file version check on a missing file is false (Specified: "the
  file version evaluation implies that the file exists"); an absolute path with
  `%` is Unknown.
- `WindowsVersion` follows `VerifyVersionInfo` for major, minor and service
  pack (hierarchical, lexicographic; Specified for that API), uses the same
  `Comparison` for `BuildNumber` as a separate test (Unverified; the two
  readings agree on every real Windows build because builds grow with
  versions), `ProductType` for EQUALITY whatever the `Comparison` is (Observed
  on one machine, 12.7: first version of this evaluator applied the
  `Comparison` and was wrong), and `SuiteMask` with all-or-any
  (`AllSuitesMustBePresent`; Specified). `Comparison` defaults to `EqualTo`
  (Specified). The OS facts are `RtlGetVersion` values, not the manifest-shimmed
  `GetVersionEx` (Specified: the shim exists for `VerifyVersionInfo` callers
  without a Windows 10 manifest).
- Operators documented elsewhere but not understood, and any attribute this
  crate does not model, make the whole operator unsupported rather than ignored.

### 12.5 Evaluability over the real catalog

All 5168 revisions parse without error or panic (`FragmentIndex` lenient
fragment parser plus the typed parser).

| Measure | Value |
| --- | --- |
| Revisions with `ApplicabilityRules` | 5127 of 5168 |
| Rules with no unsupported operator in any section | 5107 of 5127 (99.61% of the rules, 98.82% of all revisions) |
| Rules with at least one unsupported operator | 20: `ProductReleaseVersion` (17 uses), `Platform` (3 uses) |
| `IsInstalled` definite against an empty closed-world Windows 11 x64 machine (`FakeFacts`) | 5056 of 5127 (98.62%); the 71 Unknown: 17 `ProductReleaseVersion`, 1 `Platform`, 56 `WmiQuery` (no fake WQL answer), 12 `SystemMetric` (not set); several rules carry two blockers |
| Distinct fact queries the catalog needs | 20449: 18720 `msi_product`, 920 `reg_value`, 499 `reg_key`, 132 `file`, 61 `wmi_query`, 59 `cbs_package`, 27 `license_dword`, 13 `msi_feature`, 10 `msi_component`, 3 `reg_subkeys`, 3 `msi_patch`, 2 `system_metric` (3 of the registry templates sit in a `RegKeyLoop` body) |

"Evaluable" here means the rule contains only operators with implemented
semantics; it says nothing about those semantics being right (12.4 labels, C32).
`scripts/wsus/applicability-queries.py` and the Rust listing agree exactly,
including the update lists, on the full catalog (`applicability_real.rs`).

### 12.6 Facts, snapshots and the collector

- `FactProvider` (synchronous, object safe) answers typed queries with
  Known, Absent or Unavailable. `FakeFacts` is an in-memory closed-world
  machine for tests; `RecordedFacts` loads the JSON snapshot written by
  `scripts/wsus/collect-facts.ps1`. A query missing from a snapshot is
  Unavailable, never Absent.
- Snapshot format `wsus-applicability-facts/1`: `schema`, `collected_at`,
  free-form `machine`, an `os` object (major, minor, build, service pack,
  product type, suite mask, native processor architecture, UI language,
  MUI flag) and `facts`, each fact being the query object of `queries.json`
  plus `result` (`state` known, absent or unavailable). The format is documented
  in `recorded.rs`; `tests/fixtures/applicability_facts_sample.json` is a
  hand-written sample and the roundtrip is tested
  (`applicability_snapshot.rs`).
- Collector decisions, all Unverified until a differential run: file facts use
  `SHGetFolderPath` for the CSIDL (current value) and `File.Exists`, the file
  version is the fixed file version of the version resource, MSI products
  are those `MsiEnumProductsEx` lists for the running account (SYSTEM: machine
  and SYSTEM's own contexts) with install state local, source or default,
  patch state is not collected (Unavailable), CBS package state is the
  `CurrentState` value under `Component Based Servicing\Packages\<identity>`,
  `LicenseDword` is `SLGetWindowsInformationDWORD`, MUI is "more than one
  UI language installed".

### 12.7 Differential against the native agent (2026-10-04)

How to run: docs/wsus-validation.md, "Applicability differential run".

**Setup (Observed).** Guest: Windows 11 25H2, OS 10.0.26200 UBR 8037, 64-bit,
facts collected as SYSTEM by `collect-facts.ps1` (20447 facts: 203 known,
20243 absent, 3 unavailable = `msi_patch`). Defender definitions had been
removed (AntivirusSignatureVersion 0.0.0.0). The native scan ran after the
collection on the same state: against the real WSUS (WS2025 10.0.26100) the
client sent a series of `SyncUpdates` requests; the request `scan/000054`
lists 94 `InstalledNonLeafUpdateIDs` and 1364 `OtherCachedUpdateIDs`. The
responses of the scan delivered 1461 distinct updates with their Core
fragments; the harness evaluates `IsInstalled` of each against `facts.json`.

**Truncated captures (Observed, found 2026-10-05).** Some captured scan responses are cut off
mid-document (`diff/native-diff/scan/000034`; `diff-leaf` and `diff-msi3` `scan/000023`, `000038`,
`000039`, `000043`, `000049`: 30 `UpdateInfo` each) and no longer parse as XML, so the strict
decoder used by the first versions of the harnesses silently skipped them. The harnesses now
recover every complete `UpdateInfo` from such bodies (`applicability_common::lenient_update_infos`).
Effect: the non-leaf differential went from 275 to 279 candidates (the previously unresolved
installed id is now resolved: 94 of 94), the leaf differential from 84 to 85; no verdict
changed to a disagreement.

**RETRACTION (Observed).** A first run mapped the native ids through the stored
revisions' `deployment.id` and reported 14 disagreements. All 11 stored-origin
ones were an artefact: of the 1461 updates delivered in the scan, all 1461 exist
in the stored revisions (same update id and revision) and NONE under the same
server-local id (for example server id 1666 is update 2b496c37 r101 in the scan
and 0c524dac-0419-0080 r200 in the stored copy; "1662 and 1666 are the same
update" was this effect). The server-local ids are assigned per sync and are
not stable between the stored client's run and this scan. Therefore: (1) the
harness maps ids only through the responses of the same capture as the
requests (stored ids only with `WSUS_DIFF_TRUST_STORED_IDS=1`); (2) the 12.7
statements of the earlier version of this section (17 of 94 ids resolved, 8 of
11 stored ids IsLeaf true, category id 66 cached while its prerequisite was
installed) were built on the invalid mapping and are withdrawn. The earlier
`flow` capture's ids cannot be mapped through the stored revisions either.

**Real disagreements and fix (Observed, then Implementation decision).** Three
disagreements remained, all categories delivered in the scan (server ids
106466, 106474, 106511; updates 34f268b4 r203, 405706ed r205, 05eebf61 r202),
each `IsInstalled` = `And(WindowsVersion GreaterThan Major=6 Minor=3|2
ProductType=1, Or(Processor 0, 9), Not(RegSz EditionID=Cloud), Not(RegSz
EditionID=CloudN))`. Facts: OS 10.0, product type 1, architecture 9, EditionID
`Professional`: everything holds except the evaluator's reading of `ProductType`
with `Comparison=GreaterThan` as "product type greater than 1" (False). The
native agent reported all three installed. Cause: evaluator semantics guess
(an Unverified decision of the first version). Fix: `ProductType` is tested for
equality whatever `Comparison` says. Evidence: those three rules only; 12.3
notes the extrapolation (74 `GreaterThanOrEqualTo ProductType=1` agree either
way; 9 + 9 `GreaterThanOrEqualTo ProductType=2` and `3` and 1 + 1 `GreaterThan`
are decided by this guess).

**Result after the fix.** 279 candidates (every delivered non-leaf update; the first version of this section had 275 = 93 + 182 and missed the updates of one truncated response, see below):

| Native report | Our `IsInstalled` | Count |
| --- | --- | ---: |
| in `InstalledNonLeafUpdateIDs` | True | 94 (75 categories, 19 detectoids) |
| in `InstalledNonLeafUpdateIDs` | False or Unknown | 0 |
| in `OtherCachedUpdateIDs` only, non-leaf | False | 185 (weak agreement: 149 categories, 36 detectoids) |
| in `OtherCachedUpdateIDs` only, non-leaf | True | 0 |

No disagreement, no Unknown. The remaining 1182 delivered updates are leaves:
the client cached them without reporting any as installed, although 193 of them
evaluate True for us, so a cached leaf says nothing about `IsInstalled`;
the harness classes them not comparable (Observed: no leaf id is in the
installed list in this scan; this is not established for other scans). No
delivered update was in neither list.

**What the agreement does and does not show.** One machine, one state (a clean
Windows 11 Professional with Defender definitions removed), one catalog subset
(Defender product tree), a closed-world facts snapshot. Of the 93 installed
updates 61 rules are the constant `True` and 69 contain only logical operators,
`WindowsVersion` and `Processor`; 24 read machine facts, using
`RegKeyExists`, `RegDword`, `RegSz`, `RegValueExists`, `FileExists`,
`FileVersion`, `FileExistsPrependRegSz`, `FileVersionPrependRegSz`,
`LicenseDword` and `WmiQuery`. Of the 182 not-installed updates 144 read machine
facts; `MsiProductInstalled` (30 of them) was only ever exercised on the
absent side, and `RegKeyLoop`, `FileModified`/`FileCreated`, `RegSzToVersion`,
`RegExpandSz`, `SystemMetric`, `CbsPackageInstalledByIdentity` and the MSI
feature/component/patch operators are not exercised at all. The weak agreements
cannot separate "evaluated, not installed" from "not evaluated" (the client
evaluates an update once). Nothing here covers `IsInstallable`,
prerequisites, supersedence or any other machine state.

### 12.8 Leaf-level differential against the native search (2026-10-05)

Command (exact; the test is `applicability_leaf_differential.rs`):

```sh
D=~/vm-lab/wsus-m0/diff-leaf
WSUS_FACTS_JSON=$D/facts.json WSUS_SEARCH_JSON=$D/search2.json \
  WSUS_NATIVE_FIXTURES=$D/native WSUS_NATIVE_SETS=scan \
  WSUS_REAL_REVISIONS=~/vm-lab/wsus-m0/client-run6/state/meta/revisions \
  WSUS_EXTRA_REVISIONS=~/vm-lab/wsus-m0/client-run5/state/meta/revisions \
  cargo test -p wsus-protocol --test applicability_leaf_differential -- --ignored --nocapture
```

**Setup (Observed).** Guest Windows 11 Pro 25H2, OS 10.0.26200 UBR 8037, 64-bit; Office
ProPlus2024Retail x64 16.0.17928.20148 (Click-to-Run, Platform x64, CDNBaseUrl and UpdateChannel
`http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60`, UpdateChannelChanged
`False`), Defender signature 1.459.553.0, VC++ 14.44. Facts: `collect-facts.ps1`, 20455 facts
collected 2026-10-05T04:51:40Z from the union query list of the full real catalog. Ground truth:
native WUA COM searches on the same state right after: `IsInstalled=1` lists 27 Office updates;
`IsInstalled=0 and IsHidden=0` finds 0 (ResultCode 2). The lab WSUS offered 110 active updates
(84 Office, 26 Defender; one approved Defender bundle). Candidates: the 84 leaf updates the
native scan (`scan/000060` and its predecessors, truncated responses included) delivered with action Install, plus the search
identities (all 27 already among them), identified by UpdateID + RevisionNumber from their Core
fragments, never by server ids. Child revisions come from the stored catalog of 11835 revisions
(client-run6) and, for the Defender bundle's children, client-run5 (12856 identities in total).

**Structure found (Observed).** The Install-action Office updates are BUNDLES: their Core
fragment has no `ApplicabilityRules`, only `BundledUpdates` (one child revision) and
prerequisites (two `IsCategory` clauses); the rules sit in the child (`Action` Bundle). The
Defender bundle has 4 clauses of 7, 7, 7 and 103 alternatives. So the evaluator needed a
bundle rule (this harness, not the library): a bundle without its own section takes AND over
its clauses of the alternatives' verdicts; a clause whose alternatives disagree is Unknown.

**Result (Observed).** 85 candidates (the first version of this section had 84: one Install update sat in a truncated response):

| Measure | Value |
| --- | --- |
| `IsInstalled` True for the 27 native-installed | 27 of 27 |
| `IsInstalled` False for the 58 not installed | 57 of 58; 1 Unknown (the Defender bundle) |
| Disagreements, either direction | 0 |
| Predicted `applicable` (IsInstallable True, IsInstalled False, prerequisites satisfied, not superseded) vs native found (0) | 84 False (agree); 1 Unknown; 0 True |
| Prerequisite clauses | all True for all 85 (the two category clauses evaluate installed) |
| Superseded by an installed update (assumption below) | 0 of 85 |

Operators in the `IsInstalled` rules: the 27 installed and the 57 Office not-installed use only
`RegSzToVersion` (Windows `CurrentVersion` > 6.1.0.0; Click-to-Run `VersionToReport` >= build)
and `RegSz` (`Platform` = x64, `UpdateChannelChanged` = True under `Not`); the not-installed
Defender bundle's children use `FileVersion`, `RegDword` and `RegValueExists`. No `RegKeyExists`
decides an `IsInstalled`; `RegKeyExists` (the CLSID `{B7F1785F-D69B-46F1-92FC-D2DE9C994F13}`),
`RegValueExists` (`UpdateChannel` REG_SZ), `RegSz` (`Platform`, `CDNBaseUrl`/`UpdateChannel`
Contains) and `RegSzToVersion` appear in the `IsInstallable` rules.

**Why the 56 Office updates are not offered (Observed from the rules and facts).**
`IsInstallable` evaluates False for all 57 (56 analysed below; the one recovered from the truncated response was not analysed separately). 50 require a Click-to-Run channel GUID other than
the guest's `492350f6-...` (by child rule: `7ffbc6bf-...` 32, `64256afe-...` 8, `55336b82-...` 6,
`b8f9b850-...` 2, `5030841d-...` 1, `f2e724c1-...` 1), 4 name no channel GUID, and 2 (build
20430.20118, x86 and x64) name the guest's channel. The x64 one fails only because the CLSID key
`HKLM\SOFTWARE\Classes\CLSID\{B7F1785F-D69B-46F1-92FC-D2DE9C994F13}` is absent in the facts
(the x86 one also requires Platform x86). Whether that absence is the real registry or a
collection gap was not separately checked; the native search agrees with it.

**Root causes found on the way (all fixed).** (1) `RegSzToVersion` returned Unknown for
`CurrentVersion` = `6.3` (not four parts): 14 of the 27 installed updates were Unknown. Fix:
one to four numeric parts are accepted, missing parts zero. Justification: `6.3` is the
standard Windows value and the 27 native-installed updates are only explained by it being
greater than 6.1.0.0 (one machine, one rule family). (2) The Defender bundle: with "any
alternative installed" per clause the bundle was True while the native agent does not list it
installed, so that reading is refuted by this one observation; "all alternatives" would give
False and fit, but one observation cannot separate it from other readings, so mixed clauses are
Unknown (open item: what the bundle clauses mean for the installed state).

**Supersedence assumption (Implementation decision, Unverified).** An update is superseded when
another known update lists it in `SupersededUpdates` and that update's `IsInstalled` is True on
this machine; nothing else (deployment state, revision expiry) is considered. It never fired
here, so it is untested.

**Limits.** One machine, one state: Office ProPlus2024Retail x64 Current-channel build 17928 only,
Windows 11 Pro 25H2 10.0.26200, plus the Defender bundle (one candidate, Unknown). The agreement
rests on a few registry operators (`RegSz`, `RegSzToVersion`, `RegKeyExists`, `RegValueExists`);
bundle semantics beyond single-child bundles, supersedence, prerequisites that are False, and
installed states of other channels or versions are untested. The native "found 0" says nothing
about updates the server did not offer.

### 12.9 MSI present side: model-based check only (2026-10-05)

**Setup (Observed).** On the same guest (Windows 11 25H2, 10.0.26200 UBR 8037, Office
ProPlus2024 x64 installed) three REAL MSI products built with wixl (msitools) were installed with
product codes taken from detectoids the native agent receives: `{99EFD904-A89C-4116-91C9-80FD7FD40DA7}`
at ProductVersion 4.2.1338, `{574CB555-A5C9-4E08-A2CD-FC530C17AD3F}` at 4.2.1205 and
`{DFF93860-2113-4207-A7AC-3901ABCE8002}` at 4.2.1700. Windows Installer confirmed state 5 and
VersionString 4.2.1338, 4.2.1205 and 4.2.1700. Facts: `~/vm-lab/wsus-m0/diff-msi3/facts.json`
(collected right after the installs); `diff-msi/facts.json` has the same codes at 1.0.0.0
(outside every range). **The collector's `msi_product` facts matched Windows Installer's
`MsiQueryProductState` (5) and `VersionString` for the three products** (the test asserts the
versions).

**Observability limitation (Observed).** The native agent cannot be the oracle for these rules:
all 42 delivered MSI-gated updates of the three products are Detectoids, leaf, action `Evaluate`;
the agent exposes installed state only through the non-leaf `InstalledNonLeafUpdateIDs` list and
through software-update search results, and the whole synced catalog has `MsiProductInstalled`
only in 2081 Detectoid and 57 Category `IsInstalled` rules, no Software update (checked in
client-run6). The native non-leaf (279) and leaf (85) differentials are therefore unchanged by
the installs, as expected.

**Model-based regression test (NOT native evidence).** `applicability_msi_model.rs` evaluates the 42
delivered rules (14 per code; `And(MsiProductInstalled, Processor)` alone or as the first branch of
an `Or` whose second branch names another product with Architecture 0) with the shared evaluator
against both fact files and compares with an expectation computed in the test from the
Windows-Installer-measured versions and the documented INCLUSIVE `VersionMin`/`VersionMax`
semantics (MsiApplicabilityRules page), using a plain integer comparison that does not call the
evaluator's version code. Result: all 42 verdicts equal the expectation, no evaluator change was
needed. With the installed versions: 21 True and 21 False; 4.2.1338: exactly the rules with
`VersionMax` >= 4.2.1338.0 are True (7 of 14, the boundary rule at 1338 included); 4.2.1205: all 14
True (both bounds inclusive, including the rule with `VersionMin` = `VersionMax` = 4.2.1205.0);
4.2.1700: none True; with the three products at 1.0.0.0: 0 of 42 True. The Architecture 9
branches are satisfied by the guest facts; the Architecture 0 branch of the `Or` rules is False.

**Limits.** The MSI present side is validated only against Windows Installer facts and the
documented range semantics, NOT against the native agent. One guest, three wixl products
(three-part version strings), one rule shape (`And` with `Processor`). `Language`, the present
side of `ExcludeVersion*`, features, components and patches are not exercised.

### 12.10 CommandLineInstallation: observed HandlerSpecificData and install decisions (2026-10-05)

Sources: the stored revision records `~/vm-lab/wsus-m0/client-run5/state/meta` (5168 revisions) and
`client-run6/state/meta` (11835 revisions), parsed by `crates/wsus-client/tests/install_real_defender.rs`
(`every_real_handler_spec_parses`, env-gated). Nothing in this section was executed against Windows.

**Observed schema.** A Software revision that installs through a command line carries, in its
**Extended** fragment (never in Core), three sibling elements:

```xml
<ExtendedProperties DefaultPropertiesLanguage="en"
    Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation"
    MaxDownloadSize="6478752" MinDownloadSize="0">
  <InstallationBehavior [Impact="Minor"] [RebootBehavior="CanRequestReboot"] />
</ExtendedProperties>
<Files><File Digest="..." DigestAlgorithm="SHA1" FileName="AM_Slim_Delta.exe" Size="6478752"
    Modified="2026-10-04T05:16:26Z"><AdditionalDigest Algorithm="SHA256">...</AdditionalDigest></File></Files>
<HandlerSpecificData type="cmd:CommandLineInstallation">
  <InstallCommand Program="AM_Slim_Delta.exe" [Arguments="WD /q"]
                  [RebootByDefault="false" DefaultResult="Failed"]>
    <ReturnCode Code="0" Result="Succeeded" [Reboot="false"] />
    [<ReturnCode Code="-2142207945" Result="Failed" />
     | <ReturnCode Code="-2142207945" Result="Succeeded" Reboot="true" />]
  </InstallCommand>
</HandlerSpecificData>
```

| Observation | client-run5 (917 specs) | client-run6 (3836 specs) |
| --- | --- | --- |
| `Handler` URI | `CommandLineInstallation` (917 of 917) | same (3836 of 3836); no other handler URI occurs in any Extended fragment of either store |
| Elements under `HandlerSpecificData` | one `InstallCommand` with one or more `ReturnCode` children; no other element | same |
| `InstallCommand` attributes | `Program`, optionally `Arguments` | `Program`, `RebootByDefault="false"`, `DefaultResult="Failed"` (3794 of 3836) or `Program` alone |
| `ReturnCode` attributes | `Code`, `Result`; no `Reboot` | `Code`, `Result`, `Reboot` (3794 with `Reboot="false"`; 21 with `Reboot="true"`) |
| `Result` values | `Succeeded`, `Failed` only | same |
| Codes | `0` Succeeded everywhere; `-2142207945` (0x80508037) `Failed` in 21 | `0`; `-2142207945` `Failed` (21) or `Succeeded` with `Reboot="true"` (21, with `InstallationBehavior RebootBehavior="CanRequestReboot"`) |
| `Arguments` | `WD /q` (588), `/LastPackage` (84), `/Store` (28); none (217) | none |
| Programs | `MpSigStub.exe`, `AM_Engine*.exe`, `AM_Base*.exe`, `AM_Slim_Base*.exe`, `AM_Delta*.exe`, `AM_Slim_Delta*.exe` | `NoOp.exe` (13,160 bytes) in 3794; the Defender programs in the rest |
| Files | exactly one `File`, and its `FileName` equals `Program` (917 of 917) | same |

The attribute order of `ReturnCode` differs between the Defender and the `NoOp.exe` shapes (the latter
writes `Reboot`, `Result`, `Code`); the parser reads attributes by name. The element and attribute
names, the handler URI and the `type` value `cmd:CommandLineInstallation` are Observed; what a Windows
Update Agent does with each is NOT observed (the agent's installation steps are not on the wire, 9.4).

**Meaning adopted (Implementation decisions, Unverified).** `Program` is a file name that must equal
the update's own payload and is executed from the verified store. `Arguments` are space-separated
tokens of `[A-Za-z0-9/._=:-]`, passed as separate arguments (every observed value fits). An exit code
without a `ReturnCode` is `Failed` (the observed `DefaultResult` is always `Failed`). `Succeeded` with
`Reboot="true"` is success with a reboot required; `RebootByDefault` is only honoured for `Succeeded`
(it is `false` wherever it occurs). The Windows exit code is compared as the `i32` with the same bits.
0x80508037 is a Defender-specific value; its meaning is not established here.

**The Defender bundle `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe` rev 200 (Observed, structure).** Deployment
action `PreDeploymentCheck`, leaf, 10 superseded updates, prerequisites two bare identities and two
`AtLeastOne IsCategory` clauses, no `ApplicabilityRules` of its own, four `BundledUpdates` clauses of 7, 7,
7 and 103 alternatives. The alternatives are sub-bundles (action `Bundle`, no rules, two category
prerequisites, one clause of 4 to 30 installers) or installers directly; the planner visits 433 nodes
(1 root, 28 sub-bundles, 404 installers). The clauses correspond to `MpSigStub.exe /Store` (28 installers),
the `AM_Engine*` packages, the `AM_Base*` and `AM_Slim_Base*` packages, and the `AM_Delta*`/`AM_Slim_Delta*`
delta packages. The SHA-1 digests and sizes of `AM_Engine.exe` (6,662,560 bytes), `AM_Base.exe`
(204,745,168) and `AM_Delta.exe` (11,606,440) in the plan below equal the files the native agent
downloaded in 9.4.

**Dry-run plans (Observed from the host test; no execution).** Facts snapshots of the lab guest:

| Facts | Result |
| --- | --- |
| `diff-msi3/facts.json` (Defender 1.459.553.0, 2026-10-05) | `nothing_to_do_installed`: 184 installers installed, 220 not applicable, root installed; 32 facts (8 file, 19 registry value, 2 key, 1 license, OS, architecture); no blocker |
| `diff/facts.json` (Defender definitions removed, 2026-10-04) | `install`, 3 steps, no blocker, 29 facts: `AM_Engine.exe` (update `ff36f0b5-dded-4780-8664-cd78af8b62c1@200`, no arguments), `AM_Base.exe` (`14419a7a-86f2-48ff-b6c0-24dd102f2b2d@200`), `AM_Delta.exe WD /q` (`266f6222-c89d-43f2-9f8a-69340271e677@200`); the 28 `MpSigStub.exe` installers evaluate installed |

Difference, explained (see 12.11): the native agent downloaded `MpSigStub.exe` too (9.4), while this
plan for the removed-definitions snapshot treats every `MpSigStub.exe` installer as installed. The
snapshot was taken on a guest whose `System32\MpSigStub.exe` already had the target version (written by an
earlier native install); with the stub absent the plan has the same four files as the native agent. The native agent also never requested 5 of the 9 `AM_Delta.exe` locations;
the plan picks one delta, consistent with that, but the selection rule ("every qualifying alternative") is
Unverified.

**Not established:** that Windows runs these commands the way the agent does (working directory,
environment, token, reboot handling); what 0x80508037 means; whether the evaluator says installed after the
install (that is the post-check, ledger C42); anything for a handler other than `CommandLineInstallation`.
The installer is described in [wsus-install.md](wsus-install.md).

**Guest run (2026-10-05, Observed, one Windows 11 Pro 25H2 10.0.26200 UBR 8037 guest, Defender definitions removed).**
`facts-check` of the Rust provider against the PowerShell collector: 20461 queries, 0 disagreements, 59
`ours_unavailable` (all `wmi_query`, by design). The first run had 11 of 132 file disagreements: OS files
reported 6.2.26100.x instead of 10.0.26100.x because the binary had no application manifest declaring Windows
10/11 support (version compatibility behaviour); fixed by embedding `wsus.exe.manifest`. Hazard: any Windows
binary that reads versions needs the manifest. `scan` found exactly `a2fef9b0@200` applicable (agrees with the
native agent), `plan` gave the 3 steps above (guest `plan_sha256` 91b581ab0fb7..., facts hash 9af7e061...), and
`install --yes` ran them: digest verified, signer `Microsoft Corporation`, exit 0 each, post-check all installed,
`AntivirusSignatureVersion` 0.0.0.0 -> 1.459.547.0 (independent), 10.9 s. A re-run was `no_action`. `--trust-signer
"Contoso Ltd"` refused with nothing executed. A flipped byte in the stored `AM_Engine.exe` was repaired by the
download verification before execution (the pre-execution digest gate was not exercised). The `MpSigStub.exe`
difference is explained in 12.11. 0x80508037 was not seen (all exits were 0).



### 12.11 `MpSigStub.exe`: binary analysis and the System32 experiment (2026-10-05)

Subject: the `MpSigStub.exe` payload of the Defender update (918,944 bytes, SHA-256
`071b0d3a08503a8b88aeeda1d20f371a563377028f6e252dc66cce60ab8f823e`, x64 PE, 2,075 functions, stripped,
Microsoft-signed), taken from the content store and opened in IDA (headless). Four objects named
`MpSigStub.exe` exist in the catalog; this is one of them. Everything under "From the binary" is read from
that file; nothing was run under a debugger.

**Update metadata (Observed, real revisions).** Each of the 28 `MpSigStub` children has
`IsInstalled = FileVersion Path="MpSigStub.exe" Csidl=37 Comparison=EqualTo Version="1.1.24010.2001"`
(Csidl 37 is System32) and an `IsInstallable` gated by gradual-release state: `DisableGradualRelease`
(`SOFTWARE\Microsoft\Windows Defender\MpEngine`), `mpasdlta.vdm` under the `SignatureLocation` being newer than
1.339.0.0, and `MpEngineRing` (present and equal to a ring number, or absent in the variants written with
`Not(RegValueExists)`). The command is `MpSigStub.exe /Store`.

**From the binary.**

| Finding | Evidence |
| --- | --- |
| It embeds the version `1.1.24010.2001` (48 references), the same value the `IsInstalled` rule compares | string at `0x1400c0610` |
| Its purpose is applying signature delta updates: strings `mpasdlta.vdm`, `mpavdlta.vdm`, `mpengine.dll`, `*_to_*_mpengine.dll._p`, `*_to_*_mpasdlta.vdm._p`, `DeltaUpdateFailure`, `BddUpdateFailure`; it talks to the `windefend` service (OpenSCManager, OpenService, StartService) | strings and imports |
| `0x14002FDD4` is the top-level dispatcher, not the Store operation: before dispatching it removes a *stale* System32 copy (version below the floor 1.1.16500.1, not below its own version), then selects the operation by option presence. The Store operation itself is the small function `0x14002F78C` (section 12.12) | decompilation (corrected 2026-10-05: the first reading of this row was wrong) |
| Product selection switches `/Forefront`, `/WindowsDefender`, `/Antimalware`; options must start with `-` or `/`; a command file is supported | strings |
| `UpdateStubInstall` is an environment variable name (the lookup returns `ERROR_ENVVAR_NOT_FOUND`, 0x800700CB, when it is unset), not evidence of a self-copy | `0x1400A27C4` |
| A child-process exit code `0x80501109` is rewritten to 1; the constant `0x80508037` (the return code the update metadata maps to Failed or Succeeded plus Reboot) does not occur as an immediate in this binary, so that code comes from the `AM_*` packages or elsewhere, not from this stub | `0x14002D08B`, byte search |

**Experiment (Observed, one disposable guest, 2026-10-05).** `System32\MpSigStub.exe` was moved aside and the
definitions removed. The installing client's plan then had four steps (above) and `install --yes` succeeded; the
file in System32 reappeared with SHA-256 `071b0d3a08503a8b...` equal to the moved copy and to the analysed
payload, version 1.1.24010.2001. Therefore running `MpSigStub.exe /Store` from the verified store places the
stub in System32. Whether it also does so when a newer stub is present, and what the deletion of stale copies
touches, was read from the binary but not exercised.

The remaining questions of this section are answered in 12.12.


### 12.12 `MpSigStub.exe` 1.1.24010.2001: control flow, exit codes, newer-stub behaviour, rings (2026-10-05)

Method: three independent static analyses of the payload in IDA (headless, private copies; one thread each:
control flow and exit codes, the Store operation and version comparison, ring and registry configuration), plus
behavioural tests of the genuine Microsoft-signed binary on the disposable guest (Windows 11 25H2 10.0.26200
UBR 8037). Labels: **READ** (decompilation, address given), **OBSERVED** (run on the guest), **INFERRED**.
Where READ and OBSERVED disagree, both are stated. Nothing here is a statement about other versions of the stub.

#### Control flow (READ)

`start` 0x14001BED0 -> CRT -> `WinMain` 0x1400315F0; the process exit code is WinMain's return value passed to
`exit()`, an HRESULT with no translation table (no `ExitProcess`/`TerminateProcess` on the path).

1. WinMain: registers ETW providers; an empty command line returns `0x80070667` (0x14003170F); rewrites legacy
   tokens (below); parses options into a map (global 0x1400D7D28); opens the log and writes the header; logs
   `Command:`, `Administrator: yes|no`, `Version:`; runs the WOW64/ARM64 guard `0x14002FBE8` (a 32-bit process
   or ARM64 returns `0x8007029E`); calls the dispatcher; if the result is negative logs
   `ERROR 0x%08lx : MpSigStubMain` and returns it unchanged. A `catch(...)` returns `0x80004005`.
2. Dispatcher `0x14002FDD4`: (A) admin only: if `System32\MpSigStub.exe` has a version below 1.1.16500.1 (packed
   `0x0001000140740001`, the floor of a hard-coded constant, not the stub's own version) it logs
   `Deleting stale(%ls) %ws` and marks it delete-on-close, failures ignored; (B) if option `Store` is present run
   `Op_Store` (0x14002F78C): a result of 1 ("nothing to do") is mapped to 0, any other value is returned as the
   exit code; the Store branch never reaches the product steps; (C) otherwise the stub-version gate: the value of
   option `stub` must equal `1.1.24010.2001` (wcscmp 0x1400303DE, default `N/A`) or it logs
   `Invalid stub version(%ws)` and returns `0x80070032`; (D) the update path: SearchForInstalledProducts ->
   (option `MpWUStub`) AccumulatePackages -> DiscoverSignaturePackages -> SearchForApplicableProducts
   (`0x80070490` not found is mapped to success) -> per product patch application (0x140037B54) and update
   (0x14002CE14); any one product succeeding clears the accumulated error, otherwise the first error is returned.
   The metadata only ever uses the Store path.

#### Options (READ; items marked OBSERVED were run)

Each argument must start with `-` or `/` (`--` also accepted); a value is the next argument if it does not start
with either character; an `@file` argument is a command file (blank lines and `#` comments skipped, `%VAR%`
expansion unless `__NO_STRING_EXPANSION`). Legacy token rewrite (first substring match, case-sensitive, table at
0x1400B39B0): `FCS`/`FCS2` -> `/Forefront`, `WD` -> `/WindowsDefender`, `ANTIMALWARE` -> `/Antimalware`,
`ISA` -> `/ISA`, `SWP` -> `/SWP`; because it is a substring match, these tokens can also match inside other text on the command
line. (How `AM_Delta.exe WD /q` relates to this table was not examined: `AM_Delta.exe` is a different binary.) Options consumed: `Store`, `stub`, `MpWUStub`,
`ConnectTimeoutMS` (default 120000, clamped to 1000..300000), `PlatformUpdateTimeout` (default 120000),
`WUScenario`, `from`, `ProductGUID` (default 212e9c34-cc85-497b-a25d-3896e21b5a77), `OverrideVersionCheck`,
`Verbose`/`V`, `NoMaxRetries`, `EnableETW` (default 10, admin only, sampling probability about EnableETW/10000),
`KeepETW`, `UpdateStubTest` (test hook, INFERRED), and the product switches in a 20-row table at 0x1400B3A50
(`Test`, `WindowsDefender`, `Sense`, `Forefront`, `Antimalware`, `ISA`, `SWP`, `DownlevelMOCAMP`; mapping of
switch to row INFERRED). Unknown options are not rejected by the parser.

#### Exit codes

| Condition | Exit code | Basis |
| --- | --- | --- |
| `/Store`, copy done, nothing to do, or not administrator | `0x00000000` | READ (1 mapped to 0, 0x14003031C-0x140030350); OBSERVED for the first three and for non-admin |
| No arguments / empty command line | `0x80070667` (ERROR_INVALID_COMMAND_LINE) | READ 0x14003170F; OBSERVED |
| Argument without a leading `-` or `/` (`Store`) | `0x80070667` | READ; OBSERVED |
| Option other than Store without `/stub 1.1.24010.2001` (`/?`, `/bogus`, `/Foo`) | `0x80070032` (ERROR_NOT_SUPPORTED), log `Invalid stub version(N/A)` then `ERROR 0x80070032 : MpSigStubMain` | READ; OBSERVED |
| Missing command file (`@nofile.txt`) | `0x80070002` | OBSERVED (READ expected a parse-error family code) |
| Duplicate option (`/Store /Store`) | exit `0x00000000` | OBSERVED; the code reading predicted `0x80070667` (the duplicate check applies to command-file entries; not resolved) |
| `--Store`, `-Store`, `/Store x`, `/Store /WindowsDefender` | `0x00000000` | OBSERVED |
| 32-bit (WOW64) or ARM64 process | `0x8007029E` | READ; not run (the binary is x64) |
| Store, copy fails | the translated `GetLastError` of `CopyFileW`, returned unmapped | READ; not provoked |
| Update path: nothing applicable | 0 | READ |
| Update path: product failure | that product's HRESULT (e.g. `0x80070670` BDD destination version higher, `0x8007051A` older version after update, `0x80070645` all products disabled, `0x8000000A` platform update pending) | READ; see 12.13: the loop is over the packages of one product, "any success clears the error" only gates `UpdateProduct`, and the exit code is the last failing package, not masked |
| Exception in the dispatcher | `0x80004005` | READ |

A child exit code `0x80501109` from the platform updater (`MpRecovery.exe`) is rewritten to 1 (0x14002D08B). No
code in the binary builds or compares `0x80508037`, and the stub has **no reboot-needed exit path**: the
return-code table in the update metadata (`0x80508037` Failed, or Succeeded with `Reboot="true"`) therefore
concerns the `AM_*` packages and the Defender engine, whose HRESULTs the stub would only pass through (INFERRED;
the stub's own Store path cannot produce it). In the lab no exit other than 0 was seen from the installers.

#### Store operation and newer-stub behaviour (READ + OBSERVED)

`Op_Store` (0x14002F78C): not administrator -> return 1 (OBSERVED: exit 0, no change, a non-elevated standard user
run left an older System32 copy untouched). Otherwise it logs `Parent process:`, takes the path of the running image
and `System32\MpSigStub.exe`; equal paths -> return 1; otherwise opens both, compares sizes, then the content in
chunks of up to 0x4000 bytes; **byte-identical -> skip**; any open failure, size difference or content
difference -> `SetFileAttributes(NORMAL)`, `CopyFileW(src, dst, bFailIfExists=FALSE)`, `SetFileAttributes(NORMAL)`,
log `CacheMpSigStub` banner and `Copied MpSigStub.exe to %ws`, then `CleanupDropLocation` (0x140043A0C: removes
`%windir%\Temp\<dir>` named by `HKLM\SOFTWARE\Microsoft\MpSigStub\DropLocation` if it is empty, then deletes the
value). There is no temp-file-and-rename, no `MoveFileEx`/reboot scheduling (not imported), no ACL change and no
locking: a System32 copy that is running would make `CopyFileW` fail with a sharing violation (INFERRED).

| Installed `System32\MpSigStub.exe` | Result of `MpSigStub.exe /Store` | Basis |
| --- | --- | --- |
| Absent | copied, exit 0 | OBSERVED (restored with the identical SHA-256) |
| Older (file version 1.1.23000.2001) | overwritten, `Copied MpSigStub.exe to ...`, exit 0 | OBSERVED |
| **Newer** (1.1.24020.2001) | **overwritten with the older stub, i.e. downgraded**, exit 0 | OBSERVED; READ explains it: no version comparison on this path |
| Same version, different bytes | overwritten, exit 0 | OBSERVED |
| Byte-identical | not touched, exit 0, no further log lines | OBSERVED; READ `identical` |
| Any of the above, run without administrator rights | not touched, exit 0 | OBSERVED (standard user) |

Consequences for an installer: an exit code of 0 does not show the stub was stored, so success must be judged by
the post-condition (our client's post-check does); and because the metadata's `IsInstalled` is an `EqualTo`
comparison, a machine with a *newer* stub is evaluated not installed and a plan would downgrade it, exactly as
the native agent's metadata would. The two version comparisons are different things: the floor in the dispatcher
(1.1.16500.1, stale delete) and the `/stub` gate (equality with the stub's own version, non-Store runs only).

#### Update path internals (READ; partly traced)

SearchForInstalledProducts (0x140036CF8): 20 product records (88 bytes each) from registry roots
`SOFTWARE\Microsoft\Windows Defender`, `...\Windows Advanced Threat Protection`, `...\Microsoft Forefront\Client
Security\1.0\AM` and `2.0\AM`, `SOFTWARE\Microsoft\Fpc`, `...\Standalone System Sweeper`, `...\Microsoft
Antimalware` (product switches restrict the set); messages `No installed products found` and
`All products are disabled` (`0x80070645`). DiscoverSignaturePackages (0x14003B1EC) tries, in order, the
WUScenario directory, the `/from` directory, the current directory, the stub's own directory; a candidate must be
non-empty and distinct. Patch application (0x140037B54) iterates 10 file slots (1 mpengine.dll, 2 mpasbase.vdm,
3 mpavbase.vdm, 4 mpasdlta.vdm, 5 mpavdlta.vdm, 6 nisbase.vdm, 7 nisfull.vdm, 8 MpClient.dll, 9
SenseUpdateProvision.dll, 10 unknown), finds a patch keyed by the installed file's packed version (exact, then the
wildcard 9999.9999.9999.9999), names `*_to_*_<file>._p` parsed with a 13-field format, applies it (`MPSP` header
dispatch; the patch algorithms were not reversed) and checks the patched version. The BDD rule: with no matching
patch, slots 4 and 5 where installed >= destination give `0x8007066F` (logged `... is not higher then currently
installed version. MpSigStub will not fail.`, treated as non-failing and the failure DWORDs reset), every other
case gives `0x80070670` (`... will fail`, `DeltaUpdateFailure`/`BddUpdateFailure` set to 1 under
`<product root>\Miscellaneous Configuration`). Signatures are applied through `mpclient.dll`
(`MpOpen`, `MpUpdateEngine`, `MpUpdatePlatform`); the platform update uses `MpRecovery.exe`; when the primary
attempt fails with a sharing-class error and the caller is an administrator, an xcopy fallback drops the package in
`SignatureDropLocation` and waits (180000 ms, or 420000 ms for a product flag) for the Defender service to change
`SignatureLocation` (change notification on `Signature Updates`, timeout `0x800705B4`).

#### Gradual-release rings (READ + metadata)

The stub **never branches on a ring**. `MpCampRing`, `MpEngineRing` and `MpSignatureRing` under
`HKLM\SOFTWARE\Microsoft\Windows Defender\MpEngine` (fallback `Microsoft Antimalware\MpEngine`) are read only
by two telemetry functions (0x14003FF70, 0x1400460A0), default -1, as strict REG_DWORD, and only logged to ETW.
`DisableGradualRelease` is not referenced anywhere in the binary (exhaustive string search): it is evaluated only
by the Windows Update agent through the update's `IsInstallable` rules. In the metadata the 28 `MpSigStub`
children are seven groups of four: AND forms for rings 0, 1, 2, 3, 4 and 6
(`Not(DisableGradualRelease>0) AND mpasdlta.vdm under SignatureLocation > 1.339.0.0 AND MpEngineRing present as
REG_DWORD AND MpEngineRing == N`) and one catch-all OR group (`DisableGradualRelease>0 OR mpasdlta.vdm not above
1.339.0.0 OR MpEngineRing absent or not REG_DWORD OR MpEngineRing == 5 OR MpEngineRing > 6`). Ring 5 and rings of
7 or more therefore appear only in the OR group, rings 0 to 4 and 6 once per group, and the seven classes
partition every machine state. What distinguishes the four children inside a group was not determined. A machine
with no `MpEngineRing` (every guest in this lab) matches only the OR group, which is why the plan selected child
`0daf8592-9e3f-4a8a-9141-d83fafebd09f`. Who writes `MpEngineRing` is outside the stub (INFERRED: the Defender
engine or service).

Other registry use (READ): `HKLM\SOFTWARE\Microsoft\MpSigStub` values `LastStartTime` (REG_QWORD),
`LastExitCode` (REG_DWORD) and `DropLocation` (above); `Signature Updates\SignatureLocation`,
`NISSignatureLocation`, `SignatureDropLocation`, `SignatureRootLocation`; WER `ForceQueue` (crash-report queueing
only, unrelated to update jobs); `Windows Defender\Features\SenseEnabled` (telemetry flag). Command-line only
(not registry): `ConnectTimeoutMS`, `PlatformUpdateTimeout`, `EnableETW`, `Store`, `MpWUStub`.

#### Logging (READ + OBSERVED)

File `MpSigStub.log`: administrators `%SystemRoot%\Temp\MpSigStub.log`, others the per-user temp directory;
UTF-16LE with a BOM, opened for append (retried each second up to 120 times unless `NoMaxRetries`, truncated above
1 MiB, refused if a reparse point). No per-line timestamp. A run writes `Start time: yyyy-MM-dd HH:mm:ssZ`,
`Process: <pid>.<id>`, `Command: <args>`, `Administrator: yes|no`, `Version: 1.1.24010.2001`,
`Parent process: <exe>`, optional step banners (`=== CacheMpSigStub ===`), messages such as
`Copied MpSigStub.exe to C:\WINDOWS\system32\MpSigStub.exe`, and `End time:`. Errors are `ERROR 0x%08lx : <where>`.
Observed example lines: `Command: /Store`, `Administrator: yes`, `ERROR 0x80070032 : Invalid stub version(N/A)`,
`FailedFunction: P2`. A separate ETW session writes `%SystemRoot%\Temp\MpSigStub.etl` in about 0.1 percent of
administrator runs by default.

#### Not established

Why a duplicate command-line option exits 0 where the parser reading suggests an error; the content of the
product-record parser (0x140029648); the meaning of the `~` prefix in numeric parameters; any behaviour of a version
of the stub other than 1.1.24010.2001. Since resolved (see 12.13): option names are case-insensitive (OBSERVED on
the guest: `/Store`, `/store`, `/STORE`, `-sToRe`), the exit code of an update run, the xcopy fallback (READ), the
accumulation rendezvous, and the patch formats (READ, decoder self-consistent only). The update path itself ran
on the guest in the normal Engine, Base, Delta order (log lines above); it was not run in other orders.

**Defender package exit codes precede the update (Observed 2026-10-05, same guest).** `AM_Engine.exe` exits 0
after about 1 s and leaves a detached `MpSigStub.exe /stub <ver> /payload <ver> /MpWUStub /program <AM_Engine.exe>`
waiting in AccumulatePackages (default `ConnectTimeoutMS` 120000) for `AM_Base.exe` and `AM_Delta.exe`; in a
normal Engine, Base, Delta run it applies the update within seconds and writes `%SystemRoot%\Temp\MpSigStub.log`
(UTF-16LE: `Signatures updated from ...`, `MpSigStub successfully updated ...`, `DeltaUpdateFailure set to 0`). A lone
`AM_Engine.exe` leaves the stub waiting about 120 s, then `ERROR 0x800705b4 : AccumulatePackages`, nothing updated, all
exits 0. The `ReturnCode` list above therefore cannot prove success for these packages; see the waiting post-check in
[wsus-install.md](wsus-install.md) (ledger C39, C42).


### 12.13 Defender package launchers, the rendezvous, the update tail and patch formats (2026-10-05)

Static analysis (IDA, decompiled addresses; `S` = `MpSigStub.exe` 1.1.24010.2001, `L` = the package launcher) plus
checks against the real package files of bundle `a2fef9b0` rev 200. Labels: READ = decompiled, OBSERVED = checked
against real files or guest logs, INFERRED = deduced. **No part of 12.13 was re-run on a guest**; the guest
evidence is the log lines already recorded in 12.12 and above.

#### The three packages are one launcher (READ, OBSERVED)

`AM_Engine.exe`, `AM_Base.exe` and `AM_Delta.exe` have byte-identical `.text`, `.rdata`, `.data`, `.pdata` and
`.reloc` (PDB name `MpWUStub.pdb`, version string 1.1.24010.2001); only the resources differ. The launcher does not
unpack anything and does not carry the stub. It runs `%SystemRoot%\System32\MpSigStub.exe` (L 0x140020CA8,
0x140022618) and returns `0x80070650` unless that file's version is exactly 1.1.24010.2001 (L 0x140021770). This is
why the plan must be able to restore the System32 stub (12.11).

| Package | Resources | CAB payload |
|---|---|---|
| `AM_Engine.exe` 6,662,560 B, 1.1.26080.3 | `CABINET/UPDATEPAYLOAD` | `mpengine.dll` 18,546,544 B |
| `AM_Delta.exe` 11,606,440 B, 1.459.547.0 | `BINARY/MPSIGSTUB` (1 byte, 0x01), `CABINET/UPDATEPAYLOAD` | `mpasdlta.vdm` 7,691,168, `mpavdlta.vdm` 3,633,616 |
| `AM_Base.exe` 204,745,168 B, 1.459.0.0 | `CABINET/UPDATEPAYLOAD` | `mpasbase.vdm` 141,843,400, `mpavbase.vdm` 62,575,056 |

The stub, not the launcher, reads the CAB out of each package (FDI over a datafile-mapped module, pseudo path
`UPDATEPAYLOAD\<hex HMODULE>`, S 0x140044F50, 0x140045960). `BINARY/MPSIGSTUB` is the "last package" marker (the
`*` in the log's package list); 7z does not list it.

#### Rendezvous protocol (READ)

- **Key:** the pipe is `\\.\pipe\%x.%I64x` of the **parent process** of the launcher (parent PID in hex, dot, parent
  creation FILETIME in hex; L 0x1400247FC). It is not derived from a GUID, version or directory. The three packages
  therefore meet only if the same process starts them. Our installer starts all three from one process, which
  satisfies this; starting them from different parents would not.
- **Launcher:** finds a sibling process (same parent PID) whose image is `System32\MpSigStub.exe` and reuses it;
  otherwise spawns the stub with the PARENT_PROCESS attribute set to the launcher's own parent, flags `0x08080000`
  (so the stub is a sibling, not a child: this is the "detached" process seen in 12.12). Stub command line:
  `MpSigStub.exe /stub 1.1.24010.2001 /payload <package FileVersion> /MpWUStub /program <all of the launcher's argv>`.
  The launcher scans argv only for `LastPackage` and `NoMaxRetries`. It then `WaitNamedPipeW`s (timeout rule below),
  and `CallNamedPipeW`s one message. Stub exited: `0x8007042B`; pipe wait timed out: `0x800705B4` (retried forever with
  `NoMaxRetries`).
- **Server:** the stub, only with `/MpWUStub`. `CreateNamedPipeW` mode 0x40080003 (duplex, overlapped), message
  type, `PIPE_REJECT_REMOTE_CLIENTS`, one instance; DACL from SIDs Administrators and Users plus token user and owner
  (ACE masks not read). `ConnectTimeoutMS` default 120000, clamped to 1000..300000, applies to the whole wait and the
  timer restarts after every non-terminal package (S 0x1400308E2, 0x140041C60).
- **Message** (client to server), `14 + 2n` bytes: offset 0 client creation FILETIME (8), offset 8 client PID (4)
  with bit 0 = `LastPackage`, offset 12 `n` (2), offset 14 the client's own module path (`n` WCHAR, no NUL).
  The server accepts 15..65549 bytes. **Reply** is one DWORD: 1 = accepted (launcher exits 0), anything else is
  returned as the exit code; a reply not 4 bytes gives `0x8007000D`.
- **Server checks:** PID in the message vs `GetNamedPipeClientProcessId` (mismatch `0x8007000D`); the client's parent
  identity equals the server's own parent (else reply `0x80070020`, timer not reset); the parent still alive and
  not recycled (`0x8000FFFF`). It does not check the client's image path.
- **Termination:** accumulation ends when the message has `LastPackage` or the package has `BINARY/MPSIGSTUB`.
  Non-terminal clients (Engine, Base) are answered at once and exit 0 after about a second. The terminal client
  (Delta) gets no reply until the update has run; then the server destructor sends the stub's **final HRESULT**
  (S 0x140041A44), so `AM_Delta.exe`'s exit code is the stub's final result. That is the reason a normal run's last
  exit code carries the outcome while the first two never do.
- **A lone `AM_Engine.exe`:** no sibling stub exists, so it spawns one, gets reply 1, exits 0; the stub waits
  `ConnectTimeoutMS`, then `0x800705B4` in `AccumulatePackages` (OBSERVED in 12.12, now explained by the code).
- **INFERRED, not run:** `AM_Delta.exe` alone would stop accumulating immediately (it carries the marker) and
  update from the delta package only.

**`AM_Delta.exe WD /q` (metadata command line).** The launcher does not interpret `WD` or `/q`; it appends every
argv entry after `/program`. They reach the stub only if that launcher is the one that spawns it; the stub's legacy
rewrite then turns `WD` into `/WindowsDefender` (12.12). In the observed Engine, Base, Delta order Engine spawns the
stub, so `WD /q` is dropped and is never seen by the stub (consistent with the real log, which shows no `WD`). The
arguments are not carried in the pipe message. (INFERRED from the command-line construction; no guest run with
Delta spawning the stub.)

#### Exit codes of an update run: correction and decision table (READ)

**Correction to the table in 12.12.** The dispatcher loop (S 0x14002FDD4) iterates the **packages of one applicable
product**, not several products. "Any success clears the error" is only the gate that decides whether
`UpdateProduct` runs; it does not set the exit code.

1. Each package `i` gets `r_i = ApplyPatchesForPackage` (S 0x140037B54). If any `r_i >= 0` the error is cleared and
   `UpdateProduct` (S 0x14002CE14) runs, giving `U`; otherwise `UpdateProduct` is skipped and `U` is the first
   negative `r_i`.
2. If `U == 0x8000000A` (platform update pending) post-processing is skipped and the final code is 0.
3. Otherwise `PostUpdateReportAndFailureFlags` (S 0x14003B7FC) runs per package: with `c = r_i`, if the update ran
   and `c >= 0` then `c = ValidateUpdate` (S 0x14002DD38) (and if `U < 0` and validation failed, `c = U`); if
   `c < 0` and `c != 0x8007066F` the **last** failing `c` is the result and the failure flag is set to 1; otherwise
   the `DeltaUpdateFailure`, `BddUpdateFailure` or `NISDeltaUpdateFailure` value is set to 0.

| Case | Final HRESULT |
|---|---|
| All packages and `UpdateProduct` succeed | 0 |
| All patch fine, `ValidateUpdate` finds an older version | `0x8007051A` |
| One package fails (not `0x8007066F`), others fine | that failing HRESULT, not masked |
| All packages fail, none tolerated | `UpdateProduct` skipped; the last failing HRESULT |
| All fail, only tolerated BDD `0x8007066F` | 0, `UpdateProduct` skipped |
| Platform update returns `0x8000000A` | 0, counters untouched |
| BDD tolerated `0x8007066F`, rest fine | 0, counters reset |
| BDD fatal `0x80070670` | `0x80070670` even if the rest succeeded; `BddUpdateFailure` = 1 |
| `UpdateProduct` fails but `ValidateUpdate` succeeds | 0 (rescued) |
| No applicable product | 0 (`0x80070490`, 12.12) |
| Exception in the dispatcher | `0x80004005` |

Which package supplies the stub's exit code in a run is the terminal client's reply (above), not a separate code.

#### Xcopy fallback (READ)

`UpdateSignatures` (S 0x14002D838) first calls the engine's update entry with the package directory. If that fails with
`0x800106B5`, `0x800106BA`, `0x800106BB`, `0x800106BF` (RPC-class) or `0x80070020` (sharing violation) and the caller
is an administrator, `XcopyDeployment` (S 0x14002ED54) reads `Signature Updates\SignatureDropLocation`, copies each
product slot file with `CopyFileW` into it (`XcopyForProduct`, S 0x14003C91C, log lines `Copied %ws` and
`DropLocation: %ws`), starts the service for the four RPC codes, and `WaitForSignatureUpdate` (S 0x14002E6F8) watches
`HKLM\<product>\Signature Updates` (change notification plus a 500 ms timer) until `SignatureLocation` (and
`NISSignatureLocation` if flagged) equals the expected path: 420000 ms if the product field `a1+24` is 1, else
180000 ms, then `0x800705B4`. Non-administrators get `ServiceStart` (RPC codes) or a copy to a new directory and a
retry (sharing violation). Effect: a successful xcopy turns the original failure into 0; a failing xcopy replaces the
code with its own; a non-triggering code leaves the original. Not read: `sub_14002C3B8` (post-update step) and the
sense-client path (S 0x14002D620). Never exercised on a guest.

#### Patch formats (READ; decoder self-consistency only)

- `ApplyPatchDispatch` (S 0x140035730) reads a 4-byte magic. `MPSP` goes to the stub's own applier; anything else goes
  to `LoadLibrary("mspatcha.dll")` and `ApplyPatchToFileByHandles` (Windows PatchAPI, PA19 family, no stub decoder;
  the repository's `windows-delta` README states legacy PA19 is unsupported, so this repo cannot apply them).
- Patch files only arrive as separate `<from>_to_<to>_<file>._p` files in the discovery directories. **None of the
  three packages carries one** (OBSERVED: no `MPSP`/`MPSZ`/PA30 magic, no `_to_` names in any CAB or VDM). The three
  packages ship full files; `AM_Delta` is a full "delta" VDM pair, not a patch. This matches the lab log (no
  `Patched ...` lines).
- No source or target hash and no signature check surrounds a patch; the only checks are those inside the MPSP code
  and a final comparison of the patched file's version resource with the expected one (`0x80070670` on mismatch;
  wildcard `0x270F270F270F270F`).
- **MPSP container** (little-endian): 4 magic `MPSP` (or `MPSZ`), 4 payload length (= file size - 16), 4 decoded
  stream size (12..0x7FFFFFFF), 4 unused by the parser (meaning undetermined), then a zlib stream (`MPSP`) or, for
  `MPSZ`, a u32 that must be 10505 followed by one zstd frame. Errors are `n | 0x84990000` (1039 magic, 1040 length,
  1042 size, 1051 `MPSZ` revision, 1026 size or CRC, 1017 codec, 1019 record tag, 1004..1006 RMDX header).
- **Decoded stream:** `out_size` (u32), `crc` (u32), then chunks until `out_size` bytes exist: a u16 `L`; bit 15
  clear = literal of `L` bytes; bit 15 set = copy `(L & 0x7FFF) + 6` bytes from the expanded old file at a
  3-byte (or 4 if either size is at least 0x1000000) offset. The CRC is reflected CRC-32 (0xEDB88320), init
  0xFFFFFFFF, no final xor. Only copy and literal exist.
- **Applied to the expanded old VDM**, not the raw file: the old VDM (a PE whose resource id 1000 holds an `RMDX`
  blob; flags need `0x200002`, bit 4 = zstd) is expanded to 12-byte-header records (`C0C0C0C0` raw, `D1D1D1D1`
  deflate with the uncompressed payload, `D2D2D2D2` zstd), patched, and recompressed (deflate level 6, window 15, mem
  level 8, first two bytes dropped; zstd level unknown).
- **OBSERVED on the four real VDMs** (`mpavdlta`, `mpasdlta`, `mpavbase`, `mpasbase`): RMDX header, payload offset and
  stub CRC parse; inflated size equals header field 7; Adler-32 matches; **level-6 recompression is byte-identical**
  to the shipped payload (levels 4, 5, 7, 8, 9 are not); expand and rebuild round-trips to the identical file. All four
  use the deflate codec; no zstd VDM was seen.
- A decoder exists outside the repository (analysis scratch, not committed). Its MPSP header and chunk decoding has
  only been checked against a patch built by the same author from the same description (internal consistency, **not
  Microsoft validation**: no real MPSP patch was available).

#### Not established after 12.13

Whether `WD /q` reaches the stub when `AM_Delta.exe` is the spawner (command-line construction only); the pipe DACL
masks; the code creating the `%windir%\Temp\<GUID>...` working directory (ctor S 0x140042230); the xcopy fallback on
a guest, and the post-update step `sub_14002C3B8` and sense-client path; the meaning of MPSP header dword 3 and of
10505 in `MPSZ`; the zstd level for `D2` recompression; whether real MPSP patches target only the delta VDMs
(INFERRED: `mpengine.dll` has no RMDX resource, so MPSP is VDM-only); the mspatcha patch details; behaviour of any
stub version other than 1.1.24010.2001; any run with the three packages started from different parents.

### 12.14 `windows-mpsp`: VDM blob structure and remaining patch-format answers (2026-10-05)

Implemented in `crates/windows-mpsp` (README there holds the evidence table). Evidence labels as in 12.13.

- **WDExtract correction.** `hfiref0x/WDExtract` only inflates the RMDX payload, merges deltas and scans for PE images;
  it does not walk the signature records or extract Lua (OBSERVED by reading its source). The crate does more.
- **Blob framing (OBSERVED on all four real files).** The inflated payload is a flat chain of `type:u8, size:u24le,
  payload`, consuming every byte with no padding: `mpavbase` 3,428,348 records, `mpasbase` 6,026,858. The earlier
  reading of the first dwords as a 27,764-entry table was wrong: `74 6c 00 00` is a normal record header (type
  `0x74`, size 108).
- **Delta VDMs (OBSERVED).** Exactly two top-level records: `0x74` (`(type, count24)` pairs, per-type record count
  increases, informational) and `0x73` (`merged_size:u32`, `jamcrc:u32`, then commands). Commands: `u16 w`; bit 15
  set copies `(w & 0x7FFF) + 6` bytes from the inflated base at a `u32` offset, else `w` literal bytes. Applying
  `mpavdlta` to `mpavbase` gives 110,150,305 bytes and `mpasdlta` to `mpasbase` 287,217,200 bytes, each with matching
  JAMCRC (CRC-32 without the final xor), and the result is again a plain record chain. This is a second patch
  algorithm, distinct from MPSP, and it needs the base blob rather than the base file.
- **Records.** `0x5C`/`0x5D` bracket each threat (never nested; `0x5D` repeats the 4-byte id). `0x5C` payload:
  `id:u32`, three unknown `u16`, `namelen:u16` at offset 10, name, NUL, tail (unknown). About 40 percent of names
  start with a 2-byte coded prefix (second byte `0x21`; HYPOTHESIS: an abbreviated category prefix). `0xBD` is Lua:
  `namelen:u8, kind:u8, pre:u16, lualen:u32, name, pre, script`; scripts are plain standard Lua 5.1 bytecode (header
  `1B 4C 75 61 51 00 01 04 08 04 08 01`, `u32` string lengths); 370 of 370 in `mpavbase` and 64,843 of 64,846 in
  `mpasbase` parse to the exact record end. A few records (3 in `mpasbase`, 148 in merged `mpasdlta`, all in
  `...InfrastructureShared...` threats) look obfuscated: kept opaque. Unknown: `kind`, the `0x5C` `u16` fields and
  tail, types `0x28` and `0x80`, the coded name prefix mapping.
- **Remaining patch-format unknowns, now READ (stub 1.1.24010.2001).** Container dword at offset 12 is never read.
  `MPSZ` accepts only 10505 (hard-coded; 10403..10504 are logged as in range and still rejected with `0x8499041B`).
  The chunk stream has no other opcodes or header words; width rule confirmed from instructions; a zero-length
  literal is a no-op. D2 recompression is zstd level 3 with the pledged size set and no dictionary; the recorded
  size is a cap; the bundled zstd version is unknown. After `RecordsToVdm` the stub does not refresh the RMDX
  size/CRC block, check signatures or hashes, and deletes the output on any failure.
- **Deflate.** The stub's `D1` recompression is zlib level 6; a pure-Rust 1:1 port of zlib 1.3.2 deflate
  (`zlib_deflate.rs`) reproduces the shipped payloads byte for byte on all four real VDMs (largest payload 282,564,806
  bytes, 6.4 s) and C zlib on synthetic inputs. The pure-Rust `miniz` and `zlib-rs` backends do not.
- **Still unestablished:** D2 and MPSZ are unexercised (no sample); the mspatcha path is out of scope. The patch
  decoder's evidence is in the next subsection.

#### Real MPSP patches from the Microsoft CDN (OBSERVED 2026-10-05)

- **Source.** The WSUS catalog lists `AM_Delta_Patch_1.459.<n>.0.exe` (828 file rows, 276 distinct digests, 0.36 to
  0.9 MB). Package URLs are content addressed on the public CDN:
  `http://download.windowsupdate.com/c/msdownload/update/software/defu/<year>/<month>/<lowercased name>_<sha1>.exe`
  (the month is not in the metadata, so months are probed). 138 of the 276 were still served (all under 2026/10), each
  verified against its catalog SHA-1; the rest return 404 (expired or another path). Fetch script:
  `scripts/mpsp/fetch-defender-patches.py`.
- **Content.** Each package is a PE with a CAB holding `<from>_to_<to>_mpavdlta.vdm._p` and `..._mpasdlta.vdm._p`
  (for example `1.459.537.0_to_1.459.547.0`); the target is the current definition version, so patches from many older
  versions share the same target. 92 distinct patch files: all 92 begin `MPSP` (no `MPSZ`), and no patch exists for
  the base VDMs.
- **Header dword at offset 12 is the stub CRC of the payload bytes** (CRC-32, init 0xFFFFFFFF, no final xor): 92 of
  92. The stub does not read it (12.13).
- **End-to-end validation.** Applying `1.459.537.0_to_1.459.547.0_mpavdlta.vdm._p` and `..._mpasdlta.vdm._p` to the
  537 VDMs (from the full `AM_Delta.exe` of that version, downloaded the same way) produced files **byte-identical to
  the shipped 1.459.547.0 VDMs** (3,633,616 and 7,691,168 bytes), through container, chunk decode with the in-patch
  CRC, record expansion, and level-6 recompression. The same patches also applied to three different full `AM_Delta`
  packages that share the 537 VDMs; the 537-to-546 patches decoded and applied too (CRC verified, no reference file for
  546 to compare). Limits: one target pair, delta VDMs only, no `MPSZ`, no D2, no base VDM patch, and the stub's own
  application (version check, file replacement) was not run on a guest with these patches.
- **Consequence.** The earlier evidence limit (self-consistency only) is lifted for `MPSP` over `D1` records.

#### Wider patch coverage and the stub applying them on a guest (OBSERVED 2026-10-05)

- **More families.** The catalog also lists `AM_Slim_Delta_Patch`, `AS_Delta_Patch`, `AM_Base_Patch1`,
  `AM_Slim_Base_Patch1`, `AS_Base_Patch1`, `AM_Engine_Patch_*` and `AS_Engine_Patch_*`; all 715 distinct package digests
  were still served by the CDN (paths `c/` and `d/`, 2026/10 and earlier months; each verified against its SHA-1).
  1,170 patch files are `MPSP` (delta and base VDMs); the 32 engine patches (`mpengine.dll._p`) are `PA19`, the
  `mspatcha` path of the stub (12.13), not `MPSP`. No `MPSZ` and no zstd (`D2`) container exists in any of them, in
  any full VDM downloaded (Base, Delta, Slim, AS), or in the public full package `mpam-fe.exe` (1.459.557.0): the
  `MPSZ` and zstd code paths have no sample in the current public feed.
- **Host matrix.** All 1,170 patches parse and carry a payload CRC equal to ours. Applying each patch to every
  full VDM of the same family and kind that I hold: wherever a matching old VDM was held it applied (CRC verified) and
  the output was byte-identical to a held full VDM: `AM_Delta` 36 of 36 per kind (`mpavdlta`, `mpasdlta`),
  `AM_Slim_Delta` 36 of 36 per kind, `AS_Delta` 20 of 20, over several version pairs (for example 539 to 547, 540 to
  546, 537 to 547). The other combinations did not apply because no old file of that version was held (the apply
  fails on the CRC or a copy range, as designed).
- **Base patches.** All are `1.457.0.0_to_1.459.0.0` and every full base obtainable is 1.459.0.0, so none could be
  applied (the 1.457 base is not served). The 14 base patches parse exactly (chunk walk lands on the end of the
  stream) with 4-byte copy offsets as the width rule requires (outputs up to 282,578,449 bytes). That supports the
  width rule at parse level only; the base patch application is **not validated**.
- **Stub applying a real patch on a guest.** Guest `w11-ours`, Windows 11 25H2, packages SHA-1 verified, each run
  from one PowerShell parent with `WD /q` (the catalog command line). (1) After removing definitions, `AM_Engine`
  (1.1.26080.3), `AM_Base` (1.459.0.0) and `AM_Delta` (1.459.537.0) all exited 0 and the guest reported
  antivirus and antispyware definitions 1.459.537.0; the installed `mpavdlta.vdm` and `mpasdlta.vdm` equalled the
  VDMs inside the 537 package. (2) The catalog applicability rule for `AM_Delta_Patch_1.459.537.0` is
  `mpavdlta.vdm` in `SignatureLocation` exactly 1.459.537.0. Running the x64 `AM_Delta_Patch_1.459.537.0.exe WD /q`
  (407,968 bytes, the 537-to-547 variant) exited 0 in 8 s; the stub log shows `Patched mpasdlta.vdm to 1.459.547.0`,
  `Patched mpavdlta.vdm to 1.459.547.0`, `MpSigStub successfully updated ... using the AM BDD package` and
  `DeltaUpdateFailure` / `BddUpdateFailure` set to 0; definitions then read 1.459.547.0. (3) The new definition
  store's `mpavdlta.vdm` (sha1 `66ac0ebf0830977f5e98913592d729abc3e32f86`, 3,633,616 bytes) and `mpasdlta.vdm`
  (sha1 `79dc9b4460d43741cd91e70e34b3f7970f099e93`, 7,691,168 bytes) equal the shipped 1.459.547.0 VDMs, which are also
  what `windows-mpsp` produces from the same patches. So for these two patches the stub's own output and the
  crate's output agree byte for byte.
- **Not tested in that round:** `MPSZ`, zstd, base-VDM patches, a failing patch on the guest, other pairs, x86 and
  arm64, the `PA19` engine patches (all but base, zstd and arm64 were run in the next round).

#### Second guest round: failures, PA19 engine patches, MPSZ, x86 (OBSERVED 2026-10-05, same guest `w11-ours`)

- **Base patches without the old file.** `windows-mpsp check-target` checks a patch against the known target: the
  patch's output size and CRC equal the expanded 1.459.0.0 base (`mpavbase` 108,328,444 and `mpasbase` 282,578,449
  bytes), every literal chunk (79,053 and 344,376) equals the target bytes, the copy chunks (121,896 and 582,020) show
  no contradictions, and the implied old size is 107,879,957 and 277,522,147 bytes at least, with 4-byte offsets.
  Passes for `AM_Base` and `AM_Slim_Base` (the `AS_Base` patch is the same file). The old 1.457.0.0 base is not served, so
  no base patch was applied: this is consistency evidence, not application.
- **Wrong installed version.** Installed 1.459.547.0 and the 537 patch run: exit 0, `No products found to update`,
  definitions unchanged (the applicability rule is not met). Installed 537 and the x64 539-to-547 patch: exit
  `0x80070670`, log `No patch for 1.459.537.0; sequence is incorrect` and `BddUpdateFailure set to 0x1`, definitions
  unchanged. This matches the table in 12.12/12.13.
- **Corrupted patches** (repacked by hand, installed 537): a flipped byte in the zlib stream gives `0x849903f9`
  (`0x84990000 | 1017`, codec error); a wrong output CRC gives `0x8007000D`; wrong source bytes (539 patch under the 537
  name) give `0x8007000D`. Definitions stayed unchanged in each case and `windows-mpsp` rejects the same files.
  A rebuilt, unsigned package with the real patches applied normally and produced the shipped 547 hashes (one control run):
  the launcher and stub do not check the package signature or who built the CAB.
- **PA19 engine patches.** An engine patch package alone is not a terminal package (no `*` marker), so it waits and
  times out with `0x800705b4` exactly like a lone `AM_Engine`: it must be run together with a delta package from the
  same parent. Running the `1.1.26080.3 to 1.1.26090.9` and `1.1.26080.3 to 1.1.26100.3` engine patch packages each
  with the 537-to-547 delta patch gave `Patched mpengine.dll to ...` and installed `mpengine.dll` files whose SHA-1
  equal the shipped 26090.9 (`bd6246c9...`) and 26100.3 (`1060d80e...`) engines. This is the stub applying `PA19` via
  `mspatcha.dll`; the native PA19 decoder in `windows-delta` is validated separately.
- **`MPSZ` is not accepted by this stub (correction to 12.13).** Our `MPSZ` patches (zstd level 3) made the stub
  exit `0xc00e4102` through the `mspatcha` path with definitions unchanged. READ: `ApplyPatchDispatch` compares the
  first four bytes only with `MPSP`, and `MpspParseContainer` is only reachable from that dispatcher, so in
  1.1.24010.2001 the `MPSZ` parser is unreachable for patch files (it exists, probably for a later stub). D2 (zstd VDM)
  could not be tested: it would need a validly signed zstd VDM. The 10504 and corrupt-frame variants were not run
  because they hit the same dispatch.
- **x86 package on an x64 guest.** Exit `0x80070002`: the 32-bit launcher looks for `SysWOW64\MpSigStub.exe`, which
  does not exist. With a temporary copy of the stub in `SysWOW64` it applied the patch and produced the shipped 547
  hashes (copy removed afterwards; the lookup path is INFERRED from the failure). arm64 was not testable.
- **Crate bug found and fixed:** `ruzstd` 0.9.0 panics (`not implemented`) for `CompressionLevel::Default`; the
  crate now uses `Fastest`, so its zstd output is valid but not byte-identical to the stub's level 3.

### 12.15 Legacy PA19 patches in `windows-delta` (2026-10-05)

`windows_delta::pa19::{inspect_pa19, apply_pa19}` (decoder only; `--format pa19` on `inspect` and `apply`). The full
format description is the module documentation of `crates/windows-delta/src/pa19.rs`; this is the summary. Labels: READ =
decompilation of Windows Server 2025 26100.32230 `mspatcha.dll`, OBSERVED = measured on the real patches.

- **Where it occurs.** `MpSigStub.exe` hands every patch whose magic is not `MPSP` to `mspatcha.dll`
  `ApplyPatchToFileByHandles` (12.13); the real ones are the `mpengine.dll._p` files of the engine patch packages
  (`AM_Engine_Patch_*`, `AS_Engine_Patch_*`: 32 distinct, x86, x64 and arm64 builds).
- **Varints (READ).** The last byte of a number has bit 7 set (opposite of LEB128); `uvar` 7 bits per byte; `svar` has
  the sign in bit 6 and 6 data bits in the first byte; at most 5 bytes.
- **Container (READ).** `"PA19"`, `u32` flags (stored value XOR `0x00800000`; forbidden bits `0x3F00FFF8`), optional
  options, time, COFF and resource times, `uvar` new size, `u32` new CRC-32, optional window shift, `u8` source count; per
  source: `svar` size difference, `u32` CRC of the old file after normalization, ignore and retain ranges, a rift table
  (`uvar` pairs accumulating old and new RVA) and `uvar` stream size; the streams follow back to back and a `u32`
  trailer equals the complement of the CRC-32 of everything before it. OBSERVED: header plus stream sizes plus 4 equals
  the file length on all 32 patches, and all trailer CRCs verify.
- **Old-file normalization (READ).** PE32 sources only: COFF time and image base replaced, image rebased through the
  relocation table, bound imports removed, lock-prefix targets set to `F0`, checksum recomputed; ignore and retain
  ranges zeroed; a non-empty rift table then transforms the source (marks, relocations, imports, exports, `E9`/`0F 8x`
  jumps, `E8` calls, resources; passes can be disabled by option bits).
- **Stream (READ).** Exactly the chunked MS-PATCH LZX Delta the crate already decodes (`u16` chunk prefix, 32,768
  bytes per chunk, old file preloaded as history, first chunk with a 1-bit `E8` flag and 32-bit size); default window is
  the smallest power of two at least new size plus the old size rounded up to 32 KiB, minimum 128 KiB.
  `ms_compress::lzx::decompress_lzxd` is reused unchanged.
- **Validation (OBSERVED).** All 32 patches parse; six were applied and are **byte-identical (SHA-1) to the shipped
  targets**: x86 `1.1.26080.3` to `26090.9` and to `26100.3` (rift tables of 33 and 53 entries, so the normalization and
  transform passes are exercised), and the same two on x64 (one with `E8` translation on, one off) and on arm64. Two more
  (`26090.7` to `26090.9`, x86 and arm64) only hit the already-current shortcut because the held old file was the
  target; 24 could not be applied because their from-version engines (26060.3008, 26070.7, 26080.2, 26090.7, 26100.2)
  are not held. On the guest the real stub, running the same engine patch packages through `mspatcha.dll`, installed
  engines with the same SHA-1 as these shipped targets (12.14); the native decoder and the stub therefore agree.
- **Not validated or not supported.** Synthetic-only paths (ignore and retain ranges, multiple sources), option-driven
  pass disabling beyond `0x10`, explicit window shifts, the newer pass order (options `0x100`/`0x200`) and interleaved LZX
  groups (flag `0x40000000`; tables parsed, semantics unvalidated, no real patch uses them), and any PA19 creation.
  Looser or stricter than `mspatcha.dll`: malformed PE structures give an error instead of a read overrun, the trailer CRC
  is checked before applying, and table sizes are bounded.

#### PA19 completion: all option bits, interleave and creation, validated against the real Windows tools (OBSERVED 2026-10-05)

Supersedes the unvalidated and unsupported list of 12.15 above (same guest `w11-ours`; oracle files in the scratchpad).

- **Now decoded:** both rift transform pass orders (the newer order, options `0x100` or `0x200`, uses a different mark
  rule, imports, exports, a different resource walker, then relocations, jumps and calls; with `0x200` and no usable
  relocation directory an x86 image gets an absolute-pointer scan), every legal option bit (the six pass-disabling
  bits, `0x100`, `0x200`, explicit window shift), interleaved LZX groups (flag `0x40000000`: each group is an
  independent LZX decode whose history is a slice of the old file), and old-file preload when the old file is larger
  than the window.
- **Creation.** `create_pa19`, `create_pa19_with` (window order, interleave groups), `plan_interleave`, CLI
  `create --format pa19`. Single source, no ranges, no rift or PE normalization, fixed-tree encoder (larger than
  `mspatchc` output); the encoder never enables `E8` translation. PE-aware creation is not implemented.
- **Real `mspatchc.dll` creator to our decoder: 356 patches, all byte-identical to the new file.** Inputs: synthetic
  data, 20 x86 system DLL pairs from two builds, 16 MB x86 Defender engine pairs. Covered: both pass orders with every
  option bit, zeroed and unmapped relocation directories under `0x200`, LZX A, B and large, six flag variants, window
  shifts, ignore ranges, retain ranges, three old files, an identical old file, default and explicit interleave with 4
  to 63 groups and windows of 128 KiB to 8 MiB. Mutation checks: disabling the pointer scan makes 60 of them fail and
  forcing the legacy pass order makes 11 fail, so both paths are exercised.
- **Our `create_pa19` to real `mspatcha.dll`: 30 of 30 applied to the exact target**, including interleaved patches on
  16 MB files.
- **Fixtures.** 9 `mspatchc`-made patches of synthetic data (240 KB, no Microsoft files) are committed under
  `crates/windows-delta/tests/fixtures/pa19/`; real-engine and oracle cases stay env gated
  (`WINDOWS_DELTA_PA19_DIR`, `WINDOWS_DELTA_PA19_ORACLE`).
- **Still not validated or not implemented:** PE-aware creation, `E8` translation in created patches, PE32+ sources
  (the transform is PE32 only, as in `mspatcha.dll`), other `mspatchc.dll` builds.

#### PA19 creation completed: E8, PE32-aware, PE32+ (OBSERVED 2026-10-05)

Supersedes the creation limits listed in 12.15. Same guest and oracle method (real `mspatchc.dll` creator and real
`mspatcha.dll` applier).

- **E8 translation in created patches** (`Pa19E8`, CLI `--e8 off|on|auto`): the target is translated before encoding,
  the exact inverse of the decoder including its skip of the last ten bytes of each 32,768-byte chunk; `auto` builds
  both variants and keeps the smaller patch.
- **PE32-aware creation** (`Pa19Pe`, CLI `--pe`): the header carries the COFF fields and a rift table written as
  `mspatchc` writes them; the old image goes through the decoder's own normalization and transform code; the rift
  generator is this project's own (unique 8-byte anchors per section pair, a step wherever the shift changes); the
  smallest of the PE candidates and the raw candidate wins. Header time is written as 0 (accepted by `mspatcha`).
- **PE32+ (x64, arm64):** raw path. OBSERVED: `mspatchc` itself writes x64 patches with flags `0x440001`, no COFF
  fields, options 0 and no rift on all 70 x64 DLL pairs and 12 x64 and arm64 engine pairs; no other PE32+ treatment
  (checksum, timestamps) was found.
- **Our patches into the real `mspatcha`: 605 new patches byte-identical** (70 PE and E8 mode patches on x86 DLLs, 79 E8
  patches on code-like data with E8 operands at every offset from 14 bytes before to 2 after each chunk boundary, 420
  patches on 70 x86 and 70 x64 DLL pairs between two builds, 36 on 18 engine pairs of 16 to 19 MB). **`mspatchc` patches
  into our decoder: 158 new patches byte-identical** (x86, x64, arm64). Mutation check: writing the E8 flag without
  translating makes our round-trip verification reject every E8 patch.
- **Sizes** (auto mode vs raw; vs `mspatchc` output): 70 x86 DLL pairs 0.64 of raw (smaller in 64 of 70), about 2.9
  times larger than `mspatchc`; 70 x64 pairs 0.97 of raw (E8 helps), about 4.4 times larger; 18 engine pairs about 2.2
  to 2.4 times larger than `mspatchc` (PE path gains nothing over raw with E8 there). The fixed-tree LZX encoder, not
  the rift, accounts for most of the gap.
- **`mspatchc` E8 policy (OBSERVED, INFERRED as size-based trial):** off on 66 of 70 small x86 pairs; on, with call
  pass option `0x10`, for the 16 MB x86 engines and 4 small x86 pairs; on for x64 engines; none for arm64.
- **Not validated:** other `mspatchc.dll` builds; rift quality beyond these pairs (a poor rift only costs size).

#### Defender launcher packages: terminal marker, patch selection and the native agent (OBSERVED 2026-10-05)

- **Terminal marker table.** Scan of the 711 launcher packages downloaded from the CDN (every architecture) for the
  `BINARY/MPSIGSTUB` resource name: present on every `AM_Delta` (18), `AM_Delta_Patch_*` (276), `AM_Slim_Delta` (18),
  `AM_Slim_Delta_Patch_*` (276), `AS_Delta` (12) and `AS_Delta_Patch_*` (52) package; absent from every `*_Engine` (14),
  `*_Engine_Patch_*` (32), `*_Base` (8) and `*_Base_Patch*` (8) package. Only the former can end the stub's
  accumulation (12.13).
- **Catalog shape.** The bundle `a2fef9b0@200` (KB2267602 1.459.547.0, Broad) lists the stub, engine and bases
  children and, per source version and architecture, one "Full Deltas 1.459.547.0 (patch from X)" child (X in
  1.459.516.0 .. 1.459.543.0, for each of amd64, x86, arm64 and the Slim line), plus the plain "Full Deltas
  1.459.547.0" child for sources that have no patch (for example 546). A patch child's `IsInstalled` is
  `SignatureType != 1` and both delta VDMs at least the target version and `DeltaUpdateFailure` below 1; its
  applicability is the exact source version of `mpavdlta.vdm` in `SignatureLocation`.
- **Native selection equals the plan.** At installed deltas 537, 543 and 546 the native WUA, searching the real lab WSUS
  and downloading, fetched exactly one file, the same one this client's plan selects (407,968 B patch, 346,528 B patch,
  11,606,440 B full delta); at 547 it offers nothing of the bundle. Details and hashes: wsus-install.md, round 2.
- **Engine patches are ring and age gated.** The `IsInstallable` of "AM Engine 1.1.26100.3 (patch from 1.1.26080.3)
  ... Ring0" requires `HKLM\SOFTWARE\Microsoft\Windows Defender\MpEngine\MpEngineRing` to exist and equal 0, both delta
  VDMs below 1.459.514.0, the engine at exactly the patch source version and `DisableGradualRelease`,
  `DisableEnginePatch` and `DeltaUpdateFailure` unset; so at the 537 to 547 delta states these patches evaluate not
  installable, which is why only the bundle's delta child is selected.
- **The real definition store is protected.** Even SYSTEM cannot write or take ownership of the files in
  `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\` on the guest (access denied).
  `SignatureLocation` itself is writable, so a copy of the directory can be substituted to inject a stub failure.

### 12.16 Windows Installer updates on the wire and the MSI handler (OBSERVED 2026-10-05)

No update in the synced Microsoft catalog uses a Windows Installer handler (4,395 stored fragments: only
`CommandLineInstallation` and `Category`), so the shape was obtained by publishing `.msi` files (wixl-built, product
codes `{A1B2C3D4-0001-4000-8000-000000000100}` and others) on the lab's real WSUS (Windows Server 2025, 10.0.26100.32230)
through the administration API (`SoftwareDistributionPackage.PopulatePackageFromWindowsInstaller`, `IPublisher.PublishPackage`
after `SetSigningCertificate` with a self-signed code-signing certificate, approval for All Computers) and reading what
this project's client received over `SyncUpdates` and `GetExtendedUpdateInfo`.

- **Core fragment.** `UpdateType="Software"`, prerequisites are two category clauses, and
  `<ApplicabilityRules><IsInstalled><m.MsiApplicationInstalled /></IsInstalled><IsSuperseded><m.MsiApplicationSuperseded /></IsSuperseded><IsInstallable><m.MsiApplicationInstallable /></IsInstallable><Metadata><m.MsiApplicationMetadata><m.ProductCode>{GUID}</m.ProductCode></m.MsiApplicationMetadata></Metadata></ApplicabilityRules>`
  (lower-case GUID as written by the API). The three operators carry no attributes: the product is named by the update's own
  `Metadata`. The evaluator now resolves `MsiApplicationInstalled` to the product being installed
  (`MsiProductInstalled`, no version bounds) and `MsiApplicationInstallable` to its negation; `MsiApplicationSuperseded` stays
  unsupported.
- **Extended fragment.** `ExtendedProperties ... IsLocallyPublished="true" Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsInstaller" CanSourceBeRequired="false"`
  with `InstallationBehavior` and `UninstallationBehavior` (`RebootBehavior="CanRequestReboot"` by default), one file
  `<update-guid>_<n>.cab` (SHA-1 and SHA-256 digests, signed with the WSUS signing certificate) and
  `<HandlerSpecificData type="msp:WindowsInstallerApp"><MsiData ProductCode="{...}" MsiFile="name.msi"><RepairPath RelativeToServer="true" Path="<update>\<guid>" /></MsiData></HandlerSpecificData>`.
  The payload is a CAB wrapping `MsiFile`. The published schema (`WindowsInstaller`) also defines `MsiData/@CommandLine`,
  `@UninstallCommandLine`, `@MediaPackagePath` and, for patches, `MspData` with `PatchCode`, `FullFilePatchCode`,
  `CommandLine`, `TargetsSystemMsi`; the patch form was not observed (no MSP could be built).
- **Supersedence.** Republishing the upgrade (`1.1.0.0`) with `SupersededPackages` created revision 2 and made the server
  list the older update as superseded; this project's client then skipped the older update in the plan once the upgrade was
  installed (the rule fired for the first time on real data). The native agent still listed the superseded older update as
  offered (`IsInstalled=0`), so the two differ here; installing it would fail with 1638 (another version is installed),
  which is the case supersedence normally prevents.
- **Metadata propagation.** A newly published update appeared in the client's sync only after the server regenerated its
  client cache (a few minutes in this lab, with revisions replaced in place for republished updates).
- **Client results** (guest Windows 11 25H2 10.0.26200, SYSTEM, `wsus.exe` with `msi-handler`, state under a private
  `C:\ProgramData` directory because the store gate refuses a directory writable by everyone): `1.0.0.0` install
  `succeeded` (`msiexec /i`, exit 0; `MsiQueryProductState` 5, marker file present, registry value in the 32-bit view),
  re-run `no_action`; upgrade `1.1.0.0` `succeeded` (exit 0, old product removed: state -1, new product 5, version
  `1.1.0.0`); an MSI whose launch condition is false exited 1603 and was `failed` with the product absent; an MSI with a
  `ScheduleReboot` action exited 3010 and was `reboot_required` with the product installed (state 5); a payload altered on
  the server was refused at download (`Sha1 digest mismatch; partial object discarded`, nothing executed); a payload altered
  in the client store was re-fetched and verified before use.
- **Native comparison.** A `Microsoft.Update.Session` search on the same guest against the same WSUS reported the two
  installed products as installed (`1.1.0.0`, reboot test) and offered the not-installed ones (`1.0.0.0` superseded,
  launch-condition test): the same IsInstalled and IsInstallable verdicts as this project's evaluator for all four
  updates. Only the supersedence skip differs (above).
- **Not established:** MSP updates and their wire shape, exit codes 1620 and 1641, `CommandLine` properties on a real
  update, uninstall, `MsiApplicationSuperseded`, MSI updates served by this project's own server.

#### 12.16 addendum: MSP updates, exit codes, properties, our own server (OBSERVED 2026-10-05)

Same lab (real WSUS 10.0.26100.32230, guest Windows 11 25H2 as SYSTEM, `wsus.exe` built with `msi-handler`).

- **MSP updates on the wire.** A real `.msp` was built with WiX 3.11 (`candle`, `light`, `torch`, `pyro`; base and
  updated `.msi` of one product, `PatchFamily`, `AllowRemoval="yes"`) and published with
  `SoftwareDistributionPackage.PopulatePackageFromWindowsInstallerPatch` (`PopulatePackageFromWindowsInstaller`
  accepts only `.msi`: `GetMsiInfo` fails on an `.msp`). The update's Core fragment has
  `IsInstalled`/`IsSuperseded`/`IsInstallable` = `m.MsiPatchInstalled`/`m.MsiPatchSuperseded`/`m.MsiPatchInstallable`
  (no attributes) and `Metadata/m.MsiPatchMetadata/MsiPatch` in the **default namespace**
  `http://www.microsoft.com/msi/patch_applicability.xsd` (`xmlns` declared on `MsiPatch`, after its other
  attributes): `PatchGUID`, `MinMsiVersion`, one `TargetProduct` per target (`TargetProductCode`, `TargetVersion` with
  `Validate`, `ComparisonType`, `ComparisonFilter`, `TargetLanguage`, `UpdatedLanguages`, `UpgradeCode`), the flat
  `TargetProductCode` list and `SequenceData` (`PatchFamily`, `Sequence`, `Attributes`). The Extended fragment has the
  same WindowsInstaller `Handler` URI, a `File` named `<msp base>.cab` with `PatchingType="SelfContained"` and
  `HandlerSpecificData type="msp:WindowsInstaller"` holding `<MspData FullFilePatchCode="{...}"><RepairPath .../></MspData>`:
  **no `PatchCode` attribute and no member name** (the code is `FullFilePatchCode`, the patch is the single `.msp` in the
  cabinet). The SDP form is `msp:MspInstallerData FullFilePatchCode` with `msp:MspFileName`.
- **MSP install on the guest.** The base `.msi` (update `7ba3bd14...`) installed through the handler (exit 0, state 5), the
  plan for the patch was `nothing_to_do_not_applicable` while the target product was absent and `install` (one `msi`
  step, kind `msp`) once it was installed; `msiexec /update` exit 0, the patched file content, the patch registered under
  the product's `UserData\S-1-5-18\Products\<packed>\Patches` key, the post-check converged (`MsiEnumPatchesEx`
  fact), a re-run `no_action`. `msiexec /uninstall <patch> /package <product>` exit 0 restored the original content and
  the patch became applicable again. Evaluator decisions (this project's, Unverified against a native agent):
  Installed is "applied to a target product", Installable is "target product installed within its `TargetVersion`
  bounds and not patched", Superseded stays unsupported.
- **Exit codes seen through the handler.** 1620 (a truncated `.msi`, `ERROR_INSTALL_PACKAGE_INVALID`): `failed`, product
  absent; the captured console text is UTF-16LE (now decoded in the job record). 1604 (`ERROR_INSTALL_SUSPEND`): a package
  whose `ForceReboot` action runs under `/norestart` (the handler's switch) exits 1604 with product state 2 and
  stays so after a reboot that has no interactive logon (the continuation is a `RunOnce` entry that runs at logon, and a
  manual run of it returned 1605): the handler reports `failed`. A `ForceReboot` sequenced after `InstallFinalize`
  exits 1603 (`Error 2762`) yet leaves the product installed. 3010: `ScheduleReboot` (earlier run).
- **1641 is not reachable through the handler.** `/norestart` turns every reboot request into 3010. 1641 was observed
  directly: `msiexec /i <package with ScheduleReboot> /qn /forcerestart` returned 1641 (`MainEngineThread is returning
  1641`, Windows Installer event 1005) and the guest restarted. After a deliberate reboot the job record of the
  earlier run was byte-identical (same SHA-1).
- **Uninstall.** The client has no uninstall action (docs/wsus-install.md lists it as out of scope). With `msiexec /x`
  directly: a plain package exit 0 and state -1; a package with an unconditional `ScheduleReboot` exit 3010 with the
  product **removed** (state -1; this corrects the earlier note that it stayed installed).
- **`CommandLine` properties.** `CommandLine="LABVALUE="hello world" INSTALLDIR="C:\ProgramData\... Custom""` (set with
  the SDK's `InstallCommandLine`) arrives as `MsiData/@CommandLine` (XML-escaped quotes). Passed as `"NAME=a b"` tokens
  (what `std::process::Command` builds) `msiexec.exe` hung as SYSTEM (usage dialog, never exits, 40 s timeout in the direct
  repro); the handler now builds the line as `NAME="a b"` (quotes doubled inside values) and the properties were honored
  (registry `LabValue`, files under the custom directory, default directory untouched).
- **Our server serves the same updates.** A second server (`wsus admin sync start --content all` from the real WSUS with the
  custom product and Application classification filters, approvals set locally) handed the guest the same 10
  updates: Core and Extended fragments are identical after normalizing `" />` to `"/>` once the `MsiPatch` namespace
  declaration is kept (it was dropped by the fragment flattening before this change; the fix keeps `xmlns` for the
  patch_applicability namespace). Installs from our server: patch exit 0 and converged, properties MSI exit 0 with the
  properties honored, corrupt MSI 1620 `failed`; the install plan hashes equal the real-WSUS ones.
- **Incidental finding.** With the real WSUS's catalog grown by a concurrent Windows 11 product sync, the unfiltered
  client sync failed on a 39,256,409-byte metadata body (limit 33,554,432); `[client] filter_categories` restricted it to
  the test product and the run proceeded.

### 12.17 Windows servicing metadata: the Cbs and OSInstaller handlers (OBSERVED 2026-10-05)

Source: the lab WSUS (Windows Server 2025 10.0.26100.32230) was given the `Windows 11` product
(`72e7624a-5b00-45d2-b92f-e561c0a6a160`) on top of its Defender and Office subscription (the existing categories were
kept; the subscription already listed the classifications Critical Updates, Definition Updates, Security Updates and
Updates and the language `en`), metadata only (nothing approved, no content downloaded). The product stays subscribed on
that server. The sync of 1,572 updates took 976 s and raised the server's update count from 4,088
to 4,543. This project's client then synced it: 406 `SyncUpdates` pages, 5,253 revisions stored (5,077 visible), 1,094
Extended fragments, 65 s. Real fragments and counts are in `docs/fixtures/wsus-m0-cbs/` (README and
`catalog-stats.json`); the statistics below are over the stored catalog.

- **Revisions.** 3,433 leaf and 277 non-leaf detectoids, 448 categories, and 1,094 software updates with an Extended
  fragment: 561 deployment action `Bundle`, 441 `PreDeploymentCheck` (a deployment action not seen before), 92 `Install`.
  `Prerequisites` appear in 5,143 revisions, `SupersededUpdates` in 633 (16,664 edges), `BundledUpdates` in 525.
- **Handlers.** `Handler` URIs in the 1,094 Extended fragments: `OSInstaller`
  (`http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller`) 297, `Cbs`
  (`.../2002/12/UpdateHandlers/Cbs`) 180, `CommandLineInstallation` 84 (the Defender updates), `WindowsInstaller` 8 (the
  published test MSIs of 12.16). Bundles with `BundledUpdates` hold children of one handler each: 297 bundles hold
  `OSInstaller` children, 144 hold `Cbs` children and 84 hold `CommandLineInstallation` children.
- **`Cbs`.** One `.cab` per update (SelfContained, for example 507 MB for one arm64 update),
  `InstallationBehavior RebootBehavior="CanRequestReboot"` on all 180, `CompatibleProtocolVersion` on 138 and
  `UninstallationBehavior` on at least some,
  `<HandlerSpecificData type="cbs:Cbs"><CbsData PackageIdentity="" /></HandlerSpecificData>` with the
  `PackageIdentity` EMPTY on all 180. The package is named only by the Core fragment: `IsInstalled` is
  `<CbsPackageInstalled />` (no attributes), `IsInstallable` is `<CbsPackageInstallable />`, and
  `Metadata/CbsPackageApplicabilityMetadata` holds the complete CBS package manifest
  (`assembly`/`assemblyIdentity name version processorArchitecture language publicKeyToken`, `package identifier
  releaseType restart`, `parent ... disposition="detect"` with `revisionCompare`/`buildCompare`, `update`,
  `component`, `installerAssembly` and so on). A manifest is up to 47 MB (Core XML median 167 KB for CBS updates, 10 of
  all 5,252 Core documents exceed 32 MiB, the total is 1,184 MB). Families: `Package_for_RollupFix` (the monthly cumulative
  update, `releaseType="Security Update"`) and `Package_for_DotNetRollup_*`; arm64 and amd64 only in this catalog. Some
  rules add a registry term, for example `IsInstalled` = `CbsPackageInstalled` AND NOT `RegDword
  ...\Component Based Servicing\LCUReoffer = 1`.
- **`OSInstaller`.** `ExtendedProperties ProductName ReleaseVersion ReleaseRevision` (`Client.OS.RS2.AMD64/ARM64` for
  Windows 11 monthly updates, `Microsoft.NetFX.amd64/arm64`; 151 distinct release versions up to
  `2400.28000.9347.1`), `<HandlerSpecificData type="OSInstallerMetadata"><OSInstallData InitialModule="UpdateAgent.dll"
  /></HandlerSpecificData>`, several files per update (`.cab` 2,114, `.wim` 854, `.psf` 698, `.msu` 173 declarations;
  `PatchingType="SelfContained"` on all, `PatchingTypePreferred` `Metadata` 297 and `ServicingStack` 231; the largest
  total `MaxDownloadSize` is 14.8 GB, median 9.6 GB). Rules: `IsInstalled` = `ProductReleaseInstalled Name Version`;
  `IsInstallable` = `DeviceAttribute` terms on `OSSkuId`, `sku` (both are written, with the same values) and
  `OSVersion` (`GreaterThanOrEqualTo` the lower and `LessThan` the upper build), for example `10.0.22621.1` to
  `10.0.22622.0`.
- **`DeviceAttribute`** (2,459 uses): `OSSkuId` 747, `sku` 747, `OSVersion` 604, `ProductType` 198 (values `WinNT`,
  `ServerNT`, `LanmanNT`), `DL_OSVersion` 88, `IsRemoteDesktopSessionHost` 66, `CurrentBranch` 9 (`br_release`);
  comparisons `EqualTo` 1,767, `GreaterThanOrEqualTo` 447, `LessThan` 245; `Type` is `String` or `Version`.
- **Real wire facts.** `GetExtendedUpdateInfo` answered for the unapproved updates; `GetFileLocations` answered for the file
  of a CBS update with `http://<server>/Content/<last two hex digits of the SHA-1>/<SHA-1>.cab`, which returned `404`
  because the server had never downloaded that content (it only holds approved, downloaded files). A WSUSSS
  `GetUpdateData` request for 100 revisions returned 80 (a 2.6 MB response) and the downstream sync must ask for the
  rest again. The WSUSSS answer carries the Microsoft Update URL of each file (`http://download.windowsupdate.com/c/
  msdownload/update/software/secu/2022/08/windows10.0-kb5016629-arm64_<sha1>.cab`; the same CDN scheme as 12.14).
- **What the client now does with it.** The `Cbs` and `OSInstaller` handlers are read (`install/handlers/cbs.rs`) and
  planned with their payload but never executed: the plan names `planned handler cbs, not executable by this client`
  and the executor refuses the run before it runs or modifies anything. In the evaluator `CbsPackageInstalled` is
  resolved (parse-time, Implementation decision, Unverified against a native agent) to `CbsPackageInstalledByIdentity`
  of the identity `name~publicKeyToken~processorArchitecture~language~version` read from the manifest (language
  `neutral` is the empty field, the format of the 59 identities of the Defender and Office catalog);
  `CbsPackageInstallable` stays unsupported (it needs the component store); `DeviceAttribute` decides `OSVersion` and
  `DL_OSVersion` from the OS major, minor and build (equal builds are Unknown because the revision is not a fact) and
  `ProductType` from the product type (`WinNT` 1, `LanmanNT` 2, `ServerNT` 3: Unverified), every other attribute
  (`OSSkuId`, `sku`, `IsRemoteDesktopSessionHost`, `CurrentBranch`) is Unknown (no fact source);
  `ProductReleaseInstalled` and `ProductReleaseVersion` stay unsupported. Scan of all 1,094 software revisions against
  the recorded Windows 11 25H2 facts: before 492 not applicable and 602 unknown, after 699 not applicable and 395
  unknown (remaining blockers: `ProductReleaseVersion` 387, `OSSkuId`/`sku` 90 each, `ProductReleaseInstalled` 90, equal-build
  `OSVersion` 38).
- **Limits found and fixed (OBSERVED failures of the previous defaults).** A Windows 11 `SyncUpdates` page decodes to about
  51 MB, so the 32 MiB response and XML caps rejected a real catalog (now 256 MiB, configurable
  `[client] max_response_bytes`); one Core document is 47 MB, so the 32 MiB document cap failed `scan` (the index now keeps
  only the identity, the package attributes and a count of the dropped descendants of each manifest, in memory only;
  the stored fragment is unchanged); the downstream client's 16 MiB cap on one decompressed metadata blob became 256 MiB;
  the server's own stored-document parsing uses the same larger bound; and the downstream sync treated a short
  `GetUpdateData` answer as fatal and now re-requests the missing revisions (it still fails when a batch returns
  nothing).
- **Numbers (this host, one run each).** Client `sync` of the whole catalog 65 s wall (68.7 s through the recording proxy),
  peak 2.8 GB resident; state on disk 1.3 GB in 5,253 files; `inspect` 29 s; `scan --all` 21 s with 3.7 GB resident (the
  whole catalog is held in memory). Downstream sync into this project's server (`wsus admin sync start`, filter =
  the Windows 11 product with the Security, Critical and Updates classifications): 75.6 s, 701 MB resident, a 1.2 GB
  SQLite file, 5,249 revisions listed and fetched, 183 excluded by the filter and 183 pulled back in as dependencies, 54
  withdrawn, generation activated. Serving those updates to a client through this project's server was not examined
  (two test approvals did not make them visible to a freshly registered client; resolved in the addendum below).
- **Not established.** What a native agent does with `Cbs` and `OSInstaller` updates; the meaning of
  `PreDeploymentCheck`; the semantics of `CbsPackageInstallable`, `ProductReleaseInstalled` and `ProductReleaseVersion`;
  the source of the OS SKU for `OSSkuId`/`sku`; how a servicing engine would install these packages; any `Cbs` metadata
  for x86 or for Windows Server products; the content (the CAB, PSF and WIM files were not downloaded).

#### 12.17 addendum: why two approvals seemed invisible, and what the real WSUS delivers unapproved (OBSERVED and INFERRED 2026-10-05)

- **The earlier "approvals not visible" result was a test-setup error, not a server defect (INFERRED from two pieces of
  evidence, REPRODUCED the other way).** The lab run's own server log ends with `cannot bind 127.0.0.1:18541: Address
  already in use`, and port 18541 is the port another lab run used for its own server (the MSI work), so the client
  most likely talked to that other server (its `client sync` returned 444 revisions, none of them the approved
  updates). The exact scenario was then repeated on a fresh instance of this project's server (its own port, a fresh
  downstream sync of the same real Windows 11 catalog: 5,249 revisions, 1.2 GB): the two approvals the lab run used
  (`f1ff1e3d-dd47-4fcb-9405-8f7275ce1ea6@200` and `f97b86e6-5c6c-4366-b948-b5426295a5a7@100`, group `Unassigned
  Computers`, by `UUID@REVISION`) made a freshly registered client receive both updates with deployment action
  `Install`, `IsLeaf` true, their Extended fragments (1 and 14 files) and 11 prerequisite revisions (categories and
  detectoids, `Evaluate`, non-leaf), 13 revisions in 5 pages. Two approvals for `All Computers` gave the same.
- **Every approved Windows 11 software update is delivered.** All 924 present Software updates of that catalog were
  approved for `Unassigned Computers`; a fresh client received 968 revisions (924 Software, each with its Extended
  fragment, plus 44 prerequisite and category revisions) in 35 `SyncUpdates` pages and 646 s. The 48 withdrawn Software
  revisions are not offered (by design: `scope::compute` keeps only `Present` revisions), and the 43 bundle edges that
  point at withdrawn children are dropped with them. No approved update was missing.
- **Cost at that scale (OBSERVED, one host).** With all 924 approved, `SyncUpdates` took 4.5 s at the minimum, 6.7 s
  median and 19.6 s at the maximum, and `GetExtendedUpdateInfo` 4.3 to 12.2 s (median 5.4 s), because every call loads
  the stored documents of the whole scope (about 1.2 GB; one Core document is up to 47 MB). Two approvals cost
  milliseconds. Not a visibility problem; a request that approves a whole Windows catalog is slow.
- **The real WSUS does not restrict delivery to approved updates; this server does (OBSERVED difference).** The lab WSUS
  had nothing approved for Windows 11, yet delivered to this project's client all 1,094 software revisions of the
  catalog, with these deployment actions (counted over the 5,252 stored revisions): `Bundle` on 561 (297 `OSInstaller`
  children, 180 `Cbs` children, 84 `CommandLineInstallation` children), `PreDeploymentCheck` on 441 and `Install` on
  92. The 441 `PreDeploymentCheck` revisions are exactly the bundle parents of the Windows children (297 `OSInstaller`
  parents plus 144 `Cbs` parents), all unapproved, and the 84 Defender bundle parents and 8 test MSIs are `Install`
  (approved). So: an unapproved Software update that is a bundle parent is delivered as `PreDeploymentCheck`, its
  members as `Bundle`, everything else metadata-only as `Evaluate`, and approved updates as `Install`. This explains
  the earlier unexplained `PreDeploymentCheck` (3 of 159 in the first capture). Whether the real WSUS also delivers
  unapproved updates that are not part of any bundle is not shown (every Software update in this catalog is bundled), and
  whether the 84 Defender parents were approved by hand or by an automatic approval rule is not known.
  This server instead offers an update only when it is approved for the computer or is a prerequisite, category or
  bundle member of an approved update (`scope::compute`, `closure`), and never emits `PreDeploymentCheck`. That is an
  Implementation decision, now pinned by `crates/wsus-server/tests/endpoints_windows_shape.rs` (Windows-shaped
  catalogs in both delivery modes, a real Core fragment from `docs/fixtures/wsus-m0-cbs`). Matching the real server
  would mean delivering every non-declined update, which changes what a native agent scans and reports; it is a
  decision for the owner, not made here.

### 12.18 Online servicing of CBS packages through DISM (OBSERVED 2026-10-05, one guest)

Guest: Windows 11 Pro 25H2 10.0.26200.8037, DISM 10.0.26100.5074 (servicing stack 10.0.26100.8035), SYSTEM,
`wsus.exe` with the `cbs-handler` feature talking to this project's server (catalog import of synthetic `Cbs` updates
whose payloads are real Microsoft cabs from the Windows 11 25H2 media `sources\sxs`). Fixtures:
`docs/fixtures/wsus-m0-cbs/dism-online-get-packages.txt`, `dism-online-get-packageinfo-ie-optional.txt`.

- **No real catalog `Cbs` update fits the guest.** Scanning the 180 real `Cbs` updates of 12.17 against the guest's facts,
  even with `CbsPackageInstallable` treated as True, gave `not_applicable` for all 180 (they are 2021 to 2022 .NET Framework
  rollups; every one has `IsInstallable` exactly `<CbsPackageInstallable />`). The real packages used instead come from
  the media; the metadata around them is synthetic.
- **`dism /English /Online /Get-Packages /Format:List`:** 142 packages on the guest, states `Installed` and `Staged`,
  exit 0; the strict parser of `windows-dism` reads it.
- **`dism /English /Online /Get-PackageInfo /PackagePath:<cab>`** prints, after the package block (`Package Identity`,
  `Applicable : Yes|No`, `State : Not Present|Installed`, `Restart Required`), a `Custom Properties:` list and a
  `Features listing for package` with `State` lines of their own. The offline parser `windows_dism::
  parse_package_applicability` rejects that output as an ambiguous `State` (OBSERVED: the first live run failed closed
  with `ambiguous package State` and installed nothing); this client reads the block before those sections itself. For a
  package that is not installed the reported state is `Not Present`; an installed one reports `Install Time`.
- **State values.** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\<identity>`:
  no key while the package is absent; `CurrentState 0x70` (112) when DISM lists it `Installed`; `0x40` (64) after an install
  was killed (DISM lists it absent then). The CBS keys are protected: even an administrator could not create
  `...\RebootPending`.
- **`/Add-Package` on a multi-lingual optional package fails:** the Internet Explorer mode optional package
  (`Microsoft-Windows-InternetExplorer-Optional-Package`, `Release Type : OnDemand Pack`, `Applicable : Yes`, `State : Not
  Present`) gave `0x800f0955`; CBS.log says `Multi-lingual package can only be installed from UUP respository ...
  CBS_E_INVALID_PACKAGE_REQUEST_ON_MULTILINGUAL_FOD`. Such packages are installed as capabilities, not with `/Add-Package`.
- **`.NET Framework 3.5` on-demand package** (`Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~~
  10.0.26100.1`, 71 MB, `Restart Required : Possible`): `/Disable-Feature /FeatureName:NetFx3 /Remove` removes it (absent, no
  pending state); `/Add-Package` then needs the feature content, which CBS acquires through Windows Update
  (`FCAcquirerWUClient: WULib DownloadProgress`). With the guest's WSUS policy (`UseWUServer = 1`, the lab WSUS has no such
  content) DISM sat at `75 / 100` for more than ten minutes; with `UseWUServer = 0` (direct Microsoft Update) the add
  completed in under 10 minutes (14:00:16 to 14:10:02, including the 71 MB download from this project's server): exit 0, listing
  `Installed`, `CurrentState 0x70`, no pending indicator.
- **Killing DISM mid-install is harmful:** `Stop-Process` on the stuck `dism.exe` returned exit `0xffffffff`, left
  `CurrentState 0x40`, set `CBS RebootPending`, DISM still listed the package absent; after a reboot the transaction
  had completed (`Installed`, `0x70`). That is why the client never kills DISM on timeout.
- **A timed-out call is not an error:** with `--timeout-secs 20` DISM ran on to completion by itself (`Installed` later,
  `RebootPending` cleared without a reboot). A package listing requested while the add is still running BLOCKS until it
  finishes (the post-run listing delayed the client's return by about 7.5 minutes before the client was changed to skip it).
- **Gates observed:** a pending-restart indicator (`PendingFileRenameOperations`, set by hand) refused the run before any
  DISM add; the CBS state `0x40` made the plan undecidable (`CbsPackageInstalledByIdentity: package state 64 is not the
  installed state; meaning of other states is unverified`); altered server content was refused at download.
- **Not observed:** a servicing stack update, a cumulative update, a `.msu`/`wusa` install, the DISM API, `0x800f081e`
  from `/Add-Package`, a package that reports `Install Pending`, a reboot barrier run, a real WSUS or native agent
  installing the same update.

### 12.19 What a real WSUS delivers to a fresh client, and `delivery_scope = "all_non_declined"` (OBSERVED and INFERRED 2026-10-05)

Source: a fresh client of this project (3 runs, one per proxy; computer id new, group `Unassigned Computers`) against the lab WSUS
(Windows Server 2025 10.0.26100.32230, Defender, Office and Windows 11 subscribed), read only through a logging proxy
(the proxy forwards unchanged except `Accept-Encoding`, so bodies were plain XML; nothing on the WSUS was approved,
declined or changed), plus the WSUS administration API (`GetUpdates`, read only) for the update states, plus a native
Windows Update Agent on the lab guest. Evidence stays local (`/dev/shm`, 50 MB logs, not committed); the scripts that produced the
numbers are `logproxy*.py`, `replay.py`, `cmp.py` in the session scratchpad.

- **What arrived (OBSERVED, run 1: 697 `SyncUpdates`, 5,225 revisions; runs 2 and 3 the same set).** 3,404 leaf and 277 non-leaf
  detectoids, 199 leaf and 249 non-leaf categories, 1,096 software revisions (561 bundle members, 441 unapproved bundle parents, 84
  approved Defender bundles, 10 approved standalone). Nothing was approved for Windows 11. The administration API lists 4,546
  updates of which **3,982 are declined (0 of them arrived)** and 564 are not declined; 535 of the 564 arrived as software
  updates, 561 more software revisions arrived as bundle members that the API does not list, 29 non-declined updates did not
  arrive (consistent with the staged prerequisite rule: their prerequisites were never reported installed, INFERRED), 430 of the
  564 are superseded and **arrived** (supersession does not suppress delivery; `SupersedenceBehavior` is 0 everywhere).
- **`Deployment` mapping (OBSERVED).** Every `UpdateInfo` has a `Deployment` with exactly `ID`, `Action`, `IsAssigned` (always `true`),
  `LastChangeTime` (date only), `AutoSelect`, `AutoDownload`, `SupersedenceBehavior` (all three `0` for every action); no `Deadline`, no
  flags, no `DownloadPriority`. `Action`: detectoids and categories `Evaluate` (4,129, leaf or non-leaf, whatever the approvals);
  software that is a member of any bundle `Bundle` (561, also when it is itself a parent: 28 in another catalog); software
  that is a bundle parent and not a member: `Install` when approved (84), `PreDeploymentCheck` when not (441: 297 `OSInstaller`
  and 144 `Cbs`); standalone software that is neither parent nor member: `Install` when approved (the 10 lab test updates); an
  unapproved standalone software update was not seen in any real catalog (the same action `PreDeploymentCheck` is **INFERRED**).
  The same mapping held in three other stored real catalogs (client-run, run5, run6: 6, 13 and 3,808 unapproved parents, all
  `PreDeploymentCheck`; 632, 945 and 3,836 members, all `Bundle`, among them 8 whose parent was outside the stored subset). `IsLeaf`
  follows the existing rule. `Deployment/ID` is a separate id space from the revision id (for example revision 108230 had
  deployment 8067; no deployment id equals its revision id), and `LastChangeTime` is a per-revision date (2026-10-04 for the
  revisions imported on the first sync day, 2026-10-05 for the Windows 11 ones), not the date of the last configuration change.
- **Staged rule (OBSERVED).** In all 5,225 deliveries every prerequisite clause of the revision was satisfied by an id in the
  request's `InstalledNonLeafUpdateIDs` (0 violations; also 0 against the ids delivered in earlier pages). The client caps that
  list at 400 (it reached 400 at call 200 and stayed there for the remaining 490 or so calls; `OtherCachedUpdateIDs` reached 4,679).
- **Paging and order (OBSERVED, not reproducible).** 696 of 697 responses had `Truncated` true. 658 carried fewer than 30
  `UpdateInfo` (415 carried exactly one), 39 carried 30; 35 carried `OutOfScopeRevisionIDs` (146 ids in total). The order inside
  a page is neither by revision id, deployment id, update id, nor leaf first. **The real server delivers far fewer revisions per
  call than the staged rule allows:** 3,632 of 5,225 revisions arrived at least 10 calls after their clauses were first
  satisfied, and at call 300 there were 488 satisfiable not-cached revisions while 1 arrived. The selection rule behind this
  throttling is not established; sets per call cannot be reproduced.
- **Implementation (this commit).** `[server] delivery_scope = "approved" | "all_non_declined"` (default `approved`, behavior
  unchanged; the configuration fingerprint changes only for the non-default value). `all_non_declined` offers every present,
  non-declined update (declined state is local: `wsus admin` policy; the downstream synchronization carries none), drops a
  bundle member whose bundles are all declined (INFERRED), applies the staged or closure delivery as before, and marks the
  deployment: approved software the approval's action, bundle members `Bundle`, other software `PreDeploymentCheck`,
  everything else `Evaluate`. It also answers `GetFileLocations` and `GetExtendedUpdateInfo` with a location for a file whose
  content was never downloaded, as the real server did (OBSERVED in 12.17; the URL then answers 404); the default scope still
  announces only verified content.
- **Differential, replayed requests (OBSERVED).** The 693 `SyncUpdates` requests of run 3 were replayed to this server
  (revision ids translated through update id and revision; 0 ids unmapped). On 33 sampled calls with a real page of fewer
  than 30 items (every 20th, two workers, page limit 100,000 so the whole deliverable set is visible) **this server's deliverable
  set contained every revision the real WSUS delivered (0 real-only revisions) and no action or `IsLeaf` differed on the common
  items**; this server's sets were larger (for example 603 against 1 at call 240) because of the throttling above. The same replay with a
  page limit of 30 is not comparable.
- **Differential, whole synchronization with this project's client (OBSERVED).** Real: 5,224 distinct revisions. This server
  (catalog: the same upstream, unfiltered, 14,807 present revisions; the 3,982 declined update ids and the 94 approved update
  revisions copied from the real WSUS; 161 pages, 28 s): 4,811, of which 4,756 common. After correcting the update type read from
  prefixed documents there is **no `Action` or `IsLeaf` mismatch on the common revisions**; `LastChangeTime` differs on 4,066
  (this server uses the date of its last configuration change). Not common: 468 only real (144 `Cbs` bundle parents, their 180
  members and 144 gating detectoids: the client's 400-id cap, ranked by dependents known so far, withheld the prerequisite when
  this server delivered non-leaf updates faster than the real one; a client-side effect, INFERRED) and 55 only here (19 bundle
  parents, 31 members, 5 detectoids that the upstream export lists but that the real WSUS never delivered and that are not in its
  administration API: INFERRED to be updates the WSUS cleanup removed; nothing in their metadata, `PublicationState="Published"`,
  marks them).
- **Native Windows Update Agent (OBSERVED, guest Windows 11 25H2, fresh `SoftwareDistribution`, no errors).** Against the real
  WSUS: 66 `SyncUpdates`, 1,950 `UpdateInfo`, 7 `GetExtendedUpdateInfo`, search `IsInstalled=0 and Type='Software'` returned 8
  updates (the lab's test MSI updates) in 9.6 s and `IsInstalled=1` returned 27. Against this server (`all_non_declined`, staged,
  page limit 30): 71 `SyncUpdates`, 2,099 `UpdateInfo` (684 members, 169 parents `PreDeploymentCheck`, 94 `Install`), no fault, **the same 8
  updates and the same 27 installed** in 25.6 s. The first attempt returned 0 updates: the test updates' content was not in this
  server's store, so no file location was announced; announcing locations independently of content (above) fixed it. The
  `0x80244010` limit (more than 200 server trips) was not reached with the unfiltered 5,225-revision catalog (71 trips); the earlier
  Office catalog needed 3,974 declined updates, and here the declined set is what keeps the delivery small.
- **Performance (OBSERVED, one run).** The first request after a start or a policy or catalog change builds an index of the
  generation (14,807 present revisions, 1.7 GB database): 12.6 s; the next 70 requests: median 8 ms, 90th percentile 130 ms, maximum
  166 ms (30-revision pages; `GetExtendedUpdateInfo` 5 to 254 ms); resident memory 548 MB. Without the index every call re-read the documents
  (about 1.2 GB) and, with a page limit of 100,000, a single response took 9 to 41 s and the process reached 2 to 10 GB; the
  approved scope is unchanged (the per-call reading is the earlier behavior).
- **Not established.** The real throttling rule and page order; whether the real server hides members of declined bundles; the
  real action for an unapproved standalone software update; real behavior for declined updates (only that 0 of 3,982 arrived);
  whether `all_non_declined` changes what a native agent reports to a server (events were not examined); a client that evaluates
  installed state (the acquisition client reports its cached non-leaf ids as installed); other native agent builds; closure mode
  with this scope on a native agent (host-tested only).
