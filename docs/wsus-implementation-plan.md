# Rust WSUS client and server implementation plan

Status: proposed implementation plan; no WSUS compatibility is established by this document.

## 1. Objective and scope

Implement reusable Rust libraries and executable tools for Windows Server Update Services communication. The system must acquire metadata and verified content from an existing WSUS server, serve genuine updates to unmodified Windows Update Agent clients, and eventually interoperate with upstream and downstream WSUS servers.

Separate the two protocol families:

| Protocol | Client responsibility | Server responsibility |
| --- | --- | --- |
| MS-WUSP | Computer registration, update discovery, metadata/content acquisition, reporting | Serve computers, deployments, metadata, content locations, and accept reports |
| MS-WSUSSS | Downstream server synchronization from an upstream server | Serve downstream servers, including metadata, content, and eventually replica policy |

The first release targets a selected Windows 11 x64 build and a selected Windows Server build. Pin exact builds during baseline investigation. Expand architectures, older clients, drivers, feature upgrades, and hierarchy modes only after independent validation.

A portable acquisition client is not a complete replacement for Windows Update Agent. Installation, inventory, applicability evaluation, reboot handling, and update handlers require a separate Windows integration layer. Initial Windows installation support uses native Windows facilities.

Direct Microsoft Update communication is a separate compatibility profile. On-premises WSUS interoperability does not prove public-service compatibility.

## 2. Existing workspace and integration constraints

The workspace already contains `crates/uup-client`, which implements blocking and asynchronous UUP dump JSON API access. It does not implement WSUS SOAP. Its runtime-independent transport pattern is useful, but its GET-only transport interface must not be reused unchanged for SOAP POST operations.

`crates/uup-client/src/manifest.rs` defines exact-target payload manifests with filename validation, checksums, and API provenance. Signed payload links are fetched separately. `crates/windows-uup/src/download.rs` implements acquisition behavior. Reuse suitable verification and recovery primitives after auditing their coupling to UUP dump.

Do not force arbitrary WSUS selections into the existing exact-target manifest. A WSUS catalog can contain servicing updates without the full payload closure needed to construct installation media. Introduce explicit source provenance and a WSUS selection model before adapting compatible selections.

Preserve input metadata and payloads. Retain job recovery evidence. Do not persist signed download URLs in manifests, fixtures, or logs. Preserve current `uup-client` public behavior while adding a separate WSUS acquisition provider.

## 3. References and evidence policy

Primary references:

- [MS-WUSP: client-server protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b8a2ad1d-11c4-4b64-a2cc-12771fcb079b).
- [MS-WSUSSS: server-server protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusss/f49f0c3e-a426-4b4b-b401-9aeb2892815c).
- [WSUS protocol overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusod/81f4d6b5-b197-4fa9-9936-f370fd6517b1).
- [Microsoft client-server implementation](https://github.com/microsoft/update-client-server-sync).
- [Microsoft server-server implementation](https://github.com/microsoft/update-server-server-sync).

Pin specification revisions and reference-code commits in the protocol inventory. Treat sample implementations as supporting evidence, not substitutes for the specification or native interoperability tests. Review licenses before adapting source.

For each operation, record endpoint, SOAP version, action, namespaces, request/response structure, preconditions, state changes, limits, pagination, faults, recovery sequence, and fixture provenance. Distinguish specified behavior, observed behavior, and implementation decisions.

Maintain `docs/wsus-validation.md` as implementation proceeds. Every compatibility claim must link to a test run and identify exact client/server builds, protocol profile, supported operations, and limitations.

## 4. Proposed crate architecture

```text
crates/wsus-protocol/src/
  soap/          envelope, actions, XML primitives, faults
  wusp/          client-facing service messages
  wsusss/        server synchronization messages
  metadata/      fragments and relationship parsing
  identity.rs    scoped IDs and digest types

crates/wsus-client/src/
  transport/     backend-neutral POST/GET transport and adapters
  session/       configuration, authorization, cookies, recovery
  sync/          metadata synchronization and checkpoints
  download/      verified resumable acquisition
  reporting/     durable event queue

crates/wsus-server/src/
  endpoints/     protocol routes and dispatch
  catalog/       revisions, relationships, metadata generations
  policy/        groups, approvals, deployments
  computers/     registration and membership
  reporting/     event ingestion and derived status
  upstream/      downstream synchronization orchestration
  storage/       migrations and repositories
  content/       verified object storage and HTTP delivery

crates/wsus-cli/src/
  client/        scan, inspect, download, report
  server/        process startup and configuration
  admin/         import, sync, approvals, diagnostics
```

Keep `wsus-protocol` independent of databases, HTTP servers, and runtimes. Keep WSUS libraries independent of offline servicing and ISO construction. Place the native Windows adapter in a separate module or crate when its API is established.

Use an asynchronous client core with a backend-neutral transport. Add an optional Reqwest/Tokio adapter and a blocking facade when needed. Prototype namespace-aware XML processing, HTTP framework integration, and SQLite access before choosing dependencies. Axum, Reqwest, quick-xml, and SQLite libraries are candidates, not committed requirements.

## 5. Shared wire representation

Introduce typed identities for update GUID/revision pairs, server-local revision IDs, computers, servers, groups, deployments, and file digests. A server-local revision ID is scoped to its originating server and is not interchangeable with an update revision number.

Preserve raw metadata fragments with their origin and parsed indexes. Avoid flattening applicability rules or unknown fields into a lossy JSON summary. Store metadata provenance hashes over received representations; do not assume XML byte identity implies semantic identity.

XML requirements:

- Match namespace URI and local name, independently of namespace prefixes.
- Preserve absent, empty, and nil values where the schema distinguishes them.
- Decode the SOAP versions required by the selected profiles.
- Validate action/body consistency and schema-required ordering.
- Parse SOAP faults independently of HTTP success status.
- Reject external entities and enforce body, nesting, array, and decompression limits.
- Preserve unknown metadata extensions without silently claiming to understand them.
- Serialize deterministic test output without requiring reference servers to use identical formatting.

Tests cover captured requests/responses, alternate namespace prefixes, optional fields, malformed XML, mismatched actions, faults, oversized arrays, and truncated compressed responses. Add parser fuzz targets once decoders are present.

## 6. MS-WUSP client implementation

### 6.1 Session state machine

Implement the specified configuration, authorization, and cookie sequence. `GetCookie` follows `GetConfig` and `GetAuthorizationCookie`; later requests reuse the cookie until renewal is required. See [GetCookie behavior](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/71a6003a-e934-4ca3-98ac-26c8c3f99567).

Persist a stable computer identity, source-server identity, configuration generation, cookies, expiration, registration state, cached revisions, synchronization progress, and pending reports. Cookies and credentials require protected storage and redacted diagnostics.

Classify errors into transport failure, HTTP failure, SOAP fault, metadata failure, and local storage failure. Implement fault-specific renewal/re-registration sequences. Bound recovery attempts; do not repeatedly restart an entire synchronization on every failure. Apply retries according to operation semantics rather than assuming every POST is safe to replay.

### 6.2 Operation implementation order

1. Configuration discovery and authorization service handling.
2. `GetCookie` and configuration/server-change recovery.
3. `RegisterComputer` when the server requires registration.
4. Required prerequisite synchronization operations for the chosen profile.
5. `SyncUpdates`, including continuation and cached revision behavior.
6. `GetExtendedUpdateInfo` and localized metadata selection.
7. `GetFileLocations` and `GetExtendedUpdateInfo2` where required.
8. Verified content downloading.
9. `ReportEventBatch` with durable event delivery.

The exact operation set, including prerequisite methods, is finalized from the protocol inventory. A partial implementation must advertise and document its profile.

### 6.3 Acquisition semantics

Represent selection by stable update identity and revision, not display name. Resolve bundle and prerequisite relationships without dropping metadata needed by consumers. Keep acquisition closure distinct from machine installation applicability.

Refresh expired locations using stable identities. Verify lengths and all required digests. Resume only when the partial object is known to correspond to the expected content. Reject unexpected full responses to range requests unless deliberately restarting. Never publish partial or unverifiable content as complete.

First acceptance criterion: synchronize from real WSUS, acquire a genuine verified payload, restart, resume work, and complete an incremental synchronization without losing revisions or duplicating committed work.

## 7. Applicability and Windows installation

The portable client exposes acquired metadata and explicit selection. It must not invent installed-update inventory or report installation success from download success.

The Windows adapter uses native Windows Update Agent APIs for the first scan/install workflow. Isolate service configuration changes to disposable test guests and retain before/after configuration. Capture native result codes, reboot requirements, and post-reboot installed state.

A later portable evaluator requires a typed applicability expression representation, inventory fact providers, prerequisite/bundle semantics, and native differential tests. Return applicable, not applicable, or unknown. Unsupported rules return unknown and remain visible.

Do not equate the workspace's offline component/package applicability logic with complete Windows Update applicability. Native servicing remains an independent installation gate.

## 8. Catalog and database model

Start with SQLite for a single server process. Use explicit migrations and transactional repositories. Add PostgreSQL only when a demonstrated deployment requirement demands it.

Logical tables:

| Area | Records |
| --- | --- |
| Provenance | Sources, source revisions, synchronization runs, committed generations |
| Catalog | Update identities, revisions, raw fragments, localized properties |
| Relationships | Prerequisites, bundles, supersedence, other supported relationship types |
| Classification | Products, classifications, categories, memberships |
| Content | File descriptors, digests, sizes, verification state, object references |
| Policy | Groups, memberships, approvals, deployments, deadlines |
| Clients | Computer identities, registration data, last contact |
| Reporting | Raw events, deduplication keys where supported, derived update status |
| Sessions | Server generations, cookie/signing state, protocol checkpoints |

Retain both source identity and local mappings. Model withdrawn/deleted metadata according to protocol behavior; supersedence does not automatically authorize deleting content or prerequisites.

Stage imported metadata under a synchronization generation. Validate relationships before activating a generation. Failed imports retain useful recovery evidence but do not expose an inconsistent active catalog.

## 9. Content store and delivery

Use an internal content-addressed store with strong local integrity digests while retaining protocol-required digests and filenames. Paths are derived from validated identities, never arbitrary request paths.

Acquisition lifecycle:

1. Record expected descriptors and create a recoverable partial object.
2. Stream download with configured concurrency, size, and disk limits.
3. Verify length and required hashes.
4. Flush and atomically promote the object.
5. Commit its availability in the database.

Recovery reconciles promoted objects without committed records and database records whose objects are missing. Garbage collection uses references from active metadata and retained jobs and must not race with downloads or serving.

HTTP delivery supports streaming, `HEAD`, byte ranges, correct response lengths, cancellation, stable validators where appropriate, and deliberate handling of unsatisfiable ranges. Independently test native BITS/Windows downloads.

Client-facing content paths and server-server content paths may differ. Implement MS-WSUSSS path and port conventions from the [transport specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusss/b2b10e10-18ac-49e2-bcca-73c17843c4f2); do not impose an arbitrary HTTPS-only route layout that breaks the selected protocol profile.

## 10. MS-WUSP server

Implement protocol endpoint paths, request dispatch, authorization, configuration, cookies, registration, synchronization, extended metadata, file locations, and reporting over the shared types.

Cookies must be opaque, integrity-protected or backed by server-side state, expiring, and associated with relevant server/configuration generations. Validate them before data access. Restart behavior and key rotation must be defined and tested.

Synchronization handlers use a coherent catalog snapshot and stable paging behavior. Apply deployment scope while retaining prerequisite metadata needed for evaluation. Enforce configured request limits and emit protocol faults rather than framework-specific JSON errors.

Policy requirements:

- Explicit group membership and approval state.
- No default publication of every imported update.
- Durable approval changes before client visibility.
- Distinguish metadata publication from verified content availability.
- Handle declines, withdrawals, revisions, and deadlines according to the supported profile.

Preserve genuine metadata and signed payloads. Do not regenerate applicability rules from simplified catalog properties. Discover requirements for auxiliary services and legacy self-update behavior in the reference matrix; implement only the declared compatibility profiles.

Acceptance criterion: an unmodified Windows guest scans our server, sees a specifically approved genuine update, downloads it locally, installs through native servicing, reboots when necessary, and reports an outcome consistent with independently observed guest state.

## 11. MS-WSUSSS downstream client

Add upstream authorization/configuration, category discovery, filtered initial synchronization, incremental synchronization, metadata acquisition, content acquisition, and checkpoint recovery. Inventory exact methods and ordering from the pinned specification before implementation.

Begin with autonomous downstream operation. Replica mode is a separate milestone because it inherits groups and deployments as well as metadata. Keep locally managed approvals separate from upstream policy.

Resolve source revision mappings and dependencies before catalog activation. Handle content stored upstream and content referenced at external locations. Preserve the distinction between successfully synchronized metadata and successfully acquired files.

Test no-change synchronization, new revisions, withdrawals, upstream server changes, expired authorization, interruption during paging, interruption during activation, and repeated resume.

Acceptance criterion: real WSUS upstream feeds our server, which serves an approved update to a native Windows client without manual metadata fabrication.

## 12. MS-WSUSSS upstream server

Implement downstream authorization, configuration, metadata enumeration/data retrieval, content delivery, and supported reporting. Add replica groups/deployments and aggregated reporting after autonomous synchronization works.

Use immutable catalog generations for consistent enumeration. Maintain protocol-required revision identity mappings independently of database row IDs. Define compatibility across restarts and catalog refreshes.

Acceptance criterion: a real downstream WSUS server synchronizes from our server and serves a genuine update to its Windows client. Our own client passing against our own server is not sufficient evidence.

## 13. Administration, configuration, and observability

Proposed CLI surface; names remain subject to usability review:

```text
wsus client configure|sync|inspect|download|report
wsus server run
wsus admin source add|list
wsus admin sync start|status|resume
wsus admin updates list|inspect
wsus admin groups create|list
wsus admin approval set|remove
wsus admin content verify
wsus admin diagnostics export
```

Configuration defines service origins, advertised content URLs, trust roots, proxy settings, database/content paths, filters, concurrency, limits, and retention. Keep administrative authentication separate from protocol client authorization. Local CLI administration is sufficient initially; a web UI is later work.

Structured logs include operation, correlation ID, duration, fault code, server generation, and counts. Metrics cover synchronization lag, active catalog size, verified/missing content, scan latency, faults, queued reports, and disk usage. Redact cookies, credentials, keys, signed URLs, and sensitive registration fields.

Provide sanitized evidence export with a manifest identifying software versions, configuration profile, fixture hashes, and test outcomes. Full request/response tracing is opt-in and sanitized before persistence.

## 14. Integration with windows-uup

Introduce a provider boundary after independent client interoperability is demonstrated. Avoid initially modifying all acquisition callers.

Define a WSUS selection document containing schema version, source-server identity, update GUID/revision pairs, required metadata references, and payload identities/digests. File locations remain transient.

Audit whether verified downloading can be extracted into a shared primitive without changing existing job behavior. Add an adapter to existing manifests only where exact target identity and payload closure are established. If provenance cannot be represented faithfully, version or extend the model deliberately rather than overloading `api_base`.

Regression tests retain UUP dump exact-target matching, filename validation, checksum handling, signed-link exclusion, and recovery behavior. A downloaded WSUS update set must not automatically qualify as ISO input.

## 15. Test strategy and platform gates

| Test pair | Required evidence |
| --- | --- |
| Our WUSP client → real WSUS | Session, sync, content, recovery |
| Native Windows client → our server | Scan, deployment scope, download, native install, reporting |
| Our client → our server | Integration, deterministic faults, restart recovery |
| Our downstream server → real upstream WSUS | Initial/incremental server synchronization |
| Real downstream WSUS → our upstream server | Independent server-server interoperability |

Host tests cover XML fixtures, state transitions, identity scoping, relationship import, migrations, approvals, downloads, and recovery. Use local HTTP servers and temporary databases. Add adversarial parser and content tests where they verify meaningful boundaries.

Native tests use disposable VMs with pinned baselines and snapshots. For each run record configured service URLs, approvals, expected update identities, protocol traces, Windows Update logs, hashes, native result codes, reboot events, and post-reboot installed state. A scan with no errors does not prove update installation.

Required scenarios include empty catalogs, repeated scans, pagination boundaries, prerequisite/bundle relationships, multiple locales, cookie expiration, configuration changes, registration requests, interrupted content, corrupted content, repeated reports, approval removal, and server restart.

Start with a bounded genuine update fixture. Add cumulative updates, modern UUP delivery, feature upgrades, drivers, ARM64, and replica hierarchies as separate gates. Each unsupported category remains explicitly documented.

Run rustfmt, locked Cargo tests, and `cargo clippy --all-targets --all-features --locked -- -D warnings`. Cross-build Windows client tools. Use focused checks during development and the repository-required checks before submission.

## 16. Milestones and implementation sequence

| Milestone | Work | Exit criterion |
| --- | --- | --- |
| M0 | Protocol inventory, pinned reference environment, sanitized captures | Reproducible real WSUS/native Windows baseline |
| M1 | Shared identities, SOAP codecs, faults, XML limits | Independent captured fixtures decode and encode correctly |
| M2 | WUSP session, sync, metadata, verified download | Real WSUS client interoperability and restart recovery |
| M3 | Catalog schema, imports, content store, migrations | Atomic generation activation and crash reconciliation |
| M4 | WUSP server, approvals, reporting, content routes | Native client scan/download/install/report gate |
| M5 | WSUSSS downstream synchronization | Real upstream → our server → native client gate |
| M6 | Windows adapter and windows-uup acquisition boundary | Explicit source selection and preserved existing behavior |
| M7 | WSUSSS upstream role | Real downstream WSUS interoperability |
| M8 | Replica mode and expanded update/platform profiles | Independent evidence for every advertised capability |

Suggested reviewable changes within M1–M4:

1. Add protocol inventory and reference fixture provenance.
2. Add identities and bounded XML envelope/fault decoding.
3. Add configuration/authorization/cookie messages and session tests.
4. Add synchronization messages and persistent client state.
5. Add metadata relationships and transient location resolution.
6. Add verified acquisition and real-server evidence.
7. Add database migrations and coherent catalog imports.
8. Add content storage/reconciliation and range delivery.
9. Add server configuration/authorization/registration handlers.
10. Add synchronization and extended metadata handlers.
11. Add group approvals and reporting.
12. Add native Windows evidence and publish supported profile.

Estimate effort after M0 identifies observed protocol variants, metadata complexity, and available reference content. Do not claim a full WSUS replacement based on the first download prototype.

## 17. Open decisions and investigation tasks

- Pin initial Windows client/server builds and WSUS configuration.
- Determine the smallest genuine update suitable for reproducible installation tests.
- Verify exact auxiliary endpoint and authentication requirements of those builds.
- Determine modern UUP metadata/content requirements through captured native behavior.
- Select XML and database libraries through representative prototypes.
- Decide when a blocking facade and Windows-specific authentication adapters are needed.
- Define initial autonomous synchronization filters and retention policy.
- Decide whether Microsoft Update direct synchronization is required for the first release or a later profile.
- Determine which shared downloading primitives can be extracted without changing existing recovery behavior.

These decisions do not block the initial inventory, wire codecs, or reference fixtures. They must be resolved before declaring their corresponding compatibility milestones complete.

## 18. Definition of done

The initial usable release is complete when our portable client interoperates with real WSUS, our server obtains genuine metadata/content from an upstream WSUS server, and an unmodified Windows client successfully consumes an approved update through our server with independently verified installation/reporting evidence.

The broader client/server implementation is complete only after real downstream WSUS interoperability, documented hierarchy behavior, recovery tests, and every advertised platform/update category pass their own gates. Deliver libraries, CLI documentation, example configurations, migration/recovery procedures, fixture provenance, and an explicit supported-capabilities matrix.
