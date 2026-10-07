# wsus command line

The `wsus` binary (crate `wsus-cli`) drives the MS-WUSP client in `wsus-client`,
the MS-WUSP server in `wsus-server`, and local administration of that server.
It implements section 13 of `docs/wsus-implementation-plan.md`.

## Evidence status

Read this first. Almost everything in this document and in the crate's tests was
verified on a Linux host against **this workspace's own client and this
workspace's own server**. Those tests prove that the pair is consistent with each
other and with the pinned specification text both were written from. They are
**not** WSUS compatibility evidence. The exceptions, all on one lab build and
recorded in `docs/wsus-validation.md`:

- `wsus admin sync start|resume` (the downstream importer) was run against a real
  WSUS (Windows Server 2025 10.0.26100) acting as an upstream server: metadata for
  one product and classification, a no-change second run, and the content of one
  approved update (inventory 9.5; rows C15 to C18, `Partially validated`). It is the
  first command tested against a real WSUS server.
- on 2026-10-06, `admin sync categories` and metadata-only `admin sync start`
  also contacted Microsoft's public synchronization service over verified TLS.
  Discovery returned 444 categories and 3,804 detectoids. A Win10/11 Critical
  Updates filter activated 4,420 fragments, including shared configuration and
  required dependencies, in 65.35 seconds. A subsequent run activated a second
  generation, fetching 137 revisions and carrying 4,283 forward; it was not a
  no-change response. No payloads were downloaded. This validates this metadata
  path and selected filter, not all products/classifications or content delivery.
  Evidence: `/data/cache/wsus-microsoft-sync-20261006/`;
- `wsus server run` was pointed at by one native Windows Update Agent (1507.2601.30012.0,
  Windows 11 25H2) on 2026-10-04, in both `sync_delivery` modes: the agent found,
  downloaded and installed one approved Defender definitions bundle (inventory 9.7; row
  C31, `Partially validated`). Limits: one update, one guest build, plain HTTP, a
  lab-modified image, install verified by the guest's signature version, one client at a
  time, an unrecorded server tree (commit `fd2a126` plus uncommitted work);
- this project's own client was run against this project's own server in one P3 session on 2026-10-06 (host and one Windows
  guest clone, plain HTTP, one catalog, commit `cda13ef`; inventory 9.9, rows C14 and C52 to C58, `Partially validated`):
  sync in both delivery modes and scopes, verified downloads with resume after an injected cut, a changed file location, a
  killed client and a killed server, sync recovery after a kill, cookie expiry, a configuration change, event delivery, and
  scan, plan and install of the Defender bundle on the guest. It is evidence that this pair agrees, never about Microsoft
  software. Observed limit at `cda13ef`: with `sync_delivery = "staged"` and `delivery_scope = "all_non_declined"` this client never
  received the approved bundle (C52); fixed at `84a1b95` (probe requests for the ids the 400-entry cap withholds), a host re-run
  downloaded the bundle 155 of 155 in all four combinations, the guest was not re-run;
- nothing else about a native client or a Windows installation is validated: no TLS,
  no second client, no approval removal or decline, no deadline or uninstall, no
  restart under a native client, no drivers or cumulative updates.

The capability matrix at the end marks every row accordingly. Plan section 15
requires real-WSUS and native-client gates before any compatibility claim.

## Commands

```text
wsus [--config FILE] [--json] [-v|-vv] [--trace-file FILE] <command>

wsus client configure [--origin URL] [--state-dir DIR] [--dns-name NAME] [--target-group G]
wsus client sync
wsus client inspect [--revision UUID[@REV]]
wsus client download (--all | --update UUID[@REV]...) [--include-prerequisites]
wsus client report --namespace-id N --event-id N [--source-id N] [--hresult N]
                   [--sequence N] [--update UUID@REV] [--instance-id UUID]
                   [--app-name S] [--no-flush]
wsus client report --flush-only
wsus client report --job JOBID [--no-flush]
wsus client report --inventory [--force] [--facts-file F] [--no-flush]
wsus client facts-check --queries queries.json --expect facts.json [--facts-file F] [--max-details N]
wsus client scan [--facts-file F] [--update UUID[@REV]]... [--all]
wsus client plan --update UUID[@REV] [--facts-file F] [--allow-unknown] [--out plan.json]
wsus client install --update UUID[@REV] [--facts-file F] [--yes] [--trust-signer NAME]...
                    [--allow-unknown] [--allow-writable-store] [--timeout-secs N]
wsus client uninstall --update UUID[@REV] [--facts-file F] [--yes] [--allow-undeclared]
                      [--package IDENTITY] [--allow-writable-store] [--timeout-secs N]
                      [--post-check-wait-secs N]

wsus server run

wsus admin source add NAME [--kind upstream|local|import] [--description S]
wsus admin source list
wsus admin sync start|resume [--source NAME] [--content none|all|approved]
wsus admin sync status [--source NAME]
wsus admin sync categories [--source NAME]
wsus admin catalog import --dir DIR [--manifest FILE] [--source NAME] [--dry-run]
wsus admin catalog export --out FILE.cab [--source NAME] [--content-base-url URL]
wsus admin updates list [--source NAME] [--after ID] [--limit N] [--all]
wsus admin updates inspect UUID[@REV] [--source NAME]
wsus admin groups create NAME [--description S]
wsus admin groups list
wsus admin approval set UUID[@REV] --group NAME|ID [--action install|uninstall]
                        [--deadline UNIX|XS_DATETIME] [--source NAME]
wsus admin approval remove UUID[@REV] --group NAME|ID [--action install|uninstall]
wsus admin content verify [--deep] [--source NAME]
wsus admin diagnostics export --out DIR [--fixture FILE]... [--outcome NAME=RESULT]...
                              [--include-trace]
```

Output is `key: value` text on stdout, or JSON with `--json`. Logs go to stderr.
Exit status: `0` success, `1` error, `2` the command produced its result but
part of the work failed (for example a file that did not verify in
`client download`, or corruption found by `admin content verify`).

### client

- `configure` merges the given options into the `[client]` section, validates,
  rewrites the configuration file (comments of the previous file are lost) and
  creates the persistent computer identity. Run it once per client profile.
- `sync` performs the handshake (`GetConfig`, authorization, `GetCookie`,
  registration when the server requires it), then `SyncUpdates` with the cached
  revision lists, then `GetExtendedUpdateInfo` (`Extended` fragment) for every
  in-scope software revision whose file list is unknown. Checkpoints are
  committed per page, so an interrupted run resumes without loss or duplication.
- `inspect` prints state (identity, registration, cookie *expiry only*, checkpoint
  and cached revision count) and the in-scope updates with their file lists;
  with `--revision` it adds relationships.
- `download` resolves the acquisition closure of the selection (bundled
  revisions; prerequisites only with `--include-prerequisites`), obtains file
  locations by SHA-1, and downloads through the verified, resumable downloader.
  Objects are promoted only after every declared digest matches over the whole
  file. Locations are transient and never persisted or logged.
- `report` queues one event (de-duplicated by `--instance-id`) in a durable
  queue and delivers queued events with `ReportEventBatch`. No event id table
  is built in: the ids are required arguments because the table is unverified.

- `facts-check`, `scan`, `plan`, `install` and `uninstall` are the installing client
  ([wsus-install.md](wsus-install.md)): `facts-check` compares the live Windows
  fact provider with a snapshot written by `scripts/wsus/collect-facts.ps1`;
  `scan` prints a verdict per update (applicable, installed, not applicable,
  unknown with blockers); `plan` builds the deterministic install plan; `install`
  is a **dry run unless `--yes`** and with `--yes` needs Windows, live facts and
  elevation, downloads the payloads, gates (path, digest, Authenticode signature
  against the signer allowlist, default `Microsoft Corporation`; `--trust-signer`
  replaces it), executes, and re-evaluates; its exit status is 2 when the plan
  was refused, a gate refused, a step failed or the post-check does not say
  installed. Any Unknown on a decision path refuses the plan unless
  `--allow-unknown` (risky, see the install document). No reporting event is sent unless
  `[install] report_events` is on (then the job's `181` and `183`, `201` or `182` are queued
  and delivered best effort after the run, shown under `reporting` in the output; see the
  install document). `client report --job JOBID` queues the events of a recorded job. With
  `[install] report_inventory` the client status event `156` (the `U` and `V` lists of the updates the evaluator
  says are not installed and installed, the event the real WSUS derives Installed and NotInstalled from, inventory 9.11) is
  queued after the job as well, built from the live facts with the job's own post-check deciding for the updates it executed,
  and shown under `reporting.inventory`; `client sync` queues and delivers it after the sync, and
  `client report --inventory` emits it explicitly (an unchanged inventory is queued once, `--force` queues it again;
  needs live facts or `--facts-file`).

- `uninstall` removes one installed servicing update (a `.NET` rollup) through the
  configured `[install] servicing_backend` (`dism` or `dism_api`; `wusa` has no
  removal and is refused). It is a **dry run unless `--yes`**; with `--yes` it needs
  Windows, live facts and elevation. It reads only the stored catalog (no network,
  no download) and builds an uninstall plan (`wsus-install-plan/3`, outcome
  `uninstall`; `nothing_to_do_not_installed` when the update does not evaluate
  installed; `refused` otherwise). `--allow-undeclared` accepts an update whose
  metadata declares no `UninstallationBehavior` (the real `.NET` rollup leaf
  declares none, so it is needed for that update; the plan records that the removal
  is the operator's request). `--package` names the CBS package identity instead of
  taking it from the update's manifest or from its CompDB cabinet (which must then
  be in the content store, digest-verified; `--allow-writable-store` as for
  `install`). Exit 3010 gives job status `reboot_required`; restart, then run the
  command again: a removed update reports `nothing_to_do_not_installed`. A package
  the stack refuses as permanent (`0x800f0825`, the monthly cumulative update) gives
  status `failed`, exit status 2, a refusal recorded as `permanent_package` and no
  retry (a later run is refused without asking the stack again). The servicing call
  is never killed on timeout (status `unconfirmed`). Nothing is reported to the
  server. Design and evidence: [wsus-install.md](wsus-install.md) (Uninstall),
  ledger C50.

Client files, under `client.state_dir`: `state.json` (mode 0600, holds the
session cookie), `meta/revisions/` (received metadata), `events/` (event queue),
`content/partial` and `content/complete` (downloads), `jobs/` (install job
records and `install.lock`).

### server

`server run` opens the database and content store, reconciles content with the
database (see Recovery), then serves MS-WUSP over plain HTTP with axum until
interrupted. Only protocol routes exist. TLS must be terminated in front of the
service; listening beyond loopback logs a warning.

### admin

Administration is **local only and separate from protocol authorization**. There
is no administrative route, port or credential in the protocol surface. The
authority is write access to the server database file, which also holds the
cookie signing key: the database and its directory are created owner-only, and
`wsus admin` refuses to run if the database file or its directory is writable by
group or others (Unix). Clients obtain protocol access through the SOAP
authorization flow, which never grants administrative rights.

Administration may run while `wsus server run` serves (shared SQLite database in
write-ahead-log mode); approval changes apply to the next client request. The
configuration *file* is read only at server start.

- `source add|list`: catalog sources. The server serves the active generation of
  the source named by `server.source_name`.
- `sync start|resume|status`: see below.
- `updates list|inspect`: pages of the active generation (cursor `--after` is
  the printed `next`); `inspect` shows relationships, files with content
  availability, approvals and reported client status counts.
- `groups create|list`, `approval set|remove`: approval `set` requires the
  update to exist in the active generation; re-approving updates the deadline;
  `remove` withdraws the active approval and fails if there is none.
- `content verify [--deep]`: **reconciles** (completes interrupted promotions,
  marks missing objects, quarantines unrecorded or, with `--deep`, corrupt
  objects) and reports coverage of the active catalog. It repairs as it
  verifies. Exit status 2 when corrupt or missing objects were found; catalog
  files without stored content are reported as `catalog_files_unavailable` but do
  not by themselves fail the command (a metadata-only server is legitimate).
- `diagnostics export`: see below.

#### Export for Microsoft WSUS

`wsus admin catalog export --out catalog.cab` exports the selected source's
active generation to a new CAB containing `metadata.txt` and `package.xml`.
It preserves the original full update XML, validates identities and required
dependencies, and publishes atomically without replacing an existing file.
Client-side WUSP fragments are insufficient: export requires full upstream
update documents, including their localized properties.

File locations come from the original metadata. When those are absent,
`--content-base-url` (or `server.advertised_content_url`) supplies this server's
content origin. Export fails when required file digests or locations are missing.
The package contains metadata only; payloads, approvals and computer state are
not included. Payload transfer and approval configuration remain separate steps.

The implemented format follows Microsoft's
[WSUS 2016 export reference](https://github.com/microsoft/update-server-server-sync/blob/master/src/microsoft-update-endpoints/WsusExport.cs).
The intended target command is `wsusutil.exe import catalog.cab import.log`.
**Native import compatibility remains unverified.** Modern WSUS workflows also
use `.xml.gz`; that format is not implemented, and renaming this CAB does not
convert it. Host tests verify framing, dependency checks, original XML
preservation and refusal to overwrite; they do not prove Microsoft WSUS accepts
the package. On 2026-10-06 the complete `wsus-cli` and `wsus-server` host test
suites passed, as did workspace formatting and all-target/all-feature locked
Clippy with warnings denied. An actual CLI-generated synthetic package was
tested and extracted successfully with the independent 7-Zip 17.05 reader;
its metadata framing and original XML bytes matched the input. The retained
host receipt is `/data/cache/wsus-export-cli-independent-20261006/host-validation.json`.

#### Upstream synchronization

`sync categories` validates the configured upstream handshake and retrieves
category metadata, printing product/classification GUIDs, revisions and titles.
It creates the local upstream source when absent but does not activate a catalog.
Use these GUIDs for `products` and `classifications`; configure both lists to
send a server-side filter. `--content none` synchronizes metadata without payloads.

Progress is written to stderr, leaving `--json` stdout usable by other tools.
It reports completed responses, received HTTP body bytes, elapsed time and
average MiB/s; metadata synchronization also reports listed and staged counts.
These transfer totals include retries and exclude reused local content.
Set `[upstream] progress = false` to suppress progress.

`metadata_concurrency` controls simultaneous metadata requests (default 4,
range 1–16). Each worker forks the current session, sharing the HTTP connection
pool while independently handling cookie renewal and adaptive response limits.
Catalog imports remain serialized; partial replies are requested again.
In one live discovery comparison, four workers completed in 60.82 seconds
versus 523.95 seconds for the preceding serial implementation; both returned
the same category identities/types and detectoid count. This is a live
observation across code revisions, not a controlled throughput benchmark.
`download_concurrency` controls simultaneous content transfers (default 4,
range 1–32). Digest verification, resumable partial files and serialized content
publication remain in force. Set either value to 1 for serial operation.

Microsoft documents `https://sws.update.microsoft.com` as its
[current synchronization origin](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/update-management/wsus-synchronization-fails-with-soapexception).
The live SOAP endpoint observed on 2026-10-06 is
`https://sws.update.microsoft.com/ServerSyncWebService/ServerSyncWebService.asmx`.
On this Linux host, TLS requires Microsoft's published Root CA 2011 in the
configuration's explicit trust roots; certificate and hostname verification stay
enabled. Download the root from the
[Microsoft PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm)
and verify its published SHA-1 certificate fingerprint
`8F43288AD272F3103B6FB1428485EA3014C0BCFE` before using it. Convert DER to PEM
with `openssl x509 -inform DER -in root2011.der -out root2011.pem`.

```toml
[upstream]
origin = "https://sws.update.microsoft.com"
download_files_fallback = false
allow_mu_url = true
metadata_concurrency = 4
download_concurrency = 4
progress = true
# products = ["GUIDs from sync categories"]
# classifications = ["GUIDs from sync categories"]

[network]
trust_roots = ["root2011.pem"]
```

`allow_mu_url` permits transient Microsoft payload locations in memory; it does
not persist signed URLs. Microsoft advertises `CatalogOnlySync=true`; when
`allow_mu_url=true`, content acquisition can still use those supplied locations.
`download_files_fallback=false` avoids asking Microsoft to stage content through
the downstream-WSUS `DownloadFiles` fallback.

The live filtered test used products `72e7624a-5b00-45d2-b92f-e561c0a6a160`
(Windows 11), `a3c2375d-0c8a-42f9-bce0-28333e198407` (Windows 10), and
`b3c75dc1-155f-4be4-b015-3f1a91758e52` (Windows 10, version 1903 and later),
with classification `e6cf1350-c01b-414d-a61f-263d14d133b4` (Critical Updates).
Discover the categories again when changing scope rather than assuming these
three IDs cover every Windows 10/11 product variant.

`sync start` runs `UpstreamSync` (MS-WSUSSS downstream, autonomous mode) using
the `[upstream]` section and the reqwest backend. It refuses to start when an
interrupted (staging) generation exists; `sync resume` continues one (a resume
whose pending checkpoint no longer matches fails the old generation and keeps it
as evidence, which is the library's documented behavior). `--content all|approved`
afterwards acquires files into the content store with verified downloads
(downloads staging area: `upstream-downloads/` next to `server.content_dir`).
Startup and admin recovery use `Catalog::recover_after_restart()`, never
`abandon_interrupted()`: staging generations of `upstream` sources are left in
place so `sync resume` can continue them, while staging generations of `local`
and `import` sources (nothing can resume those) are failed with evidence kept.
This runs in `server run` start-up, at the start of `admin sync start|resume`
and, for the target source only, at the start of `admin catalog import`.
`wsus admin` commands other than those do not run it, so a second administrator
process never fails another process's in-flight import. Starting `server run`
while an import into a `local` or `import` source is running in another process
fails that import's staging generation (the import then fails at activation).
**Evidence status: the orchestration is host-tested against the fake upstream
in the `wsus-server` crate's own tests and, in `tests/restart_recovery.rs`,
against this workspace's own MS-WSUSSS server on a loopback socket (a staged
generation survives a server restart and `sync resume` activates that same
generation without refetching): self-consistency only. Separately, on 2026-10-04
the command ran against a real WSUS upstream (Windows Server 2025 10.0.26100,
anonymous, HTTP, Microsoft Defender catalog): the filtered initial run listed 28,784
revisions and staged 5,581 in 24 s (release build), the second run reported no
change, and `--content approved` fetched the 155 files of the approved bundle (1.2
GiB) with every digest verified (inventory 9.5, rows C15 to C18 of the validation
ledger, `Partially validated`). Recovery after an interruption, revision changes and
withdrawals arriving later, `DownloadFiles` and HTTPS or authenticated upstreams were
not exercised against a real server.**

Observed behavior the configuration depends on (one build):

- `products` and `classifications` are applied locally to the revisions' `IsCategory`
  prerequisites; the wire filter is sent only when BOTH lists are non-empty and
  `send_wire_filter` is true (a one-sided filter selects nothing upstream). Bundled
  revisions the filter excluded are pulled in by dependency, so the leaves that carry
  the files arrive through their bundles. Find the ids with
  `scripts/wsus/probe-wsusss.py --origin URL categories`.
- `--content approved` acquires the files of the approved updates AND everything they
  bundle or require (an approved bundle has no files of its own). All files are tried;
  one that every location refuses with 404 is reported as failed. With
  `download_files_fallback = true` (the default) those files are then requested from the
  upstream with batched `DownloadFiles` calls, which makes the upstream fetch them from
  its own parent; set it to `false` to leave the upstream untouched. `--content all`
  tries every file of the active generation (a real catalog can hold hundreds of
  gigabytes).
- File URLs are built as `<content_base_url>/Content/<last two hex of the SHA-1, upper
  case>/<SHA-1 hex, upper case>.<extension of the file name>`; `content_base_url`
  defaults to `origin` (the real server served content on the same port).
- The upstream's metadata blobs (`XmlUpdateBlobCompressed`) are read as a Cabinet with one
  member of UTF-16LE XML (`wsus_client::wsusss::CabMetadataDecompressor`).

#### Catalog import (no upstream)

`admin catalog import --dir DIR` makes a server usable without any upstream.
`DIR` holds well-formed `Update` XML documents (one revision per file, the shape
`GetUpdateData` delivers: `UpdateIdentity`, `Properties`, `Relationships`,
`Files`) and the payload files they declare. Without `--manifest`, every
`*.xml` directly inside `DIR` is imported and a declared file `NAME` is read
from `DIR/payloads/NAME`. With `--manifest FILE` (JSON, unknown keys are
errors) the documents come from the manifest:

```json
{"updates":[{"xml":"docs/u.xml","payloads":{"x.cab":"blobs/x.bin"}}]}
```

Rules, all enforced before anything is written:

- every document must parse as a single `Update` with an `UpdateIdentity`; a
  duplicate identity across documents is an error;
- every declared file needs a plain `FileName` (no separators, no `..`), a
  `Size` and at least one digest (SHA-1, SHA-256 or SHA-512, primary or
  `AdditionalDigest`); the payload must exist, have exactly that size and match
  every declared digest; manifest paths must stay inside `DIR` (symbolic links
  that leave it are refused);
- the target source (`--source`, default `server.source_name`) must exist and
  must be of kind `local` or `import`; `upstream` sources belong to
  `admin sync`.

Then the content is stored through the content store (which re-verifies size
and digests), the metadata is staged as a new generation in one batch
(relationships and file descriptors derived from the documents with the same
alternative-clause rule as the upstream importer), and the generation is
activated atomically by the catalog's own validation. If the catalog rejects
the generation (for example a prerequisite that is not part of the import) the
command fails, the generation is kept as failed evidence and the previously
active generation keeps serving. Stored content objects of a failed import stay
in the store (unreferenced; garbage collection is a content-store matter).
`--dry-run` performs all verification and writes nothing; it does not evaluate
relationship closure, which only the catalog check at activation does.

An import is a full snapshot: the new generation replaces the source's active
generation, and updates absent from `DIR` disappear from the catalog (approvals
remain in the policy store but refer to nothing). Compressed documents,
localized fragments and Core/Extended documents are not accepted; the document
is stored exactly as read. Approve the imported updates with `admin approval
set` as usual.

**Evidence status: tests write the documents themselves and check this
workspace's catalog, server and client against each other
(`tests/catalog_import.rs`). The documents are not captured from WSUS and no
real server or native client has consumed them.**

## Configuration

One TOML file (`--config`, `WSUS_CONFIG`, else `./wsus.toml` when present).
Relative paths resolve against the file's directory. Unknown keys are errors.
The file contains no secrets. See `crates/wsus-cli/examples/wsus.example.toml`.

| Section | Purpose |
| --- | --- |
| `[network]` | `proxy` (bare origin, no credentials), `trust_roots` (PEM files); applied to client and upstream HTTP |
| `[client]` | `origin`, `state_dir`, `accept_xpress` (default true: `Accept-Encoding: xpress` on SOAP requests, responses decoded with the decoded size capped by `max_response_bytes`; never sent on content downloads), `dns_name`, `target_group`, path overrides, timeouts, retries, download limits, `filter_categories`, `[client.computer]` declared OS fields |
| `[server]` | `listen`, `database`, `content_dir`, `source_name`, `advertised_content_url` (origin of file URLs), request/array/page limits, `sync_delivery` (`"staged"` default or `"closure"`, see below), `delivery_scope` (`"approved"` default or `"all_non_declined"`, see below), `max_sync_new_updates` (30 staged; 200 closure when unset), `protocol_version` (3.2 staged, 3.0 closure when unset), `max_installed_non_leaf_ids` (400), `out_of_scope_unsatisfied` (true), `xpress_responses` (default true: Xpress-compress SOAP responses for clients that send `Accept-Encoding: xpress`, never content files; Xpress request bodies are always accepted, bounded by `max_request_bytes`), `allowed_event_ids`, cookie lifetimes |
| `[upstream]` | `origin`, `endpoint_key`, account identity, `content_base_url` (default `origin`), `download_files_fallback` (default true), product/classification filters (GUID lists; see above), `send_wire_filter`, `keep_superseded_generations`, `request_timeout_secs` |
| `[install]` | `trust_signers` (signer organisation allowlist, default `["Microsoft Corporation"]`), `timeout_secs` (one installer process, default 1800), `msi_handler_uris` (only with the `msi-handler` feature), `report_events` (queue install outcome events, default false), `report_uninstall_events` (queue uninstall outcome events, default false; ids from the real WSUS event table, not observed from a native agent), `report_inventory` (queue the client status event `156` with the `U` and `V` lists after `client sync` and after an install or uninstall job, default false; inventory 9.11) |
| `[logging]` | `level` (tracing filter), `format` (`text` or `json`) |

#### `[server] sync_delivery`

| Value | `SyncUpdates` behavior | Advertised `ProtocolVersion` | Status |
| --- | --- | --- | --- |
| `staged` (default) | Real-WSUS-like. The server reads `InstalledNonLeafUpdateIDs`. A revision is delivered only when every prerequisite clause (AND of `AtLeastOne` ORs, read from the Core fragment) is satisfied by an id in that list, so a client evaluates metadata in dependency order and reports what is installed. Non-leaf first, 30 per page, `Truncated` when more are deliverable, at most 400 installed ids (401 is `InvalidParameters`), `StartCategoryScan` answered, cached revisions with unsatisfied prerequisites answered in `OutOfScopeRevisionIDs` (`out_of_scope_unsatisfied`) | 3.2 | Matches the recorded real-WSUS dialogue in shape (offline replay, `crates/wsus-server/tests/native_sim.rs`). Native Windows Update Agent, 2026-10-04: found, downloaded and installed the Defender bundle in 11 `SyncUpdates` rounds (170 `UpdateInfo`, pages of at most 30, installed ids 3, 4, 5, 7, 8), no `StartCategoryScan` sent by the guest (inventory 9.7, C31, `Partially validated`) |
| `closure` | The earlier behavior: the whole approved closure at once (200 per page when `max_sync_new_updates` is unset), the installed list is ignored, no installed-id cap | 3.0 | Native Windows Update Agent, 2026-10-04: found, downloaded and installed the Defender bundle in 4 `SyncUpdates` (200, 200 and 44 `UpdateInfo` plus the driver pass; up to 1,125,833 decoded bytes per page, Xpress on the wire). This CONTRADICTS the earlier expectation (and the offline model `native_sim.rs`, which predicts closure fails: it is more conservative than the real agent and is not evidence of native behavior). Which of the category-chain and staged-delivery changes closure mode needed is not isolated: both modes include the `Deployment`, `IsLeaf` and category-chain fixes. Kept as the simpler fallback; `staged` stays the default because it matches the recorded real-WSUS dialogue |

#### `[server] delivery_scope`

Which updates a computer is offered. Orthogonal to `sync_delivery` (which decides the order and the paging), and
validated at load (an unknown value is a configuration error). Changing it changes the configuration fingerprint only
when it is not the default, so existing servers keep theirs.

| Value | Offered set | `Deployment` `Action` of what is not approved | Status |
| --- | --- | --- | --- |
| `approved` (default) | Updates approved for the computer's groups plus their prerequisite, category and bundle closure | `Evaluate` (`Bundle` for bundle members); `PreDeploymentCheck` is never emitted | Unchanged behavior; native-agent evidence in rows C11 and C31 |
| `all_non_declined` | Every non-declined update of the active generation (declined: `wsus admin` policy; a member whose bundles are all declined is not offered), approved or not, so a client evaluates and reports unapproved updates as a real WSUS lets it | `PreDeploymentCheck` for unapproved software that is not a bundle member, `Bundle` for bundle members, `Evaluate` for detectoids, categories and other types; approved software keeps the approval's action | Rule derived from a real WSUS (inventory 12.19); host-tested, differential and native-agent results in 12.19 |

Staged delivery still applies the prerequisite rule in both scopes. `all_non_declined` builds an index of the active
generation on the first request after a catalog or policy change (a Windows catalog is over a gigabyte of documents
and took 12.6 s to read once in the lab run of inventory 12.19) and keeps it for the next requests; it does not copy declined state from an
upstream: the downstream synchronization carries no declined flag, so decline the same updates locally.

`StartCategoryScan` is answered in both modes (the guest sent none in the two native runs, so the answer was not exercised natively). Shared in both modes: `Deployment` on every `UpdateInfo`, the `IsLeaf` rule, the cookie, `DriverSyncNotNeeded` (driver pass `true` with no `NewUpdates`; a software pass `false`, `true` when it carries `FilterCategoryIds`) and the approved-update visibility rules. Changing `sync_delivery` or `protocol_version` changes the configuration fingerprint, so clients re-handshake.

`advertised_content_url` should be set explicitly; otherwise the request `Host`
header is used. Changing a client-visible server setting (`max_extended_updates_per_request`,
`allowed_event_ids`) advances the configuration generation at the next start, and
clients re-read it.

## Logging and redaction

Every command logs one summary event with `operation`, `correlation_id`,
`duration_ms`, `outcome`, `fault_code`, `server_generation` and `counts`. The
server logs one `http_request` event per request (route class, SOAP action,
status, fault code read from fault bodies, duration). All output passes a
sanitizing writer that reduces URLs to scheme and host, removes values of
credential-like keys (cookie, authorization, token, signature, key, password,
account GUID, ...) and long non-hex blobs; hexadecimal digests are kept as
evidence. Opt-in full debug tracing: `--trace-file FILE` (mode 0600), sanitized
line by line before it reaches disk.

Metrics named in the plan (synchronization lag, scan latency, queued reports,
disk usage) are **not implemented**; only the counts above are logged.

## Diagnostics export

`wsus admin diagnostics export --out DIR` writes `manifest.json`:
software versions, OS/arch, the configuration profile (origins reduced to scheme
and host, no paths), counts from the client state and the server database,
SHA-256 and size of each `--fixture` file (file name only), caller-supplied
`--outcome NAME=RESULT` test outcomes, and an `evidence_status` block that states
nothing has been validated against real WSUS or a native client. With
`--include-trace` (needs `--trace-file`) a re-sanitized `trace.jsonl` is added.
The manifest is sanitized before it is written. The tool does not run tests; the
outcomes are what the caller asserts.

## Recovery procedures

- **Interrupted download**: run `client download` again. A partial object is
  resumed with a Range request only if its sidecar matches the expected
  descriptor and the recorded prefix hash matches the bytes on disk; otherwise it
  is discarded. Final digests are always checked over the whole file.
- **Interrupted client sync**: run `client sync` again; pages already committed
  are not resent.
- **Cookie expiry, key rotation, configuration change**: handled automatically
  by bounded recovery in the session (renewal, new handshake, re-read of
  configuration). After an expired cookie the server may resend deployment data as
  "changed"; no revision is new or removed.
- **Server restart or crash**: restart `wsus server run`. The signing key,
  catalog, policy, registrations and reports are in SQLite, so existing client
  cookies keep working. At start the content store is reconciled: promotions that
  crashed before commit are completed, unrecorded objects are quarantined, stale
  partial uploads are discarded. The result is logged as `startup_recovery`.
- **Corrupt or missing server content**: `wsus admin content verify --deep`
  quarantines corrupt objects and reports what the catalog lacks; re-acquire with
  `admin sync start|resume --content ...` or restore the object. Clients refuse
  corrupt bytes regardless.
- **Interrupted upstream sync**: a server restart does not fail the staging
  generation; `admin sync status`, then `admin sync resume`.
- **Interrupted local import**: nothing can resume it; the next start of
  `server run` or `admin catalog import` fails it (evidence kept). Run the import
  again.
  Failed generations stay in the database as evidence; they are never deleted by
  this tool.
- **Lost client event queue / lost acknowledgement**: sending the same event
  instance id again is safe; the server keeps one copy.
- **Client state corruption**: a corrupt `state.json` is an error, never reset
  silently; move it aside deliberately to create a new identity.
- **Replaced server database**: the client detects the changed server identity
  and discards server-local state (cookie, registration, cached revisions).

Not covered by any procedure: database corruption, schema downgrade, multi-
process writers other than the supported server plus local admin.

## Supported capabilities

Legend: **Implemented, host-tested** = implemented and covered by tests in this
workspace against the in-process or loopback pair only. **Not validated against
real WSUS or Windows** = no evidence beyond that. **Not implemented**.

| Capability | Status |
| --- | --- |
| Client handshake, registration, `SyncUpdates`, extended info, file locations | Implemented, host-tested (own pair only). Not validated against real WSUS or Windows. The message codecs decode recorded real-WSUS exchanges (this project's driver: `wsus-m0`, `docs/wsus-validation.md` C1 to C3; a native Windows Update Agent: `wsus-m0-native`, C27), decode only, not a live run of this CLI |
| Verified, resumable download with digest checks | Implemented, host-tested (own pair; includes interruption and corruption). Not validated against real WSUS or Windows |
| Cookie expiry, signing key rotation, configuration change recovery | Implemented, host-tested (own pair only). Cookie expiry (renewals and a server `CookieExpired` fault) and a configuration change (`ConfigChanged`) were also observed in the P3 session of 2026-10-06 (C55, C56, own pair, `Partially validated`); key rotation was not. Not validated against real WSUS or Windows |
| Event reporting with de-duplication, durable queue | Implemented, host-tested (own pair only). Install and uninstall outcome events can be queued from job records (`[install] report_events`, `report_uninstall_events`, `client report --job`, off by default; inventory 9.10, ledger C71 to C73: the native shapes of `181`, `201`, `183` and `182` were observed, the uninstall ids are the real server's table and not observed from a native agent). The real server's event table names the ids; it sent no `AllowedEventIds`. The `156` status report that makes the real WSUS show an update as installed is sent only behind `[install] report_inventory` (off by default; inventory 9.11, C77 to C79, `Partially validated`). A native client's events 147, 156, 167, 162, 181 and 183 were accepted by this server with `true` and the computer got a `last_report` time (inventory 9.7, C12, `Partially validated`: acceptance only; the derived status was not verified) |
| Server over HTTP (axum), range and HEAD for content | Implemented, host-tested (loopback with reqwest). Native Windows Update Agent, 2026-10-04: 215 closed-range `GET`s per run, all `206`, `Content-Range` equal to the request, 223,014,168 bytes of 3 files, over 5 (staged) and 3 (closure) connections (inventory 9.7, C11, `Partially validated`). `HEAD`, conditional requests, `416`, resume, TLS and several clients not exercised natively |
| Server restart recovery, content reconciliation | Implemented, host-tested |
| Local administration: sources, groups, approvals, updates, content verify | Implemented, host-tested |
| Approval removal hides updates from clients | Implemented, host-tested (own pair only) |
| Admin separated from protocol authorization (local, file-ownership) | Implemented, host-tested (permission check is Unix only) |
| Structured logs with correlation id, duration, fault code, counts; redaction | Implemented, host-tested |
| Opt-in sanitized tracing; sanitized evidence manifest | Implemented, host-tested |
| Upstream sync CLI (`admin sync start|resume|status`, content acquisition) | Wired; guards and error paths host-tested, orchestration tested against the library's fake upstream and this project's own upstream server. Run once against a real WSUS upstream: authorization, filtered metadata sync, a no-change run and content acquisition `Partially validated` (C15 to C18, one build, one catalog). Recovery, `DownloadFiles`, revision changes and HTTPS not exercised against a real server |
| Proxy and extra trust roots | Implemented, not host-tested (no TLS or proxy fixture). Not validated against real WSUS or Windows |
| TLS listener | Not implemented (terminate TLS in front) |
| Import of updates without an upstream (`admin catalog import`) | Implemented, host-tested (own catalog, server and client; self-authored documents, not WSUS output). Not validated against real WSUS or Windows |
| Staged upstream generation survives restart and resumes | Implemented, host-tested (own MS-WSUSSS server on loopback only). Not validated against real WSUS |
| Metrics (sync lag, scan latency, queued reports, disk usage) | Not implemented |
| Web UI, remote administration | Not implemented (plan: later work) |
| Compressed upstream metadata (`XmlUpdateBlobCompressed`) | Implemented for the form one real WSUS build sent (Cabinet, one LZX member of UTF-16LE XML); host-tested with real blobs; other forms are refused with an error |
| Encrypted content, drivers, express/delta, replica mode | Not implemented |
| Applicability evaluation and installation of command-line-handler updates (`client scan|plan|install|facts-check`) | Implemented, host-tested with fakes; the Windows fact provider, signature gate and ACL check are type-checked by cross-compilation only. Not validated against Windows (ledger C37 to C42). Windows servicing beyond that is not implemented |
| Xpress transport coding | Client decode verified against the real lab WSUS (inventory 9.3, validation C28). Server-side Xpress responses: host-tested, and accepted by a native Windows Update Agent once (17 of 18 and 10 of 11 SOAP responses of the 2026-10-04 runs, up to 1,125,833 decoded bytes; acceptance inferred from the agent proceeding; inventory 9.7, C28) |
| Native Windows Update client against this server | Partially validated (C31): one native agent (1507.2601.30012.0, Windows 11 25H2, lab-modified image), plain HTTP, both delivery modes, one Defender definitions bundle found, downloaded and installed (signature version `1.459.547.0`), 2026-10-04. Not validated: TLS, several or concurrent clients, approval removal or decline, deadline, uninstall, restart or key rotation under a native client, drivers, cumulative updates, any other update, an unmodified image |
| This client against a real WSUS | Not validated for the MS-WUSP client commands (the `wsus-protocol` message types, driven as a plain SOAP client, handshook, registered and synchronized 136 pages, then stopped at the 400-entry `InstalledNonLeafUpdateIDs` cap; `wsus client` was not run against a real WSUS). The MS-WSUSSS importer side is in the `admin sync` row above |
| Windows build of this binary | Cross-compiles (`task build:windows:wsus` gives `dist/wsus.exe`, x86-64 MSVC, static CRT) and `cargo xwin clippy` is clean; the binary has never been run on Windows. Not validated |

## Tests

`cargo test -p wsus-cli` runs: `tests/pair_consistency.rs` (in-process
`Transport` bridge to `WsusServer::handle`), `tests/loopback.rs` (real axum
socket, reqwest adapter), `tests/cli_binary.rs` (the compiled binary, a server
process, client and admin commands, logs, manifest), `tests/cli_surface.rs`
(command surface, configuration, redaction, permissions, diagnostics, upstream
guards), `tests/restart_recovery.rs` (own MS-WSUSSS server on loopback; staged
generation survives restart and resumes) and `tests/catalog_import.rs` (local
import, verification failures, atomic activation). Each file states in its
header that it is own-pair evidence only. `tests/install_cli.rs` drives `client
scan|plan|install|facts-check` with fake services (no Windows, no network).
