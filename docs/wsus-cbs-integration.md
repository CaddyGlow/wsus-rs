# WSUS client: installing Windows servicing (CBS) updates online

Status: DESIGN PROPOSAL, 2026-10-05. Nothing in this document has been implemented or run. No statement
below claims that online CBS installation works; the only validated install paths of the WSUS client are the
command-line handler (Defender bundle, ledger C38 to C40, C42) and the MSI handler (C41), see
[wsus-install.md](wsus-install.md).

Label convention. Every statement carries one of:

* **READ**: taken from code or documents in this repository (cited).
* **OBSERVED**: stated by a retained evidence document of this repository (cited), on the narrow scope that
  document states.
* **INFERRED / PROPOSED**: not established here. INFERRED is general Windows platform knowledge or a deduction
  that has not been checked in this repository; PROPOSED is a design choice of this document.

Companion documents: [wsus-install.md](wsus-install.md) (installing client, safety model),
[wsus-protocol-inventory.md](wsus-protocol-inventory.md) sections 12.3 and 12.10 to 12.16,
[wsus-validation.md](wsus-validation.md) (ledger),
[windows-servicing-implementation-plan.md](../../windows-uup/docs/windows-servicing-implementation-plan.md) (offline servicing engine),
[servicing-engine-selection.md](../../windows-uup/docs/servicing-engine-selection.md), [servicing-transactions.md](../../windows-uup/docs/servicing-transactions.md),
[servicing-staging.md](../../windows-uup/docs/servicing-staging.md), [servicing-snapshots.md](../../windows-uup/docs/servicing-snapshots.md),
[package-parent-applicability.md](../../windows-uup/docs/package-parent-applicability.md),
[installed-verification.md](../../windows-uup/docs/installed-verification.md).

Note on scope of the working tree: `crates/windows-cbs`, `windows-csi`, `windows-dism` carry other contributors'
uncommitted work at the time of writing. Everything cited about them is what the files contained when read; this
document asks for changes (section 6.4) and makes none.

## 1. Goal and non-goals

### 1.1 Goal

PROPOSED. Let `wsus client install` install, on the machine it runs on (online), the CBS-serviced updates a WSUS
offers, with the same discipline the client already applies to command-line and MSI updates: applicability from
the validated evaluator over live facts, a deterministic plan, payloads fetched through the verified downloader,
gates before execution, write-ahead job evidence, and a post-check that decides success by re-evaluating fresh
facts rather than by an exit code (READ: wsus-install.md, "The safety model", gate 7).

Target update classes (PROPOSED, in priority order, each to be confirmed against real metadata, section 2):

1. Servicing stack updates (SSU).
2. Cumulative updates (LCU, `Package_for_RollupFix`), including the combined SSU+LCU CAB shape.
3. .NET Framework cumulative updates delivered as CBS packages.
4. Features on Demand / language and optional-component CABs delivered as CBS packages.

### 1.2 Non-goals

* Offline image servicing. That is `windows-uup` and the servicing crates' job (READ: servicing-engine-selection.md,
  windows-servicing-implementation-plan.md). This design must not change those crates' offline contracts.
* Feature updates and OS upgrade (setup-based, `Setup.exe`, ESD/WIM payloads). Not CBS Add-Package.
* Driver INF updates (PnP, `pnputil`/DIFx). A different handler.
* Defender, Office Click-to-Run, MSI: already handled or deliberately out of scope (READ: wsus-install.md).
* Replacing the Windows servicing stack with our own staging implementation online (section 4.5 explains why not).
* Sending WUA reporting events. The client sends none today and the event ids are not established (READ:
  wsus-install.md, "What it does"; inventory 9.4). This stays out of scope here.
* Uninstall / rollback of an installed update.
* Expedited, hotpatch (baseline/hotpatch LCU), delta/express differential download negotiation beyond what
  section 2 observes. Hotpatch is a non-goal until real metadata shows its shape.

## 2. What the real metadata looks like

Status: FILLED from inventory 12.17 and `docs/fixtures/wsus-m0-cbs/` (OBSERVED 2026-10-05, lab WSUS Windows Server 2025
10.0.26100.32230, product `Windows 11`, metadata only, no content downloaded). Answers to Q1 to Q10 are in the table
below the "already known" notes. The headline change to this design: the real catalog has TWO servicing handlers, not
one. `Cbs` (180 updates: one `.cab` each, for example `Package_for_RollupFix` and `Package_for_DotNetRollup_*`) fits the
DISM and `wusa` backends proposed here. `OSInstaller` (297 updates: the monthly Windows 11 and .NET cumulative updates,
several `.cab`/`.psf`/`.wim`/`.msu` files each, up to 14.8 GB, `InitialModule="UpdateAgent.dll"`) is a different,
UUP-style installation whose execution this design does not yet cover (see Q-J in 8.3a).

What is already known from the existing evidence, to avoid re-asking:

* READ (inventory 12.10): in the two stored catalogs (client-run5, client-run6), the only `Handler` URI that occurs
  in any Extended fragment is `CommandLineInstallation`; no CBS handler occurs. The synced Microsoft catalog is therefore
  not a source of CBS handler shape.
* READ (inventory 12.3): the operator `CbsPackageInstalledByIdentity` occurs 68 times in 24 updates, and 59
  `cbs_package` fact queries exist in the real query set (inventory 12.5). Its `PackageIdentity` attribute is a CBS
  package identity string. OBSERVED that it exists; UNVERIFIED that the evaluator's reading (CurrentState 112 under
  `Component Based Servicing\Packages\<identity>`) matches the native agent: ledger C32 to C34 compared the
  evaluator with the native agent on selected updates and the reading is called Unverified in the table.
* READ (inventory 12.16): the MSI handler shape was obtained by publishing synthetic updates through the WSUS
  administration API, because the Microsoft catalog had none. The same trick is probably not available for CBS
  payloads without a real CAB (a synthetic CBS package would have to be built and signed); this is one of the
  reasons the real shape must come from the other agent's capture.
* INFERRED (from general knowledge of the WSUS schema, not checked here): CBS updates use a distinct handler URI
  and a `HandlerSpecificData` element whose type is a CBS data type, and the payload is a `.cab` (or `.msu`) plus,
  for newer LCUs, a `.psf` or express/PSFX content. These guesses must not leak into code; they are listed only to
  frame the questions.

Questions section 2 had to answer (answers follow the table):

| # | Question | Why the design needs it |
| --- | --- | --- |
| Q1 | Exact `Handler` URI and `HandlerSpecificData` `type` and element names of a real CBS update (LCU, SSU, .NET, FOD); which attributes (package identity, `InstallMode`, install/uninstall command, `RebootBehavior`) exist | parser in `handlers/` (section 5.2); decides whether the identity can be taken from metadata or only from the payload MUM |
| Q2 | Package identities: is the CBS identity (`Package_for_RollupFix~31bf3856ad364e35~amd64~~<ver>`) present in metadata, only in the CAB's `update.mum`, or both; do metadata and MUM agree | post-check must name an exact identity; offline code derives it from the MUM (`windows_cbs::packages`, READ) |
| Q3 | SSU-before-LCU: is the SSU a separate update, a prerequisite clause of the LCU, a bundle child, or embedded in a combined CAB; what do `Prerequisites` look like | the planner currently only checks prerequisites, it does not order or plan them (READ: plan.rs `prerequisites()`), section 5.3 |
| Q4 | Payload files per update: how many, names, sizes, digests (SHA-1 and SHA-256), `.cab` vs `.msu` vs `.psf`, whether Express/PSFX files appear as separate `File` entries or as separate download URLs, and what `GetExtendedUpdateInfo` returns for them | `PayloadRef`/`pick()` currently require exactly one candidate file (READ: plan.rs `pick`), which fails for multi-file updates |
| Q5 | Applicability rule operators actually used (`IsInstalled`, `IsInstallable`, `IsSuperseded`): is it `CbsPackageInstalledByIdentity`, `WindowsVersion`, `RegDword`, `Processor`, file versions; any operator marked unsupported in inventory 12.3 (`ProductReleaseVersion`, `Platform`) | evaluator facts; any Unknown refuses the plan (READ: wsus-install.md, "Unknown policy") |
| Q6 | Reboot behavior: `InstallationBehavior RebootBehavior` and `Impact` values; whether metadata declares `CanRequestReboot`/`AlwaysRequiresReboot` | job status `reboot_required`, section 5.6 |
| Q7 | Supersedence: how the LCU chain is expressed (`SupersededUpdates` lists, whether the latest LCU supersedes every older one), and what the native agent offers when an older LCU is already superseded by an installed one | planner supersedence rule is Unverified and never fired on real data except for the MSI case (READ: inventory 12.16) |
| Q8 | Content trust: what is signed (the CAB's embedded signature, a `.cat` inside, only the WSUS metadata digest), signer subject of real CBS payloads | signature gate currently embeds Authenticode only and refuses catalog-signed payloads (READ: wsus-install.md, gate 4; C40 limits), section 8.1 |
| Q9 | Download route: do CBS payloads download through the normal content route of the lab WSUS (size of one real LCU), and is the lab WSUS able to host them (disk, `UpdateServicesPackages`) | validation cost, section 7 |
| Q10 | Native agent behavior on the same update: which package identities end `Installed`, what `/Get-Packages` lists afterwards, whether the update needs a reboot | oracle, section 7.2 |


Answers (OBSERVED unless marked; fixtures `docs/fixtures/wsus-m0-cbs/`, inventory 12.17):

* Q1: handler URI `http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs`, `HandlerSpecificData type="cbs:Cbs"`
  with `<CbsData PackageIdentity="" />` (identity EMPTY on all 180); `InstallationBehavior RebootBehavior="CanRequestReboot"`
  on all 180; `UninstallationBehavior` on some. The monthly updates use `.../2016/01/UpdateHandlers/OSInstaller`,
  `type="OSInstallerMetadata"`, `<OSInstallData InitialModule="UpdateAgent.dll" />`.
* Q2: the identity is NOT in the handler data. It is only in the Core fragment's `CbsPackageApplicabilityMetadata`
  (a full package manifest, up to 47 MB). The evaluator derives
  `name~publicKeyToken~processorArchitecture~language~version` from it (Implementation decision, Unverified against a native agent).
* Q3: prerequisites appear in 5,143 revisions and bundles (`BundledUpdates` in 525) hold children of one handler each;
  how a servicing stack update is tied to a cumulative update (prerequisite clause vs separate bundle child vs
  `PatchingTypePreferred="ServicingStack"` on 231 OSInstaller updates) is NOT established.
* Q4: `Cbs`: one `.cab` (self-contained, for example 507 MB for one arm64 update). `OSInstaller`: `.cab` 2,114, `.wim` 854,
  `.psf` 698, `.msu` 173 declarations, `PatchingType="SelfContained"`, median 9.6 GB, largest 14.8 GB. Content was not downloaded.
* Q5: `CbsPackageInstalled` and `CbsPackageInstallable` (no attributes; the real names, not `CbsPackageInstalledByIdentity`),
  `ProductReleaseInstalled`, `ProductReleaseVersion`, `DeviceAttribute` (`OSSkuId`, `sku`, `OSVersion`, `ProductType`, `DL_OSVersion`,
  `IsRemoteDesktopSessionHost`, `CurrentBranch`), registry terms such as `LCUReoffer`. Evaluator state: see 12.17 (395 of 1,094 still Unknown).
* Q6: `CanRequestReboot` on all `Cbs` updates; `OSInstaller` behavior not extracted here.
* Q7: 16,664 supersedence edges over 633 revisions; how the native agent treats a superseded installed LCU is NOT established.
* Q8: not established (content not downloaded). The WSUSSS answer carries Microsoft Update CDN URLs, and the CDN scheme matches 12.14.
* Q9: the lab WSUS only serves approved and downloaded content (`GetFileLocations` URL returned 404 for unapproved content);
  hosting a real LCU needs approval and a multi-GB download.
* Q10: not established (native agent behavior on `Cbs` and `OSInstaller` updates was not observed).

Q3, Q7, Q8 and Q10 are still open, so every proposal in sections 5 and 6 about the handler parser, the payload picking and
the plan is PROPOSED against an unknown wire shape.

## 3. Existing capabilities map

All rows are READ unless a cell says OBSERVED. "Online?" answers: does the stated assumption hold when the target
is the running OS, the Windows servicing stack is live, and TrustedInstaller may be modifying the store
concurrently.

### 3.1 `windows-cbs`

Crate description: "Windows CBS package metadata, applicability, and state validation"; features `windows-native`
(default) and `rust-native` (READ: `crates/windows-cbs/Cargo.toml`, README). The README states the crate "does not
execute DISM"; native execution lives in `windows-dism`.

| Module (`crates/windows-cbs/src/`) | What it does (READ) | What an online handler needs | Assumptions | Holds online? |
| --- | --- | --- | --- | --- |
| `packages.rs` (`AssemblyIdentity::dism_identity`, `parse_package_metadata`, `inspect_cab_package`, `read_cab_manifest`, `CabPackageInspection::require_ordinary / require_psfx_forward_only`) | MUM parsing into identity, parents, preserved parent expressions; bounded CAB inspection; classifies ordinary vs Windows 10 amd64 PSFX ForwardOnly vs combined container (via `caby`) | Package identity of the payload before and after install; refuse payload shapes not understood | Pure bytes, no image. Supported container shapes are exactly the audited ones: ordinary CAB, Win10 amd64 PSFX ForwardOnly, CAB-index v1 SSU (OBSERVED: fixtures cbs-psfx-native). `.msu` is not accepted (READ: `Dism::add_verified_cab` rejects non-`.cab`) | Yes. Portable, offline-safe, no store access. Shape coverage is narrow (Win10 22H2 era fixtures, not Windows 11 24H2/25H2 LCUs; Windows 11 LCU shape is unobserved here) |
| `applicability.rs` (`evaluate_parents`, `ParentInventory`, `observed_identity`, `identity_family`) | Evaluates MUM `parent` conditions against an observed inventory: matched / not_matched / unresolved; only observed `Installed` matches; revision-check failures stay unresolved | An early, local "does this CAB even target this OS" check | Needs a `ParentInventory` with complete families; the only producer is `Dism::parent_inventory` over a MOUNTED image plus a `servicing/Packages/*.mum` enumeration (READ: package-parent-applicability.md). The docs state DISM remains the applicability authority and a parent match is not applicability | Partly. The model is pure; the inventory producer is offline-image-bound. Online, the equivalent census would be `Windows\servicing\Packages\*.mum` plus `dism /Online /Get-PackageInfo`, unwritten and unvalidated |
| `planner.rs` (`order_packages`, `AuditedPackage`) | Topological order of audited exact prerequisites against an Installed inventory; `defer_missing`; cycles rejected | Order between SSU and LCU if both are our steps | Every package is hash-bound, with `evidence` and `image_role == "install"`; dependencies are exact identities. Supersedence and pending do not satisfy | Partly. The ordering algorithm is reusable; the audit inputs (`dependencies`, `evidence`) are produced by a human/caller audit in the offline flow, not by WSUS metadata. `image_role` is meaningless online |
| `state.rs` (`PackageState`, `PackageRecord`, `verify_package_postcondition`, `verify_package_persistence`) | Typed package states (`Installed`, `InstallPending`, `UninstallPending`, `Staged`, `Superseded`, `Removed`, `Unknown`); exact-identity postcondition: `Installed` ok, `InstallPending` -> `RequiresGuestCompletion`, anything else an error | Pre/post package state | Exact identity match, no supersedence inference. `Superseded` is an error. Persistence = commit/remount, an offline concept | Types: yes. Postcondition function: only as a building block. Online an LCU's older identities become `Superseded` by design (INFERRED), so the function must be applied to the requested identity only, and the "persisted" notion maps to "after reboot" |
| `snapshot.rs`, `capture.rs` (`ImageSnapshot`, `Coverage`, `compare_snapshots`, `verify_evidence`, `load_snapshot`) | Versioned, hash-bound observations of a private applied image, explicit coverage, semantic compare, replay | A before/after comparison as evidence | Collected by `scripts/servicing/capture-image.ps1` against a private applied NTFS image; it "rejects the live Windows root and linked/reparse paths" and requires a new output directory outside the image (READ: servicing-snapshots.md). Identity fields are runner assertions (`source_sha256`, `image_index`, `lineage`) | No. The collector refuses the live root by design and the model assumes a quiescent image. Reuse only the idea (before/after + hash-bound artifacts) in a thin layer, not the types |
| `transaction.rs` (+ `transaction/windows.rs`) (`Transaction`, journal, rollback, `complete`) | Durable intent/completion journal, recovery, rollback over `windows_csi::transaction_store::ControlledStore` | Journaling and rollback of an install | The store is an engine-OWNED controlled store, "independent controlled-store plans"; "does not mutate Windows stores"; native pending execution is M7 (READ: servicing-transactions.md, transaction_store.rs header). Needs `rust-native` | No. It journals operations on a model store, not on the live component store. Using it online would give the appearance of rollback with none |
| `staging_*.rs` (`staging_input`, `staging_policy`, `staging_recipe`, `staging_source`, `staging_files`, `staging_metadata`, `staging_target`, `staging_workspace`, `staging_action`, `staging_executor`) | Rust-native staging into an offline target's COMPONENTS/SOFTWARE hives and WinSxS (private hive copies, journaled publication) | Staging a package into the store without Windows servicing | `rust-native` only; "Independent native staging is not yet admitted"; exact fixture: SSU 7714 on RTM 19041.1 Professional amd64, stage-only; publication to a real target and independent staged-package recognition remain open (READ: servicing-staging.md) | No, and unsafe online (section 4.5) |
| `servicing_plan.rs`, `manifest_input.rs` (`PackagePlan`, `CandidateAdmission`) | M2 explainable read-only plan over a replayed snapshot; reports always `executable: false` | A plan-shaped explanation | Needs a replayed snapshot of an image, pinned inputs; "Reports always set executable: false" (READ: servicing-plans.md) | No for execution. Possibly its blocker vocabulary |

### 3.2 `windows-csi`

Description: "Windows component analysis and recoverable controlled-store operations" (READ: Cargo.toml).

| Module (`crates/windows-csi/src/`) | What it does (READ) | Online need | Assumptions | Holds online? |
| --- | --- | --- | --- | --- |
| `lib.rs` (component closure: `analyze_component_closure_with_matching`, `ComponentIdentity`, `ClosureReport`) | Read-only dependency closure of expanded manifests; "does not model package applicability, installed state, winner selection, or payload availability" | Nothing at install time; at most diagnostic closure of a payload's manifests | Pinned expanded XML; DCM1/PA30 inputs need an externally pinned dictionary | Not needed |
| `inventory.rs` (`ComponentObservation`, `DeploymentObservation`, `FileObservation`, `HardlinkGroup`) | Records of captured store facts; "do not infer installed state or winners" | Optional evidence fields | Captured from an image | Types are neutral; capture is offline |
| `planning.rs` (`plan_components`, `WinnerDecision`, ...) | Component/deployment/winner planning with unresolved native policy explicit | None | Winner semantics unresolved by design | No |
| `native_keyform.rs` | ASCII component/family naming, canonical identity text, file value names; "grants no authentication or write authority" | None | Selected fixture only | No |
| `offline_hive.rs` | Prepares edits on PRIVATE COPIED hives; guarded mount mode | None | Never the live COMPONENTS hive; "does not authorize native registration or target publication" | No (and must never be pointed at the live hives) |
| `staging_path.rs` | Bounded relative store path validation, alias detection | None | ASCII-only name comparison initially | No |
| `transaction_store.rs` (feature `rust-native`) | Controlled store persistence with reservations, durable replace; Unix process-interruption guarantees, other platforms fail closed | None | Model store, not Windows | No |

### 3.3 `windows-dism`

Description: "Job-owned offline Windows DISM servicing and recovery evidence" (READ: Cargo.toml). Critical
distinction for this design, READ in `crates/windows-dism/src/lib.rs`: the crate's "native" execution is a
SUBPROCESS of `dism.exe` through `Job::run` (`job.run(OsStr::new("dism.exe"), ...)`); it does not call the DISM API
(`DismApi.dll`). Its observation side parses DISM TEXT output (`/English /Get-Packages /Format:List`).

| Item (`crates/windows-dism/src/`) | What it does (READ) | Online need | Assumptions | Holds online? |
| --- | --- | --- | --- | --- |
| `parse_package_inventory`, `parse_package_applicability`, `parse_package_state` (lib.rs) | Strict parsing of English DISM list output: rejects missing State, duplicate identities, missing "The operation completed successfully." marker; `Applicable: Yes/No` | Pre/post package state; applicability from `/Get-PackageInfo` | English output only (`/English` is always appended); cross-checked against hidden-parent omissions (Get-Packages omits hidden edition parents, OBSERVED: fixtures cbs-first) | Yes as pure parsers. They run on any `dism` text, online or offline. Note: online `/Get-Packages` output has the same record layout (INFERRED; the repo also runs `dism /Online /English` queries in the installed-verification collector, READ: installed-verification.md, with no claim that it was run on a guest in this document) |
| `observation.rs` (`decode_dism_text`, `replay_packages`, `bind_packages`, `verify_package_replay`) | Decodes DISM output bytes (UTF-16/BOM handling) and binds replayed package records to evidence | Decoding of captured DISM output | Retained artifacts | Yes for `decode_dism_text`; the replay/bind pieces serve snapshots |
| `classify_exit` | `0` Success, `3010` RebootRequired, `0x800f081e` NotApplicable, else Fatal | Exit mapping | DISM exit codes | Yes as a starting table. OBSERVED additional codes from offline trials: 14099 (`0x80073713`) and 1625 (`0x80070659`, ESU policy rejection) (fixtures cbs-psfx-native), currently Fatal |
| `Dism::preflight/mount/unmount/inventory/applicability/add_verified_cab/commit_and_verify_packages/parent_inventory/cleanup/enable_netfx3` | Image-bound operations: `owned()` requires a job-owned mount whose path equals `job.directory/mount`; all commands use `/Image:<mount>`; `add_verified_cab` accepts only `.cab`, inspects it with `windows_cbs::packages`, runs `/Add-Package` | The command lines resemble what online needs (`/Add-Package /PackagePath:`), but with `/Online` | `ensure_windows()` states: "offline DISM servicing requires a Windows x64 host; no online servicing is supported". Needs 20 GiB free, NTFS, elevated Administrator (via a `powershell.exe` probe), DISM 10.0.19041+, exclusive job directory | No for the `Dism` struct and `Job`. The online adapter must be a new thin type that shares only the parsers |
| `job.rs` (`Job`, `run`, `recover`, `status`, `MountRecord`, `HiveRecord`) | Exclusive job directory, durable mount intent, shell-free subprocess evidence with logs per operation, recovery of mounts and hives | Process execution with retained stdout/stderr/log | Mount/hive ownership model | No for mounts; the "shell-free subprocess with retained logs" idea is already in `wsus-client` (`Runner`, 64 KiB capture) |
| `inventory_replay.rs`, `registry.rs`, `appx*` | Replay of captured raw artifacts; bounded WinPE registry edits; AppX | None | Offline | No |

### 3.4 How `windows-uup` uses them (offline media)

READ: `crates/windows-uup/src/main.rs` calls `windows_cbs::snapshot::{load_snapshot, compare_snapshots}`,
`windows_dism::inventory_replay::verify_*`, `windows_cbs::capture::verify_operations` for evidence replay and
comparison; `crates/windows-uup/src/servicing_plan.rs` builds read-only plans from `windows_cbs::servicing_plan`
and `windows_csi::planning`; media builds drive `windows_dism::Dism` against job-owned mounted install images and
verify with `commit_and_verify_packages`. `crates/windows-uup/Cargo.toml` forwards `windows-native` and `rust-native`
to the three crates; the workspace declares them with `default-features = false` (READ: root `Cargo.toml`).
`EngineSelection` routes `Windows` (DISM) by default, accepts `Rust` only for advisory `Plan`, and rejects Rust
`Stage/Install/Remove/Cleanup/Configure` (READ: servicing-engine-selection.md).

What the offline flow validated natively (OBSERVED, disposable guests, offline private copies of 19041.1 and stock
22H2 images):

* Add-Package of an ordinary SSU CAB, exact identity `Installed` after commit and remount (fixtures cbs-first,
  cbs-postconditions); cleanup/ResetBase success (cbs-cleanup-boot); two clean boots, no pending state, but no
  InstallPending -> Installed transition observed.
* Native installation of SSU 5071 and the combined PSFX KB5045594 CAB (LCU `...19041.5073.1.11`) into a private
  image, committed, then two boots with the exact rollup Installed and no pending markers (cbs-psfx-native,
  "pre-ESU"). Applicability of the combined CAB reported `Multiple_Packages~~~~0.0.0.0`, State `Not Present`,
  Applicable Yes.
* Rejected trials: KB5129236 on RTM returned 14099 (0x80073713) and filled the host disk; on stock 22H2 the
  ExtendedSecurityUpdatesAI policy returned 1625 (0x80070659) (cbs-psfx-native).
* No genuine native `Install Pending` to `Installed` transition was captured; M7 of the servicing plan is the
  open item (READ: windows-servicing-implementation-plan.md, cbs-cleanup-boot README).

None of this was online. Every OBSERVED result above is "offline image serviced by DISM in a guest".

### 3.5 Summary of what the existing crates cannot give an online handler

1. A way to talk to the live servicing stack (the `Dism` struct is mount-bound; `ensure_windows` refuses online).
2. An online package census (hidden families, `servicing\Packages` listing) and online applicability.
3. Pending/reboot semantics (M7 open).
4. Any safe store mutation (`rust-native` staging is not admitted even offline).

What they do give: payload shape classification (`packages.rs`), strict DISM text parsers, a state vocabulary,
an exit-code starting table, an ordering algorithm, evidence-binding habits, and, as research, a catalog of failure
codes seen in real servicing.

## 4. Execution options for the online install

Common context. INFERRED unless noted: the Windows servicing stack (CBS, `TrustedInstaller.exe`, `CbsCore.dll`,
`wcp.dll`) owns the component store; clients request operations through it; it serializes operations with a
servicing session lock and may defer part of the work to the next boot (`pending.xml`, `SessionsPending`). The
installed servicing stack version determines what packages it can install (a newer LCU may need a newer SSU:
ledger-free fact, OBSERVED offline only through the rejection trials above). The client already requires an elevated
token (READ: executor gate 5, "Elevation is checked before anything is downloaded") and has been run as SYSTEM on
the lab guest (READ: wsus-install.md guest run).

### 4.1 Option (a): `dism.exe /Online /Add-Package` or the DISM API

* Mechanism. Subprocess: `dism.exe /Online /English /NoRestart /LogPath:<file> /Add-Package /PackagePath:<cab>`.
  The DISM API (`DismApi.dll`: `DismInitialize`, `DismOpenSession(DISM_ONLINE_IMAGE)`, `DismAddPackage`) is the
  in-process equivalent (INFERRED). The repo's `windows-dism` uses only the subprocess (READ).
* Privileges. Elevated Administrator; DISM runs the operation by contacting TrustedInstaller (INFERRED). SYSTEM
  works (the client runs as SYSTEM on the lab guest for other handlers, OBSERVED, inventory 12.16).
* Servicing stack dependency. DISM uses the OS's own CBS; no extra dependency on our side. The DISM binary version
  is a separate matter: the offline adapter requires DISM 10.0.19041 or newer (READ: `preflight`).
* SSU ordering. DISM does not reorder separate packages; each `/Add-Package` is one call (INFERRED). A combined SSU+LCU
  CAB is accepted by DISM as one container (OBSERVED offline: KB5045594, aggregate applicability
  `Multiple_Packages~~~~0.0.0.0`).
* Reboot / pending. `/NoRestart` is already always passed by the adapter (READ). Exit `3010` means reboot required
  (READ: `classify_exit`). After the call, `/Get-Packages` shows `Install Pending` when completion needs a reboot
  (READ: `PackageState::InstallPending` and the offline docs' note that pending requires guest verification).
* Idempotence. Re-adding an installed package is a no-op or an error depending on state (INFERRED, to be observed);
  our plan avoids it by re-evaluating first (existing behavior).
* Timeouts. LCU installs can take many minutes; offline trials took 4 to 6 minutes per test including mount
  (OBSERVED: 221 to 337 s totals in cbs-postconditions, cbs-second). The existing default `timeout_secs = 1800`
  per process (READ: wsus-install.md) is a reasonable start; killing DISM mid-operation is dangerous
  (the "process tree is not killed" caveat, READ, becomes a feature: do not kill on timeout, mark `unconfirmed`).
* Results. Exit code + `dism.log` (`/LogPath`) + `%WINDIR%\Logs\CBS\CBS.log` + post-state via `/Get-Packages` and
  `/Get-PackageInfo`. The repo already has strict parsers for the text (READ). Failure HRESULTs are in the output.
* Risks. A hung or killed servicing operation leaves the store in a state the stack must repair at next boot
  (INFERRED). Concurrent operations by the native WUA/TrustedInstaller block or fail with an error such as
  `0x800f0902`/`0x800f0922` family (INFERRED, to be observed; exact codes must be captured, not assumed).
  Text parsing is locale-fragile (the adapter forces `/English`, READ).
* Fit. Best match with existing code and evidence: same command family as the validated offline trials, same
  parsers. DISM API avoids text parsing but adds an unsafe FFI surface and no existing code or evidence; defer.

### 4.2 Option (b): PowerShell `Add-WindowsPackage -Online`

* Mechanism. `powershell.exe -NoProfile -Command Add-WindowsPackage -Online -PackagePath ... -NoRestart` (INFERRED:
  wraps the DISM API; returns objects with `RestartNeeded`). Output is structured objects, avoiding text parsing.
* Privileges, stack dependency, ordering, idempotence: as (a) (INFERRED).
* Risks. Adds a PowerShell host (execution policy, profile, module autoload, Constrained Language Mode on locked
  machines) to the trust path of an installer that runs elevated; the client otherwise avoids any shell (READ:
  wsus-install.md gate 1, "No shell is used"). The repo's offline collector scripts run PowerShell with
  process-local bypass (READ: cbs-cleanup-boot README), but only on disposable guests.
* Results. Terminating errors with HRESULT; `RestartNeeded` property. Needs a JSON conversion layer.
* Fit. Not recommended as a backend; useful as an OBSERVATION oracle during validation (section 7.2).

### 4.3 Option (c): `wusa.exe` for `.msu`

* Mechanism. `wusa.exe <file>.msu /quiet /norestart` (INFERRED); `.msu` is the standalone-installer wrapper that
  is typically what the Catalog serves. WSUS content for CBS updates may be `.cab` rather than `.msu` (Q4).
* Privileges. Elevated; WUSA uses the Windows Update service (`wuauserv`) and the standalone installer (INFERRED).
* Servicing stack dependency. Via the installed Windows Update Standalone Installer, which in turn uses CBS.
* SSU ordering. An `.msu` for a combined LCU may carry its own SSU (INFERRED); several `.msu` need explicit order.
* Reboot. Exit codes `3010` (reboot required), `2359302` (`0x00240006`, already installed), `2359303`
  (`0x00240007`, not applicable) (INFERRED from general knowledge; none is in the repo, must be observed).
* Idempotence. WUSA reports already-installed with a distinct code (INFERRED).
* Timeouts. WUSA returns when the installer service finishes its part; completion may continue in the background
  (INFERRED), so exit code is even weaker evidence than for DISM; the post-check wait matters.
* Results. Exit code; `wusa` events in the event log (`Microsoft-Windows-WUSA`), `CBS.log`, `WindowsUpdate.log`.
* Risks. A hidden dependency on `wuauserv` and the Windows Update client's own state and policies, which on a
  WSUS-managed machine is exactly the client we are replacing/driving; it can collide with our own download/scan
  flow. No `.msu` support in the existing offline code (READ: `add_verified_cab` rejects non-CAB, "direct MSU ...
  require further audit").
* Fit. Second backend, only if real payloads are `.msu` (Q4). Needs its own exit-code table captured on a guest.

### 4.4 Option (d): `pkgmgr` / TrustedInstaller CBS COM interfaces

* Mechanism. `pkgmgr.exe /ip /m:<cab>` is the legacy servicing front end (deprecated; INFERRED); the CBS COM/RPC
  interfaces (`CbsSession`, `ICbsSession` via `CbsApi.dll`) are undocumented and internal (INFERRED).
* Risks. Undocumented and unsupported interfaces whose layout changes between builds (INFERRED). The repo's own
  reverse engineering of CBS (research under `cbss-research/`, referenced from windows-servicing-implementation-plan.md)
  targets the OFFLINE data model (hive formats, key forms) for the Rust engine, not an online session API.
* Fit. Do not use. Revisit only if (a) proves insufficient and only with explicit research evidence.

### 4.5 Option (e): our own staging into the live component store (the `rust-native` path)

Why this is unsafe online, and must stay excluded from this design:

1. READ: independent native staging "is not yet admitted" even offline; scope is one exact SSU on one exact RTM
   fixture, "stage-only"; "Native publication to a real target" and "independent staged-package recognition"
   remain open (servicing-staging.md). `servicing-engine-selection.md` rejects Rust `Stage/Install` in routing.
2. READ: the transaction backend is "an engine-owned controlled store" and states the native hive formats, WinSxS
   publication, NTFS projection and boot execution "are admitted in later milestones" (servicing-transactions.md).
   Its crash-recovery evidence covers subprocess termination on a Unix-validated store, with abrupt power loss and
   native Windows durability explicitly not claimed.
3. READ: `offline_hive` works on private copied hives; the live COMPONENTS/SOFTWARE hives are loaded by the
   servicing stack and protected. The M4 executor's recovery models "foreign state" from an unrelated writer as a
   recovery-required event; online, TrustedInstaller and the Windows Update stack are exactly such concurrent writers.
4. READ: M5 (file projection, winners, ownership), M6 (registry/component configuration), M7 (pending actions and
   reboot recovery) are all open (windows-servicing-implementation-plan.md). Staging alone would leave
   `Staged` packages, never `Installed`; OBSERVED that DISM's own answer-file stage action yields `Staged` with no
   install time (servicing-staging.md).
5. INFERRED: a wrong write to the live component store is the classic way to brick a machine (an unservicing OS:
   `0x800f0831`/`0x80073712` families), and there is no offline rollback when the OS is running from that store.
6. M4 validation gaps that remain (READ: servicing-staging.md): durable Windows journal and store publication,
   restart/remount recognition, interrupted staging recovery without orphaned references or unowned files,
   Unicode name behavior, and an executed (not static) trust branch inside WCP; plus M5 to M8 above.

Conclusion: option (e) is a research track on disposable offline images; it is not an online execution option now
and this document sets no schedule for it. The first admissible use would be an offline target, not the running OS.

### 4.6 Comparison

| | (a) DISM subprocess | (a') DISM API | (b) PowerShell | (c) wusa | (d) pkgmgr/COM | (e) own staging |
| --- | --- | --- | --- | --- | --- | --- |
| Supported by Microsoft (INFERRED) | yes | yes | yes | yes | no | no |
| Existing code to reuse | parsers, exit table, payload inspection | none | none | none | none | much, but unsafe |
| Existing evidence | offline native trials | none | none | none | none | offline private only |
| Result channel | exit + text + logs | HRESULT + structs | objects | exit + events | n/a | n/a |
| Extra trust surface | `dism.exe` | `DismApi.dll` FFI | PowerShell host | `wuauserv` | undocumented | our writer |
| Handles combined SSU+LCU CAB | yes offline | likely | likely | for `.msu` | n/a | no |
| Recommended | PRIMARY backend | later | observation only | optional, if `.msu` | no | no |

### 4.7 Cross-cutting facts every option shares (INFERRED, each must be observed on the guest)

* Pending state sources to read after any option: `Windows\WinSxS\pending.xml`; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
  `...\RebootInProgress`, `...\SessionsPending`, `...\PackagesPending`; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`;
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`. The repository's own
  `observe-installed` collector already "captures pending-operation indicators" and treats any pending package or
  indicator as a failure (READ: installed-verification.md); its exact key list is the in-repo source to reuse (read
  the collector before fixing this list; the keys above are not verified against it).
* Servicing is serialized: a second servicing client waits or fails while one session is active. The client must
  hold its own lock (the existing `jobs/install.lock`, READ) and additionally tolerate "busy" errors from the
  stack with bounded retry, never by killing other processes.
* The servicing stack version is a prerequisite fact: an LCU may require an SSU level (OBSERVED offline: baseline
  with SSU 7714 was the working precondition for the PSFX trials; the RTM trial still failed with 14099 for an
  unestablished reason). Treat "SSU version at least X" as an applicability fact, not as something to bypass.

## 5. Proposed architecture

PROPOSED throughout. Design rule: add a handler beside `command_line` and `msi`, keep the plan/executor/job
contracts, add only what CBS needs, gate the whole thing behind a Cargo feature.

### 5.1 Module layout (`crates/wsus-client/src/install/`)

```text
handlers/cbs.rs          typed CbsSpec parsed from Extended (feature "cbs-handler")
servicing/mod.rs         ServicingBackend trait, PackageSnapshot, ServicingResult, errors
servicing/fake.rs        FakeBackend (host tests, scripted package states and outcomes)
servicing/dism.rs        DismBackend (windows only): runs dism.exe through the existing Runner seam
servicing/wusa.rs        WusaBackend (windows only, later, only if payloads are .msu)
servicing/state.rs       PackageState <-> registry CurrentState mapping, pending-indicator probe (windows)
```

`HandlerSpec` gains a `Cbs(CbsSpec)` variant (serde tag `"cbs"`) behind the feature, exactly as `Msi` is behind
`msi-handler` (READ: handlers/mod.rs). `HandlerSpec::kind/classify` are extended; `classify` for CBS maps the
BACKEND's native code (DISM exit or HRESULT), not a `ReturnCode` list.

### 5.2 `CbsSpec` (what the plan carries)

Fields (PROPOSED; names depend on Q1 to Q4):

* `identity`: the exact CBS package identity the post-check must see `Installed`, taken from metadata if present
  (Q2) and otherwise from the payload's `update.mum` using `windows_cbs::packages::parse_package_metadata` after
  download (this check happens at gate time, not plan time, because the plan cannot read an undownloaded file;
  the plan then records `identity: None` and the executor refuses if the MUM identity is not what metadata or a
  pinned policy allows).
* `container`: `Ordinary | PsfxForwardOnly | Combined | Msu | Unsupported`, from `inspect_cab_package` at gate time.
* `files`: ordered payload list (Q4), not just one `PayloadRef`. `InstallStep.payload` is a single `PayloadRef`
  today (READ: plan.rs); CBS needs `payloads: Vec<PayloadRef>` or a main payload plus `extra_payloads`. This is a
  schema change to `wsus-install-plan/1` (bump to `/2` with an adapter that keeps `/1` plans readable).
* `reboot`: the metadata's declared behavior (Q6) as an informational field; execution result decides.
* `min_servicing_stack`: only if Q3/Q5 show it in metadata; otherwise absent and covered by DISM applicability.

Parsing refuses anything not understood (same fail-closed rule as `HandlerError::UnsupportedHandler`, READ).

### 5.3 What the plan decides

Existing behavior (READ: plan.rs header and `visit`): decide per node `IsInstallable`, `IsInstalled`,
prerequisite clauses (satisfied only when an alternative evaluates `IsInstalled` True; "a category is not
followed deeper"), supersedence (Unverified), bundle clauses; Unknown refuses the plan; one `InstallStep` per
qualifying installer in metadata order; steps are NOT reordered by prerequisites.

CBS-specific decisions to add:

1. Order. When an LCU's prerequisite clause names an SSU update that is itself an installable CBS node, plan the
   SSU as an earlier step (topological order over prerequisite edges among planned installers) instead of
   declaring the LCU not installable. This is a change to the planner's meaning of prerequisites for ALL handlers
   and so needs a flag (`plan_prerequisites`, default off) so the Defender and MSI plans stay byte-identical
   (their determinism is validated, C38). Reuse the algorithm of `windows_cbs::planner::order_packages` only if its
   input type (`AuditedPackage`, requiring SHA-256, evidence, `image_role`) is generalized (request in 6.4); else a
   ten-line local topological sort.
2. Reboot barrier between steps. If a step's backend result is `reboot_required` and the next step depends on its
   completion (an LCU after an SSU that must finalize), the run STOPS after the first step with status
   `reboot_required` and a `remaining_steps` list; a resumed job continues (5.6). Whether an SSU needs a reboot
   before the LCU is Q3/Q10 evidence; the default is conservative: stop at the first `reboot_required`.
3. Applicability via the evaluator facts, including CBS state facts: `CbsPackageInstalledByIdentity` over
   `WindowsFacts::cbs_package` (READ: facts_windows.rs reads `CurrentState` under
   `...\Component Based Servicing\Packages\<identity>`, Known(u32)/Absent/Unavailable; `CBS_STATE_INSTALLED = 112`).
   For SSU/LCU the `IsInstalled` rule is the success criterion (5.5). Applicability that depends on operators
   listed unsupported in 12.3 refuses the plan (`Unknown` policy), which is the safe default.
4. Supersedence. Reuse the existing Unverified rule (skip an installer when another stored update that lists it in
   `SupersededUpdates` evaluates installed) but treat it as ADVISORY for CBS: before executing, the backend asks
   DISM `/Get-PackageInfo /PackagePath` for the payload (Applicable Yes/No, READ: `parse_package_applicability`).
   `Applicable: No` with exit `0x800f081e` (READ: `Outcome::NotApplicable`) maps to step result `not_applicable`
   and, if the evaluator also disagrees, the plan is refused (conflicting oracles). Any disagreement between
   the evaluator and DISM is evidence, never auto-resolved.
5. One target at a time. LCU chains are cumulative: install only the highest applicable revision per product
   (the plan's per-update `Install` decisions on superseded LCUs must be `NotApplicable`, Q7). A plan with two LCUs
   for the same `Package_for_RollupFix` family is refused.

### 5.4 `ServicingBackend` trait (PROPOSED)

```text
trait ServicingBackend {
    /// All packages the servicing stack lists, strict-parsed (windows_dism::parse_package_inventory).
    fn list_packages(&self) -> Result<PackageSnapshot, BackendError>;
    /// Applicability of a payload (windows_dism::parse_package_applicability).
    fn payload_applicability(&self, payload: &Path) -> Result<Applicability, BackendError>;
    /// Pending-reboot indicators (registry, pending.xml), evidence only.
    fn pending_indicators(&self) -> Result<PendingIndicators, BackendError>;
    /// Install one payload. Never reboots. Returns the native code and log paths.
    fn add_package(&self, payload: &Path, log_dir: &Path, timeout: Duration)
        -> Result<ServicingResult, BackendError>;
}
```

`ServicingResult { native_code: u32, class: Success|Reboot|NotApplicable|Failed|Busy, stdout_tail,
stderr_tail, log_paths: Vec<PathBuf>, timed_out }`. Properties:

* `FakeBackend`: scripted `PackageSnapshot` sequence and `add_package` results, so the executor path
  (write-ahead, reboot stop, post-check wait, refusal) is host-testable on Linux, like `FakeRunner` and
  `FakeVerifier` today (READ: runner.rs, testkit.rs).
* `DismBackend` (Windows): implemented on the existing `Runner` trait so the process hardening, output cap and
  timeout stay in one place: program `%SystemRoot%\System32\dism.exe` resolved from the system directory (as the MSI
  handler resolves `msiexec`, READ: `MsiSpec::program(system_dir)`), arguments as a vector (never a shell), always
  `/English`, `/NoRestart`, `/LogPath:<job dir>\dism-<step>.log`, `/Online`. Output decoded by
  `windows_dism::observation::decode_dism_text` and parsed by `windows_dism::parse_*`.
* `WusaBackend`: same seam, only if Q4 says `.msu`.
* Where does `Runner` fit: the existing executor builds a `Prepared` command from the step and runs it; for CBS the
  executor instead calls the backend at the same point of the write-ahead protocol (state `Started` is persisted
  before the call). `prepare_command` stays for command-line and MSI.

### 5.5 What the executor records and how success is decided

Gates (READ, wsus-install.md safety model) apply before the backend runs, with CBS-specific meaning:

1. Handler parsing: `CbsSpec` valid, payload file name plain, inside the verified store.
2. Path/ACL: unchanged (store not writable by Everyone/Users).
3. Digest: every digest in the plan recomputed over the share-denied handle immediately before execution. The
   DISM process must then read that same file; the open handle is held across the call (as today). A TOCTOU
   window remains between handle and DISM's own open for any shared-read design; the handle denies writers, so
   it is closed (READ: share mode read only, "denies writers and deleters").
4. Signature: see 8.1; the current embedded-Authenticode gate may refuse real CBS payloads. This is a blocker to
   resolve with Q8, not something to relax silently.
5. Payload identity check (new): `inspect_cab_package` classifies the container; unsupported shapes are refused.
   For Win10 amd64 PSFX ForwardOnly and ordinary CAB shapes only (the audited ones, READ). The Windows 11 LCU
   shape is unobserved here: refuse until a fixture exists.
6. Pre-state: `list_packages` + `pending_indicators` BEFORE the first step; if pending reboot already exists,
   refuse (the servicing stack will not install over a pending operation reliably; INFERRED) with a message
   saying reboot first. Pre-state is stored in the job record.
7. Applicability: `payload_applicability` before `add_package`; `Applicable: No` stops with `not_applicable`.

Job record additions (schema `wsus-install-job/1` -> `/2`, all `#[serde(default)]` so `/1` records stay readable,
READ: existing record fields):

| Field | Content | Why |
| --- | --- | --- |
| `step.servicing` | `{ backend, native_code, class, applicable, container, identity_expected, identity_from_mum }` | distinguish exit code from state |
| `step.log_paths` | job-local copies or hashes of `dism.log`; paths of `%WINDIR%\Logs\CBS\CBS.log` and the byte range of this run (mark offsets before and after, like `handler_log::mark`/`read_excerpt`, READ) | evidence; CBS.log is large and shared, record offsets and a bounded excerpt (64 KiB cap exists) |
| `servicing.pre` / `servicing.post` | `Vec<PackageRecord>` for the expected identity and the changed set (full lists hashed with SHA-256 and stored as files in the job directory), plus `PendingIndicators` | before/after, hash-bound; reuses `windows_cbs::state::PackageRecord` |
| `servicing.diff` | records added/changed between pre and post (exact identity compare, case-insensitive as `state.rs` does) | evidence of side effects (older identities `Superseded`) |
| `servicing.ssu_version` | servicing stack version before/after (file version of `TrustedInstaller.exe` or `CbsCore.dll`; INFERRED source) | SSU effect evidence |
| `reboot` | `{ required: bool, indicators: PendingIndicators, boot_id_before }` | resume support (5.6) |
| `post_check` | existing `PostCheck` plus `package_state: Vec<PackageRecord>` for the expected identities | success criterion evidence |

Evidence rules unchanged: no signed URLs (the downloader's concern), redacted program paths, bounded tails.

Success criterion (PROPOSED, mirrors C42): `succeeded` iff, after the last step and (if no reboot was
requested) waiting up to `post_check_wait_secs`, BOTH:

* the evaluator over FRESH live facts says every executed update is `installed` (its `IsInstalled` rule, which for
  CBS updates is expected to involve `CbsPackageInstalledByIdentity`, Q5), and
* the independent package listing says the expected identity is `Installed` (`verify_package_postcondition`
  returns `Installed`, READ), with no unexpected `Install Pending`.

Mapping of the two oracles to job status:

| Evaluator | DISM listing | Pending indicators | Job status |
| --- | --- | --- | --- |
| installed | `Installed` | none | `succeeded` |
| not installed / unknown | `InstallPending` (`RequiresGuestCompletion`) | reboot indicator set | `reboot_required` |
| installed | `Installed` | reboot indicator set (other cause) | `succeeded` with note `reboot_pending_other` (do not claim) |
| not installed | `Installed` | any | `unconfirmed` (oracles disagree: the evaluator's CBS reading is Unverified; this case is evidence for fixing it) |
| installed | not `Installed` | any | `unconfirmed` (never `succeeded` on a single oracle) |
| any | `Superseded`/`Removed`/`Unknown(_)`/absent | any | `unconfirmed`, or `failed` if the native code was a failure |

### 5.6 Reboot handling and resume after reboot

Today (READ): `reboot_required` is a terminal job status; no wait; the evaluator "may not say installed before the
reboot"; a re-run plans again from facts and is idempotent, interrupted jobs are marked `interrupted`
(wsus-install.md, "Job record and recovery"). That model already suffices for single-step installs; CBS adds the
multi-step case and the "pending completes at boot" case.

PROPOSED:

* New status `awaiting_reboot` distinct from `reboot_required`? Keep `reboot_required` and add `remaining_steps`
  to the record instead; fewer states, same meaning.
* `wsus client install --update X --yes` after the reboot: the planner re-evaluates from fresh facts. Steps that
  completed drop out (the evaluator says installed) and the remaining ones are planned, exactly the existing
  idempotence argument. Add a `--resume <job-id>` convenience that only (a) checks `boot_id` changed (INFERRED
  source: the boot time from `GetTickCount64`/`NtQuerySystemInformation`, to be chosen), (b) runs a post-check
  wait for the previous job's executed updates and appends the result to a new job record linked by
  `resumed_from`, and (c) never executes a step without a fresh plan.
* No scheduling across reboot by us (no RunOnce key, no service) in the first milestones: the operator or an outer
  automation reruns after reboot. A resume service is a later decision (section 8.3, Q-D).
* Never trigger the reboot ourselves. The client reports `reboot_required` and stops; policy is the operator's.
* INFERRED: after the reboot the pending operation finalizes during boot ("Working on updates" phase) and the
  package turns `Installed`; this transition is exactly the one NOT observed even offline (READ: cbs-cleanup-boot
  README), so the online resume path needs its own guest observation (V6, section 7).

### 5.7 Failure mapping

Backend native code -> `ExitClass` (existing `Success | Reboot | Failed`) and a new informational `reason`
string; `classify` stays pure.

| Native result | Class | Job effect |
| --- | --- | --- |
| DISM `0` | Success (to be confirmed by post-check) | continue |
| `3010` (also `ERROR_SUCCESS_REBOOT_REQUIRED`) | Reboot | stop run after this step, status `reboot_required` |
| `0x800f081e` | not applicable (READ: `Outcome::NotApplicable`) | step `refused`/`not_applicable`; no mutation expected; plan marked stale |
| `0x80070659` (1625), ESU/policy rejection (OBSERVED offline) | Failed, reason `policy_rejected` | do not retry |
| `0x80073713` (14099) (OBSERVED offline) | Failed | stop; keep logs; do not auto-retry (a retry after a failed servicing operation can worsen state, INFERRED) |
| Busy/another servicing session, codes TO BE OBSERVED | Failed, reason `busy`, retryable by re-running | no mutation occurred (INFERRED; verify with pre/post diff) |
| Timeout | Failed, `timed_out` | DO NOT kill DISM (deviation from the current runner, which kills on expiry): leave running, record `unconfirmed`, require operator inspection; this needs a runner option `kill_on_timeout=false` |
| Backend cannot start (dism missing, not elevated, not x64 native) | refused before any step | no mutation |
| Anything unlisted | Failed (fail closed, as `DefaultResult="Failed"`, READ) | stop |

Failure never triggers our own rollback. If a failed servicing operation leaves the store inconsistent, the
repair path is Windows' own (`dism /Online /Cleanup-Image /RestoreHealth`, INFERRED) and out of the client's
authority; the client records the pre/post state and the log ranges so an operator can act.

## 6. Reuse decision table

### 6.1 Decisions

| Component | Decision | Reason |
| --- | --- | --- |
| `windows_dism::parse_package_inventory`, `parse_package_applicability`, `parse_package_state` | Reuse as-is (pure functions; need an accessible, Linux-buildable path) | strict, tested against real offline output; online layout believed identical (INFERRED, verify on guest) |
| `windows_dism::observation::decode_dism_text` | Reuse as-is | byte decoding of DISM output |
| `windows_dism::classify_exit` | Reuse with a new thin layer | extend with observed codes (1625, 14099, busy codes); keep the fail-closed `Fatal` default |
| `windows_cbs::state::{PackageState, PackageRecord, verify_package_postcondition}` | Reuse as-is for types; function used for the requested identity only | `Superseded` handling is offline-oriented; do not apply to the whole inventory |
| `windows_cbs::packages::{inspect_cab_package, parse_package_metadata, AssemblyIdentity::dism_identity}` | Reuse as-is | payload shape gate and identity from MUM; pure; audited shapes only |
| `windows_cbs::planner::order_packages` | Reuse with a new thin layer (or local sort) | needs `AuditedPackage` fields that WSUS metadata cannot supply |
| `windows_cbs::applicability::evaluate_parents` | Do not use for the install decision; optionally as an advisory trace | needs an offline-image `ParentInventory`; WSUS rules plus DISM `Applicable` are the authorities; docs say a parent match is not applicability |
| `windows_dism::Dism` (all methods), `Job`, `MountRecord`, `HiveRecord`, `recover` | Do not reuse | mount/hive ownership model; `ensure_windows` refuses online; `owned()` requires a job mount; NTFS and 20 GiB preflight irrelevant |
| `windows_dism::job::Job::run` idea (shell-free subprocess, logs) | Already provided by `wsus-client` `Runner` | do not add a second runner |
| `windows_cbs::snapshot`, `capture`, `windows_dism::inventory_replay`, `scripts/servicing/capture-image.ps1` | Do not reuse for the install; reuse the PATTERN (hash-bound artifacts) | designed for private applied images; the collector refuses the live root |
| `windows_cbs::transaction`, `windows_csi::transaction_store` | Do not reuse | model store; gives false rollback assurance online |
| `windows_cbs::staging_*`, `windows_csi::offline_hive`, `native_keyform`, `staging_path` | Do not reuse | unsafe online (4.5); not admitted offline either |
| `windows_cbs::servicing_plan`, `manifest_input`, `windows_csi::planning`, closure | Do not reuse | offline M2 reporting, `executable: false` |
| `windows_uup::servicing_engine::EngineSelection` | Do not reuse as-is; mirror its principle | "routing never silently switches engines", `mark_mutation_intent`: adopt the same refusal to fall back after mutation intent |
| `observe-installed` collector / `verify-installed` (windows-uup, installed-verification.md) | Reuse the pending-indicator list and the evidence discipline; do not link the code (it lives in the CLI crate) | closest in-repo online DISM observation |
| `wintrust` crate | Candidate, not now | verifies catalog-signed members under a portable policy; could verify the inner catalog of a CBS CAB (section 8.1) but is not wired to a WSUS trust root |
| wsus-client existing pieces: `download` (verified store), gates `safety`/`signature`/`store`, `JobStore` + lock, `Runner`, `Executor` write-ahead, `PostCheck` waiting, `facts_windows` | Reuse as-is | validated for command-line and MSI (C39 to C42) |

### 6.2 Dependency impact and feature gating

READ today: `wsus-client` depends on `wsus-protocol`, `caby`, `serde`, `uuid`, `thiserror`, `sha2`, and on Windows
`windows-sys`; its only feature is `msi-handler`, off by default, plus `reqwest-async` (Cargo.toml). The servicing
crates are heavier: `windows-cbs` pulls `windows-csi`, `windows-delta`, `caby`, `wintrust`, `roxmltree`, `tempfile`,
`anyhow`; `windows-dism` pulls `regf-rs` (windows-native), `cpcopy`, `fs2`.

PROPOSED:

* New feature `cbs-handler = ["dep:windows-cbs", "dep:windows-dism"]`, off by default, with both deps declared
  `default-features = false` (the workspace already does this, READ: root `Cargo.toml`), so Linux builds neither
  `windows-native` nor `rust-native` code: no `regf-rs`, no CSI transaction store.
* All Windows-only code (`servicing/dism.rs`, `servicing/state.rs` registry probe) under `#[cfg(windows)]`, exactly
  like `facts_windows.rs` and `signature_windows.rs` (READ: install/mod.rs). On Linux the feature compiles
  `handlers/cbs.rs`, the trait, the fake backend and the parsers, so plan and job logic are host-testable.
* Without the feature, `wsus-client` must build and its existing tests and `plan` bytes must not change. A CBS
  update then yields the existing `UnsupportedHandler` blocker (fail closed, READ).
* Cycle check: `windows-cbs`/`windows-dism` do not depend on `wsus-*` (READ: their Cargo.toml). No cycle.
* Compile cost and attack surface: the feature pulls `wintrust`, `windows-delta`, `caby` into the installer
  binary even if only `packages.rs` and the DISM parsers are used. Prefer requesting a lighter seam (6.4 R1).
* Build task: add `task build:windows:wsus:cbs` beside `build:windows:wsus:msi` (READ: wsus-install.md names the
  latter) producing `dist/wsus-cbs.exe`; keep the default `wsus.exe` free of the feature until validated.
* The manifest requirement from C37 applies (a Windows binary reading versions needs the embedded
  `wsus.exe.manifest`, READ: inventory 12.10 guest run); `dism.exe` is a separate process and unaffected.

### 6.3 Test-level reuse

Existing real DISM outputs under `docs/fixtures/cbs-*` (READ: `before.stdout`, `after.stdout`,
`applicability.stdout`, `aggregate-applicability.stdout`, `before_commit.stdout`, `after_remount.stdout`) are real
inputs for host tests of `parse_package_inventory`/`parse_package_applicability` inside `wsus-client`, giving the
fake backend realistic transcripts without a guest. They are offline-image outputs; online transcripts must be
added as new fixtures.

### 6.4 Requests to the servicing crates' owner (not done here)

* R1. Provide a light, Linux-buildable seam that exports the DISM text parsers and exit table without the
  mount/job code: e.g. move `parse_package_inventory`, `parse_package_applicability`, `parse_package_state`,
  `classify_exit` into `windows-cbs::state` (or a new `windows-dism-text` crate) and re-export from
  `windows-dism`, so `wsus-client` need not depend on `windows-dism`'s `cpcopy`/`regf-rs`.
* R2. Generalize `AuditedPackage` / `order_packages` so `sha256`, `evidence` and `image_role` are not mandatory for
  non-offline callers (or add a dependency-only ordering function).
* R3. A statement in `windows-dism` docs that `ensure_windows()`'s "no online servicing is supported" is deliberate
  and which parts (parsers, exit table) are valid for online use; today the rule is in an error string only.
* R4. Extend `classify_exit` and `Outcome` with the observed codes (1625 `0x80070659`, 14099 `0x80073713`) and a
  `Busy` class once observed; keep `Fatal` as the fail-closed default.
* R5. Record in `windows-cbs::state` the numeric `CurrentState` to `PackageState` mapping once it is observed
  (the evaluator uses 112 as installed, READ: facts.rs; other values are unlabelled). A single owner for that table
  avoids two interpretations (registry vs DISM text).
* R6. Online parent/family census: if `evaluate_parents` is to serve online use, a `ParentInventory` producer over
  the live servicing store with explicit completeness evidence (today only `Dism::parent_inventory` over a mount).
* R7. Win11 LCU shape support in `inspect_cab_package` (current fixtures are Windows 10 amd64 PSFX ForwardOnly).
* R8. A statement of the stability contract of `PackageRecord`/`PackageState` serialization, since job records will
  persist it.

## 7. Validation plan

All guest steps use a disposable Windows 11 guest from the lab (READ: wsus-install.md; the `vm-runner` setup is
the user's lab) reverted between scenarios. Nothing below has been run.

### 7.1 Scenarios (V-numbers are proposals)

| V | Scenario | Needs | Pass criterion |
| --- | --- | --- | --- |
| V0 | Observation only: on the guest, record `dism /Online /English /Get-Packages /Format:List`, `Get-PackageInfo`, the CBS registry keys, pending indicators, SSU file version; compare `WindowsFacts::cbs_package` against DISM state for N packages | guest, existing `wsus.exe facts-check` extended | evaluator state mapping (112 etc.) agrees with DISM text for every sampled package; produces the `CurrentState` table (R5) |
| V1 | Parse-only: feed real online DISM transcripts to the parsers | V0 output | zero parse rejections, or each rejection explained |
| V2 | Dry run on the guest: `scan`, `plan`, `install` (no `--yes`) of a real SSU/LCU offered by the lab WSUS | metadata fixtures (section 2), real WSUS | plan shape equals the expected steps, no download |
| V3 | Real SSU install through the WSUS content route, `--yes` | the real SSU payload on the lab WSUS (size tens of MB, INFERRED), one guest | job `succeeded` or `reboot_required` with the correct oracle table row; package listing diff recorded |
| V4 | Real LCU install | the real LCU payload (hundreds of MB to over 1 GB for Windows 11 LCUs, INFERRED; plus WSUS disk and sync/transfer time, Q9) | as V3; time recorded: offline trials took 4 to 6 minutes including mounts (OBSERVED), online with reboot expected longer |
| V5 | Combined SSU+LCU, and separate SSU then LCU with a reboot between | V3/V4 payloads | order honored, reboot barrier honored |
| V6 | Resume after reboot: `reboot_required` job, reboot, rerun | V4 | the pending package becomes `Installed` (first observation of this transition for the project, READ: not observed offline), plan `nothing_to_do_installed`, job `no_action` |
| V7 | Idempotence: rerun after success | V3/V4 | `no_action` |
| V8 | Oracle comparison: a second, identical guest updates through native WUA from the SAME WSUS | two guests | resulting package states and installed identities equal (section 7.2) |

### 7.2 Oracles

1. Native WUA on a snapshot-identical guest installing the same update from the same server (the C29/C41 pattern,
   READ: ledger). Compare `Get-HotFix`/`dism /Get-Packages` identity sets, `Installed` states, the SSU version,
   UBR (`CurrentBuildNumber.UBR`), and reboot requirement.
2. DISM before/after `/Get-Packages /Format:List` (the parser reads it). Exactly the expected identity added or
   changed; superseded older identities explained by Q7.
3. Hashes: payload SHA-1 and SHA-256 equal metadata (existing downloader/gate); SHA-256 of the pre/post package
   listings and of the `CBS.log` excerpts stored in the job record.
4. Independent registry read of the CBS package key (V0) and `observe-installed` collector output.
5. `windows-uup verify-installed` requirements built from the LCU's root MUM identity (READ: installed-verification.md
   describes this for a different flow) as a stricter, separately authored final check.

### 7.3 Negative tests

* Payload byte flipped in the store: existing digest gate refuses before DISM runs (READ pattern, C40).
* Foreign-signed or unsigned CAB: signature gate refuses (once 8.1 is decided).
* Wrong architecture CAB (arm64 on amd64): `Applicable: No`, `0x800f081e` path.
* Already installed update: plan `AlreadyInstalled` / `no_action`.
* Pending reboot present before start: refused with explicit message.
* Concurrent servicing (start a native WUA or `dism` operation, then run): `busy` mapping; document the actual codes.
* Low disk: observe and map (offline trials hit host disk exhaustion with 14099, OBSERVED, which is a reminder to
  preflight free space online: the client should refuse below a configured floor).
* Killed client mid-step: the job record is `interrupted`, rerun plans from facts; DISM/TrustedInstaller state
  inspected afterwards (V9, destructive; run only on a revertable guest).
* `--allow-unknown` is not allowed for CBS steps (refuse the combination; skipping an Unknown prerequisite on a
  servicing stack update is exactly the risky case).
* Timeout path with `kill_on_timeout=false`: record `unconfirmed`, no kill.
* MUM identity differs from metadata identity: refuse.
* Unsupported container shape (e.g. `.psf` external, `.msu` without wusa backend): refuse, nothing executed.

### 7.4 Ledger rows to add (proposed numbers continue after C42; the metadata agent may take C43 and following, renumber at merge)

| Row | Claim | Pair | Evidence gate |
| --- | --- | --- | --- |
| C-cbs-1 | The real CBS handler metadata (URI, `HandlerSpecificData`, files, prerequisites, supersedence) parses into `CbsSpec` without loss | real WSUS capture | metadata fixtures (section 2) + parser test over them |
| C-cbs-2 | The evaluator's `CbsPackageInstalledByIdentity` / `cbs_package` reading (CurrentState) agrees with DISM `/Get-Packages` and the native agent for sampled packages | native collector, DISM, Rust provider | V0 report, `facts-check` extension |
| C-cbs-3 | The CBS plan selects the same SSU/LCU set and order as a native WUA install on the same machine state | native WUA vs plan on recorded facts | V2 plus V8 |
| C-cbs-4 | The DISM backend installs a real SSU through the WSUS content route and the post-check reaches the documented status | execution on guest, native comparison | V3 |
| C-cbs-5 | The same for a real LCU, including `reboot_required` and resume | execution on guest | V4, V6 |
| C-cbs-6 | The gates (digest, signature policy for CBS payloads, payload shape) refuse every negative case of 7.3 before any DISM call | execution on guest | negative suite |
| C-cbs-7 | Idempotence and interruption recovery | execution on guest | V7, V9 |

Rules from the ledger apply (READ: wsus-validation.md "Rules for this ledger"): a row leaves `Not validated` only
with a retained run identifying client and server builds; synthetic fakes never validate; update this file and
inventory in the same change.

### 7.5 What cannot be validated on the host

* Any real servicing: DISM/TrustedInstaller behavior, applicability by the real stack, pending completion at boot,
  reboot persistence, concurrency with WUA, SSU effects. Host tests with `FakeBackend` only prove the client's own
  logic (ordering, write-ahead, status mapping), as for C39 before its guest run.
* Online parser agreement (transcripts are offline until V0/V1).
* The real size/time of an LCU download through the lab WSUS and its disk impact.
* Any claim about Windows 11 builds beyond the lab guest (10.0.26200 UBR 8037 in the Defender run, READ).
* Signature behavior of real CBS payloads (needs the real payload).
* Power-loss behavior during servicing (no evidence anywhere in the repo, READ: transactions doc).

## 8. Risks and open questions

### 8.1 Security: content trust

* READ: the digests in WSUS metadata are SHA-1 (always) with SHA-256 as an additional digest where declared
  (inventory 12.10 file records). The plan records every declared digest and the gate recomputes all of them
  (wsus-install.md gate 3). SHA-1 alone is collision-weak, but the metadata that carries it is itself trusted only as
  much as the server; the independent check is the signature on the payload (READ: "Microsoft's signature on the
  file is the independent check").
* READ: the current signature gate is embedded Authenticode through `WinVerifyTrust`, "embedded signatures only (a
  catalog-signed payload is refused)" (C40 limits). CBS packages are verified by the servicing stack through the
  package's own catalog (`.cat`) and the manifests' hashes (INFERRED; the repo's own work establishes that SSU members
  verify against 16 catalogs, READ: servicing-staging.md, `Ssu7714OfflineSourceProfile`), and the outer CAB/MSU may carry
  no embedded signature. Consequence: the gate may refuse every real CBS payload (Q8). Options, none chosen:
  (i) `WinVerifyTrust` on the CAB through the cabinet SIP (INFERRED to be possible) if the container is signed;
  (ii) rely on DISM/CBS to authenticate content (it does, INFERRED) and keep our gate to digest + container shape
  + signer-if-present, recording "authenticated by the servicing stack" as an evidence statement, not as our check;
  (iii) use the `wintrust` crate's portable verification (CAB member kind, pinned roots, revocation policy;
  READ: portable-catalog-trust.md) on the nested catalog, which then needs a trust policy for Microsoft's servicing
  roots (the repo has a policy for the SSU catalog, revocation disabled in diagnostics, READ).
  Decision needed from the owner (section 8.3, Q-A). Whatever is chosen, DISM's own verification must not be
  disabled and our gate must not be weaker than it is for command-line payloads (the default signer allowlist
  `Microsoft Corporation` remains).
* Revocation is not checked by the existing gate (READ) and offline diagnostics also disabled it. State that
  explicitly in the job record for CBS steps.
* The WSUS server itself: a compromised or malicious WSUS (or one that re-signs with its own cert as the MSI
  examples did, OBSERVED inventory 12.16) can offer arbitrary packages; for CBS the stack's catalog check is the
  main defense. `trust_signers` with a local WSUS signing certificate must NOT be extended to CBS payloads by
  default.
* TOCTOU between our open handle and the DISM process opening the file: mitigated by share-deny handle held across the
  call (READ pattern) and a store ACL gate; remains a residual risk if DISM copies the file elsewhere first
  (INFERRED).

### 8.2 Other risks

* Privilege: the client already requires an elevated token; SYSTEM context may be needed for some servicing paths
  (INFERRED, V0/V3 decide). Running the whole `wsus.exe` as SYSTEM is the lab practice (READ).
* Bricking. A failed or interrupted servicing operation can leave an OS that cannot servicing-boot (INFERRED). Risk
  controls: refuse on pending reboot, refuse below a disk-space floor, never kill DISM, one servicing client at
  a time (client lock + stack lock), require `--yes`, require an explicit `--i-understand-cbs` flag on first use
  (PROPOSED), validate only on revertable guests.
* Rollback. No rollback exists in this design. Uninstall (`/Remove-Package`) is a non-goal; LCU removal is limited
  by design (INFERRED). The offline controlled-store rollback must not be advertised online (4.5).
* Detached completion: as with Defender (READ: packages exit 0 before the update is applied), a CBS front end may
  return before work completes; the waiting post-check is the mitigation, and the `reboot_required` branch must not
  loop on waiting.
* Evaluator risk: `CbsPackageInstalledByIdentity` reading (112) is Unverified; if the native agent treats other
  states as installed (for example a superseded identity), the plan could re-install or skip wrongly. The two-oracle
  success table (5.5) is the mitigation and V0 is the first gate.
* Supersedence unverified (Q7): the plan could skip a needed LCU or install a superseded one; DISM `Applicable` is
  the backstop.
* Scale: payload size. A Windows 11 LCU can exceed 1 GB (INFERRED); the verified downloader's timeouts, disk space and
  the 64 KiB tails matter; DISM log size also (DISM log can be many MB; store a hash and bounded excerpt).
* Localization: DISM text parsing requires `/English` (READ) and still depends on English strings; a non-English
  OS with English DISM output is believed supported by the flag (INFERRED).
* Licensing/ESU policy rejection (1625 offline, OBSERVED) is a legitimate refusal, not an error to bypass.
* Scope creep: Windows 10 22H2 fixtures dominate the offline evidence while the lab guest is Windows 11 (READ);
  support claims must name the build.

### 8.3 Open questions needing the owner's decision

* Q-A (trust). How do CBS payloads get authenticated by OUR gate: embedded Authenticode on the CAB if present,
  rely on the servicing stack and record that, or wire `wintrust` to a Microsoft servicing root policy?
  Recommendation: (ii) first (digest + shape + stack authentication, signer-if-present), (iii) as a later
  hardening, never weaker than the existing gate for other handlers.
* Q-B (backend). Start with DISM subprocess only (recommended), or also build `wusa` and a DISM-API backend now?
  Recommendation: DISM subprocess only; wusa only if Q4 shows `.msu`.
* Q-C (planner). May the planner be changed so prerequisite SSUs become planned steps (5.3 item 1), behind a flag,
  given plan bytes for Defender/MSI must not change? Alternative: refuse and tell the operator to install the SSU
  update first (smaller, safer first milestone).
* Q-D (resume). Is operator-driven rerun after reboot enough, or do we want an automatic post-reboot continuation
  (RunOnce/service)? Recommendation: operator-driven until V6 passes.
* Q-E (kill on timeout). Accept the deviation of not killing DISM/TrustedInstaller on timeout (5.7)?
* Q-F (servicing crate changes). Will the owner of `windows-cbs`/`windows-dism` accept requests R1 to R8, in
  particular R1 (a light parser seam), or should `wsus-client` carry its own copy of the DISM text parsers
  (duplication, but no heavy dependency)?
* Q-G (scope). Which update classes first: SSU only, SSU+LCU, or also .NET/FOD? Recommendation: SSU, then LCU.
* Q-H (lab). Can the lab WSUS (Windows Server 2025, 10.0.26100.32230, READ) host and serve a real LCU (disk, content
  download from Microsoft Update), and is a second identical guest available for the native WUA oracle?
* Q-I (reporting). Keep `reporting_sent: false` for CBS too (recommended: yes, same reasons).

### 8.3a Decisions recorded (owner, 2026-10-05)

* Q-A (trust): rely on DISM/CBS to authenticate the payload; the client records that the authentication was delegated
  and does not apply its own Authenticode gate to CBS payloads (SHA-1/SHA-256 from the metadata are still verified).
* Q-B (backend): DISM subprocess, plus `wusa` and the DISM API backends (all behind the backend trait).
* Q-C (planner): the planner schedules the servicing stack update (SSU) as a prerequisite step.
* Q-D (resume): operator-driven rerun after a reboot is enough.
* Q-E (kill on timeout): owner had no preference. Working decision (PROPOSED, revisit with evidence): do not kill
  DISM/TrustedInstaller on timeout; stop waiting, record the step as `unconfirmed` with the process still running, and
  judge by fresh state on the next run.
* Q-F (servicing crates): small change requests to `windows-cbs`/`windows-dism` are acceptable (R1 to R8).
* Q-G (scope): SSU first, then LCU; .NET and features-on-demand behind an additional flag.
* Q-H (lab): the lab may be used: real LCU through the lab WSUS and, if needed, a second guest for the native oracle.
* Q-I (reporting): owner had no preference. Working decision (PROPOSED): `reporting_sent: false` for CBS until the
  event ids for CBS outcomes are observed from a native client.

* Q-J (OSInstaller, NEW; spike done 2026-10-05, findings in docs/wsus-osinstaller-spike.md: the install code ships in the update as `DesktopDeployment.cab` and the native agent drives CBS in-process as `UpdateAgentLCU`; `UpdateAgent.dll` exports a `UA_*` C API; canonical `.NET` and servicing stack cabs are DISM-recognizable). The monthly cumulative updates use the `OSInstaller` handler with `UpdateAgent.dll`, several
  payload files and tens of GB, not a single CAB for `dism /Add-Package`. Decide: (1) first milestone is `Cbs` only
  (180 updates: `Package_for_RollupFix` and .NET CAB updates) with `OSInstaller` refused (current behavior); (2) study how
  `UpdateAgent.dll` installs an `OSInstaller` update (the workspace's `windows-uup` knows UUP media, PSF and WIM payloads,
  and may supply the planning); (3) whether the SSU-first rule applies to `OSInstaller` through
  `PatchingTypePreferred="ServicingStack"`. RECOMMENDATION (PROPOSED): do (1) now, run an investigation spike for (2).

### 8.3b Implementation status (2026-10-05)

* Implemented (feature `cbs-handler`, off by default): `ServicingBackend` trait (always compiled, with `FakeBackend`),
  `DismBackend`, `WusaBackend`, `DismApiBackend` (in process `DismApi.dll`, added 2026-10-06; OBSERVED on one guest, see `docs/wsus-install.md`), pending-indicator probe, SSU
  prerequisite scheduling (`PlanOptions::plan_prerequisites`, plan schema `/2`), `delegate_cbs_installable` (new, see
  below), job schema `/2` with `servicing` evidence, reboot barrier with `remaining_steps`, no kill on timeout, two-oracle
  post-check. Details: `docs/wsus-install.md`.
* Deviations from the design text: (1) the trait and executor logic are always compiled and only the Windows backends
  (the servicing crates' text parsers) are behind the feature, so the executor is host-testable by default; (2) the
  servicing crates are used through `windows-dism` only (`default-features = false`), no change to `windows-cbs` or
  `windows-dism` was needed, so requests R1 to R8 were not raised; (3) the offline `windows_dism::
  parse_package_applicability` cannot read online `/Get-PackageInfo` output, so `servicing/dism.rs` has its own
  `parse_package_info`; (4) `CbsPackageInstallable` is the `IsInstallable` of every real `Cbs` update and cannot be
  evaluated from facts, so planning needed an explicit opt-in (`delegate_cbs_installable`) that lets the stack decide
  just before each install; (5) after a timed-out call the post-run listing is skipped (it blocks on the busy stack).
* Observed on one guest (inventory 12.18, ledger C43 to C47): a real Microsoft package installed absent to Installed with
  both oracles agreeing; DISM failure, killed DISM, timeout without kill, pending indicator and digest gates. NOT done: a
  real SSU or LCU, a real catalog `Cbs` update (none applicable to the guest), `OSInstaller` (Q-J), `wusa` on a real `.msu`,
  the native agent as an oracle, reboot-barrier execution.

### 8.4 Phased milestones and acceptance criteria

| Milestone | Content | Acceptance (all must hold) |
| --- | --- | --- |
| P0 Metadata (blocking) | Complete section 2 from inventory 12.17 and `docs/fixtures/wsus-m0-cbs/`; decide Q-A to Q-C with the owner | Q1 to Q10 each answered OBSERVED with fixture paths, or explicitly marked unobserved; this document updated; no code |
| P1 Read-only on the guest | `servicing/` trait, `FakeBackend`, DismBackend read operations only (`list_packages`, `payload_applicability`, `pending_indicators`), V0 and V1; feature `cbs-handler` compiles on Linux and cross-compiles for Windows | host tests pass with offline transcripts as fixtures; V0 shows evaluator/DISM agreement or lists the discrepancies; no mutation code path is reachable; `task check` clean (fmt, clippy `-D warnings`, tests) with and without the feature; existing plan/job bytes unchanged (C38 golden) |
| P2 Handler and plan | `handlers/cbs.rs`, plan schema bump with adapter, CBS plan on real fixtures, `plan`/`scan`/dry-run `install` refusing execution without the backend | plans for real LCU/SSU fixtures byte-deterministic; unsupported shapes refused; `--allow-unknown` refused for CBS; V2 passes on the guest |
| P3 Execute SSU | DismBackend `add_package`, write-ahead, pre/post state, post-check, job record v2 | V3 passes on a revertable guest, the oracle table row is as predicted or the discrepancy is documented; ledger C-cbs-4 moves to Partially validated with a retained run |
| P4 Execute LCU and reboot | LCU, `reboot_required`, `remaining_steps`, resume, kill-on-timeout policy | V4, V5, V6, V7 pass; first observation of Install Pending to Installed; C-cbs-3 and C-cbs-5 Partially validated; negative tests V9 done |
| P5 Oracles and hardening | Native WUA comparison V8, signature option (iii) if chosen, ledger/inventory docs updated in the same change | package-state equality with native WUA for the tested updates; docs updated per the ledger rules |
| P6 Optional | `.msu` via wusa, DISM API backend, .NET/FOD classes, post-reboot automation | each only after its own metadata evidence and guest run |

Exit criterion for the whole design: the claim "the WSUS client installs an SSU and an LCU online" may be written in
any document only after P4 evidence exists; before then the documents must keep saying "not validated".

## 9. Summary of recommendations

1. Treat online CBS install as a new `cbs` handler beside `command_line` and `msi`, feature-gated (`cbs-handler`,
   off by default), reusing the existing plan, store, gates, job record and post-check machinery.
2. Execute through `dism.exe /Online /Add-Package` as a subprocess on the existing `Runner` seam; do not call the
   DISM API, PowerShell, `pkgmgr` or COM now; `wusa` only if real payloads are `.msu`.
3. Reuse only the pure parts of the servicing crates: DISM text parsers and exit table, package state types,
   CAB/MUM inspection, optionally the ordering algorithm. Do not reuse `Dism`/`Job` (offline-mount bound), the
   transaction/staging/snapshot machinery (offline, controlled store, `executable: false`).
4. Never write to the live component store ourselves (option (e)); the Rust-native staging path is not admitted even offline.
5. Success is decided by two independent oracles on fresh state, the evaluator (`IsInstalled` over CBS facts) and
   the DISM package listing, plus pending indicators; any disagreement is `unconfirmed`.
6. Plan SSU before LCU explicitly (planner change behind a flag) or refuse with an instruction; stop at the first
   reboot; never reboot or schedule across reboot in the first milestones.
7. Do not kill DISM on timeout; refuse on pre-existing pending reboot, low disk, and `--allow-unknown`.
8. Block everything on section 2 (real metadata) and on the owner's decision about payload trust (Q-A).
