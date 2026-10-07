# OSInstaller handler spike (2026-10-05)

Question: how does the native Windows Update Agent (WUA) download and install updates whose handler is
`http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller` (the monthly Windows 11 and .NET cumulative
updates, inventory 12.17), and what would this project's installing client have to do to install one? This is a
spike: it recommends a design and does not implement the handler.

Evidence labels: READ = decompiled or read from a real file; OBSERVED = seen on the lab guest or in the real catalog;
INFERRED = deduced and not checked directly. Fixtures: `docs/fixtures/wsus-m0-osinstaller/`.

## 1. Answers in brief

1. **What the handler is (OBSERVED, READ).** `InitialModule="UpdateAgent.dll"` names the OS update stack, and that stack
   is delivered inside the update: the `DesktopDeployment.cab` file (`PatchingTypePreferred="ServicingStack"`) holds
   `UpdateAgent.dll`, `updatedeploy.dll`, `wcp.dll` (the CBS engine), `dpx.dll`, `UpdateCompression.dll`, `TurboStack.dll`,
   `WinREAgent.dll` and more (15 files). The native agent runs it as a COM server inside `wuaucltcore.exe`.
2. **How it installs (OBSERVED, READ).** `UpdateAgent` builds an `ActionList.xml` from the update's CompDB metadata plus a
   generated device inventory, chooses canonical or express payloads, downloads only the needed subset, and drives the CBS
   servicing processor itself (`ICbsServicingProcessor->Process`, servicing stack update first, then the other packages)
   under the CBS client name `UpdateAgentLCU`. No `TiWorker.exe`, `dism.exe`, `wusa.exe` or `msiexec.exe` was started.
3. **Files fetched (OBSERVED).** Not the declared list. For a `.NET` update the two declared files (97 MB). For the
   monthly cumulative update about 455 MB were fetched against 14.3 GB declared (section 4.3).
4. **Can DISM or `wusa` replace it (partly).** DISM recognizes the canonical CBS cabs the update delivers (`.NET` cab and
   servicing stack cab: OBSERVED with `/Get-PackageInfo`), so a DISM route works for canonical-cab payloads. The monthly
   cumulative update is delivered as express content (wim, mumx.esd, psf) unless the metadata also declares a `.msu`; only
   the UpdateAgent route reproduces what the native agent does for every update (section 6).
5. **Recommended design (PROPOSED).** An `osinstaller` handler with its own backend that loads the delivered
   `UpdateAgent.dll` and calls its exported `UA_*` functions (section 5), validated first on the small `.NET` updates; keep
   the DISM and `wusa` backends of `docs/wsus-cbs-integration.md` for the `Cbs` handler and for `.msu` payloads.
6. **Not done:** a fresh absent-to-installed observation (the guest already had the package staged, section 3.2), any
   `DISM /Add-Package` of an OSInstaller payload, any monthly cumulative update download by this spike, and any call of
   `UA_*` ourselves.

## 2. Setup and limits

- Guest `w11-cli` (Windows 11 25H2, build 26200, UBR 8037 at the start), real lab WSUS `wsus-srv`. A dedicated group
  `spike-osinstaller` held only this computer, one update (`88661612-7dd9-49d4-bb34-1e54802c99b9`, "2026-09 Cumulative
  Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 25H2 for x64 (KB5126052)", child
  `b5f388e1-6f28-4eae-b94a-3e058db208ea`) was approved for it, the update's 96,660,271 bytes were downloaded by the WSUS in
  under a minute. At the end the approval and the group were removed and the guest's WUServer policy keys were removed.
  The 96 MB of content stays in the WSUS content store.
- The host root filesystem had 12 to 21 GB free during the run (other work shares it), under the 25 GB threshold of the
  task. Only a 97 MB download was needed, so the run continued with monitoring; the multi-GB monthly update was NOT
  downloaded. That is the main limit of this spike: the monthly cumulative update path is observed from an earlier
  native install on the same guest (section 4.3), not from a run of this spike.
- Static analysis used `UpdateAgent.dll` 10.0.26100.32230 from the Windows Server 2025 media (IDA, private copy). The
  newer copy inside `DesktopDeployment.cab` (4,437,464 bytes against 4,085,136) was not analysed. The engine DLLs under
  `C:\Windows\UUS\` could not be read (access denied for SYSTEM), so the WUA engine's own rule evaluation was not read.

## 3. What the metadata gives (OBSERVED)

Over the 297 `OSInstaller` revisions of the stored Windows 11 catalog (inventory 12.17):

| Group | Revisions | Declared files per update | Declared download |
| --- | --- | --- | --- |
| `Microsoft.NetFX.amd64` / `arm64` | 66 | 2: the KB cab (74 to 97 MB) and a `DotNetServicingCompDB_KB<n>.xml.cab` (11 KB, `PatchingTypePreferred="Metadata"`) | 74 to 97 MB |
| `Client.OS.RS2.AMD64` / `ARM64` | 231 | 8 to 19: `Wsus.AggregatedMetadata.cab` (Metadata), `DesktopDeployment.cab` (ServicingStack), `SSU-<build>-<arch>.cab` and `-express.cab`, `Windows11.0-KB<n>-<arch>.cab`, `.psf`, `-baseless.cab`/`-baseless.psf`, `.wim`, `.msu` (173 declarations), language pack, FoD, Edition and FoD metadata | 8.8 to 14.8 GB |

All files have `PatchingType="SelfContained"` except the Metadata and ServicingStack files, which carry
`PatchingTypePreferred`. The update is a leaf with deployment action `Bundle`; its parent (the update an administrator
sees, with the KB number and title) has action `PreDeploymentCheck` and `ExplicitlyDeployable="true"` (inventory 12.17).

### 3.1 Rules

- `IsInstalled` = `ProductReleaseInstalled Name="Microsoft.NetFX.amd64" Version="2400.26200.9347.1"` (the monthly updates:
  `Client.OS.RS2.AMD64` and a `10.0.26200.<n>` version).
- `IsInstallable` = `DeviceAttribute` terms on `OSSkuId`/`sku`, `ProductType`, `OSVersion` (a range such as 26200.1 to
  26201.0), `IsRemoteDesktopSessionHost` (`.NET` updates).
- Where "installed product release" is stored (OBSERVED, INFERRED conclusion): after the install a registry search of
  `HKLM\SOFTWARE\Microsoft` for the data `9347.1` found matches only under
  `...\Component Based Servicing\Packages\` (the `Package_for_DotNetRollup_481` identity and the
  `Package_<n>_for_KB5126052` sub-packages) and none under `WindowsUpdate`, `Orchestrator` or any other key. The release
  version `2400.26200.9347.1` is therefore derived from CBS package state, with `10.0.9347.1` as the CBS version. This is the
  mapping our evaluator lacks (`ProductReleaseInstalled` is unsupported); how WUA computes the `2400.26200` prefix was not
  read.

### 3.2 Starting state of the guest (limit)

The guest already held `Package_for_DotNetRollup_481` 9347.1 and `Package_for_RollupFix` 26100.9457.1.0 as "Install
Pending" (and `RebootPending` set) from earlier native installs the same day (session records of 12:33 in
`C:\Windows\SoftwareDistribution\Download`, `CBS.log` at 13:27). The spike's flow therefore re-drove the agent over an
already staged package. The process tree, file set, ActionList and reboot behaviour below are real; the absent-to-pending
transition of the package state was not seen by this spike.

## 4. The native flow (OBSERVED)

### 4.1 Timeline of the `.NET` update (guest local time)

| Time | Event |
| --- | --- |
| 16:44:06 | WUA search with the WSUS policy: 8 updates found (7 lab test updates and the `.NET` update); the bundled child `b5f388e1` with 2 contents |
| 16:44:11 to 16:44:32 | `Download()` result 2 (succeeded), 21 s; `IsDownloaded=True` |
| 16:44:27 | CBS session `initialized by client Arbiter`; ActionList written (`SessionData="DesktopServicing"`) |
| 16:44:30 to 16:44:33 | CBS sessions `initialized by client UpdateAgentLCU`; DPX phases `Apply Deltas Provided In File`, some `0x80070002` file-not-found exceptions logged inside DPX (the sessions still finalized `S_OK`); `Package Format: PSFX`, `Delta Format: ForwardOnly` |
| 16:44:37 | `wuaucltcore.exe /DeploymentHandlerFullPath \\?\C:\Windows\UUS\Packages\Preview\AMD64\UpdateDeploy.dll /ClassId 24c49901-a226-4e9b-af65-797bf9c329d0 /RunHandlerComServer` (parent: the WUA service host) |
| 16:46:27 | `Install()` result 2 (succeeded), `hr=0x00000000`, `RebootRequired=True` (115 s from the start of the install) |

Process poll at 300 ms: the only process created by the install was `wuaucltcore.exe`. The CBS work ran inside it
(`CBS.log`: sessions by `UpdateAgentLCU`), so there is no external servicing command line to replicate.

### 4.2 Files and generated state

For the `.NET` update the working directory `SoftwareDistribution\Download\<session>\` held: the two declared cabs, a
generated `ActionList.xml` (1,146 bytes), `windlp.state.xml` (7 KB, the deployment session state: `State`, `Scenario=4`,
`RebootRequired`, `ExpansionComplete`, `CompDBsExpanded`, `ContainsExpressPackage=0` and more), and
`Metadata\DeviceInventory.xml` (831,500 bytes, generated by `UA_CreateDeviceInformation`), plus the extracted CompDB. A
`SharedFileCache` directory holds hash-named copies of cabs shared between sessions.

The `.NET` `ActionList.xml` (fixture `dotnet-ActionList.xml`) is short:

- `Downloads/Package Id="Package_for_DotNetRollup_481"` with one `Payload PayloadType="Canonical"`, `Hash` (SHA-256 base64,
  equal to the metadata's `AdditionalDigest`), `DownloadSize` 96,649,380, `SourceName`;
- `Plan/InstallFeature Id="GDR_KB5126052"`;
- `Actions/InstallPackage Keyform="Package_for_DotNetRollup_481~~amd64~~10.0.9347.1" InstalledSize="425655775"` and its
  `InstallPayload`.

### 4.3 The monthly cumulative update (from an earlier native install on the same guest, OBSERVED)

The leftover working directory of the cumulative update KB5129195 (26100.9457) shows what the agent fetched:

| File | Bytes | Role |
| --- | --- | --- |
| `<guid>.AggregatedMetadata.cab` | 2,799,173 | 310 CompDB cabs (Desktop target and baseless CompDBs per language and edition) |
| `DesktopDeployment.cab` | 13,590,485 | the update stack (section 4.4) |
| `SSU-26100.9441-x64.cab` | 20,623,941 | servicing stack update, canonical |
| `Windows11.0-KB5043080-x64.wim` | 113,666,182 | express baseline content for the previous cumulative update |
| `Windows11.0-KB5129195-x64.mumx.esd` | 114,384,136 | express metadata container |
| `Windows11.0-KB5124015-x64.cab` | 170,798,447 | SafeOS (WinRE) dynamic update, `PayloadType="PSFX"` |
| `PFL_Package_for_RollupFix~~amd64~~26100.9457.1.0.xml` and `extended_PFL_...xml` | 6,835,185 and 2,292,993 | generated package file lists |
| `ActionList.xml` | 5,533 | generated |

About 455 MB in total against the 14.3 GB the update declares (the big `.wim` and `.psf` files, the language packs and
the FoD and Edition wims were not fetched). The `ActionList.xml` (fixture `lcu-ActionList.xml`) has four `Downloads`
packages (cumulative update as `Express` with `AltSourceName` the corresponding `.msu` and a CiX path, SafeOS as
`PSFX`, the servicing stack as `Canonical` with the `.msu` as alternative), a `Plan` with four features and `Actions` that
`StagePartial` the previous rollup, install the new rollup with its express payloads, and install the SafeOS and servicing
stack packages. So the choice between canonical, express and `.msu` is made by the stack, per package, from the
CompDB metadata and the device inventory (READ: the string "This error will force a canonical retry").

### 4.4 `DesktopDeployment.cab` (OBSERVED listing, fixture)

`UpdateAgent.dll` (4,437,464 bytes), `dpx.dll`, `Mitigation.dll`, `UAOneSettings.dll`, `wcp.dll` (the CBS engine),
`TurboStack.dll`, `ReserveManager.dll`, `WinREAgent.dll`, `UpdateCompression.dll`, `updatedeploy.dll`,
`AppxDeviceInventory.dll`, `MsixPackagePro...`, `featurestaging.dll`, `turbocontainer.dll`, `Deployment.cab`.
INFERRED: the agent extracts it to `C:\Windows\UUS\Packages\Preview\...` and runs the handler from there (the observed
`/DeploymentHandlerFullPath` points there; the extraction itself was not observed).

### 4.5 After the reboot (OBSERVED)

The guest rebooted (an earlier `shutdown /r /t 5` from the guest agent did nothing; `shutdown /r /t 3 /f` worked).
After the boot (16:52): UBR 9457, `Package_for_DotNetRollup_481` 9347.1 `Installed` (9321.3 `Superseded`),
`Package_for_RollupFix` 26100.9457.1.0 `Installed` (8037 `Superseded`), `clr.dll` 4.8.9345.0 (was 4.8.9221.0),
`RebootPending` cleared, the agent no longer offered KB5126052, and the update history shows
`2026-09 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 25H2 for x64 (KB5126052)` with result
2 (succeeded). Before the reboot DISM listed the new packages as `Install Pending` and the superseded rollup as
`Uninstall Pending`; `RebootPending` and `pending.xml` existed. The servicing finalizes at boot, so the client does not
need to resume anything after the reboot except to re-evaluate.

DISM recognizes the delivered cabs: `dism /Online /Get-PackageInfo /PackagePath:<cab>` printed the identity
(`Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1`, then the servicing stack package), `Applicable : Yes`,
`State : Installed` and `Install Client : UpdateAgentLCU` for both, exit 0.

## 5. What `UpdateAgent.dll` exposes (READ, Server 2025 build 26100.32230)

Exports (all by ordinal): `CreateDeploymentSession`, `CreateDeploymentSessionEx`, `CreateOfflineDeploymentSession`,
`GetSupportedSessionInitializationOptions`, `UA_CreateDeviceInformation`, `UA_CreateDeviceInformation2`,
`UA_CreateActionList`, `UA_CreateActionList2`, `UA_CreateDownloadList`, `UA_CreateDownloadListFromActionList`,
`UA_CreatePackageListFromDownloadList`, `UA_InstallActionList`, `UA_CommitActionList`, `UA_ReleaseDownloadList`.

Behavior read from the strings and the three functions decompiled:

- `UA_CreateActionList2(options in 1..2, ..., sourceDirectory, outputPath, ...)` requires the source directory to exist and
  the output to be a file path (`GetFileAttributesW` checks), creates a session (`CreateSessionData`) and calls the
  `Arbiter`'s `CreateActionList`. The Arbiter reads the CompDBs extracted from `*.AggregatedMetadata.cab` ("Missing
  AggregateMetadata.cab! CompDBs are expected to be downloaded as loose files!" is the `.NET` case: the CompDB cab is a
  loose file) and the device inventory.
- `UA_CreateDownloadListFromActionList(actionListPath, &count, &list)` loads the ActionList and generates the list of files
  to fetch (`GenerateDownloadList`, "Adding file: Optional, Category, FileName, Container, Hash, Cix, payloadName", express
  download lists and "All Express content is rangeless" handling); free with `UA_ReleaseDownloadList`.
- `UA_InstallActionList(options 1..2, ..., actionListPath)` loads the update API DLL (`GetUpdateAPIPath`,
  `LoadLibraryExW`) and calls its `StageUpdateWithActionList` ("Calling IU StageUpdateWithActionList"); the staging runs
  `CScenarioCtrlDesktopCBS`, which calls `ICbsServicingProcessor->Process` first for the servicing stack update and then for
  the non-SSU packages ("Actionlist does not have both an SSU and non-SSU package(s)"), with the CBS client name
  `UpdateAgentLCU`.
- Express-to-canonical fallback (`ReportEventFellBackToCanonical`), disk-space checks for express, SafeOS and WinRE
  servicing (`CScenarioCtrlWinREServicing`), reboot state (`RebootRequired` persisted in `windlp.state.xml`), feature
  update plans (`OSInstallPlan.xml`) and mitigation scenarios are all in this DLL.

Unread: the `UpdateAPI` DLL named by `GetUpdateAPIPath`, the exact argument layouts of `UA_*` (the first argument looks
like an options value 1 or 2, the next is a context, the paths follow), and how the WUA engine hands the update to the
handler (the engine DLL was not readable).

## 6. What our client would have to do

### 6.1 Options

| Option | Works for | Needs | Verdict |
| --- | --- | --- | --- |
| A. Drive the native WUA (COM) | everything the agent can install | Windows, our server or WSUS reachable through policy | Not a client of ours; useful only as the oracle |
| B. Canonical payload with DISM or `wusa` | `.NET` updates (one cab), servicing stack cabs, any update whose metadata declares an `.msu` (173 of 297) | a way to pick the canonical file; DISM recognizes the cabs (section 4.5) | Cheap first step; does not cover express-only monthly updates |
| C. `UpdateAgent.dll` `UA_*` API | every `OSInstaller` update as the native agent installs it | the delivered `DesktopDeployment.cab` (to get the matching `UpdateAgent.dll`), the metadata cabs, our own download of the files named by `UA_CreateDownloadListFromActionList`, Windows, SYSTEM | Recommended target (PROPOSED), validated first on `.NET` |
| D. Re-implement the ActionList generation and call CBS directly | nothing yet | the CompDB and CiX semantics, express and PSF handling | Not recommended; `windows-uup`'s PSF work covers only part of it |

### 6.2 Option C in detail (PROPOSED, every step to be validated)

1. Download `Wsus.AggregatedMetadata.cab` or the loose CompDB cab (the files with `PatchingTypePreferred="Metadata"`) and
   `DesktopDeployment.cab` (`ServicingStack`) through the normal verified download path (digests from the metadata).
2. Extract `DesktopDeployment.cab` into a private directory and load that `UpdateAgent.dll`. Trust: the files come from the
   WSUS metadata digests; verify the Authenticode signature of the extracted DLLs with `WinVerifyTrust` before loading.
   (Decision needed, section 9: the owner chose to rely on DISM/CBS for `Cbs` payloads; this handler loads Microsoft code,
   which is a different trust surface.)
3. `UA_CreateDeviceInformation2` to produce the device inventory, extract the CompDBs, `UA_CreateActionList2` to produce the
   `ActionList.xml`, `UA_CreateDownloadListFromActionList` to learn the files and hashes.
4. Download exactly those files (our own content path: hash checked, ranged, resumable), place them in the layout the
   stack expects (the `SoftwareDistribution\Download\<session>\` layout seen in section 4; `SharedFileCache` and
   `windlp.state.xml` are the stack's own state).
5. `UA_InstallActionList`, then judge success (section 7); `UA_CommitActionList` presumably follows (INFERRED from the
   export name; its role was not read).

This route inherits all the stack's behavior (SSU ordering, express fallback, SafeOS and WinRE servicing, reserve
manager, mitigations) at the cost of depending on private Microsoft interfaces that can change per build; the stack is
shipped with each update, which limits drift but does not remove it.

### 6.3 Option B in detail

For a `.NET` update the plan is: download the KB cab, `DISM /Online /Add-Package /PackagePath:<cab> /NoRestart` (the
`cbs-handler` DISM backend), post-check by package state. The `DotNetServicingCompDB` cab is only metadata for the stack.
Whether `/Add-Package` yields the same end state as the native route (the native run showed `Install Client :
UpdateAgentLCU`, a DISM run would show `DISM Package Manager Provider`) was not tested.

## 7. Oracles, reboot, rollback

- **Success (PROPOSED):** two agreeing signals on fresh state: the CBS package state of the identity named in the
  ActionList (`Package_for_DotNetRollup_481~~amd64~~10.0.9347.1` is `Installed` or `Install Pending` in
  `dism /Online /Get-Packages`) and the evaluator, which needs `ProductReleaseInstalled` support mapped to that package
  state (section 3.1). Before the reboot the package is `Install Pending`: whether `ProductReleaseInstalled` is true then
  was not observed (the pre-reboot search was not repeated). Until it is, report `reboot_required` and judge `succeeded`
  only after the reboot, like the `cbs-handler` design.
- **Reboot (OBSERVED):** the install returns `RebootRequired=True`; CBS finalizes during the next boot; no client action
  is needed to resume.
- **Rollback (INFERRED):** the stack stages and commits at boot. A superseded rollup is `Uninstall Pending` until the
  reboot (OBSERVED), so the previous rollup remains until then. No failed-install rollback was observed.
- **Logs to keep in the job record:** `CBS.log` offsets, `SoftwareDistribution\Download\<session>\windlp.state.xml`,
  `ActionList.xml`, the WUA history entry.

## 8. Reuse in this repository

- `crates/windows-uup/src/psf.rs` and `docs/psf-reconstruction.md`: PSF container reconstruction (`.psf` with a CiX index,
  PA30 and PA31 deltas via `windows-delta`; KB5043080 reconstructs 26,357 outputs). Relevant only for options B and D
  with `.psf` payloads; the express path of option C does it inside the stack.
- `crates/windows-cbs/src/packages.rs`: reads `PSFXDeltaFormat` and the package format from MUM files; the PSFX
  `ForwardOnly` declaration is what `CBS.log` printed (section 4.1).
- `windows-delta` (PA30, PA31, PA19) and `windows-mpsp` are not involved.
- `wsus-client`: the download, digest and job machinery, the `Cbs` and `OSInstaller` parsing of
  `handlers/cbs.rs`, and the servicing backend trait of `docs/wsus-cbs-integration.md` (a `UpdateAgentBackend` would not fit
  `ServicingBackend` as designed: it takes a payload set and an action list, not one package path).

## 9. Risks, decisions and effort

Risks: private and unversioned `UA_*` interfaces; loading Microsoft code downloaded at run time (supply chain and
signature policy); disk (several GB working set, `SharedFileCache`); express and SafeOS behavior (WinRE partition
changes) that we cannot test cheaply; the stack expects to be run by the update agent or setup (SYSTEM, specific
directories, `windlp.state.xml` sessions); reboots; downgrade of the agent's own state if our client and WUA both act.

Decisions for the owner: (1) is loading the delivered `UpdateAgent.dll` acceptable (with signature verification), or should
this client stop at option B (DISM/`wusa`) for canonical payloads; (2) first target: `.NET` updates only, or the monthly
cumulative update too; (3) a dedicated guest with a clean (nothing staged) servicing state for the next validation round.

Effort (ESTIMATE, not measured): `UA_*` argument layouts by reading the DLL and a probe harness 1 week; an
`OSInstaller` plan and parser on top of `handlers/cbs.rs` with the fake backend 1 week; the `UpdateAgent` backend with
`.NET` end to end on a clean guest 1 to 2 weeks; the monthly cumulative update (several GB, SSU ordering, SafeOS)
another 2 weeks plus the lab time. Option B for `.NET` alone is a few days on top of the `cbs-handler`.

## 10. Not established

- A fresh absent-to-installed run with the transition of package states, and a clean DISM `/Add-Package` of the `.NET` cab
  (the package was already staged).
- The argument layouts of the `UA_*` exports and the `UpdateAPI` DLL's `StageUpdateWithActionList`; the newer
  `UpdateAgent.dll` inside `DesktopDeployment.cab` was not compared with the Server 2025 one.
- How the WUA engine computes `ProductReleaseInstalled` and the `2400.26200` release prefix; whether the update counts as
  installed while `Install Pending`.
- Whether the file selection for monthly updates is deterministic from the CompDBs alone (we observed one selection).
- Behavior for x86, arm64 hosts, Server SKUs and failure or rollback paths.

## 11. Lab state left behind

- `wsus-srv`: the approval and the `spike-osinstaller` group are removed; the 96 MB `.NET` content stays in the content
  store; nothing was declined or deleted; the other test updates are untouched.
- `w11-cli`: rebooted; UBR 9457 with the LCU and the `.NET` rollup `Installed`; the WSUS policy keys are removed; the
  helper scripts and logs are in `C:\spike` and `C:\*.ps1`.
- Both VMs were already running and were left running. Host scratch under `/data/cache/osi-spike` (about 70 MB of
  extracted DLLs and an IDA database) is not part of the repository.

## 12. Appendix: `UA_*` calling conventions and first calls (READ + OBSERVED 2026-10-05, stage 1)

Evidence: `UpdateAgent.dll` 10.0.26100.9457 (from `DesktopDeployment.cab`) and the guest's `System32` copy 10.0.26100.7920,
decompiled; calls made with `crates/wsus-client/examples/ua_probe.rs` on a fresh Windows 11 25H2 guest.

- **Prerequisites (OBSERVED).** COM must be initialized on the calling thread (`UA_CreateActionList2` returns `0x800401f0`
  otherwise). The DLL needs `C:\Windows\ImageUpdate\OEMInput.xml` only for `UA_CreateDeviceInformation` (not needed for
  the ActionList path). Load with `LOAD_WITH_ALTERED_SEARCH_PATH`.
- **`UA_CreateDeviceInformation(opt 1|2, dir, ctx, dir2?)`** (READ): needs an existing directory; `0x80070057` for a null
  argument, `0x80070003` for a missing directory. Not required by `UA_CreateActionList2`, which wrote
  `DeviceInventory.xml` (830,515 bytes) into the sandbox itself (OBSERVED).
- **`UA_CreateActionList2(opt 1|2, sessionJson, sandboxDir, inventoryFile?, flags, 0, 0, actionListPath)`** (READ, and
  OBSERVED to return 0): `sessionJson` is a JSON object whose `ModuleID` must be one of the names the stack knows
  (`LocalServicing`, `LocalServicingOnline`, `LocalServicingOffline`, `FOD`, `ModifyFOD`, `Repair`, `ReService`,
  `ImageBasedPBR`, `DesktopInplaceUpgrade`, ...); other keys read: `Features` (array), `PackageFileList`, `MediaVersion`,
  `MediaBranch`, `LocalSources`, `LocalSourceSandboxPath`, `ModuleOperation`, `SourceInventory`, `Edition`,
  `SystemLanguage`, `UserLanguages`; any other key is `0x8007000d`. `Features` entries accepted a bare `{"Name":...}`
  (returns 0) but not the `AddIntent` forms tried (`true`, `1`, `"USER"`: `0x8007000d`).
- **Limit (OBSERVED).** With `{"ModuleID":"LocalServicingOnline"}` (and with `LocalServicing`, `ExecuteOnlineCloudPBR`) and
  the real `.NET` KB cabinet plus its CompDB loose in the sandbox, the stack returned `S_OK` and wrote an EMPTY ActionList
  (`SessionData="Unknown" Operation="Unknown"`, no `Downloads`, `Plan` or `Actions`), whereas the native agent's
  ActionList for the same files has `SessionData="DesktopServicing"` and an `InstallPackage`. The session description that
  makes the stack plan the feature `GDR_KB5126052` was not found; `AddIntent` value syntax is unread. The native
  `SessionData` comes from the WUA engine (not readable on the guest). Consequence: the `update_agent` backend reports an
  empty plan as `NotApplicable` and installs nothing.
- **Other exports (READ).** `UA_CreateDownloadListFromActionList(actionList, &count, &list)`: 32-byte entries (tag u32 at 0:
  1 Canonical, 2 PSFX, 3 Diff, 4 ReverseDiff, 5 Express; strings at 8, 16, 24); `UA_ReleaseDownloadList(count, list)`;
  `UA_InstallActionList(opt, 0, actionList)` loads `UpdateAPI.dll` (directory of the running stack DLL, else `System32`;
  the guest has none in `System32`) and calls its `StageUpdateWithActionList`; `UA_CommitActionList(opt)` calls
  `CommitUpdate(1)`. These two were not called.
- **Hosting (READ).** `UpdateDeploy.dll` (UUS) loads the stack with `CreateDeploymentSessionEx`/`CreateDeploymentSession`
  (`GetSupportedSessionInitializationOptions`) and drives an `IDeploymentSession` (`GenerateDownloadRequest`, `Install`,
  `Commit`, `PostDownload`, `Suspend`, `Revert`, `Uninstall`): this session API, not the `UA_*` exports, is what the native
  agent uses, and is the better target for the next stage.

## 13. Stage 1 guest validation (OBSERVED 2026-10-05)

A fresh `win11-25h2` instance cannot be rebooted (the Windows setup dialog "The computer restarted unexpectedly or
encountered an unexpected error" appears and the guest agent never answers; three attempts), and its Delivery
Optimization service cannot be started without a reboot. The runs below therefore used working copies of a clone
(`osi-gold`) of the stopped settled lab guest `w11-ours` (UBR 8037, `Package_for_DotNetRollup_481` 9321.3 installed,
WSUS policy already pointing at `wsus-srv`); a copy survived a reboot. Each copy got a new MAC and, for the native run,
a new `SusClientId`. WSUS: one group `osi-clean` holding only that computer, update `88661612-...` ("2026-09 Cumulative
Update for .NET Framework 3.5 and 4.8.1 ... (KB5126052)") approved for it only; both removed afterwards.

- **Native oracle (WUA COM on the copy).** After renaming `SoftwareDistribution` (a cached search hid the update) the update
  was offered; `Download()` result 2 fetched exactly the 2 declared files (KB cab 96,649,380 bytes and the CompDB cab 10,891
  bytes) and generated `ActionList.xml` (`SessionData="DesktopServicing"`, `InstallFeature GDR_KB5126052`, one
  `InstallPackage Keyform="Package_for_DotNetRollup_481~~amd64~~10.0.9347.1"`, identical to the earlier fixture) AT
  DOWNLOAD TIME. `Install()` result 2, reboot required, 59 s; processes seen: `wuaucltcore.exe` and `TiWorker.exe`. DISM before the
  reboot: 9347.1 `Install Pending`; after the reboot: 9347.1 `Installed`, 9321.3 `Superseded`, `RebootPending` false,
  UBR unchanged (8037).
- **Our client, `osinstaller_mode = "dism"`, on a second copy** (`wsus-os.exe`, feature `osinstaller-handler`): sync 128 s;
  `plan`: `install`, one step (the bundle child, KB cab primary, CompDB cab extra); `install --yes`: 84 s, DISM exit 3010,
  job `reboot_required`, `servicing.diff` identical to the oracle's pre-reboot state (9321.3 `Installed` to
  `Uninstall Pending`, 9347.1 absent to `Install Pending`), oracles `agree_pending`. A re-run before the reboot gave
  `no_action` (the evaluator's `ProductReleaseInstalled` already reads the pending package as installed: INFERRED mapping,
  a possible early success, to be fixed by requiring `Installed`). After the reboot DISM showed 9347.1 `Installed` and
  9321.3 `Superseded`, equal to the oracle.
- **Negative cases (third copy).** One byte of the downloaded KB cab flipped in the client store and `--timeout-secs 3`:
  the run reached DISM (the store re-verified and re-fetched the file: no refusal recorded) and ended `unconfirmed`,
  `timed_out`, DISM left running. Not run: wrong server digest, pending-reboot refusal (the pending state made the
  plan `no_action` instead), `update_agent` mode.
- **Not done:** stage 4 (the `UpdateDeploy` session API). The native flow's ActionList is produced by the download phase
  (WUA calls the stack with a `DesktopServicing` session); our `UA_CreateActionList2` attempts with `LocalServicingOnline`
  produce an empty plan (section 12). Establishing that session is the open item.

## 14. Pre-reboot CBS state of the `.NET` rollup (OBSERVED 2026-10-05)

Recorded on cloned guests (UBR 8037), fixture `docs/fixtures/wsus-m0-osinstaller/dotnet-cbs-state.json`:

| Moment | Package `CurrentState` | Old rollup | `PackagesPending` key | `RebootPending` | `pending.xml` | DISM |
| --- | --- | --- | --- | --- | --- | --- |
| native agent, before reboot | 64 (`Install Client = UpdateAgentLCU`) | 112 | absent | true | no | Install Pending |
| native agent, after reboot | 112 | 80 | absent | false | no | Installed |
| `dism /Add-Package`, before reboot | 96 (`Install Client = DISM Package Manager Provider`) | 5 | 38 entries including the package | true | yes | Install Pending |

The reading "PackagesPending means not installed yet" is therefore CONFIRMED for the DISM path and REFUTED as a
general rule (the native path has no such key); the discriminating fact is `CurrentState` (112 only when installed).
`WindowsUpdate\Auto Update\RebootRequired` is set only by the native agent. The evaluator text now says OBSERVED, and
`Microsoft.NetFX` presence (`ProductReleaseVersion greaterthan 0.0.0.0`) accepts any non-zero state, because with both
rollups in a pending state the earlier reading made the whole update "not applicable" (OBSERVED: plan
`nothing_to_do_not_applicable` on the DISM-pending guest). With the fix our client plans `install` there and the
executor refuses: `a restart or servicing operation is already pending (CBS RebootPending, CBS PackagesPending, WinSxS
pending.xml): restart the machine first` (the pending-reboot refusal, OBSERVED). The earlier pre-reboot `no_action` after
our own install was not reproduced and stays unexplained.

Stage 4 (the `UpdateDeploy` session API) was not started in this round.

## 15. Stage 4 checkpoint: the session API, what is established (READ + OBSERVED 2026-10-05)

Superseded in part by section 16: the session API was then driven successfully; this section keeps the static findings.

- **How the native agent reaches the stack (OBSERVED, wuauserv ETL).** `wuauserv` loads the undocked modules from
  `C:\Windows\UUS\Packages\Preview\AMD64`: `UpdateDeploy.dll` (`wu.core.updatedeploy`) and the handler modules
  `wuauengcore.dll`, `wuuhdrv.dll`, `wuuhext.dll`, `wuuhosdeployment.dll` (the OS deployment handler); it registers
  the `OSDeploymentInformationFactory` COM servers (CLSIDs `{D590B6C9-8D6A-4960-A7DF-FF0327FF5D19}` and
  `{DEAB1CF6-BF64-44E4-B768-A5573E3036AD}`), queues "update ... for download handler request generation" and
  `CAgentDownloadManager::GenerateDownloadRequest` runs; the install runs in `wuaucltcore.exe` (earlier observation).
  `UpdateDeploy.dll` (`OSDeploymentHelper::CDeploymentSessionWrapper::CreateDeploymentSessionFromLibrary`) loads the
  delivered `UpdateAgent.dll` and calls its export `CreateDeploymentSessionEx`.
- **`CreateDeploymentSessionEx(version = 1, workDir, GUID *callbackFactory, optionsVersion 1..6, OptionalSessionInfo *,
  IDeploymentSession **)`** (READ, UpdateAgent 10.0.26100.9457): the version must be 1 and `workDir` an existing
  directory; the object (`CDeploymentSession`, 0x310 bytes, implements `IDeploymentSession` up to `IDeploymentSession10`)
  keeps `ActionList.xml`, `DownloadList.xml` and `windlp.state.xml` there and a `metadata` subdirectory. OptionalSessionInfo
  (up to 0x70 bytes, version 6): `+0 SessionData` (wide JSON), `+8 UpdateId`, `+16 FlightId`, `+24 FlightMetadata`,
  `+32` and `+40` narrow strings (correlation vectors), `+48` working directory override (else `workDir`), `+56` country
  code, `+64` flags, `+104` download capability flags.
- **Methods of the wrapper** (READ, names in `UpdateDeploy.dll`): `get_Id`, `GenerateDownloadRequest`, `Install(
  IDeploymentErrorInfo **, int *)`, `Commit`, `Cleanup`, `Cancel(long)`, `Merge(const wchar_t *)`,
  `GetPostRebootResult(long *)`, `PostDownload`, `Suspend(long)`, `Revert(int *)`, `get_Capabilities`, `Pause`, `Resume`,
  `Uninstall(int *)`. The vtable order of the real interface and the download-request interface were not extracted.
- **SessionData grammar** (READ, `CreateSessionData`): a JSON object; `ModuleID` one of `ModifyFOD`, `FOD`, `LangPack`,
  `EnumerateFOD`, `EnumerateFeatures`, `Repair`, `ReService`, `CreateMedia`, `EnumerateEdition`, `ExportRepository`,
  `ExportRepositoryIncludeInboxFeatures`, `SetupDynamicUpdate`, `ImageDynamicUpdate`, `ImageLocalCompDB`,
  `OnDemandLateAcquisition`, `LocalServicing`, `LocalServicingOffline`, `LocalServicingOnline` (module 16, displayed
  `DesktopLocalServicing`), `ImageBasedPBR`, `CurrentVersionScan`, `DesktopInplaceUpgrade`; keys `Features` (array of
  `{Name, Language, AddIntent[], RemoveIntent[]}` with intents `AVOID`, `CONFIGURATION`, `CONTEXTUAL`, `MSIX`,
  `PREINSTALL`, `SYSTEM`, `USER`), `PackageFileList`, `MediaVersion`, `MediaBranch`, `LocalSources`,
  `LocalSourceSandboxPath`, `ModuleOperation`, `SourceInventory`, `Edition`, `SystemLanguage`, `UserLanguages`.
  OBSERVED: `{"ModuleID":"LocalServicing","Features":[{"Name":"GDR_KB5126052","AddIntent":["SYSTEM"]}]}` is accepted
  (`0x8007000d` for `AddIntent` given as a boolean, number or bare string).
- **`UA_CreateActionList2` is not the native route (OBSERVED).** With option 2 and the real `.NET` files (KB cab and
  CompDB, loose and under `Metadata\`) the stack evaluates the installed features and writes an empty ActionList
  (`SessionData="Unknown" Operation="Unknown"`, `SessionId="TestMode"`); with option 1 it fails with `0x80070003` because it
  reads `C:\Windows\ImageUpdate\OEMInput.xml` (absent on Windows 11 desktop). The native ActionList
  (`SessionData="DesktopServicing"`) is therefore produced by the session API (`GenerateDownloadRequest`), whose inputs
  (the SessionData the handler builds from the update metadata, the callback factory and download-request objects) were
  not captured: tracing needs the handler's COM hosting in `wuaucltcore.exe` (a debugger or an API hook), which this round
  did not set up.

## 16. Stage 4: the session API driven, and the `update_agent` backend validated (OBSERVED 2026-10-05)

Lab: clones of `osi-gold` (a settled `w11-ours`, Windows 11 25H2, UBR 8037), one fresh working copy per experiment;
the delivered stack is `DesktopDeployment.cab` 10.0.26100.9457 extracted to a private directory. The WSUS side was the
authorized group `osi-clean` (one computer) with the `.NET` update approved, removed afterwards.

**Vtable (READ, `CDeploymentSession` vtable at `0x180320148`).** Plain COM (not IInspectable): slots 0 to 2 IUnknown,
3 `get_Id`, 4 `GenerateDownloadRequest(IDeploymentDownloadRequest **)`, 5 `Install(IDeploymentErrorInfo **, int *)`,
6 `Commit`, 7 `Cleanup`, 8 `Cancel(long)`, 9 `Merge(const wchar_t *)`, 10 `GetPostRebootResult(long *)`, 11 `PostDownload`,
12 `Suspend(long)`, 13 `Revert(int *)`, 14 `get_Capabilities`, 15 `Pause`, 16 `Resume`, 17 `Uninstall(int *)`.

**What drives it (OBSERVED, `crates/wsus-client/examples/ua_session.rs` and the backend).**

| Input | Result |
|---|---|
| `CreateDeploymentSessionEx(1, dir, GUID, 6, info, &s)` with a NULL GUID pointer | access violation: the GUID is dereferenced (READ: copied to `v24`) |
| SessionData file written with a UTF-8 BOM | `0x8007000d` (the log shows the BOM as `U+FEFF` in the JSON) |
| SessionData `{"ModuleID":"LocalServicing", Features:[GDR_KB5126052]}` | session created (`Scenario` 16), ActionList EMPTY: "Edition version is unchanged ... CompDB not applicable" |
| NO SessionData (all-zero `OptionalSessionInfo`) | `Scenario` "Upgrade or update", the Arbiter logs "Standalone packages, installing" and "Desktop Servicing, notify servicing stack"; the ActionList equals the native one (`SessionData="DesktopServicing"`, `InstallFeature GDR_KB5126052`, `InstallPackage Package_for_DotNetRollup_481~~amd64~~10.0.9347.1`) |
| non-zero callback GUID (`24c49901-...`, the handler class id) | `Install` fails `0x80040154` (`IDeploymentInformationFactory` COM server not registered: only `wuauserv` registers it) |
| all-zero callback GUID | the progress COM server is skipped (READ), `Install` runs |

The native `windlp.state.xml` fixture also has no SessionData string and `Scenario` 4, which is how the no-SessionData
call was found. The CompDB cabinet must be a loose file in `<sandbox>\metadata` (the log warns "Missing
AggregateMetadata.cab! CompDBs are expected to be downloaded as loose files" and verifies `metadata\*.xml.cab`).

**Sequence that worked, all `S_OK`:** `CreateDeploymentSessionEx`, `GenerateDownloadRequest` (writes `ActionList.xml`,
`DownloadList.xml`, `DeviceInventory.xml`; benign `0x80040154` for `IDeploymentInformationFactory` in the log), `PostDownload`,
`Install`, `Commit`. Direct probe run on one copy: `Install` flag 0, "Reboot required: FALSE", the new rollup went straight to
`CurrentState` 112 (old 80). Through our client on two other copies: `Install` flag 1, new rollup `64`, `RebootPending`
present, job `reboot_required`; after a reboot new `112` and old `80`, `dism` lists the old rollup `Superseded`, the new
`Installed`: the same states as the native oracle (section 14 table). The flag is therefore the reboot request (observed
0 and 1); why the direct probe run needed no reboot was not investigated.

**Our client, `update_agent` mode, delivered stack (OBSERVED).** `wsus client install` with
`osinstaller_mode = "update_agent"`, `osinstaller_stack_dir = C:\ua\stage` (14 DLLs of the cabinet): phases
`create_session`, `generate_download_request`, `post_download`, `install`, `commit` all `0x00000000`, backend class `reboot`,
job `reboot_required`, `CurrentState` 64 and `UpdateAgentLCU` before the reboot, 112 after. A rerun after the reboot
answers `no_action`.

**Negative cases (OBSERVED, `update_agent` mode).**

| Case | Outcome |
|---|---|
| tampered stack DLL (one byte of `UpdateAgent.dll` flipped) | refused before any load: `refusing the delivered update stack: ...UpdateAgent.dll is not acceptable: the signature does not verify: WinVerifyTrust 0x80096010`; job `failed`; the package was not touched |
| pending reboot | refused: `a restart or servicing operation is already pending (CBS RebootPending): restart the machine first` (reached for real: the first attempt to set the `RebootPending` key by hand was denied by its ACL, so the update installed and left the real pending state; the second run was refused) |
| tampered payload (one byte of the stored KB cabinet) | NOT a refusal: `client install` runs the acquisition first, which detected the unusable stored file and re-fetched it (the file hash then matched the declared digest again); the install proceeded with the verified copy and succeeded. The executor's own re-hash gate (`gate_all`) was not reached by a mismatch on a guest; it is covered by host tests only |
| wrong server digest (the metadata declaring a digest that the file does not have) | NOT run: it needs an edit of the WSUS database, which was not authorized. The tampered-payload case above is its client-side equivalent only up to the acquisition step |

**Limits.** One update (`.NET` rollup, complete 2-file set) on one Windows build. Not validated: the system `System32` stack
as `StackSource::System` through the session API (the delivered stack was used), monthly cumulative updates, a progress or
result callback COM server (an all-zero factory GUID skips it, so progress callbacks and `IDeploymentErrorInfo` details were
not exercised), `Cancel`, and `Cleanup`. The executor did not yet fetch `DesktopDeployment.cab` itself at the time of
section 16: the stack directory was configuration (see section 17 for the fetch and for the `System32` stack). The host test
suite does not run the Windows backend.

## 17. Executor-fetched stack (host tests) and the `System32` stack through the session API (OBSERVED 2026-10-05 to 06)

**Executor fetches and stages the stack (implemented, HOST TESTS ONLY).** When an `OSInstaller` update declares
`DesktopDeployment.cab` with `PatchingType` `ServicingStack` and a SHA-1 or SHA-256 digest, the planner records it as the
step's `stack_payload` (it is never a sandbox payload and never an `extra_payload`); the acquisition path already downloads
every declared file with digest verification. In `update_agent` mode, unless the backend was given an explicit stack
directory (`osinstaller_stack_dir`, which stays the override), the executor re-hashes the stored cabinet, extracts every
member (flat names only, 256 MiB per member, 1 GiB total) to `<jobs>/<job id>-os/stack`, passes that directory in the
backend request (`stack_dir`), and the backend Authenticode-verifies every DLL before loading `UpdateAgent.dll` from it,
exactly as for a configured directory. The directory is removed afterwards (kept after a timeout, the stack is not stopped)
and the job records `fetched_stack` (file, digest, members). A missing, tampered or unextractable stack cabinet fails the
step before the backend runs. Host tests (`tests/install_osinstaller.rs`, fake backend, stack cabinets built with `caby`):
planning, extraction and hand-over, override, no declared stack, tampered and missing cabinet, `dism` mode ignoring the
stack. (Superseded by section 19: a real `DesktopDeployment.cab` fetched from the real WSUS was loaded on a guest.) Originally NOT observed: a real `DesktopDeployment.cab` fetched from the WSUS and loaded on a guest. The only `OSInstaller`
update used on guests (the `.NET` rollup, 2 declared files) does not declare `DesktopDeployment.cab`; the updates that
do (the monthly cumulative updates) are still refused as incomplete sets, so no live path reaches the new code yet. The
member-name check (path separators, `..`) is not covered by a test because the `caby` writer refuses such names.

**`StackSource::System` through the session API (OBSERVED, one guest).** Clone of `osi-gold` (settled `w11-ours` state,
UBR 8037, `Package_for_DotNetRollup_481` 9321.3 `Installed`, System32 `UpdateAgent.dll` 10.0.26100.7920), new
`SusClientId`, WSUS group with only that clone, update `88661612-...` approved for it only. `wsus.exe` with the
`osinstaller-handler` feature, config `osinstaller_mode = "update_agent"` and NO `osinstaller_stack_dir` (the update declares
no stack cabinet), so the backend resolved `System32\UpdateAgent.dll`. `client install --yes`: status `reboot_required`,
phases `create_session`, `generate_download_request`, `post_download`, `install` (out flag 1, no error info), `commit` all
`0x00000000`, 156 s by the guest's stopwatch; no `fetched_stack` and no stack directory. The generated `ActionList.xml` has
`SessionData="DesktopServicing"`, `InstallFeature GDR_KB5126052`, `Keyform="Package_for_DotNetRollup_481~~amd64~~10.0.9347.1"`
(as native and as with the delivered 9457 stack). Before the reboot: new rollup `CurrentState` 64, `InstallClient`
`UpdateAgentLCU`, old 112, `RebootPending` present. After one reboot: a first read soon after boot showed new 96, old 5 and
`RebootPending` still present (boot-time servicing still running); a later read showed new 112, old 80, `RebootPending`,
`PackagesPending` and `pending.xml` absent, `dism` listing 9347.1 `Installed` and 9321.3 `Superseded`, `clr.dll` 4.8.9345.0,
and a rerun of `client install` answered `no_action`. The System32 stack therefore produced the same package states as the
delivered 9457 stack and the native agent for this update. NOT established: that the process really loaded
`System32\UpdateAgent.dll` (inferred from the configuration and the code path, no module list was taken); anything for
other updates or builds; the failure behaviour of the System stack (no failure was observed, none was provoked); monthly
cumulative updates. The 7920 versus 9457 difference did not show in this update's outcome. The lab guest ran far slower
than wall-clock (host load about 15), which only affected waiting. WSUS side removed afterwards: the approval, the group;
the clone's computer record was already absent when the cleanup ran (another clone with the same host name and a different
id was present and was left alone).

## 18. Open items: feasibility and lab results (OBSERVED 2026-10-05 to 06)

Four items were open: (1) a real monthly `OSInstaller` cumulative update through `update_agent` mode, (2) reboot, uninstall
and rollback handling, (3) a real servicing stack update, (4) `wusa` on a real `.msu`. Phase 1 was read-only (the lab WSUS
`wsus-srv` through its admin API, host content directories); phase 2 ran on clones of `osi-gold` (settled `w11-ours`,
Windows 11 25H2 10.0.26200.8037, `Package_for_RollupFix` 26100.8037.1.19, servicing stack `Package_for_ServicingStack_8035`,
`Package_for_DotNetRollup_481` 9321.3).

### 18.1 Phase 1: what is obtainable

- The WSUS catalog holds 4,546 updates. Non-declined, non-superseded Windows 11 / `.NET` entries: 29, one monthly cumulative
  update for 25H2 x64, `725139c2-ea1b-4ea2-aeff-79256d5a4f68` ("2026-09 Cumulative Update for Windows 11, version 25H2 for
  x64-based Systems (KB5129195) (26200.9457)"), and the `.NET` update `88661612-...` (KB5126052, content present). There is no
  separate servicing stack update in the catalog (the stack ships inside the cumulative update, as `SSU-26100.9441-x64`).
- The cumulative update leaf declares 19 files totalling 14,306,190,901 bytes (two `.msu` of 533,761,740 and 4,639,422,594
  bytes, `FoD_Common.wim` 5,071,315,940, `Edition_Common.wim` 2,461,590,545, `LP_Desktop.wim` 923,684,337, a 436,783,921-byte
  `.psf` and others). None of it is in the WSUS content store (171 files, 1.3 GB, the `.NET` cab among them). Approving it
  would make `wsus-srv` download all 14.3 GB. `wsus-srv`'s disk is a 21 GB qcow2 overlay on a host filesystem that had 13 GB
  free, so the approval was not made (it would also have changed `wsus-srv` state, which was out of bounds).
- Host files already present: the real 24H2 baseline `Windows11.0-KB5043080-x64.msu` (533,761,740 bytes, build 26100.1742),
  the `.NET` cab, `DesktopDeployment.cab` extracted stack files under `/data/cache/osi-ua`.
- The Microsoft Update Catalog (the route `docs/fixtures/cbs-psfx-native/pre-esu-download.json` already used) lists the same
  update: its `DownloadDialog` gave a link to `Windows11.0-KB5129195-x64.msu` (4,639,422,594 bytes, the size and the hash in the
  file name equal the WSUS metadata's; SHA-1 `ed361878ec2b56a7dfdb8f256565263a7fdc8eaa` recomputed, equal). That `.msu` contains
  `SSU-26100.9441-x64.cab`, `DesktopDeployment.cab` and `_x86`, `Windows11.0-KB5129195-x64.psf` (2.25 GB), `.wim`,
  `.mumx.esd`, and msix files (7z listing).

| Item | Verdict | Why |
| --- | --- | --- |
| 1. Monthly cumulative update through `update_agent` mode and the WSUS path | NOT feasible at the time; DONE later, see section 19 | the WSUS has no content for it and cannot be given 14.3 GB; `client install` also refuses monthly updates as incomplete sets (section 17); the stack-fetch code is being changed by another agent |
| 1b. The same real cumulative update through the Catalog `.msu` and `wusa` | feasible, DONE (18.2) | content fetched from the Catalog (an endpoint already used by this repository), no WSUS write |
| 2. Reboot, uninstall, rollback | feasible natively, DONE for the `.NET` rollup and the cumulative update (18.2 to 18.6); the client-side uninstall step of 18.9 is implemented and was run on guests (18.11) | |
| 3. Real servicing stack update | feasible, DONE (18.2, 18.7): the real `SSU-26100.9441-x64.cab` through DISM, and inside the `.msu` | not tested through our client (no WSUS content) |
| 4. `wusa` on a real `.msu` | feasible, DONE (18.2, 18.6) | `wusa` was run by hand in 18.2; the `wusa` backend of our client was exercised afterwards on the same `.msu` (18.12) |

Lab handling: clones `osi-lcu-1` and `osi-lcu-2` (new MAC, user networking, VNC 40 and 41, files served from the host on
port 18720), the clones' `WUServer` and `WUStatusServer` policy values were set to `http://127.0.0.1:9` and `SusClientId`
removed before any update work, so the clones could not report. No WSUS group, approval or computer record was created; the
WSUS was only read (the `deployv-topvv2a` computer record seen in the WSUS list at 22:15 belongs to another clone of
`osi-gold`: both clones' new `SusClientId` values are absent from the WSUS list).

### 18.2 Real cumulative update with an embedded servicing stack update, by `wusa` (OBSERVED, clone `osi-lcu-1`)

`wusa C:\lcu\Windows11.0-KB5129195-x64.msu /quiet /norestart`, 4.6 GB local file (copied from the host with `curl.exe`
in 23 s; `Invoke-WebRequest` managed about 0.5 MB/s on the same path and was abandoned).

- Duration 14.7 minutes from the start to the "installed" event (Setup log 22:08 to 22:22:59 guest time); the servicing stack
  part (Setup log package `KB5124007`, taken to be the stack update because `Package_for_ServicingStack_9441` appeared at that time: Absent, Staged 22:08:14, Installed 22:14:58) came first, then `KB5129195` (Staged 22:15:13 to 22:19:48,
  Installed requested 22:20:00). CBS client id `UpdateAgentLCU` for both packages (`wusa` reached the same stack as the
  native agent). Setup events: "was successfully installed" and "requires a computer restart".
- The exit code of this `wusa` run was NOT captured (the `vm-exec` call that held it timed out; the process itself finished).
  The "restart needed" Setup event is the evidence of the reboot request, 3010 is the expected value and was not seen.
- Servicing stack: `Package_for_ServicingStack_9441` 26100.9441.1.11 reached `CurrentState` 64 then 112 (`Installed`) before the
  cumulative update started; the engine DLL `wcp.dll` in WinSxS is 10.0.26100.9441 from that point; 8035 stays `Installed`
  (it is not `Superseded`). `servicing\TrustedInstaller.exe` still shows 10.0.26100.7019 before and after the reboot.
- Before the reboot: `Package_for_RollupFix` 26100.9457.1.0 `CurrentState` 96 (`Install Pending`, `UpdateAgentLCU`), 26100.8037
  state 5 (`Uninstall Pending` in DISM), `RebootPending` true, `PackagesPending` true, `pending.xml` present, and
  `WindowsUpdate\Auto Update\RebootRequired` true (set here, unlike with `dism /Add-Package`). The update history entry
  stayed at result 1 (in progress).
- After one reboot: build 26200.9457 at the first read (about 40 s after boot) but the package still 96 and `PackagesPending`
  true; about 100 s later 9457.1.0 `Installed` (112), 8037 `Superseded` (80), all pending indicators gone. So the boot-time
  finalization takes a few minutes and a client must poll, as the `.NET` runs already showed (section 16, 17).

### 18.3 Rollback of a pending install (OBSERVED, `.NET` rollup, clone `osi-lcu-2`)

After `dism /Add-Package` of the KB5126052 cab (exit 3010, new rollup 96, old 5, `PackagesPending`, `pending.xml`), a
`dism /Remove-Package` of the new package BEFORE the reboot succeeded (exit 3010, new rollup state 5, old rollup 96). After the
reboot: 9321.3 `Installed` (112), 9347.1 absent from the listing, no pending indicator. The pending install was therefore
rolled back by the same command that uninstalls. Not observed: a failed install's automatic rollback.

### 18.4 Uninstall of an installed `.NET` rollup (OBSERVED, `.NET` rollup)

`dism /Online /Remove-Package /PackageName:Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1 /NoRestart`
on the installed rollup, tried twice: after a DISM install (client `DISM Package Manager Provider`) and after an
`update_agent`-route install (client `UpdateAgentLCU`, 18.5). Both: exit 3010 in 10 to 12 s; 9347.1 to state 5, the
superseded 9321.3 back to 96 (`Install Pending`), `RebootPending`, `PackagesPending`, `pending.xml`; `clr.dll` still 4.8.9345.0.
After a reboot 9321.3 `Installed`, 9347.1 gone, `clr.dll` 4.8.9221.0 (the version before the rollup). The earlier native
oracle states of section 14 are thus reversed by DISM in one step plus a reboot.

### 18.5 The session API's own uninstall and revert (OBSERVED, `.NET` rollup, probe `ua_session`)

`crates/wsus-client/examples/ua_session.rs` gained the steps `revert` (vtable slot 13) and `uninstall` (slot 17), both calling
`(session, int *)`. On a clone with the stack of `DesktopDeployment.cab` 9457 in `C:\ua\stage` and the `.NET` files in the
sandbox, the sequence `gdr,post,install,commit` (all `0x00000000`, install flag 1) installed the rollup (new 64,
`UpdateAgentLCU`, after the reboot 112; same as section 16). Then, with a new session created over the same working
directory (its `windlp.state.xml` was deserialized: `RebootRequired = TRUE` before the reboot):

| Call | Before the reboot | After the reboot |
| --- | --- | --- |
| `Uninstall` (slot 17) | `0x80004001` (E_NOTIMPL), out value 0, nothing changed | `0x80004001`, nothing changed |
| `Revert` (slot 13) | `0x80070032` (ERROR_NOT_SUPPORTED), nothing changed | not run |

For the `DesktopServicing` scenario of this update the session API therefore offers no uninstall; the CBS-level `Remove-Package`
(18.4) removed an `UpdateAgentLCU`-installed package. Not run: the session calls for a cumulative update, `Cancel`,
`Cleanup`, `GetPostRebootResult`.

### 18.6 Uninstall of the cumulative update, and `wusa /uninstall` (OBSERVED, clone `osi-lcu-1`, after 18.2)

- `dism /Online /Remove-Package /PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0 /NoRestart`:
  `0x800f0825`, 3 s, nothing changed. `dism.log`: "Permanent package cannot be uninstalled". The Setup log:
  "Package KB5129195 failed to be changed to the Absent state. Status: 0x800f0825." The monthly cumulative update of this build
  is not removable by DISM.
- `wusa /uninstall /kb:5129195 /quiet /norestart`: exit 87 (`0x57`, "The parameter is incorrect", Setup event 8), nothing changed.
- `wusa` on the older real `.msu` `Windows11.0-KB5043080-x64.msu` (533,761,740 bytes, a baseline for build 26100.1742) after the
  newer update: exit `0x80240017` (`WU_E_NOT_APPLICABLE`) in 4 s, no package change.

Consequence for a client-side uninstall: it must treat the cumulative update as non-removable (the verdict can only be learned
from the stack's answer, `0x800f0825`; the registry `CurrentState` and DISM's listing give no "permanent" marker that was
identified), while `.NET` rollups are removable.

### 18.7 Servicing stack update on its own (OBSERVED, clone `osi-lcu-2`)

`dism /Online /Add-Package /PackagePath:C:\lcu\SSU-26100.9441-x64.cab /NoRestart` with the cab extracted from the `.msu` (20,623,941
bytes, SHA-1 `161e61ddb65e96738f11308affd6f2c9ce9c3ce` computed on the extracted file): exit 0 in 7.8 s with the message
"The changes due to package Package_for_ServicingStack_9441 requires the current servicing session to be reloaded. All the
packages will be processed again." The package was `Installed` (112, `DISM Package Manager Provider`) immediately, with no
`RebootPending`, no `PackagesPending` and no `pending.xml`; `wcp.dll` 10.0.26100.9441 appeared in WinSxS; 8035 stayed `Installed`.
A servicing stack update therefore needs no reboot barrier on this build when added alone, which differs from
`wusa`'s combined run (18.2, where the stack was committed before the cumulative update started). This was not run through
our client (the WSUS has no SSU content and the plan's SSU prerequisite scheduling, C46, remains validated on host tests and
a synthetic plan only).

### 18.8 Where this leaves the items

| Item | Status after this round |
| --- | --- |
| 1 | Not done through `update_agent` mode. The real cumulative update was installed through `wusa` (reboot, package states observed). Blockers for the client path: no WSUS content (14.3 GB declared, disk), the executor's refusal of monthly update sets, and the session SessionData for a cumulative update (the ActionList of a monthly update was produced by the native agent only, section 4.3) |
| 2 | Reboot and re-evaluation: `reboot_required` and the post-reboot states were already observed for `update_agent` mode (sections 16, 17); uninstall and rollback of a pending install observed for the `.NET` rollup with DISM; cumulative update uninstall refused by CBS (permanent). The client-side uninstall step was implemented afterwards (18.11) |
| 3 | Standalone stack update observed with DISM, embedded stack update observed with `wusa`; not through our client |
| 4 | `wusa` observed on a real 4.6 GB `.msu` (install, reboot) and on an older `.msu` (not applicable); our `wusa` backend run on the same `.msu` in 18.12 (exit 3010 captured) |

### 18.9 Client-side uninstall: worth it, design (PROPOSED; implemented in 18.11)

Worth designing for `.NET` rollups and other removable packages, because `Remove-Package` is a one-step, reversible-by-reboot
operation that the existing servicing backends could carry; not worth building for monthly cumulative updates (permanent).

- Trigger: an approval of action Uninstall for an update that declares `UninstallationBehavior` (`handlers/cbs.rs` already parses
  it). The WSUS side (the server's handling of removal approvals) was not examined in this round.
- Plan: map the update to its CBS identity (the manifest or the ActionList `Keyform`, as for install), refuse when the identity is
  absent, when a restart or servicing operation is pending (the existing gate), and when the update class is a cumulative
  update with a known "permanent" answer.
- Execution: a `remove_package(identity)` method on `ServicingBackend` (DISM `/Remove-Package`, DISM API `DismRemovePackage`);
  exit 3010 gives the same `reboot_required` class as install; `0x800f0825` gives a `failed` job with the reason recorded
  as "permanent package", not a retry.
- Post-check (two oracles, like install): after the reboot the identity is absent from the DISM listing and from
  `Component Based Servicing\Packages` and the evaluator says the update is applicable again; also record that the predecessor
  returned to `Installed` (observed for the `.NET` rollup: 9321.3). A pending-install rollback (18.3) is the same call.
- Do not use `update_agent`'s session `Uninstall` (E_NOTIMPL here).
- Open: the reporting side (what the WSUS expects to hear after an uninstall), a failed-uninstall path (none provoked), whether
  the evaluator re-offers the update immediately (it will: the install rule is false again).
- Not implemented because `servicing/mod.rs`, `dism.rs` and `dism_api.rs` are shared with other work in progress and the trait
  change would touch them; needs the owner's decision first. (Superseded by 18.11: implemented 2026-10-06, with two
  corrections of this design, below.)

### 18.11 Client-side uninstall implemented and run on guests (OBSERVED 2026-10-06)

`wsus client uninstall` (plan `wsus-install-plan/3`, job `wsus-install-job/3`, `ServicingBackend::remove_package` for `dism`
and `dism_api`; documentation `docs/wsus-install.md` (Uninstall) and `docs/wsus-cli.md`, ledger C50). Corrections of 18.9
found in the real catalog metadata of the target update:

- The real `.NET` rollup leaf (`OSInstaller`, KB5126052) declares NO `UninstallationBehavior` (only `InstallationBehavior`) and its
  core fragment has no package manifest (`IsInstalled` is `ProductReleaseInstalled Microsoft.NetFX.amd64 2400.26200.9347.1`).
  18.9's trigger ("an update that declares `UninstallationBehavior`") would refuse that very update, and "the identity from the
  manifest" does not exist for it. Conservative choices taken: refuse by default, an explicit `--allow-undeclared` (plan and
  executor) records the operator's request; the identity is `--package`, else the manifest (`Cbs`), else the digest-verified
  CompDB cabinet in the content store (one package or refuse).
- The pending-install rollback (18.3) is not offered through the client: the pending gate refuses first.

Run (clones of `osi-gold`, no WSUS contact, two REAL catalog revisions and the real CompDB cabinet as the only content):
the `.NET` rollup installed by `dism /Add-Package` (3010), restart, settled; then `client uninstall --yes`.

| Backend | Result |
| --- | --- |
| `dism` | `/Remove-Package` exit 3010, job `reboot_required`; 9347.1 to registry state 5 and absent from the listing, 9321.3 `Superseded` to `Install Pending` (96); `RebootPending`, `PackagesPending`, `pending.xml`; both oracles said removed; after the restart 9321.3 `Installed` (112), 9347.1 gone, `clr.dll` 4.8.9221.0: identical to 18.4 |
| `dism_api` | `DismRemovePackage` 3010, the same states before and after the restart |
| permanent | `Package_for_RollupFix` 26100.8037.1.19 (the guest's baseline cumulative update, not the 9457 of 18.6): `0x800f0825`, job `failed`, `refusal_class permanent_package`, nothing changed, the second run refused from the job store without a DISM call |

Not observed: timeout, a removal without a restart, a pending-install rollback through the client, `0x80070BC2`, the 9457
cumulative update (the 8037 baseline answered the same way), reporting to a WSUS. Working clones removed; `osi-gold` kept.

### 18.12 The `wusa` backend through our client on the real cumulative update (OBSERVED 2026-10-06, clone `osi-wusa-1`)

Closes the gap noted in 18.2 (exit code not captured) and 18.8 item 4 (backend not exercised). What ran is only PART of the
chain: the metadata was NOT served by a WSUS. The lab WSUS was neither written nor contacted (the clone's `WUServer` and
`WUStatusServer` were set to `http://127.0.0.1:9` and its `SusClientId` removed first).

- Route: this project's own `wsus server run` on the host (loopback, port 18741), populated by `wsus admin catalog import` with
  ONE synthetic update in the real `Cbs` handler shape (`Handler` `.../UpdateHandlers/Cbs`, `HandlerSpecificData` `cbs:Cbs`,
  `IsInstalled` = `CbsPackageInstalled` and not the `LCUReoffer` flag as in `docs/fixtures/wsus-m0-cbs/cbs-rollupfix-core-reduced.xml`,
  `IsInstallable` = `CbsPackageInstallable`, manifest identity `Package_for_RollupFix` 26100.9457.1.0) declaring the real
  `Windows11.0-KB5129195-x64.msu` (4,639,422,594 bytes, SHA-1 `ed361878ec2b56a7dfdb8f256565263a7fdc8eaa`, SHA-256
  `b33ff7aa...6dfa`) as its only file. The real leaf is an `OSInstaller` update of 19 files; the executor refuses that shape
  (section 17), so this route tests the backend and the executor, NOT the real WSUS metadata and NOT `update_agent` mode.
  The `.msu` came from the Update Catalog (the same URL route as 18.1; SHA-1 recomputed).
- Client: `wsus.exe` (feature `cbs-handler`, built from `6f66132`), `servicing_backend = "wusa"`, `delegate_cbs_installable = true`,
  `timeout_secs = 3600`, SYSTEM, a private state directory under `C:\wsus`. `client sync` (1 revision), `client scan` (`applicable`),
  `client plan` (`wsus-install-plan/1`, one `servicing` step, `servicing_identity` `Package_for_RollupFix~...~26100.9457.1.0`).
- Gates met on the way (real, not provoked): the first `install --yes` was refused because the store file was writable by everyone
  (the state directory inherited the volume's ACL; fixed by a private ACL on the directory); the next was refused with
  `PendingFileRenameOperations` (set by OneDrive in the clone before any update work; cleared by a restart).
- `client install --yes`: download of the 4.6 GB from the host (about 25 s on this path), digest re-check, `wusa` started by the
  backend, step 07:47:19Z to 07:59:01Z (11.7 minutes), **exit code 3010** recorded in the job record (`exit_code` 3010, `exit_class`
  `reboot`, description "0x00000bc2: completed, a restart is required"), job `reboot_required`, `servicing.oracles.combined`
  `agree_pending` (evaluator not installed, listing `Install Pending`). The client process exited 0. The Setup log carries the
  exact command line `wusa.exe <store path>\Windows11.0-KB5129195-x64.msu /quiet /norestart` (events 2 "successfully installed" and 4 "requires a
  computer restart", 07:59:01; `KB5124007`, the stack, `Installed` 07:52:54, then `KB5129195` Staged 07:56:21).
- Before the restart: `Package_for_ServicingStack_9441` 26100.9441.1.11 `Installed` (112), `wcp.dll` 10.0.26100.9441,
  `Package_for_RollupFix` 9457 state 96 (`UpdateAgentLCU`), 8037 state 5, `RebootPending`, `PackagesPending`, `pending.xml`,
  `WindowsUpdate RebootRequired` all present. The post-run DISM listing grew from 142 to 208 packages (the update also moves
  about 60 FoD and language packages to `Install Pending`, recorded in the job's `servicing.diff`).
- After one restart: a rerun of `client install` at about 40 s of uptime (build already 26200.9457, 9457 still 96,
  `PackagesPending`) was `refused` before any call with "a restart or servicing operation is already pending (CBS RebootInProgress)";
  a rerun at about 81 s was `no_action` (evaluator: installed) and the registry then read 9457 112 (`Installed`), 8037 80
  (`Superseded`), 9441 112, no pending indicator, `dism` listing 9457 `Installed`, 8037 `Superseded`: the same states as 18.2.
- Not observed through the client: `0x80240017` (the older `.msu` of 18.6 was only run by hand; an attempt to plan it through the client
  stopped at the evaluator, which answers `unknown` for a package in registry state 64, the `Staged` baseline), `0x240006`, a `wusa`
  failure, a timeout, a `.msu` for a different architecture; reporting; the stack update as a separate step. The backend code needed
  no change; its exit-code mapping and timeout handling gained host tests (`servicing/wusa.rs`). Ledger row C51.

### 18.10 Lab state

Working clones and copied files removed at the end; `osi-gold` kept. Host scratch `/data/cache/osi-lcu` holds scripts only; the 18.12 run used the clone `osi-wusa-1`, the scratch `/data/cache/osi-wusa` (scripts only after cleanup, the 4.6 GB download and the imported content store deleted) and a host-side `wsus server run` on port 18741, stopped afterwards.
`wsus-srv`, `w11-ours`, `w11-cli`, the SUSDB and the WSUS configuration were not modified.

## 19. The real monthly cumulative update through the real lab WSUS and `update_agent` mode (OBSERVED 2026-10-06, clone `osi-m2-1`)

Closes item 1 of section 18 (it was "NOT feasible here": no WSUS content, the executor refused monthly sets). What ran: the
real WSUS `wsus-srv` (Windows Server 2025, protocol 3.2) served its real metadata and its real downloaded content for
`725139c2-ea1b-4ea2-aeff-79256d5a4f68` (KB5129195, 26200.9457, 19 declared files, 14,306,190,901 bytes) to this project's
client (`wsus.exe` built from the working tree of this round, features `osinstaller-handler`), which synchronized, downloaded,
planned and installed it with `osinstaller_mode = "update_agent"` on a Windows 11 25H2 guest (clone of `osi-gold`, UBR 8037,
`Package_for_RollupFix` 26100.8037.1.19, servicing stack 8035). Nothing was synthetic: metadata, files, stack and guest are real.

**WSUS side (authorized, removed afterwards).** Group `osi-lcu2` holding only the clone's computer record (the client's own
identity `1c005127-...`, `osi-m2-1.lab.invalid`, registered by the first `client sync`: 788 pages, 5,337 revisions, 1,102 extended
fragments, 199 s on the guest); the update approved (action Install) for that group only. WSUS downloaded the content itself
(progress counter 0.00 to 13.32 GiB, finished without intervention; not timed): content store 1.23 GB in 171 files before,
14.55 GB in 323 files after (it stays), `wsus-srv` guest free space 41.4 GB before, 28.1 GB after, host `/data` about 700 GB,
host `/` 70 GB (limits of 8 GB, 100 GB and 20 GB never approached). Afterwards: approval removed (a `NotApproved` row is what the
admin API leaves; the update then has no approval), group deleted, the computer record deleted by id after checking its name;
no record with id `3e5297a4...` (`w11-ours`) or of `w11-cli` was touched, and none with that id existed at the end.
The clone started with `w11-ours`'s `SusClientId` and a WUA policy pointing at `wsus-srv`; both were changed (policy to
`http://127.0.0.1:9`, a new `SusClientId`) within about a minute of its first boot; the native agent therefore did not scan in
this run, and whether it contacted the WSUS during that first minute was not checked.

**What the client did (before the code change, section 17 and the executor).** `client plan` on the real leaf
(`53aaab51-2c0f-45d5-8204-37583662181c@100`) gave one servicing step with the largest file as the only payload; the executor
refused it as an incomplete set ("not a complete small cabinet set": `plan.rs` `pick_servicing_payload` treated an OSInstaller
update as one set only when every file was a `.cab` and the total at most 2 GiB, `executor.rs` `os_installer_refusal` refused a
step without extra payloads). Reason: the stack picks its files from its own download list, which stage 1 could not name.

**Code changes (host tests: `tests/install_osinstaller.rs`, `servicing/os_installer.rs`, `servicing/msu.rs`).**
- Plan: an OSInstaller update is one complete set when every declared file has a name, a size and a SHA-1 or SHA-256 digest
  (total at most 64 GiB as a metadata sanity bound). Primary payload: the largest non-`Metadata` `.cab` or `.msu`. A set with a file
  lacking a digest is an error of the plan; a single declared file stays refused ("does not declare a complete acquirable file set").
  The `DesktopDeployment.cab` stack payload is unchanged (section 17).
- Executor: hard links, not copies, put the 18 sandbox payloads (14 GB) in the job's sandbox (copy as fallback); sandbox file names
  drop the WSUS content-hash prefix (`<40 hex>_FoD_Common.wim` to `FoD_Common.wim`) and `<hash>_<guid>_Wsus.AggregatedMetadata.cab`
  becomes `<guid>.AggregatedMetadata.cab`; the free-space gate counts such payloads once (they are already on disk) instead of
  three times (42.9 GB needed against 27.4 GB free refused the first attempt); a monthly set has no CompDB cabinet, so in
  `update_agent` mode its post-check identities are the ActionList's `InstallPackage` keyforms (in `dism` mode a set without a CompDB
  cabinet is refused with a pointer to `update_agent`).
- Backend: `*.AggregatedMetadata.cab` is also put into `<sandbox>\metadata` (READ in `ExpandCompDBs`: it searches the metadata folder
  for that pattern); after `GenerateDownloadRequest` a download-list file the declared set lacks is taken out of the declared `.msu`
  files (a Windows 11 `.msu` is a WIM archive, read with the `wim` crate, host-tested on the real baseline `.msu`), and so are the
  `ExpressSourceName` `.psf` files. The job records every such file (`os_installer.provisioned`: name, container, bytes) and the
  stack's `DownloadList.xml`, `windlp.state.xml` and `DeviceInventory.xml` are kept in the job's log directory.

**Path to the working run (each step observed on the guest; what was NOT isolated is said).**

| Step | Outcome (numbered in the order tried, not by the guest's job count) |
|---|---|
| 1 | refused: store file writable by everyone (private ACL on `C:\wsus` needed, as in 18.12) |
| 2 | refused: `PendingFileRenameOperations` (set in the clone before any update work; a restart cleared it, as in 18.12) |
| 3 | refused by the free-space gate (see above), fixed |
| 4 | the stack ran: `generate_download_request` `0x00000000` but the ActionList was empty (`SessionData="DesktopUpgrade"`, "No DBs found in the sandbox ...\metadata", "Missing AggregateMetadata.cab"): the aggregated metadata cabinet was not where `ExpandCompDBs` looks, under the name it expects |
| 5 | `GenerateDownloadRequest` `0xC1900401` (with the cabinet named but only in the sandbox root) |
| 6 | the real ActionList (`SessionData` as native, four packages: `Package_for_RollupFix` 26100.1742.1.10 `StagePartial` and 26100.9457.1.0, `Package_for_SafeOSDU` 26100.9444.1.29, `Package_for_ServicingStack_9441`); its download list names `Windows11.0-KB5043080-x64.wim`, `Windows11.0-KB5129195-x64.mumx.esd` (Express), `Windows11.0-KB5124015-x64.cab` and `SSU-26100.9441-x64.cab`; the WSUS declares neither the wim, the esd nor the canonical SSU cabinet as files: they are members of the declared `.msu` files (`AltSourceName` in the ActionList). Stopped by the executor's missing-file gate |
| 7, 8 | extraction from the sandbox's `.msu` failed: the sandbox links of the `.msu` files were gone (`os error 2`): OBSERVED, the stack removes declared files from the sandbox during `GenerateDownloadRequest`; extraction now reads the verified store files |
| 9 | after the fix the stack's `PostDownload` returned `0x8024200D` (`WU_E_UH_NEEDANOTHERDOWNLOAD`): log "Expanding package ... with [0] RNG files", "Expand: Redownload is required". `windlp.state.xml`: `ExpansionRequired` 1, `ContainsExpressPackage` 1, `DownloadingHistoryCIX` 1. The native agent range-reads the `.psf` files over HTTP (`IsRangeRequestSupported` fails here with `0x80040154`, no callback factory, so ranges are off) |
| 10 | with the two `.psf` files (386,541,934 and 2,254,101,317 bytes, members of the two declared `.msu` files) also placed in the sandbox: `PostDownload`, `Install`, `Commit` all `0x00000000` |

It is INFERRED, not isolated, that the missing `.psf` files were what `0x8024200D` asked for: the two changes (wim/esd/SSU and the `.psf`
files) were not tried separately in the last step.

**Result of the working run (OBSERVED).** `client install --yes` (one step, 19 files re-hashed by the executor, three passes about
100 s each, then the stack): 1,053 s for the whole command, the stack step 13:23:00Z to 13:38:24Z (15.4 minutes). Phases `create_session`,
`generate_download_request`, `provision` (5 files taken out of the `.msu` files: wim 113,666,182, esd 114,384,136, SSU cabinet 20,623,941,
two `.psf`), `post_download`, `install` (out flag 1, no error info), `commit`; the stack's own log line "UpdateAgent.dll" loaded from the
extracted `DesktopDeployment.cab` directory (digest-verified, Authenticode-verified by the backend). Job `reboot_required`, oracles
`agree_pending`. Before the restart: `Package_for_RollupFix` 26100.9457.1.0 state 96 (`UpdateAgentLCU`), 8037 state 5,
`Package_for_ServicingStack_9441` 112 (`UpdateAgentLCU`; `wcp.dll` 10.0.26100.9441 in WinSxS), 8035 112, `RebootPending`,
`PackagesPending` and `pending.xml` present, `WindowsUpdate\Auto Update\RebootRequired` ABSENT (the `wusa` run of 18.2 had it set),
`servicing.diff` 132 package entries (the FoD and language packages move to `Install Pending` as with `wusa`), guest free space 27.1 GB
before the stack and 20.7 GB after. After one restart: at 48 s of uptime build 26200.9457, 9457 still 96, `PackagesPending` still
present (boot-time servicing running); a later read (uptime 20 s: the guest restarted once more by itself) 9457 112, 8037 80,
9441 112, 8035 112, no pending indicator; guest free space 21.9 GB (store 14.3 GB included). `client install` again: `no_action`,
plan outcome `nothing_to_do_installed`, 85 s.

**Comparison with section 18 (`wusa`, same update, same guest build).** Same final package states (9457 `Installed`, 8037
`Superseded`, 9441 present, 8035 `Installed`) and the same pre-reboot states; the same client id `UpdateAgentLCU`. Differences observed:
the `Auto Update\RebootRequired` value was not set; duration 15.4 minutes for the stack step against 11.7 to 14.7 minutes for `wusa`
(plus the hashing passes and extraction here); disk: 14.3 GB of declared content on the guest plus 2.6 GB of extracted `.psf`
data, against a 4.6 GB `.msu`. The native agent fetched about 455 MB by its own download list and range reads; this client fetches
everything the WSUS declares and the stack uses a subset (which of the other 12 declared files, such as the language, FoD and Edition
`.wim` files, the stack read was not recorded).

**Not run / not established.** The wrong-server-digest case (it needs an edit of the WSUS database, not authorized; a tampered store
file is repaired by the acquisition step, as in section 16). Timeout, `Cancel`, a failed stack install, uninstall of this update, the
`System32` stack for a monthly update (the delivered stack was used), reporting to the WSUS, a second Windows build, more than one
guest. The hotpatch helper inside the stack writes `HOTPATCHUTIL` text to the process's standard output, so the `--json` output of
`client install` is not pure JSON when the stack is loaded (the job record file is clean): fixed afterwards, section 20. The 14 GB acquisition and three
re-hash passes are slow on a laptop-class disk; no attempt was made to reduce them. The `.psf` extraction pulls 2.6 GB through the
WIM reader per run.

Lab state afterwards: the clone `osi-m2-1` stopped and its state deleted (`osi-gold` untouched), host scratch `/data/cache/osi-m2`
(scripts, `evidence/job-install-12.json`, `evidence/job-rerun-13.json`), target dir `/data/cache/rust/target-m2`.


## 20. Standard output of the update stack (OBSERVED 2026-10-06, clone `osi-j-1`)

Fixes the `--json` purity problem of section 19. The hotpatch helper inside the stack writes `HOTPATCHUTIL` text to the process's
standard output; `update_agent` mode now captures it (`install/stdout_guard.rs`, used by `servicing/update_agent.rs`).

**What the code does.** An RAII guard (`StdoutGuard`) redirects the process's standard output to a file in the step's log directory for
the duration of the session calls and restores it afterwards (the guard is dropped on every exit path, including an error and a panic
unwind; one guard at a time). On Windows both the C runtime descriptor 1 and the Win32 standard handle are redirected: the CRT
functions (`_dup`, `_dup2`, `_close`, `_open_osfhandle`, `_get_osfhandle`, `_flushall`) are resolved from `ucrtbase.dll`, the shared
UCRT the stack uses, NOT from the client's own CRT (the release build links the CRT statically, so its descriptor table is a different
one), and `SetStdHandle` points `STD_OUTPUT_HANDLE` at the capture file, so that `printf` and `WriteFile(GetStdHandle(..))` writers
and Rust's own stdout (which reads `GetStdHandle` on every write) all land in the file; restoring puts a duplicate of the original
descriptor back, flushes the stack's CRT buffers first, and resets the Win32 handle. On Linux the same guard is `dup`/`dup2` on
descriptor 1 (host tests: capture, restore, restore on a panic unwind, bounded tail; the test harness prints its own progress lines to
descriptor 1 meanwhile, so the tests assert `contains`). If the redirect cannot be set up the install continues and the job records a
`stack_stdout` phase with the reason.
Where the text goes: the whole text in `<jobs>/<job id>-servicing/ua-stack-stdout.txt` (listed in the step's `log_paths`), the last
8 KiB in the step's `os_installer.stack_stdout` and in `stdout_tail`, and a `stack_stdout` phase with the byte count. The redirect is
process-wide: nothing else may print to standard output while the stack runs (the client prints only after the step). A timeout does
not release the guard early: the client waits for the stack (section 21), so the guard covers the whole call.

**Guest run (OBSERVED, one guest, one run).** Clone `osi-j-1` of `osi-gold` (Windows 11 25H2, UBR 8037, `.NET` rollup 9321.3), new
`SusClientId`, WSUS group `osi-j` holding only the clone's record, update `88661612-7dd9-49d4-bb34-1e54802c99b9` (KB5126052) approved
for that group; `wsus.exe` (static CRT, `osinstaller-handler`, built from `f8d6e24` plus the guard) with `osinstaller_mode =
"update_agent"` and no `osinstaller_stack_dir`; the update declares no stack cabinet, so the `System32` stack was used (the job has no
`fetched_stack`; the loaded module list was not taken, as in section 17). `wsus.exe --json client install --update 88661612-... --yes` with
standard output redirected to a file: exit 0 after 148 s, status `reboot_required`, phases `create_session`,
`generate_download_request`, `post_download`, `install` (flag 1), `commit` all `0x00000000`. The standard output file (6,448 bytes)
parsed with `ConvertFrom-Json` as one document; the `HOTPATCHUTIL` lines (1,414 bytes, 16 lines, `GetSystemReadyForHotPatchStatus`,
`IsProcessElevated`, `CheckSystemCompatibilityForHotpatch` ...) are in `ua-stack-stdout.txt` and, as a JSON string, in `stack_stdout`
of the printed job. The first attempt of the session was refused by `PendingFileRenameOperations` (as in 18.12; a restart cleared it).
NOT observed: standard output attached to a console (the run used a redirect to a file), `client uninstall` (it uses the DISM
backends, which were not looked at for standard output), a timeout with the stack still writing, a monthly update, text the stack
writes in a wide-character mode, writes to standard error (the stderr file held only the client's own log lines; the stack's were not
looked for), which of the two mechanisms (descriptor or Win32 handle) the helper uses (both are redirected).


## 21. Failure, timeout and interruption paths of the `OSInstaller` modes (OBSERVED 2026-10-06, clones `osi-j-2` to `osi-j-10`)

Same lab as section 20 (real WSUS, group `osi-j` holding only the clone, `.NET` update KB5126052 approved for it, removed afterwards;
clones of `osi-gold`, Windows 11 25H2 UBR 8037, `.NET` rollup 9321.3; a template clone synchronized once, copies of it for each case so
that every case starts from the same state: content downloaded, no job, restart done). `wsus.exe` static CRT with `osinstaller-handler`.
Each case is one run unless said; "rerun" is the same `client install --yes` command later. Honest limits are listed per case.

**(a) A failing stack step, `update_agent` mode.** Two provocations, both ordinary operating-system conditions, not edits of the client.
1. `TrustedInstaller` start type `Disabled` (and stopped): NOT a stack failure. The executor's package listing before the step
   (`servicing_backend = "dism"`) failed (`dism /Get-Packages exited 0x00000057`) and the job was `refused` ("cannot list the installed
   packages"), the stack was never called. (OBSERVED; it shows the pre-gate, not a failing session phase.)
2. The `.NET` cabinet deleted from the job's SANDBOX (a hard link: the verified store file stayed) by a watcher script as soon as
   `ActionList.xml` appeared there. Result: phases `create_session` `0x00000000`, `generate_download_request` `0x80070002` and nothing
   after (no `post_download`, `install`, `commit`: one attempt, no retry loop); step `finished`, `exit_class` `failed`,
   `exit_code` -2147024894, refusal "GenerateDownloadRequest failed"; job `failed`, `servicing.oracles` `neither_installed`
   (evaluator not installed, package listing `absent`), expected identity `absent`; the stack's stdout text captured as in section 20
   and standard output still one JSON document; exit 2; `<jobs>/<id>-os` and `-servicing` kept as evidence.
   Rerun with the condition gone (the service start type back to `Manual`; the earlier refused job did not matter either): a new plan,
   `reboot_required`, all phases `0x00000000`, the same as a first run. NOT reached: a failure in the `install` or `commit` phase (the
   removal landed in `GenerateDownloadRequest`; a failure after `Install` was requested was not provoked in this mode), and the
   `unconfirmed` class for a failure (it appeared only for the timeout below).

**(a) A failing step, `dism` mode.** Insufficient disk during the add: a script waited for `dism.exe` to start (the free-space gate and
the hash passes had already passed) and then allocated a file leaving about 25 MB free on `C:` (41.7 GB free before). Result: job
`failed`, step `exit_code` 112 (`0x70`, `ERROR_DISK_FULL`), description "0x00000070: failure, code not in the known table" (the table
has no text for it), `oracles` `neither_installed`, no pending indicator, `pending_after` empty; the package was left with
`CurrentState` 32 (staged) and the stack did not clean it. Rerun after the file was deleted (the guest showed 38.8 GB free against 41.7
before): plan again (new facts hash, the state 32 did not block it), `/Add-Package` exit 3010, job `reboot_required`. NOT run: a
`dism` failure with another cause; `dism_api` backend failures.

**(b) The timeout, `update_agent` mode: a finding and a fix.** `--timeout-secs 20` against the real install (the stack call takes about 2 minutes).
BEFORE the fix the backend ran the session on a thread, and on the bound it returned `timed_out` and left the thread: the client
printed the job (`unconfirmed`, step `timed_out`, `install` phase "timed out; the stack was NOT stopped") and EXITED, which ends the
in-process stack. OBSERVED then: the client exited at 17:23:42; `CBS.log` ended 9 seconds later ("Restoring default priority");
`Package_for_DotNetRollup_481` 9347.1 stayed at `CurrentState` 64 (`InstallRequested`) with NO `RebootPending`, `PackagesPending` or
`pending.xml` (a finished install shows `RebootPending` and `PackagesPending` at 64 or 96); `TrustedInstaller` and `TiWorker` stayed alive
and idle (CPU time unchanged over 5 minutes); no client action followed. So the claim "the stack is not stopped on timeout" was
NOT true for this mode: it holds for the `dism` exe (below), not for the in-process stack. A later run (6 minutes after) planned
from fresh facts and installed: `reboot_required`, phases all `0x00000000`, the state 64 did not block the plan (the package
was then at 64 WITH `RebootPending`).
AFTER the fix (`servicing/update_agent.rs`): on the bound the client writes one line to standard error ("the update stack exceeded the 20 s
bound; it is running inside this process and is not stopped, waiting for it to return"), waits for the call to return, and records the
result with `timed_out` true and a `timeout` phase; the step verdict stays `unconfirmed`. OBSERVED (clone `osi-j-6`, same 20 s bound): command
123 s, standard output one JSON document, status `unconfirmed`, step `timed_out` true with the real stack result (all phases
`0x00000000`, install flag 1, "installed; ... treated as a reboot request"), `oracles` `neither_installed` and `packages`
`unavailable` (the listing after a timeout is skipped as designed), `RebootPending` and `PackagesPending` set when it ended.
Consequence, a DECISION: `--timeout-secs` no longer bounds the wall time of a `update_agent` step; it only marks the step
`timed_out` (judged by fresh state later). A hung stack keeps the command waiting until the operator kills it, which aborts it.
A helper process for the stack (which could outlive the command) was not built.
What a later run does: a run started 18 seconds before the first one finished (`osi-j-6`, and the same on `osi-j-9`) ended `refused`
with "a restart or servicing operation is already pending (CBS RebootPending)" after 40 to 45 s, with no message about the other run.
`jobs/install.lock` is taken with `try_lock` (job.rs); whether this second run reached it before the first one released it, or what the
message is when it does, was NOT observed. After the first run had finished a rerun was `refused` for the same indicator (the restart
case after a timeout was observed in the kill case below, not for the fixed timeout path).

**(b) The timeout, `dism` mode (`osi-j-10`, `--timeout-secs 20`).** The client returned with job `unconfirmed`, step `timed_out`
("DISM was left running, the install is judged by fresh state later"), `pending_after` `CBS RebootPending`, `oracles` `packages`
`unavailable`; the sampler (every 4 s) saw `Dism`, `DismHost`, `TiWorker`, `TrustedInstaller` keep running after `wsus.exe` had gone,
the package go 64 then 96 with `RebootPending`, `PackagesPending` and `pending.xml`, all without the client. A rerun at that point was
`refused` (pending indicators); after a restart (about 3 minutes later, 150 s of waiting) the package was 112 and the rerun was
`no_action`. This is the same as the earlier observation for the `Cbs` handler (wsus-install.md, ledger C46/C47), now for an `OSInstaller` step.

**(c) Interrupted job after a hard kill, `update_agent` mode.** `Stop-Process -Force` on `wsus.exe` (`TerminateProcess`, the Windows
analogue of SIGKILL: no handler, no cleanup), twice, on separate clones.
1. 2 seconds into the step (the step record `started` was written; the stack had not reached the install): the job record stayed
   `running`, step `started`, `install.lock` present but released (the OS lock went with the process); nothing was installed. The
   next run: `recovered_interrupted_jobs` listed the job id, the old record was rewritten `interrupted` with the note "marked
   interrupted by a later run; steps started but not finished: [0] (their effect is decided by re-evaluation)", a new job planned from
   fresh facts and ended `reboot_required` (all phases `0x00000000`).
2. 25 seconds after `ActionList.xml` appeared (by then `TrustedInstaller` had finished the install: package 64, `RebootPending` set
   14 s after the ActionList; the kill came after that): the job stayed `running`/`started`; the next run marked it `interrupted` and was
   itself `refused` by the pending gate (`CBS RebootPending`); after a restart (about 4 minutes until the package read 112, 9321.3 80) the
   next run was `no_action`, `recovered_interrupted_jobs` empty (already marked).
The servicing processes (`TiWorker`, `TrustedInstaller`) survived the kill in both cases. NOT observed: a kill during the `install` call
before `TrustedInstaller` finished (the timing used landed before or after it), in `dism` mode, a kill of a monthly update, a real
power loss.

Lab afterwards: the WSUS approval, the group `osi-j` and the two computer records the clones created removed (no other record or group
touched; the group `osi-rep` of another agent was already gone when the cleanup listed groups); clone states `osi-j-1` to `osi-j-10`
deleted, `osi-gold` untouched; scratch `/data/cache/osi-j` (scripts, `evidence/`), target dir `/data/cache/rust/target-j`.
