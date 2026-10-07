# wsus install: the installing client

Status: **one guest run, narrowly Observed** (2026-10-05, see "Guest run
results"); everything else is host-tested with fakes or type-checked by
cross-compilation only. The evaluator has its own narrow evidence (inventory
12.7 and 12.8). Ledger rows C37 to C42 in [wsus-validation.md](wsus-validation.md)
state exactly what moved.

Companion documents: [wsus-cli.md](wsus-cli.md) (command surface),
[wsus-protocol-inventory.md](wsus-protocol-inventory.md) section 12 (evaluator,
facts, differentials) and 12.10 (the observed `HandlerSpecificData` schema and
the decisions below), [scripts/wsus/README.md](../scripts/wsus/README.md) (the
reference fact collector).

## What it does

For one class of update, those installed by a **command-line handler** (the
Microsoft Defender security-intelligence bundle is the only one in the lab
catalog), the client does what a Windows Update Agent does for the cases the
evaluator was compared on:

1. decide applicability with the validated evaluator over live Windows facts
   (`WindowsFacts`) or a recorded snapshot (`--facts-file`);
2. build a deterministic **install plan** from the stored catalog;
3. download the payloads of the steps through the existing verified downloader;
4. gate every payload (path, digest, Authenticode signature, signer allowlist);
5. run the installers, with write-ahead evidence;
6. **re-evaluate** with fresh facts: success means the evaluator now says the
   executed updates are installed, not that the exit code was 0.

It sends **no reporting event by default**. With `[install] report_events = true` every install job that
ends `succeeded`, `reboot_required` or `failed` queues two events in the durable event queue (inventory 9.10): `181`
(installation started) and then `183` (success), `201` (restart required, `Win32HResult` `0x00240005`) or `182` (failure,
the code as an `HRESULT`), in the shapes a native agent was recorded sending. They are delivered by the next
`client sync`, `client report` or by the install command itself, best effort (a failed delivery leaves them queued and does
not change the install result). `[install] report_uninstall_events = true` does the same for `client uninstall` with
`226` and then `222`, `224` or `221`; those ids come from the real WSUS's event table and NO native agent was seen to send
one, so they are a decision, not an observation. Nothing is queued for refused, no-action, interrupted or unconfirmed jobs.
With `[install] report_inventory = true` (off by default) the client also queues the status event `156` after `client sync`
and after an install or uninstall job: its `U` and `V` lists are the updates the evaluator says are not installed and installed
(`client scan`'s `applicable` and `installed`; unknown, not applicable and superseded are left out), the lists the real WSUS
derives the update's Installed and NotInstalled state from (inventory 9.11). An install that needs a restart stays on `U` until
an evaluation after the restart says installed; `wsus client report --inventory` emits the event on demand.
A success marker in a report is still not install evidence: the real WSUS did not change the update's status for the
reboot-required events (it moved only on `182` and on the client's later `156` inventory lists, inventory 9.10).
`job::ReportHook` is the extension point; `reporting::install_events::InstallReporter` is the implementation.
`wsus client report --job JOBID` queues the events of a recorded job afterwards (the event ids are derived from the job, so
repeating it adds nothing).

## Commands

```text
wsus client facts-check --queries queries.json --expect facts.json [--facts-file F] [--max-details N]
wsus client scan    [--facts-file F] [--update UUID[@REV]]... [--all]
wsus client plan    --update UUID[@REV] [--facts-file F] [--allow-unknown] [--out plan.json]
wsus client install --update UUID[@REV] [--facts-file F] [--yes]
                    [--trust-signer NAME]... [--allow-unknown] [--allow-writable-store]
                    [--timeout-secs N]
```

Configuration (`[install]`, all optional):

```toml
[install]
trust_signers = ["Microsoft Corporation"]  # signer organisation allowlist
timeout_secs = 1800                         # one installer process
msi_handler_uris = []                       # only with the msi-handler feature
plan_prerequisites = false                  # schedule prerequisite updates (SSU) as earlier steps
delegate_cbs_installable = false            # CbsPackageInstallable decided by the servicing stack
servicing_backend = "dism"                  # cbs-handler feature: dism | wusa | dism_api
```

* `facts-check` runs the live Windows provider over a `queries.json` (the
  output of `scripts/wsus/applicability-queries.py`) and compares each answer
  with the snapshot `collect-facts.ps1` wrote on the same machine state. It
  reports per kind: `agree`, `disagree` (both definite and different),
  `ours_unavailable` (the Rust provider cannot answer what the collector did),
  `reference_unavailable`. Only `disagree` fails the command (exit status 2).
  `--facts-file` replaces the live provider with a snapshot (host self-test).
* `scan` prints a verdict per update: `applicable`, `installed`,
  `not_applicable` (also for superseded, with a detail) or `unknown` with the
  blockers. Default scope: the highest stored revision of every leaf Software
  update whose deployment action is `Install` or `PreDeploymentCheck` (the
  roots); `--all` takes every leaf Software revision; `--update` names them.
* `plan` prints (or writes with `--out`) the full plan: every decision, the
  steps, the blockers, the facts hash. Nothing is executed.
* `install` is a **dry run unless `--yes`**: it prints the plan summary and the
  exact command line of every step, and whether the payload is already in the
  verified store. It downloads nothing, changes nothing and writes no job
  record. With `--yes` it requires Windows, live facts (no `--facts-file`) and
  an elevated token (checked, then refused otherwise), downloads the payloads
  of the steps, gates, executes and re-checks.
* `--trust-signer NAME` (repeatable) **replaces** the allowlist for this run
  (default and config default: `Microsoft Corporation`). It is recorded in the
  job evidence.
* `--allow-unknown` and `--allow-writable-store`: see the risks below.

## The plan

`plan.rs` follows the leaf differential (inventory 12.8) and adds the install
side. Per node:

* an **installer** (an Extended fragment with `HandlerSpecificData`) is
  installed when `IsInstallable` is True (absent section counts as True),
  `IsInstalled` is False (absent section: Unknown) and every prerequisite
  clause is satisfied: a clause (an `AtLeastOne` or a bare identity) is
  satisfied when some alternative's latest revision evaluates `IsInstalled`
  True through its own rule; categories are not followed deeper;
* a **bundle** (no handler, `BundledUpdates`) is gated by its own sections and
  prerequisites when it has them, then every alternative of every clause is
  evaluated and every qualifying one is installed. The verdict of the children
  decides; no verdict is derived for the bundle itself (the derived one is
  Unknown for the Defender bundle, inventory 12.8). The result is `Install`
  when any step results, `AlreadyInstalled` when every clause has an installed
  alternative, `NotApplicable` otherwise;
* **supersedence** (Implementation decision, **Unverified**, it never fired in
  the differential): an installer is skipped when another stored update lists it
  in `SupersededUpdates` and that update evaluates installed. An Unknown
  superseder is recorded as a note and does not block;
* the meaning of `AtLeastOne` for the install side is **Unverified**. The
  native agent fetched one file per clause for the Defender bundle (inventory
  9.4); this planner installs every alternative that qualifies. If several
  qualify in one clause, all are planned, in metadata order.

### Unknown policy

Any Unknown on a decision path **refuses** the plan (`outcome: refused`, no
steps, the blockers grouped by text with the updates they affect). Blockers are
the evaluator's: an unsupported operator, an unavailable fact, an undecidable
comparison, a bundled revision missing from the catalog, an Extended fragment
that was never fetched, a handler that is not understood.

`--allow-unknown` skips the Unknown nodes instead and plans the rest. **Risk:**
an update that should have been installed is silently left out, or a
prerequisite that could not be evaluated is treated as not met or ignored; the
plan records it (`allow_unknown`, the decision notes) but nothing else warns.
Use it only to look at what the definite part of a plan would be.

### Determinism and the facts hash

The plan contains no timestamps: the same catalog, options and answers give the
same bytes. `facts.hash` is the SHA-256 over the sorted, case-folded
`query -> answer` lines the evaluation actually asked (a recording wrapper
around the provider), so it identifies the facts the decisions depended on.
`plan_sha256` is the hash of the compact plan JSON. The job record keeps both.

## The safety model

Gates, in the order a step meets them. A refusal at any gate before the first
process starts refuses the **whole run**; nothing is executed.

1. **Handler parsing.** `Program` must be a plain file name (no separators,
   reserved names, `..`) equal to the update's one declared payload file;
   `Arguments` are split on spaces into separate arguments, each limited to
   `[A-Za-z0-9/._=:-]`. Anything else makes the spec invalid. No shell is used
   and no command line is pasted together: `std::process::Command` gets the
   program and an argument vector.
2. **Path.** The payload must lie inside the verified store root (canonical
   comparison); no component below the root may be a symbolic link or reparse
   point; unless `--allow-writable-store`, neither the payload, nor its
   directory, nor the store root may be writable by everyone (Unix: `o+w`;
   Windows: the ACL grants Everyone, Authenticated Users or BUILTIN\Users
   write/replace/delete rights, see `windows_acl.rs`). The Windows ACL check is
   unvalidated and strict: a state directory under `C:\` usually inherits
   `Authenticated Users: Modify` and is refused; use `C:\ProgramData\wsus`, or
   pass `--allow-writable-store` on a disposable guest. Nothing is copied
   outside the store; the working directory of an installer is its payload's
   directory.
3. **Digest.** The payload is opened (Windows: share mode read only, which
   denies writers and deleters for as long as the handle lives), its size is
   compared with the plan and **every digest recorded in the plan** (SHA-1 and
   SHA-256 when declared) is recomputed over that handle. This happens in the
   preflight and again immediately before each execution, with the handle kept
   open until the process has started.
4. **Signature.** `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI,
   revocation checks off and cache-only URL retrieval, embedded signatures
   only) runs on that same handle. The signer's certificate organisation (`O`,
   else `CN`) must equal an allowlist entry (exact, ASCII case-insensitive).
   Default `Microsoft Corporation`. The crate `wintrust` of this workspace is
   not used: it verifies catalog members under a portable policy and has no
   PE/MSI Authenticode path. Off Windows the verifier refuses everything.
5. **Execution.** Elevation is checked before anything is downloaded. The
   process runs with stdin closed, a timeout (kill on expiry; the process tree
   is not killed), and at most 64 KiB captured per stream. The environment is
   inherited (an elevated shell's environment is not a SYSTEM service's).
6. **Exit codes.** Mapped by the handler's own `ReturnCode` list; an unlisted
   code is `Failed` (fail closed). A failed or timed-out step stops the run.
7. **Post-state, with waiting.** Exit codes cannot prove success (see below).
   After the last step, fresh facts are taken and each executed update is
   evaluated again, every 2 s, until all are `installed` or
   `post_check_wait_secs` (config `[install]`, `--post-check-wait-secs`, default
   180, 0 disables waiting) has passed; no waiting after a failed or
   reboot-class step. The job record keeps `polls`, `waited_secs`,
   `wait_bound_secs` and `converged`. `succeeded` needs convergence within the
   bound; otherwise `unconfirmed` (`failed` if an exit code said failed). The
   sleeper is injected, so host tests do not sleep. `succeeded` needs all of them `installed`. An exit that means success with
   nothing changed is `unconfirmed`; a reboot-required exit is
   `reboot_required` (the evaluator may not say installed before the reboot).

What this does not protect against: a compromised signer on the allowlist; a
malicious but correctly signed, correctly hashed payload (the digests come from
the same metadata that selected the update; Microsoft's signature on the file is
the independent check); revocation (not checked); an administrator who edits the
job directory or the allowlist; side effects of the installer itself.

### Defender packages exit 0 before the update is applied (Observed 2026-10-05)

Observed on the guest: `AM_Engine.exe` exits 0 after about 1 s and leaves a
detached `MpSigStub.exe /stub <ver> /payload <ver> /MpWUStub /program <AM_Engine.exe>`
running. That stub waits in AccumulatePackages for the sibling packages
(`AM_Base.exe`, `AM_Delta.exe`; default `ConnectTimeoutMS` 120000). In a normal
run (Engine, Base, Delta in order) it applies the update within seconds and
writes `%SystemRoot%\Temp\MpSigStub.log` (UTF-16LE: `Signatures updated from
...`, `MpSigStub successfully updated ...`, `DeltaUpdateFailure set to 0`). A
lone `AM_Engine.exe` leaves the stub waiting about 120 s, then it logs `ERROR
0x800705b4 : AccumulatePackages` and updates nothing, while every package still
exits 0. Hence the waiting post-check above. Evidence hooks (never used to
decide success, never fail the install): the new tail of that log, at most 64 KiB
decoded from UTF-16LE, goes to the job record as `handler_log_excerpt` when a
step's payload is a Defender package (`AM_*.exe`, `MpSigStub.exe`; generic
`HandlerLog` hook); and on Windows, `MpSigStub.exe` processes started after the
first step and still running while waiting are listed under
`post_check.detached_processes` (name, pid, start time; never killed). The wait,
the log excerpt and the process listing are **new and not yet run on a guest**.

### Office updates use `NoOp.exe`

3794 of the 3836 handler specs in the larger stored catalog (client-run6) are
`NoOp.exe` (13,160 bytes) with `RebootByDefault="false"`. Planning such an
update would run `NoOp.exe`, which installs nothing; the post-check will then say
`unconfirmed`. Click-to-Run Office updates are not installed by this client. They
are not a target of this work.

## Facts: `WindowsFacts`

`install/facts_windows.rs` mirrors `scripts/wsus/collect-facts.ps1` query by
query (read the module header for the exact rules: registry views and value
types, the `PrependRegSz` join, `VS_FIXEDFILEINFO` versions, OS identity through
`RtlGetVersion`, MSI through `msi.dll`, CBS state from the registry, licensing
through `slc.dll`). Differences from the collector, by design:

* `wmi_query` is **Unavailable** (no WMI client; the collector answers it with
  `Get-CimInstance`). The Defender bundle's decision path asks no WMI query (29
  to 32 distinct facts: registry values and keys, a few files, one license
  value, the OS and the architecture), but other updates' rules do;
* `msi_patch` is Unavailable (the collector does not collect it either);
* a file that exists but cannot be inspected for lack of permission is
  Unavailable here; the collector's `[IO.File]::Exists` says false (Absent).

Run it as the same account as the collector (the collector's header recommends
SYSTEM; per-user MSI products and profile folders differ otherwise) and as a
native 64-bit process (file system redirection otherwise changes `System32`
answers; the shipped `wsus.exe` is x86-64).

## Job record and recovery

`<state_dir>/jobs/<job-id>.json`, replaced atomically on every transition and
written **before** the step starts (`started`) and after it finishes. It holds
the plan, the facts hash and source, the trusted signers and flags, per step
the redacted command (program relative to the store, arguments with paths
outside the store replaced), digest and signature results (signer subject,
issuer, thumbprint), exit code and class, timestamps, a bounded output tail,
the post-check, and `reporting_sent: false` (the field stays false: the install path sends nothing itself; the optional hook only queues events, see the top).

A run holds `jobs/install.lock` (an OS file lock, released when the process
dies). The next run marks every record still `planned` or `running` as
`interrupted` (listing the steps started but not finished) and plans again from
the machine's facts. An installer that did complete evaluates installed and
drops out of the new plan, so **re-running is idempotent**; one that did not is
planned again. The outcome of the step that was in flight is decided only by
that re-evaluation.

## Windows Installer handler (feature `msi-handler`, off by default)

Observed 2026-10-05 against a real WSUS (Windows Server 2025, 10.0.26100.32230) that published `.msi` files through its
administration API (inventory 12.16). The update's Extended fragment declares the handler
`http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsInstaller` with
`HandlerSpecificData type="msp:WindowsInstallerApp"` holding `<MsiData ProductCode MsiFile [CommandLine]>`; the payload is
a **CAB** that contains `MsiFile`. The handler routes on that URI (or on a URI listed in `install.msi_handler_uris`, which
falls back to the payload extension), verifies the CAB like any payload (digest, Authenticode signer allowlist), extracts
the named member into a fresh `<cab>.extracted` directory next to it and runs `msiexec /i <msi> [PROP=value ...] /qn
/norestart`; an `.msp` runs `msiexec /update <msp> ...` (its real shape: `MspData FullFilePatchCode`, a cabinet with the single
`.msp`, rules `MsiPatchInstalled`/`Installable`, observed with a WiX-built patch). `msiexec` parses its own command line:
properties with spaces must read `NAME="a b"`, which the runner builds for `msiexec.exe` (as `"NAME=a b"` it hangs).
Exit 0 is success, 3010 and 1641 success with reboot, anything else failure (1620, 1603, 1604 included). The applicability
rules of these updates use `MsiApplicationInstalled` / `Superseded` / `Installable` with the product code in
`Metadata/MsiApplicationMetadata/ProductCode`; the evaluator resolves them to `MsiProductInstalled(ProductCode)` and its
negation (Installable) and leaves `Superseded` to the relationships; the patch rules resolve to "applied to a target
product" (Installed) and "target product installed within its `TargetVersion` and not patched" (Installable), using
`MsiEnumPatchesEx` on Windows. The signature gate needs the publisher certificate
trusted on the guest and its name in `install.trust_signers` (the WSUS signing certificate signs the CAB). Build the
Windows binary with `task build:windows:wsus:msi` (`dist/wsus-msi.exe`).

Validated on a guest (Windows 11 25H2, SYSTEM): real-WSUS install, upgrade, failure and reboot results are in the ledger
row C41 and inventory 12.16 and its addendum (MSP install, 1620, 1604, `CommandLine` properties, our own server).
Not validated: 1641 through the handler (`/norestart` makes it unreachable; seen with a direct `/forcerestart`), reboot
completion of a suspended (1604) install, uninstall (no client action), MSP supersedence, other architectures.

## How to run it on a guest (lead's procedure)

Preconditions: a disposable Windows guest (the lab image of inventory 9.4: DoSvc
enabled, Defender enabled and, for a Defender test, definitions removed or old),
Administrator or SYSTEM. Build and copy:

```sh
task build:windows:wsus                 # dist/wsus.exe, static CRT, x86-64
# copy dist/wsus.exe, queries.json, facts.json (from collect-facts.ps1 on the
# SAME state), wsus.toml and the client state directory (meta\revisions) to C:\work
```

`wsus.toml` (state under ProgramData avoids the ACL refusal):

```toml
[client]
origin = "http://<lab server>:8530"
state_dir = "C:\\ProgramData\\wsus"
```

1. Validate the Rust fact provider against the PowerShell collector (run both
   as SYSTEM, one after the other, no changes in between):

   ```text
   psexec -s powershell -ExecutionPolicy Bypass -File collect-facts.ps1 -Queries C:\work\queries.json -Out C:\work\facts.json
   psexec -s C:\work\wsus.exe client facts-check --queries C:\work\queries.json --expect C:\work\facts.json --json > C:\work\facts-check.json
   ```

   Expected: `disagree: 0`. `ours_unavailable` is expected for `wmi_query`
   (59 in the lab snapshot) and `msi_patch`; anything else is a gap to read.
2. `wsus.exe --config wsus.toml client scan` (live facts), then
   `client plan --update a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe --out C:\work\plan.json`.
3. Dry run: `client install --update a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe`.
   Read the steps and the commands.
4. Real run, elevated: `client install --update a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe --yes`
   (add `--allow-writable-store` if the state directory is not private). The
   payloads must be obtainable: either `client sync` against a server that has
   them (the C31 setup) has been run, or the verified objects were produced
   elsewhere with `client download --update ...` and the `content\complete`
   directory was copied into the state directory (a verified object needs no
   network access).
5. Check: `Get-MpComputerStatus | select AntivirusSignatureVersion`, the job
   record under `C:\ProgramData\wsus\jobs\`, then run step 4 again: the plan must
   be `nothing_to_do_installed` and the job `no_action`.
6. Windows-only tests: `cargo test -p wsus-client --test install_windows -- --ignored --nocapture`
   (needs a toolchain on the guest; the registry, file, runner and signature
   cases listed in the file header).

### Defender launcher packages: parent process, terminal package, stub preconditions

`install/defender.rs` holds what the plan and the executor know about the family
(`AM_Engine`, `AM_Base`, `AM_Delta`, their `*_Patch_*` variants, `AM_Slim_*`,
`AS_*`). Evidence labels: READ = decompiled (inventory 12.13), OBSERVED = guest
(this document, inventory 12.12 to 12.14).

* **One launcher program.** The packages share one launcher; it runs
  `System32\MpSigStub.exe` and passes the package to it through a named pipe whose
  name is derived from the launcher's PARENT process (parent PID and creation
  time) (READ). All steps of a run must therefore come from the same parent. The
  executor starts every step itself, so it is the common parent; the job record
  keeps its pid (`defender.parent_pid`).
* **Terminal package.** The stub accumulates packages until one carrying the
  `BINARY/MPSIGSTUB` marker resource arrives. OBSERVED on the launcher packages
  downloaded from the CDN (711 packages, all architectures): the marker is present on every
  `AM_Delta`, `AM_Delta_Patch_*`, `AM_Slim_Delta*` and `AS_Delta*` package and absent
  from every `*_Engine`, `*_Engine_Patch_*`, `*_Base` and `*_Base_Patch*` package.
  The terminal package's exit code is the stub's final HRESULT; the other packages
  exit 0 after about a second whatever happens later (OBSERVED, 12.12/12.14).
* **The plan** (`defender::arrange`): non-launcher steps (for example the
  `MpSigStub.exe /Store` step) first, then the non-terminal launcher packages, the
  single terminal package last. A selection without a terminal package (an engine
  patch alone, Engine or Base alone) is **refused** with the reason (the stub would
  time out with `0x800705b4` and update nothing while every package exits 0,
  OBSERVED); two terminal packages are refused. Plan steps carry `launcher`
  (`role`, `flavor`, `from_version`).
* **The executor** refuses the whole run before anything starts if the last
  launcher step is not the single terminal package, and (when the CLI supplies the
  probed environment, Windows only) if `System32\MpSigStub.exe` is not exactly
  `1.1.24010.2001` and the plan does not install it (`0x80070650`), or if a
  payload's machine differs from the host (an x86 package on an x64 host needs
  `SysWOW64\MpSigStub.exe`, else the launcher exits `0x80070002`, OBSERVED;
  arm64 on x64 is never runnable). After the terminal step it records
  `stub_result` (the exit code as the stub's HRESULT with a name and reason:
  `0x80070670` no patch for the installed version, `0x8499xxxx` MPSP patch decoder
  errors (1026 size/CRC, 1017 codec), `0x8007000D`, `0x800705b4`, `0x80070650`,
  `0x80070002`, `0x8000000A`, ...). A non-zero terminal code is a failed run (not in
  the metadata `ReturnCode` list, so fail closed); success still needs the
  post-check to converge. If the stub's new log text says `No products found to
  update` (exit 0, nothing applied: OBSERVED when the installed version equals the
  patch target) the post-check does not wait and the run is `unconfirmed`
  (`defender.nothing_applied`). `converged` is no longer true when no step
  executed successfully (the first failed-patch guest run showed the vacuous
  `converged: true` with empty lists).
* **Not covered by the plan, only by the executor and the stub:** which package
  variant fits the machine is decided by the evaluator over the catalog rules (see
  the round 2 results: the plan chose the native-architecture package every time).

## Windows servicing handlers (`Cbs`, `OSInstaller`) and the `cbs-handler` feature

A real Windows 11 catalog (inventory 12.17) declares two servicing handlers:
`.../2002/12/UpdateHandlers/Cbs` (`cbs:Cbs`, one `.cab`, empty `PackageIdentity`) and
`.../2016/01/UpdateHandlers/OSInstaller` (`OSInstallerMetadata`, several `.cab`/`.psf`/`.wim`/`.msu` files).
`install/handlers/cbs.rs` parses both (`HandlerInfo::servicing`) into a `ServicingSpec`.

**Default build (and any build without a configured backend):** both are read and planned with their payload, and the
executor refuses the whole run before it runs or modifies anything (`planned handler cbs, not executable by this
client: ...`). `OSInstaller` is refused in every build (owner decision Q-J: `Cbs` first; the OS installer needs
`UpdateAgent.dll` and tens of GB and has not been studied).

**`cbs-handler` feature (off by default; design: `docs/wsus-cbs-integration.md`):** a `Cbs` step runs through a
`ServicingBackend` (`install/servicing/`). The trait, the pending-indicator probe and the scripted `FakeBackend` are
always compiled (so the executor logic is host-testable); the Windows backends are behind the feature because they use the
servicing crates' text parsers (`windows-dism`, an optional dependency):

* `DismBackend`: `dism.exe /English /Online /Get-Packages /Format:List`, `/Get-PackageInfo /PackagePath:<cab>` and
  `/Add-Package /PackagePath:<cab> /NoRestart /LogPath:<job dir>`; the process is never killed on timeout
  (`RunRequest::kill_on_timeout = false`).
* `WusaBackend`: `wusa.exe <msu> /quiet /norestart` for `.msu` payloads, observation delegated to DISM. Run once through the
  executor on a real `.msu` (monthly cumulative update, exit 3010, restart, evaluator; see "Guest run, wusa backend"); the
  not-applicable and already-installed codes were not produced through it.
* `DismApiBackend` (`servicing/dism_api.rs`): `DismApi.dll` loaded dynamically from the system directory (selecting the
  backend where the DLL is absent is an error, nothing else is affected) and called in process: `DismInitialize`,
  `DismOpenSession(DISM_ONLINE_IMAGE)`, `DismGetPackages`, `DismGetPackageInfo` (by path, `Applicable`), `DismAddPackage`
  with a progress callback and no cancel event, `DismCloseSession`, `DismShutdown`; each operation opens and closes its own
  session. The add runs on a worker thread and a timeout leaves it running (never cancelled). HRESULTs are classified by
  the same table as the exe backend. Host tests use a mock function table; the guest run is below.

Selection: `[install] servicing_backend = "dism" | "wusa" | "dism_api"` (default `dism`); build with
`task build:windows:wsus:cbs` (`dist/wsus-cbs.exe`). Other keys: `plan_prerequisites` (and `--plan-prerequisites` on
`plan`/`install`): an installable prerequisite update, for example a servicing stack update, becomes an earlier step
(plan schema `wsus-install-plan/2`; plans without the option are still `/1`, byte for byte);
`delegate_cbs_installable`: `CbsPackageInstallable`, which needs the component store and so cannot be evaluated from
facts (it is the `IsInstallable` of ALL 180 real `Cbs` updates), is treated as True when planning and the servicing
stack's own verdict (`/Get-PackageInfo`, `Applicable : Yes|No`) is asked just before each install; a package it says is
not applicable is refused (the plan says so in a note).

Gates and behavior of a `Cbs` step (owner decisions, `docs/wsus-cbs-integration.md` 8.3a):

* trust is delegated to DISM/CBS: the metadata SHA-1/SHA-256 are verified (twice, as for every payload) but the
  Authenticode gate is NOT applied and no signer allowlist is consulted; the job records `trust: servicing_stack`;
* refused before anything runs: no backend, `OSInstaller`, `--allow-unknown`, a payload extension the backend cannot add,
  no derivable package identity (the manifest's `assemblyIdentity`, the second oracle needs it), a pending restart or
  servicing operation (`CBS RebootPending`, `RebootInProgress`, `PackagesPending`, `WindowsUpdate RebootRequired`,
  `WinSxS\pending.xml`, `PendingFileRenameOperations`, setup flags), less free system-volume space than
  `max(2 GiB, 3 x payload sizes)`, or a package listing that cannot be read;
* just before each add: the stack's applicability verdict; `Applicable : No` or an unreadable verdict stops the run
  (the oracles conflict, nothing installed);
* a reboot-class result (3010, or a package listed `Install Pending` after a zero exit) stops the run after that step
  with `reboot_required` and `remaining_steps`; the operator reruns after the reboot, the plan is made again from fresh
  facts and continues (no automatic resume);
* a call that hits the timeout is NOT killed: the step stays `timed_out`, the job is `unconfirmed`, and the next run
  judges by fresh state;
* success needs BOTH oracles after the run: the evaluator over fresh facts says installed AND the package listing shows
  the expected identity `Installed`; any disagreement is `unconfirmed` (job `servicing.oracles.combined`);
* the job record is schema `wsus-install-job/2` (`/1` records stay readable) with `servicing`: backend, trust, package
  listing counts and SHA-256 before and after, the diff, pending indicators before and after, free disk, the byte range
  `CBS.log` grew, remaining steps, the oracle verdict; per step the native code, class, description and the stack's
  applicability verdict; no reporting event is sent unless `report_uninstall_events` is on (`reporting_sent: false` either way).

Evidence: host tests (`tests/install_servicing.rs`, 17 tests with a fake backend and a synthetic catalog in the real
handler shape; the DISM parsers over real online output) and one Windows guest (see "Guest run results, round 3"
below). No real servicing stack update or cumulative update was installed.

## Uninstall (`client uninstall`, design: docs/wsus-osinstaller-spike.md 18.9)

Implemented 2026-10-06 for servicing updates (`Cbs` and `OSInstaller`), starting with the `.NET` rollup (KB5126052).
Nothing is downloaded and no payload is executed: the step asks the servicing backend to remove one CBS package.

**Plan.** `build_uninstall_plan` (`wsus-install-plan/3`, outcome `uninstall`, `nothing_to_do_not_installed` or `refused`;
the outcome value is new so an older reader fails to parse a plan it would run as an install). Install plans and job
records are unchanged byte for byte (`/1`, `/2`). The update must be a servicing installer (no bundle, no command line or
MSI handler), must evaluate installed (`IsInstalled` of exactly that revision; Unknown refuses, `--allow-unknown` has no
effect), and its package must be nameable. The choices where the design left one, all conservative:

* **`UninstallationBehavior`.** The design's trigger was an update that declares it. The real `.NET` rollup leaf
  (`OSInstaller`, KB5126052) declares none (OBSERVED in the lab catalog: only `InstallationBehavior`), so by the design's
  own rule the very update it targets would be refused. Default: refuse. `--allow-undeclared` (plan option and executor
  option, both required, so a plan file alone cannot enable it) accepts it and records in the plan that the removal is the
  operator's request, not something the metadata offers.
* **Package identity.** Operator (`--package`, validated as `name~token~arch~language~version`, characters
  `[A-Za-z0-9_.-~]`), else the update's manifest (`Cbs` updates), else, for an `OSInstaller` update (its core fragment
  carries no manifest, OBSERVED), the package its CompDB cabinet names, read by the executor from the digest-verified
  cabinet in the content store (exactly one package, else refused as ambiguous; a missing cabinet refuses the step).
  No name-based guess at what is permanent: only the stack's answer is believed.
* **Pending-install rollback (spike 18.3) is not offered.** The existing gate refuses a run while a restart or servicing
  operation is pending, and the target must be listed `Installed`; restart first, then uninstall.

**Execution.** `ServicingBackend::remove_package` (additive trait method with a default that returns `Unsupported`, and
`supports_remove_package`, default false; the `wusa` backend is unchanged and is refused for uninstall steps):
`dism.exe /English /Online /Remove-Package /PackageName:<identity> /NoRestart /LogPath:<file>`, or `DismRemovePackage`
(`DismPackageName`, no cancel event, progress callback, same worker and timeout handling as `DismAddPackage`). Neither is
ever killed on timeout (job `unconfirmed`, the next run judges by fresh state). The write-ahead record, the pending gate,
the disk gate and the package listing diff are the install path's. Classes: `0` success, `3010` and `0x80070BC2`
reboot (job `reboot_required`; the remaining steps are recorded), `0x800f0825` the new class `permanent` (job `failed`,
step refusal `permanent package: ...`, `servicing.refusal_class = permanent_package`; a later run for the same identity is
refused from the job store without asking the stack), anything else `failed`.

**Post-check.** The same two oracles, inverted: the evaluator over fresh live facts must say the update is NOT installed
(polled up to `post_check_wait_secs` after a success without restart; not waited after a restart request), and the package
listing must no longer have the identity (`absent`; `pending` for `Uninstall Pending`; `installed` if still there).
`servicing.oracles.combined`: `agree_removed`, `agree_pending`, `disagree_evaluator_removed`, `disagree_packages_absent`,
`neither_removed`; `evaluator_installed` holds the evaluator's "removed" verdict for an uninstall job. Succeeded only on
`agree_removed` with no restart requested. The listing diff records the predecessor's change (evidence, not an assumption
that it returns to `Installed`: that is only known after the restart).

Job record: schema `wsus-install-job/3`; `steps[].servicing.operation = "uninstall"` (absent for installs).

### Guest results (2026-10-06, Observed, clones of the lab guest, no WSUS contact)

Guests: clones of the settled lab guest (Windows 11 25H2 10.0.26200.8037, `Package_for_DotNetRollup_481` 9321.3,
`Package_for_RollupFix` 26100.8037.1.19), SYSTEM, `wsus.exe` built with `cbs-handler`, a state directory holding two REAL
catalog revisions copied from the lab catalog (the `.NET` rollup leaf for 26200 amd64, `b5f388e1-...@100`, and the 8037
monthly update `db6bc359-...@100`) and the REAL CompDB cabinet at its content path; origin `http://127.0.0.1:9`, the
clones' `SusClientId` removed, so no server was contacted. The rollup was first installed with `dism /Add-Package` (3010),
rebooted, and settled (9347.1 112, 9321.3 80 `Superseded`, `clr.dll` 4.8.9345.0).

| Case | Observed |
| --- | --- |
| Dry run with live facts | outcome `uninstall`, the real evaluator said installed, notes record the missing `UninstallationBehavior` and the CompDB identity source |
| `--yes`, `dism` backend | the identity was read from the CompDB; DISM exit 3010; job `reboot_required`; diff 9321.3 `Superseded` to `Install Pending`, 9347.1 `Installed` to absent; registry 9347.1 `CurrentState` 5, 9321.3 96; `CBS RebootPending`, `PackagesPending`, `pending.xml`; oracles `agree_removed` (evaluator removed, listing absent) with status `reboot_required`; `CBS.log` growth recorded |
| Re-run before the restart | `no_action` (the evaluator reads state 5 as not installed) |
| After the restart | 9321.3 `CurrentState` 112 `Installed`, 9347.1 gone, `clr.dll` 4.8.9221.0, no pending indicator: the same end state as the native `dism /Remove-Package` of spike 18.4. Re-run: `nothing_to_do_not_installed` |
| `--yes`, `dism_api` backend (second clone) | `DismRemovePackage` returned 3010 (plain, class `reboot`), the same diff, oracles, indicators and the same end state after the restart |
| Permanent package (first clone, after the above) | the baseline cumulative update `Package_for_RollupFix` 26100.8037.1.19 (named with `--package` on the 8037 monthly update's record): `0x800f0825`, job `failed` (CLI exit status 2), step refusal `permanent package ...`, `refusal_class permanent_package`, diff empty, oracles `neither_removed`, nothing changed; the second run was `refused` ("already refused ... not asked again") without a DISM call |

Not observed on a guest: the timeout path (host-tested only), a removal without a restart (`agree_removed` with status
`succeeded`; host-tested only), `ERROR_SUCCESS_REBOOT_REQUIRED` as `0x80070BC2` (mapped), the refusal of a pending run
through the CLI (host-tested), rollback of a pending install, an update installed by `update_agent` mode, a `Cbs`-handler
update (its manifest path is host-tested), the monthly cumulative update of spike 18.2 (the 8037 baseline was used), a
WSUS-driven removal (the WSUS side and the reporting of an uninstall are open), more than one guest image.

## Limits

Defender definition bundles on one lab image are the only target. Specifically
not done: HTTPS content, hash of `AM_Base.exe` beyond what the downloader
verifies, uninstall (except of servicing updates, above), drivers, cumulative updates, per-user installs, revocation
checking, process-tree termination on timeout, WMI facts, reporting, running as
a service, concurrent runs (a second run is refused by the lock), a scheduler,
and any update whose handler is not command line (except the unverified MSI
handler). A reboot is never performed.

## Guest run results (2026-10-05, Observed, one guest)

Guest: Windows 11 Pro 25H2 10.0.26200 UBR 8037, disposable, lab-modified image,
SYSTEM/elevated, Defender definitions removed (`AntivirusSignatureVersion`
0.0.0.0), `dist/wsus.exe` from `task build:windows:wsus`, server: this project's
`wsus-server` (staged mode).

1. `facts-check` right after the collector on the same state: 20461 queries,
   disagree 0, `ours_unavailable` 59 (all `wmi_query`, by design),
   `reference_unavailable` 0. Agreed per kind: msi_product 18720, reg_value 927,
   reg_key 500, file 132, cbs_package 59, license_dword 27, msi_feature 13,
   msi_component 10, msi_patch 3, reg_subkeys 3, system_metric 2, wmi_query 2
   (plus the 59 unavailable), os, architecture, language, mui 1 each.
2. **Finding and hazard: the application manifest.** The first run had 11 file
   disagreements of 132: file versions of OS files (`ntoskrnl.exe`, `kernel32.dll`,
   `lsass.exe`, `afd.sys`, `d3d11.dll`, ...) came back as 6.2.26100.x instead of
   10.0.26100.x, because `wsus.exe` carried no manifest declaring Windows 10/11
   support and Windows applied version compatibility behaviour. Fixed with
   `crates/wsus-cli/build.rs` and `wsus.exe.manifest` (supportedOS
   `{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}`, `asInvoker`), embedded through
   `/MANIFEST:EMBED /MANIFESTINPUT` on the MSVC target; afterwards 0
   disagreements. **Any Windows binary that reads versions must carry the
   manifest.** `tests/windows_manifest.rs` checks on the host that the manifest
   lists the GUID and that `build.rs` embeds it; that the exe really contains it
   can only be verified on the Windows build.
3. `client sync` against this project's server: 19 pages, 444 new revisions, 433
   extended fragments, 5.0 s.
4. `client scan`: one update applicable, `a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe@200`
   (facts source windows, 29 queries), agreeing with the native agent on the same
   guest state (it found and installed that update).
5. `client plan` and dry-run `install`: outcome `install`, 3 steps identical to
   the host dry run (`AM_Engine.exe`, `AM_Base.exe`, `AM_Delta.exe WD /q`),
   433 decisions, no blockers; the guest `plan_sha256` is 91b581ab0fb7... and
   `facts_hash` 9af7e061... (same plan content as the host plan from the
   removed-definitions snapshot).
6. `install --yes` (state directory locked with `icacls /inheritance:r`, SYSTEM
   and Administrators full control, so `--allow-writable-store` was not needed):
   status `succeeded`, 10.9 s including the download of about 223 MB; per step
   digest verified, signer `Microsoft Corporation`, exit code 0, class success;
   post-check performed, all three updates evaluate installed, none unknown; job
   record written. Independent confirmation: `Get-MpComputerStatus`
   `AntivirusSignatureVersion` 0.0.0.0 -> 1.459.547.0.
7. Idempotence: running it again gave `no_action`, signature unchanged.
8. Wrong allowlist (definitions reset first): `--trust-signer "Contoso Ltd"` gave
   `refused`, exit 2, `signer Microsoft Corporation is not in the allowlist
   (Contoso Ltd)`, nothing executed, signature stayed 0.0.0.0.
9. Tamper test: one byte of the stored `AM_Engine.exe` (offset 1000000) flipped,
   then `install --yes`: it succeeded and the stored file's SHA-256 afterwards
   equals the plan digest and its mtime changed, i.e. the download/store
   verification detected the corruption and re-downloaded BEFORE execution. This
   exercised the download path, **not** the immediate pre-execution digest gate.
10. The `MpSigStub.exe` difference is explained by guest state (2026-10-05, Observed). The 28
    `MpSigStub` children are installed when `System32\MpSigStub.exe` has file version exactly
    `1.1.24010.2001` (`FileVersion Path="MpSigStub.exe" Csidl=37 Comparison=EqualTo`). On both guests
    that file was already present at that version, written at the moment the native agent installed
    the Defender update (modification times 15:55 and 17:54 on 2026-10-04), so later plans correctly
    treated the stub as installed. With the stub moved away from System32 and the definitions removed,
    the plan on the guest had **four** steps, `MpSigStub.exe /Store` (child
    `0daf8592-9e3f-4a8a-9141-d83fafebd09f@200`) then `AM_Engine.exe`, `AM_Base.exe` and
    `AM_Delta.exe WD /q`: the same four files the native agent fetched. `install --yes` ran all four
    (exit 0, signer `Microsoft Corporation`), `System32\MpSigStub.exe` was restored with the same
    SHA-256 as the moved copy (`071b0d3a08503a8b...`, also the hash of the binary analysed in
    inventory 12.11), the post-check said all four updates installed, and `AntivirusSignatureVersion`
    was 1.459.547.0. So `/Store` places the stub in System32 (Observed), and the evaluator's `EqualTo`
    file-version rule was exercised on its not-installed and installed sides on a real machine.
11. No reporting event was sent.

Still Unverified: reboot-class handling, timeouts, token and working-directory
edge cases, the MSI handler, refusal of an unsigned or invalid-signature payload,
the pre-execution digest refusal, Office/`NoOp.exe` updates, the ACL check's
refusal case, other guests and states. Observed only for the Defender packages
on this one guest: signer `Microsoft Corporation` (O).

## Guest run results, round 2 (2026-10-05, Observed, one guest, Defender family)

Same guest (`w11-ours`, Windows 11 25H2, stub 1.1.24010.2001), `wsus.exe` built
from this tree (before the final converged and reason-text edits, which are
host-tested), this project's server on the host as the origin of the client, the
real lab WSUS (Server 2025) as the native agent's server. Definition states were
set with the real full packages (`AM_Engine` 1.1.26080.3, `AM_Base` 1.459.0.0,
then `AM_Delta` 537, 543 or 546) after `MpCmdRun -RemoveDefinitions -All`.

12. **Plan against the native Windows Update Agent, same state (Observed).** The
    native agent (`Microsoft.Update.Session` search of the managed server, then
    `IUpdateDownloader.Download`, `SoftwareDistribution\Download` emptied before)
    offered the bundle `a2fef9b0@200` (KB2267602 1.459.547.0, Broad) in states 537,
    543 and 546 and fetched exactly one file each time; the plan (`client plan`
    over the guest's live facts, 433 decisions) had exactly one step each time and
    the same file:

    | Installed deltas | Native agent fetched | Plan step |
    |---|---|---|
    | 1.459.537.0 | 407,968 B, SHA-1 `9f006b69...` (child `f979ffd1...`, "Full Deltas 1.459.547.0 (patch from 1.459.537.0) for Defender amd64fre") | `AM_Delta_Patch_1.459.537.0.exe`, 407,968 B, update `f979ffd1...@200` |
    | 1.459.543.0 | 346,528 B, SHA-1 `7dc9454d...` (patch from 543) | `AM_Delta_Patch_1.459.543.0.exe`, 346,528 B, SHA-1 `7dc9454d...` |
    | 1.459.546.0 | 11,606,440 B, SHA-1 `87f5bd04...` (the full `AM_Delta.exe`: no patch from 546 exists) | `AM_Delta.exe`, 11,606,440 B, SHA-1 `87f5bd04...` |
    | 1.459.547.0 | the Defender bundle is not offered (the two other results were the lab MSI test updates) | `nothing_to_do_installed` |

    At 537 the 433 decisions were: root install 1, installers install 1, already
    installed 136, not applicable 267 (every x86, arm64 and Slim variant, every other
    patch source version, the engine patches): the plan never selected an x86 or
    arm64 package on the x64 guest, and not the 200 MB base. The other engine
    patches evaluate not installable at these states: their `IsInstallable` needs
    `MpEngine\MpEngineRing` equal to the ring of the update, the delta definitions
    older than 1.459.514.0 and the engine at the exact patch source version, so an
    engine patch and a delta patch together are not reachable through this plan at
    any state of this guest (Unvalidated through the installer; the stub applied
    such pairs in inventory 12.14).
13. **`install --yes` end to end (Observed).** From 537 with the patch variant:
    `succeeded` in 8 s (including the download of 407,968 bytes), one step (the
    terminal package) exit 0, `stub_result` success, `defender` evidence
    `{parent_pid, terminal_step 0, environment {host x64, System32 stub 1.1.24010.2001,
    SysWOW64 stub none}, nothing_applied false}`, post-check converged on the first
    poll; definitions 1.459.547.0 and the installed `mpavdlta.vdm` (SHA-1
    `66ac0ebf0830977f5e98913592d729abc3e32f86`) and `mpasdlta.vdm`
    (`79dc9b4460d43741cd91e70e34b3f7970f099e93`) equal the shipped 1.459.547.0 files.
    From 546 with the full `AM_Delta.exe`: `succeeded`, the same final hashes.
    Re-running at 547: `no_action`.
14. **Failed patch, no false success (Observed).** To make the stub fail while the
    evaluator still says applicable, `SignatureLocation` was pointed at a copy of the
    537 definition directory whose `mpavdlta.vdm` had one byte flipped at offset
    3,000,000 (the file version resource unchanged; the real definition store
    cannot be modified, even `takeown` by SYSTEM is denied). `install --yes`: status
    `failed` (CLI exit 2), the terminal step exited `0x84990402` (error 1026 of the
    MPSP family), `stub_result` `mpsp_patch_error`, the log excerpt in the job record
    shows `Patched mpasdlta.vdm to 1.459.547.0` followed by
    `ERROR 0x84990402 : ApplyPatch(C:\work\defcopy\mpavdlta.vdm, ...)`, and no
    update was applied. The post-check of that run showed `converged: true` with
    empty lists, which the fix above removes (host test).
15. **Refusals (host tests, not run on the guest):** no terminal package, a
    hand-made plan that does not end with the terminal package, a wrong stub
    version, an x86 package without the SysWOW64 stub, a PE image that cannot be read.

Still Unvalidated through the installer: an engine patch together with a delta
patch, the SysWOW64 and x86 refusals on a guest, an arm64 host, other
architectures' packages, base patches (the 1.457.0.0 base is not available),
`MpSigStub.exe` missing at plan time with a patch step, and the post-check on a
reboot-class exit.

## Guest run results, round 3 (2026-10-05, Observed, one guest, `Cbs` handler through DISM)

Guest Windows 11 Pro 25H2 10.0.26200.8037 (DISM 10.0.26100.5074), `wsus.exe` built with `task build:windows:wsus:cbs`
(feature `cbs-handler`, `[install] delegate_cbs_installable = true`, `plan_prerequisites = true`), SYSTEM, a private
state directory. Server: this project's `wsus server run` with a catalog import of SYNTHETIC `Cbs` updates (the real
handler and manifest shape of inventory 12.17, real manifest identities) whose payloads are REAL Microsoft cabs from the
Windows 11 25H2 media. Details and fixtures: inventory 12.18; ledger rows C43 to C47.

| Case | Observed |
| --- | --- |
| Plan with live facts for the language package needing its neutral package | `wsus-install-plan/2`, steps `[neutral, en-US]`, `servicing_identity` derived from each manifest, note `prerequisite updates scheduled as earlier steps`, `CbsPackageInstallable was treated as True` |
| First install: the stack's applicability verdict | failed closed (`ambiguous package State`: the offline DISM parser cannot read the online `/Get-PackageInfo` output); nothing installed; parser fixed with a test over the real output |
| Real DISM failure on a multi-lingual optional package | `/Add-Package` exit `0x800f0955`; job `failed`, step `finished`, later step `pending`, package listing and registry unchanged, `servicing.oracles.combined = neither_installed` (twice) |
| `.NET Framework 3.5` package, WSUS-only policy | DISM sat at `WULib DownloadProgress 75/100` for over 10 minutes; killed by hand: exit `0xffffffff`, job `failed`, `CurrentState 0x40`, `CBS RebootPending` set, listing absent, plan then `refused` (state 64 undecidable); after a reboot the package was `Installed` (`0x70`) |
| Re-run when installed | `no_action` (job `/1`): the evaluator read `0x70` as installed |
| Success path (package removed with `/Disable-Feature /Remove`, `UseWUServer` temporarily 0) | job `succeeded` (schema `/2`), exit 0, listing absent to `Installed` (141 to 142 packages, diff recorded), registry `0x70`, evaluator installed, `oracles = agree_installed`, `trust = servicing_stack`, `CBS.log` growth recorded; under 10 minutes including the 71 MB download |
| `--timeout-secs 20` | DISM left running, job `unconfirmed`, step `timed_out`, `pending_after = CBS RebootPending`; the package was `Installed` minutes later without any client action and the pending flag cleared; re-run `no_action`. The post-run package listing blocked about 7.5 minutes on the busy stack; the client now skips it after a timeout (host-tested) |
| Server content altered | `acquisition failed, nothing was executed: ... Sha1 digest mismatch; partial object discarded`, no job record |
| Pending-restart gate | `PendingFileRenameOperations` set by hand: job `refused`, `a restart or servicing operation is already pending (PendingFileRenameOperations): restart the machine first`, no DISM add |

Limits: one guest and one real package, published with synthetic metadata; no servicing stack update or cumulative update;
the stack's `Applicable : No`, the free-disk gate, `--allow-unknown`, the reboot barrier and `wusa` were
not run on the guest (the DISM API backend was run separately, next section); a package listing is not requested after a timeout (changed after the observation, host-tested
only). The lab guest was restored (`UseWUServer = 1`, NetFx3 installed as found, hand-made indicator removed).


## Guest run, DISM API backend (2026-10-06, Observed, clones of the lab guest, backend driven directly)

Guest: Windows 11 25H2 10.0.26200.8037, DISM 10.0.26100.5074, `DismApi.dll` in `System32`. Clones of the settled lab guest
(the same one the OSInstaller runs used), no WSUS contact (the clones carry the original client identity, so
none was made), SYSTEM. The backend was driven by `crates/wsus-client/examples/servicing_probe.rs` (`dism` or `dism_api`, `list`,
`info`, `add`), not through the executor or a job. Package: the `.NET` rollup cab of KB5126052 (96,649,380 bytes), from a
local path, the one the OSInstaller `dism` mode installed.

| Case | Observed |
| --- | --- |
| Listing | API 192 packages, exe 142. Every exe entry is in the API listing with the same state; the 50 extra are `FOD` packages. Compare each backend only with itself |
| Applicability by path | API `Applicable` true, exe `Applicable : Yes` (a first build passed the wrong `DismPackageIdentifier` value and got `0x80070057`; fixed, 2 is the path form) |
| Add, API (clone 1) | native code 3010 (plain, not `0x80070BC2`), class `reboot`, 44 s, progress callback reached 1000/1000, `dism-api-add-package.log` written at the requested path (16 KB); diff 9321.3 `Installed` to `Uninstall Pending`, 9347.1 absent to `Install Pending`; indicators `CBS RebootPending`, `CBS PackagesPending`, `WinSxS pending.xml` |
| Add, exe (clone 2) | exit 3010, 41 s, the same diff and the same indicators; applicability true |
| After a reboot (clone 1) | 9347.1 `Installed`, 9321.3 `Superseded` in the API and the exe listing |
| Timeout 10 s, process stays (clone 3) | result `timed_out`, no code, progress 121/1000; the post-call listing blocked until the add finished (about 40 s in total) and showed the pending diff |
| Timeout 10 s, process exits at once (clone 4) | probe exited after 14 s; `TiWorker` and `TrustedInstaller` kept running, `PackagesPending` appeared within 30 s and the final state was `Install Pending` in both listings, with no client action |

Limits: one guest image, one successful package, no failing, not-applicable or busy case, no SSU or LCU, the
`0x80070BC2` form is mapped but was not seen, the executor, job and CLI path was not run with `dism_api`. The last case
shows the servicing work is not tied to the client process in this one run; it is not a guarantee for other packages. The
struct layout read for `DismGetPackageInfo` only reaches `Applicable` and matched the exe on this one package. Ledger C48.

## Guest run, wusa backend (2026-10-06, Observed, one clone, metadata served by this project's server)

Guest Windows 11 Pro 25H2 10.0.26200.8037 (clone of the lab guest, no WSUS contact: `WUServer` set to a dead address), `wsus.exe`
from `6f66132` with feature `cbs-handler`, `[install] servicing_backend = "wusa"`, `delegate_cbs_installable = true`,
`timeout_secs = 3600`, SYSTEM. Server: this project's `wsus server run` on the host with a catalog import of one SYNTHETIC `Cbs`-shaped
update (real handler shape, manifest identity `Package_for_RollupFix` 26100.9457.1.0) declaring the REAL
`Windows11.0-KB5129195-x64.msu` (4.6 GB). It is not the real WSUS metadata of that update (an `OSInstaller` leaf of 19 files that the
executor refuses); only the sync, download, plan, gates, `wusa` call, restart and post-checks are exercised. Details: spike section 18.12,
ledger row C51.

| Case | Observed |
| --- | --- |
| `client sync`, `scan`, `plan` | 1 revision, `applicable`, one `servicing` step with the identity above, `wsus-install-plan/1` |
| First `install --yes` | refused: the store file was writable by everyone (private ACL on the state directory needed) |
| Second | refused: `PendingFileRenameOperations` (OneDrive, set in the clone); cleared by a restart |
| Install | 4.6 GB downloaded and re-hashed, `wusa <path> /quiet /norestart`, 11.7 minutes, exit code 3010 in the job record, class `reboot`, job `reboot_required`, oracles `agree_pending`; the client process exit status was 0 |
| After the restart, about 40 s | `refused` (`CBS RebootInProgress`; package still `Install Pending`), nothing started |
| After the restart, about 81 s | `no_action`; registry 9457 112, 8037 80, servicing stack 9441 112; `dism` listing `Installed` and `Superseded` |

Limits: not a real WSUS or its metadata, not `update_agent` mode, one guest, one build; `0x80240017` and `0x240006` not produced
through the backend; no failure or timeout of `wusa` was provoked.

## OSInstaller (`.NET`, stage 1) (OBSERVED 2026-10-05)

`[install] osinstaller_mode = "dism"` installs a `.NET` OSInstaller update (a complete small `.cab` set) through the
servicing backend. `update_agent` mode (default) needs the `osinstaller-handler` feature (Windows) and drives the
delivered `UpdateAgent.dll` through its deployment session API (`CreateDeploymentSessionEx`, no SessionData,
`GenerateDownloadRequest`, `PostDownload`, `Install`, `Commit`); `[install] osinstaller_stack_dir` points at a directory
holding the stack of `DesktopDeployment.cab`, every DLL of which is Authenticode-verified before the load and which
overrides everything else. Without it, when the update declares `DesktopDeployment.cab` (`PatchingType`
`ServicingStack`) with a SHA-1 or SHA-256 digest, the plan records it as the step's stack payload (`stack_payload`, not a
sandbox file), the acquisition path downloads it with the other declared files, the executor re-hashes it, extracts
every member to `<jobs>/<job id>-os/stack` (flat member names only, size limits) and hands that directory to the backend,
which Authenticode-verifies every DLL before the load; the directory is removed after the run (kept after a timeout,
because the stack is not stopped) and the job records `fetched_stack` (file, digest, members). A missing, tampered or
unextractable stack cabinet refuses the step. Without a declared stack and without the override the OS's `System32` stack
is used (OBSERVED once, `.NET` update, one guest: same package states as the delivered stack, spike doc section 17).
A monthly cumulative update (19 declared files, 14.3 GB for 26200.9457) is planned as a complete set when every declared file has a
name, a size and a SHA-1 or SHA-256 digest: all of them are acquired and verified, hard-linked into the sandbox under the names the
stack looks for (the WSUS content-hash prefix is dropped, the aggregated metadata cabinet is named `<guid>.AggregatedMetadata.cab`
and also placed in `<sandbox>\metadata`), and what the stack's download list names but the WSUS does not declare (the Express
wim and mumx.esd, the canonical servicing stack cabinet, the `.psf` data files) is extracted from the declared `.msu` files, which are WIM
archives (the job records these as `os_installer.provisioned`). A set with an undigested file, or a single declared file, stays refused;
`dism` mode refuses a set without a servicing CompDB cabinet. OBSERVED once, on the real lab WSUS and one guest (spike doc section 19,
ledger row C60): `reboot_required`, then after the restart the same package states as `wusa` and the native agent, and `no_action` on
the rerun. Limits there: one update, one build, the delivered stack, no wrong-digest case, no timeout or failure case. The stack
prints `HOTPATCHUTIL` lines on standard output; the backend captures the process's standard output while the stack runs (file `ua-stack-stdout.txt` in the step's log directory, bounded tail in `os_installer.stack_stdout`), so `--json` output stays one JSON document (OBSERVED once, `.NET` update, standard output redirected to a file; not tried on a console; spike doc section 20). Guest evidence,
the native oracle comparison, negative cases and limits: `docs/wsus-osinstaller-spike.md` sections 13, 16 and 17 (both modes:
reboot_required, package states equal to the native agent's before and after the reboot; one update, one Windows build;
the wrong-server-digest case was not run, a tampered stored payload is repaired by the acquisition step).

Failure, timeout and interruption of `OSInstaller` steps (OBSERVED on clones of the lab guest, `.NET` update, spike doc section 21, ledger
rows C74 to C76): a stack failure is a `failed` job after ONE attempt (no retry), with the phase list showing where it stopped (a sandbox
payload removed during the run: `generate_download_request` `0x80070002`; `dism` mode, disk full during the add: exit `0x70`), and a rerun
plans again from fresh facts and installs. A timeout (`--timeout-secs`) never stops the stack: in `dism` mode the DISM process is left
running and the command returns `unconfirmed`; in `update_agent` mode the stack runs INSIDE the client process, so returning would end it
(OBSERVED before the change: package left at `InstallRequested` without a pending restart), and the client therefore prints a line to
standard error, WAITS for the stack to return and records `timed_out` (step `unconfirmed`); in this mode the timeout no longer bounds the
wall time of the command. A hard kill of the client leaves the job `running`; the next run marks it `interrupted` (listing
`recovered_interrupted_jobs`) and decides from fresh state; the servicing processes keep running.

## Guest run on two more Windows images (2026-10-06, Observed, client only, no server)

Ledger row C61. Binaries from a clean worktree at `f8d6e24` (host and `x86_64-pc-windows-msvc`, default features, so no
`cbs-handler`). Guests were fresh instances of the bases `win10-22h2` (Windows 10 Pro 22H2, 10.0.19045.3803) and `ws2025`
(Windows Server 2025 Standard Evaluation, 10.0.26100.32230), compared with a clone of `osi-gold` (Windows 11 25H2, UBR 8037). No server
was contacted: the client state held the revisions of an earlier real-WSUS sync (5,168 revisions, copied), the four verified content
objects of the bundle were copied into `content\complete` from earlier client states, and `origin` pointed at a dead address. So this
exercises facts, scan, plan and the executor gates and install, not `sync` or `download`.

| | Windows 11 25H2 (clone of `osi-gold`) | Windows 10 22H2 | Windows Server 2025 |
|---|---|---|---|
| `facts-check` (20,453 queries) | disagree 0, `ours_unavailable` 59 (`wmi_query`), `reference_unavailable` 3 (`msi_patch`) | the same, same per-kind counts | the same, same per-kind counts |
| `scan`, 13 root updates | 7 installed, 6 not applicable (51 queries) | 6 applicable, 7 not applicable (46) | 6 applicable, 7 not applicable (48) |
| `plan` of `a2fef9b0-...@200` | `install`, 3 steps, 29 queries | `install`, 4 steps (`MpSigStub.exe /Store` first), 29 | `install`, 4 steps, 30 |
| `System32\MpSigStub.exe` before | 1.1.24010.2001 | absent | absent |
| `install --yes` | not run here (C57) | `succeeded`, 18 s | `succeeded`, 15 s |
| signatures | 1.459.561.0 (removed to 0.0.0.0 for the plan) | 1.303.25.0 to 1.459.547.0 | 1.437.1.0 to 1.459.547.0 |
| rerun | | `no_action` | `no_action` |

The extra step is the planner's stub rule working as designed (the launchers need `System32\MpSigStub.exe` 1.1.24010.2001, the plan
installs it when it is missing), not a defect. After the install `System32\MpSigStub.exe` was 1.1.24010.2001 on both, the engine
1.1.26080.3, the platform unchanged (4.18.1909.6 on Windows 10, 4.18.25080.5 on Server), and a second scan listed
`dc8cd110-fb75-45bb-8379-859df2409586@200` as applicable (not covered by this bundle; installed on 25H2, not applicable on the
other two before the install). The collector `scripts/wsus/collect-facts.ps1` at this commit reports `msi_patch` as not collected on
all three images; the older figures above ("msi_patch 3" among the agreements) predate that and are not reproduced.

Lab notes. The `win10-22h2` base disables Defender by policy (`DisableAntiSpyware`, `DisableAntiVirus`, services `Start` 4) like the
25H2 lab image; it was re-enabled by removing the policy values and the Real-Time Protection and Spynet policy keys, setting the
service start types back and rebooting, so it is a lab-modified image. The `ws2025` base needed nothing. Fresh `win10-22h2` instances
are fragile on the first boot: the first one was rebooted by hand about five minutes in, during the OOBE pass, and showed the
"Install Windows ... restarted unexpectedly" dialog (discarded); in the second the `disable-windows-defender.ps1` step of the
specialize pass sat in `gpupdate.exe /target:computer /force` for over ten minutes until the PowerShell process was killed (OOBE then
finished; the guest agent answered again only after the next reboot, SSH as `deploy` worked meanwhile; the script's `-Enable` mode
hung in the same `gpupdate` call). A fresh `ws2025` instance came up without a dialog.

Not done: any server contact on these images (sync, download, reports, the P3 matrix), the wrong-server-digest negative case
(copying the server store for a working copy was denied by the permission classifier, so no catalog with a changed digest was
served), the `Cbs` and `OSInstaller` handlers, the `-offline` bases.
