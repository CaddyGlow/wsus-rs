# WSUS M0 fixtures: real Windows servicing (CBS and OS installer) metadata

Provenance: REAL update metadata of the `Windows 11` product, synced by the lab WSUS (Windows Server 2025, build
10.0.26100.32230, `ProtocolVersion` 3.2) from Microsoft Update on 2026-10-05 and then pulled by this project's
`wsus client sync` (5,253 revisions, 406 `SyncUpdates` pages, 1,094 Extended fragments). Nothing here is authored by
this project except the reductions listed below. No content was approved or downloaded. Update identifiers, KB numbers
and file digests are public Microsoft catalog data. Cookies, signed URLs and host identities are not included; the one
protocol exchange kept (`get-file-locations-response.xml`) has its cookie fields redacted and its server address
replaced by `wsus.lab.invalid`.

The raw state stays local (`/dev/shm/wsus-cbs-state`, 1.3 GB) and is never committed. `catalog-stats.json` holds the
counts quoted by the inventory section 12.17.

| File | What it is | Reduction |
| --- | --- | --- |
| `cbs-dotnet-core-reduced.xml` | Core fragment of the CBS update `f1ff1e3d-dd47-4fcb-9405-8f7275ce1ea6@200` (KB5017029, a .NET 4.8.1 rollup, amd64) | the `CbsPackageApplicabilityMetadata` manifest is cut to `assembly`, its first `assemblyIdentity` and an empty `package` element (49,953 of 50,662 bytes removed) |
| `cbs-dotnet-extended.xml` | its Extended fragment (real, unmodified) | none |
| `cbs-rollupfix-core-reduced.xml` | Core fragment of `267dd2b4-f9fa-4bcd-bba7-1cb00e0e59d9@200` (KB5026368, `Package_for_RollupFix`, arm64): `IsInstalled` is `CbsPackageInstalled` AND NOT a `LCUReoffer` registry flag | same cut (309,507 of 310,337 bytes removed) |
| `cbs-rollupfix-extended.xml` | its Extended fragment (real, unmodified) | none |
| `osinstaller-core.xml` | Core fragment of the OS installer update `f97b86e6-5c6c-4366-b948-b5426295a5a7@100` (`Client.OS.RS2.ARM64` 10.0.22621.5909) | none |
| `osinstaller-extended.xml` | its Extended fragment (real, unmodified; 4,818 bytes, 8 declared files) | none |
| `get-file-locations-response.xml` | the real `GetFileLocations` answer for the file of `f1ff1e3d...@200` | cookie fields `REDACTED`, server address replaced |
| `catalog-stats.json` | counts over the whole stored catalog | derived |

Unit tests read these files: `crates/wsus-protocol` (`applicability::windows_servicing_tests`) and
`crates/wsus-client` (`install::handlers::cbs`).

## Facts the fixtures show (OBSERVED)

* The CBS handler URI is `http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs` with
  `HandlerSpecificData type="cbs:Cbs"` and `<CbsData PackageIdentity="" />`: the attribute is empty on all 180 CBS
  updates. The package is identified by `Metadata/CbsPackageApplicabilityMetadata/assembly/assemblyIdentity` of the Core
  fragment (name, version, processorArchitecture, language, publicKeyToken), for example
  `Package_for_RollupFix` `22000.1936.1.9` arm64.
* The OS installer handler URI is `http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller` with
  `HandlerSpecificData type="OSInstallerMetadata"` and `<OSInstallData InitialModule="UpdateAgent.dll" />`;
  `ExtendedProperties` carries `ProductName`, `ReleaseVersion` and `ReleaseRevision`.
* Rule operators not in the public schema pages: `CbsPackageInstalled`, `CbsPackageInstallable` (no attributes),
  `ProductReleaseInstalled` (`Name`, `Version`), `DeviceAttribute` (`Name`, `Type`, `Comparison`, `Value`).
* The real server answered `GetFileLocations` for a file of an unapproved update with a location
  (`.../Content/<last two hex of SHA-1>/<SHA-1>.cab`); that URL returned `404` because the content was never
  downloaded to the server.

## DISM online output (added 2026-10-05, inventory 12.18)

- `dism-online-get-packages.txt`: `dism.exe /English /Online /Get-Packages /Format:List` on the lab guest (Windows 11 25H2
  10.0.26200.8037, DISM 10.0.26100.5074), 142 packages, exit 0; read by the parser tests of `wsus-client`
  `install/servicing/dism.rs`.
- `dism-online-get-packageinfo-ie-optional.txt`: `dism.exe /English /Online /Get-PackageInfo /PackagePath:<cab>` for a real
  optional package from the Windows 11 25H2 media (`Applicable : Yes`, `State : Not Present`, with the `Custom Properties`
  and `Features listing` sections that make the offline `windows-dism` parser fail).
