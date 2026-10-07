//! Machine-readable operator table: which operators are implemented and what
//! the evidence for each rule of their semantics is. The same content is in
//! `docs/wsus-protocol-inventory.md` ("Applicability rules"); a test keeps the
//! operator names in sync with the parser.
//!
//! Evidence labels:
//!
//! * [`Evidence::Specified`]: stated by public Microsoft documentation
//!   (the "BaseApplicabilityRules", "MsiApplicabilityRules", "BaseTypes" and
//!   "Version Detection Logic" pages of the WSUS SDK on learn.microsoft.com,
//!   `VerifyVersionInfo`/`VerSetConditionMask`).
//! * [`Evidence::Observed`]: read from the 5168 stored real revisions (shape
//!   only; the data never shows the client's behaviour).
//! * [`Evidence::Decision`]: this crate chose a behaviour where the sources
//!   are silent.
//! * [`Evidence::Unverified`]: a guess about the native client that only a
//!   differential run can confirm; where it would change the answer the
//!   evaluator returns `Unknown` instead.

/// Evidence class of one semantic rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    Specified,
    Observed,
    Decision,
    Unverified,
}

impl Evidence {
    /// Label used in the documentation.
    pub fn label(self) -> &'static str {
        match self {
            Evidence::Specified => "Specified",
            Evidence::Observed => "Observed",
            Evidence::Decision => "Implementation decision",
            Evidence::Unverified => "Unverified",
        }
    }
}

/// One operator.
#[derive(Debug, Clone, Copy)]
pub struct OperatorInfo {
    /// Bare operator name.
    pub name: &'static str,
    /// `logical`, `base`, `msi` or `unprefixed` (as in the real data).
    pub family: &'static str,
    /// Evaluated by this crate (given facts). `false` means the parser keeps
    /// it as an unsupported node and the result is `Unknown`.
    pub implemented: bool,
    /// Rules with their evidence.
    pub rules: &'static [(Evidence, &'static str)],
}

use Evidence::{Decision, Observed, Specified, Unverified};

/// Every operator named in the public schema pages or seen in the real data.
pub const OPERATORS: &[OperatorInfo] = &[
    OperatorInfo {
        name: "True",
        family: "logical",
        implemented: true,
        rules: &[(Specified, "constant true (LogicalApplicabilityRules)")],
    },
    OperatorInfo {
        name: "False",
        family: "logical",
        implemented: true,
        rules: &[(Specified, "constant false")],
    },
    OperatorInfo {
        name: "And",
        family: "logical",
        implemented: true,
        rules: &[
            (Specified, "logical conjunction"),
            (
                Decision,
                "n-ary; Kleene strong logic; no operands is unsupported",
            ),
        ],
    },
    OperatorInfo {
        name: "Or",
        family: "logical",
        implemented: true,
        rules: &[
            (Specified, "logical disjunction"),
            (
                Decision,
                "n-ary; Kleene strong logic; no operands is unsupported",
            ),
        ],
    },
    OperatorInfo {
        name: "Not",
        family: "logical",
        implemented: true,
        rules: &[
            (Specified, "logical negation"),
            (
                Decision,
                "exactly one operand, else unsupported; Not Unknown is Unknown",
            ),
        ],
    },
    OperatorInfo {
        name: "RegKeyExists",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "true when HKLM\\Subkey exists; Key is HKEY_LOCAL_MACHINE or HKEY_LOOP_TARGET only",
            ),
            (Specified, "RegType32 is a boolean, default false"),
            (
                Decision,
                "RegType32=true is the 32-bit view (KEY_WOW64_32KEY), false is the native view; names compare case-insensitively",
            ),
        ],
    },
    OperatorInfo {
        name: "RegValueExists",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "existence of the value; the default value when Value is omitted; with Type the value must have that type",
            ),
            (
                Observed,
                "Type REG_BINARY occurs (945 times) although the public RegistryValueType enumeration lacks it; Value is present on every occurrence",
            ),
            (
                Decision,
                "a present value of another type is false; Value=\"\" is the default value",
            ),
        ],
    },
    OperatorInfo {
        name: "RegDword",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares a REG_DWORD value with Data (unsigned 32-bit) using ScalarComparison",
            ),
            (
                Specified,
                "operand order observed value <op> Data (by the FileVersion example)",
            ),
            (Observed, "Data is decimal in every occurrence"),
            (
                Decision,
                "missing key or value is false (the Not(RegDword ...) guards in the Defender rules rely on it)",
            ),
            (
                Unverified,
                "a value of another registry type is Unknown, not false",
            ),
        ],
    },
    OperatorInfo {
        name: "RegSz",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares a REG_SZ value with Data using StringComparison (EqualTo, BeginsWith, Contains, EndsWith)",
            ),
            (Observed, "EqualTo, Contains and BeginsWith occur"),
            (
                Decision,
                "missing value is false; a value of another type is Unknown",
            ),
            (
                Unverified,
                "case sensitivity: both ordinal and case-folded comparison are computed and the result is Unknown when they differ",
            ),
        ],
    },
    OperatorInfo {
        name: "RegExpandSz",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares a REG_EXPAND_SZ value with Data using StringComparison",
            ),
            (
                Decision,
                "the unexpanded data is compared; data containing % is Unknown (whether the client expands is unverified); case rule as RegSz",
            ),
        ],
    },
    OperatorInfo {
        name: "RegSzToVersion",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares a REG_SZ value, read as a four-part version, with Data (bt:Version) using ScalarComparison",
            ),
            (
                Decision,
                "numeric per-part ordering; missing value is false",
            ),
            (
                Observed,
                "the registry string may have fewer than four parts: Windows CurrentVersion is `6.3` and rules compare it with 6.1.0.0; one to four parts are accepted, missing parts are zero. Evidence: the 27 Office updates the native search reports installed only evaluate True with that reading (one machine, one rule family)",
            ),
            (
                Unverified,
                "a string that is not a numeric version (or a non-REG_SZ value) is Unknown; the client may treat it as false",
            ),
        ],
    },
    OperatorInfo {
        name: "RegKeyLoop",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "evaluates the body against every sub-key of the key; TrueIf is Any, All or None; HKEY_LOOP_TARGET names the current sub-key",
            ),
            (
                Decision,
                "Any is Or over the iterations, None is Not Any; the body's registry operators use the loop key's view",
            ),
            (
                Unverified,
                "a missing loop key behaves as no sub-keys (Any false, None true); All over zero sub-keys is Unknown",
            ),
        ],
    },
    OperatorInfo {
        name: "FileExists",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "existence of the file; when Version or Size are given all must match; Csidl is resolved with SHGetFolderPath and prepended; duplicate backslashes are removed",
            ),
            (
                Observed,
                "Csidl 35, 36, 37, 38, 41, 42, 43 occur; Size occurs on 5 uses; Version, Created, Modified, Language never",
            ),
            (
                Decision,
                "Created, Modified and Language attributes make the operator unsupported; Version and Size compare for equality",
            ),
        ],
    },
    OperatorInfo {
        name: "FileExistsPrependRegSz",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "as FileExists with the REG_SZ value prepended instead of a CSIDL",
            ),
            (
                Decision,
                "base and path are joined with exactly one backslash; a missing base value is false",
            ),
            (
                Unverified,
                "the client may concatenate without inserting a separator",
            ),
        ],
    },
    OperatorInfo {
        name: "FileVersion",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares the file's version with a four-part version using ScalarComparison; the version check implies the file exists (Version Detection Logic)",
            ),
            (
                Decision,
                "missing file is false; numeric per-part ordering; the version is the fixed file version (VS_FIXEDFILEINFO)",
            ),
            (
                Unverified,
                "an existing file without a recorded version is Unknown",
            ),
        ],
    },
    OperatorInfo {
        name: "FileVersionPrependRegSz",
        family: "base",
        implemented: true,
        rules: &[
            (Specified, "as FileVersion with the REG_SZ value prepended"),
            (Decision, "as FileExistsPrependRegSz and FileVersion"),
        ],
    },
    OperatorInfo {
        name: "FileCreated",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares the file's creation date with Created (xs:dateTime) using ScalarComparison",
            ),
            (
                Decision,
                "UTC instants compared at 100 ns; a missing file is false; a dateTime without time zone is malformed",
            ),
        ],
    },
    OperatorInfo {
        name: "FileCreatedPrependRegSz",
        family: "base",
        implemented: true,
        rules: &[
            (Specified, "as FileCreated with the REG_SZ value prepended"),
            (Decision, "see FileExistsPrependRegSz"),
        ],
    },
    OperatorInfo {
        name: "FileModified",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares the file's modification date with Modified using ScalarComparison",
            ),
            (Decision, "as FileCreated"),
        ],
    },
    OperatorInfo {
        name: "FileModifiedPrependRegSz",
        family: "base",
        implemented: true,
        rules: &[
            (Specified, "as FileModified with the REG_SZ value prepended"),
            (Decision, "see FileExistsPrependRegSz"),
        ],
    },
    OperatorInfo {
        name: "FileSize",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "compares the file size with Size using ScalarComparison",
            ),
            (Decision, "a missing file is false"),
        ],
    },
    OperatorInfo {
        name: "FileSizePrependRegSz",
        family: "base",
        implemented: true,
        rules: &[
            (Specified, "as FileSize with the REG_SZ value prepended"),
            (Decision, "see FileExistsPrependRegSz"),
        ],
    },
    OperatorInfo {
        name: "WindowsVersion",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "implemented with VerifyVersionInfo; Comparison applies to MajorVersion, MinorVersion, BuildNumber, ServicePackMajor and ServicePackMinor and defaults to EqualTo",
            ),
            (
                Specified,
                "VerifyVersionInfo tests major, minor and service pack hierarchically (lexicographically, stopping at the first unequal field)",
            ),
            (
                Specified,
                "SuiteMask: all suites with AllSuitesMustBePresent=true, otherwise at least one (VER_AND / VER_OR)",
            ),
            (
                Decision,
                "major, minor, SP major, SP minor compare as one lexicographic tuple over the fields present",
            ),
            (
                Unverified,
                "BuildNumber is a separate test with the same Comparison (VerifyVersionInfo does not put the build number in the hierarchy; equivalent on real builds that increase with version); the facts are RtlGetVersion values",
            ),
        ],
    },
    OperatorInfo {
        name: "WindowsLanguage",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "true if the OS is localized to Language; always false if MUI is installed",
            ),
            (
                Decision,
                "case-insensitive tag equality is true; a different language is false",
            ),
            (
                Unverified,
                "a neutral tag (en) against a specific OS tag (en-US) is Unknown",
            ),
        ],
    },
    OperatorInfo {
        name: "MuiInstalled",
        family: "base",
        implemented: true,
        rules: &[(
            Specified,
            "true if the Multilingual User Interface is installed",
        )],
    },
    OperatorInfo {
        name: "SystemMetric",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "GetSystemMetrics(Index) compared with Value using ScalarComparison",
            ),
            (Observed, "indices 86 and 87 only"),
        ],
    },
    OperatorInfo {
        name: "Processor",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "the processor architecture equals Architecture (SYSTEM_INFO.wProcessorArchitecture); optional Level and Revision",
            ),
            (
                Observed,
                "Architecture 0, 5, 6, 9, 12 occur; Level and Revision never",
            ),
            (
                Decision,
                "the native architecture (GetNativeSystemInfo); Level or Revision make the operator unsupported",
            ),
        ],
    },
    OperatorInfo {
        name: "WmiQuery",
        family: "base",
        implemented: true,
        rules: &[
            (
                Specified,
                "executes the WQL query, true for one or more rows, false for none",
            ),
            (
                Decision,
                "Namespace defaults to root\\cimv2; a query that cannot be run is Unavailable",
            ),
        ],
    },
    OperatorInfo {
        name: "LicenseDword",
        family: "base",
        implemented: true,
        rules: &[
            (
                Observed,
                "Value (a licensing name or GUID), Comparison, Data; 750 uses, not in the public schema pages",
            ),
            (
                Unverified,
                "read as SLGetWindowsInformationDWORD(Value) <op> Data; a name the licensing service does not know is false",
            ),
        ],
    },
    OperatorInfo {
        name: "MsiProductInstalled",
        family: "msi",
        implemented: true,
        rules: &[
            (
                Specified,
                "the product is installed; VersionMin/VersionMax bound the version, ExcludeVersionMin/Max make the bound exclusive and are valid only with their bound; Language filters",
            ),
            (
                Observed,
                "ExcludeVersionMax occurs without VersionMax on 133 uses and ExcludeVersionMin without VersionMin on 55",
            ),
            (
                Decision,
                "Exclude without a bound is ignored; missing numeric parts compare as zero; installed means MsiQueryProductState is local, source or default",
            ),
        ],
    },
    OperatorInfo {
        name: "MsiFeatureInstalledForProduct",
        family: "msi",
        implemented: true,
        rules: &[
            (
                Specified,
                "the features are installed for one (all with AllProductsRequired) of the products",
            ),
            (
                Decision,
                "AllFeaturesRequired selects all-of or any-of the listed features; Kleene combination",
            ),
        ],
    },
    OperatorInfo {
        name: "MsiComponentInstalledForProduct",
        family: "msi",
        implemented: true,
        rules: &[
            (
                Specified,
                "the components are installed for one (all with AllProductsRequired) of the products",
            ),
            (
                Decision,
                "as MsiFeatureInstalledForProduct with AllComponentsRequired",
            ),
        ],
    },
    OperatorInfo {
        name: "MsiPatchInstalledForProduct",
        family: "msi",
        implemented: true,
        rules: &[
            (
                Specified,
                "the patch is installed for the product; VersionMin/VersionMax/Language also exist in the schema",
            ),
            (
                Decision,
                "those extra attributes make the operator unsupported (never seen)",
            ),
        ],
    },
    OperatorInfo {
        name: "CbsPackageInstalledByIdentity",
        family: "unprefixed",
        implemented: true,
        rules: &[
            (
                Observed,
                "PackageIdentity is a CBS package identity string; 68 uses; not in the public schema pages",
            ),
            (
                Unverified,
                "read as CurrentState 112 (0x70, installed) of the identity's key under Component Based Servicing\\Packages; other states are Unknown",
            ),
        ],
    },
    OperatorInfo {
        name: "DeviceAttribute",
        family: "unprefixed",
        implemented: true,
        rules: &[
            (
                Observed,
                "Name, Type (String or Version), Comparison (EqualTo, GreaterThanOrEqualTo, LessThan) and Value; 2459 uses on a real Windows 11 catalog (OSSkuId 747, sku 747, OSVersion 604, ProductType 198, DL_OSVersion 88, IsRemoteDesktopSessionHost 66, CurrentBranch 9); not in the public schema pages",
            ),
            (
                Decision,
                "OSVersion and DL_OSVersion compare major, minor and build; equal builds are Unknown because the revision (UBR) is not a fact",
            ),
            (
                Unverified,
                "ProductType WinNT, LanmanNT and ServerNT are read as product types 1, 2 and 3; every other attribute (OSSkuId, sku, IsRemoteDesktopSessionHost, CurrentBranch) has no fact source and is Unknown",
            ),
        ],
    },
    OperatorInfo {
        name: "ProductReleaseInstalled",
        family: "unprefixed",
        implemented: true,
        rules: &[
            (
                Observed,
                "Name and Version (for example Client.OS.RS2.AMD64 and 10.0.22621.5909, Microsoft.NetFX.amd64 and 2400.26200.9347.1); 297 uses, one per OS installer update; not in the public schema pages",
            ),
            (
                Decision,
                "Client.OS.* is installed when the OS version (major, minor, build, UBR) is at least Version and the architecture matches; Microsoft.NetFX.<arch> is installed when an installed Package_for_DotNetRollup_* package of that architecture has a package build and revision (last two components of 10.0.B.R) at least those of Version",
            ),
            (
                Unverified,
                "the mapping is inferred from one native install (the package state after the .NET update is 9347.1 for release 2400.26200.9347.1) and from the OS version; OBSERVED pre-reboot states (fixture dotnet-cbs-state.json): native install pending has CurrentState 64 and no PackagesPending key, `dism /Add-Package` pending has CurrentState 96 and a PackagesPending list, installed is 112, so both pending states read as not installed; Microsoft.NetFX presence (ProductReleaseVersion) accepts any non-zero state of a rollup package; other product names are Unknown; the UBR must be a fact",
            ),
        ],
    },
    OperatorInfo {
        name: "CbsPackageInstalled",
        family: "unprefixed",
        implemented: false,
        rules: &[
            (
                Observed,
                "no attributes; 180 uses, one per CBS update; the package is named by Metadata/CbsPackageApplicabilityMetadata/assembly/assemblyIdentity",
            ),
            (
                Decision,
                "resolved at parse time to CbsPackageInstalledByIdentity with the identity name~publicKeyToken~processorArchitecture~language~version (language neutral is empty); unsupported when the metadata is absent",
            ),
        ],
    },
    OperatorInfo {
        name: "CbsPackageInstallable",
        family: "unprefixed",
        implemented: false,
        rules: &[
            (
                Observed,
                "no attributes; 180 uses; the manifest's parent assemblies (disposition detect, revisionCompare or buildCompare) describe the applicability",
            ),
            (
                Unverified,
                "evaluating it needs the CBS component store; always unsupported",
            ),
        ],
    },
    OperatorInfo {
        name: "ProductReleaseVersion",
        family: "unprefixed",
        implemented: true,
        rules: &[
            (
                Observed,
                "Name, Version and Comparison (lower-case greaterthan); 17 uses, all Version 0.0.0.0 on product names such as Client.OS.RS2.AMD64, Server.OS.amd64, Microsoft.NetFX.amd64; not in the public schema pages",
            ),
            (
                Decision,
                "only `greaterthan 0.0.0.0` (the product is present) is read: Client.OS.* is present on a workstation of that architecture, Server.OS.* on a server of that architecture, Microsoft.NetFX.<arch> when an installed Package_for_DotNetRollup_* package of that architecture exists; other product names and comparisons are Unknown",
            ),
            (
                Unverified,
                "the readings are inferred from the product names; no native agent compared them",
            ),
        ],
    },
    OperatorInfo {
        name: "Platform",
        family: "base",
        implemented: false,
        rules: &[
            (
                Observed,
                "PlatformID=\"Windows\" on 3 uses; not in the public schema pages",
            ),
            (
                Unverified,
                "probably true on every Windows client, but that is a guess; always unsupported",
            ),
        ],
    },
    OperatorInfo {
        name: "NumberOfProcessors",
        family: "base",
        implemented: false,
        rules: &[(Specified, "documented, never seen; no fact source")],
    },
    OperatorInfo {
        name: "ClusteredOS",
        family: "base",
        implemented: false,
        rules: &[(Specified, "documented, never seen; no fact source")],
    },
    OperatorInfo {
        name: "ClusterResourceOwner",
        family: "base",
        implemented: false,
        rules: &[(Specified, "documented, never seen; no fact source")],
    },
    OperatorInfo {
        name: "MuiLanguageInstalled",
        family: "base",
        implemented: false,
        rules: &[(Specified, "documented, never seen; no fact source")],
    },
    OperatorInfo {
        name: "InstalledOnce",
        family: "base",
        implemented: false,
        rules: &[(
            Specified,
            "documented, never seen; needs the client's installation history",
        )],
    },
    OperatorInfo {
        name: "GenericQuery",
        family: "base",
        implemented: false,
        rules: &[(Specified, "documented, never seen; vendor-defined")],
    },
];

/// Names of the implemented operators.
pub fn implemented_names() -> impl Iterator<Item = &'static str> {
    OPERATORS.iter().filter(|o| o.implemented).map(|o| o.name)
}
