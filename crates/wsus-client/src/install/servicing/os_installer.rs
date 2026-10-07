//! The `OSInstaller` handler's execution seam (docs/wsus-osinstaller-spike.md).
//!
//! An `OSInstaller` update (the monthly cumulative and the `.NET` rollup updates) is installed by the
//! Windows Update stack itself (`UpdateAgent.dll`, the servicing stack, `UpdateDeploy.dll`), not by one
//! `dism /Add-Package`. The executor therefore hands a verified sandbox directory (every declared payload
//! of the update, by its declared name) to an [`OsInstallerBackend`], which returns the evidence of what
//! the stack did. The trait and the [`FakeOsBackend`] are always compiled so the executor logic is
//! host-testable; the Windows backend that drives `UpdateAgent.dll` is behind the
//! `osinstaller-handler` feature (`update_agent` module).
//!
//! Evidence labels: READ = decompiled from `UpdateAgent.dll` 10.0.26100.9457 (docs/wsus-osinstaller-spike.md);
//! OBSERVED = seen on a guest; INFERRED = deduced, not checked.
use super::{BackendError, ServicingClass, ServicingResult};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

/// Which stack executes an `OSInstaller` update (`[install] osinstaller_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsInstallerMode {
    /// Drive `UpdateAgent.dll` through its `UA_*` exports (what the native agent's stack does).
    #[default]
    UpdateAgent,
    /// Add the canonical single `.cab` with DISM or `wusa` (the `Cbs` handler's backends).
    Dism,
}

impl OsInstallerMode {
    pub fn name(self) -> &'static str {
        match self {
            OsInstallerMode::UpdateAgent => "update_agent",
            OsInstallerMode::Dism => "dism",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "update_agent" => Some(Self::UpdateAgent),
            "dism" => Some(Self::Dism),
            _ => None,
        }
    }
}

/// How `UpdateAgent.dll` classifies one file of a download list (READ: the strings compared in
/// `UA_CreatePackageListFromDownloadList`, in this order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadPayloadType {
    Canonical,
    Psfx,
    Diff,
    ReverseDiff,
    Express,
    /// A numeric tag outside 1 to 5.
    Unknown(u32),
}

impl DownloadPayloadType {
    pub fn from_tag(tag: u32) -> Self {
        match tag {
            1 => Self::Canonical,
            2 => Self::Psfx,
            3 => Self::Diff,
            4 => Self::ReverseDiff,
            5 => Self::Express,
            n => Self::Unknown(n),
        }
    }
}

/// One entry of the download list `UpdateAgent.dll` derives from an ActionList: a file the update still
/// needs, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadItem {
    pub payload_type: DownloadPayloadType,
    /// The source path or name as the stack gives it.
    pub source: String,
    /// The file name the stack will look for in the sandbox.
    pub target_file_name: String,
}

/// What the executor asks the backend to do.
#[derive(Debug, Clone)]
pub struct OsInstallRequest {
    /// Directory holding every verified payload of the update under its declared file name.
    pub sandbox: PathBuf,
    /// The declared file names (the plan's payloads), for the fetched-versus-needed comparison.
    pub declared: Vec<String>,
    /// SessionData JSON for the session. EMPTY (the default) passes no SessionData, which is what the
    /// native agent does for a `.NET` update (OBSERVED: its `windlp.state.xml` has no SessionData and
    /// `Scenario` 4, the ActionList says `SessionData="DesktopServicing"`).
    pub session_json: String,
    /// A directory holding the stack of the update's own `DesktopDeployment.cab`, extracted by the
    /// executor from the digest-verified payload. A backend whose stack was not configured explicitly
    /// loads the stack from here (verifying every DLL first) instead of the system one.
    pub stack_dir: Option<PathBuf>,
    /// Where the backend may write its own evidence files.
    pub log_dir: PathBuf,
    /// Bound for the install call (the stack is never killed on timeout).
    pub timeout: Duration,
    /// Store paths of the declared `.msu` containers (WIM archives; the verified store files, NOT the
    /// sandbox links: OBSERVED, the stack removes declared files from the sandbox during
    /// `GenerateDownloadRequest`). A file the stack's download list names that the sandbox does not hold
    /// is looked for inside them and extracted into the sandbox: the `.msu` is the `AltSource` the
    /// ActionList names for the Express payloads (the native flow's canonical fallback), and the WSUS
    /// declares the `.msu` files, not the Express files. Read only.
    pub containers: Vec<PathBuf>,
}

/// One phase of the run (`create_action_list`, `download_list`, `install`, `commit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsPhase {
    pub name: String,
    /// HRESULT as the export returned it; `None` when the phase did not run.
    pub hresult: Option<u32>,
    pub note: String,
}

/// What the job records about one `OSInstaller` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsStepEvidence {
    /// `update_agent` or `dism`.
    pub mode: String,
    /// Files declared by the metadata and held by the sandbox (names).
    pub declared: Vec<String>,
    /// Files the update stack says it needs (empty in `dism` mode: the stack was not asked).
    pub download_list: Vec<DownloadItem>,
    /// Files the stack needs that the sandbox does not hold.
    pub missing: Vec<String>,
    /// Package identities the post-check expects (from the ActionList or the CompDB).
    pub expected_identities: Vec<String>,
    pub phases: Vec<OsPhase>,
    /// SHA-256 of the generated `ActionList.xml`, when the stack produced one.
    pub action_list_sha256: Option<String>,
    /// The generated `ActionList.xml` kept as evidence.
    pub action_list_path: Option<String>,
    /// The update's own `DesktopDeployment.cab` fetched, extracted and offered to the backend as the
    /// stack (absent: the backend's configured or system stack was used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_stack: Option<FetchedStack>,
    /// Files the stack asked for that were extracted from a declared `.msu` container into the sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provisioned: Vec<ProvisionedFile>,
    /// What the update stack wrote to the process's standard output while it ran (bounded tail; the
    /// whole text is in the step's log directory). OBSERVED: the hotpatch helper writes `HOTPATCHUTIL`
    /// text there; it is captured so that `--json` output stays pure JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_stdout: Option<String>,
}

/// A file taken out of a declared `.msu` container for the stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionedFile {
    pub name: String,
    /// The declared container it came out of.
    pub container: String,
    pub bytes: u64,
}

/// Evidence of a servicing stack the executor extracted from the update's declared cabinet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedStack {
    pub file_name: String,
    /// Declared digest the cabinet was verified against (`algorithm:hex`).
    pub digest: String,
    /// Names of the extracted members.
    pub files: Vec<String>,
}

/// What the backend reports for the whole run.
#[derive(Debug, Clone)]
pub struct OsInstallOutcome {
    pub phases: Vec<OsPhase>,
    /// The generated `ActionList.xml` (kept as evidence), when the stack produced one.
    pub action_list: Option<PathBuf>,
    /// Files the stack says the update needs.
    pub download_list: Vec<DownloadItem>,
    /// Package identities the ActionList installs (DISM form), the second post-check oracle.
    pub expected_identities: Vec<String>,
    /// The install result in the shared servicing form.
    pub result: ServicingResult,
    /// Files extracted from a declared `.msu` container into the sandbox for the download list.
    pub provisioned: Vec<ProvisionedFile>,
}

/// The stack behind `OSInstaller` steps. Implementations never kill a servicing process.
pub trait OsInstallerBackend: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;
    /// True when the backend was given an explicit stack directory, which then wins over a stack the
    /// update delivers.
    fn stack_overridden(&self) -> bool {
        false
    }
    fn run(&self, req: &OsInstallRequest) -> Result<OsInstallOutcome, BackendError>;
}

/// Package identities an ActionList installs, in the form DISM lists them.
///
/// `InstallPackage/@Keyform` is the CBS key form with an empty public key token
/// (`Package_for_DotNetRollup_481~~amd64~~10.0.9347.1`, OBSERVED in the native `.NET` ActionList); DISM
/// lists the same package with the Microsoft token inserted (`~31bf3856ad364e35~`).
pub fn identities_from_action_list(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<InstallPackage") {
        rest = &rest[i + "<InstallPackage".len()..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        if let Some(k) = tag.find("Keyform=\"") {
            let v = &tag[k + "Keyform=\"".len()..];
            if let Some(q) = v.find('"') {
                out.push(keyform_to_identity(&v[..q]));
            }
        }
        rest = &rest[end..];
    }
    out.sort();
    out.dedup();
    out
}

/// The files an ActionList's `<Downloads>` section names (`SourceName` per `<Payload>`), the shape the
/// native `.NET` ActionList has (fixture `dotnet-ActionList.xml`).
pub fn downloads_from_action_list(xml: &str) -> Vec<DownloadItem> {
    let mut out = Vec::new();
    let Some(start) = xml.find("<Downloads>") else {
        return out;
    };
    let section = &xml[start
        ..xml[start..]
            .find("</Downloads>")
            .map_or(xml.len(), |e| start + e)];
    let attr = |tag: &str, name: &str| -> Option<String> {
        let k = tag.find(&format!("{name}=\""))? + name.len() + 2;
        let v = &tag[k..];
        Some(v[..v.find('"')?].to_owned())
    };
    let mut rest = section;
    while let Some(i) = rest.find("<Payload ") {
        rest = &rest[i..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        if let Some(name) = attr(tag, "SourceName") {
            let payload_type = match attr(tag, "PayloadType").as_deref() {
                Some("Canonical") => DownloadPayloadType::Canonical,
                Some("PSFX") => DownloadPayloadType::Psfx,
                Some("Diff") => DownloadPayloadType::Diff,
                Some("ReverseDiff") => DownloadPayloadType::ReverseDiff,
                Some("Express") => DownloadPayloadType::Express,
                _ => DownloadPayloadType::Unknown(0),
            };
            out.push(DownloadItem {
                payload_type,
                source: name.clone(),
                target_file_name: name,
            });
        }
        rest = &rest[end..];
    }
    out
}

/// The Express source files (`ExpressSourceName`, the `.psf` data files) an ActionList's payloads name, in
/// order and without duplicates. They are not in the download list (the native agent reads ranges of
/// them over HTTP); they are members of the declared `.msu` containers.
pub fn express_sources_from_action_list(xml: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("ExpressSourceName=\"") {
        rest = &rest[i + "ExpressSourceName=\"".len()..];
        if let Some(q) = rest.find('"') {
            let v = rest[..q].to_owned();
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

fn keyform_to_identity(keyform: &str) -> String {
    let mut parts: Vec<&str> = keyform.split('~').collect();
    if parts.len() == 5 && parts[1].is_empty() {
        parts[1] = "31bf3856ad364e35";
    }
    parts.join("~")
}

/// Package identities a servicing CompDB declares, in the form DISM lists them.
///
/// `<CompDB BuildArch="amd64"><Packages><Package ID="Package_for_DotNetRollup_481" Version="10.0.9347.1">`
/// (OBSERVED in the `.NET` update's `DotNetServicingCompDB_KB5126052.xml`) names the CBS package
/// `Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1`. INFERRED: the architecture is the
/// CompDB's `BuildArch` and the language is neutral for these packages.
pub fn identities_from_compdb(xml: &str) -> Vec<String> {
    let arch = attr_value(xml, "<CompDB", "BuildArch").unwrap_or_default();
    let mut out = Vec::new();
    let mut rest = xml;
    // Only `Package` elements inside `Packages` that carry a `Version` are installable packages.
    while let Some(i) = rest.find("<Package ") {
        rest = &rest[i + "<Package".len()..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        let id = attr_in_tag(tag, "ID");
        let version = attr_in_tag(tag, "Version");
        if let (Some(id), Some(version)) = (id, version)
            && !arch.is_empty()
        {
            out.push(format!("{id}~31bf3856ad364e35~{arch}~~{version}"));
        }
        rest = &rest[end..];
    }
    out.sort();
    out.dedup();
    out
}

fn attr_in_tag<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let i = tag.find(&key)?;
    let v = &tag[i + key.len()..];
    // Reject a longer attribute name that merely ends with `name` (for example `FMID` for `ID`).
    if i > 0 && !tag.as_bytes()[i - 1].is_ascii_whitespace() {
        return None;
    }
    Some(&v[..v.find('"')?])
}

fn attr_value<'a>(xml: &'a str, element: &str, name: &str) -> Option<&'a str> {
    let i = xml.find(element)?;
    let rest = &xml[i + element.len()..];
    attr_in_tag(&rest[..rest.find('>')?], name)
}

/// The name a declared file has in the sandbox. The WSUS metadata names some files with the content hash
/// in front (`<40 hex digits>_FoD_Common.wim`) and the aggregated metadata cabinet as
/// `<hash>_<guid>_Wsus.AggregatedMetadata.cab`; the stack looks for `FoD_Common.wim` and for
/// `*.AggregatedMetadata.cab` (READ in `UpdateAgent.dll`: the pattern `*.AggregatedMetadata.cab`; the
/// native working directory held `<guid>.AggregatedMetadata.cab`, docs/fixtures/wsus-m0-osinstaller). So
/// the hash prefix is removed and `<guid>_Wsus.AggregatedMetadata.cab` becomes
/// `<guid>.AggregatedMetadata.cab`. Any other name is unchanged.
pub fn sandbox_file_name(declared: &str) -> String {
    let mut name = declared;
    if name.len() > 41
        && name.as_bytes()[40] == b'_'
        && name.as_bytes()[..40].iter().all(u8::is_ascii_hexdigit)
    {
        name = &name[41..];
    }
    const TAIL: &str = "_Wsus.AggregatedMetadata.cab";
    if name.len() > TAIL.len()
        && name.is_char_boundary(name.len() - TAIL.len())
        && name[name.len() - TAIL.len()..].eq_ignore_ascii_case(TAIL)
    {
        return format!(
            "{}.AggregatedMetadata.cab",
            &name[..name.len() - TAIL.len()]
        );
    }
    name.to_owned()
}

/// Files the stack needs that the sandbox does not hold (case-insensitive file-name comparison).
pub fn missing_from_sandbox(items: &[DownloadItem], declared: &[String]) -> Vec<String> {
    items
        .iter()
        .filter(|i| {
            let name = Path::new(&i.target_file_name)
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            !declared
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&name) || d.to_ascii_lowercase().ends_with(&name))
        })
        .map(|i| i.target_file_name.clone())
        .collect()
}

/// Scripted backend for host tests.
#[derive(Debug)]
pub struct FakeOsBackend {
    script: Mutex<Option<Result<OsInstallOutcome, BackendError>>>,
    pub requests: Mutex<Vec<OsInstallRequest>>,
    /// File names found in `stack_dir` at the time of each run (the directory is removed afterwards).
    pub stack_files: Mutex<Vec<Vec<String>>>,
    overridden: bool,
}

impl FakeOsBackend {
    pub fn new(outcome: Result<OsInstallOutcome, BackendError>) -> Self {
        Self {
            script: Mutex::new(Some(outcome)),
            requests: Mutex::new(Vec::new()),
            stack_files: Mutex::new(Vec::new()),
            overridden: false,
        }
    }

    /// Pretends an explicit stack directory is configured.
    pub fn with_stack_override(mut self) -> Self {
        self.overridden = true;
        self
    }

    /// Pretends the backend took these files out of a declared `.msu` container.
    pub fn with_provisioned(self, names: &[&str], container: &str) -> Self {
        if let Some(Ok(out)) = self.script.lock().unwrap().as_mut() {
            out.provisioned = names
                .iter()
                .map(|n| ProvisionedFile {
                    name: (*n).to_owned(),
                    container: container.to_owned(),
                    bytes: 1,
                })
                .collect();
        }
        self
    }

    /// A successful run that installs `identity` and needs a reboot.
    pub fn reboot(identity: &str, items: Vec<DownloadItem>) -> Self {
        Self::new(Ok(OsInstallOutcome {
            phases: vec![
                phase("create_action_list", 0),
                phase("download_list", 0),
                phase("install", 0),
            ],
            action_list: None,
            download_list: items,
            expected_identities: vec![identity.to_owned()],
            result: ServicingResult {
                backend: "fake_update_agent".into(),
                native_code: Some(0),
                class: ServicingClass::Reboot,
                description: "installed; a restart completes it".into(),
                timed_out: false,
                stdout_tail: None,
                stderr_tail: None,
                log_paths: Vec::new(),
            },
            provisioned: Vec::new(),
        }))
    }
}

fn phase(name: &str, hr: u32) -> OsPhase {
    OsPhase {
        name: name.into(),
        hresult: Some(hr),
        note: String::new(),
    }
}

impl OsInstallerBackend for FakeOsBackend {
    fn name(&self) -> &'static str {
        "fake_update_agent"
    }

    fn stack_overridden(&self) -> bool {
        self.overridden
    }

    fn run(&self, req: &OsInstallRequest) -> Result<OsInstallOutcome, BackendError> {
        self.requests.lock().unwrap().push(req.clone());
        let mut names: Vec<String> = req
            .stack_dir
            .as_ref()
            .and_then(|d| std::fs::read_dir(d).ok())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        self.stack_files.lock().unwrap().push(names);
        self.script
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| Err(BackendError::Command("fake backend used twice".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOTNET_ACTION_LIST: &str =
        include_str!("../../../../../docs/fixtures/wsus-m0-osinstaller/dotnet-ActionList.xml");
    const LCU_ACTION_LIST: &str =
        include_str!("../../../../../docs/fixtures/wsus-m0-osinstaller/lcu-ActionList.xml");

    #[test]
    fn identities_come_from_the_real_dotnet_action_list() {
        assert_eq!(
            identities_from_action_list(DOTNET_ACTION_LIST),
            vec!["Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1".to_owned()]
        );
    }

    #[test]
    fn downloads_come_from_the_real_dotnet_action_list() {
        let d = downloads_from_action_list(DOTNET_ACTION_LIST);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].payload_type, DownloadPayloadType::Canonical);
        assert_eq!(
            d[0].target_file_name,
            "Windows11.0-KB5126052-x64-NDP481.cab"
        );
        assert!(downloads_from_action_list("<ActionList/>").is_empty());
    }

    #[test]
    fn sandbox_names_drop_the_content_hash_prefix_and_rename_the_aggregated_metadata() {
        assert_eq!(
            sandbox_file_name("7491D52800C7D4DF7FEA3E873B935B6C1597BD4F_FoD_Common.wim"),
            "FoD_Common.wim"
        );
        assert_eq!(
            sandbox_file_name(
                "0134C1535266B5691BF9A133FBC1B5D294B5076B_881515ea-5c9a-47b8-9708-cbb0e65c3cb5_Wsus.AggregatedMetadata.cab"
            ),
            "881515ea-5c9a-47b8-9708-cbb0e65c3cb5.AggregatedMetadata.cab"
        );
        for plain in [
            "Windows11.0-KB5129195-x64.msu",
            "SSU-26100.9441-x64.psf",
            "DotNetServicingCompDB_KB5126052.xml.cab",
            "7491D52800C7D4DF7FEA3E873B935B6C1597BD4_FoD_Common.wim",
            "ü",
        ] {
            assert_eq!(sandbox_file_name(plain), plain);
        }
    }

    #[test]
    fn express_sources_come_from_the_real_lcu_action_list() {
        assert_eq!(
            express_sources_from_action_list(LCU_ACTION_LIST),
            vec![
                "Windows11.0-KB5043080-x64.psf".to_owned(),
                "Windows11.0-KB5129195-x64.psf".to_owned()
            ]
        );
    }

    #[test]
    fn identities_come_from_the_real_lcu_action_list() {
        let ids = identities_from_action_list(LCU_ACTION_LIST);
        assert!(ids.iter().all(|i| i.matches('~').count() == 4), "{ids:?}");
        assert!(
            ids.iter()
                .any(|i| i.starts_with("Package_for_RollupFix~31bf3856ad364e35~amd64~~"))
        );
    }

    const DOTNET_COMPDB: &str =
        include_str!("../../../../../docs/fixtures/wsus-m0-osinstaller/dotnet-CompDB.xml");

    #[test]
    fn identities_come_from_the_real_dotnet_compdb() {
        assert_eq!(
            identities_from_compdb(DOTNET_COMPDB),
            vec!["Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1".to_owned()]
        );
    }

    #[test]
    fn compdb_without_an_architecture_yields_no_identity() {
        assert!(
            identities_from_compdb(
                r#"<CompDB><Packages><Package ID="P" Version="1.0.0.0"/></Packages></CompDB>"#
            )
            .is_empty()
        );
    }

    #[test]
    fn payload_type_tags_follow_the_stack() {
        assert_eq!(
            DownloadPayloadType::from_tag(1),
            DownloadPayloadType::Canonical
        );
        assert_eq!(
            DownloadPayloadType::from_tag(5),
            DownloadPayloadType::Express
        );
        assert_eq!(
            DownloadPayloadType::from_tag(9),
            DownloadPayloadType::Unknown(9)
        );
    }

    #[test]
    fn missing_files_are_reported_by_name() {
        let items = vec![
            DownloadItem {
                payload_type: DownloadPayloadType::Canonical,
                source: "x".into(),
                target_file_name: "a.cab".into(),
            },
            DownloadItem {
                payload_type: DownloadPayloadType::Express,
                source: "y".into(),
                target_file_name: "B.psf".into(),
            },
        ];
        assert_eq!(
            missing_from_sandbox(&items, &["A.CAB".into()]),
            vec!["B.psf".to_owned()]
        );
    }

    #[test]
    fn mode_names_round_trip() {
        for m in [OsInstallerMode::UpdateAgent, OsInstallerMode::Dism] {
            assert_eq!(OsInstallerMode::parse(m.name()), Some(m));
        }
        assert_eq!(OsInstallerMode::parse("other"), None);
        assert_eq!(OsInstallerMode::default(), OsInstallerMode::UpdateAgent);
    }
}
