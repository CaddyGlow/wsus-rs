//! The DISM subprocess backend (the in-process DISM API backend is in `dism_api`).
//!
//! Commands (READ: `docs/wsus-cbs-integration.md` 5.4; the online forms are INFERRED, nothing here
//! ran online until the guest validation recorded in `docs/wsus-install.md`):
//!
//! * list: `dism.exe /English /Online /Get-Packages /Format:List`, parsed by
//!   `windows_dism::parse_package_inventory`;
//! * applicability: `dism.exe /English /Online /Get-PackageInfo /PackagePath:<cab> /Format:List`,
//!   parsed by `windows_dism::parse_package_applicability`;
//! * add: `dism.exe /English /Online /Add-Package /PackagePath:<cab> /NoRestart /LogPath:<file>`;
//! * remove: `dism.exe /English /Online /Remove-Package /PackageName:<identity> /NoRestart /LogPath:<file>`
//!   (OBSERVED natively for the `.NET` rollup, spike 18.4; through this backend, see `docs/wsus-validation.md`).
//!
//! The process runs through the shared [`Runner`] seam with `kill_on_timeout: false`: DISM is never
//! killed mid-transaction (owner decision Q-E, working). Output is decoded with
//! `windows_dism::observation::decode_dism_text` (UTF-8 or UTF-16).
use super::{
    BackendError, PackageEntry, PackageSnapshot, PendingIndicators, ServicingBackend,
    ServicingClass, ServicingResult, pending,
};
use crate::install::runner::{RunRequest, RunResult, Runner};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use windows_dism::{PackageState, observation::decode_dism_text};

/// Classifies a DISM or `wusa` exit code. READ: 0, 3010 and 0x800f081e are the codes
/// `windows_dism::classify_exit` knows (observed in the offline trials). Every other row is INFERRED
/// from general knowledge of the servicing stack and is labelled so in its description.
pub fn describe_exit(code: u32) -> (ServicingClass, String) {
    use ServicingClass::*;
    let (class, text): (ServicingClass, &str) = match code {
        0 => (Success, "completed successfully"),
        3010 => (
            Reboot,
            "completed, a restart is required (ERROR_SUCCESS_REBOOT_REQUIRED)",
        ),
        0x8007_0BC2 => (
            Reboot,
            "restart required (ERROR_SUCCESS_REBOOT_REQUIRED as HRESULT) [INFERRED]",
        ),
        0x0024_0006 => (
            Success,
            "update already installed (WU_S_ALREADY_INSTALLED) [INFERRED]",
        ),
        0x800F_081E => (
            NotApplicable,
            "not applicable to this system (CBS_E_NOT_APPLICABLE)",
        ),
        0x8024_0017 => (
            NotApplicable,
            "not applicable (WU_E_NOT_APPLICABLE) [INFERRED]",
        ),
        0x800F_0825 => (
            Permanent,
            "the package is permanent and cannot be uninstalled (OBSERVED: dism.log `Permanent package cannot be uninstalled`)",
        ),
        0x800F_0830 => (
            Busy,
            "image unserviceable: a pending operation, restart first (CBS_E_IMAGE_UNSERVICEABLE) [INFERRED]",
        ),
        0x800F_0831 => (
            Failed,
            "a prerequisite package or its source is missing (CBS_E_NO_SOURCE) [INFERRED]",
        ),
        0x800F_0823 => (
            Failed,
            "a newer servicing stack is required (CBS_E_NEW_SERVICING_STACK_REQUIRED) [INFERRED]",
        ),
        0x800F_0922 => (
            Failed,
            "installers failed (CBS_E_INSTALLERS_FAILED) [INFERRED]",
        ),
        0x8007_3712 => (
            Failed,
            "the component store is corrupt (ERROR_SXS_COMPONENT_STORE_CORRUPT) [INFERRED]",
        ),
        0x8007_0005 => (Failed, "access denied: not elevated [INFERRED]"),
        0x8007_0057 | 87 => (Failed, "invalid parameter [INFERRED]"),
        0x8007_0002 | 2 => (Failed, "file not found [INFERRED]"),
        0x8007_05B4 | 1460 => (Failed, "operation timed out [INFERRED]"),
        _ => (Failed, "failure, code not in the known table"),
    };
    (class, format!("{code:#010x}: {text}"))
}

fn state_text(s: &PackageState) -> String {
    match s {
        PackageState::Installed => "Installed".into(),
        PackageState::InstallPending => "Install Pending".into(),
        PackageState::UninstallPending => "Uninstall Pending".into(),
        PackageState::Staged => "Staged".into(),
        PackageState::Superseded => "Superseded".into(),
        PackageState::Removed => "Removed".into(),
        PackageState::Unknown(o) => o.clone(),
    }
}

/// What `/Get-PackageInfo /PackagePath:` says about one package file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub identity: String,
    /// `Applicable : Yes|No`.
    pub applicable: bool,
    /// The package's own `State` (`Not Present`, `Installed`, ...): the first `State` line, before the
    /// feature listing, which has `State` lines of its own.
    pub state: String,
    /// `Restart Required : ...` as printed (`Required`, `Possible`, ...), when present.
    pub restart_required: Option<String>,
}

/// Parses the English output of `dism.exe /Online /Get-PackageInfo /PackagePath:<file>`.
///
/// READ/OBSERVED: the real online output (docs/fixtures/wsus-m0-cbs/
/// dism-online-get-packageinfo-ie-optional.txt) continues after the package block with
/// `Custom Properties:` and `Features listing for package`, which carry further `State` lines, so
/// `windows_dism::parse_package_applicability` (written for offline output) rejects it as ambiguous.
/// Only the block before those sections is read here, and every key must occur exactly once.
pub fn parse_package_info(text: &str) -> Result<PackageInfo, BackendError> {
    let mut identity = Vec::new();
    let mut applicable = Vec::new();
    let mut state = Vec::new();
    let mut restart = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.starts_with("Custom Properties") || line.starts_with("Features listing") {
            break;
        }
        if let Some((k, v)) = line.split_once(" : ").or_else(|| line.split_once(':')) {
            let v = v.trim().to_owned();
            match k.trim() {
                "Package Identity" => identity.push(v),
                "Applicable" => applicable.push(v),
                "State" => state.push(v),
                "Restart Required" => restart.push(v),
                _ => {}
            }
        }
    }
    let one = |name: &str, v: &[String]| match v {
        [x] if !x.is_empty() => Ok(x.clone()),
        _ => Err(BackendError::Parse(format!(
            "DISM package info has a missing or repeated `{name}`"
        ))),
    };
    let identity = one("Package Identity", &identity)?;
    let applicable = match one("Applicable", &applicable)?.as_str() {
        "Yes" => true,
        "No" => false,
        other => {
            return Err(BackendError::Parse(format!(
                "DISM `Applicable` is `{other}`, not Yes or No"
            )));
        }
    };
    Ok(PackageInfo {
        identity,
        applicable,
        state: one("State", &state)?,
        restart_required: restart.into_iter().next(),
    })
}

fn tail(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text =
        decode_dism_text(bytes).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned());
    Some(text.chars().take(4096).collect())
}

/// Runs `dism.exe` from the system directory.
pub struct DismBackend {
    pub(crate) runner: Arc<dyn Runner + Send + Sync>,
    pub(crate) system_dir: PathBuf,
    pub(crate) query_timeout: Duration,
}

impl std::fmt::Debug for DismBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DismBackend")
            .field("system_dir", &self.system_dir)
            .finish_non_exhaustive()
    }
}

impl DismBackend {
    /// `system_dir` is the Windows system directory (the one holding `dism.exe`).
    pub fn new(runner: Arc<dyn Runner + Send + Sync>, system_dir: impl Into<PathBuf>) -> Self {
        Self {
            runner,
            system_dir: system_dir.into(),
            query_timeout: Duration::from_secs(15 * 60),
        }
    }

    pub fn program(&self) -> PathBuf {
        self.system_dir.join("dism.exe")
    }

    pub(crate) fn run_dism(
        &self,
        args: Vec<String>,
        timeout: Duration,
    ) -> Result<RunResult, BackendError> {
        self.runner
            .run(&RunRequest {
                program: self.program(),
                args,
                cwd: self.system_dir.clone(),
                timeout,
                output_limit: 4 * 1024 * 1024,
                kill_on_timeout: false,
            })
            .map_err(|e| BackendError::Command(e.to_string()))
    }

    fn query(&self, args: Vec<String>) -> Result<(u32, String), BackendError> {
        let r = self.run_dism(args, self.query_timeout)?;
        if r.timed_out {
            return Err(BackendError::Command(
                "the DISM query timed out (the process was left running)".into(),
            ));
        }
        let code = r
            .exit_code
            .ok_or_else(|| BackendError::Command("DISM returned no exit code".into()))?
            as u32;
        let text = decode_dism_text(&r.stdout).map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok((code, text))
    }
}

impl ServicingBackend for DismBackend {
    fn name(&self) -> &'static str {
        "dism"
    }

    fn list_packages(&self) -> Result<PackageSnapshot, BackendError> {
        let (code, text) = self.query(
            ["/English", "/Online", "/Get-Packages", "/Format:List"]
                .map(String::from)
                .to_vec(),
        )?;
        if code != 0 {
            return Err(BackendError::Command(format!(
                "dism /Get-Packages exited {code:#010x}"
            )));
        }
        let records = windows_dism::parse_package_inventory(&text)
            .map_err(|e| BackendError::Parse(e.to_string()))?;
        Ok(PackageSnapshot {
            packages: records
                .iter()
                .map(|r| PackageEntry {
                    identity: r.identity.clone(),
                    state: state_text(&r.state),
                })
                .collect(),
        })
    }

    fn payload_applicability(&self, payload: &Path) -> Result<Option<bool>, BackendError> {
        let (code, text) = self.query(vec![
            "/English".into(),
            "/Online".into(),
            "/Get-PackageInfo".into(),
            format!("/PackagePath:{}", payload.display()),
            "/Format:List".into(),
        ])?;
        match code {
            0 => parse_package_info(&text).map(|i| Some(i.applicable)),
            0x800F_081E => Ok(Some(false)),
            other => Err(BackendError::Command(format!(
                "dism /Get-PackageInfo exited {other:#010x}"
            ))),
        }
    }

    fn pending_indicators(&self) -> Result<PendingIndicators, BackendError> {
        Ok(pending::probe())
    }

    fn free_disk_bytes(&self) -> Result<Option<u64>, BackendError> {
        pending::free_disk_bytes().map_err(BackendError::Command)
    }

    fn add_package(
        &self,
        payload: &Path,
        log_dir: &Path,
        timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        let log = log_dir.join("dism-add-package.log");
        let r = self.run_dism(
            vec![
                "/English".into(),
                "/Online".into(),
                "/Add-Package".into(),
                format!("/PackagePath:{}", payload.display()),
                "/NoRestart".into(),
                format!("/LogPath:{}", log.display()),
            ],
            timeout,
        )?;
        Ok(self.result_of(r, &log, "the install"))
    }

    fn supports_remove_package(&self) -> bool {
        true
    }

    fn remove_package(
        &self,
        identity: &str,
        log_dir: &Path,
        timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        if !super::is_valid_package_identity(identity) {
            return Err(BackendError::Command(format!(
                "`{identity}` is not a package identity (name~token~architecture~language~version)"
            )));
        }
        let log = log_dir.join("dism-remove-package.log");
        let r = self.run_dism(
            vec![
                "/English".into(),
                "/Online".into(),
                "/Remove-Package".into(),
                format!("/PackageName:{identity}"),
                "/NoRestart".into(),
                format!("/LogPath:{}", log.display()),
            ],
            timeout,
        )?;
        Ok(self.result_of(r, &log, "the removal"))
    }
}

impl DismBackend {
    fn result_of(&self, r: RunResult, log: &Path, what: &str) -> ServicingResult {
        let (code, class, description) = match (r.exit_code, r.timed_out) {
            (_, true) | (None, _) => (
                None,
                ServicingClass::Failed,
                format!("timed out: DISM was left running, {what} is judged by fresh state later"),
            ),
            (Some(c), false) => {
                let (class, d) = describe_exit(c as u32);
                (Some(c as u32), class, d)
            }
        };
        ServicingResult {
            backend: "dism".into(),
            native_code: code,
            class,
            description,
            timed_out: r.timed_out,
            stdout_tail: tail(&r.stdout),
            stderr_tail: tail(&r.stderr),
            log_paths: vec![log.display().to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::runner::{FakeRunner, RunResult};

    const LIST: &str = "\nDeployment Image Servicing and Management tool\nVersion: 10.0.26100.1150\n\nImage Version: 10.0.26200.8037\n\nPackages listing:\n\nPackage Identity : Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1.1.0\nState : Installed\nRelease Type : Security Update\nInstall Time : 2/1/2026 10:00 AM\n\nPackage Identity : Package_for_X~31bf3856ad364e35~amd64~~1.0.0.0\nState : Install Pending\nRelease Type : Update\nInstall Time : 2/2/2026 10:00 AM\n\nThe operation completed successfully.\n";

    fn backend(reply: impl Fn(&RunRequest) -> RunResult + Send + Sync + 'static) -> DismBackend {
        DismBackend::new(
            Arc::new(FakeRunner::new(move |r| Ok(reply(r)))),
            "C:\\Windows\\System32",
        )
    }

    fn out(code: i32, text: &str) -> RunResult {
        RunResult {
            exit_code: Some(code),
            stdout: text.as_bytes().to_vec(),
            ..RunResult::default()
        }
    }

    #[test]
    fn get_packages_output_is_parsed_into_entries() {
        let b = backend(|_| out(0, LIST));
        let snap = b.list_packages().unwrap();
        assert_eq!(snap.packages.len(), 2);
        assert_eq!(snap.packages[0].state, "Installed");
        assert_eq!(snap.packages[1].state, "Install Pending");
        assert!(
            snap.find("package_for_rollupfix~31bf3856ad364e35~amd64~~26100.1.1.0")[0]
                .is_installed()
        );
    }

    /// Real output of `dism.exe /English /Online /Get-Packages /Format:List` on the lab guest
    /// (Windows 11 25H2, 10.0.26200.8037, DISM 10.0.26100.5074), exit code 0.
    const REAL_ONLINE: &str =
        include_str!("../../../../../docs/fixtures/wsus-m0-cbs/dism-online-get-packages.txt");

    #[test]
    fn the_real_online_listing_parses_with_staged_and_installed_states() {
        let b = backend(|_| out(0, REAL_ONLINE));
        let snap = b.list_packages().unwrap();
        assert_eq!(snap.packages.len(), 142);
        assert!(snap.packages.iter().any(|p| p.state == "Staged"));
        assert!(snap.packages.iter().any(|p| p.state == "Installed"));
        let one = snap.find(
            "Microsoft-OneCore-ApplicationModel-Sync-Desktop-FOD-Package~31bf3856ad364e35~amd64~~10.0.26100.8036",
        );
        assert_eq!(one.len(), 1);
        assert!(one[0].is_installed());
    }

    /// Real output of `dism.exe /English /Online /Get-PackageInfo /PackagePath:<cab>` for the
    /// Internet Explorer mode optional package taken from the Windows 11 25H2 media (guest above).
    const REAL_PACKAGE_INFO: &str = include_str!(
        "../../../../../docs/fixtures/wsus-m0-cbs/dism-online-get-packageinfo-ie-optional.txt"
    );

    #[test]
    fn the_real_get_packageinfo_output_with_a_feature_listing_parses() {
        let info = parse_package_info(REAL_PACKAGE_INFO).unwrap();
        assert!(info.applicable);
        assert_eq!(info.state, "Not Present");
        assert_eq!(info.restart_required.as_deref(), Some("Required"));
        assert_eq!(
            info.identity,
            "Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~~11.0.26100.1"
        );
        // the offline parser of windows-dism cannot read this output (OBSERVED on the guest)
        assert!(windows_dism::parse_package_applicability(REAL_PACKAGE_INFO).is_err());
        let b = backend(|_| out(0, REAL_PACKAGE_INFO));
        assert_eq!(
            b.payload_applicability(Path::new("C:\\x.cab")).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn package_info_without_applicable_or_with_repeats_is_rejected() {
        assert!(parse_package_info("Package Identity : x\nState : Installed\n").is_err());
        assert!(
            parse_package_info("Package Identity : x\nApplicable : Maybe\nState : Installed\n")
                .is_err()
        );
        assert!(
            parse_package_info("Package Identity : x\nApplicable : Yes\nState : A\nState : B\n")
                .is_err()
        );
    }

    #[test]
    fn utf16_output_is_decoded() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in LIST.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let b = backend(move |_| RunResult {
            exit_code: Some(0),
            stdout: bytes.clone(),
            ..RunResult::default()
        });
        assert_eq!(b.list_packages().unwrap().packages.len(), 2);
    }

    #[test]
    fn a_failing_listing_is_an_error_not_an_empty_list() {
        let b = backend(|_| out(0x800f0831u32 as i32, ""));
        assert!(matches!(b.list_packages(), Err(BackendError::Command(_))));
    }

    #[test]
    fn add_package_builds_the_command_and_never_kills() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        let b = backend(move |r| {
            s2.lock().unwrap().push(r.clone());
            out(3010, "")
        });
        let res = b
            .add_package(
                Path::new("C:\\store\\update.cab"),
                Path::new("C:\\jobs\\j1"),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(res.class, ServicingClass::Reboot);
        assert_eq!(res.native_code, Some(3010));
        let calls = seen.lock().unwrap();
        let r = &calls[0];
        assert!(r.program.ends_with("dism.exe"));
        assert!(!r.kill_on_timeout);
        assert_eq!(
            &r.args[..4],
            [
                "/English",
                "/Online",
                "/Add-Package",
                "/PackagePath:C:\\store\\update.cab"
            ]
        );
        assert!(r.args.contains(&"/NoRestart".to_string()));
        assert!(r.args.iter().any(|a| a.starts_with("/LogPath:")));
    }

    #[test]
    fn a_timeout_is_reported_without_a_code() {
        let b = backend(|_| RunResult {
            timed_out: true,
            ..RunResult::default()
        });
        let res = b
            .add_package(Path::new("x.cab"), Path::new("."), Duration::from_secs(1))
            .unwrap();
        assert!(res.timed_out);
        assert_eq!(res.native_code, None);
    }

    #[test]
    fn remove_package_builds_the_command_and_never_kills() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        let b = backend(move |r| {
            s2.lock().unwrap().push(r.clone());
            out(3010, "")
        });
        assert!(b.supports_remove_package());
        let id = "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1";
        let res = b
            .remove_package(id, Path::new("C:\\jobs\\j1"), Duration::from_secs(60))
            .unwrap();
        assert_eq!(res.class, ServicingClass::Reboot);
        assert_eq!(res.native_code, Some(3010));
        let calls = seen.lock().unwrap();
        let r = &calls[0];
        assert!(r.program.ends_with("dism.exe"));
        assert!(!r.kill_on_timeout);
        assert_eq!(&r.args[..3], ["/English", "/Online", "/Remove-Package"]);
        assert_eq!(r.args[3], format!("/PackageName:{id}"));
        assert!(r.args.contains(&"/NoRestart".to_string()));
        assert!(r.args.iter().any(|a| a.starts_with("/LogPath:")));
    }

    #[test]
    fn remove_package_refuses_anything_that_is_not_a_package_identity() {
        let b = backend(|_| panic!("no process may start"));
        for bad in [
            "",
            "Package_for_X",
            "a~b~c~d~e /Online",
            "a~b~c~d~e\"/x",
            "..\\x~b~c~d~e",
            "a~b~c~d~",
        ] {
            assert!(
                b.remove_package(bad, Path::new("."), Duration::from_secs(1))
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_removal_that_times_out_has_no_code_and_is_not_killed() {
        let b = backend(|_| RunResult {
            timed_out: true,
            ..RunResult::default()
        });
        let res = b
            .remove_package("a~b~c~d~e", Path::new("."), Duration::from_secs(1))
            .unwrap();
        assert!(res.timed_out);
        assert_eq!(res.native_code, None);
        assert!(res.description.contains("the removal"));
    }

    #[test]
    fn a_permanent_package_is_a_classified_refusal() {
        let b = backend(|_| out(0x800f0825u32 as i32, ""));
        let res = b
            .remove_package(
                "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0",
                Path::new("."),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(res.class, ServicingClass::Permanent);
        assert_eq!(res.native_code, Some(0x800f0825));
        assert!(!res.description.contains("[INFERRED]"));
    }

    #[test]
    fn exit_codes_are_classified() {
        assert_eq!(describe_exit(0x800f0825).0, ServicingClass::Permanent);
        assert_eq!(describe_exit(0).0, ServicingClass::Success);
        assert_eq!(describe_exit(3010).0, ServicingClass::Reboot);
        assert_eq!(describe_exit(0x800f081e).0, ServicingClass::NotApplicable);
        assert_eq!(describe_exit(0x800f0830).0, ServicingClass::Busy);
        assert_eq!(describe_exit(0x1234).0, ServicingClass::Failed);
        assert!(describe_exit(0x800f0831).1.contains("[INFERRED]"));
        assert!(!describe_exit(0x800f081e).1.contains("[INFERRED]"));
    }
}
