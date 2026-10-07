//! The `wusa.exe` backend for `.msu` payloads.
//!
//! `wusa.exe <file>.msu /quiet /norestart` installs one standalone update package. Observation
//! (package listing, applicability, pending indicators, disk space) is delegated to a
//! [`DismBackend`] because `wusa` has no listing of its own. Exit codes: 0 and 3010 as for DISM.
//! OBSERVED on a Windows 11 25H2 guest (docs/wsus-install.md, "Guest run, wusa backend"): the real
//! monthly cumulative update `.msu` (KB5129195, 4.6 GB, with its servicing stack update inside) run by
//! this backend through the executor exited 3010 after 11.7 minutes (Setup event 2 and 4 carry the
//! exact command line); a `.msu` for an older build, run by hand earlier, exited `0x80240017`
//! (`WU_E_NOT_APPLICABLE`); `wusa /uninstall` with a bad `/kb` exited 87. The `0x240006`
//! (`WU_S_ALREADY_INSTALLED`) mapping is still INFERRED: no run produced it. `wusa` itself offers no
//! package-level result beyond the exit code, so the listing and the evaluator stay the judges.
use super::{
    BackendError, PackageSnapshot, PendingIndicators, ServicingBackend, ServicingClass,
    ServicingResult,
    dism::{DismBackend, describe_exit},
};
use crate::install::runner::{RunRequest, Runner};
use std::{path::Path, sync::Arc, time::Duration};

pub struct WusaBackend {
    dism: DismBackend,
    runner: Arc<dyn Runner + Send + Sync>,
}

impl std::fmt::Debug for WusaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WusaBackend").finish_non_exhaustive()
    }
}

impl WusaBackend {
    pub fn new(
        runner: Arc<dyn Runner + Send + Sync>,
        system_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            dism: DismBackend::new(Arc::clone(&runner), system_dir),
            runner,
        }
    }
}

impl ServicingBackend for WusaBackend {
    fn name(&self) -> &'static str {
        "wusa"
    }

    fn payload_extensions(&self) -> &'static [&'static str] {
        &["msu"]
    }

    fn list_packages(&self) -> Result<PackageSnapshot, BackendError> {
        self.dism.list_packages()
    }

    fn payload_applicability(&self, _payload: &Path) -> Result<Option<bool>, BackendError> {
        // DISM cannot query an .msu directly: only the evaluator decides.
        Ok(None)
    }

    fn pending_indicators(&self) -> Result<PendingIndicators, BackendError> {
        self.dism.pending_indicators()
    }

    fn free_disk_bytes(&self) -> Result<Option<u64>, BackendError> {
        self.dism.free_disk_bytes()
    }

    fn add_package(
        &self,
        payload: &Path,
        _log_dir: &Path,
        timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        let r = self
            .runner
            .run(&RunRequest {
                program: self.dism.system_dir.join("wusa.exe"),
                args: vec![
                    payload.display().to_string(),
                    "/quiet".into(),
                    "/norestart".into(),
                ],
                cwd: self.dism.system_dir.clone(),
                timeout,
                output_limit: 64 * 1024,
                kill_on_timeout: false,
            })
            .map_err(|e| BackendError::Command(e.to_string()))?;
        let (code, class, description) = match (r.exit_code, r.timed_out) {
            (_, true) | (None, _) => (
                None,
                ServicingClass::Failed,
                "timed out: wusa was left running, the install is judged by fresh state later"
                    .to_owned(),
            ),
            (Some(c), false) => {
                let (class, d) = describe_exit(c as u32);
                (Some(c as u32), class, d)
            }
        };
        Ok(ServicingResult {
            backend: "wusa".into(),
            native_code: code,
            class,
            description,
            timed_out: r.timed_out,
            stdout_tail: None,
            stderr_tail: None,
            log_paths: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::runner::{FakeRunner, RunResult};

    #[test]
    fn wusa_runs_quiet_without_restart_and_maps_codes() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        let b = WusaBackend::new(
            Arc::new(FakeRunner::new(move |r| {
                s2.lock().unwrap().push(r.clone());
                Ok(RunResult {
                    exit_code: Some(3010),
                    ..RunResult::default()
                })
            })),
            "C:\\Windows\\System32",
        );
        let r = b
            .add_package(
                Path::new("C:\\s\\u.msu"),
                Path::new("."),
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(r.class, ServicingClass::Reboot);
        let calls = seen.lock().unwrap();
        assert!(calls[0].program.ends_with("wusa.exe"));
        assert_eq!(calls[0].args, ["C:\\s\\u.msu", "/quiet", "/norestart"]);
        assert!(!calls[0].kill_on_timeout);
        assert_eq!(b.payload_extensions(), ["msu"]);
    }

    fn add_with_exit(code: Option<i32>, timed_out: bool) -> ServicingResult {
        let b = WusaBackend::new(
            Arc::new(FakeRunner::new(move |_| {
                Ok(RunResult {
                    exit_code: code,
                    timed_out,
                    ..RunResult::default()
                })
            })),
            "C:\\Windows\\System32",
        );
        b.add_package(
            Path::new("C:\\s\\u.msu"),
            Path::new("."),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    #[test]
    fn wusa_exit_codes_map_to_the_servicing_classes() {
        let ok = add_with_exit(Some(0), false);
        assert_eq!(ok.class, ServicingClass::Success);
        assert_eq!(ok.native_code, Some(0));
        // OBSERVED by hand on a real older `.msu`: the HRESULT is the exit code, as a negative i32.
        let na = add_with_exit(Some(0x8024_0017_u32 as i32), false);
        assert_eq!(na.class, ServicingClass::NotApplicable);
        assert_eq!(na.native_code, Some(0x8024_0017));
        assert_eq!(
            add_with_exit(Some(0x0024_0006), false).class,
            ServicingClass::Success
        );
        // OBSERVED: `wusa /uninstall /kb:...` answered 87; it is not a success whatever the text says.
        let bad = add_with_exit(Some(87), false);
        assert_eq!(bad.class, ServicingClass::Failed);
        assert_eq!(bad.native_code, Some(87));
    }

    #[test]
    fn a_wusa_timeout_has_no_code_and_is_not_a_success() {
        let t = add_with_exit(None, true);
        assert!(t.timed_out);
        assert_eq!(t.native_code, None);
        assert_eq!(t.class, ServicingClass::Failed);
    }
}
