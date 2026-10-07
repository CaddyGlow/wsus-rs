//! Scripted [`ServicingBackend`] for host tests.
use super::{
    BackendError, PackageEntry, PackageSnapshot, PendingIndicators, ServicingBackend,
    ServicingClass, ServicingResult,
};
use std::{collections::VecDeque, path::Path, sync::Mutex, time::Duration};

/// What the next `add_package` call does.
#[derive(Debug, Clone)]
pub struct AddScript {
    pub result: ServicingResult,
    /// Packages inserted or updated (by identity) when the call returns.
    pub upsert: Vec<PackageEntry>,
    /// Pending indicators after the call.
    pub pending_after: Option<PendingIndicators>,
}

impl AddScript {
    /// A successful install that leaves `identity` Installed.
    pub fn installed(identity: &str) -> Self {
        Self {
            result: result(Some(0), ServicingClass::Success, "success"),
            upsert: vec![PackageEntry {
                identity: identity.to_owned(),
                state: "Installed".to_owned(),
            }],
            pending_after: None,
        }
    }

    /// An install that needs a reboot: the package is `Install Pending` and an indicator is set.
    pub fn reboot(identity: &str) -> Self {
        Self {
            result: result(Some(3010), ServicingClass::Reboot, "reboot required"),
            upsert: vec![PackageEntry {
                identity: identity.to_owned(),
                state: "Install Pending".to_owned(),
            }],
            pending_after: Some(PendingIndicators {
                set: vec!["CBS RebootPending".to_owned()],
                unavailable: Vec::new(),
            }),
        }
    }

    /// A failure with `code` and no state change.
    pub fn failed(code: u32) -> Self {
        Self {
            result: result(Some(code), ServicingClass::Failed, "failed"),
            upsert: Vec::new(),
            pending_after: None,
        }
    }

    /// A call that hits the timeout and leaves the process running (no code).
    pub fn timeout() -> Self {
        let mut r = result(
            None,
            ServicingClass::Failed,
            "timed out, process left running",
        );
        r.timed_out = true;
        Self {
            result: r,
            upsert: Vec::new(),
            pending_after: None,
        }
    }
}

/// What the next `remove_package` call does.
#[derive(Debug, Clone)]
pub struct RemoveScript {
    pub result: ServicingResult,
    /// Packages whose state changes (by identity) when the call returns.
    pub upsert: Vec<PackageEntry>,
    /// Identities that disappear from the listing when the call returns.
    pub remove: Vec<String>,
    /// Pending indicators after the call.
    pub pending_after: Option<PendingIndicators>,
}

impl RemoveScript {
    /// A removal that completes at once: `identity` is gone from the listing.
    pub fn removed(identity: &str) -> Self {
        Self {
            result: result(Some(0), ServicingClass::Success, "success"),
            upsert: Vec::new(),
            remove: vec![identity.to_owned()],
            pending_after: None,
        }
    }

    /// DISM's observed behaviour for a removable package: exit 3010, the package `Uninstall Pending`,
    /// a restart indicator set.
    pub fn reboot(identity: &str) -> Self {
        Self {
            result: result(Some(3010), ServicingClass::Reboot, "reboot required"),
            upsert: vec![PackageEntry {
                identity: identity.to_owned(),
                state: "Uninstall Pending".to_owned(),
            }],
            remove: Vec::new(),
            pending_after: Some(PendingIndicators {
                set: vec!["CBS RebootPending".to_owned()],
                unavailable: Vec::new(),
            }),
        }
    }

    /// Also changes the state of another package in the same call.
    pub fn with_upsert(mut self, e: PackageEntry) -> Self {
        self.upsert.push(e);
        self
    }

    /// The stack's refusal of a permanent package (`0x800f0825`), no state change.
    pub fn permanent() -> Self {
        Self {
            result: result(
                Some(0x800f_0825),
                ServicingClass::Permanent,
                "permanent package",
            ),
            upsert: Vec::new(),
            remove: Vec::new(),
            pending_after: None,
        }
    }

    /// A failure with `code` and no state change.
    pub fn failed(code: u32) -> Self {
        Self {
            result: result(Some(code), ServicingClass::Failed, "failed"),
            upsert: Vec::new(),
            remove: Vec::new(),
            pending_after: None,
        }
    }

    /// A call that hits the timeout and leaves the process running (no code).
    pub fn timeout() -> Self {
        let mut r = result(
            None,
            ServicingClass::Failed,
            "timed out, process left running",
        );
        r.timed_out = true;
        Self {
            result: r,
            upsert: Vec::new(),
            remove: Vec::new(),
            pending_after: None,
        }
    }
}

fn result(code: Option<u32>, class: ServicingClass, text: &str) -> ServicingResult {
    ServicingResult {
        backend: "fake".into(),
        native_code: code,
        class,
        description: text.into(),
        timed_out: false,
        stdout_tail: None,
        stderr_tail: None,
        log_paths: Vec::new(),
    }
}

#[derive(Debug)]
struct State {
    packages: Vec<PackageEntry>,
    pending: PendingIndicators,
    free: Option<u64>,
    applicability: Option<bool>,
    extensions: &'static [&'static str],
    adds: VecDeque<AddScript>,
    removes: VecDeque<RemoveScript>,
    supports_remove: bool,
    calls: Vec<String>,
    list_error: Option<BackendError>,
}

/// Records every call; installs what the script says.
#[derive(Debug)]
pub struct FakeBackend {
    state: Mutex<State>,
}

impl FakeBackend {
    pub fn new(packages: Vec<PackageEntry>) -> Self {
        Self {
            state: Mutex::new(State {
                packages,
                pending: PendingIndicators::default(),
                free: Some(50 * 1024 * 1024 * 1024),
                applicability: None,
                extensions: &["cab"],
                adds: VecDeque::new(),
                removes: VecDeque::new(),
                supports_remove: true,
                calls: Vec::new(),
                list_error: None,
            }),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().expect("fake backend lock"))
    }

    pub fn pending(self, p: PendingIndicators) -> Self {
        self.with(|s| s.pending = p);
        self
    }

    pub fn free_disk(self, bytes: Option<u64>) -> Self {
        self.with(|s| s.free = bytes);
        self
    }

    pub fn applicability(self, a: Option<bool>) -> Self {
        self.with(|s| s.applicability = a);
        self
    }

    pub fn extensions(self, e: &'static [&'static str]) -> Self {
        self.with(|s| s.extensions = e);
        self
    }

    pub fn list_fails(self, e: BackendError) -> Self {
        self.with(|s| s.list_error = Some(e));
        self
    }

    pub fn script(self, a: AddScript) -> Self {
        self.with(|s| s.adds.push_back(a));
        self
    }

    pub fn script_remove(self, r: RemoveScript) -> Self {
        self.with(|s| s.removes.push_back(r));
        self
    }

    /// Makes the fake a backend that does not implement removal (the trait's default).
    pub fn without_remove(self) -> Self {
        self.with(|s| s.supports_remove = false);
        self
    }

    /// `list`, `applicability <file>`, `pending`, `free`, `add <file>`, `remove <identity>` in call order.
    pub fn calls(&self) -> Vec<String> {
        self.with(|s| s.calls.clone())
    }
}

impl ServicingBackend for FakeBackend {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn payload_extensions(&self) -> &'static [&'static str] {
        self.with(|s| s.extensions)
    }

    fn list_packages(&self) -> Result<PackageSnapshot, BackendError> {
        self.with(|s| {
            s.calls.push("list".into());
            if let Some(e) = &s.list_error {
                return Err(e.clone());
            }
            Ok(PackageSnapshot {
                packages: s.packages.clone(),
            })
        })
    }

    fn payload_applicability(&self, payload: &Path) -> Result<Option<bool>, BackendError> {
        self.with(|s| {
            s.calls.push(format!(
                "applicability {}",
                payload.file_name().unwrap_or_default().to_string_lossy()
            ));
            Ok(s.applicability)
        })
    }

    fn pending_indicators(&self) -> Result<PendingIndicators, BackendError> {
        self.with(|s| {
            s.calls.push("pending".into());
            Ok(s.pending.clone())
        })
    }

    fn free_disk_bytes(&self) -> Result<Option<u64>, BackendError> {
        self.with(|s| {
            s.calls.push("free".into());
            Ok(s.free)
        })
    }

    fn add_package(
        &self,
        payload: &Path,
        _log_dir: &Path,
        _timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        self.with(|s| {
            s.calls.push(format!(
                "add {}",
                payload.file_name().unwrap_or_default().to_string_lossy()
            ));
            let script = s
                .adds
                .pop_front()
                .ok_or_else(|| BackendError::Command("no scripted add_package result".into()))?;
            for u in script.upsert {
                match s
                    .packages
                    .iter_mut()
                    .find(|p| p.identity.eq_ignore_ascii_case(&u.identity))
                {
                    Some(p) => p.state = u.state,
                    None => s.packages.push(u),
                }
            }
            if let Some(p) = script.pending_after {
                s.pending = p;
            }
            Ok(script.result)
        })
    }

    fn supports_remove_package(&self) -> bool {
        self.with(|s| s.supports_remove)
    }

    fn remove_package(
        &self,
        identity: &str,
        _log_dir: &Path,
        _timeout: Duration,
    ) -> Result<ServicingResult, BackendError> {
        self.with(|s| {
            s.calls.push(format!("remove {identity}"));
            if !s.supports_remove {
                return Err(BackendError::Unsupported(
                    "the fake backend was built without removal".into(),
                ));
            }
            let script = s
                .removes
                .pop_front()
                .ok_or_else(|| BackendError::Command("no scripted remove_package result".into()))?;
            for u in script.upsert {
                match s
                    .packages
                    .iter_mut()
                    .find(|p| p.identity.eq_ignore_ascii_case(&u.identity))
                {
                    Some(p) => p.state = u.state,
                    None => s.packages.push(u),
                }
            }
            s.packages.retain(|p| {
                !script
                    .remove
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(&p.identity))
            });
            if let Some(p) = script.pending_after {
                s.pending = p;
            }
            Ok(script.result)
        })
    }
}
