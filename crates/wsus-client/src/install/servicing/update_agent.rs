//! The `update_agent` mode of the `OSInstaller` handler: drives `UpdateAgent.dll` through its deployment
//! session API (`CreateDeploymentSessionEx`), the route the native agent takes.
//!
//! Windows only (feature `osinstaller-handler`). Evidence labels: READ = decompiled from
//! `UpdateAgent.dll` 10.0.26100.9457 (docs/wsus-osinstaller-spike.md, sections 12 and 15);
//! OBSERVED = seen on a Windows 11 25H2 guest (section 16); INFERRED = deduced, not checked.
//!
//! * `CreateDeploymentSessionEx(1, sandbox, &callbackFactory, 6, &OptionalSessionInfo6, &session)` (READ)
//!   returns a COM object whose vtable is IUnknown (3 slots) then `get_Id`, `GenerateDownloadRequest`,
//!   `Install(IDeploymentErrorInfo **, int *)`, `Commit`, `Cleanup`, `Cancel`, `Merge`,
//!   `GetPostRebootResult`, `PostDownload`, `Suspend`, `Revert`, `get_Capabilities`, `Pause`, `Resume`,
//!   `Uninstall` (slots 3 to 17, READ from the `CDeploymentSession` vtable).
//! * An all-zero callback factory GUID makes the stack skip its progress COM server (READ in
//!   `CProgressHandler::InitializeDeploymentProgress`); a non-zero one needs a registered
//!   `IDeploymentInformationFactory` and makes `Install` fail with `0x80040154` (OBSERVED).
//! * No SessionData (all-zero `OptionalSessionInfo`) is the native `.NET` scenario: the ActionList then
//!   says `SessionData="DesktopServicing"` and plans the CompDB's `GDR` feature (OBSERVED; a
//!   `LocalServicing` SessionData plans nothing for the same files).
//! * The CompDB cabinet must be a loose file in `<sandbox>\metadata` (OBSERVED: the stack warns
//!   "Missing AggregateMetadata.cab! CompDBs are expected to be downloaded as loose files" and verifies
//!   the CompDB cabinet there); this backend copies every `*.xml.cab` and `*.AggregatedMetadata.cab` of the sandbox there
//!   (READ: `ExpandCompDBs` finds `*.AggregatedMetadata.cab` in the metadata folder).
//! * Sequence (OBSERVED, all `S_OK`): `GenerateDownloadRequest` writes `ActionList.xml`,
//!   `DownloadList.xml` and `DeviceInventory.xml`; `PostDownload`; `Install`; `Commit`.
//! * The `int` that `Install` returns was 0 for an install the stack logged as "Reboot required: FALSE"
//!   (OBSERVED). Its meaning is not established; a non-zero value is treated as a reboot request
//!   (INFERRED, conservative).
//!
//! The stack comes from `System32` or from a directory of the delivered `DesktopDeployment.cab`; every
//! DLL of a delivered directory is verified (Authenticode, signer allowlist) BEFORE the first load.
use super::{
    BackendError, ServicingClass, ServicingResult,
    os_installer::{
        OsInstallOutcome, OsInstallRequest, OsInstallerBackend, OsPhase,
        downloads_from_action_list, express_sources_from_action_list, identities_from_action_list,
    },
};
use crate::install::{
    signature::{SignatureVerifier, TrustPolicy},
    signature_windows::WinVerifyTrustVerifier,
    stdout_guard::StdoutGuard,
};
use std::{
    ffi::{OsStr, c_void},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};
use windows_sys::Win32::{
    Foundation::FreeLibrary,
    System::{
        Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize},
        LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
        SystemInformation::GetSystemWindowsDirectoryW,
    },
};

/// `CreateDeploymentSessionEx(version, workDir, callbackFactoryGuid, optionsVersion, options, &session)`.
type CreateSession =
    unsafe extern "system" fn(i32, *const u16, *const u8, i32, *const u8, *mut *mut c_void) -> i32;
type Slot0 = unsafe extern "system" fn(*mut c_void) -> i32;
type SlotOut = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
type SlotInstall = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, *mut i32) -> i32;

/// Vtable slots of the session object (READ).
const RELEASE: usize = 2;
const GENERATE_DOWNLOAD_REQUEST: usize = 4;
const INSTALL: usize = 5;
const COMMIT: usize = 6;
const POST_DOWNLOAD: usize = 11;

/// `OptionalSessionInfo` version 6 is 0x70 bytes; all zero means no SessionData, no UpdateId, no flags.
const OPTIONAL_INFO_VERSION: i32 = 6;
const OPTIONAL_INFO_SIZE: usize = 0x70;

fn wide(p: &OsStr) -> Vec<u16> {
    p.encode_wide().chain(Some(0)).collect()
}

/// Which stack is loaded.
#[derive(Debug, Clone)]
pub enum StackSource {
    /// The OS's own `System32\UpdateAgent.dll`, trusted by its protected location.
    System,
    /// A directory holding the stack of a delivered `DesktopDeployment.cab`. Every `*.dll` in it is
    /// verified (Authenticode, `Microsoft Corporation`) before `UpdateAgent.dll` is loaded; a failure
    /// refuses the step.
    Staged(PathBuf),
}

/// Drives `UpdateAgent.dll` through the session API.
#[derive(Debug)]
pub struct UpdateAgentBackend {
    pub source: StackSource,
}

impl Default for UpdateAgentBackend {
    fn default() -> Self {
        Self {
            source: StackSource::System,
        }
    }
}

fn system_dll() -> Result<PathBuf, BackendError> {
    let mut buf = [0u16; 260];
    // SAFETY: the buffer is 260 UTF-16 units, the length passed.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(BackendError::Command(
            "cannot read the Windows directory".into(),
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n]))
        .join("System32")
        .join("UpdateAgent.dll"))
}

struct Module(*mut c_void);

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: the handle came from LoadLibraryExW and is freed once.
        unsafe { FreeLibrary(self.0) };
    }
}

/// A session object; released on drop.
struct Session(*mut c_void);

impl Session {
    fn slot<T>(&self, index: usize) -> T {
        // SAFETY: `self.0` is a live COM object whose vtable has at least 18 slots (READ); `T` is the
        // extern "system" function type of that slot.
        unsafe {
            let vt = *(self.0 as *const *const usize);
            std::mem::transmute_copy::<usize, T>(&*vt.add(index))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let release: Slot0 = self.slot(RELEASE);
        // SAFETY: releases the one reference the creation call returned.
        unsafe { release(self.0) };
    }
}

fn hr(code: i32) -> u32 {
    code as u32
}

fn phase(name: &str, code: Option<i32>, note: &str) -> OsPhase {
    OsPhase {
        name: name.into(),
        hresult: code.map(hr),
        note: note.into(),
    }
}

fn result(code: Option<u32>, class: ServicingClass, text: &str) -> ServicingResult {
    ServicingResult {
        backend: "update_agent".into(),
        native_code: code,
        class,
        description: text.into(),
        timed_out: false,
        stdout_tail: None,
        stderr_tail: None,
        log_paths: Vec::new(),
    }
}

/// Verifies every `*.dll` of a delivered stack directory; the first failure is the error.
fn verify_stack(dir: &Path, verifier: &dyn SignatureVerifier) -> Result<usize, BackendError> {
    let policy = TrustPolicy::default();
    let mut checked = 0;
    let entries = std::fs::read_dir(dir)
        .map_err(|e| BackendError::Command(format!("cannot read {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("dll"))
        {
            continue;
        }
        let file = std::fs::File::open(&path)
            .map_err(|e| BackendError::Command(format!("cannot open {}: {e}", path.display())))?;
        let info = verifier.verify(&file, &path).map_err(|e| {
            BackendError::Command(format!(
                "refusing the delivered update stack: {} is not acceptable: {e}",
                path.display()
            ))
        })?;
        policy.check(&info).map_err(|e| {
            BackendError::Command(format!(
                "refusing the delivered update stack: {}: {e}",
                path.display()
            ))
        })?;
        checked += 1;
    }
    if checked == 0 || !dir.join("UpdateAgent.dll").is_file() {
        return Err(BackendError::Command(format!(
            "{} holds no UpdateAgent.dll",
            dir.display()
        )));
    }
    Ok(checked)
}

impl UpdateAgentBackend {
    /// The DLL to load, after the signature gate for a delivered stack.
    fn resolve(&self, delivered: Option<&Path>) -> Result<PathBuf, BackendError> {
        let source = match (&self.source, delivered) {
            (StackSource::System, Some(dir)) => &StackSource::Staged(dir.to_path_buf()),
            (configured, _) => configured,
        };
        match source {
            StackSource::System => system_dll(),
            StackSource::Staged(dir) => {
                verify_stack(dir, &WinVerifyTrustVerifier)?;
                Ok(dir.join("UpdateAgent.dll"))
            }
        }
    }

    /// The whole sequence on the current thread (COM initialized for its duration).
    fn run_here(
        &self,
        req: &OsInstallRequest,
        dll: &Path,
    ) -> Result<OsInstallOutcome, BackendError> {
        // SAFETY: plain COM initialization on this thread, balanced below.
        let hr_com = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        let com_ok = hr_com >= 0;
        let out = self.run_com(req, dll);
        if com_ok {
            // SAFETY: balances the successful CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
        out
    }

    fn run_com(
        &self,
        req: &OsInstallRequest,
        dll: &Path,
    ) -> Result<OsInstallOutcome, BackendError> {
        // The CompDB cabinets are read from `<sandbox>\metadata` as loose files (OBSERVED).
        let meta = req.sandbox.join("metadata");
        std::fs::create_dir_all(&meta)
            .map_err(|e| BackendError::Command(format!("cannot create {}: {e}", meta.display())))?;
        for e in std::fs::read_dir(&req.sandbox)
            .map_err(|e| BackendError::Command(format!("cannot read the sandbox: {e}")))?
            .flatten()
        {
            let name = e.file_name();
            let lower = name.to_string_lossy().to_ascii_lowercase();
            // `ExpandCompDBs` (READ) searches `<sandbox>\metadata` for `*.AggregatedMetadata.cab` (the
            // monthly updates' CompDB container); the `.NET` updates' CompDB cabinets are `*.xml.cab`.
            if lower.ends_with(".xml.cab") || lower.ends_with(".aggregatedmetadata.cab") {
                std::fs::copy(e.path(), meta.join(&name)).map_err(|e| {
                    BackendError::Command(format!("cannot stage a CompDB cabinet: {e}"))
                })?;
            }
        }

        let w = wide(dll.as_os_str());
        // SAFETY: `w` is a NUL-terminated wide path; the search-path flag makes the stack's companion
        // DLLs resolve from its own directory.
        let handle = unsafe {
            LoadLibraryExW(
                w.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if handle.is_null() {
            return Err(BackendError::Command(format!(
                "cannot load {}: {}",
                dll.display(),
                std::io::Error::last_os_error()
            )));
        }
        let m = Module(handle);
        let name = c"CreateDeploymentSessionEx";
        // SAFETY: m.0 is a valid module handle for the lifetime of `m`.
        let Some(create) = (unsafe { GetProcAddress(m.0, name.as_ptr().cast()) }) else {
            return Err(BackendError::Command(
                "UpdateAgent.dll has no export CreateDeploymentSessionEx".into(),
            ));
        };
        // SAFETY: the export has the `CreateSession` signature (READ in the decompilation).
        let create: CreateSession = unsafe { std::mem::transmute_copy(&create) };

        let mut phases = Vec::new();
        let action_list = req.sandbox.join("ActionList.xml");
        let sandbox = wide(req.sandbox.as_os_str());
        // The callback factory GUID is all zero (no progress COM server), the session description is
        // either empty (the native `.NET` scenario) or the caller's SessionData at offset 0.
        let factory = [0u8; 16];
        let session_data =
            (!req.session_json.is_empty()).then(|| wide(OsStr::new(&req.session_json)));
        let mut info = [0u8; OPTIONAL_INFO_SIZE];
        if let Some(sd) = &session_data {
            info[..8].copy_from_slice(&(sd.as_ptr() as usize as u64).to_le_bytes());
        }
        let mut obj: *mut c_void = std::ptr::null_mut();
        // SAFETY: arguments follow the layout READ from CreateDeploymentSessionInternal; every buffer
        // outlives the call.
        let c = unsafe {
            create(
                1,
                sandbox.as_ptr(),
                factory.as_ptr(),
                OPTIONAL_INFO_VERSION,
                info.as_ptr(),
                &mut obj,
            )
        };
        phases.push(phase("create_session", Some(c), ""));
        let provisioned_cell = std::cell::RefCell::new(Vec::new());
        let outcome =
            |phases: Vec<OsPhase>, items, identities, res: ServicingResult| OsInstallOutcome {
                phases,
                action_list: Some(action_list.clone()).filter(|p| p.exists()),
                download_list: items,
                expected_identities: identities,
                result: res,
                provisioned: provisioned_cell.borrow().clone(),
            };
        if c < 0 || obj.is_null() {
            return Ok(outcome(
                phases,
                Vec::new(),
                Vec::new(),
                result(
                    Some(hr(c)),
                    ServicingClass::Failed,
                    "CreateDeploymentSessionEx failed",
                ),
            ));
        }
        let session = Session(obj);

        let gen_request: SlotOut = session.slot(GENERATE_DOWNLOAD_REQUEST);
        let mut request: *mut c_void = std::ptr::null_mut();
        // SAFETY: a live session; `request` receives an object this code releases below.
        let g = unsafe { gen_request(session.0, &mut request) };
        if !request.is_null() {
            let release: Slot0 = {
                // SAFETY: `request` is a COM object returned by the call above.
                let vt = unsafe { *(request as *const *const usize) };
                // SAFETY: slot 2 of a COM object is Release.
                unsafe { std::mem::transmute_copy::<usize, Slot0>(&*vt.add(RELEASE)) }
            };
            // SAFETY: drops the reference returned by GenerateDownloadRequest.
            unsafe { release(request) };
        }
        phases.push(phase("generate_download_request", Some(g), ""));
        let xml = std::fs::read_to_string(&action_list).unwrap_or_default();
        let identities = identities_from_action_list(&xml);
        let items = downloads_from_action_list(&xml);
        if g < 0 {
            return Ok(outcome(
                phases,
                items,
                identities,
                result(
                    Some(hr(g)),
                    ServicingClass::Failed,
                    "GenerateDownloadRequest failed",
                ),
            ));
        }
        if identities.is_empty() {
            // OBSERVED: with a non-matching session description the stack answers S_OK with an empty plan.
            return Ok(outcome(
                phases,
                items,
                identities,
                result(
                    Some(0),
                    ServicingClass::NotApplicable,
                    "the update stack produced an ActionList without any InstallPackage: it did not plan this update (not applicable to this system)",
                ),
            ));
        }
        // Missing files are judged by the executor (it holds the declared names); do not install over a
        // partial sandbox.
        // Express data files: members of the declared containers, taken when present (not required).
        let express_sources = express_sources_from_action_list(&xml);
        let mut missing = super::os_installer::missing_from_sandbox(&items, &req.declared);
        // Evidence: the stack's own download list and session state, kept in the job's log directory.
        for f in [
            "DownloadList.xml",
            "windlp.state.xml",
            "DeviceInventory.xml",
        ] {
            for d in [req.sandbox.clone(), req.sandbox.join("metadata")] {
                if d.join(f).exists() {
                    let _ = std::fs::create_dir_all(&req.log_dir);
                    let _ = std::fs::copy(d.join(f), req.log_dir.join(format!("ua-{f}")));
                }
            }
        }
        // Evidence: what the sandbox holds once the stack has produced its download list (OBSERVED: the
        // stack removes declared files it does not need from the sandbox during this call).
        {
            let mut names: Vec<String> = std::fs::read_dir(&req.sandbox)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            phases.push(phase(
                "sandbox_after_download_list",
                None,
                &names.join(", "),
            ));
        }
        // A file the list names that the declared set does not hold may be a member of a declared `.msu`
        // (the ActionList's `AltSourceName`): take it out into the sandbox.
        let mut provisioned = Vec::new();
        if (!missing.is_empty() || !express_sources.is_empty()) && !req.containers.is_empty() {
            let optional: Vec<String> = express_sources
                .iter()
                .filter(|n| !req.declared.iter().any(|d| d.eq_ignore_ascii_case(n)))
                .cloned()
                .collect();
            for name in missing
                .iter()
                .chain(optional.iter())
                .cloned()
                .collect::<Vec<_>>()
            {
                let want = Path::new(&name)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| name.clone());
                let mut why = Vec::new();
                for path in &req.containers {
                    let container = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    match super::msu::extract_member(path, &want, &req.sandbox) {
                        Ok(done) => {
                            let bytes = std::fs::metadata(&done).map(|m| m.len()).unwrap_or(0);
                            provisioned.push(super::os_installer::ProvisionedFile {
                                name: want.clone(),
                                container,
                                bytes,
                            });
                            why.clear();
                            break;
                        }
                        Err(e) => why.push(e),
                    }
                }
                if !why.is_empty() {
                    phases.push(phase(
                        "provision",
                        None,
                        &format!("{want}: {}", why.join("; ")),
                    ));
                }
            }
            let mut held = req.declared.clone();
            held.extend(provisioned.iter().map(|p| p.name.clone()));
            *provisioned_cell.borrow_mut() = provisioned.clone();
            missing = super::os_installer::missing_from_sandbox(&items, &held);
            phases.push(phase(
                "provision",
                Some(0),
                &format!(
                    "{} file(s) taken out of declared .msu containers, {} still missing",
                    provisioned.len(),
                    missing.len()
                ),
            ));
        }
        if !missing.is_empty() {
            return Ok(outcome(
                phases,
                items,
                identities,
                result(
                    Some(0),
                    ServicingClass::Failed,
                    "the ActionList names files the sandbox does not hold",
                ),
            ));
        }

        let post: Slot0 = session.slot(POST_DOWNLOAD);
        // SAFETY: a live session.
        let p = unsafe { post(session.0) };
        phases.push(phase("post_download", Some(p), ""));
        if p < 0 {
            return Ok(outcome(
                phases,
                items,
                identities,
                result(Some(hr(p)), ServicingClass::Failed, "PostDownload failed"),
            ));
        }

        let install: SlotInstall = session.slot(INSTALL);
        let mut err_info: *mut c_void = std::ptr::null_mut();
        let mut flag = 0i32;
        // SAFETY: a live session; both out-parameters are valid. NEVER cancelled or abandoned: the
        // call returns when the stack is done.
        let i = unsafe { install(session.0, &mut err_info, &mut flag) };
        if !err_info.is_null() {
            // SAFETY: an object returned by Install; its reference is dropped.
            unsafe {
                let vt = *(err_info as *const *const usize);
                let rel: Slot0 = std::mem::transmute_copy(&*vt.add(RELEASE));
                rel(err_info);
            }
        }
        phases.push(phase(
            "install",
            Some(i),
            &format!(
                "out flag {flag}; error info {}",
                if err_info.is_null() {
                    "none"
                } else {
                    "returned"
                }
            ),
        ));
        if i < 0 {
            return Ok(outcome(
                phases,
                items,
                identities,
                result(Some(hr(i)), ServicingClass::Failed, "Install failed"),
            ));
        }
        let commit: Slot0 = session.slot(COMMIT);
        // SAFETY: a live session.
        let k = unsafe { commit(session.0) };
        phases.push(phase("commit", Some(k), ""));
        let (class, code, text) = if k < 0 {
            (ServicingClass::Failed, hr(k), "Commit failed")
        } else if flag != 0 {
            (
                ServicingClass::Reboot,
                0,
                "installed; the stack's Install flag is non-zero, treated as a reboot request",
            )
        } else {
            (
                ServicingClass::Success,
                0,
                "installed through the deployment session (Install and Commit returned S_OK)",
            )
        };
        Ok(outcome(
            phases,
            items,
            identities,
            result(Some(code), class, text),
        ))
    }
}

impl OsInstallerBackend for UpdateAgentBackend {
    fn name(&self) -> &'static str {
        "update_agent"
    }

    fn stack_overridden(&self) -> bool {
        matches!(self.source, StackSource::Staged(_))
    }

    fn run(&self, req: &OsInstallRequest) -> Result<OsInstallOutcome, BackendError> {
        let dll = self.resolve(req.stack_dir.as_deref())?;
        // OBSERVED: the stack's hotpatch helper writes text to the process's standard output. Capture it
        // for the duration of the session calls so a `--json` command keeps pure JSON on stdout. The
        // redirect is process-wide; it is undone on every exit path (timeout, error, panic) by the guard.
        let stdout_file = req.log_dir.join("ua-stack-stdout.txt");
        let (guard, guard_note) = match StdoutGuard::capture(&stdout_file) {
            Ok(g) => (Some(g), None),
            Err(e) => (None, Some(format!("stack stdout not captured: {e}"))),
        };
        // The session runs on its own thread so the bound can be noticed while it runs. The stack is
        // IN-PROCESS: leaving the thread behind and returning would let the command exit, and the process
        // exit would abort the stack in the middle of an install (OBSERVED, spike doc section 21: a 20 s
        // bound left the package `InstallRequested` without a pending restart, the servicing session ended
        // about 9 s after the exit). So after the bound the call is NOT abandoned: the client says so on
        // standard error and waits for the stack to return, then records `timed_out` (the step stays
        // `unconfirmed` and the next run judges by fresh state).
        let (tx, rx) = mpsc::channel();
        let this_req = req.clone();
        let backend = UpdateAgentBackend {
            source: self.source.clone(),
        };
        thread::spawn(move || {
            let _ = tx.send(backend.run_here(&this_req, &dll));
        });
        let mut over_bound = false;
        let received = match rx.recv_timeout(req.timeout) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                over_bound = true;
                eprintln!(
                    "the update stack exceeded the {} s bound; it is running inside this process and is not stopped, waiting for it to return",
                    req.timeout.as_secs()
                );
                rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected)
            }
            other => other,
        };
        // Standard output is handed back before the caller prints anything.
        let captured = guard.map(StdoutGuard::finish);
        let attach = |out: &mut OsInstallOutcome| {
            if let Some(c) = &captured {
                if c.total_bytes > 0 {
                    out.result.stdout_tail = c.tail.clone();
                    out.result.log_paths.push(c.path.display().to_string());
                }
                out.phases.push(phase(
                    "stack_stdout",
                    None,
                    &format!(
                        "{} byte(s) written to standard output by the stack, captured",
                        c.total_bytes
                    ),
                ));
            }
            if let Some(n) = &guard_note {
                out.phases.push(phase("stack_stdout", None, n));
            }
        };
        match received {
            Ok(out) => out.map(|mut o| {
                attach(&mut o);
                if over_bound {
                    o.result.timed_out = true;
                    o.phases.push(phase(
                        "timeout",
                        None,
                        &format!(
                            "exceeded the {} s bound; the stack was NOT stopped and was waited for",
                            req.timeout.as_secs()
                        ),
                    ));
                }
                o
            }),
            Err(_) => Err(BackendError::Command(
                "the update stack thread ended without a result".into(),
            )),
        }
    }
}
