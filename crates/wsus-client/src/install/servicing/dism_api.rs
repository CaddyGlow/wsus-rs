//! The DISM API backend: `DismApi.dll` called in process, loaded dynamically.
//!
//! Calls (READ from `dismapi.h` as remembered, validated against the DISM exe backend on a guest,
//! see `docs/wsus-install.md`): `DismInitialize`, `DismOpenSession(DISM_ONLINE_IMAGE)`,
//! `DismGetPackages`, `DismGetPackageInfo` (by path, for the applicability verdict),
//! `DismAddPackage` and `DismRemovePackage` with a progress callback, `DismCloseSession`, `DismShutdown`, `DismDelete`.
//!
//! * The DLL is loaded at selection time from the system directory with `LoadLibraryExW`; where it is
//!   absent, [`DismApiBackend::load`] returns an error and nothing else is affected.
//! * Every operation is initialize, open session, call, close session, shutdown, so no state outlives
//!   a call.
//! * `DismAddPackage` is synchronous. It runs on a worker thread and the caller waits up to the
//!   timeout. On timeout the call is NOT cancelled (no cancel event is passed, the DLL is never
//!   unloaded); the worker finishes and closes the session by itself and the install is judged by
//!   fresh state later, as for the DISM exe backend.
//! * HRESULTs are classified by [`describe_exit`], the table the DISM exe backend uses;
//!   `0x80070BC2` (ERROR_SUCCESS_REBOOT_REQUIRED as an HRESULT) is the reboot class.
//!
//! The function table is a plain struct of `extern "system"` pointers so host tests substitute a
//! mock with the same ABI (including the progress callback and the `DismPackage` array layout).
use super::{
    BackendError, PackageEntry, PackageSnapshot, PendingIndicators, ServicingBackend,
    ServicingClass, ServicingResult, dism::describe_exit, pending,
};
use std::{
    ffi::c_void,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    time::Duration,
};

/// `DISM_ONLINE_IMAGE`.
pub const DISM_ONLINE_IMAGE: &str = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";
/// `DismLogErrorsWarningsInfo`.
const LOG_ERRORS_WARNINGS_INFO: i32 = 2;
/// `DismPackagePath` (`DismPackageIdentifier`: None 0, Name 1, Path 2).
const IDENT_PATH: i32 = 2;
/// `DismPackageName`.
const IDENT_NAME: i32 = 1;

/// `DismPackage` (x64 layout: pointer, two enums, `SYSTEMTIME`).
#[repr(C)]
pub struct RawPackage {
    pub package_name: *const u16,
    pub package_state: i32,
    pub release_type: i32,
    pub install_time: [u16; 8],
}

/// The head of `DismPackageInfo` up to `Applicable`, then the fields up to `RestartRequired`
/// (READ from the header from memory; only `package_name` and `applicable` are used for a verdict,
/// and `applicable` was compared with the exe's `Applicable : Yes|No` on the guest).
#[repr(C)]
pub struct RawPackageInfo {
    pub package_name: *const u16,
    pub package_state: i32,
    pub release_type: i32,
    pub install_time: [u16; 8],
    pub applicable: i32,
}

pub type ProgressFn = unsafe extern "system" fn(current: u32, total: u32, user: *mut c_void);
pub type InitializeFn =
    unsafe extern "system" fn(log_level: i32, log_path: *const u16, scratch: *const u16) -> i32;
pub type ShutdownFn = unsafe extern "system" fn() -> i32;
pub type OpenSessionFn = unsafe extern "system" fn(
    image: *const u16,
    windows_dir: *const u16,
    system_drive: *const u16,
    session: *mut u32,
) -> i32;
pub type CloseSessionFn = unsafe extern "system" fn(session: u32) -> i32;
pub type AddPackageFn = unsafe extern "system" fn(
    session: u32,
    path: *const u16,
    ignore_check: i32,
    prevent_pending: i32,
    cancel_event: *mut c_void,
    progress: Option<ProgressFn>,
    user: *mut c_void,
) -> i32;
/// `DismRemovePackage(session, identifier, DismPackageName, cancel, progress, user)`.
pub type RemovePackageFn = unsafe extern "system" fn(
    session: u32,
    identifier: *const u16,
    kind: i32,
    cancel_event: *mut c_void,
    progress: Option<ProgressFn>,
    user: *mut c_void,
) -> i32;
pub type GetPackagesFn =
    unsafe extern "system" fn(session: u32, out: *mut *mut RawPackage, count: *mut u32) -> i32;
pub type GetPackageInfoFn = unsafe extern "system" fn(
    session: u32,
    identifier: *const u16,
    kind: i32,
    out: *mut *mut RawPackageInfo,
) -> i32;
pub type DeleteFn = unsafe extern "system" fn(ptr: *mut c_void) -> i32;

/// The `DismApi.dll` entry points the backend uses.
#[derive(Clone, Copy)]
pub struct DismTable {
    pub initialize: InitializeFn,
    pub shutdown: ShutdownFn,
    pub open_session: OpenSessionFn,
    pub close_session: CloseSessionFn,
    pub add_package: AddPackageFn,
    pub remove_package: RemovePackageFn,
    pub get_packages: GetPackagesFn,
    pub get_package_info: GetPackageInfoFn,
    pub delete: DeleteFn,
}

#[cfg(windows)]
impl DismTable {
    /// Loads `<system_dir>\DismApi.dll` and resolves the entry points. The module is never freed (a
    /// timed-out add may still be running inside it).
    pub fn load(system_dir: &Path) -> Result<Self, BackendError> {
        use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
        };
        let dll = system_dir.join("DismApi.dll");
        let wide = wide(&dll.to_string_lossy());
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if module.is_null() {
            return Err(BackendError::Command(format!(
                "{} could not be loaded (the DISM API is not available here)",
                dll.display()
            )));
        }
        macro_rules! sym {
            ($name:literal, $ty:ty) => {{
                // SAFETY: `module` is a loaded module and the name is a NUL-terminated ASCII string.
                let p = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                match p {
                    // SAFETY: the exported symbol has the documented signature of the field type.
                    Some(f) => unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f) },
                    None => {
                        return Err(BackendError::Command(format!(
                            "DismApi.dll does not export {}",
                            $name
                        )));
                    }
                }
            }};
        }
        Ok(Self {
            initialize: sym!("DismInitialize", InitializeFn),
            shutdown: sym!("DismShutdown", ShutdownFn),
            open_session: sym!("DismOpenSession", OpenSessionFn),
            close_session: sym!("DismCloseSession", CloseSessionFn),
            add_package: sym!("DismAddPackage", AddPackageFn),
            remove_package: sym!("DismRemovePackage", RemovePackageFn),
            get_packages: sym!("DismGetPackages", GetPackagesFn),
            get_package_info: sym!("DismGetPackageInfo", GetPackageInfoFn),
            delete: sym!("DismDelete", DeleteFn),
        })
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn path_wide(p: &Path) -> Result<Vec<u16>, BackendError> {
    p.to_str()
        .map(wide)
        .ok_or_else(|| BackendError::Command(format!("path {} is not valid Unicode", p.display())))
}

fn hr_failed(hr: i32) -> bool {
    hr < 0
}

fn hr_error(what: &str, hr: i32) -> BackendError {
    BackendError::Command(format!("{what} failed: {}", describe_exit(hr as u32).1))
}

/// `DismPackageFeatureState` as the English text DISM prints. INFERRED for the values the exe was not
/// compared on (`Not Present`, `Resolved`, `Partially Installed`).
pub fn state_text(state: i32) -> String {
    match state {
        0 => "Not Present".into(),
        1 => "Uninstall Pending".into(),
        2 => "Staged".into(),
        3 => "Resolved".into(),
        4 => "Installed".into(),
        5 => "Install Pending".into(),
        6 => "Superseded".into(),
        7 => "Partially Installed".into(),
        other => format!("Unknown ({other})"),
    }
}

/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: the caller guarantees NUL termination.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` units were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// An initialized DISM API with an open online session; closes and shuts down on drop.
struct Session {
    table: DismTable,
    id: u32,
}

impl Session {
    fn open(table: DismTable, log: Option<&Path>) -> Result<Self, BackendError> {
        let log_w = log.map(path_wide).transpose()?;
        let log_p = log_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
        // SAFETY: pointers are null or NUL-terminated strings that outlive the call.
        let hr = unsafe { (table.initialize)(LOG_ERRORS_WARNINGS_INFO, log_p, std::ptr::null()) };
        if hr_failed(hr) {
            return Err(hr_error("DismInitialize", hr));
        }
        let image = wide(DISM_ONLINE_IMAGE);
        let mut id = 0u32;
        // SAFETY: `image` is NUL-terminated, the other strings are null (online), `id` is writable.
        let hr = unsafe {
            (table.open_session)(image.as_ptr(), std::ptr::null(), std::ptr::null(), &mut id)
        };
        if hr_failed(hr) {
            // SAFETY: balances the successful DismInitialize.
            unsafe { (table.shutdown)() };
            return Err(hr_error("DismOpenSession", hr));
        }
        Ok(Self { table, id })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: closes the session opened in `open` and balances DismInitialize.
        unsafe {
            (self.table.close_session)(self.id);
            (self.table.shutdown)();
        }
    }
}

/// Progress of a running add, written by the callback.
#[derive(Default)]
struct Progress {
    current: AtomicU32,
    total: AtomicU32,
}

unsafe extern "system" fn on_progress(current: u32, total: u32, user: *mut c_void) {
    if user.is_null() {
        return;
    }
    // SAFETY: `user` is the `Arc<Progress>` pointer passed by `add_package`, alive until the worker
    // ends.
    let p = unsafe { &*(user as *const Progress) };
    p.current.store(current, Ordering::Relaxed);
    p.total.store(total, Ordering::Relaxed);
}

/// The DISM API backend.
#[derive(Clone, Copy)]
pub struct DismApiBackend {
    table: DismTable,
}

impl std::fmt::Debug for DismApiBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DismApiBackend").finish_non_exhaustive()
    }
}

impl DismApiBackend {
    /// Loads `DismApi.dll` from `system_dir`.
    #[cfg(windows)]
    pub fn load(system_dir: &Path) -> Result<Self, BackendError> {
        Ok(Self::with_table(DismTable::load(system_dir)?))
    }

    /// Uses the given function table (the host tests pass a mock).
    pub fn with_table(table: DismTable) -> Self {
        Self { table }
    }
}

impl ServicingBackend for DismApiBackend {
    fn name(&self) -> &'static str {
        "dism_api"
    }

    fn list_packages(&self) -> Result<PackageSnapshot, BackendError> {
        let t = self.table;
        let s = Session::open(t, None)?;
        let mut arr: *mut RawPackage = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: valid session, writable out pointers.
        let hr = unsafe { (t.get_packages)(s.id, &mut arr, &mut count) };
        if hr_failed(hr) {
            return Err(hr_error("DismGetPackages", hr));
        }
        let mut packages = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            // SAFETY: the API returned `count` consecutive `DismPackage` records at `arr`.
            let p = unsafe { &*arr.add(i) };
            packages.push(PackageEntry {
                // SAFETY: `package_name` is a NUL-terminated string owned by the array.
                identity: unsafe { from_wide(p.package_name) },
                state: state_text(p.package_state),
            });
        }
        // SAFETY: `arr` was allocated by the API.
        unsafe { (t.delete)(arr as *mut c_void) };
        if packages.iter().any(|p| p.identity.is_empty()) {
            return Err(BackendError::Parse(
                "DismGetPackages returned a package without a name".into(),
            ));
        }
        Ok(PackageSnapshot { packages })
    }

    fn payload_applicability(&self, payload: &Path) -> Result<Option<bool>, BackendError> {
        let t = self.table;
        let s = Session::open(t, None)?;
        let path = path_wide(payload)?;
        let mut info: *mut RawPackageInfo = std::ptr::null_mut();
        // SAFETY: valid session, NUL-terminated path, writable out pointer.
        let hr = unsafe { (t.get_package_info)(s.id, path.as_ptr(), IDENT_PATH, &mut info) };
        if hr as u32 == 0x800F_081E {
            return Ok(Some(false));
        }
        if hr_failed(hr) {
            return Err(hr_error("DismGetPackageInfo", hr));
        }
        if info.is_null() {
            return Err(BackendError::Parse(
                "DismGetPackageInfo returned no record".into(),
            ));
        }
        // SAFETY: the API returned a `DismPackageInfo`; the prefix read is within it.
        let applicable = unsafe { (*info).applicable };
        // SAFETY: allocated by the API.
        unsafe { (t.delete)(info as *mut c_void) };
        match applicable {
            0 => Ok(Some(false)),
            1 => Ok(Some(true)),
            other => Err(BackendError::Parse(format!(
                "DismGetPackageInfo Applicable is {other}, not 0 or 1"
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
        let t = self.table;
        let path = path_wide(payload)?;
        self.call_with_timeout(
            "dism-api-add-package",
            log_dir.join("dism-api-add-package.log"),
            timeout,
            "DismAddPackage",
            "the install",
            move |s, user| {
                // SAFETY: valid session, NUL-terminated path, a callback with the documented
                // signature, and `user` kept alive by the caller until after the call.
                unsafe {
                    (t.add_package)(
                        s.id,
                        path.as_ptr(),
                        0,
                        0,
                        std::ptr::null_mut(),
                        Some(on_progress),
                        user,
                    )
                }
            },
        )
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
        let t = self.table;
        let name = wide(identity);
        self.call_with_timeout(
            "dism-api-remove-package",
            log_dir.join("dism-api-remove-package.log"),
            timeout,
            "DismRemovePackage",
            "the removal",
            move |s, user| {
                // SAFETY: valid session, NUL-terminated identity, no cancel event, a callback with
                // the documented signature, and `user` kept alive until after the call.
                unsafe {
                    (t.remove_package)(
                        s.id,
                        name.as_ptr(),
                        IDENT_NAME,
                        std::ptr::null_mut(),
                        Some(on_progress),
                        user,
                    )
                }
            },
        )
    }
}

impl DismApiBackend {
    /// Runs one synchronous DISM API operation on a worker thread that owns the session, waits up to
    /// `timeout`, and on timeout leaves the call running (never cancelled, the DLL never unloaded):
    /// the worker closes the session by itself and the outcome is judged by fresh state later.
    fn call_with_timeout(
        &self,
        thread: &str,
        log: std::path::PathBuf,
        timeout: Duration,
        api: &str,
        what: &str,
        op: impl FnOnce(&Session, *mut c_void) -> i32 + Send + 'static,
    ) -> Result<ServicingResult, BackendError> {
        let t = self.table;
        let progress = Arc::new(Progress::default());
        let worker_progress = Arc::clone(&progress);
        let worker_log = log.clone();
        let (tx, rx) = mpsc::channel::<Result<i32, BackendError>>();
        std::thread::Builder::new()
            .name(thread.into())
            .spawn(move || {
                let outcome = Session::open(t, Some(&worker_log)).map(|s| {
                    let user = Arc::as_ptr(&worker_progress) as *mut c_void;
                    op(&s, user)
                });
                let _ = tx.send(outcome);
            })
            .map_err(|e| BackendError::Command(format!("cannot start the DISM API worker: {e}")))?;
        let fmt_progress = |p: &Progress| {
            format!(
                "last progress {}/{}",
                p.current.load(Ordering::Relaxed),
                p.total.load(Ordering::Relaxed)
            )
        };
        match rx.recv_timeout(timeout) {
            Ok(Ok(hr)) => {
                let (class, description) = describe_exit(hr as u32);
                Ok(ServicingResult {
                    backend: "dism_api".into(),
                    native_code: Some(hr as u32),
                    class,
                    description,
                    timed_out: false,
                    stdout_tail: Some(fmt_progress(&progress)),
                    stderr_tail: None,
                    log_paths: vec![log.display().to_string()],
                })
            }
            Ok(Err(e)) => Err(e),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(ServicingResult {
                backend: "dism_api".into(),
                native_code: None,
                class: ServicingClass::Failed,
                description: format!(
                    "timed out: {api} was left running (not cancelled), {what} is judged by fresh state later"
                ),
                timed_out: true,
                stdout_tail: Some(fmt_progress(&progress)),
                stderr_tail: None,
                log_paths: vec![log.display().to_string()],
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BackendError::Command(
                "the DISM API worker ended without a result".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The mock functions have no context argument (as the real ones), so tests that use them take
    /// this lock and reset [`MOCK`].
    static SERIAL: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock::new());

    struct Mock {
        calls: Vec<String>,
        packages: Vec<(&'static str, i32)>,
        applicable: i32,
        info_hr: i32,
        add_hr: i32,
        remove_hr: i32,
        remove_name: String,
        add_delay: Duration,
        init_hr: i32,
        open_hr: i32,
        progress: Vec<(u32, u32)>,
        array_len: usize,
        add_path: String,
        log_path: String,
    }

    impl Mock {
        const fn new() -> Self {
            Self {
                calls: Vec::new(),
                packages: Vec::new(),
                applicable: 1,
                info_hr: 0,
                add_hr: 0,
                remove_hr: 0,
                remove_name: String::new(),
                add_delay: Duration::ZERO,
                init_hr: 0,
                open_hr: 0,
                progress: Vec::new(),
                array_len: 0,
                add_path: String::new(),
                log_path: String::new(),
            }
        }
    }

    fn call(name: &str) {
        MOCK.lock().unwrap().calls.push(name.to_owned());
    }

    unsafe extern "system" fn m_init(level: i32, log: *const u16, _s: *const u16) -> i32 {
        call("init");
        let mut m = MOCK.lock().unwrap();
        assert_eq!(level, LOG_ERRORS_WARNINGS_INFO);
        // SAFETY: the backend passes null or a NUL-terminated string.
        m.log_path = unsafe { from_wide(log) };
        m.init_hr
    }
    unsafe extern "system" fn m_shutdown() -> i32 {
        call("shutdown");
        0
    }
    unsafe extern "system" fn m_open(
        image: *const u16,
        wd: *const u16,
        sd: *const u16,
        session: *mut u32,
    ) -> i32 {
        call("open");
        // SAFETY: NUL-terminated by the backend.
        assert_eq!(unsafe { from_wide(image) }, DISM_ONLINE_IMAGE);
        assert!(wd.is_null() && sd.is_null());
        // SAFETY: writable out pointer.
        unsafe { *session = 7 };
        MOCK.lock().unwrap().open_hr
    }
    unsafe extern "system" fn m_close(session: u32) -> i32 {
        assert_eq!(session, 7);
        call("close");
        0
    }
    unsafe extern "system" fn m_add(
        session: u32,
        path: *const u16,
        ignore: i32,
        prevent: i32,
        cancel: *mut c_void,
        progress: Option<ProgressFn>,
        user: *mut c_void,
    ) -> i32 {
        assert_eq!(session, 7);
        assert!(cancel.is_null(), "a cancel event must never be passed");
        assert_eq!((ignore, prevent), (0, 0));
        let (steps, delay, hr) = {
            let mut m = MOCK.lock().unwrap();
            // SAFETY: NUL-terminated by the backend.
            m.add_path = unsafe { from_wide(path) };
            m.calls.push("add".into());
            (m.progress.clone(), m.add_delay, m.add_hr)
        };
        for (c, t) in steps {
            // SAFETY: the backend passed a callback and user data valid for this call.
            unsafe { progress.unwrap()(c, t, user) };
        }
        std::thread::sleep(delay);
        hr
    }
    unsafe extern "system" fn m_remove(
        session: u32,
        name: *const u16,
        kind: i32,
        cancel: *mut c_void,
        progress: Option<ProgressFn>,
        user: *mut c_void,
    ) -> i32 {
        assert_eq!(session, 7);
        assert_eq!(kind, IDENT_NAME);
        assert!(cancel.is_null(), "a cancel event must never be passed");
        let (steps, delay, hr) = {
            let mut m = MOCK.lock().unwrap();
            // SAFETY: NUL-terminated by the backend.
            m.remove_name = unsafe { from_wide(name) };
            m.calls.push("remove".into());
            (m.progress.clone(), m.add_delay, m.remove_hr)
        };
        for (c, t) in steps {
            // SAFETY: the backend passed a callback and user data valid for this call.
            unsafe { progress.unwrap()(c, t, user) };
        }
        std::thread::sleep(delay);
        hr
    }
    unsafe extern "system" fn m_packages(
        session: u32,
        out: *mut *mut RawPackage,
        count: *mut u32,
    ) -> i32 {
        assert_eq!(session, 7);
        call("get_packages");
        let mut m = MOCK.lock().unwrap();
        let v: Vec<RawPackage> = m
            .packages
            .iter()
            .map(|(n, s)| RawPackage {
                package_name: Box::leak(wide(n).into_boxed_slice()).as_ptr(),
                package_state: *s,
                release_type: 0,
                install_time: [0; 8],
            })
            .collect();
        m.array_len = v.len();
        let b = Box::leak(v.into_boxed_slice());
        // SAFETY: writable out pointers.
        unsafe {
            *out = b.as_mut_ptr();
            *count = b.len() as u32;
        }
        0
    }
    unsafe extern "system" fn m_info(
        session: u32,
        ident: *const u16,
        kind: i32,
        out: *mut *mut RawPackageInfo,
    ) -> i32 {
        assert_eq!(session, 7);
        assert_eq!(kind, IDENT_PATH);
        // SAFETY: NUL-terminated by the backend.
        assert!(unsafe { from_wide(ident) }.ends_with(".cab"));
        call("get_info");
        let m = MOCK.lock().unwrap();
        if m.info_hr != 0 {
            return m.info_hr;
        }
        let b = Box::new(RawPackageInfo {
            package_name: std::ptr::null(),
            package_state: 0,
            release_type: 0,
            install_time: [0; 8],
            applicable: m.applicable,
        });
        // SAFETY: writable out pointer.
        unsafe { *out = Box::into_raw(b) };
        0
    }
    unsafe extern "system" fn m_delete(_p: *mut c_void) -> i32 {
        call("delete");
        0
    }

    fn table() -> DismTable {
        DismTable {
            initialize: m_init,
            shutdown: m_shutdown,
            open_session: m_open,
            close_session: m_close,
            add_package: m_add,
            remove_package: m_remove,
            get_packages: m_packages,
            get_package_info: m_info,
            delete: m_delete,
        }
    }

    fn setup(f: impl FnOnce(&mut Mock)) -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = MOCK.lock().unwrap();
        *m = Mock::new();
        f(&mut m);
        g
    }

    fn calls() -> Vec<String> {
        MOCK.lock().unwrap().calls.clone()
    }

    #[test]
    fn packages_are_listed_with_dism_state_text_and_the_array_is_released() {
        let _g = setup(|m| {
            m.packages = vec![
                ("Package_A~31bf~amd64~~1.0", 4),
                ("Package_B~31bf~amd64~~2.0", 5),
            ];
        });
        let snap = DismApiBackend::with_table(table()).list_packages().unwrap();
        assert_eq!(snap.packages.len(), 2);
        assert!(snap.packages[0].is_installed());
        assert_eq!(snap.packages[1].state, "Install Pending");
        assert_eq!(
            calls(),
            [
                "init",
                "open",
                "get_packages",
                "delete",
                "close",
                "shutdown"
            ]
        );
    }

    #[test]
    fn an_empty_name_in_the_listing_is_a_parse_error() {
        let _g = setup(|m| m.packages = vec![("", 4)]);
        assert!(matches!(
            DismApiBackend::with_table(table()).list_packages(),
            Err(BackendError::Parse(_))
        ));
    }

    #[test]
    fn open_failure_shuts_down_and_is_an_error() {
        let _g = setup(|m| m.open_hr = 0x800F_0830u32 as i32);
        let e = DismApiBackend::with_table(table())
            .list_packages()
            .unwrap_err();
        assert!(e.to_string().contains("DismOpenSession"));
        assert_eq!(calls(), ["init", "open", "shutdown"]);
    }

    #[test]
    fn initialize_failure_does_not_open_a_session() {
        let _g = setup(|m| m.init_hr = 0x8007_0005u32 as i32);
        assert!(DismApiBackend::with_table(table()).list_packages().is_err());
        assert_eq!(calls(), ["init"]);
    }

    #[test]
    fn applicability_follows_the_applicable_field_and_not_applicable_hresult() {
        let b = DismApiBackend::with_table(table());
        {
            let _g = setup(|m| m.applicable = 1);
            assert_eq!(
                b.payload_applicability(Path::new("C:\\x.cab")).unwrap(),
                Some(true)
            );
        }
        {
            let _g = setup(|m| m.applicable = 0);
            assert_eq!(
                b.payload_applicability(Path::new("C:\\x.cab")).unwrap(),
                Some(false)
            );
        }
        {
            let _g = setup(|m| m.info_hr = 0x800F_081Eu32 as i32);
            assert_eq!(
                b.payload_applicability(Path::new("C:\\x.cab")).unwrap(),
                Some(false)
            );
        }
        {
            let _g = setup(|m| m.info_hr = 0x8007_0002u32 as i32);
            assert!(b.payload_applicability(Path::new("C:\\x.cab")).is_err());
        }
        {
            let _g = setup(|m| m.applicable = 5);
            assert!(matches!(
                b.payload_applicability(Path::new("C:\\x.cab")),
                Err(BackendError::Parse(_))
            ));
        }
    }

    fn add(b: &DismApiBackend, timeout: Duration) -> ServicingResult {
        b.add_package(
            Path::new("C:\\store\\u.cab"),
            Path::new("C:\\jobs\\j1"),
            timeout,
        )
        .unwrap()
    }

    #[test]
    fn add_package_success_reports_progress_and_the_log_path() {
        let _g = setup(|m| m.progress = vec![(1, 100), (100, 100)]);
        let r = add(
            &DismApiBackend::with_table(table()),
            Duration::from_secs(30),
        );
        assert_eq!(r.class, ServicingClass::Success);
        assert_eq!(r.native_code, Some(0));
        assert!(!r.timed_out);
        assert_eq!(r.stdout_tail.as_deref(), Some("last progress 100/100"));
        assert!(r.log_paths[0].ends_with("dism-api-add-package.log"));
        let m = MOCK.lock().unwrap();
        assert_eq!(m.add_path, "C:\\store\\u.cab");
        assert!(m.log_path.ends_with("dism-api-add-package.log"));
        assert_eq!(m.calls, ["init", "open", "add", "close", "shutdown"]);
    }

    #[test]
    fn reboot_required_hresults_map_to_the_reboot_class() {
        let b = DismApiBackend::with_table(table());
        for hr in [0x8007_0BC2u32, 3010] {
            let _g = setup(|m| m.add_hr = hr as i32);
            let r = add(&b, Duration::from_secs(30));
            assert_eq!(r.class, ServicingClass::Reboot);
            assert_eq!(r.native_code, Some(hr));
        }
    }

    #[test]
    fn failure_hresults_are_classified_like_the_exe_backend() {
        let b = DismApiBackend::with_table(table());
        for (hr, class) in [
            (0x800F_081Eu32, ServicingClass::NotApplicable),
            (0x800F_0830, ServicingClass::Busy),
            (0x800F_0922, ServicingClass::Failed),
            (0x8000_4005, ServicingClass::Failed),
        ] {
            let _g = setup(|m| m.add_hr = hr as i32);
            let r = add(&b, Duration::from_secs(30));
            assert_eq!(r.class, class, "{hr:#x}");
            assert_eq!(r.native_code, Some(hr));
        }
    }

    #[test]
    fn a_timeout_leaves_the_call_running_and_closes_the_session_afterwards() {
        let _g = setup(|m| {
            m.add_delay = Duration::from_millis(600);
            m.progress = vec![(40, 100)];
        });
        let r = add(
            &DismApiBackend::with_table(table()),
            Duration::from_millis(100),
        );
        assert!(r.timed_out);
        assert_eq!(r.native_code, None);
        assert_eq!(r.stdout_tail.as_deref(), Some("last progress 40/100"));
        // no close yet: the add is still in flight and was not cancelled
        assert_eq!(calls(), ["init", "open", "add"]);
        std::thread::sleep(Duration::from_millis(1200));
        assert_eq!(calls(), ["init", "open", "add", "close", "shutdown"]);
    }

    #[test]
    fn session_errors_during_add_are_returned() {
        let _g = setup(|m| m.open_hr = 0x800F_0830u32 as i32);
        let e = DismApiBackend::with_table(table())
            .add_package(
                Path::new("C:\\u.cab"),
                Path::new("."),
                Duration::from_secs(5),
            )
            .unwrap_err();
        assert!(e.to_string().contains("DismOpenSession"));
    }

    const ID: &str = "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1";

    fn remove(b: &DismApiBackend, timeout: Duration) -> ServicingResult {
        b.remove_package(ID, Path::new("C:\\jobs\\j1"), timeout)
            .unwrap()
    }

    #[test]
    fn remove_package_passes_the_name_and_reports_the_reboot_class() {
        let _g = setup(|m| {
            m.remove_hr = 0x8007_0BC2u32 as i32;
            m.progress = vec![(100, 100)];
        });
        let b = DismApiBackend::with_table(table());
        assert!(b.supports_remove_package());
        let r = remove(&b, Duration::from_secs(30));
        assert_eq!(r.class, ServicingClass::Reboot);
        assert_eq!(r.native_code, Some(0x8007_0BC2));
        assert!(r.log_paths[0].ends_with("dism-api-remove-package.log"));
        let m = MOCK.lock().unwrap();
        assert_eq!(m.remove_name, ID);
        assert_eq!(m.calls, ["init", "open", "remove", "close", "shutdown"]);
    }

    #[test]
    fn a_permanent_package_is_classified_not_failed() {
        let _g = setup(|m| m.remove_hr = 0x800F_0825u32 as i32);
        let r = remove(
            &DismApiBackend::with_table(table()),
            Duration::from_secs(30),
        );
        assert_eq!(r.class, ServicingClass::Permanent);
        assert_eq!(r.native_code, Some(0x800F_0825));
    }

    #[test]
    fn a_removal_timeout_leaves_the_call_running() {
        let _g = setup(|m| m.add_delay = Duration::from_millis(600));
        let r = remove(
            &DismApiBackend::with_table(table()),
            Duration::from_millis(100),
        );
        assert!(r.timed_out);
        assert_eq!(r.native_code, None);
        assert!(r.description.contains("DismRemovePackage was left running"));
        assert_eq!(calls(), ["init", "open", "remove"]);
        std::thread::sleep(Duration::from_millis(1200));
        assert_eq!(calls(), ["init", "open", "remove", "close", "shutdown"]);
    }

    #[test]
    fn remove_package_refuses_a_string_that_is_not_an_identity() {
        let _g = setup(|_| {});
        let b = DismApiBackend::with_table(table());
        assert!(
            b.remove_package("x y", Path::new("."), Duration::from_secs(1))
                .is_err()
        );
        assert!(calls().is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn nothing_to_load_off_windows_is_not_a_constructor() {
        // `load` is Windows only; `with_table` is the host entry point.
        assert_eq!(DismApiBackend::with_table(table()).name(), "dism_api");
    }
}
