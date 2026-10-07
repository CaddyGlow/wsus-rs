//! Probe for the `CreateDeploymentSessionEx` session API of a delivered `UpdateAgent.dll`
//! (docs/wsus-osinstaller-spike.md, section 15).
//!
//! Windows only. `ua_session <dll> <workdir> <sessiondata.json|-> <steps> [guid]` creates a session
//! (OptionalSessionInfo version 6 carrying the JSON as SessionData, an optional factory GUID) and
//! runs the comma-separated steps on it: `gdr` GenerateDownloadRequest (vtable slot 4), `post`
//! PostDownload (11), `install` Install (5), `commit` Commit (6), `cleanup` Cleanup (7), `id` get_Id (3), `revert` Revert (13, prints the int it returns),
//! `uninstall` Uninstall (17, prints the int it returns).
//! Every HRESULT is printed. Install is never given a timeout.

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ua_session runs on Windows only");
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    type Create =
        unsafe extern "system" fn(i32, *const u16, *const u8, i32, *const u8, *mut usize) -> i32;

    fn parse_guid(s: &str) -> [u8; 16] {
        let h: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let b: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let mut g = [0u8; 16];
        g[0..4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
        g[4..6].copy_from_slice(&[b[5], b[4]]);
        g[6..8].copy_from_slice(&[b[7], b[6]]);
        g[8..16].copy_from_slice(&b[8..16]);
        g
    }

    pub fn run() {
        let a: Vec<String> = std::env::args().collect();
        if a.len() < 5 {
            eprintln!("usage: ua_session <dll> <workdir> <sessiondata.json|-> <steps> [guid]");
            std::process::exit(2);
        }
        // SAFETY: plain COM initialization on the main thread of this probe.
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        println!("CoInitializeEx: {hr:#010x}");
        let dll = wide(&a[1]);
        // SAFETY: loading the DLL under test; documented purpose of the probe.
        let module = unsafe {
            LoadLibraryExW(
                dll.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if module.is_null() {
            eprintln!("LoadLibraryExW failed: {}", std::io::Error::last_os_error());
            std::process::exit(3);
        }
        // SAFETY: module is valid; the export has the signature documented in the spike.
        let create: Create = unsafe {
            std::mem::transmute(
                GetProcAddress(module, b"CreateDeploymentSessionEx\0".as_ptr()).expect("export"),
            )
        };
        let work = wide(&a[2]);
        let json = if a[3] == "-" {
            Vec::new()
        } else {
            wide(std::fs::read_to_string(&a[3]).expect("json").trim_end())
        };
        let guid = a.get(5).map(|g| parse_guid(g));
        let mut info = [0u64; 14];
        if !json.is_empty() {
            info[0] = json.as_ptr() as u64;
        }
        let mut session: usize = 0;
        // SAFETY: arguments follow the layout recovered from UpdateAgent.dll; buffers outlive the call.
        let hr = unsafe {
            create(
                1,
                work.as_ptr(),
                guid.as_ref().map_or(std::ptr::null(), |g| g.as_ptr()),
                6,
                info.as_ptr().cast(),
                &mut session,
            )
        };
        println!("CreateDeploymentSessionEx: {hr:#010x} session={session:#x}");
        if hr < 0 || session == 0 {
            return;
        }
        // SAFETY: a COM object pointer; slot numbers from the vtable recovered from the DLL.
        let vt = unsafe { *(session as *const *const usize) };
        let slot = |i: usize| unsafe { *vt.add(i) };
        for step in a[4].split(',') {
            let r: i32 =
                unsafe {
                    match step {
                        "gdr" => {
                            let mut out = 0usize;
                            let f: unsafe extern "system" fn(usize, *mut usize) -> i32 =
                                std::mem::transmute(slot(4));
                            let r = f(session, &mut out);
                            println!("  download request object: {out:#x}");
                            r
                        }
                        "post" => std::mem::transmute::<
                            usize,
                            unsafe extern "system" fn(usize) -> i32,
                        >(slot(11))(session),
                        "install" => {
                            let mut err = 0usize;
                            let mut reboot = 0i32;
                            let f: unsafe extern "system" fn(usize, *mut usize, *mut i32) -> i32 =
                                std::mem::transmute(slot(5));
                            let r = f(session, &mut err, &mut reboot);
                            println!("  error info: {err:#x} flag: {reboot}");
                            r
                        }
                        "commit" => std::mem::transmute::<
                            usize,
                            unsafe extern "system" fn(usize) -> i32,
                        >(slot(6))(session),
                        "cleanup" => std::mem::transmute::<
                            usize,
                            unsafe extern "system" fn(usize) -> i32,
                        >(slot(7))(session),
                        "revert" | "uninstall" => {
                            let mut out = 0i32;
                            let idx = if step == "revert" { 13 } else { 17 };
                            let f: unsafe extern "system" fn(usize, *mut i32) -> i32 =
                                std::mem::transmute(slot(idx));
                            let r = f(session, &mut out);
                            println!("  {step} out: {out}");
                            r
                        }
                        "id" => {
                            let mut p = 0usize;
                            let f: unsafe extern "system" fn(usize, *mut usize) -> i32 =
                                std::mem::transmute(slot(3));
                            let r = f(session, &mut p);
                            if p != 0 {
                                let mut v = Vec::new();
                                let mut q = p as *const u16;
                                while *q != 0 {
                                    v.push(*q);
                                    q = q.add(1);
                                }
                                println!("  id: {}", String::from_utf16_lossy(&v));
                            }
                            r
                        }
                        other => {
                            eprintln!("unknown step {other}");
                            std::process::exit(2)
                        }
                    }
                };
            println!("{step}: {r:#010x}");
        }
    }
}
