//! Probe for the `UA_*` exports of a delivered `UpdateAgent.dll` (docs/wsus-osinstaller-spike.md).
//!
//! Windows only. `ua_probe <dll> <export> [arg ...]` loads the DLL (its own directory is added to
//! the DLL search path), calls the export with up to 12 integer-class arguments and prints the
//! returned HRESULT and the output slots.
//!
//! Arguments: `s:<text>` a NUL-terminated UTF-16 string, `f:<path>` the same read from a UTF-8 file
//! (for JSON, which the shell would otherwise strip of its quotes), `i:<n>` an integer (decimal or 0x hex),
//! `n` a null pointer, `o:<name>` a pointer to a zeroed 64-byte output slot printed after the call
//! (as hex qwords and, when the first qword looks like a pointer, as UTF-16 text).

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ua_probe runs on Windows only");
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

    fn show_wide(p: usize) -> Option<String> {
        if p < 0x10000 || p > 0x7fff_ffff_ffff {
            return None;
        }
        // SAFETY: probe tool; the address came from the DLL under test and is only read when it
        // lies in the user address range. A bad pointer faults the probe process, which is the
        // intended signal.
        unsafe {
            let mut v = Vec::new();
            let mut q = p as *const u16;
            for _ in 0..512 {
                let c = *q;
                if c == 0 {
                    break;
                }
                v.push(c);
                q = q.add(1);
            }
            let s = String::from_utf16_lossy(&v);
            if s.chars().all(|c| !c.is_control()) && !s.is_empty() {
                Some(s)
            } else {
                None
            }
        }
    }

    pub fn run() {
        let a: Vec<String> = std::env::args().collect();
        if a.len() < 3 {
            eprintln!("usage: ua_probe <dll> <export> [s:text|i:n|n|o:name ...]");
            std::process::exit(2);
        }
        // The stack uses COM (the servicing processor, the XML DOM): `UA_*` fails with 0x800401f0
        // (CO_E_NOTINITIALIZED) on a thread that did not initialize it.
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
        let name = std::ffi::CString::new(a[2].as_str()).unwrap();
        // SAFETY: module is a valid handle returned above.
        let proc = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
        let Some(proc) = proc else {
            eprintln!("export {} not found", a[2]);
            std::process::exit(4);
        };
        let mut keep: Vec<Vec<u16>> = Vec::new();
        let mut slots: Vec<(String, Box<[u64; 8]>)> = Vec::new();
        let mut raw: Vec<usize> = Vec::new();
        for s in &a[3..] {
            if let Some(t) = s.strip_prefix("s:") {
                keep.push(wide(t));
                raw.push(keep.last().unwrap().as_ptr() as usize);
            } else if let Some(path) = s.strip_prefix("f:") {
                let text = std::fs::read_to_string(path).expect("read argument file");
                keep.push(wide(text.trim_end()));
                raw.push(keep.last().unwrap().as_ptr() as usize);
            } else if let Some(n) = s.strip_prefix("i:") {
                let v = if let Some(h) = n.strip_prefix("0x") {
                    usize::from_str_radix(h, 16).unwrap()
                } else {
                    n.parse::<i64>().unwrap() as usize
                };
                raw.push(v);
            } else if s == "n" {
                raw.push(0);
            } else if let Some(n) = s.strip_prefix("o:") {
                slots.push((n.to_string(), Box::new([0u64; 8])));
                raw.push(slots.last().unwrap().1.as_ptr() as usize);
            } else {
                eprintln!("bad arg {s}");
                std::process::exit(2);
            }
        }
        raw.resize(12, 0);
        type F = unsafe extern "system" fn(
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
        ) -> i64;
        // SAFETY: calling an export with integer-class arguments; the probe's purpose is to find
        // the real signature, wrong guesses surface as HRESULTs or a crash of this process.
        let f: F = unsafe { std::mem::transmute(proc) };
        let r = unsafe {
            f(
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7], raw[8], raw[9],
                raw[10], raw[11],
            )
        };
        println!("result: {:#010x} ({})", r as u32, r as i32);
        for (n, s) in &slots {
            let q: Vec<String> = s.iter().map(|x| format!("{x:#x}")).collect();
            println!("slot {n}: {}", q.join(" "));
            if let Some(t) = show_wide(s[0] as usize) {
                println!("  text: {t}");
            }
        }
        // A returned list (count slot, pointer slot) is dumped by the caller with `dump`.
    }
}
