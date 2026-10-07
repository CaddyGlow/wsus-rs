//! A process-level guard for standard output while native code that writes to it runs.
//!
//! OBSERVED (docs/wsus-osinstaller-spike.md, section 19): the hotpatch helper inside the Windows Update
//! servicing stack writes `HOTPATCHUTIL` text to the process's standard output, so a `--json` command
//! that drives the stack would print that text in front of its JSON. [`StdoutGuard::capture`] points the
//! process's standard output at a file for the guard's lifetime; [`StdoutGuard::finish`] (or dropping the
//! guard, on every exit path including a panic unwind) puts it back and the captured text is kept as
//! evidence instead of being mixed into the command's own output.
//!
//! * Unix (the host tests, and the only place the logic is exercised without a guest): `dup`/`dup2` on
//!   file descriptor 1.
//! * Windows: the C runtime descriptor 1 AND the Win32 standard handle are both redirected. Native code
//!   writes through either `printf` (descriptor 1 of the shared UCRT, `ucrtbase.dll`, the instance the
//!   stack uses; its functions are resolved from that module) or `WriteFile(GetStdHandle(..))`; Rust's own
//!   stdout reads `GetStdHandle` on every write, so it is redirected too while the guard is held and
//!   unaffected once it is restored.
//!
//! The redirect is process-wide: nothing else may print to standard output while a guard is held. Only one
//! guard is active at a time (a second `capture` waits for the first).
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

/// The captured text kept in the job record is the last this many bytes.
pub const CAPTURE_TAIL_BYTES: u64 = 8 * 1024;

static ACTIVE: Mutex<()> = Mutex::new(());

/// What was written to standard output while the guard was held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// Total bytes written.
    pub total_bytes: u64,
    /// The last [`CAPTURE_TAIL_BYTES`] bytes (lossy UTF-8); `None` when nothing was written.
    pub tail: Option<String>,
    /// The file that holds everything that was written.
    pub path: PathBuf,
}

/// Redirects the process's standard output to a file until finished or dropped.
pub struct StdoutGuard {
    saved: Option<imp::Saved>,
    path: PathBuf,
    _lock: MutexGuard<'static, ()>,
}

impl std::fmt::Debug for StdoutGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdoutGuard")
            .field("path", &self.path)
            .field("active", &self.saved.is_some())
            .finish()
    }
}

impl StdoutGuard {
    /// Starts capturing into `path` (created, truncated). Anything Rust buffered for standard output so far
    /// is flushed to the real standard output first.
    pub fn capture(path: &Path) -> io::Result<Self> {
        let lock = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let file = File::create(path)?;
        let _ = io::stdout().flush();
        let saved = imp::redirect(&file)?;
        // The redirected descriptor holds its own duplicate of the file; this handle is not needed.
        drop(file);
        Ok(Self {
            saved: Some(saved),
            path: path.to_path_buf(),
            _lock: lock,
        })
    }

    /// Restores standard output and returns what was captured.
    pub fn finish(mut self) -> Captured {
        self.restore();
        read_capture(&self.path)
    }

    fn restore(&mut self) {
        if let Some(saved) = self.saved.take() {
            imp::restore(saved);
        }
    }
}

impl Drop for StdoutGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

fn read_capture(path: &Path) -> Captured {
    let mut out = Captured {
        total_bytes: 0,
        tail: None,
        path: path.to_path_buf(),
    };
    let Ok(mut f) = File::open(path) else {
        return out;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return out;
    };
    out.total_bytes = len;
    if len == 0 {
        return out;
    }
    let start = len.saturating_sub(CAPTURE_TAIL_BYTES);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(start)).is_ok()
        && f.take(CAPTURE_TAIL_BYTES).read_to_end(&mut buf).is_ok()
    {
        let text = String::from_utf8_lossy(&buf).into_owned();
        out.tail = Some(if start > 0 {
            format!("[first {start} of {len} bytes omitted] {text}")
        } else {
            text
        });
    }
    out
}

#[cfg(unix)]
mod imp {
    use std::{fs::File, io, os::fd::AsRawFd};

    unsafe extern "C" {
        fn dup(fd: i32) -> i32;
        fn dup2(from: i32, to: i32) -> i32;
        fn close(fd: i32) -> i32;
    }

    pub struct Saved(i32);

    pub fn redirect(file: &File) -> io::Result<Saved> {
        // SAFETY: plain descriptor duplication of descriptor 1 and of an open file.
        unsafe {
            let saved = dup(1);
            if saved < 0 {
                return Err(io::Error::last_os_error());
            }
            if dup2(file.as_raw_fd(), 1) < 0 {
                let e = io::Error::last_os_error();
                close(saved);
                return Err(e);
            }
            Ok(Saved(saved))
        }
    }

    pub fn restore(saved: Saved) {
        // SAFETY: `saved.0` is the duplicate taken by `redirect`, closed once here.
        unsafe {
            dup2(saved.0, 1);
            close(saved.0);
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, fs::File, io, os::windows::io::IntoRawHandle, sync::OnceLock};
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleW, GetProcAddress, LoadLibraryW,
    };

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetStdHandle(which: u32, handle: *mut c_void) -> i32;
    }

    /// `STD_OUTPUT_HANDLE` is `(DWORD)-11`.
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    /// `_O_BINARY`.
    const O_BINARY: i32 = 0x8000;

    /// The C runtime functions the stack uses, from the shared UCRT instance.
    struct Crt {
        dup: unsafe extern "C" fn(i32) -> i32,
        dup2: unsafe extern "C" fn(i32, i32) -> i32,
        close: unsafe extern "C" fn(i32) -> i32,
        open_osfhandle: unsafe extern "C" fn(isize, i32) -> i32,
        get_osfhandle: unsafe extern "C" fn(i32) -> isize,
        flushall: unsafe extern "C" fn() -> i32,
    }

    fn crt() -> io::Result<&'static Crt> {
        static CRT: OnceLock<Result<Crt, String>> = OnceLock::new();
        CRT.get_or_init(load_crt)
            .as_ref()
            .map_err(|e| io::Error::other(e.clone()))
    }

    fn load_crt() -> Result<Crt, String> {
        let name: Vec<u16> = "ucrtbase.dll\0".encode_utf16().collect();
        // SAFETY: NUL-terminated wide module name; ucrtbase.dll is loaded in every process that uses the
        // UCRT, and loading it again only bumps its reference count.
        let module = unsafe {
            let m = GetModuleHandleW(name.as_ptr());
            if m.is_null() {
                LoadLibraryW(name.as_ptr())
            } else {
                m
            }
        };
        if module.is_null() {
            return Err("ucrtbase.dll is not loaded".into());
        }
        macro_rules! sym {
            ($n:literal) => {{
                // SAFETY: valid module handle, NUL-terminated ASCII name.
                let p = unsafe { GetProcAddress(module, concat!($n, "\0").as_ptr()) };
                match p {
                    // SAFETY: the export has the declared C signature (documented UCRT function).
                    Some(p) => unsafe { std::mem::transmute_copy(&p) },
                    None => return Err(format!("ucrtbase.dll has no export {}", $n)),
                }
            }};
        }
        Ok(Crt {
            dup: sym!("_dup"),
            dup2: sym!("_dup2"),
            close: sym!("_close"),
            open_osfhandle: sym!("_open_osfhandle"),
            get_osfhandle: sym!("_get_osfhandle"),
            flushall: sym!("_flushall"),
        })
    }

    pub struct Saved {
        /// A duplicate of CRT descriptor 1, or -1 when it was not open.
        fd: i32,
        /// The Win32 standard output handle before the redirect (used only when descriptor 1 was not open).
        std_handle: *mut c_void,
    }

    // SAFETY: the handle value is only passed back to SetStdHandle.
    unsafe impl Send for Saved {}

    pub fn redirect(file: &File) -> io::Result<Saved> {
        let crt = crt()?;
        let std_handle = std::os::windows::io::AsRawHandle::as_raw_handle(&io::stdout());
        // SAFETY: each call follows the documented UCRT contract; every descriptor is closed once.
        unsafe {
            let saved = (crt.dup)(1);
            let dup_file = file.try_clone()?.into_raw_handle();
            let fd = (crt.open_osfhandle)(dup_file as isize, O_BINARY);
            if fd < 0 {
                // The descriptor did not take the handle; it is still ours.
                drop(<File as std::os::windows::io::FromRawHandle>::from_raw_handle(dup_file));
                if saved >= 0 {
                    (crt.close)(saved);
                }
                return Err(io::Error::other("_open_osfhandle failed"));
            }
            let r = (crt.dup2)(fd, 1);
            (crt.close)(fd);
            if r != 0 {
                if saved >= 0 {
                    (crt.dup2)(saved, 1);
                    (crt.close)(saved);
                }
                return Err(io::Error::other("_dup2 failed"));
            }
            // `_dup2` may or may not move the Win32 handle for descriptor 1; make it explicit, so that
            // `WriteFile(GetStdHandle(..))` writers and Rust's stdout land in the file as well.
            SetStdHandle(STD_OUTPUT_HANDLE, (crt.get_osfhandle)(1) as *mut c_void);
            Ok(Saved {
                fd: saved,
                std_handle,
            })
        }
    }

    pub fn restore(saved: Saved) {
        let Ok(crt) = crt() else { return };
        // SAFETY: `saved.fd` is the duplicate taken by `redirect`, closed once here.
        unsafe {
            // Text the stack left in the C runtime's buffers belongs to the capture file.
            (crt.flushall)();
            if saved.fd >= 0 {
                (crt.dup2)(saved.fd, 1);
                (crt.close)(saved.fd);
                // `_dup2` closed the original handle and gave descriptor 1 a new one: point the Win32
                // standard handle at it.
                SetStdHandle(STD_OUTPUT_HANDLE, (crt.get_osfhandle)(1) as *mut c_void);
            } else {
                (crt.close)(1);
                SetStdHandle(STD_OUTPUT_HANDLE, saved.std_handle);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::{fs::File, io};

    pub struct Saved;

    pub fn redirect(_: &File) -> io::Result<Saved> {
        Err(io::Error::other(
            "no standard output redirect on this platform",
        ))
    }

    pub fn restore(_: Saved) {}
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    }

    fn raw_stdout(text: &str) {
        // SAFETY: writes a valid buffer to descriptor 1, as native code would.
        unsafe { write(1, text.as_ptr(), text.len()) };
    }

    #[test]
    fn captures_descriptor_output_and_restores_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let g = StdoutGuard::capture(&path).unwrap();
        raw_stdout("HOTPATCHUTIL: hello\n");
        let c = g.finish();
        // The test harness may print its own progress lines to descriptor 1 meanwhile: contains, not equals.
        assert!(c.total_bytes >= 20);
        assert!(c.tail.as_deref().unwrap().contains("HOTPATCHUTIL: hello\n"));
        // After the restore, descriptor 1 is not the first capture file any more.
        let again = StdoutGuard::capture(&dir.path().join("second.txt")).unwrap();
        raw_stdout("MARKER-X");
        let c2 = again.finish();
        assert!(c2.tail.unwrap().contains("MARKER-X"));
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("HOTPATCHUTIL: hello\n") && !first.contains("MARKER-X"));
    }

    #[test]
    fn restores_on_drop_and_on_panic_unwind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let p2 = path.clone();
        let r = std::panic::catch_unwind(move || {
            let _g = StdoutGuard::capture(&p2).unwrap();
            raw_stdout("before panic");
            panic!("boom");
        });
        assert!(r.is_err());
        // The lock was released by the unwind and the descriptor restored: a new guard starts clean.
        let g = StdoutGuard::capture(&dir.path().join("b.txt")).unwrap();
        raw_stdout("MARKER-AFTER");
        let c = g.finish();
        assert!(c.tail.as_deref().unwrap().contains("MARKER-AFTER"));
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("before panic") && !first.contains("MARKER-AFTER"));
    }

    #[test]
    fn keeps_only_a_bounded_tail_of_a_long_capture() {
        let dir = tempfile::tempdir().unwrap();
        let g = StdoutGuard::capture(&dir.path().join("long.txt")).unwrap();
        let chunk = "a".repeat(1000);
        for _ in 0..20 {
            raw_stdout(&chunk);
        }
        raw_stdout("MARKER-END");
        let c = g.finish();
        assert!(c.total_bytes >= 20_010);
        let tail = c.tail.unwrap();
        assert!(tail.starts_with("[first "));
        assert!(tail.len() < 8300);
    }

    #[test]
    fn empty_capture_has_no_tail() {
        let dir = tempfile::tempdir().unwrap();
        let g = StdoutGuard::capture(&dir.path().join("e.txt")).unwrap();
        let c = g.finish();
        assert_eq!(c.tail.is_none(), c.total_bytes == 0);
    }
}
