//! Pending-servicing indicators and free disk space on the system volume.
//!
//! The key list is the one the repository's own post-install collector uses (READ:
//! `crates/windows-uup/src/verification/collector.rs`, `scripts/observe-cbs-boot.ps1`): the CBS
//! `RebootPending`, `RebootInProgress` and `PackagesPending` keys, the Windows Update
//! `RebootRequired` key, `WinSxS\pending.xml`, a non-empty `PendingFileRenameOperations`, and the
//! setup-in-progress flags. That these are the right online indicators is INFERRED (the collector ran
//! on offline image copies); they are evidence, and any one set refuses a servicing run.
use super::PendingIndicators;

#[cfg(windows)]
mod imp {
    use super::PendingIndicators;
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        Storage::FileSystem::GetDiskFreeSpaceExW,
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegOpenKeyExW,
            RegQueryValueExW,
        },
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    enum Probe {
        Present(HKEY),
        Absent,
        Failed(u32),
    }

    fn open(subkey: &str) -> Probe {
        let name = wide(subkey);
        let mut h: HKEY = ptr::null_mut();
        // SAFETY: `name` is NUL terminated and `h` is a valid out pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                name.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut h,
            )
        };
        match rc {
            ERROR_SUCCESS => Probe::Present(h),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Probe::Absent,
            other => Probe::Failed(other),
        }
    }

    fn close(h: HKEY) {
        // SAFETY: `h` was opened by RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(h) };
    }

    fn key_present(out: &mut PendingIndicators, label: &str, subkey: &str) {
        match open(subkey) {
            Probe::Present(h) => {
                close(h);
                out.set.push(label.to_owned());
            }
            Probe::Absent => {}
            Probe::Failed(e) => out
                .unavailable
                .push(format!("{label}: RegOpenKeyEx error {e}")),
        }
    }

    /// The REG_DWORD value, or `None` when absent; `Err` when the key cannot be read.
    fn dword(subkey: &str, value: &str) -> Result<Option<u32>, String> {
        let h = match open(subkey) {
            Probe::Present(h) => h,
            Probe::Absent => return Ok(None),
            Probe::Failed(e) => return Err(format!("RegOpenKeyEx error {e}")),
        };
        let name = wide(value);
        let mut data = [0u8; 4];
        let mut size = 4u32;
        let mut ty = 0u32;
        // SAFETY: valid key handle, NUL terminated name and a 4 byte buffer with its size.
        let rc = unsafe {
            RegQueryValueExW(
                h,
                name.as_ptr(),
                ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut size,
            )
        };
        close(h);
        match rc {
            ERROR_SUCCESS if ty == 4 => Ok(Some(u32::from_le_bytes(data))),
            ERROR_SUCCESS => Ok(None),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(format!("RegQueryValueEx error {other}")),
        }
    }

    /// True when the value exists and holds anything but NUL bytes (REG_MULTI_SZ list).
    fn non_empty_value(subkey: &str, value: &str) -> Result<bool, String> {
        let h = match open(subkey) {
            Probe::Present(h) => h,
            Probe::Absent => return Ok(false),
            Probe::Failed(e) => return Err(format!("RegOpenKeyEx error {e}")),
        };
        let name = wide(value);
        let mut size = 0u32;
        // SAFETY: size query only (null data pointer).
        let rc = unsafe {
            RegQueryValueExW(
                h,
                name.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut size,
            )
        };
        let result = match rc {
            ERROR_SUCCESS if size == 0 => Ok(false),
            ERROR_SUCCESS => {
                let mut buf = vec![0u8; size as usize];
                let mut got = size;
                // SAFETY: the buffer holds `got` bytes.
                let rc2 = unsafe {
                    RegQueryValueExW(
                        h,
                        name.as_ptr(),
                        ptr::null(),
                        ptr::null_mut(),
                        buf.as_mut_ptr(),
                        &mut got,
                    )
                };
                if rc2 == ERROR_SUCCESS {
                    Ok(buf[..got as usize].iter().any(|b| *b != 0))
                } else {
                    Err(format!("RegQueryValueEx error {rc2}"))
                }
            }
            ERROR_FILE_NOT_FOUND => Ok(false),
            other => Err(format!("RegQueryValueEx error {other}")),
        };
        close(h);
        result
    }

    pub fn probe() -> PendingIndicators {
        const CBS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing";
        let mut out = PendingIndicators::default();
        key_present(
            &mut out,
            "CBS RebootPending",
            &format!(r"{CBS}\RebootPending"),
        );
        key_present(
            &mut out,
            "CBS RebootInProgress",
            &format!(r"{CBS}\RebootInProgress"),
        );
        key_present(
            &mut out,
            "CBS PackagesPending",
            &format!(r"{CBS}\PackagesPending"),
        );
        key_present(
            &mut out,
            "WindowsUpdate RebootRequired",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        );
        for (label, value) in [
            ("SystemSetupInProgress", "SystemSetupInProgress"),
            ("OOBEInProgress", "OOBEInProgress"),
        ] {
            match dword(r"SYSTEM\Setup", value) {
                Ok(Some(v)) if v != 0 => out.set.push(label.to_owned()),
                Ok(_) => {}
                Err(e) => out.unavailable.push(format!("{label}: {e}")),
            }
        }
        match non_empty_value(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "PendingFileRenameOperations",
        ) {
            Ok(true) => out.set.push("PendingFileRenameOperations".to_owned()),
            Ok(false) => {}
            Err(e) => out
                .unavailable
                .push(format!("PendingFileRenameOperations: {e}")),
        }
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let pending_xml = std::path::Path::new(&root)
            .join("WinSxS")
            .join("pending.xml");
        match pending_xml.try_exists() {
            Ok(true) => out.set.push("WinSxS pending.xml".to_owned()),
            Ok(false) => {}
            Err(e) => out.unavailable.push(format!("pending.xml: {e}")),
        }
        out
    }

    pub fn free_disk_bytes() -> Result<Option<u64>, String> {
        let root = std::env::var_os("SystemDrive").unwrap_or_else(|| "C:".into());
        let mut path = std::path::PathBuf::from(root);
        path.push("\\");
        let w: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut free = 0u64;
        // SAFETY: NUL terminated path and a valid out pointer; the other outputs are optional.
        let ok =
            unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, ptr::null_mut(), ptr::null_mut()) };
        if ok == 0 {
            Err("GetDiskFreeSpaceExW failed".to_owned())
        } else {
            Ok(Some(free))
        }
    }
}

/// Reads the indicators. Off Windows nothing can be read: every indicator is reported unavailable.
pub fn probe() -> PendingIndicators {
    #[cfg(windows)]
    {
        imp::probe()
    }
    #[cfg(not(windows))]
    {
        PendingIndicators {
            set: Vec::new(),
            unavailable: vec!["not a Windows host".to_owned()],
        }
    }
}

/// Free bytes on the system volume (`None` off Windows).
pub fn free_disk_bytes() -> Result<Option<u64>, String> {
    #[cfg(windows)]
    {
        imp::free_disk_bytes()
    }
    #[cfg(not(windows))]
    {
        Ok(None)
    }
}
