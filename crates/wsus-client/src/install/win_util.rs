//! Small Windows helpers shared by the Windows-only modules.
#![cfg(windows)]
use super::handler_log::{DetachedProcess, ProcessWatcher};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::PathBuf};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        SystemInformation::GetSystemDirectoryW,
        Threading::{
            GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

/// NUL-terminated UTF-16 of `s`.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Text of a UTF-16 buffer up to the first NUL.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// True when the process token is elevated (UAC) or the account is SYSTEM.
pub fn is_elevated() -> Result<bool, String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no close;
    // `token` is a valid out pointer for the duration of the call.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err("OpenProcessToken failed".into());
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: `token` is the valid token handle opened above; the output
    // buffer is a TOKEN_ELEVATION and its exact size is passed.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` was opened by OpenProcessToken above and is closed once.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err("GetTokenInformation(TokenElevation) failed".into());
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// The Windows system directory (`C:\Windows\System32`).
pub fn system_directory() -> Result<PathBuf, String> {
    let mut buf = vec![0u16; 520];
    // SAFETY: the buffer is writable for `buf.len()` UTF-16 units.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return Err("GetSystemDirectoryW failed".into());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
}

/// Lists processes by image name with `CreateToolhelp32Snapshot`; the start
/// time comes from `GetProcessTimes` when the process can be opened. Never
/// signals or kills a process. UNVALIDATED until run on a guest.
#[derive(Debug, Clone, Copy, Default)]
pub struct ToolhelpWatcher;

fn start_unix(pid: u32) -> Option<i64> {
    // SAFETY: plain call; the returned handle is closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let z = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    // SAFETY: `h` is a valid process handle; the out pointers are valid.
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) };
    // SAFETY: `h` was opened above and is closed once.
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return None;
    }
    let ft = (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime);
    Some((ft / 10_000_000) as i64 - 11_644_473_600)
}

impl ProcessWatcher for ToolhelpWatcher {
    fn running(&self, image_name: &str) -> Vec<DetachedProcess> {
        let mut out = Vec::new();
        // SAFETY: plain call; the snapshot handle is closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        // SAFETY: PROCESSENTRY32W is plain data; dwSize is set as required.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: `snap` is valid and `entry` is a valid out structure.
        let mut more = unsafe { Process32FirstW(snap, &mut entry) } != 0;
        while more {
            let name = from_wide(&entry.szExeFile);
            if name.eq_ignore_ascii_case(image_name) {
                out.push(DetachedProcess {
                    name,
                    pid: entry.th32ProcessID,
                    started_unix: start_unix(entry.th32ProcessID),
                });
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap, &mut entry) } != 0;
        }
        // SAFETY: `snap` was opened above and is closed once.
        unsafe { CloseHandle(snap) };
        out
    }
}
