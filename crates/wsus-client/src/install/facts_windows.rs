//! `WindowsFacts`: the live fact provider on Windows, mirroring
//! `scripts/wsus/collect-facts.ps1` query by query (that script, including
//! its C# P/Invoke helper, is the reference; `facts-check` compares the two).
//!
//! UNVALIDATED: type-checked by cross-compilation only. Anything the
//! collector answers that this provider does not is `Unavailable`, never a
//! guess:
//!
//! * `wmi_query`: the collector uses `Get-CimInstance`; this provider has no
//!   WMI client and answers `Unavailable` (evaluator: Unknown);
//! * `msi_patch`: the collector does not collect it either (Unavailable).
//!
//! Semantics worth knowing (all copied from the collector):
//!
//! * registry: `HKLM` only; `Native` is the 64-bit view, `Wow32` the 32-bit
//!   view; a missing key or value is `Absent`, any other error `Unavailable`;
//!   `REG_EXPAND_SZ` data is returned unexpanded; the key path is trimmed of
//!   `\` at both ends;
//! * files: `[IO.File]::Exists` decides existence; the resolved path joins the
//!   base and the path with exactly one `\`, then collapses `\\+` to `\`, then
//!   turns `/` into `\` (in that order); version is the `VS_FIXEDFILEINFO` file
//!   version (as `FileVersionInfo.FileMajorPart...`), recorded when any part is
//!   non-zero or a `FileVersion` string exists; times are the UTC creation and
//!   last-write times of the file (`FileInfo`). The process must be a native
//!   64-bit one, or file system redirection changes `System32` answers;
//! * OS: `RtlGetVersion`, `GetNativeSystemInfo`, `GetSystemDefaultUILanguage`
//!   with `LCIDToLocaleName`, MUI installed when `EnumUILanguages` yields more
//!   than one language (an Unverified definition, copied);
//! * MSI: products are enumerated once with `MsiEnumProductsEx` for all
//!   contexts and kept when `MsiQueryProductState` is 3 to 5; features and
//!   components of an absent product are `Known(false)`;
//! * CBS: `CurrentState` (`REG_DWORD`) under
//!   `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\<id>`
//!   in the native view.
#![cfg(windows)]
use super::win_util::{from_wide, wide};
use std::{
    collections::HashMap, fs, os::windows::fs::MetadataExt, path::Path, ptr, sync::OnceLock,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS, FreeLibrary, HMODULE,
    },
    Globalization::{EnumUILanguagesW, GetSystemDefaultUILanguage, LCIDToLocaleName},
    Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
    },
    System::{
        ApplicationInstallationAndServicing::{
            MsiEnumPatchesExW, MsiEnumProductsExW, MsiGetProductInfoExW, MsiQueryComponentStateW,
            MsiQueryFeatureStateW, MsiQueryProductStateW,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryExW},
        Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, RegCloseKey,
            RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
        },
        SystemInformation::{GetNativeSystemInfo, GetProductInfo, OSVERSIONINFOEXW, SYSTEM_INFO},
    },
    UI::{Shell::SHGetFolderPathW, WindowsAndMessaging::GetSystemMetrics},
};
use wsus_protocol::applicability::{
    Fact, FactProvider, FileInfo, FileLocation, RegValue, RegView,
    facts::{CbsState, MsiProduct, OsInfo},
    value::{FileTime, Version},
};

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;
/// Ticks from 0001-01-01 to the FILETIME epoch 1601-01-01.
const FILETIME_TO_DOTNET_TICKS: i64 = 504_911_232_000_000_000;
const SL_E_VALUE_NOT_FOUND: i32 = 0xC004_F012_u32 as i32;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const MUI_LANGUAGE_NAME: u32 = 0x8;
const MSIINSTALLCONTEXT_ALL: u32 = 7;
/// `MSIPATCHSTATE_APPLIED`: patches applied to the product.
const MSIPATCHSTATE_APPLIED: u32 = 1;

type SlGetDword = unsafe extern "system" fn(*const u16, *mut u32) -> i32;

/// The live provider.
#[derive(Default)]
pub struct WindowsFacts {
    products: OnceLock<Result<HashMap<String, u32>, String>>,
}

impl WindowsFacts {
    pub fn new() -> Self {
        Self::default()
    }
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

enum Open {
    Key(Key),
    Absent,
    Failed(String),
}

fn open_key(view: RegView, subkey: &str) -> Open {
    let flag = match view {
        RegView::Native => KEY_WOW64_64KEY,
        RegView::Wow32 => KEY_WOW64_32KEY,
    };
    let name = wide(subkey.trim_matches('\\'));
    let mut h: HKEY = ptr::null_mut();
    // SAFETY: `name` is NUL terminated and `h` is a valid out pointer.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_READ | flag,
            &mut h,
        )
    };
    match rc {
        ERROR_SUCCESS => Open::Key(Key(h)),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Open::Absent,
        other => Open::Failed(format!("RegOpenKeyEx error {other}")),
    }
}

/// `GetProductInfo` of this machine: the `PRODUCT_*` value the real catalog's `OSSkuId` and `sku` device
/// attributes compare (Implementation decision, Unverified against a native agent).
fn product_sku(major: u32, minor: u32, sp_major: u16, sp_minor: u16) -> Option<u32> {
    let mut out = 0u32;
    // SAFETY: `out` is a valid out pointer.
    let ok = unsafe {
        GetProductInfo(
            major,
            minor,
            u32::from(sp_major),
            u32::from(sp_minor),
            &mut out,
        )
    };
    (ok != 0).then_some(out)
}

/// The update build revision (`UBR`), the fourth component of the OS version.
fn os_ubr() -> Option<u32> {
    match reg_value(
        RegView::Native,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "UBR",
    ) {
        Fact::Known(RegValue::Dword(d)) => Some(d),
        _ => None,
    }
}

fn utf16_units(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn read_value(key: &Key, name: &str) -> Fact<RegValue> {
    let wname = wide(name);
    let mut ty = 0u32;
    let mut size = 0u32;
    // SAFETY: a null data pointer asks for the size; all pointers are valid.
    let mut rc = unsafe {
        RegQueryValueExW(
            key.0,
            wname.as_ptr(),
            ptr::null(),
            &mut ty,
            ptr::null_mut(),
            &mut size,
        )
    };
    let mut data = Vec::new();
    for _ in 0..8 {
        if rc == ERROR_FILE_NOT_FOUND {
            return Fact::Absent;
        }
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            return Fact::unavailable(format!("RegQueryValueEx error {rc}"));
        }
        data = vec![0u8; size as usize + 2];
        let mut got = data.len() as u32;
        // SAFETY: `data` is writable for `got` bytes; the other pointers are valid.
        rc = unsafe {
            RegQueryValueExW(
                key.0,
                wname.as_ptr(),
                ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut got,
            )
        };
        if rc == ERROR_SUCCESS {
            data.truncate(got as usize);
            break;
        }
        if rc != ERROR_MORE_DATA {
            continue;
        }
        size = got.max(size.saturating_mul(2));
    }
    if rc != ERROR_SUCCESS {
        return if rc == ERROR_FILE_NOT_FOUND {
            Fact::Absent
        } else {
            Fact::unavailable(format!("RegQueryValueEx error {rc}"))
        };
    }
    Fact::Known(match ty {
        REG_DWORD if data.len() >= 4 => {
            RegValue::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        REG_QWORD if data.len() >= 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[..8]);
            RegValue::Qword(u64::from_le_bytes(b))
        }
        REG_DWORD | REG_QWORD => {
            return Fact::unavailable("registry value is shorter than its type");
        }
        REG_SZ => RegValue::Sz(from_wide(&utf16_units(&data))),
        REG_EXPAND_SZ => RegValue::ExpandSz(from_wide(&utf16_units(&data))),
        REG_MULTI_SZ => {
            let units = utf16_units(&data);
            let mut items: Vec<String> = units
                .split(|c| *c == 0)
                .map(String::from_utf16_lossy)
                .collect();
            while items.last().is_some_and(String::is_empty) {
                items.pop();
            }
            RegValue::MultiSz(items)
        }
        REG_BINARY => RegValue::Binary(data),
        // .NET RegistryValueKind: REG_NONE is `None`, undefined types `Unknown`.
        0 => RegValue::Other("REG_NONE".into()),
        _ => RegValue::Other("REG_UNKNOWN".into()),
    })
}

fn reg_value(view: RegView, subkey: &str, name: &str) -> Fact<RegValue> {
    match open_key(view, subkey) {
        Open::Absent => Fact::Absent,
        Open::Failed(e) => Fact::Unavailable(e),
        Open::Key(k) => read_value(&k, name),
    }
}

/// `Join-Prepend` of the collector.
fn join_prepend(base: &str, path: &str) -> String {
    let joined = format!(
        "{}\\{}",
        base.trim_end_matches('\\'),
        path.trim_start_matches('\\')
    );
    let mut out = String::with_capacity(joined.len());
    let mut run = 0usize;
    for c in joined.chars() {
        if c == '\\' {
            run += 1;
            if run == 1 {
                out.push('\\');
            }
        } else {
            run = 0;
            out.push(c);
        }
    }
    out.replace('/', "\\")
}

fn known_folder(csidl: i32) -> Result<String, String> {
    let mut buf = vec![0u16; 520];
    // SAFETY: the buffer holds 520 units (SHGetFolderPath needs MAX_PATH).
    let hr =
        unsafe { SHGetFolderPathW(ptr::null_mut(), csidl, ptr::null_mut(), 0, buf.as_mut_ptr()) };
    if hr == 0 {
        Ok(from_wide(&buf))
    } else {
        Err(format!("SHGetFolderPath failed, hr=0x{:08x}", hr as u32))
    }
}

fn file_version(path: &str) -> Option<[u32; 4]> {
    let w = wide(path);
    let mut handle = 0u32;
    // SAFETY: `w` is NUL terminated; `handle` is a valid out pointer.
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return None;
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is writable for `size` bytes.
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let root = wide("\\");
    let mut p: *mut core::ffi::c_void = ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `block` holds a version resource; on success `p` points into it.
    if unsafe { VerQueryValueW(block.as_ptr().cast(), root.as_ptr(), &mut p, &mut len) } == 0
        || p.is_null()
        || (len as usize) < size_of::<VS_FIXEDFILEINFO>()
    {
        return None;
    }
    // SAFETY: `p` points to at least size_of::<VS_FIXEDFILEINFO>() bytes inside
    // `block`; read_unaligned tolerates any alignment.
    let ffi: VS_FIXEDFILEINFO = unsafe { ptr::read_unaligned(p.cast()) };
    if ffi.dwSignature != 0xFEEF_04BD {
        return None;
    }
    Some([
        ffi.dwFileVersionMS >> 16,
        ffi.dwFileVersionMS & 0xFFFF,
        ffi.dwFileVersionLS >> 16,
        ffi.dwFileVersionLS & 0xFFFF,
    ])
}

/// Probes what the Defender launcher packages depend on: the FileVersion of
/// `System32\MpSigStub.exe` and `SysWOW64\MpSigStub.exe` and the native machine.
pub fn probe_stub_env() -> super::defender::StubEnv {
    use super::defender::{Machine, StubEnv};
    let version = |p: &std::path::Path| {
        file_version(&p.to_string_lossy()).map(|v| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]))
    };
    let system = super::win_util::system_directory().ok();
    let system_version = system
        .as_ref()
        .and_then(|d| version(&d.join("MpSigStub.exe")));
    let wow64_version = system
        .as_ref()
        .and_then(|d| d.parent().map(|r| r.join("SysWOW64").join("MpSigStub.exe")))
        .and_then(|p| version(&p));
    // SAFETY: SYSTEM_INFO is plain data; GetNativeSystemInfo fills it.
    let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `si` is a valid out pointer.
    unsafe { GetNativeSystemInfo(&mut si) };
    // SAFETY: reading the member the call just initialised.
    let arch = unsafe { si.Anonymous.Anonymous.wProcessorArchitecture };
    let host_machine = match arch {
        0 => Machine::X86,
        9 => Machine::X64,
        12 => Machine::Arm64,
        other => Machine::Other(other),
    };
    StubEnv {
        system_version,
        wow64_version,
        host_machine,
    }
}

fn file_version_string_present(path: &str) -> bool {
    let w = wide(path);
    let mut handle = 0u32;
    // SAFETY: as in `file_version`.
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return false;
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: as in `file_version`.
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return false;
    }
    let translations = wide("\\VarFileInfo\\Translation");
    let mut p: *mut core::ffi::c_void = ptr::null_mut();
    let mut len = 0u32;
    let mut candidates: Vec<String> = Vec::new();
    // SAFETY: as in `file_version`; the translation table is `len` bytes of
    // (language, codepage) u16 pairs.
    if unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            translations.as_ptr(),
            &mut p,
            &mut len,
        )
    } != 0
        && !p.is_null()
        && len >= 4
    {
        // SAFETY: `p` points to `len` readable bytes inside `block`.
        let raw = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len as usize) };
        for pair in raw.chunks_exact(4) {
            let lang = u16::from_le_bytes([pair[0], pair[1]]);
            let cp = u16::from_le_bytes([pair[2], pair[3]]);
            candidates.push(format!("{lang:04x}{cp:04x}"));
        }
    }
    candidates.extend(["040904b0".into(), "040904e4".into(), "04090000".into()]);
    for c in candidates {
        let q = wide(format!("\\StringFileInfo\\{c}\\FileVersion"));
        let mut sp: *mut core::ffi::c_void = ptr::null_mut();
        let mut sl = 0u32;
        // SAFETY: as above.
        if unsafe { VerQueryValueW(block.as_ptr().cast(), q.as_ptr(), &mut sp, &mut sl) } != 0
            && !sp.is_null()
            && sl > 1
        {
            return true;
        }
    }
    false
}

fn file_time(ft: u64) -> FileTime {
    FileTime(ft as i64 + FILETIME_TO_DOTNET_TICKS)
}

fn file_fact(loc: &FileLocation, path: &str) -> Fact<FileInfo> {
    let full = match loc {
        FileLocation::Csidl { csidl } => match known_folder(*csidl) {
            Ok(dir) => join_prepend(&dir, path),
            Err(e) => return Fact::Unavailable(e),
        },
        FileLocation::RegSz {
            view,
            subkey,
            value,
        } => match reg_value(*view, subkey, value) {
            Fact::Absent => return Fact::Absent,
            Fact::Unavailable(r) => return Fact::Unavailable(r),
            Fact::Known(RegValue::Sz(s)) | Fact::Known(RegValue::ExpandSz(s)) => {
                join_prepend(&s, path)
            }
            Fact::Known(_) => {
                return Fact::unavailable("base registry value is not REG_SZ or REG_EXPAND_SZ");
            }
        },
        FileLocation::Absolute => {
            if path.contains('%') {
                return Fact::unavailable(
                    "environment variable in an absolute path is not expanded",
                );
            }
            path.replace('/', "\\")
        }
    };
    let meta = match fs::metadata(Path::new(&full)) {
        Ok(m) if m.is_file() => m,
        Ok(_) => return Fact::Absent,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Fact::unavailable(format!("cannot inspect the file: {e}"));
        }
        Err(_) => return Fact::Absent,
    };
    let mut info = FileInfo {
        resolved_path: Some(full.clone()),
        size: Some(meta.len()),
        ..FileInfo::default()
    };
    let parts = file_version(&full);
    // Recorded when any numeric part is non-zero or a FileVersion string
    // exists (the collector's condition).
    let any_nonzero = parts.is_some_and(|p| p.iter().any(|x| *x != 0));
    if any_nonzero || file_version_string_present(&full) {
        info.version = Some(Version(parts.unwrap_or([0; 4])));
    }
    info.modified = Some(file_time(meta.last_write_time()));
    info.created = Some(file_time(meta.creation_time()));
    Fact::Known(info)
}

unsafe extern "system" fn collect_ui_language(lang: *const u16, lparam: isize) -> i32 {
    // SAFETY (caller contract): `lparam` is the address of a live
    // `Vec<String>` passed by `ui_languages`, `lang` a NUL-terminated string.
    let out = unsafe { &mut *(lparam as *mut Vec<String>) };
    let mut len = 0usize;
    // SAFETY: `lang` is NUL terminated per the EnumUILanguages contract.
    while unsafe { *lang.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units were just read from `lang`.
    let s = unsafe { std::slice::from_raw_parts(lang, len) };
    out.push(String::from_utf16_lossy(s));
    1
}

fn ui_languages() -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    // SAFETY: the callback only touches the Vec behind `lparam`, which lives
    // across the (synchronous) call.
    let ok = unsafe {
        EnumUILanguagesW(
            Some(collect_ui_language),
            MUI_LANGUAGE_NAME,
            (&mut out as *mut Vec<String>) as isize,
        )
    };
    if ok == 0 {
        return Err("EnumUILanguages failed".into());
    }
    Ok(out)
}

fn msi_products() -> Result<HashMap<String, u32>, String> {
    let mut map = HashMap::new();
    for index in 0u32.. {
        let mut code = [0u16; 39];
        let mut ctx = 0i32;
        // SAFETY: `code` holds the 39 units MsiEnumProductsEx requires; the
        // SID out parameters may be null.
        let rc = unsafe {
            MsiEnumProductsExW(
                ptr::null(),
                ptr::null(),
                MSIINSTALLCONTEXT_ALL,
                index,
                code.as_mut_ptr(),
                &mut ctx,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != 0 {
            return Err(format!("MsiEnumProductsEx returned {rc}"));
        }
        let text = from_wide(&code);
        let w = wide(&text);
        // SAFETY: `w` is NUL terminated.
        let state = unsafe { MsiQueryProductStateW(w.as_ptr()) };
        if (3..=5).contains(&state) {
            map.insert(text.to_ascii_uppercase(), ctx as u32);
        }
    }
    Ok(map)
}

fn product_info(product: &str, ctx: u32, prop: &str) -> Option<String> {
    let p = wide(product);
    let n = wide(prop);
    let mut cap = 512u32;
    for _ in 0..3 {
        let mut buf = vec![0u16; cap as usize];
        let mut len = cap;
        // SAFETY: `buf` is writable for `len` units; strings are NUL terminated.
        let rc = unsafe {
            MsiGetProductInfoExW(
                p.as_ptr(),
                ptr::null(),
                ctx as i32,
                n.as_ptr(),
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        match rc {
            0 => return Some(from_wide(&buf)),
            234 => cap = len + 1,
            _ => return None,
        }
    }
    None
}

impl WindowsFacts {
    fn products(&self) -> &Result<HashMap<String, u32>, String> {
        self.products.get_or_init(msi_products)
    }
}

impl FactProvider for WindowsFacts {
    fn reg_key_exists(&self, view: RegView, subkey: &str) -> Fact<()> {
        match open_key(view, subkey) {
            Open::Key(_) => Fact::Known(()),
            Open::Absent => Fact::Absent,
            Open::Failed(e) => Fact::Unavailable(e),
        }
    }

    fn reg_value(&self, view: RegView, subkey: &str, name: &str) -> Fact<RegValue> {
        reg_value(view, subkey, name)
    }

    fn reg_subkeys(&self, view: RegView, subkey: &str) -> Fact<Vec<String>> {
        let key = match open_key(view, subkey) {
            Open::Key(k) => k,
            Open::Absent => return Fact::Absent,
            Open::Failed(e) => return Fact::Unavailable(e),
        };
        let mut names = Vec::new();
        for index in 0u32.. {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            // SAFETY: `buf` holds `len` units; unused out parameters are null.
            let rc = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Fact::unavailable(format!("RegEnumKeyEx error {rc}"));
            }
            names.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
        Fact::Known(names)
    }

    fn file(&self, loc: &FileLocation, path: &str) -> Fact<FileInfo> {
        file_fact(loc, path)
    }

    fn os(&self) -> Fact<OsInfo> {
        // SAFETY: OSVERSIONINFOEXW is plain data; all-zero is a valid start.
        let mut v: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
        v.dwOSVersionInfoSize = size_of::<OSVERSIONINFOEXW>() as u32;
        // SAFETY: RtlGetVersion accepts an OSVERSIONINFOEXW through the
        // OSVERSIONINFOW pointer when dwOSVersionInfoSize says so.
        let st = unsafe {
            windows_sys::Wdk::System::SystemServices::RtlGetVersion(
                (&mut v as *mut OSVERSIONINFOEXW).cast(),
            )
        };
        if st != 0 {
            return Fact::unavailable(format!("RtlGetVersion returned {st}"));
        }
        Fact::Known(OsInfo {
            major: v.dwMajorVersion,
            minor: v.dwMinorVersion,
            build: v.dwBuildNumber,
            sp_major: u32::from(v.wServicePackMajor),
            sp_minor: u32::from(v.wServicePackMinor),
            product_type: u32::from(v.wProductType),
            suite_mask: u32::from(v.wSuiteMask),
            sku: product_sku(
                v.dwMajorVersion,
                v.dwMinorVersion,
                v.wServicePackMajor,
                v.wServicePackMinor,
            ),
            ubr: os_ubr(),
        })
    }

    fn processor_architecture(&self) -> Fact<u32> {
        // SAFETY: SYSTEM_INFO is plain data; GetNativeSystemInfo fills it.
        let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: `si` is a valid out pointer.
        unsafe { GetNativeSystemInfo(&mut si) };
        // SAFETY: reading the processor architecture member of the union the
        // call just initialised.
        Fact::Known(u32::from(unsafe {
            si.Anonymous.Anonymous.wProcessorArchitecture
        }))
    }

    fn system_metric(&self, index: i32) -> Fact<i32> {
        // SAFETY: GetSystemMetrics has no pointer arguments.
        Fact::Known(unsafe { GetSystemMetrics(index) })
    }

    fn windows_language(&self) -> Fact<String> {
        // SAFETY: no arguments.
        let lcid = u32::from(unsafe { GetSystemDefaultUILanguage() });
        let mut buf = [0u16; 85];
        // SAFETY: the buffer holds `buf.len()` units.
        let n = unsafe { LCIDToLocaleName(lcid, buf.as_mut_ptr(), buf.len() as i32, 0) };
        if n <= 0 {
            return Fact::unavailable(format!("LCIDToLocaleName failed for 0x{lcid:04x}"));
        }
        Fact::Known(from_wide(&buf))
    }

    fn mui_installed(&self) -> Fact<bool> {
        match ui_languages() {
            Ok(l) => Fact::Known(l.len() > 1),
            Err(e) => Fact::Unavailable(e),
        }
    }

    fn license_dword(&self, name: &str) -> Fact<u32> {
        let dll = wide("slc.dll");
        // SAFETY: NUL terminated name; only the system directory is searched.
        let module: HMODULE =
            unsafe { LoadLibraryExW(dll.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Fact::unavailable("slc.dll cannot be loaded");
        }
        // SAFETY: `module` is a valid loaded module; the name is NUL terminated.
        let proc =
            unsafe { GetProcAddress(module, c"SLGetWindowsInformationDWORD".as_ptr().cast()) };
        let result = match proc {
            None => Fact::unavailable("SLGetWindowsInformationDWORD is not exported"),
            Some(p) => {
                // SAFETY: the export has the signature
                // HRESULT SLGetWindowsInformationDWORD(PCWSTR, DWORD*).
                let f: SlGetDword = unsafe { std::mem::transmute(p) };
                let n = wide(name);
                let mut v = 0u32;
                // SAFETY: valid NUL terminated name and out pointer.
                let hr = unsafe { f(n.as_ptr(), &mut v) };
                if hr == 0 {
                    Fact::Known(v)
                } else if hr == SL_E_VALUE_NOT_FOUND {
                    Fact::Absent
                } else {
                    Fact::unavailable(format!(
                        "SLGetWindowsInformationDWORD hr=0x{:08x}",
                        hr as u32
                    ))
                }
            }
        };
        // SAFETY: `module` was loaded above and is released once; `f` is not
        // used afterwards.
        unsafe { FreeLibrary(module) };
        result
    }

    fn wmi_query(&self, _namespace: &str, _wql: &str) -> Fact<bool> {
        Fact::unavailable("WMI queries are not implemented by WindowsFacts")
    }

    fn msi_product(&self, product: &str) -> Fact<MsiProduct> {
        let products = match self.products() {
            Ok(p) => p,
            Err(e) => return Fact::unavailable(e.clone()),
        };
        let Some(ctx) = products.get(&product.to_ascii_uppercase()) else {
            return Fact::Absent;
        };
        let version = product_info(product, *ctx, "VersionString").unwrap_or_default();
        let language = product_info(product, *ctx, "Language").and_then(|l| l.trim().parse().ok());
        Fact::Known(MsiProduct { version, language })
    }

    fn msi_feature(&self, product: &str, feature: &str) -> Fact<bool> {
        let products = match self.products() {
            Ok(p) => p,
            Err(e) => return Fact::unavailable(e.clone()),
        };
        if !products.contains_key(&product.to_ascii_uppercase()) {
            return Fact::Known(false);
        }
        let (p, f) = (wide(product), wide(feature));
        // SAFETY: NUL terminated strings.
        let st = unsafe { MsiQueryFeatureStateW(p.as_ptr(), f.as_ptr()) };
        Fact::Known((3..=5).contains(&st))
    }

    fn msi_component(&self, product: &str, component: &str) -> Fact<bool> {
        let products = match self.products() {
            Ok(p) => p,
            Err(e) => return Fact::unavailable(e.clone()),
        };
        let Some(ctx) = products.get(&product.to_ascii_uppercase()) else {
            return Fact::Known(false);
        };
        let (p, c) = (wide(product), wide(component));
        let mut state = 0i32;
        // SAFETY: NUL terminated strings and a valid out pointer.
        let rc = unsafe {
            MsiQueryComponentStateW(p.as_ptr(), ptr::null(), *ctx as i32, c.as_ptr(), &mut state)
        };
        if rc != 0 {
            return Fact::unavailable(format!("MsiQueryComponentState error {rc}"));
        }
        Fact::Known((3..=5).contains(&state))
    }

    /// Is `patch` applied to `product`: enumerated with `MsiEnumPatchesEx` (filter: applied) in
    /// the install context of the product. The reference collector does not record patches, so
    /// this fact has no collector counterpart to compare with.
    fn msi_patch(&self, product: &str, patch: &str) -> Fact<bool> {
        let products = match self.products() {
            Ok(p) => p,
            Err(e) => return Fact::unavailable(e.clone()),
        };
        let Some(ctx) = products.get(&product.to_ascii_uppercase()) else {
            return Fact::Known(false);
        };
        let p = wide(product);
        for index in 0u32.. {
            let mut code = [0u16; 39];
            let mut target = [0u16; 39];
            let mut target_ctx = 0i32;
            // SAFETY: `p` is NUL terminated; `code` and `target` hold the 39 units the API
            // requires; the SID out parameters may be null.
            let rc = unsafe {
                MsiEnumPatchesExW(
                    p.as_ptr(),
                    ptr::null(),
                    *ctx,
                    MSIPATCHSTATE_APPLIED,
                    index,
                    code.as_mut_ptr(),
                    target.as_mut_ptr(),
                    &mut target_ctx,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != 0 {
                return Fact::unavailable(format!("MsiEnumPatchesEx returned {rc}"));
            }
            if from_wide(&code).eq_ignore_ascii_case(patch) {
                return Fact::Known(true);
            }
        }
        Fact::Known(false)
    }

    fn cbs_package(&self, identity: &str) -> Fact<CbsState> {
        let sub = format!(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages\\{identity}"
        );
        match reg_value(RegView::Native, &sub, "CurrentState") {
            Fact::Known(RegValue::Dword(v)) => Fact::Known(v),
            Fact::Known(_) => Fact::unavailable("CurrentState is not a REG_DWORD"),
            Fact::Unavailable(r) => Fact::Unavailable(r),
            Fact::Absent => match open_key(RegView::Native, &sub) {
                Open::Absent => Fact::Absent,
                Open::Key(_) => {
                    Fact::unavailable("package key exists without a CurrentState value")
                }
                Open::Failed(e) => Fact::Unavailable(e),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_matches_the_collector() {
        assert_eq!(
            join_prepend("C:\\ProgramData\\X\\", "\\a\\b.vdm"),
            "C:\\ProgramData\\X\\a\\b.vdm"
        );
        // duplicates collapse BEFORE slashes are converted, as in the script
        assert_eq!(join_prepend("C:\\X", "a//b"), "C:\\X\\a\\\\b");
        assert_eq!(join_prepend("\\\\srv\\share", "f"), "\\srv\\share\\f");
    }

    #[test]
    #[ignore = "Windows guest only"]
    fn reads_the_live_os() {
        let f = WindowsFacts::new();
        assert!(matches!(f.os(), Fact::Known(o) if o.major >= 10));
        assert!(matches!(f.processor_architecture(), Fact::Known(_)));
        assert!(matches!(
            f.reg_key_exists(
                RegView::Native,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            ),
            Fact::Known(())
        ));
    }
}
