//! ACL check used by the path policy (Windows). UNVALIDATED: written against
//! the documentation and type-checked by cross-compilation only.
#![cfg(windows)]
use super::win_util::wide;
use std::{fs, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, LocalFree},
    Security::{
        ACL,
        Authorization::{
            BuildTrusteeWithSidW, ConvertStringSidToSidW, GetEffectiveRightsFromAclW,
            GetNamedSecurityInfoW, SE_FILE_OBJECT, TRUSTEE_W,
        },
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    },
};

const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const FILE_DELETE_CHILD: u32 = 0x40;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;

/// Everyone, Authenticated Users, BUILTIN\Users.
const BROAD_SIDS: [&str; 3] = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];

/// True when one of the broad groups can modify or replace `path` (for a
/// directory: delete it or its children, or change its ACL or owner; adding
/// new files is not counted, ProgramData grants that to Users).
pub fn grants_write_to_everyone(path: &Path) -> Result<bool, String> {
    let is_dir = fs::metadata(path)
        .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?
        .is_dir();
    let dangerous = if is_dir {
        DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER
    } else {
        FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER
    };
    let name = wide(path);
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `name` is NUL terminated; the out pointers are valid; on
    // success `sd` owns the memory `dacl` points into and is freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("GetNamedSecurityInfo failed: {rc}"));
    }
    let result = (|| {
        if dacl.is_null() {
            // A NULL DACL grants everyone full access.
            return Ok(true);
        }
        for sid_text in BROAD_SIDS {
            let text = wide(sid_text);
            let mut sid: PSID = ptr::null_mut();
            // SAFETY: `text` is NUL terminated; `sid` receives a LocalAlloc
            // block that is freed below.
            if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
                return Err(format!("cannot build the SID {sid_text}"));
            }
            // SAFETY: TRUSTEE_W is plain data; BuildTrusteeWithSidW fills it
            // from the valid `sid`, which outlives the use below.
            let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
            unsafe { BuildTrusteeWithSidW(&mut trustee, sid) };
            let mut mask = 0u32;
            // SAFETY: `dacl` is non-null and valid while `sd` is alive; the
            // trustee and the out pointer are valid.
            let rc = unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut mask) };
            // SAFETY: `sid` came from ConvertStringSidToSidW (LocalAlloc).
            unsafe { LocalFree(sid) };
            if rc != ERROR_SUCCESS {
                return Err(format!("GetEffectiveRightsFromAcl failed: {rc}"));
            }
            if mask & dangerous != 0 {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    // SAFETY: `sd` was allocated by GetNamedSecurityInfoW (LocalAlloc).
    unsafe { LocalFree(sd) };
    result
}
