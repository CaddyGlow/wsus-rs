//! Authenticode verification through `WinVerifyTrust` (Windows). UNVALIDATED:
//! written against the documentation and type-checked by cross-compilation
//! only; the first run on a guest is the first test.
//!
//! Policy: `WINTRUST_ACTION_GENERIC_VERIFY_V2` on the open file handle, no
//! UI, revocation checking off and URL retrieval from the cache only (the
//! guest may have no route to the CRL hosts; the signer allowlist is the
//! control), embedded signatures only (no catalog lookup). The signer is the
//! first signer's leaf certificate.
#![cfg(windows)]
use super::{
    signature::{SignatureError, SignatureInfo, SignatureVerifier},
    win_util::wide,
};
use std::{fs::File, os::windows::io::AsRawHandle, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Cryptography::{
            CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
            CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA1_HASH_PROP_ID,
            CertGetCertificateContextProperty, CertGetNameStringW,
        },
        WinTrust::{
            CRYPT_PROVIDER_DATA, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
            WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
            WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
            WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
        },
    },
};

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;

/// `WinVerifyTrust` based verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinVerifyTrustVerifier;

fn cert_name(
    ctx: *const CERT_CONTEXT,
    kind: u32,
    flags: u32,
    para: *const core::ffi::c_void,
) -> Option<String> {
    // SAFETY: `ctx` is a certificate context owned by the open WinVerifyTrust
    // state; a null buffer asks for the required length.
    let len = unsafe { CertGetNameStringW(ctx, kind, flags, para, ptr::null_mut(), 0) };
    if len <= 1 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: the buffer holds `len` UTF-16 units.
    let n = unsafe { CertGetNameStringW(ctx, kind, flags, para, buf.as_mut_ptr(), len) };
    if n <= 1 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..(n as usize - 1)]))
}

fn thumbprint(ctx: *const CERT_CONTEXT) -> Option<String> {
    let mut buf = [0u8; 20];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is writable for `len` bytes; `ctx` is valid (see above).
    let ok = unsafe {
        CertGetCertificateContextProperty(
            ctx,
            CERT_SHA1_HASH_PROP_ID,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (ok != 0).then(|| {
        buf[..len as usize]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    })
}

/// Closes the WinVerifyTrust state on drop.
struct State<'a> {
    data: &'a mut WINTRUST_DATA,
    action: windows_sys::core::GUID,
}

impl Drop for State<'_> {
    fn drop(&mut self) {
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: `data` is the same structure passed to the VERIFY call; the
        // CLOSE action releases the state handle it holds.
        unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut self.action,
                (self.data as *mut WINTRUST_DATA).cast(),
            );
        }
    }
}

impl SignatureVerifier for WinVerifyTrustVerifier {
    fn verify(&self, file: &File, path: &Path) -> Result<SignatureInfo, SignatureError> {
        let name = wide(path);
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: name.as_ptr(),
            hFile: file.as_raw_handle() as HANDLE,
            pgKnownSubject: ptr::null_mut(),
        };
        // SAFETY: WINTRUST_DATA is plain data for which all-zero is the
        // documented initial state.
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file_info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` and `file_info` outlive the call and the CLOSE call
        // made by `State::drop`; `name` stays alive through both.
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        let state = State {
            data: &mut data,
            action,
        };
        if status != 0 {
            return Err(match status {
                TRUST_E_NOSIGNATURE | TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN => {
                    SignatureError::NotSigned(format!("WinVerifyTrust 0x{:08x}", status as u32))
                }
                other => SignatureError::Invalid(format!("WinVerifyTrust 0x{:08x}", other as u32)),
            });
        }
        // SAFETY: the state handle is valid until `State` is dropped.
        let provider: *mut CRYPT_PROVIDER_DATA =
            unsafe { WTHelperProvDataFromStateData(state.data.hWVTStateData) };
        if provider.is_null() {
            return Err(SignatureError::Signer("no provider data".into()));
        }
        // SAFETY: `provider` is valid while the state is open.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
        if signer.is_null() {
            return Err(SignatureError::Signer("no signer".into()));
        }
        // SAFETY: `signer` is valid while the state is open.
        let cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
        if cert.is_null() {
            return Err(SignatureError::Signer("no signing certificate".into()));
        }
        // SAFETY: `cert` is valid while the state is open.
        let ctx = unsafe { (*cert).pCert };
        if ctx.is_null() {
            return Err(SignatureError::Signer("no certificate context".into()));
        }
        let cn = cert_name(ctx, CERT_NAME_ATTR_TYPE, 0, c"2.5.4.3".as_ptr().cast());
        let org = cert_name(ctx, CERT_NAME_ATTR_TYPE, 0, c"2.5.4.10".as_ptr().cast());
        let issuer = cert_name(
            ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            ptr::null(),
        );
        Ok(SignatureInfo {
            subject_cn: cn,
            organization: org,
            issuer,
            thumbprint: thumbprint(ctx),
        })
    }
}
