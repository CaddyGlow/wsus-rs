//! Windows-only tests of the Windows fact provider, the signature gate and the
//! process runner. All are `#[ignore]`: run them on a disposable guest with
//!
//! ```text
//! cargo test -p wsus-client --test install_windows -- --ignored --nocapture
//! ```
//!
//! They are UNRUN until a guest executes them; see `docs/wsus-install.md`.
#![cfg(windows)]
use std::{fs::File, path::Path, time::Duration};
use wsus_client::install::{
    facts_windows::WindowsFacts,
    runner::{ProcessRunner, RunRequest, Runner},
    signature::{SignatureError, SignatureVerifier, TrustPolicy},
    signature_windows::WinVerifyTrustVerifier,
};
use wsus_protocol::applicability::{Fact, FactProvider, FileLocation, RegValue, RegView};

#[test]
#[ignore = "Windows guest only"]
fn registry_views_and_values() {
    let f = WindowsFacts::new();
    let cv = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    assert!(matches!(
        f.reg_key_exists(RegView::Native, cv),
        Fact::Known(())
    ));
    assert!(matches!(
        f.reg_value(RegView::Native, cv, "CurrentBuildNumber"),
        Fact::Known(RegValue::Sz(_))
    ));
    assert!(matches!(
        f.reg_value(RegView::Native, cv, "NoSuchValue"),
        Fact::Absent
    ));
    assert!(matches!(
        f.reg_key_exists(RegView::Native, "SOFTWARE\\NoSuchKeyWsus"),
        Fact::Absent
    ));
    match f.reg_subkeys(RegView::Native, "SOFTWARE\\Microsoft") {
        Fact::Known(v) => assert!(!v.is_empty()),
        other => panic!("{other:?}"),
    }
}

#[test]
#[ignore = "Windows guest only"]
fn os_files_and_license() {
    let f = WindowsFacts::new();
    assert!(matches!(f.os(), Fact::Known(o) if o.major >= 10));
    assert!(matches!(f.windows_language(), Fact::Known(l) if l.contains('-')));
    // CSIDL_SYSTEM = 0x25: kernel32.dll has a version, a size and times.
    match f.file(&FileLocation::Csidl { csidl: 0x25 }, "kernel32.dll") {
        Fact::Known(i) => {
            assert!(i.version.is_some() && i.size.unwrap() > 0 && i.modified.is_some());
            eprintln!("kernel32: {i:?}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        f.file(&FileLocation::Absolute, "C:\\no\\such\\file.dll"),
        Fact::Absent
    ));
    assert!(matches!(
        f.file(&FileLocation::Absolute, "%windir%\\notepad.exe"),
        Fact::Unavailable(_)
    ));
    eprintln!(
        "license sample: {:?}",
        f.license_dword("CE163B38-1AEC-47AF-854D-FC90ABD6951C")
    );
    assert!(matches!(
        f.wmi_query("root\\cimv2", "SELECT * FROM Win32_OperatingSystem"),
        Fact::Unavailable(_)
    ));
}

#[test]
#[ignore = "Windows guest only"]
fn process_runner_captures_the_exit_code() {
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let cmd = Path::new(&sys).join("System32").join("cmd.exe");
    let r = ProcessRunner
        .run(&RunRequest {
            program: cmd,
            args: vec!["/c".into(), "exit".into(), "3".into()],
            cwd: std::env::temp_dir(),
            timeout: Duration::from_secs(20),
            output_limit: 1024,
            kill_on_timeout: true,
        })
        .unwrap();
    assert_eq!(r.exit_code, Some(3));
}

#[test]
#[ignore = "Windows guest only; needs Windows Defender's MpCmdRun.exe (embedded Microsoft signature)"]
fn signature_gate_accepts_microsoft_and_refuses_unsigned() {
    let signed = Path::new("C:\\Program Files\\Windows Defender\\MpCmdRun.exe");
    if signed.is_file() {
        let file = File::open(signed).unwrap();
        let info = WinVerifyTrustVerifier.verify(&file, signed).unwrap();
        eprintln!("MpCmdRun signer: {info:?}");
        TrustPolicy::default().check(&info).unwrap();
    } else {
        eprintln!("MpCmdRun.exe not present; skipping the positive case");
    }
    // An unsigned file must be refused.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("unsigned.exe");
    std::fs::write(&p, b"MZ not a real executable").unwrap();
    let file = File::open(&p).unwrap();
    assert!(matches!(
        WinVerifyTrustVerifier.verify(&file, &p),
        Err(SignatureError::NotSigned(_)) | Err(SignatureError::Invalid(_))
    ));
}
