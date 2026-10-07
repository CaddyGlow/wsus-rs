//! Guards the Windows application manifest. Without a manifest declaring Windows 10/11 support,
//! Windows reports OS file versions as 6.2 to the process (observed 2026-10-05, 11 of 132 file
//! facts disagreed with the PowerShell collector). Host check only: that the manifest is
//! embedded in the built exe can be verified only on the Windows build.
use std::fs;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn manifest_declares_windows_10_11_and_build_script_embeds_it() {
    let m = fs::read_to_string(format!("{DIR}/wsus.exe.manifest")).unwrap();
    assert!(m.contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"));
    assert!(m.contains("asInvoker"));
    let b = fs::read_to_string(format!("{DIR}/build.rs")).unwrap();
    assert!(b.contains("wsus.exe.manifest"));
    assert!(b.contains("/MANIFEST:EMBED") && b.contains("/MANIFESTINPUT"));
}
