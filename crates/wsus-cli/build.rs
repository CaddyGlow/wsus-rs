//! Embed an application manifest declaring Windows 10/11 compatibility in the Windows binary.
//!
//! A process without a compatibility manifest gets Windows' version-lie behaviour: version APIs
//! and the file versions of operating-system files report 6.2. The applicability evaluator reads
//! those versions, so the manifest is required for correct decisions, not cosmetic.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wsus.exe.manifest");
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .join("wsus.exe.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
