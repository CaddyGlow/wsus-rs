//! Microsoft Defender definition-update packages: what the plan and the
//! executor must know about the "launcher" family.
//!
//! Every package of the family (`AM_Engine`, `AM_Base`, `AM_Delta`, their
//! `*_Patch_*` variants, `AM_Slim_*` and `AS_*`) is one launcher program with
//! a different resource section (READ, inventory 12.13). The launcher runs
//! `System32\MpSigStub.exe` and hands the package to it through a named pipe
//! whose name is derived from the PARENT process of the launcher (parent PID
//! and creation time), so:
//!
//! * all packages of one update run must be started by the same process
//!   (the executor starts every step itself, so it is the common parent);
//! * the stub accumulates packages until the **terminal** package arrives (the
//!   one carrying the `BINARY/MPSIGSTUB` marker resource: OBSERVED on every
//!   `AM_Delta`, `AM_Delta_Patch_*`, `AM_Slim_Delta*` and `AS_Delta*` package of
//!   the lab catalog, and absent from every Engine, Engine patch, Base and Base
//!   patch package), then applies the update and sends its final HRESULT to the
//!   terminal package, whose exit code it becomes. The other packages exit 0
//!   after about a second whatever happens;
//! * without a terminal package the stub waits `ConnectTimeoutMS` (120 s),
//!   logs `0x800705b4` and updates nothing, while every package exits 0 (OBSERVED
//!   on a guest, inventory 12.12);
//! * the launcher requires `System32\MpSigStub.exe` to be exactly
//!   [`EXPECTED_STUB_VERSION`] (`0x80070650` otherwise; a 32-bit launcher
//!   looks in `SysWOW64` and exits `0x80070002` when it is missing: OBSERVED).
use super::plan::InstallStep;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};

/// The stub version every launcher of the lab catalog requires (READ:
/// constant `0x100015DCA07D1` in the launcher; OBSERVED in the version
/// resource of all packages).
pub const EXPECTED_STUB_VERSION: &str = "1.1.24010.2001";

/// Which package of an update run a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageRole {
    Engine,
    EnginePatch,
    Base,
    BasePatch,
    Delta,
    DeltaPatch,
}

/// The product line of the package name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flavor {
    /// `AM_*`
    Full,
    /// `AM_Slim_*`
    Slim,
    /// `AS_*` (antispyware)
    Antispyware,
}

/// A recognised launcher package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LauncherPackage {
    pub role: PackageRole,
    pub flavor: Flavor,
    /// The source version of a `*_Patch_<version>` package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
}

impl LauncherPackage {
    /// True for the packages that carry the stub's "last package" marker.
    pub fn is_terminal(&self) -> bool {
        matches!(self.role, PackageRole::Delta | PackageRole::DeltaPatch)
    }
}

/// Recognises a Defender launcher package by its file name
/// (`AM_Delta_Patch_1.459.537.0.exe`, `AS_Base.exe`, ...).
pub fn classify_package(file_name: &str) -> Option<LauncherPackage> {
    let lower = file_name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe")?;
    let (flavor, rest) = if let Some(r) = stem.strip_prefix("am_slim_") {
        (Flavor::Slim, r)
    } else if let Some(r) = stem.strip_prefix("am_") {
        (Flavor::Full, r)
    } else if let Some(r) = stem.strip_prefix("as_") {
        (Flavor::Antispyware, r)
    } else {
        return None;
    };
    let version = |s: &str| -> Option<String> {
        (!s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')).then(|| s.to_owned())
    };
    let (role, from_version) = match rest {
        "engine" => (PackageRole::Engine, None),
        "base" => (PackageRole::Base, None),
        "delta" => (PackageRole::Delta, None),
        _ => {
            if let Some(v) = rest.strip_prefix("engine_patch_") {
                (PackageRole::EnginePatch, Some(version(v)?))
            } else if let Some(v) = rest.strip_prefix("delta_patch_") {
                (PackageRole::DeltaPatch, Some(version(v)?))
            } else if rest
                .strip_prefix("base_patch")
                .is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()))
            {
                (PackageRole::BasePatch, None)
            } else {
                return None;
            }
        }
    };
    Some(LauncherPackage {
        role,
        flavor,
        from_version,
    })
}

/// Orders and validates the steps of a plan that contains launcher packages.
///
/// Steps that are not launcher packages (for example the `MpSigStub.exe`
/// installation) keep their relative order and come first; then the
/// non-terminal launcher packages in plan order; the single terminal package
/// last. A selection that would leave the stub waiting (no terminal package)
/// or that contains more than one terminal package is refused with the reason.
pub fn arrange(steps: Vec<InstallStep>) -> Result<Vec<InstallStep>, String> {
    if !steps.iter().any(|s| s.launcher.is_some()) {
        return Ok(steps);
    }
    let terminals: Vec<&InstallStep> = steps
        .iter()
        .filter(|s| {
            s.launcher
                .as_ref()
                .is_some_and(LauncherPackage::is_terminal)
        })
        .collect();
    match terminals.len() {
        0 => {
            let names: Vec<&str> = steps
                .iter()
                .filter(|s| s.launcher.is_some())
                .map(|s| s.payload.file_name.as_str())
                .collect();
            return Err(format!(
                "the selected Defender packages ({}) contain no terminal package (a Delta or Delta patch \
                 package): MpSigStub.exe would wait for one until it times out (0x800705b4) and update \
                 nothing, although every package exits 0",
                names.join(", ")
            ));
        }
        1 => {}
        n => {
            return Err(format!(
                "{n} terminal Defender packages are selected ({}): one update run takes exactly one \
                 (the stub applies the update when the terminal package arrives)",
                terminals
                    .iter()
                    .map(|s| s.payload.file_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let rank = |s: &InstallStep| match &s.launcher {
        None => 0,
        Some(l) if !l.is_terminal() => 1,
        Some(_) => 2,
    };
    let mut out = steps;
    out.sort_by_key(rank); // stable
    Ok(out)
}

/// What the stub's exit code means (OBSERVED codes are marked in the
/// reason; the rest is READ from the stub, inventory 12.12 and 12.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitDescription {
    /// `0x%08x`.
    pub hresult: String,
    pub name: String,
    pub reason: String,
}

/// Describes the exit code of the TERMINAL package, which is the stub's final
/// HRESULT. Exit codes of other packages are not the stub's result.
pub fn describe_exit(code: i32) -> ExitDescription {
    let u = code as u32;
    let (name, reason): (&str, String) = match u {
        0 => (
            "success",
            "the stub reported success (also returned when no product needed the update; check the log)".into(),
        ),
        0x8007_0670 => (
            "no_patch_for_installed_version",
            "no patch matches the installed definition version (`No patch for <version>; sequence is incorrect`, OBSERVED); nothing was changed".into(),
        ),
        0x8007_066F => (
            "bdd_tolerated",
            "the delta destination version is not newer than the installed one; the stub tolerates this and normally exits 0".into(),
        ),
        0x8007_05B4 => (
            "accumulate_timeout",
            "the stub timed out waiting for the next package (no terminal package arrived); nothing was updated (OBSERVED)".into(),
        ),
        0x8000_000A => (
            "platform_update_pending",
            "a platform update is pending; the stub exits success-like and nothing more was applied".into(),
        ),
        0x8007_0650 => (
            "stub_version_mismatch",
            format!("System32\\MpSigStub.exe is not version {EXPECTED_STUB_VERSION}"),
        ),
        0x8007_0002 => (
            "stub_not_found",
            "the launcher could not find MpSigStub.exe (a 32-bit package on a 64-bit host looks in SysWOW64, OBSERVED)".into(),
        ),
        0x8007_000D => (
            "invalid_data",
            "invalid data: a patch failed its CRC or a chunk overran, or the pipe message was inconsistent (OBSERVED for a corrupted patch)".into(),
        ),
        0x8007_042B => (
            "stub_exited",
            "the stub process exited before the package could be handed over".into(),
        ),
        0x8007_0020 => (
            "different_parent",
            "the package was started from a different parent process than the stub's".into(),
        ),
        0x8000_FFFF => (
            "parent_changed",
            "the parent process of the update run changed or was recycled".into(),
        ),
        0x8007_051A => (
            "older_version_after_update",
            "validation found an older version than expected after the update".into(),
        ),
        0x8007_00A0 => (
            "patch_source_range",
            "a patch read beyond the old file".into(),
        ),
        0x8000_4005 => ("unspecified_failure", "unspecified failure inside the stub".into()),
        0xC00E_4102 => (
            "patch_api_failure",
            "mspatcha.dll failed (OBSERVED for a patch container the stub does not dispatch to its own applier)".into(),
        ),
        _ if u & 0xFFFF_0000 == 0x8499_0000 => (
            "mpsp_patch_error",
            format!(
                "the stub's patch decoder failed (error {} of the MPSP family: 1026 = size or CRC mismatch, OBSERVED for a patch applied to a modified source file; 1017 = codec error, OBSERVED for a corrupted stream)",
                u & 0xFFFF
            ),
        ),
        _ => ("unlisted", "an exit code this client has no description for".into()),
    };
    ExitDescription {
        hresult: format!("{u:#010x}"),
        name: name.into(),
        reason,
    }
}

/// True when the new log text says the stub found nothing to update
/// (`No products found to update`, OBSERVED with an exit code of 0).
pub fn log_says_nothing_applied(log_excerpt: &str) -> bool {
    log_excerpt.contains("No products found to update")
}

/// CPU architecture of an executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Machine {
    X86,
    X64,
    Arm64,
    Other(u16),
}

impl Machine {
    pub fn from_pe(machine: u16) -> Self {
        match machine {
            0x014C => Machine::X86,
            0x8664 => Machine::X64,
            0xAA64 => Machine::Arm64,
            other => Machine::Other(other),
        }
    }
}

/// Reads the `Machine` field of a PE file (up to the first 64 KiB).
pub fn pe_machine(file: &mut std::fs::File) -> Option<Machine> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut head = vec![0u8; 0x1000];
    let n = file.read(&mut head).ok()?;
    head.truncate(n);
    let lfa = hexspell::pe::dos::DosHeader::parse(&head)
        .ok()?
        .e_lfanew
        .value as usize;
    if lfa > 0x10_000 {
        return None;
    }
    if head.len() < lfa + 6 {
        file.seek(SeekFrom::Start(0)).ok()?;
        head = vec![0u8; lfa + 6];
        file.read_exact(&mut head).ok()?;
    }
    let nt = hexspell::pe::view::nt_offset(&head).ok()?;
    let m = hexspell::utils::extract_u16(&head, nt + 4).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    Some(Machine::from_pe(m))
}

/// The machine state the launcher packages depend on, probed once before a
/// run (the CLI fills it from the live system; tests construct it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StubEnv {
    /// FileVersion of `System32\MpSigStub.exe`, if present.
    pub system_version: Option<String>,
    /// FileVersion of `SysWOW64\MpSigStub.exe` (64-bit hosts), if present.
    pub wow64_version: Option<String>,
    pub host_machine: Machine,
}

/// Checks the preconditions of the launcher packages in `steps` against the
/// probed environment. Returns one refusal text per offending step index.
///
/// `machines[i]` is the PE machine of the payload of `steps[i]` when known.
pub fn check_environment(
    steps: &[InstallStep],
    machines: &[Option<Machine>],
    env: &StubEnv,
) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let installs_stub = steps
        .iter()
        .any(|s| s.payload.file_name.eq_ignore_ascii_case("MpSigStub.exe"));
    for (i, step) in steps.iter().enumerate() {
        let Some(l) = &step.launcher else { continue };
        let _ = l;
        if !installs_stub && env.system_version.as_deref() != Some(EXPECTED_STUB_VERSION) {
            out.push((
                i,
                format!(
                    "System32\\MpSigStub.exe is {} (the launcher requires exactly {EXPECTED_STUB_VERSION}: 0x80070650) and the plan does not install it",
                    env.system_version.as_deref().unwrap_or("missing")
                ),
            ));
            continue;
        }
        match machines.get(i).copied().flatten() {
            None => out.push((i, "the payload is not a recognisable PE image".into())),
            Some(m) if m == env.host_machine => {}
            Some(Machine::X86) if env.host_machine == Machine::X64 => {
                if env.wow64_version.as_deref() != Some(EXPECTED_STUB_VERSION) && !installs_stub {
                    out.push((
                        i,
                        format!(
                            "an x86 package on an x64 host needs SysWOW64\\MpSigStub.exe {EXPECTED_STUB_VERSION} (found {}; the launcher exits 0x80070002); use the x64 package",
                            env.wow64_version.as_deref().unwrap_or("none")
                        ),
                    ));
                }
            }
            Some(m) => out.push((
                i,
                format!(
                    "the package is {m:?} but the host is {:?}",
                    env.host_machine
                ),
            )),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{
        handlers::{CommandLineSpec, HandlerSpec},
        plan::{DigestRef, PayloadRef},
    };

    fn step(name: &str) -> InstallStep {
        InstallStep {
            index: 0,
            update: format!("u-{name}"),
            spec: HandlerSpec::CommandLine(CommandLineSpec {
                program: name.into(),
                arguments: Some("WD /q".into()),
                reboot_by_default: None,
                default_result: None,
                return_codes: vec![],
            }),
            payload: PayloadRef {
                file_name: name.into(),
                size: 1,
                digests: vec![DigestRef {
                    algorithm: "sha1".into(),
                    hex: "00".into(),
                }],
                patching: None,
            },
            extra_payloads: Vec::new(),
            launcher: classify_package(name),
            servicing_identity: None,
        }
    }

    #[test]
    fn names_are_classified() {
        let c = |n: &str| {
            classify_package(n).map(|l| (l.role, l.flavor, l.is_terminal(), l.from_version))
        };
        assert_eq!(
            c("AM_Engine.exe"),
            Some((PackageRole::Engine, Flavor::Full, false, None))
        );
        assert_eq!(
            c("AM_Base.exe"),
            Some((PackageRole::Base, Flavor::Full, false, None))
        );
        assert_eq!(
            c("AM_Delta.exe"),
            Some((PackageRole::Delta, Flavor::Full, true, None))
        );
        assert_eq!(
            c("AM_Delta_Patch_1.459.537.0.exe"),
            Some((
                PackageRole::DeltaPatch,
                Flavor::Full,
                true,
                Some("1.459.537.0".into())
            ))
        );
        assert_eq!(
            c("AM_Engine_Patch_1.1.26080.3.exe"),
            Some((
                PackageRole::EnginePatch,
                Flavor::Full,
                false,
                Some("1.1.26080.3".into())
            ))
        );
        assert_eq!(
            c("AM_Base_Patch1.exe"),
            Some((PackageRole::BasePatch, Flavor::Full, false, None))
        );
        assert_eq!(
            c("AM_Slim_Delta_Patch_1.459.512.0.exe"),
            Some((
                PackageRole::DeltaPatch,
                Flavor::Slim,
                true,
                Some("1.459.512.0".into())
            ))
        );
        assert_eq!(
            c("AS_Delta.exe"),
            Some((PackageRole::Delta, Flavor::Antispyware, true, None))
        );
        assert_eq!(
            c("AS_Engine_Patch_1.1.26070.7.exe").map(|x| x.0),
            Some(PackageRole::EnginePatch)
        );
        for no in [
            "MpSigStub.exe",
            "AM_Delta_Patch_x.exe",
            "AM_Foo.exe",
            "AM_Delta",
            "setup.exe",
        ] {
            assert_eq!(c(no), None, "{no}");
        }
    }

    #[test]
    fn terminal_package_is_ordered_last_and_other_steps_first() {
        let steps = vec![
            step("AM_Delta.exe"),
            step("AM_Engine.exe"),
            step("MpSigStub.exe"),
            step("AM_Base.exe"),
        ];
        let names: Vec<_> = arrange(steps)
            .unwrap()
            .into_iter()
            .map(|s| s.payload.file_name)
            .collect();
        assert_eq!(
            names,
            [
                "MpSigStub.exe",
                "AM_Engine.exe",
                "AM_Base.exe",
                "AM_Delta.exe"
            ]
        );
    }

    #[test]
    fn a_selection_without_a_terminal_package_is_refused() {
        for set in [
            vec!["AM_Engine.exe"],
            vec!["AM_Engine_Patch_1.1.26080.3.exe"],
            vec!["AM_Engine.exe", "AM_Base.exe"],
        ] {
            let err = arrange(set.iter().map(|n| step(n)).collect()).unwrap_err();
            assert!(
                err.contains("0x800705b4") && err.contains("no terminal"),
                "{err}"
            );
        }
        // an engine patch is fine when paired with a delta patch
        assert!(
            arrange(vec![
                step("AM_Engine_Patch_1.1.26080.3.exe"),
                step("AM_Delta_Patch_1.459.537.0.exe")
            ])
            .is_ok()
        );
    }

    #[test]
    fn two_terminal_packages_are_refused() {
        let err = arrange(vec![
            step("AM_Delta.exe"),
            step("AM_Delta_Patch_1.459.537.0.exe"),
        ])
        .unwrap_err();
        assert!(err.contains("terminal"));
    }

    #[test]
    fn plans_without_launcher_packages_are_untouched() {
        let steps = vec![step("MpSigStub.exe"), step("other.exe")];
        let before: Vec<_> = steps.iter().map(|s| s.payload.file_name.clone()).collect();
        let after: Vec<_> = arrange(steps)
            .unwrap()
            .into_iter()
            .map(|s| s.payload.file_name)
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn observed_exit_codes_have_descriptions() {
        assert_eq!(describe_exit(0).name, "success");
        assert_eq!(
            describe_exit(0x8007_0670u32 as i32).name,
            "no_patch_for_installed_version"
        );
        assert_eq!(
            describe_exit(0x8007_05B4u32 as i32).name,
            "accumulate_timeout"
        );
        assert_eq!(
            describe_exit(0x8499_03F9u32 as i32).name,
            "mpsp_patch_error"
        );
        assert!(describe_exit(0x8499_03F9u32 as i32).reason.contains("1017"));
        let wrong_source = describe_exit(0x8499_0402u32 as i32);
        assert_eq!(wrong_source.name, "mpsp_patch_error");
        assert!(wrong_source.reason.contains("error 1026"));
        assert_eq!(describe_exit(0x8007_000Du32 as i32).name, "invalid_data");
        assert_eq!(describe_exit(0x8007_0002u32 as i32).name, "stub_not_found");
        assert_eq!(
            describe_exit(0xC00E_4102u32 as i32).name,
            "patch_api_failure"
        );
        assert_eq!(describe_exit(7).name, "unlisted");
        assert_eq!(describe_exit(0x8007_0670u32 as i32).hresult, "0x80070670");
    }

    #[test]
    fn nothing_applied_is_recognised_from_the_log() {
        assert!(log_says_nothing_applied(
            "...\r\nNo products found to update\r\n"
        ));
        assert!(!log_says_nothing_applied("MpSigStub successfully updated"));
    }

    fn env(system: Option<&str>, wow: Option<&str>, host: Machine) -> StubEnv {
        StubEnv {
            system_version: system.map(Into::into),
            wow64_version: wow.map(Into::into),
            host_machine: host,
        }
    }

    #[test]
    fn stub_precondition_is_checked_unless_the_plan_installs_it() {
        let steps = vec![step("AM_Engine.exe"), step("AM_Delta.exe")];
        let m = [Some(Machine::X64), Some(Machine::X64)];
        assert!(
            check_environment(
                &steps,
                &m,
                &env(Some(EXPECTED_STUB_VERSION), None, Machine::X64)
            )
            .is_empty()
        );
        let bad = check_environment(&steps, &m, &env(Some("1.1.1.1"), None, Machine::X64));
        assert_eq!(bad.len(), 2);
        assert!(bad[0].1.contains("0x80070650"));
        let missing = check_environment(&steps, &m, &env(None, None, Machine::X64));
        assert!(missing[0].1.contains("missing"));
        // the plan restores the stub first: allowed
        let mut with_stub = vec![step("MpSigStub.exe")];
        with_stub.extend(steps);
        let m2 = [Some(Machine::X64); 3];
        assert!(check_environment(&with_stub, &m2, &env(None, None, Machine::X64)).is_empty());
    }

    #[test]
    fn x86_package_on_an_x64_host_needs_the_wow64_stub() {
        let steps = vec![step("AM_Delta_Patch_1.459.537.0.exe")];
        let m = [Some(Machine::X86)];
        let e = |wow| env(Some(EXPECTED_STUB_VERSION), wow, Machine::X64);
        let bad = check_environment(&steps, &m, &e(None));
        assert!(bad[0].1.contains("0x80070002") && bad[0].1.contains("x64 package"));
        assert!(check_environment(&steps, &m, &e(Some(EXPECTED_STUB_VERSION))).is_empty());
        // arm64 package on x64 is never runnable; unknown PE is refused
        assert!(!check_environment(&steps, &[Some(Machine::Arm64)], &e(None)).is_empty());
        assert!(!check_environment(&steps, &[None], &e(None)).is_empty());
    }

    #[test]
    fn pe_machine_reads_the_header() {
        use std::io::Write;
        let mut f = tempfile::tempfile().unwrap();
        let mut img = vec![0u8; 0x100];
        img[..2].copy_from_slice(b"MZ");
        img[0x3C] = 0x80;
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        img[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        f.write_all(&img).unwrap();
        assert_eq!(pe_machine(&mut f), Some(Machine::X64));
        let mut g = tempfile::tempfile().unwrap();
        g.write_all(b"not a pe").unwrap();
        assert_eq!(pe_machine(&mut g), None);
    }
}
