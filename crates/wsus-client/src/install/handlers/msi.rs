//! Windows Installer handler (feature `msi-handler`, off by default).
//!
//! # What real metadata looks like (OBSERVED 2026-10-05)
//!
//! A real WSUS 10.0.26100 (Windows Server 2025) that published an `.msi` through the
//! administration API serves, in the Extended fragment:
//!
//! ```xml
//! <ExtendedProperties ... Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsInstaller" ...>
//!   <InstallationBehavior ... RebootBehavior="CanRequestReboot" /> ...
//! </ExtendedProperties>
//! <Files><File Digest="..." FileName="<guid>_1.cab" Size="11551" DigestAlgorithm="SHA1">
//!   <AdditionalDigest Algorithm="SHA256">...</AdditionalDigest></File></Files>
//! <HandlerSpecificData type="msp:WindowsInstallerApp">
//!   <MsiData ProductCode="{GUID}" MsiFile="name.msi" [CommandLine="A=b C=d"]>
//!     <RepairPath RelativeToServer="true" Path="<update>\<guid>" />
//!   </MsiData>
//! </HandlerSpecificData>
//! ```
//!
//! The payload is a CAB that contains `MsiFile`; the agent extracts it. The applicability rules use
//! `MsiApplicationInstalled` / `Superseded` / `Installable` with the product code in
//! `Metadata/MsiApplicationMetadata/ProductCode` (resolved by `wsus-protocol`).
//!
//! An MSP update, as the same real WSUS serves it (OBSERVED 2026-10-05, a WiX-built patch published
//! through `SoftwareDistributionPackage.PopulatePackageFromWindowsInstallerPatch`):
//!
//! ```xml
//! <Files><File FileName="wsusmsp710.cab" PatchingType="SelfContained" ... /></Files>
//! <HandlerSpecificData type="msp:WindowsInstaller">
//!   <MspData FullFilePatchCode="{7ff3f06a-...}">
//!     <RepairPath RelativeToServer="true" Path="<update>\<guid>" />
//!   </MspData>
//! </HandlerSpecificData>
//! ```
//!
//! There is no `PatchCode` attribute and no member name: the patch code is `FullFilePatchCode` and
//! the `.msp` is the single `.msp` member of the payload cabinet. The published schema also lists
//! `PatchCode`, `CommandLine` and `TargetsSystemMsi`, which are parsed when present.
//!
//! # Execution
//!
//! * `.msi`: `msiexec.exe /i <extracted file> [PROPERTY=value ...] /qn /norestart`;
//! * `.msp`: `msiexec.exe /update <extracted file> [PROPERTY=value ...] /qn /norestart`;
//! * exit codes: 0 success, 3010 (`ERROR_SUCCESS_REBOOT_REQUIRED`) and 1641
//!   (`ERROR_SUCCESS_REBOOT_INITIATED`) success with reboot, everything else failure (including
//!   1618, another installation is in progress, 1638, another version is installed, 1603 fatal
//!   error, 1620 package cannot be opened).
//!
//! The update is routed here when its `Handler` is the WindowsInstaller URI or is in the operator's
//! `msi_handler_uris` list. The same signature gate and digest re-check as for the command-line
//! handler apply to the payload (the CAB); the extracted installer is only ever read from a fresh
//! directory next to it.
use super::{ExitOutcome, HandlerError, command_line::ExitClass};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use wsus_protocol::soap::xml::Element;

/// `ExtendedProperties/@Handler` of Windows Installer updates (OBSERVED on a real WSUS).
pub const WINDOWS_INSTALLER_HANDLER_URI: &str =
    "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsInstaller";

/// Upper bound for the extracted installer (the cabinet member).
const MAX_EXTRACTED_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsiKind {
    /// Installer package.
    Msi,
    /// Patch.
    Msp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsiSpec {
    pub kind: MsiKind,
    /// `MsiData/@MsiFile`: the installer inside the payload cabinet (unset: derive from the payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msi_file: Option<String>,
    /// `MsiData/@ProductCode` or `MspData/@PatchCode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// `CommandLine`: extra `PROPERTY=value` pairs separated by spaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
}

fn bare(el: &Element) -> &str {
    let l = el.name.local.as_str();
    l.rsplit(['.', ':']).next().unwrap_or(l)
}

impl MsiSpec {
    /// Kind from the file extension (case-insensitive); used for a payload that is itself an
    /// installer, and as the fallback for handler URIs listed by the operator.
    pub fn from_file_name(name: &str) -> Result<Self, HandlerError> {
        let lower = name.to_ascii_lowercase();
        let kind = if lower.ends_with(".msi") {
            MsiKind::Msi
        } else if lower.ends_with(".msp") {
            MsiKind::Msp
        } else {
            return Err(HandlerError::Invalid(format!(
                "`{name}` is neither an .msi nor an .msp"
            )));
        };
        Ok(Self {
            kind,
            msi_file: None,
            code: None,
            command_line: None,
        })
    }

    /// Parses `HandlerSpecificData` of the WindowsInstaller handler: `MsiData` (application) or
    /// `MspData` (patch).
    pub fn from_element(data: &Element) -> Result<Self, HandlerError> {
        let (kind, child, code_attr) =
            if let Some(c) = data.elements().find(|c| bare(c) == "MsiData") {
                (MsiKind::Msi, c, "ProductCode")
            } else if let Some(c) = data.elements().find(|c| bare(c) == "MspData") {
                (MsiKind::Msp, c, "PatchCode")
            } else {
                return Err(HandlerError::Invalid(
                    "HandlerSpecificData has neither MsiData nor MspData".into(),
                ));
            };
        let msi_file = child.attr("MsiFile").map(str::to_owned);
        if let Some(f) = &msi_file {
            validate_member_name(f)?;
        }
        if kind == MsiKind::Msi && msi_file.is_none() {
            return Err(HandlerError::Invalid("MsiData has no MsiFile".into()));
        }
        Ok(Self {
            kind,
            msi_file,
            code: child
                .attr(code_attr)
                .or_else(|| {
                    child
                        .attr("FullFilePatchCode")
                        .filter(|_| kind == MsiKind::Msp)
                })
                .map(str::to_owned),
            command_line: child.attr("CommandLine").map(str::to_owned),
        })
    }

    /// `msiexec.exe` inside `system_dir` (the Windows system directory).
    pub fn program(system_dir: &Path) -> PathBuf {
        system_dir.join("msiexec.exe")
    }

    /// Extra installer properties from `CommandLine`, one argument each. Whitespace separates
    /// them, double quotes group (and are removed); anything else is passed through untouched. Each
    /// token must look like `NAME=value`.
    pub fn properties(&self) -> Result<Vec<String>, HandlerError> {
        let Some(line) = &self.command_line else {
            return Ok(Vec::new());
        };
        let (mut out, mut cur, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
        for ch in line.chars() {
            match ch {
                '"' => {
                    quoted = !quoted;
                    any = true;
                }
                c if c.is_whitespace() && !quoted => {
                    if any {
                        out.push(std::mem::take(&mut cur));
                        any = false;
                    }
                }
                c => {
                    cur.push(c);
                    any = true;
                }
            }
        }
        if quoted {
            return Err(HandlerError::Invalid(
                "unbalanced quote in CommandLine".into(),
            ));
        }
        if any {
            out.push(cur);
        }
        for t in &out {
            let ok = t.split_once('=').is_some_and(|(n, _)| {
                !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            if !ok || t.starts_with('/') || t.starts_with('-') {
                return Err(HandlerError::Invalid(format!(
                    "CommandLine token `{t}` is not a PROPERTY=value pair"
                )));
            }
        }
        Ok(out)
    }

    /// Arguments for the installer file `file`. Each is one argument; the path is not pasted into
    /// a larger string.
    pub fn arguments(&self, file: &Path) -> Vec<String> {
        let switch = match self.kind {
            MsiKind::Msi => "/i",
            MsiKind::Msp => "/update",
        };
        let mut v = vec![switch.to_owned(), file.display().to_string()];
        // `properties` was validated when the plan was read; invalid input yields none here.
        v.extend(self.properties().unwrap_or_default());
        v.push("/qn".to_owned());
        v.push("/norestart".to_owned());
        v
    }

    /// The installer file to hand to `msiexec`: the payload itself when it is an `.msi`/`.msp`, or
    /// the member extracted from the payload cabinet into a fresh directory next to it.
    pub fn installer_file(&self, payload: &Path) -> Result<PathBuf, String> {
        let name = payload
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if name.ends_with(".msi") || name.ends_with(".msp") {
            return Ok(payload.to_path_buf());
        }
        if !name.ends_with(".cab") {
            return Err(format!("`{name}` is neither a cabinet nor an installer"));
        }
        let mut cab =
            cabinet::Cabinet::open(payload).map_err(|e| format!("cannot read the cabinet: {e}"))?;
        let want_ext = match self.kind {
            MsiKind::Msi => ".msi",
            MsiKind::Msp => ".msp",
        };
        let member = match &self.msi_file {
            Some(f) => cab
                .entries()
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(f))
                .map(|e| e.name.clone())
                .ok_or_else(|| format!("the cabinet has no `{f}`"))?,
            None => {
                let mut it = cab
                    .entries()
                    .iter()
                    .filter(|e| e.name.to_ascii_lowercase().ends_with(want_ext));
                let first = it
                    .next()
                    .ok_or_else(|| format!("the cabinet has no {want_ext} member"))?
                    .name
                    .clone();
                if it.next().is_some() {
                    return Err(format!("the cabinet has several {want_ext} members"));
                }
                first
            }
        };
        validate_member_name(&member).map_err(|e| e.to_string())?;
        let bytes = cab
            .read_file_bytes(&member, MAX_EXTRACTED_BYTES)
            .map_err(|e| format!("cannot extract `{member}`: {e}"))?;
        let dir = payload.with_file_name(format!("{name}.extracted"));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| format!("cannot clear {}: {e}", dir.display()))?;
        }
        std::fs::create_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let out = dir.join(&member);
        std::fs::write(&out, &bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
        Ok(out)
    }

    /// Exit-code classes.
    pub fn classify(&self, exit_code: i32) -> ExitOutcome {
        let class = match exit_code {
            0 => ExitClass::Success,
            3010 | 1641 => ExitClass::Reboot,
            _ => ExitClass::Failed,
        };
        ExitOutcome {
            class,
            matched: matches!(exit_code, 0 | 3010 | 1641),
        }
    }
}

/// A cabinet member name used as a file name: a plain name, no separators or traversal.
fn validate_member_name(name: &str) -> Result<(), HandlerError> {
    let bad = name.is_empty()
        || name.contains(['/', '\\', ':', '\0'])
        || name == "."
        || name == ".."
        || name.len() > 255;
    if bad {
        return Err(HandlerError::Invalid(format!(
            "`{name}` is not a plain file name"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsus_protocol::soap::{Limits, xml::parse_fragments};

    /// `HandlerSpecificData` of a real WSUS 10.0.26100 for a locally published MSI.
    const REAL_MSI_DATA: &str = r#"<HandlerSpecificData type="msp:WindowsInstallerApp"><MsiData ProductCode="{a1b2c3d4-0001-4000-8000-000000000100}" MsiFile="wsusmsi100.msi"><RepairPath RelativeToServer="true" Path="81552fa4-e38e-4a9c-83d5-1cc6e99252b6\bc856cf9-c69e-40bd-acbb-e46cedbdd580" /></MsiData></HandlerSpecificData>"#;

    fn element(xml: &str) -> Element {
        parse_fragments(xml.as_bytes(), &Limits::default())
            .unwrap()
            .remove(0)
    }

    #[test]
    fn parses_the_real_msi_handler_data() {
        let m = MsiSpec::from_element(&element(REAL_MSI_DATA)).unwrap();
        assert_eq!(m.kind, MsiKind::Msi);
        assert_eq!(m.msi_file.as_deref(), Some("wsusmsi100.msi"));
        assert_eq!(
            m.code.as_deref(),
            Some("{a1b2c3d4-0001-4000-8000-000000000100}")
        );
        assert!(m.properties().unwrap().is_empty());
    }

    /// `HandlerSpecificData` of a real WSUS 10.0.26100 for a locally published `.msp`.
    const REAL_MSP_DATA: &str = r#"<HandlerSpecificData type="msp:WindowsInstaller"><MspData FullFilePatchCode="{7ff3f06a-eb31-4490-98f1-bdd5803e2c36}"><RepairPath RelativeToServer="true" Path="d1ba3603-d1a5-496d-bf9a-b7904bb6aa66\7458c9ec-a469-453e-ab6d-66cc0fdfa0f8" /></MspData></HandlerSpecificData>"#;

    #[test]
    fn parses_the_real_msp_handler_data_with_the_full_file_patch_code() {
        let m = MsiSpec::from_element(&element(REAL_MSP_DATA)).unwrap();
        assert_eq!(m.kind, MsiKind::Msp);
        assert_eq!(m.msi_file, None);
        assert_eq!(
            m.code.as_deref(),
            Some("{7ff3f06a-eb31-4490-98f1-bdd5803e2c36}")
        );
        assert!(m.properties().unwrap().is_empty());
        let args = m.arguments(std::path::Path::new("p.msp"));
        assert_eq!(args, ["/update", "p.msp", "/qn", "/norestart"]);
    }

    #[test]
    fn parses_the_documented_msp_handler_data_and_rejects_others() {
        let msp = element(
            r#"<HandlerSpecificData type="msp:WindowsInstaller"><MspData PatchCode="{10867FC2-98D9-475F-8099-F14A75180E42}" CommandLine="A=1 B=&quot;x y&quot;" /></HandlerSpecificData>"#,
        );
        let m = MsiSpec::from_element(&msp).unwrap();
        assert_eq!(m.kind, MsiKind::Msp);
        assert_eq!(m.msi_file, None);
        assert_eq!(m.properties().unwrap(), ["A=1", "B=x y"]);
        assert!(
            MsiSpec::from_element(&element(
                "<HandlerSpecificData><Other/></HandlerSpecificData>"
            ))
            .is_err()
        );
        let traversal = element(
            r#"<HandlerSpecificData><MsiData ProductCode="{A}" MsiFile="..\evil.msi"/></HandlerSpecificData>"#,
        );
        assert!(MsiSpec::from_element(&traversal).is_err());
    }

    #[test]
    fn command_line_must_be_property_pairs() {
        let mk = |c: &str| MsiSpec {
            kind: MsiKind::Msi,
            msi_file: None,
            code: None,
            command_line: Some(c.into()),
        };
        assert!(mk("/x").properties().is_err());
        assert!(mk("A").properties().is_err());
        assert!(mk("A=\"b").properties().is_err());
        assert!(mk("-A=b").properties().is_err());
        assert_eq!(mk("  A=1   B=2 ").properties().unwrap(), ["A=1", "B=2"]);
    }

    #[test]
    fn builds_msiexec_arguments() {
        let m = MsiSpec::from_file_name("Tool.MSI").unwrap();
        assert_eq!(
            m.arguments(Path::new("C:/store/tool.msi")),
            ["/i", "C:/store/tool.msi", "/qn", "/norestart"]
        );
        let p = MsiSpec::from_file_name("fix.msp").unwrap();
        assert_eq!(p.arguments(Path::new("x.msp"))[0], "/update");
        assert!(MsiSpec::from_file_name("a.exe").is_err());
        let with = MsiSpec {
            command_line: Some("A=1".into()),
            ..m
        };
        assert_eq!(
            with.arguments(Path::new("t.msi")),
            ["/i", "t.msi", "A=1", "/qn", "/norestart"]
        );
    }

    #[test]
    fn maps_return_codes() {
        let m = MsiSpec::from_file_name("a.msi").unwrap();
        assert_eq!(m.classify(0).class, ExitClass::Success);
        assert_eq!(m.classify(3010).class, ExitClass::Reboot);
        assert_eq!(m.classify(1641).class, ExitClass::Reboot);
        assert_eq!(m.classify(1618).class, ExitClass::Failed);
        assert_eq!(m.classify(1603).class, ExitClass::Failed);
    }

    #[test]
    fn extracts_the_named_member_from_a_cabinet_and_rejects_a_missing_one() {
        let dir = tempfile_dir();
        let cab_path = dir.join("u_1.cab");
        let mut w = cabinet::CabinetBuilder::new(cabinet::WriteCompression::None);
        w.add_file("wsusmsi100.msi", b"MSI-BYTES").unwrap();
        let mut f = std::fs::File::create(&cab_path).unwrap();
        w.write(&mut f).unwrap();
        drop(f);
        let m = MsiSpec::from_element(&element(REAL_MSI_DATA)).unwrap();
        let out = m.installer_file(&cab_path).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"MSI-BYTES");
        assert!(out.starts_with(dir.join("u_1.cab.extracted")));
        let other = MsiSpec {
            msi_file: Some("nope.msi".into()),
            ..m
        };
        assert!(other.installer_file(&cab_path).is_err());
        // a payload that is itself an installer is used as is
        let direct = MsiSpec::from_file_name("a.msi").unwrap();
        assert_eq!(
            direct.installer_file(Path::new("/s/a.msi")).unwrap(),
            Path::new("/s/a.msi")
        );
        assert!(direct.installer_file(Path::new("/s/a.exe")).is_err());
    }

    fn tempfile_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("wsus-msi-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
