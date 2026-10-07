//! Windows servicing handlers: parse only, nothing here executes.
//!
//! OBSERVED on a real Windows 11 catalog synced from a Windows Server 2025 WSUS (2026-10-05, see the
//! inventory, "Windows servicing metadata"): two handler URIs carry the servicing content.
//!
//! * `http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs` (180 updates): one `.cab` payload and
//!   `<HandlerSpecificData type="cbs:Cbs"><CbsData PackageIdentity="" /></HandlerSpecificData>`. The
//!   `PackageIdentity` attribute was empty on all 180: the package is identified by the update's
//!   applicability metadata instead (`Metadata/CbsPackageApplicabilityMetadata`), not by this attribute.
//! * `http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller` (297 updates, the monthly
//!   Windows 11 and .NET cumulative updates): `ExtendedProperties` carries `ProductName`, `ReleaseVersion`
//!   and `ReleaseRevision`, the files are `.cab`, `.psf`, `.wim` and metadata cabinets, and
//!   `<HandlerSpecificData type="OSInstallerMetadata"><OSInstallData InitialModule="UpdateAgent.dll" />`.
//!
//! This client has no servicing engine behind these types. The specification is read so that a plan can
//! name the handler and the facts a CBS engine would need (see [`ServicingSpec::engine_needs`]), and the
//! executor refuses the run before executing anything.
use serde::{Deserialize, Serialize};
use wsus_protocol::soap::xml::Element;

use super::HandlerError;

/// `Handler` URI of CBS package updates.
pub const CBS_HANDLER_URI: &str = "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs";

/// `Handler` URI of OS installer updates.
pub const OS_INSTALLER_HANDLER_URI: &str =
    "http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller";

/// `RebootBehavior` of an `InstallationBehavior` or `UninstallationBehavior` element (open set: the value
/// is kept as read; only `CanRequestReboot` was observed on these handlers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Behavior {
    pub reboot_behavior: Option<String>,
}

/// Which servicing handler an update declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicingKind {
    Cbs,
    OsInstaller,
}

impl ServicingKind {
    /// Name used in evidence and plans.
    pub fn name(self) -> &'static str {
        match self {
            ServicingKind::Cbs => "cbs",
            ServicingKind::OsInstaller => "os_installer",
        }
    }
}

/// A parsed servicing handler specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicingSpec {
    pub kind: ServicingKind,
    /// `CbsData/@PackageIdentity` when non-empty (empty on every observed update).
    pub package_identity: Option<String>,
    /// `OSInstallData/@InitialModule`.
    pub initial_module: Option<String>,
    /// `ExtendedProperties/@ProductName` (OS installer).
    pub product_name: Option<String>,
    /// `ExtendedProperties/@ReleaseVersion` (OS installer).
    pub release_version: Option<String>,
    /// `ExtendedProperties/@ReleaseRevision` (OS installer).
    pub release_revision: Option<String>,
    pub installation: Behavior,
    pub uninstallation: Option<Behavior>,
    /// `ExtendedProperties/@MaxDownloadSize`.
    pub max_download_size: Option<u64>,
    /// The servicing stack cabinet (`DesktopDeployment.cab`) an `OSInstaller` update declares with a
    /// digest; set by the planner from the update's file list, never by the handler parser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_payload: Option<crate::install::plan::PayloadRef>,
}

fn behavior(el: &Element) -> Behavior {
    Behavior {
        reboot_behavior: el.attr("RebootBehavior").map(str::to_owned),
    }
}

impl ServicingSpec {
    /// Reads the specification from `ExtendedProperties` (when present) and `HandlerSpecificData`.
    pub fn from_elements(
        kind: ServicingKind,
        properties: Option<&Element>,
        data: &Element,
    ) -> Result<Self, HandlerError> {
        let expected = match kind {
            ServicingKind::Cbs => "cbs:Cbs",
            ServicingKind::OsInstaller => "OSInstallerMetadata",
        };
        let ty = data.attr("type").unwrap_or_default();
        if ty != expected {
            return Err(HandlerError::Invalid(format!(
                "HandlerSpecificData type `{ty}`, expected `{expected}`"
            )));
        }
        let mut spec = ServicingSpec {
            kind,
            package_identity: None,
            initial_module: None,
            product_name: None,
            release_version: None,
            release_revision: None,
            installation: Behavior::default(),
            uninstallation: None,
            max_download_size: None,
            stack_payload: None,
        };
        for c in data.elements() {
            match c.name.local.as_str() {
                "CbsData" if kind == ServicingKind::Cbs => {
                    spec.package_identity = c
                        .attr("PackageIdentity")
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned);
                }
                "OSInstallData" if kind == ServicingKind::OsInstaller => {
                    spec.initial_module = c.attr("InitialModule").map(str::to_owned);
                }
                _ => {}
            }
        }
        if let Some(p) = properties {
            spec.product_name = p.attr("ProductName").map(str::to_owned);
            spec.release_version = p.attr("ReleaseVersion").map(str::to_owned);
            spec.release_revision = p.attr("ReleaseRevision").map(str::to_owned);
            spec.max_download_size = p.attr("MaxDownloadSize").and_then(|v| v.parse().ok());
            for c in p.elements() {
                match c.name.local.as_str() {
                    "InstallationBehavior" => spec.installation = behavior(c),
                    "UninstallationBehavior" => spec.uninstallation = Some(behavior(c)),
                    _ => {}
                }
            }
        }
        if kind == ServicingKind::OsInstaller && spec.initial_module.is_none() {
            return Err(HandlerError::Invalid(
                "OSInstallerMetadata without OSInstallData/@InitialModule".into(),
            ));
        }
        Ok(spec)
    }

    /// Why this client does not execute the handler: the interface a servicing engine would have to
    /// provide (an interface note, not an implementation; `windows-cbs`, `windows-csi` and `windows-dism`
    /// hold the engine pieces of this workspace).
    pub fn engine_needs(&self) -> &'static str {
        match self.kind {
            ServicingKind::Cbs => {
                "needs a Component Based Servicing engine: stage the verified .cab, resolve its package \
                 manifest (the package identity is in the update's CbsPackageApplicabilityMetadata, not \
                 in HandlerSpecificData), evaluate the parent assemblies against the component store, \
                 install through the servicing stack, then report the pending-reboot state"
            }
            ServicingKind::OsInstaller => {
                "needs the OS installer: run the servicing stack and UpdateAgent.dll (InitialModule) \
                 over the downloaded cabinets, .psf delta packages and .wim files, then report the \
                 pending-reboot state"
            }
        }
    }

    /// Message of the refusal the executor records.
    pub fn refusal(&self) -> String {
        format!(
            "planned handler {}, not executable by this client: {}",
            self.kind.name(),
            self.engine_needs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::handlers::read_handler_info;

    const CBS_EXTENDED: &str =
        include_str!("../../../../../docs/fixtures/wsus-m0-cbs/cbs-dotnet-extended.xml");
    const OSI_EXTENDED: &str =
        include_str!("../../../../../docs/fixtures/wsus-m0-cbs/osinstaller-extended.xml");

    #[test]
    fn real_cbs_extended_fragment_parses() {
        let info = read_handler_info(CBS_EXTENDED).unwrap();
        assert_eq!(info.handler_uri.as_deref(), Some(CBS_HANDLER_URI));
        let spec = info.servicing().unwrap();
        assert_eq!(spec.kind, ServicingKind::Cbs);
        assert_eq!(spec.package_identity, None);
        assert_eq!(
            spec.installation.reboot_behavior.as_deref(),
            Some("CanRequestReboot")
        );
        assert_eq!(spec.max_download_size, Some(40_121_630));
        assert_eq!(
            spec.uninstallation
                .as_ref()
                .and_then(|b| b.reboot_behavior.as_deref()),
            Some("CanRequestReboot")
        );
        assert!(
            spec.refusal()
                .starts_with("planned handler cbs, not executable by this client")
        );
    }

    #[test]
    fn real_os_installer_extended_fragment_parses() {
        let info = read_handler_info(OSI_EXTENDED).unwrap();
        assert_eq!(info.handler_uri.as_deref(), Some(OS_INSTALLER_HANDLER_URI));
        let spec = info.servicing().unwrap();
        assert_eq!(spec.kind, ServicingKind::OsInstaller);
        assert_eq!(spec.initial_module.as_deref(), Some("UpdateAgent.dll"));
        assert_eq!(spec.product_name.as_deref(), Some("Client.OS.RS2.ARM64"));
        assert_eq!(spec.release_version.as_deref(), Some("10.0.22621.5909"));
        assert_eq!(spec.release_revision.as_deref(), Some("1"));
    }

    #[test]
    fn wrong_handler_data_type_is_invalid() {
        let xml = r#"<ExtendedProperties Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs" /><HandlerSpecificData type="cmd:CommandLineInstallation" />"#;
        let info = read_handler_info(xml).unwrap();
        assert!(matches!(info.servicing(), Err(HandlerError::Invalid(_))));
    }

    #[test]
    fn missing_handler_data_is_reported() {
        let xml = r#"<ExtendedProperties Handler="http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller" />"#;
        let info = read_handler_info(xml).unwrap();
        assert!(matches!(
            info.servicing(),
            Err(HandlerError::MissingData(_))
        ));
    }
}
