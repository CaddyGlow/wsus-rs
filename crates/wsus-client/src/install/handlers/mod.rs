//! Typed handler specifications read from the Extended fragment.
//!
//! Observed in the stored real catalog (see the inventory, "Observed
//! HandlerSpecificData"): every Software revision that carries
//! `HandlerSpecificData` declares the handler
//! `http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation`
//! with an `InstallCommand` and `ReturnCode` children. No other handler
//! occurs in the lab catalog; any other handler URI is reported as
//! unsupported and never guessed. The Windows servicing handlers (`Cbs`, `OSInstaller`) seen in a real
//! Windows 11 catalog are read by [`cbs`] and never executed.
pub mod cbs;
pub mod command_line;
#[cfg(feature = "msi-handler")]
pub mod msi;

use serde::{Deserialize, Serialize};
use wsus_protocol::soap::{
    Limits,
    xml::{self, Element},
};

pub use cbs::{CBS_HANDLER_URI, OS_INSTALLER_HANDLER_URI, ServicingKind, ServicingSpec};
pub use command_line::{
    CommandLineSpec, ExitClass, Outcome as ExitOutcome, ResultClass, ReturnCodeRule,
};

/// URI of the command-line handler (the `Handler` attribute of
/// `ExtendedProperties`).
pub const COMMAND_LINE_HANDLER_URI: &str =
    "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation";

/// Handler specification of one update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "handler", rename_all = "snake_case")]
pub enum HandlerSpec {
    CommandLine(CommandLineSpec),
    #[cfg(feature = "msi-handler")]
    Msi(msi::MsiSpec),
    /// Windows servicing (CBS or OS installer): read but never executed by this client.
    Servicing(ServicingSpec),
}

/// Why a handler could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandlerError {
    #[error("Extended fragment is not parseable: {0}")]
    Xml(String),
    #[error("unsupported update handler `{0}`")]
    UnsupportedHandler(String),
    #[error("HandlerSpecificData is missing for handler `{0}`")]
    MissingData(String),
    #[error("invalid handler data: {0}")]
    Invalid(String),
}

/// What the Extended fragment says about installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerInfo {
    /// `ExtendedProperties/@Handler`, when present.
    pub handler_uri: Option<String>,
    /// The element, when present.
    data: Option<Element>,
    /// `ExtendedProperties`, when present.
    properties: Option<Element>,
}

/// Reads `ExtendedProperties/@Handler` and `HandlerSpecificData`.
pub fn read_handler_info(extended_xml: &str) -> Result<HandlerInfo, HandlerError> {
    let top = xml::parse_fragments(extended_xml.as_bytes(), &Limits::default())
        .map_err(|e| HandlerError::Xml(e.to_string()))?;
    let mut uri = None;
    let mut data = None;
    let mut properties = None;
    for el in &top {
        match el.name.local.as_str() {
            "ExtendedProperties" => {
                uri = el.attr("Handler").map(str::to_owned);
                properties = Some(el.clone());
            }
            "HandlerSpecificData" => data = Some(el.clone()),
            _ => {}
        }
    }
    Ok(HandlerInfo {
        handler_uri: uri,
        data,
        properties,
    })
}

impl HandlerInfo {
    /// True when the fragment declares a handler or handler data.
    pub fn is_present(&self) -> bool {
        self.handler_uri.is_some() || self.data.is_some()
    }

    /// Parses the command-line specification. Any other handler is
    /// `UnsupportedHandler`; the (feature-gated) MSI handler is not described
    /// by metadata and is selected by the plan builder from a configured
    /// handler URI list instead.
    pub fn command_line(&self) -> Result<CommandLineSpec, HandlerError> {
        let uri = self.handler_uri.clone().unwrap_or_default();
        if uri != COMMAND_LINE_HANDLER_URI {
            return Err(HandlerError::UnsupportedHandler(uri));
        }
        let data = self
            .data
            .as_ref()
            .ok_or_else(|| HandlerError::MissingData(uri.clone()))?;
        CommandLineSpec::from_element(data)
    }
}

impl HandlerInfo {
    /// Parses a Windows servicing handler (`Cbs` or `OSInstaller`). Any other handler is
    /// `UnsupportedHandler`; the specification is read only and never executed by this client.
    pub fn servicing(&self) -> Result<ServicingSpec, HandlerError> {
        let uri = self.handler_uri.clone().unwrap_or_default();
        let kind = match uri.as_str() {
            CBS_HANDLER_URI => ServicingKind::Cbs,
            OS_INSTALLER_HANDLER_URI => ServicingKind::OsInstaller,
            _ => return Err(HandlerError::UnsupportedHandler(uri)),
        };
        let data = self.data.as_ref().ok_or(HandlerError::MissingData(uri))?;
        ServicingSpec::from_elements(kind, self.properties.as_ref(), data)
    }
}

#[cfg(feature = "msi-handler")]
impl HandlerInfo {
    /// Parses the Windows Installer specification (`MsiData` or `MspData`). `MissingData` when the
    /// fragment carries no `HandlerSpecificData` (the caller may fall back to the payload kind).
    pub fn windows_installer(&self) -> Result<msi::MsiSpec, HandlerError> {
        let uri = self.handler_uri.clone().unwrap_or_default();
        let data = self.data.as_ref().ok_or(HandlerError::MissingData(uri))?;
        msi::MsiSpec::from_element(data)
    }
}

impl HandlerSpec {
    /// Name used in evidence.
    pub fn kind(&self) -> &'static str {
        match self {
            HandlerSpec::CommandLine(_) => "command_line",
            #[cfg(feature = "msi-handler")]
            HandlerSpec::Msi(_) => "msi",
            HandlerSpec::Servicing(s) => s.kind.name(),
        }
    }

    /// Maps an exit code to its class.
    pub fn classify(&self, exit_code: i32) -> ExitOutcome {
        match self {
            HandlerSpec::CommandLine(s) => s.classify(exit_code),
            #[cfg(feature = "msi-handler")]
            HandlerSpec::Msi(s) => s.classify(exit_code),
            // Never executed: any exit code would be meaningless, so none is a success.
            HandlerSpec::Servicing(_) => ExitOutcome {
                class: ExitClass::Failed,
                matched: false,
            },
        }
    }
}

#[cfg(all(test, feature = "msi-handler"))]
mod msi_real_shape_tests {
    use super::*;

    /// The Extended fragment of an `.msi` published through the administration API of a real WSUS
    /// (Windows Server 2025, 10.0.26100.32230), as served to this project's client on 2026-10-05.
    const REAL_EXTENDED: &str = r#"<ExtendedProperties DefaultPropertiesLanguage="en" IsLocallyPublished="true" MinDownloadSize="11551" MaxDownloadSize="11551" Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsInstaller" CanSourceBeRequired="false"><InstallationBehavior CanRequestUserInput="false" RequiresNetworkConnectivity="false" Impact="Normal" RebootBehavior="CanRequestReboot" /><UninstallationBehavior CanRequestUserInput="false" RequiresNetworkConnectivity="false" Impact="Normal" RebootBehavior="CanRequestReboot" /></ExtendedProperties><Files><File Digest="br8eaMSqh4RzvhmfbQA546QF5ZM=" FileName="bc856cf9-c69e-40bd-acbb-e46cedbdd580_1.cab" Size="11551" Modified="2026-10-05T11:00:55.642Z" DigestAlgorithm="SHA1"><AdditionalDigest Algorithm="SHA256">XSVHYC1Z1ZjQVWyXCXjKcIT6EHtgckWLBFV9KIrHH9k=</AdditionalDigest></File></Files><HandlerSpecificData type="msp:WindowsInstallerApp"><MsiData ProductCode="{a1b2c3d4-0001-4000-8000-000000000100}" MsiFile="wsusmsi100.msi"><RepairPath RelativeToServer="true" Path="81552fa4-e38e-4a9c-83d5-1cc6e99252b6\bc856cf9-c69e-40bd-acbb-e46cedbdd580" /></MsiData></HandlerSpecificData>"#;

    #[test]
    fn the_real_windows_installer_fragment_is_read_as_an_msi_spec() {
        let info = read_handler_info(REAL_EXTENDED).unwrap();
        assert_eq!(
            info.handler_uri.as_deref(),
            Some(msi::WINDOWS_INSTALLER_HANDLER_URI)
        );
        // it is not the command-line handler
        assert!(matches!(
            info.command_line(),
            Err(HandlerError::UnsupportedHandler(_))
        ));
        let spec = info.windows_installer().unwrap();
        assert_eq!(spec.kind, msi::MsiKind::Msi);
        assert_eq!(spec.msi_file.as_deref(), Some("wsusmsi100.msi"));
    }
}
