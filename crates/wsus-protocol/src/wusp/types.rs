//! Complex and simple types of the MS-WUSP WSDLs.
use uuid::Uuid;

use crate::macros::{string_enum, wire_struct};
use crate::soap::wire::{Ctx, WireType, XsDateTime};
use crate::soap::xml::Element;
use crate::{error::Result, identity::UpdateRevision};

pub use crate::common::{AuthPlugInInfo, AuthorizationCookie, Cookie};

wire_struct! {
    /// A name/value pair of `Config.Properties`.
    pub struct ConfigurationProperty {
        /// Property name.
        opt name: String => "Name",
        /// Property value.
        opt value: String => "Value",
    }
}

wire_struct! {
    /// Server configuration returned by `GetConfig`.
    pub struct Config {
        /// Time the configuration last changed; sent back in `GetCookie`.
        req last_change: XsDateTime => "LastChange",
        /// Whether `RegisterComputer` must be called.
        req is_registration_required: bool => "IsRegistrationRequired",
        /// Authorization plug-ins.
        opt_array auth_info: AuthPlugInInfo => "AuthInfo" / "AuthPlugInInfo",
        /// Event ids the server wants reported.
        opt_array allowed_event_ids: i32 => "AllowedEventIds" / "int",
        /// Further name/value configuration (limits such as
        /// `MaxExtendedUpdatesPerRequest` travel here).
        opt_array properties: ConfigurationProperty => "Properties" / "ConfigurationProperty",
    }
}

wire_struct! {
    /// Client description sent by `RegisterComputer`.
    pub struct ComputerInfo {
        opt dns_name: String => "DnsName",
        req os_major_version: i32 => "OSMajorVersion",
        req os_minor_version: i32 => "OSMinorVersion",
        req os_build_number: i32 => "OSBuildNumber",
        req os_service_pack_major_number: i16 => "OSServicePackMajorNumber",
        req os_service_pack_minor_number: i16 => "OSServicePackMinorNumber",
        opt os_locale: String => "OSLocale",
        opt computer_manufacturer: String => "ComputerManufacturer",
        opt computer_model: String => "ComputerModel",
        opt bios_version: String => "BiosVersion",
        opt bios_name: String => "BiosName",
        req bios_release_date: XsDateTime => "BiosReleaseDate",
        opt processor_architecture: String => "ProcessorArchitecture",
        req suite_mask: i16 => "SuiteMask",
        req old_product_type: u8 => "OldProductType",
        req new_product_type: i32 => "NewProductType",
        req system_metrics: i32 => "SystemMetrics",
        req client_version_major_number: i16 => "ClientVersionMajorNumber",
        req client_version_minor_number: i16 => "ClientVersionMinorNumber",
        req client_version_build_number: i16 => "ClientVersionBuildNumber",
        req client_version_qfe_number: i16 => "ClientVersionQfeNumber",
        opt os_description: String => "OSDescription",
        opt oem: String => "OEM",
        opt device_type: String => "DeviceType",
        opt firmware_version: String => "FirmwareVersion",
        opt mobile_operator: String => "MobileOperator",
    }
}

wire_struct! {
    /// Installed driver of a device (driver synchronization).
    pub struct InstalledDriver {
        opt matching_id: String => "MatchingID",
        req driver_ver_date: XsDateTime => "DriverVerDate",
        req driver_ver_version: i64 => "DriverVerVersion",
        opt class: String => "Class",
        opt manufacturer: String => "Manufacturer",
        opt provider: String => "Provider",
        opt model: String => "Model",
        /// Nillable GUID: `Nil` is meaningful and preserved.
        opt matching_computer_hwid: Uuid => "MatchingComputerHWID",
        req driver_rank: i32 => "DriverRank",
    }
}

wire_struct! {
    /// Extension driver of a device.
    pub struct ExtensionDriver {
        req extension_id: String => "ExtensionId",
        req driver_ver_date: XsDateTime => "DriverVerDate",
        req driver_ver_version: i64 => "DriverVerVersion",
        req class: String => "Class",
        req driver_rank: i32 => "DriverRank",
        opt matching_computer_hwid: Uuid => "MatchingComputerHWID",
    }
}

wire_struct! {
    /// Device description for driver synchronization.
    ///
    /// Element names `installedDriver` and `extensionDriver` are lower-case
    /// in the WSDL; they are reproduced exactly.
    pub struct Device {
        opt_array hardware_ids: String => "HardwareIDs" / "string",
        opt_array compatible_ids: String => "CompatibleIDs" / "string",
        opt installed_driver: InstalledDriver => "installedDriver",
        opt_array extension_driver: ExtensionDriver => "extensionDriver" / "extensionDriver",
        opt_array driver_recovery_ids: String => "DriverRecoveryIDs" / "DriverRecoveryID",
        opt device_flags: u8 => "DeviceFlags",
    }
}

wire_struct! {
    /// Computer hardware identifiers.
    pub struct ComputerHardwareSpecification {
        opt_array hardware_ids: Uuid => "HardwareIDs" / "guid",
    }
}

wire_struct! {
    /// Category filter entry.
    pub struct CategoryIdentifier {
        /// Category GUID.
        req id: Uuid => "Id",
    }
}

wire_struct! {
    /// One category of a `StartCategoryScan` request. The list of relationships is a
    /// disjunctive normal form: entries sharing an `IndexOfAndGroup` are ANDed, groups are
    /// ORed (MS-WUSP 3.1.4.4).
    pub struct CategoryRelationship {
        /// Index of the AND group this category belongs to.
        req index_of_and_group: i32 => "IndexOfAndGroup",
        /// Category GUID.
        req category_id: Uuid => "CategoryId",
    }
}

wire_struct! {
    /// Parameters of `SyncUpdates`.
    ///
    /// The continuation protocol (MS-WUSP 3.1.5.7) is driven through the
    /// three id lists: the first call sends an empty
    /// `installed_non_leaf_update_ids`; after each response the client appends
    /// non-leaf installed revisions to `installed_non_leaf_update_ids`,
    /// drivers to `cached_driver_ids` and everything else applicable to
    /// `other_cached_update_ids`, and calls again until `NewUpdates` is empty.
    /// All ids are server-local revision ids ([`crate::identity::WireRevisionId`] values).
    pub struct SyncUpdateParameters {
        req express_query: bool => "ExpressQuery",
        /// Installed non-leaf revisions (server-local revision ids).
        opt_array installed_non_leaf_update_ids: i32 => "InstalledNonLeafUpdateIDs" / "int",
        /// Other revisions already cached by the client.
        opt_array other_cached_update_ids: i32 => "OtherCachedUpdateIDs" / "int",
        opt_array system_spec: Device => "SystemSpec" / "Device",
        opt_array cached_driver_ids: i32 => "CachedDriverIDs" / "int",
        /// True for the driver pass.
        req skip_software_sync: bool => "SkipSoftwareSync",
        opt_array filter_category_ids: CategoryIdentifier => "FilterCategoryIds" / "CategoryIdentifier",
        opt need_two_group_out_of_scope_updates: bool => "NeedTwoGroupOutOfScopeUpdates",
        opt computer_spec: ComputerHardwareSpecification => "ComputerSpec",
        opt feature_score_matching_key: String => "FeatureScoreMatchingKey",
    }
}

string_enum! {
    /// Deployment action of an update for a target group.
    pub enum DeploymentAction {
        OptionalInstall = "OptionalInstall",
        Install = "Install",
        Uninstall = "Uninstall",
        PreDeploymentCheck = "PreDeploymentCheck",
        Block = "Block",
        Evaluate = "Evaluate",
        Bundle = "Bundle",
    }
}

string_enum! {
    /// Type of a `ClientMetadata` entry.
    pub enum MetadataType {
        Audience = "Audience",
        Update = "Update",
        Admin = "Admin",
    }
}

string_enum! {
    /// Kind of update metadata fragment requested from `GetExtendedUpdateInfo`.
    pub enum XmlUpdateFragmentType {
        Published = "Published",
        Core = "Core",
        Extended = "Extended",
        VerificationRule = "VerificationRule",
        LocalizedProperties = "LocalizedProperties",
        Eula = "Eula",
        FileUrl = "FileUrl",
        FileDecryption = "FileDecryption",
    }
}

string_enum! {
    /// Reporting `ProcessorArchitecture`.
    pub enum ProcessorArchitecture {
        UnknownArchitecture = "Unknown",
        X86Compatible = "X86Compatible",
        IA64Compatible = "IA64Compatible",
        Amd64Compatible = "Amd64Compatible",
    }
}

/// Signature over a `ClientMetadata` blob. All members are attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub timestamp: XsDateTime,
    pub leaf_certificate_id: u32,
    pub signature: Vec<u8>,
    pub algorithm: String,
}

impl WireType for Verification {
    fn to_xml(&self, ns: &str, name: &str) -> Element {
        use crate::soap::wire::Scalar;
        Element::new(ns, name)
            .with_attr("Timestamp", self.timestamp.format())
            .with_attr("LeafCertificateId", self.leaf_certificate_id.to_string())
            .with_attr("Signature", self.signature.format())
            .with_attr("Algorithm", &self.algorithm)
    }

    fn from_xml(el: &Element, _ctx: &Ctx<'_>) -> Result<Self> {
        use crate::error::ProtocolError;
        use crate::soap::wire::Scalar;
        let get = |n: &str| {
            el.attr(n)
                .ok_or_else(|| ProtocolError::MissingElement(format!("@{n}")))
        };
        let bad = |n: &str, kind: &'static str, v: &str| ProtocolError::InvalidValue {
            element: format!("@{n}"),
            kind,
            value: v.to_owned(),
        };
        let ts = get("Timestamp")?;
        let id = get("LeafCertificateId")?;
        let sig = get("Signature")?;
        Ok(Self {
            timestamp: XsDateTime::parse(ts).ok_or_else(|| bad("Timestamp", "dateTime", ts))?,
            leaf_certificate_id: u32::parse(id)
                .ok_or_else(|| bad("LeafCertificateId", "unsignedInt", id))?,
            signature: Vec::<u8>::parse(sig)
                .ok_or_else(|| bad("Signature", "base64Binary", sig))?,
            algorithm: get("Algorithm")?.to_owned(),
        })
    }
}

wire_struct! {
    /// Client behaviour metadata attached to a deployment.
    pub struct ClientMetadata {
        req metadata_type: MetadataType => "MetadataType",
        req metadata: String => "Metadata",
        opt verification: Verification => "Verification",
    }
}

wire_struct! {
    /// Deployment of a revision to the caller's target group.
    ///
    /// Implementation decision: the WSDL spells the last element
    /// `" ClientBehaviors"` (leading space, not a valid XML name); it is
    /// encoded and decoded as `ClientBehaviors`. `Deadline` and
    /// `LastChangeTime` are `s:string` in the WSDL and kept as strings.
    pub struct Deployment {
        /// Server-local deployment id.
        req id: i32 => "ID",
        req action: DeploymentAction => "Action",
        opt deadline: String => "Deadline",
        req is_assigned: bool => "IsAssigned",
        req last_change_time: String => "LastChangeTime",
        opt download_priority: String => "DownloadPriority",
        opt_array hardware_ids: String => "HardwareIds" / "string",
        opt auto_select: String => "AutoSelect",
        opt auto_download: String => "AutoDownload",
        opt supersedence_behavior: String => "SupersedenceBehavior",
        opt flag_bitmask: String => "FlagBitmask",
        opt_array client_behaviors: ClientMetadata => "ClientBehaviors" / "ClientMetadata",
    }
}

wire_struct! {
    /// One revision in a `SyncInfo`.
    pub struct UpdateInfo {
        /// Server-local revision id.
        req id: i32 => "ID",
        opt deployment: Deployment => "Deployment",
        req is_leaf: bool => "IsLeaf",
        /// Core metadata fragment as an XML string (the text content of `Xml`).
        opt xml: String => "Xml",
    }
}

wire_struct! {
    /// Result of `SyncUpdates`.
    pub struct SyncInfo {
        opt_array new_updates: UpdateInfo => "NewUpdates" / "UpdateInfo",
        opt_array out_of_scope_revision_ids: i32 => "OutOfScopeRevisionIDs" / "int",
        opt_array changed_updates: UpdateInfo => "ChangedUpdates" / "UpdateInfo",
        /// True when the server returned a subset and the client must call again.
        req truncated: bool => "Truncated",
        opt new_cookie: Cookie => "NewCookie",
        opt_array deployed_out_of_scope_revision_ids: i32 => "DeployedOutOfScopeRevisionIds" / "int",
        opt driver_sync_not_needed: String => "DriverSyncNotNeeded",
    }
}

wire_struct! {
    /// A revision's metadata fragment from `GetExtendedUpdateInfo`.
    pub struct UpdateData {
        /// Server-local revision id.
        req id: i32 => "ID",
        /// Fragment XML as a string.
        opt xml: String => "Xml",
    }
}

wire_struct! {
    /// Download location of a content file.
    pub struct FileLocation {
        /// SHA-1 digest of the file.
        opt file_digest: Vec<u8> => "FileDigest",
        opt url: String => "Url",
        opt pieces_hash_url: String => "PiecesHashUrl",
        opt block_map_url: String => "BlockMapUrl",
        opt decryption_information: String => "DecryptionInformation",
        opt file_digest_algorithm: String => "FileDigestAlgorithm",
        opt encrypted_file_digest: Vec<u8> => "EncryptedFileDigest",
        opt encrypted_file_digest_algorithm: String => "EncryptedFileDigestAlgorithm",
    }
}

wire_struct! {
    /// Result of `GetExtendedUpdateInfo`.
    pub struct ExtendedUpdateInfo {
        opt_array updates: UpdateData => "Updates" / "Update",
        opt_array file_locations: FileLocation => "FileLocations" / "FileLocation",
        opt_array out_of_scope_revision_ids: i32 => "OutOfScopeRevisionIDs" / "int",
    }
}

wire_struct! {
    /// Decryption data for one file.
    pub struct FileDecryption {
        opt file_digest: Vec<u8> => "FileDigest",
        opt decryption_key: Vec<u8> => "DecryptionKey",
        opt_array security_data: Vec<u8> => "SecurityData" / "base64Binary",
    }
}

/// Second flavour of file decryption data; identical shape, separate element names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDecryption2(pub FileDecryption);

impl WireType for FileDecryption2 {
    fn to_xml(&self, ns: &str, name: &str) -> Element {
        self.0.to_xml(ns, name)
    }
    fn from_xml(el: &Element, ctx: &Ctx<'_>) -> Result<Self> {
        FileDecryption::from_xml(el, ctx).map(Self)
    }
}

wire_struct! {
    /// Whether an update has encrypted files.
    pub struct UpdateEncryptionDetail {
        req update_identity: UpdateRevision => "UpdateIdentity",
        req has_encrypted_files: bool => "HasEncryptedFiles",
    }
}

wire_struct! {
    /// Result of `GetExtendedUpdateInfo2`.
    pub struct ExtendedUpdateInfo2 {
        opt_array updates: UpdateData => "Updates" / "Update",
        opt_array file_locations: FileLocation => "FileLocations" / "FileLocation",
        opt_array file_decryption_data: FileDecryption => "FileDecryptionData" / "FileDecryption",
        opt_array file_decryption_data2: FileDecryption2 => "FileDecryptionData2" / "FileDecryption2",
        opt_array update_encryption_details: UpdateEncryptionDetail => "UpdateEncryptionDetails" / "UpdateEncryptionDetail",
    }
}

wire_struct! {
    /// Result of `GetFileLocations`.
    pub struct GetFileLocationsResults {
        opt_array file_locations: FileLocation => "FileLocations" / "FileLocation",
        opt new_cookie: Cookie => "NewCookie",
    }
}

wire_struct! {
    /// Result of one revision in `RefreshCache`.
    pub struct RefreshCacheResult {
        req revision_id: i32 => "RevisionID",
        opt global_id: UpdateRevision => "GlobalID",
        req is_leaf: bool => "IsLeaf",
        opt deployment: Deployment => "Deployment",
    }
}

// ---- Reporting service types ------------------------------------------------

wire_struct! {
    /// Computer identifier in a reporting event.
    pub struct ComputerTargetIdentifier {
        opt sid: String => "Sid",
    }
}

wire_struct! {
    /// Fixed part of a reporting event.
    pub struct BasicData {
        opt target_id: ComputerTargetIdentifier => "TargetID",
        req sequence_number: i32 => "SequenceNumber",
        req time_at_target: XsDateTime => "TimeAtTarget",
        /// Unique per event; the natural idempotency key for replays.
        req event_instance_id: Uuid => "EventInstanceID",
        req namespace_id: i32 => "NamespaceID",
        req event_id: i16 => "EventID",
        req source_id: i16 => "SourceID",
        opt update_id: UpdateRevision => "UpdateID",
        req win32_hresult: i32 => "Win32HResult",
        opt app_name: String => "AppName",
    }
}

wire_struct! {
    /// Windows version of the reporting client.
    pub struct DetailedVersion {
        req major: i32 => "Major",
        req minor: i32 => "Minor",
        req build: i32 => "Build",
        req revision: i32 => "Revision",
        req service_pack_major: i32 => "ServicePackMajor",
        req service_pack_minor: i32 => "ServicePackMinor",
    }
}

wire_struct! {
    /// Optional detail of a reporting event.
    pub struct ExtendedData {
        opt_array replacement_strings: String => "ReplacementStrings" / "string",
        opt_array misc_data: String => "MiscData" / "string",
        opt computer_brand: String => "ComputerBrand",
        opt computer_model: String => "ComputerModel",
        opt bios_revision: String => "BiosRevision",
        req processor_architecture: ProcessorArchitecture => "ProcessorArchitecture",
        req os_version: DetailedVersion => "OSVersion",
        req os_locale_id: i32 => "OSLocaleID",
        opt device_id: String => "DeviceID",
    }
}

wire_struct! {
    /// Privacy-sensitive detail of a reporting event.
    pub struct PrivateData {
        opt computer_dns_name: String => "ComputerDnsName",
        opt user_account_name: String => "UserAccountName",
    }
}

wire_struct! {
    /// One reported event.
    pub struct ReportingEvent {
        opt basic_data: BasicData => "BasicData",
        opt extended_data: ExtendedData => "ExtendedData",
        opt private_data: PrivateData => "PrivateData",
    }
}
