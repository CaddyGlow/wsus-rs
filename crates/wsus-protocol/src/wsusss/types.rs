//! Complex types of the MS-WSUSSS WSDLs.
use uuid::Uuid;

use crate::identity::UpdateRevision;
use crate::macros::wire_struct;
use crate::soap::wire::XsDateTime;

pub use crate::common::{AuthPlugInInfo, AuthorizationCookie, Cookie};

wire_struct! {
    /// Authorization configuration returned by `GetAuthConfig`.
    pub struct ServerAuthConfig {
        req last_change: XsDateTime => "LastChange",
        opt_array auth_info: AuthPlugInInfo => "AuthInfo" / "AuthPlugInInfo",
        opt_array allowed_event_ids: i32 => "AllowedEventIds" / "int",
    }
}

wire_struct! {
    /// One language known to the upstream server.
    pub struct ServerSyncLanguageData {
        req language_id: i32 => "LanguageID",
        opt short_language: String => "ShortLanguage",
        opt long_language: String => "LongLanguage",
        req enabled: bool => "Enabled",
    }
}

wire_struct! {
    /// Upstream configuration returned by `GetConfigData`; carries the
    /// per-request limits the downstream server must respect.
    pub struct ServerSyncConfigData {
        req catalog_only_sync: bool => "CatalogOnlySync",
        req lazy_sync: bool => "LazySync",
        req server_hosts_psf_files: bool => "ServerHostsPsfFiles",
        /// Maximum ids per `GetUpdateData` request.
        req max_number_of_computer_ids_in_request: i32 => "MaxNumberOfComputerIdsInRequest",
        req max_number_of_driver_sets_per_request: i32 => "MaxNumberOfDriverSetsPerRequest",
        req max_number_of_pnp_hardware_ids_in_request: i32 => "MaxNumberOfPnpHardwareIdsInRequest",
        /// Maximum revisions per `GetUpdateData` request.
        req max_number_of_updates_per_request: i32 => "MaxNumberOfUpdatesPerRequest",
        /// Opaque anchor to send as `configAnchor` next time.
        opt new_config_anchor: String => "NewConfigAnchor",
        opt protocol_version: String => "ProtocolVersion",
        opt_array language_update_list: ServerSyncLanguageData => "LanguageUpdateList" / "ServerSyncLanguageData",
        req max_updates_per_request_in_get_update_decryption_data: i32 => "MaxUpdatesPerRequestInGetUpdateDecryptionData",
    }
    // Observed public Microsoft Update protocol 1.21 response, 2026-10-06.
    // Accept this exact alternate sequence, retaining duplicate/namespace checks.
    alternate_order [
        "CatalogOnlySync", "LazySync", "ServerHostsPsfFiles",
        "MaxNumberOfUpdatesPerRequest", "MaxNumberOfDriverSetsPerRequest",
        "MaxNumberOfComputerIdsInRequest", "MaxNumberOfPnpHardwareIdsInRequest",
        "NewConfigAnchor", "ProtocolVersion", "LanguageUpdateList",
        "MaxUpdatesPerRequestInGetUpdateDecryptionData",
    ];
}

wire_struct! {
    /// Category / classification filter entry.
    pub struct IdAndDelta {
        req id: Uuid => "Id",
        req delta: bool => "Delta",
    }
}

wire_struct! {
    /// Language filter entry.
    pub struct LanguageAndDelta {
        req id: i32 => "Id",
        req delta: bool => "Delta",
    }
}

wire_struct! {
    /// Filter of `GetRevisionIdList`.
    ///
    /// Implementation decision (inventory section 8 item 10):
    /// `DssProtocolVersion` is an empty complex type in the WSDL and "MUST NOT
    /// be sent"; it is decoded into an opaque tree and never produced by the
    /// client side. `Get63LanguageOnly` is optional here because it is
    /// undefined for protocol 1.1.
    pub struct ServerSyncFilter {
        opt dss_protocol_version: crate::soap::wire::Opaque => "DssProtocolVersion",
        /// Opaque anchor from the previous successful response; absent on the first call.
        opt anchor: String => "Anchor",
        /// True to request categories/classifications/detectoids, false for software updates.
        req get_config: bool => "GetConfig",
        opt get63_language_only: bool => "Get63LanguageOnly",
        opt_array categories: IdAndDelta => "Categories" / "IdAndDelta",
        opt_array classifications: IdAndDelta => "Classifications" / "IdAndDelta",
        opt_array languages: LanguageAndDelta => "Languages" / "LanguageAndDelta",
    }
}

wire_struct! {
    /// Result of `GetRevisionIdList`.
    pub struct RevisionIdList {
        /// Opaque anchor marking this operation's completion.
        opt anchor: String => "Anchor",
        opt_array new_revisions: UpdateRevision => "NewRevisions" / "UpdateIdentity",
    }
}

wire_struct! {
    /// Metadata of one revision from `GetUpdateData`.
    ///
    /// Exactly one of `xml_update_blob` and `xml_update_blob_compressed` is
    /// present. The compressed form is an LZX variant (2 MiB window) whose
    /// decoding is outside this crate (inventory section 8 item 11); the bytes
    /// are preserved verbatim for provenance hashing.
    pub struct ServerSyncUpdateData {
        opt id: UpdateRevision => "Id",
        opt xml_update_blob: String => "XmlUpdateBlob",
        /// SHA-1 digests of the revision's content files.
        opt_array file_digest_list: Vec<u8> => "FileDigestList" / "base64Binary",
        opt xml_update_blob_compressed: Vec<u8> => "XmlUpdateBlobCompressed",
    }
}

wire_struct! {
    /// Download URLs of one content file.
    pub struct ServerSyncUrlData {
        /// SHA-1 digest.
        opt file_digest: Vec<u8> => "FileDigest",
        /// Microsoft Update URL.
        opt mu_url: String => "MUUrl",
        /// URL on the upstream server itself.
        opt uss_url: String => "UssUrl",
        opt decryption_key: Vec<u8> => "DecryptionKey",
    }
}

wire_struct! {
    /// Result of `GetUpdateData`.
    pub struct ServerUpdateData {
        opt_array updates: ServerSyncUpdateData => "updates" / "ServerSyncUpdateData",
        opt_array file_urls: ServerSyncUrlData => "fileUrls" / "ServerSyncUrlData",
    }
}

wire_struct! {
    /// Decryption key of one file.
    pub struct ServerSyncFileDecryption {
        opt file_digest: Vec<u8> => "FileDigest",
        opt decryption_key: Vec<u8> => "DecryptionKey",
    }
}

wire_struct! {
    /// Decryption data of one update.
    pub struct ServerSyncUpdateFileDecryption {
        opt update_id: UpdateRevision => "UpdateId",
        opt_array file_decryption_data: ServerSyncFileDecryption => "FileDecryptionData" / "ServerSyncFileDecryption",
    }
}

wire_struct! {
    /// Result of `GetUpdateDecryptionData`.
    pub struct ServerDecryptionData {
        opt_array update_file_decryption_data: ServerSyncUpdateFileDecryption => "UpdateFileDecryptionData" / "ServerSyncUpdateFileDecryption",
    }
}

wire_struct! {
    /// A target group of the upstream server.
    pub struct ServerSyncTargetGroup {
        req target_group_id: Uuid => "TargetGroupID",
        req parent_group_id: Uuid => "ParentGroupId",
        opt name: String => "Name",
        req is_builtin: bool => "IsBuiltin",
    }
}

wire_struct! {
    /// A deployment (approval) of an update revision to a target group.
    pub struct ServerSyncDeployment {
        req update_id: Uuid => "UpdateId",
        req revision_number: i32 => "RevisionNumber",
        req action: i32 => "Action",
        opt admin_name: String => "AdminName",
        req deadline: XsDateTime => "Deadline",
        req is_assigned: bool => "IsAssigned",
        req go_live_time: XsDateTime => "GoLiveTime",
        req deployment_guid: Uuid => "DeploymentGuid",
        req target_group_id: Uuid => "TargetGroupId",
        req download_priority: u8 => "DownloadPriority",
    }
}

wire_struct! {
    /// Result of `GetDeployments`.
    pub struct ServerSyncDeploymentResult {
        opt anchor: String => "Anchor",
        opt_array groups: ServerSyncTargetGroup => "Groups" / "ServerSyncTargetGroup",
        opt_array deployments: ServerSyncDeployment => "Deployments" / "ServerSyncDeployment",
        opt_array dead_deployments: Uuid => "DeadDeployments" / "guid",
        opt_array hidden_updates: Uuid => "HiddenUpdates" / "guid",
        opt_array accepted_eulas: Uuid => "AcceptedEulas" / "guid",
    }
}
