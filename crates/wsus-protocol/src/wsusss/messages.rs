//! MS-WSUSSS request and response messages.
use uuid::Uuid;

use super::types::*;
use super::{DSS_AUTH_NS, SERVER_SYNC_NS};
use crate::identity::UpdateRevision;
use crate::macros::wire_struct;
use crate::{soap_message, soap_request};

wire_struct! {
    /// `GetAuthConfig` request (no parameters).
    pub struct GetAuthConfig {}
}
soap_message!(GetAuthConfig, SERVER_SYNC_NS, "GetAuthConfig");

wire_struct! {
    /// `GetAuthConfig` response.
    pub struct GetAuthConfigResponse {
        opt result: ServerAuthConfig => "GetAuthConfigResult",
    }
}
soap_message!(
    GetAuthConfigResponse,
    SERVER_SYNC_NS,
    "GetAuthConfigResponse"
);
soap_request!(GetAuthConfig => GetAuthConfigResponse);

wire_struct! {
    /// `GetAuthorizationCookie` request (DSS Authorization service).
    pub struct GetAuthorizationCookie {
        /// Account name of the downstream server's identity.
        opt account_name: String => "accountName",
        /// Account GUID, as a string.
        opt account_guid: String => "accountGuid",
        opt_array program_keys: Uuid => "programKeys" / "guid",
    }
}
soap_message!(
    GetAuthorizationCookie,
    DSS_AUTH_NS,
    "GetAuthorizationCookie"
);

wire_struct! {
    /// `GetAuthorizationCookie` response.
    pub struct GetAuthorizationCookieResponse {
        opt result: AuthorizationCookie => "GetAuthorizationCookieResult",
    }
}
soap_message!(
    GetAuthorizationCookieResponse,
    DSS_AUTH_NS,
    "GetAuthorizationCookieResponse"
);
soap_request!(GetAuthorizationCookie => GetAuthorizationCookieResponse);

wire_struct! {
    /// `GetCookie` request (Server Sync service).
    pub struct GetCookie {
        opt_array auth_cookies: AuthorizationCookie => "authCookies" / "AuthorizationCookie",
        opt old_cookie: Cookie => "oldCookie",
        /// Two-part version, major MUST be 1.
        opt protocol_version: String => "protocolVersion",
    }
}
soap_message!(GetCookie, SERVER_SYNC_NS, "GetCookie");

wire_struct! {
    /// `GetCookie` response.
    pub struct GetCookieResponse {
        opt result: Cookie => "GetCookieResult",
    }
}
soap_message!(GetCookieResponse, SERVER_SYNC_NS, "GetCookieResponse");
soap_request!(GetCookie => GetCookieResponse);

wire_struct! {
    /// `GetConfigData` request.
    pub struct GetConfigData {
        opt cookie: Cookie => "cookie",
        /// Anchor from the previous `NewConfigAnchor`.
        opt config_anchor: String => "configAnchor",
    }
}
soap_message!(GetConfigData, SERVER_SYNC_NS, "GetConfigData");

wire_struct! {
    /// `GetConfigData` response.
    pub struct GetConfigDataResponse {
        opt result: ServerSyncConfigData => "GetConfigDataResult",
    }
}
soap_message!(
    GetConfigDataResponse,
    SERVER_SYNC_NS,
    "GetConfigDataResponse"
);
soap_request!(GetConfigData => GetConfigDataResponse);

wire_struct! {
    /// `GetRevisionIdList` request.
    pub struct GetRevisionIdList {
        opt cookie: Cookie => "cookie",
        opt filter: ServerSyncFilter => "filter",
    }
}
soap_message!(GetRevisionIdList, SERVER_SYNC_NS, "GetRevisionIdList");

wire_struct! {
    /// `GetRevisionIdList` response.
    pub struct GetRevisionIdListResponse {
        opt result: RevisionIdList => "GetRevisionIdListResult",
    }
}
soap_message!(
    GetRevisionIdListResponse,
    SERVER_SYNC_NS,
    "GetRevisionIdListResponse"
);
soap_request!(GetRevisionIdList => GetRevisionIdListResponse);

wire_struct! {
    /// `GetUpdateData` request. At most `MaxNumberOfUpdatesPerRequest` ids.
    pub struct GetUpdateData {
        opt cookie: Cookie => "cookie",
        opt_array update_ids: UpdateRevision => "updateIds" / "UpdateIdentity",
    }
}
soap_message!(GetUpdateData, SERVER_SYNC_NS, "GetUpdateData");

wire_struct! {
    /// `GetUpdateData` response.
    pub struct GetUpdateDataResponse {
        opt result: ServerUpdateData => "GetUpdateDataResult",
    }
}
soap_message!(
    GetUpdateDataResponse,
    SERVER_SYNC_NS,
    "GetUpdateDataResponse"
);
soap_request!(GetUpdateData => GetUpdateDataResponse);

wire_struct! {
    /// `GetUpdateDecryptionData` request.
    pub struct GetUpdateDecryptionData {
        opt cookie: Cookie => "cookie",
        opt_array update_ids: UpdateRevision => "updateIds" / "UpdateIdentity",
    }
}
soap_message!(
    GetUpdateDecryptionData,
    SERVER_SYNC_NS,
    "GetUpdateDecryptionData"
);

wire_struct! {
    /// `GetUpdateDecryptionData` response.
    pub struct GetUpdateDecryptionDataResponse {
        opt result: ServerDecryptionData => "GetUpdateDecryptionDataResult",
    }
}
soap_message!(
    GetUpdateDecryptionDataResponse,
    SERVER_SYNC_NS,
    "GetUpdateDecryptionDataResponse"
);
soap_request!(GetUpdateDecryptionData => GetUpdateDecryptionDataResponse);

wire_struct! {
    /// `DownloadFiles` request: asks the upstream to fetch content. At most 100 digests.
    pub struct DownloadFiles {
        opt cookie: Cookie => "cookie",
        opt_array file_digest_list: Vec<u8> => "fileDigestList" / "base64Binary",
    }
}
soap_message!(DownloadFiles, SERVER_SYNC_NS, "DownloadFiles");

wire_struct! {
    /// `DownloadFiles` response (empty).
    pub struct DownloadFilesResponse {}
}
soap_message!(
    DownloadFilesResponse,
    SERVER_SYNC_NS,
    "DownloadFilesResponse"
);
soap_request!(DownloadFiles => DownloadFilesResponse);

wire_struct! {
    /// `GetDeployments` request.
    pub struct GetDeployments {
        opt cookie: Cookie => "cookie",
        opt deployment_anchor: String => "deploymentAnchor",
        opt sync_anchor: String => "syncAnchor",
    }
}
soap_message!(GetDeployments, SERVER_SYNC_NS, "GetDeployments");

wire_struct! {
    /// `GetDeployments` response.
    pub struct GetDeploymentsResponse {
        opt result: ServerSyncDeploymentResult => "GetDeploymentsResult",
    }
}
soap_message!(
    GetDeploymentsResponse,
    SERVER_SYNC_NS,
    "GetDeploymentsResponse"
);
soap_request!(GetDeployments => GetDeploymentsResponse);

wire_struct! {
    /// `GetRelatedRevisionsForUpdates` request.
    pub struct GetRelatedRevisionsForUpdates {
        opt cookie: Cookie => "cookie",
        opt_array update_ids: Uuid => "updateIDs" / "guid",
    }
}
soap_message!(
    GetRelatedRevisionsForUpdates,
    SERVER_SYNC_NS,
    "GetRelatedRevisionsForUpdates"
);

wire_struct! {
    /// `GetRelatedRevisionsForUpdates` response.
    pub struct GetRelatedRevisionsForUpdatesResponse {
        opt_array result: UpdateRevision => "GetRelatedRevisionsForUpdatesResult" / "UpdateIdentity",
    }
}
soap_message!(
    GetRelatedRevisionsForUpdatesResponse,
    SERVER_SYNC_NS,
    "GetRelatedRevisionsForUpdatesResponse"
);
soap_request!(GetRelatedRevisionsForUpdates => GetRelatedRevisionsForUpdatesResponse);
