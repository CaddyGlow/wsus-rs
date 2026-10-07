//! MS-WUSP request and response messages.
use super::types::*;
use super::{CLIENT_NS, REPORTING_NS, SIMPLE_AUTH_NS};
use crate::identity::UpdateRevision;
use crate::macros::wire_struct;
use crate::soap::wire::XsDateTime;
use crate::{soap_message, soap_request};
use uuid::Uuid;

wire_struct! {
    /// `GetConfig` request: the first call of a session.
    pub struct GetConfig {
        /// Two-part client protocol version, for example `1.0`.
        opt protocol_version: String => "protocolVersion",
    }
}
soap_message!(GetConfig, CLIENT_NS, "GetConfig");

wire_struct! {
    /// `GetConfig` response.
    pub struct GetConfigResponse {
        opt result: Config => "GetConfigResult",
    }
}
soap_message!(GetConfigResponse, CLIENT_NS, "GetConfigResponse");
soap_request!(GetConfig => GetConfigResponse);

wire_struct! {
    /// `GetAuthorizationCookie` request (SimpleAuth service).
    pub struct GetAuthorizationCookie {
        opt client_id: String => "clientId",
        opt target_group_name: String => "targetGroupName",
        opt dns_name: String => "dnsName",
    }
}
soap_message!(
    GetAuthorizationCookie,
    SIMPLE_AUTH_NS,
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
    SIMPLE_AUTH_NS,
    "GetAuthorizationCookieResponse"
);
soap_request!(GetAuthorizationCookie => GetAuthorizationCookieResponse);

wire_struct! {
    /// `GetCookie` request.
    pub struct GetCookie {
        /// Exactly one authorization cookie from `GetAuthorizationCookie`.
        opt_array auth_cookies: AuthorizationCookie => "authCookies" / "AuthorizationCookie",
        /// Previous cookie, or nil/absent.
        opt old_cookie: Cookie => "oldCookie",
        /// `LastChange` from the last `GetConfig`.
        req last_change: XsDateTime => "lastChange",
        req current_time: XsDateTime => "currentTime",
        opt protocol_version: String => "protocolVersion",
    }
}
soap_message!(GetCookie, CLIENT_NS, "GetCookie");

wire_struct! {
    /// `GetCookie` response.
    pub struct GetCookieResponse {
        opt result: Cookie => "GetCookieResult",
    }
}
soap_message!(GetCookieResponse, CLIENT_NS, "GetCookieResponse");
soap_request!(GetCookie => GetCookieResponse);

wire_struct! {
    /// `RegisterComputer` request.
    pub struct RegisterComputer {
        opt cookie: Cookie => "cookie",
        opt computer_info: ComputerInfo => "computerInfo",
    }
}
soap_message!(RegisterComputer, CLIENT_NS, "RegisterComputer");

wire_struct! {
    /// `RegisterComputer` response (empty).
    pub struct RegisterComputerResponse {}
}
soap_message!(
    RegisterComputerResponse,
    CLIENT_NS,
    "RegisterComputerResponse"
);
soap_request!(RegisterComputer => RegisterComputerResponse);

wire_struct! {
    /// `StartCategoryScan` request. Carries no cookie: a native Windows Update Agent sends
    /// it without one (Observed 2026-10-04, `docs/fixtures/wsus-m0-native/scan/000005`).
    pub struct StartCategoryScan {
        opt_array requested_categories: CategoryRelationship => "requestedCategories" / "CategoryRelationship",
    }
}
soap_message!(StartCategoryScan, CLIENT_NS, "StartCategoryScan");

wire_struct! {
    /// `StartCategoryScan` response.
    pub struct StartCategoryScanResponse {
        /// Categories the client should use as `FilterCategoryIds` in `SyncUpdates`.
        opt_array preferred_category_ids: Uuid => "preferredCategoryIds" / "guid",
        /// Requested categories the server could not use.
        opt_array requested_category_ids_in_error: Uuid => "requestedCategoryIdsInError" / "guid",
    }
}
soap_message!(
    StartCategoryScanResponse,
    CLIENT_NS,
    "StartCategoryScanResponse"
);
soap_request!(StartCategoryScan => StartCategoryScanResponse);

wire_struct! {
    /// `SyncUpdates` request. See [`SyncUpdateParameters`] for the
    /// continuation / cached-revision protocol.
    pub struct SyncUpdates {
        opt cookie: Cookie => "cookie",
        opt parameters: SyncUpdateParameters => "parameters",
    }
}
soap_message!(SyncUpdates, CLIENT_NS, "SyncUpdates");

wire_struct! {
    /// `SyncUpdates` response.
    pub struct SyncUpdatesResponse {
        opt result: SyncInfo => "SyncUpdatesResult",
    }
}
soap_message!(SyncUpdatesResponse, CLIENT_NS, "SyncUpdatesResponse");
soap_request!(SyncUpdates => SyncUpdatesResponse);

wire_struct! {
    /// `RefreshCache` request (part of the recovery handshake).
    pub struct RefreshCache {
        opt cookie: Cookie => "cookie",
        opt_array global_ids: UpdateRevision => "globalIDs" / "UpdateIdentity",
    }
}
soap_message!(RefreshCache, CLIENT_NS, "RefreshCache");

wire_struct! {
    /// `RefreshCache` response.
    pub struct RefreshCacheResponse {
        opt_array result: RefreshCacheResult => "RefreshCacheResult" / "RefreshCacheResult",
    }
}
soap_message!(RefreshCacheResponse, CLIENT_NS, "RefreshCacheResponse");
soap_request!(RefreshCache => RefreshCacheResponse);

wire_struct! {
    /// `GetExtendedUpdateInfo` request: fetches non-core fragments and file
    /// URLs for server-local revision ids.
    ///
    /// Implementation decision (inventory section 8 item 8): `GeoId` is typed
    /// `s1:String` in the WSDL and is carried as an opaque string.
    pub struct GetExtendedUpdateInfo {
        opt cookie: Cookie => "cookie",
        opt_array revision_ids: i32 => "revisionIDs" / "int",
        opt_array info_types: XmlUpdateFragmentType => "infoTypes" / "XmlUpdateFragmentType",
        opt_array locales: String => "locales" / "string",
        opt geo_id: String => "GeoId",
        opt caller_attributes: String => "callerAttributes",
    }
}
soap_message!(GetExtendedUpdateInfo, CLIENT_NS, "GetExtendedUpdateInfo");

wire_struct! {
    /// `GetExtendedUpdateInfo` response.
    pub struct GetExtendedUpdateInfoResponse {
        opt result: ExtendedUpdateInfo => "GetExtendedUpdateInfoResult",
    }
}
soap_message!(
    GetExtendedUpdateInfoResponse,
    CLIENT_NS,
    "GetExtendedUpdateInfoResponse"
);
soap_request!(GetExtendedUpdateInfo => GetExtendedUpdateInfoResponse);

wire_struct! {
    /// `GetExtendedUpdateInfo2` request: like `GetExtendedUpdateInfo` but keyed
    /// by `UpdateIdentity`, and returns decryption data.
    ///
    /// Present in the MS-WUSP 38.0 WSDL (`soap` binding only; the `soap12`
    /// binding omits it, but this codec accepts either envelope version).
    pub struct GetExtendedUpdateInfo2 {
        opt cookie: Cookie => "cookie",
        opt_array update_ids: UpdateRevision => "updateIDs" / "UpdateIdentity",
        opt_array info_types: XmlUpdateFragmentType => "infoTypes" / "XmlUpdateFragmentType",
        opt_array locales: String => "locales" / "string",
        opt caller_attributes: String => "callerAttributes",
    }
}
soap_message!(GetExtendedUpdateInfo2, CLIENT_NS, "GetExtendedUpdateInfo2");

wire_struct! {
    /// `GetExtendedUpdateInfo2` response.
    pub struct GetExtendedUpdateInfo2Response {
        opt result: ExtendedUpdateInfo2 => "GetExtendedUpdateInfo2Result",
    }
}
soap_message!(
    GetExtendedUpdateInfo2Response,
    CLIENT_NS,
    "GetExtendedUpdateInfo2Response"
);
soap_request!(GetExtendedUpdateInfo2 => GetExtendedUpdateInfo2Response);

wire_struct! {
    /// `GetFileLocations` request. Digests are 20-byte SHA-1 values.
    pub struct GetFileLocations {
        opt cookie: Cookie => "cookie",
        opt_array file_digests: Vec<u8> => "fileDigests" / "base64Binary",
    }
}
soap_message!(GetFileLocations, CLIENT_NS, "GetFileLocations");

wire_struct! {
    /// `GetFileLocations` response.
    pub struct GetFileLocationsResponse {
        opt result: GetFileLocationsResults => "GetFileLocationsResult",
    }
}
soap_message!(
    GetFileLocationsResponse,
    CLIENT_NS,
    "GetFileLocationsResponse"
);
soap_request!(GetFileLocations => GetFileLocationsResponse);

wire_struct! {
    /// `ReportEventBatch` request (Reporting service).
    pub struct ReportEventBatch {
        opt cookie: Cookie => "cookie",
        req client_time: XsDateTime => "clientTime",
        opt_array event_batch: ReportingEvent => "eventBatch" / "ReportingEvent",
    }
}
soap_message!(ReportEventBatch, REPORTING_NS, "ReportEventBatch");

wire_struct! {
    /// `ReportEventBatch` response.
    pub struct ReportEventBatchResponse {
        req result: bool => "ReportEventBatchResult",
    }
}
soap_message!(
    ReportEventBatchResponse,
    REPORTING_NS,
    "ReportEventBatchResponse"
);
soap_request!(ReportEventBatch => ReportEventBatchResponse);
