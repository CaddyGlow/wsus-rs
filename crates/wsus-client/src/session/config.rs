//! Session configuration.

use crate::transport::RetryPolicy;
use std::time::Duration;
use wsus_protocol::{
    identity::ServerId,
    soap::{Limits, SoapVersion},
    wusp::ComputerInfo,
};

/// Default cap on `InstalledNonLeafUpdateIDs` entries per `SyncUpdates` call.
///
/// Observed: a Windows Server 2025 WSUS (protocol 3.2) accepts 400 entries and
/// answers `InvalidParameters` (`parameters.InstalledNonLeafUpdateIDs`) for
/// 401 (inventory 9.1). A native Windows Update Agent never approaches this
/// cap: it lists only the non-leaf revisions it evaluated as installed (87 to
/// 94 entries in the recorded native scan, inventory 9.3). See
/// `SessionConfig::installed_non_leaf_limit`.
pub const DEFAULT_INSTALLED_NON_LEAF_LIMIT: usize = 400;

/// Configuration of a [`super::WuspSession`].
///
/// Default service paths follow the MS-WUSP prose and the reference sample
/// (inventory section 3). Observed against one real WSUS (Windows Server 2025
/// build 10.0.26100, `ProtocolVersion` 3.2, 2026-10-04; inventory 9.1 and
/// 9.3), not a general guarantee:
///
/// - the client path `/ClientWebService/Client.asmx` was accepted (a native
///   Windows Update Agent sends lowercase `client.asmx`; IIS paths are
///   case-insensitive by default);
/// - the SimpleAuth path `/SimpleAuthWebService/SimpleAuth.asmx` matches
///   `GetConfig`'s relative `ServiceUrl`, and the Reporting path
///   `/ReportingWebService/ReportingWebService.asmx` is the one a native
///   client posted to (answered 200);
/// - `protocolVersion` `1.8` (specified value) was accepted; a native client
///   sends `2.90` and was answered identically;
/// - requests need no `Accept-Encoding`; a native client sends `xpress` and the
///   server then compresses responses with Xpress. This client sends
///   `Accept-Encoding: xpress` by default ([`SessionConfig::accept_xpress`]) and
///   decodes the answer with `wsus_protocol::xpress` (verified against that
///   server, inventory section 9);
/// - the server pages `SyncUpdates` at 30 updates per response, an observed
///   value of that build and not a constant.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Scheme, host and port, without trailing slash, for example
    /// `http://wsus.example:8530`.
    pub base_url: String,
    /// Client web service path.
    pub client_path: String,
    /// SimpleAuth service path, used when `GetConfig` names no `ServiceUrl`.
    pub auth_path: String,
    /// Reporting service path (prose and WSDL disagree; configurable).
    pub reporting_path: String,
    /// SOAP version of requests; replies of either version are accepted.
    pub soap_version: SoapVersion,
    /// Client protocol version sent in `GetConfig` and `GetCookie`.
    pub protocol_version: String,
    /// DNS name used for `GetAuthorizationCookie` and `RegisterComputer`.
    pub dns_name: String,
    /// Optional target group requested from SimpleAuth.
    pub target_group: Option<String>,
    /// Description sent when the server requires registration.
    pub computer_info: Option<ComputerInfo>,
    /// Identity of the source server; derived from `base_url` when absent.
    /// A different value than the persisted one discards server-local state.
    pub server_id: Option<ServerId>,
    pub request_timeout: Duration,
    /// Limit for a SOAP response body. Applied to the bytes on the wire and
    /// again to the DECODED size when the response is Xpress encoded.
    pub max_response_bytes: usize,
    /// Send `Accept-Encoding: xpress` on SOAP POSTs (default on). Content
    /// downloads never send it. A response with `Content-Encoding: xpress` is
    /// decoded whatever this setting says; any other encoding is rejected.
    pub accept_xpress: bool,
    /// Transport/HTTP retries, applied by operation idempotence.
    pub retry: RetryPolicy,
    /// Renew the cookie this long before it expires.
    pub renewal_skew_secs: i64,
    /// Fault-driven recoveries allowed for one operation.
    pub max_recoveries_per_call: u32,
    /// Fault-driven recoveries allowed between two [`super::WuspSession::begin_run`] calls.
    pub max_recoveries_per_run: u32,
    /// XML limits for every decoded message.
    pub limits: Limits,
    /// Maximum entries sent in `InstalledNonLeafUpdateIDs` per `SyncUpdates`
    /// call; non-leaf revisions beyond it are sent in `OtherCachedUpdateIDs`.
    ///
    /// Implementation decision: this client has no installed-software
    /// inventory (it only acquires), so it never claims anything is installed
    /// in the sense of MS-WUSP 3.1.5.7. The non-leaf list is instead used as
    /// "non-leaf revisions already cached", which lets the server keep
    /// delivering the leaves that depend on them. The entries chosen when the
    /// cached non-leaf revisions exceed the limit are ranked by dependent
    /// software revisions, then prerequisite depth, then server-local
    /// revision id, so the same entries are chosen on every call until new
    /// software revisions are stored. Overflow is still reported as cached
    /// through `OtherCachedUpdateIDs`, so no revision is resent because of
    /// the cap.
    ///
    /// Observed: the lab WSUS rejects more than 400 entries in
    /// `InstalledNonLeafUpdateIDs` (400 accepted, 401 `InvalidParameters`)
    /// while `OtherCachedUpdateIDs` accepted 3679 entries. The server treats a
    /// prerequisite as satisfied only when its id is in
    /// `InstalledNonLeafUpdateIDs`. Within the limit every cached non-leaf
    /// revision is listed; beyond it the entries are chosen by how many stored
    /// software revisions depend on them (see `split_cached` in the sync
    /// engine). A native Windows
    /// Update Agent sends 87 to 94 entries here (only revisions it evaluated
    /// as installed) and every other returned revision in
    /// `OtherCachedUpdateIDs`, and omits all three lists on its first call
    /// (inventory 9.3). If the server still rejects the lists the run fails
    /// with [`crate::sync::SyncError::CachedListRejected`] instead of
    /// retrying.
    pub installed_non_leaf_limit: usize,
}

impl SessionConfig {
    /// Defaults for `base_url` and `dns_name`.
    ///
    /// The paths, `protocolVersion` `1.8`, SOAP 1.1 and the 400-entry
    /// `installed_non_leaf_limit` are the values observed to work against the
    /// lab WSUS (Windows Server 2025 build 10.0.26100); see the type
    /// documentation. Nothing else about other server builds is established.
    pub fn new(base_url: &str, dns_name: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client_path: "/ClientWebService/Client.asmx".into(),
            auth_path: "/SimpleAuthWebService/SimpleAuth.asmx".into(),
            reporting_path: "/ReportingWebService/ReportingWebService.asmx".into(),
            soap_version: SoapVersion::V11,
            protocol_version: "1.8".into(),
            dns_name: dns_name.to_owned(),
            target_group: None,
            computer_info: None,
            server_id: None,
            request_timeout: Duration::from_secs(60),
            max_response_bytes: 256 * 1024 * 1024,
            accept_xpress: true,
            retry: RetryPolicy::default(),
            renewal_skew_secs: 300,
            max_recoveries_per_call: 3,
            max_recoveries_per_run: 8,
            limits: Limits {
                max_body_bytes: 256 * 1024 * 1024,
                ..Limits::default()
            },
            installed_non_leaf_limit: DEFAULT_INSTALLED_NON_LEAF_LIMIT,
        }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_owned()
        } else {
            format!("{}/{}", self.base_url, path.trim_start_matches('/'))
        }
    }
}
