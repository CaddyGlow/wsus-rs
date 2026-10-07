//! Client configuration.
use std::time::Duration;

use wsus_protocol::soap::{Limits, SoapVersion};

use crate::transport::{DEFAULT_MAX_RESPONSE_BYTES, RetryPolicy};

/// Windows limits `GetUpdateData` responses to this many bytes (inventory 6.2,
/// Specified, product behavior).
pub const MAX_UPDATE_RESPONSE_BYTES: usize = 2_000_000;
/// `DownloadFiles` accepts at most this many digests.
pub const MAX_DOWNLOAD_FILES_DIGESTS: usize = 100;

/// Directory and file-name case of `Content/<folder>/<file>` (inventory
/// section 8 item 1). Observed on one real WSUS (Windows Server 2025
/// 10.0.26100, inventory 9.3 and 9.5): the last two hex digits of the SHA-1 in
/// upper case, the file name the full upper-case hex SHA-1 plus the extension
/// of the file's own name. The Base64 reading is not offered because Base64
/// contains `/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFolderRule {
    /// Lower-case hex for the folder and the file name.
    LastTwoHexLower,
    /// Upper-case hex for the folder and the file name (observed).
    LastTwoHexUpper,
}

/// Connection and behaviour settings of [`super::WsusssClient`].
#[derive(Debug, Clone)]
pub struct WsusssConfig {
    /// Origin of the upstream web services, for example `http://wsus.test:8530`.
    pub base_url: String,
    /// Path of the Server Sync service.
    pub server_sync_path: String,
    /// Explicit URL of the DSS authorization service; when `None` it is
    /// taken from `GetAuthConfig` (relative to `base_url`, same origin only).
    pub auth_url: Option<String>,
    /// Base of the content directory (`<base>/Content/<folder>/<file>`).
    /// Never inferred from the web-service port (inventory section 3.2).
    pub content_base_url: Option<String>,
    /// SOAP version; must match the upstream's configuration.
    pub soap_version: SoapVersion,
    /// Identity presented to `GetAuthorizationCookie`.
    pub account_name: String,
    /// Account GUID presented to `GetAuthorizationCookie`.
    pub account_guid: String,
    /// `protocolVersion` of `GetCookie`; major MUST be 1.
    pub protocol_version: String,
    /// Timeout of one SOAP request.
    pub request_timeout: Duration,
    /// Transport-level retry policy (all operations are read-only or
    /// idempotent, so they are marked replayable).
    pub retry: RetryPolicy,
    /// Buffered response limit.
    pub max_response_bytes: usize,
    /// XML decoding limits.
    pub limits: Limits,
    /// How many times a call may restart authorization after
    /// `InvalidCookie` / `InvalidAuthorizationCookie`.
    pub max_session_restarts: u32,
    /// How many times a call is retried after `ServerBusy`.
    pub busy_retries: u32,
    /// Base delay between `ServerBusy` retries (multiplied by the attempt).
    pub busy_delay: Duration,
    /// Seconds before expiry at which a cookie is renewed.
    pub cookie_skew_secs: i64,
    /// Preferred `GetUpdateData` batch size; reduced to the upstream's
    /// `MaxNumberOfUpdatesPerRequest` and adaptively when responses are large.
    pub update_batch_size: usize,
    /// Wait after `DownloadFiles` before the content fetch is retried.
    pub download_files_wait: Duration,
    /// Content directory convention.
    pub folder_rule: ContentFolderRule,
    /// Call `DownloadFiles` for files every location answered 404 for
    /// (MS-WSUSSS 3.2.4.4). It asks the upstream to fetch the files from its
    /// own parent, which changes the upstream server's state; set false to
    /// leave the upstream untouched.
    pub download_files_fallback: bool,
    /// Also try the Microsoft Update URL (`MUUrl`) when downloading content.
    pub allow_mu_url: bool,
}

impl WsusssConfig {
    /// Defaults for an upstream at `base_url`.
    pub fn new(base_url: &str, account_name: &str, account_guid: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            server_sync_path: "/ServerSyncWebService/ServerSyncWebService.asmx".into(),
            auth_url: None,
            content_base_url: None,
            soap_version: SoapVersion::V11,
            account_name: account_name.to_owned(),
            account_guid: account_guid.to_owned(),
            protocol_version: "1.20".into(),
            request_timeout: Duration::from_secs(120),
            retry: RetryPolicy::default(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            limits: Limits::default(),
            max_session_restarts: 2,
            busy_retries: 2,
            busy_delay: Duration::from_secs(5),
            cookie_skew_secs: 60,
            update_batch_size: 100,
            download_files_wait: Duration::from_secs(5),
            folder_rule: ContentFolderRule::LastTwoHexUpper,
            download_files_fallback: true,
            allow_mu_url: false,
        }
    }

    /// Full URL of the Server Sync service.
    pub fn sync_url(&self) -> String {
        format!("{}{}", self.base_url, self.server_sync_path)
    }
}
