//! Configuration file (TOML).
//!
//! One file describes the client profile, the server, the optional upstream
//! source and logging. Relative paths are resolved against the directory that
//! contains the file. Unknown keys are rejected so a typo never silently falls
//! back to a default.
//!
//! Secrets are never configuration: the file holds no credentials, cookies or
//! signing keys. The server's cookie signing key lives in its database.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use wsus_client::transport::redact_url;

/// Whole configuration file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub network: NetworkSection,
    pub client: ClientSection,
    pub server: ServerSection,
    pub upstream: Option<UpstreamSection>,
    pub logging: LoggingSection,
    pub install: InstallSection,
}

/// Proxy and trust settings shared by the client and the upstream
/// synchronization. Both are applied to the HTTP backend only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkSection {
    /// Proxy URL for every request (`http://host:port`); none by default.
    pub proxy: Option<String>,
    /// PEM files with extra trusted root certificates.
    pub trust_roots: Vec<PathBuf>,
}

/// Declared description of the machine, sent in `RegisterComputer`. These are
/// declarations, not detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ComputerSection {
    pub os_major: i32,
    pub os_minor: i32,
    pub os_build: i32,
    pub locale: String,
    pub processor_architecture: String,
}

impl Default for ComputerSection {
    fn default() -> Self {
        Self {
            os_major: 10,
            os_minor: 0,
            os_build: 26100,
            locale: "en-US".into(),
            processor_architecture: "9".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientSection {
    /// Origin of the WSUS server, `http://host:port`.
    pub origin: Option<String>,
    /// Directory for state, revision records, event queue and content.
    pub state_dir: PathBuf,
    /// DNS name presented to the server.
    pub dns_name: String,
    /// Target group requested from SimpleAuth.
    pub target_group: Option<String>,
    /// Optional path overrides (the defaults follow MS-WUSP prose).
    pub client_path: Option<String>,
    pub auth_path: Option<String>,
    pub reporting_path: Option<String>,
    pub request_timeout_secs: u64,
    pub max_response_bytes: usize,
    /// Send `Accept-Encoding: xpress` on SOAP requests (default true).
    pub accept_xpress: bool,
    pub max_retries: u32,
    /// Category filter (`FilterCategoryIds`), update-id GUIDs.
    pub filter_categories: Vec<String>,
    pub max_concurrent_downloads: usize,
    pub max_file_size_bytes: u64,
    /// Pages of `SyncUpdates` allowed per run.
    pub max_sync_pages: u32,
    pub computer: ComputerSection,
}

/// Default cap on one response and on one decoded SOAP document. OBSERVED: a real Windows 11
/// `SyncUpdates` page decodes to about 51 MB and one update's Core fragment reaches 47 MB, so the
/// earlier 32 MiB cap rejected a real catalog.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            origin: None,
            state_dir: PathBuf::from("client"),
            dns_name: "wsus-client.invalid".into(),
            target_group: None,
            client_path: None,
            auth_path: None,
            reporting_path: None,
            request_timeout_secs: 60,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            accept_xpress: true,
            max_retries: 3,
            filter_categories: Vec::new(),
            max_concurrent_downloads: 4,
            max_file_size_bytes: 64 * 1024 * 1024 * 1024,
            max_sync_pages: 1000,
            computer: ComputerSection::default(),
        }
    }
}

/// `[server] sync_delivery`: how `SyncUpdates` chooses what to deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncDeliverySetting {
    /// Real-WSUS-like, installed-list driven delivery (default).
    #[default]
    Staged,
    /// Whole approved closure at once, ignoring the installed list.
    Closure,
}

/// `[server] delivery_scope`: which updates a computer is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryScopeSetting {
    /// Approved updates and their prerequisite, category and bundle closure (default).
    #[default]
    Approved,
    /// Every non-declined update, as a real WSUS delivers.
    AllNonDeclined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSection {
    /// Listen address. Plain HTTP only; keep it on loopback or behind a
    /// TLS-terminating proxy.
    pub listen: String,
    pub database: PathBuf,
    pub content_dir: PathBuf,
    /// Catalog source whose active generation is served.
    pub source_name: String,
    /// Origin used to build file URLs; the request `Host` header when absent.
    pub advertised_content_url: Option<String>,
    pub max_request_bytes: Option<usize>,
    pub max_array_len: Option<usize>,
    /// `NewUpdates` per response: 30 when absent (200 with `sync_delivery = "closure"`).
    pub max_sync_new_updates: Option<usize>,
    /// `"staged"` (default) or `"closure"`; see docs/wsus-cli.md.
    pub sync_delivery: SyncDeliverySetting,
    /// `"approved"` (default) or `"all_non_declined"`; see docs/wsus-cli.md.
    pub delivery_scope: DeliveryScopeSetting,
    /// Advertised `ProtocolVersion`: 3.2 staged, 3.0 closure when absent.
    pub protocol_version: Option<String>,
    /// Cap on `InstalledNonLeafUpdateIDs` (staged); 400 when absent, 0 disables.
    pub max_installed_non_leaf_ids: Option<usize>,
    /// Staged: answer cached revisions with unsatisfied prerequisites out of scope; on when
    /// absent.
    pub out_of_scope_unsatisfied: Option<bool>,
    pub max_extended_updates_per_request: Option<usize>,
    pub max_file_digests_per_request: Option<usize>,
    pub max_events_per_batch: Option<usize>,
    /// Compress SOAP responses with `Content-Encoding: xpress` for clients
    /// that send `Accept-Encoding: xpress`; on when absent.
    pub xpress_responses: Option<bool>,
    /// `Config.AllowedEventIds`; empty allows every event id.
    pub allowed_event_ids: Vec<i32>,
    pub cookie_ttl_secs: Option<i64>,
    pub auth_cookie_ttl_secs: Option<i64>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8530".into(),
            database: PathBuf::from("server/wsus.sqlite"),
            content_dir: PathBuf::from("server/content"),
            source_name: "upstream".into(),
            advertised_content_url: None,
            max_request_bytes: None,
            max_array_len: None,
            max_sync_new_updates: None,
            sync_delivery: SyncDeliverySetting::default(),
            delivery_scope: DeliveryScopeSetting::default(),
            protocol_version: None,
            max_installed_non_leaf_ids: None,
            out_of_scope_unsatisfied: None,
            max_extended_updates_per_request: None,
            max_file_digests_per_request: None,
            max_events_per_batch: None,
            xpress_responses: None,
            allowed_event_ids: Vec::new(),
            cookie_ttl_secs: None,
            auth_cookie_ttl_secs: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamSection {
    /// Origin of the upstream WSUS (`http://host:port`).
    pub origin: String,
    /// Identity of the upstream endpoint; changing it forces a full resync.
    pub endpoint_key: Option<String>,
    pub account_name: String,
    pub account_guid: String,
    /// Base of `Content/<folder>/<file>` URLs; defaults to `origin` (the real
    /// WSUS observed serves content on its web-service port, inventory 9.5).
    pub content_base_url: Option<String>,
    /// Ask the upstream to fetch files it lacks (`DownloadFiles`, MS-WSUSSS
    /// 3.2.4.4). That changes the upstream's state; set false to leave it alone.
    pub download_files_fallback: bool,
    /// Also use transient Microsoft Update file locations returned upstream.
    pub allow_mu_url: bool,
    /// Maximum simultaneous content transfers (metadata calls remain serialized).
    pub download_concurrency: usize,
    /// Maximum simultaneous metadata batches.
    pub metadata_concurrency: usize,
    /// Report synchronization transfer totals and speed to stderr.
    pub progress: bool,
    /// Product category ids (update-id GUIDs).
    pub products: Vec<String>,
    /// Classification ids (update-id GUIDs).
    pub classifications: Vec<String>,
    pub send_wire_filter: bool,
    /// Superseded generations kept after activation; none disables pruning.
    pub keep_superseded_generations: Option<usize>,
    pub request_timeout_secs: u64,
}

impl Default for UpstreamSection {
    fn default() -> Self {
        Self {
            origin: String::new(),
            endpoint_key: None,
            account_name: "wsus-cli".into(),
            account_guid: "00000000-0000-0000-0000-000000000000".into(),
            content_base_url: None,
            download_files_fallback: true,
            allow_mu_url: false,
            download_concurrency: 4,
            metadata_concurrency: 4,
            progress: true,
            products: Vec::new(),
            classifications: Vec::new(),
            send_wire_filter: true,
            keep_superseded_generations: Some(2),
            request_timeout_secs: 120,
        }
    }
}

/// `[install]`: the installing client (`wsus client install`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InstallSection {
    /// Allowed signer organisations of payloads (matched on the signing
    /// certificate's `O`, else `CN`). `--trust-signer` on the command line
    /// replaces this list.
    pub trust_signers: Vec<String>,
    /// Timeout of one installer process.
    pub timeout_secs: u64,
    /// Longest wait after the last step for the evaluator to say installed
    /// (polled every 2 s; 0 disables waiting).
    pub post_check_wait_secs: u64,
    /// Handler URIs treated as Windows Installer handlers (only with the
    /// `msi-handler` feature; unverified).
    pub msi_handler_uris: Vec<String>,
    /// Plan an installable prerequisite update (for example a servicing stack update) as an earlier
    /// step (plan schema `wsus-install-plan/2`). Off by default.
    pub plan_prerequisites: bool,
    /// Treat `CbsPackageInstallable` as True when planning and let the servicing stack decide at
    /// execution time (`PlanOptions::delegate_cbs_installable`). Off by default.
    pub delegate_cbs_installable: bool,
    /// Servicing backend of `Cbs` steps with the `cbs-handler` feature: `dism` (default), `wusa` (for
    /// `.msu` payloads) or `dism_api` (in-process `DismApi.dll`, loaded
    /// dynamically).
    pub servicing_backend: String,
    /// How `OSInstaller` updates are executed: `update_agent` (default; drives `UpdateAgent.dll`, needs
    /// the `osinstaller-handler` feature) or `dism` (adds the canonical `.cab` with the servicing
    /// backend, needs `cbs-handler`).
    pub osinstaller_mode: String,
    /// Directory holding the stack of a delivered `DesktopDeployment.cab` for `update_agent` mode
    /// (every DLL in it is signature-verified before the load). Unset: the OS's own `System32` stack.
    pub osinstaller_stack_dir: Option<String>,
    /// Queue install outcome events (`181` then `183`, `201` or `182`, the shapes a native agent
    /// sent) after every install job that succeeded, needs a restart or failed; delivered by the
    /// next `client sync`, `client report` or the install itself. Off by default.
    pub report_events: bool,
    /// Queue uninstall outcome events (`226` then `222`, `224` or `221`) after `client uninstall`.
    /// Their ids come from the real WSUS's event table; no native agent was seen to send one.
    /// Switched separately from `report_events`. Delivered by the next `client sync` or
    /// `client report`. Off by default.
    pub report_uninstall_events: bool,
    /// Queue the client status event `156` (the `U` and `V` lists of updates this client evaluates
    /// as not installed and installed) after `client sync` and after an install or uninstall job,
    /// built from the evaluator's own verdicts against the machine facts; `client report
    /// --inventory` emits it explicitly. The real WSUS derives an update's installed and
    /// not-installed state for a computer from this event. Delivered by the next `client sync`,
    /// `client report` or the install itself. Off by default.
    pub report_inventory: bool,
}

impl Default for InstallSection {
    fn default() -> Self {
        Self {
            trust_signers: vec![wsus_client::install::signature::DEFAULT_SIGNER.to_owned()],
            timeout_secs: 30 * 60,
            post_check_wait_secs: 180,
            msi_handler_uris: Vec::new(),
            plan_prerequisites: false,
            delegate_cbs_installable: false,
            servicing_backend: "dism".into(),
            osinstaller_mode: "update_agent".into(),
            osinstaller_stack_dir: None,
            report_events: false,
            report_uninstall_events: false,
            report_inventory: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingSection {
    /// Default filter, for example `info` or `wsus_cli=debug`.
    pub level: String,
    /// `text` or `json`.
    pub format: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "text".into(),
        }
    }
}

impl Config {
    /// Reads and validates a file; relative paths become absolute against its
    /// directory.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read configuration {}", path.display()))?;
        let mut config: Config = toml::from_str(&text)
            .with_context(|| format!("invalid configuration {}", path.display()))?;
        let base = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        config.resolve(base);
        config.validate()?;
        Ok(config)
    }

    /// Defaults resolved against `base`, for commands that run without a file.
    pub fn defaults_in(base: &Path) -> Self {
        let mut config = Self::default();
        config.resolve(base);
        config
    }

    fn resolve(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.client.state_dir);
        fix(&mut self.server.database);
        fix(&mut self.server.content_dir);
        for root in &mut self.network.trust_roots {
            fix(root);
        }
    }

    /// Checks values that would otherwise fail late.
    pub fn validate(&self) -> Result<()> {
        if let Some(origin) = &self.client.origin {
            check_origin("client.origin", origin)?;
        }
        if let Some(up) = &self.upstream {
            if !(1..=32).contains(&up.download_concurrency) {
                bail!("upstream.download_concurrency must be between 1 and 32");
            }
            if !(1..=16).contains(&up.metadata_concurrency) {
                bail!("upstream.metadata_concurrency must be between 1 and 16");
            }
            check_origin("upstream.origin", &up.origin)?;
            if let Some(c) = &up.content_base_url {
                check_origin("upstream.content_base_url", c)?;
            }
            for id in up.products.iter().chain(&up.classifications) {
                parse_guid("upstream filter", id)?;
            }
        }
        if let Some(c) = &self.server.advertised_content_url {
            check_origin("server.advertised_content_url", c)?;
        }
        if let Some(p) = &self.network.proxy {
            check_origin("network.proxy", p)?;
        }
        self.server
            .listen
            .parse::<SocketAddr>()
            .with_context(|| "server.listen must be an address such as 127.0.0.1:8530")?;
        for id in &self.client.filter_categories {
            parse_guid("client.filter_categories", id)?;
        }
        match self.logging.format.as_str() {
            "text" | "json" => {}
            _ => bail!("logging.format must be `text` or `json`"),
        }
        if self.client.max_concurrent_downloads == 0 {
            bail!("client.max_concurrent_downloads must be positive");
        }
        if self.install.trust_signers.is_empty()
            || self
                .install
                .trust_signers
                .iter()
                .any(|s| s.trim().is_empty())
        {
            bail!("install.trust_signers must list at least one non-empty signer");
        }
        if self.install.timeout_secs == 0 {
            bail!("install.timeout_secs must be positive");
        }
        Ok(())
    }

    /// Client origin or an error naming the missing setting.
    pub fn client_origin(&self) -> Result<&str> {
        self.client
            .origin
            .as_deref()
            .context("client.origin is not configured (run `wsus client configure --origin URL`)")
    }

    /// Sanitized view for diagnostics: origins are reduced to scheme and
    /// host, paths are not included.
    pub fn profile(&self) -> serde_json::Value {
        let host = |o: &Option<String>| o.as_deref().map(redact_url);
        serde_json::json!({
            "client": {
                "origin": host(&self.client.origin),
                "request_timeout_secs": self.client.request_timeout_secs,
                "max_response_bytes": self.client.max_response_bytes,
                "accept_xpress": self.client.accept_xpress,
                "max_retries": self.client.max_retries,
                "filter_categories": self.client.filter_categories.len(),
                "max_concurrent_downloads": self.client.max_concurrent_downloads,
                "max_file_size_bytes": self.client.max_file_size_bytes,
                "target_group_set": self.client.target_group.is_some(),
            },
            "server": {
                "listen": self.server.listen,
                "source_name": self.server.source_name,
                "advertised_content_url": host(&self.server.advertised_content_url),
                "max_request_bytes": self.server.max_request_bytes,
                "max_array_len": self.server.max_array_len,
                "max_sync_new_updates": self.server.max_sync_new_updates,
                "sync_delivery": self.server.sync_delivery,
                "delivery_scope": self.server.delivery_scope,
                "protocol_version": self.server.protocol_version,
                "max_installed_non_leaf_ids": self.server.max_installed_non_leaf_ids,
                "out_of_scope_unsatisfied": self.server.out_of_scope_unsatisfied,
                "max_extended_updates_per_request": self.server.max_extended_updates_per_request,
                "max_file_digests_per_request": self.server.max_file_digests_per_request,
                "max_events_per_batch": self.server.max_events_per_batch,
                "xpress_responses": self.server.xpress_responses,
                "allowed_event_ids": self.server.allowed_event_ids.len(),
            },
            "upstream": self.upstream.as_ref().map(|u| serde_json::json!({
                "origin": redact_url(&u.origin),
                "products": u.products.len(),
                "classifications": u.classifications.len(),
                "send_wire_filter": u.send_wire_filter,
                "keep_superseded_generations": u.keep_superseded_generations,
            })),
            "network": {
                "proxy_set": self.network.proxy.is_some(),
                "trust_roots": self.network.trust_roots.len(),
            },
            "logging": { "level": self.logging.level, "format": self.logging.format },
        })
    }

    /// Writes the file atomically (comments of a previous file are lost).
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).context("cannot serialize configuration")?;
        wsus_client::state::atomic_write(path, text.as_bytes())
            .with_context(|| format!("cannot write configuration {}", path.display()))?;
        Ok(())
    }
}

/// Accepts `http://host[:port]` and `https://host[:port]` without userinfo,
/// path, query or fragment.
pub fn check_origin(name: &str, value: &str) -> Result<()> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .with_context(|| format!("{name} must start with http:// or https://"))?;
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() || rest.contains(['@', '?', '#', ' ']) || rest.contains('/') {
        bail!("{name} must be a bare origin: scheme, host and optional port");
    }
    Ok(())
}

/// Parses a GUID, naming the setting on failure.
pub fn parse_guid(what: &str, value: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(value).with_context(|| format!("{what}: `{value}` is not a GUID"))
}
