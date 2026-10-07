//! The MS-WSUSSS client: sessions and calls.
use std::collections::VecDeque;
use std::sync::Arc;

use wsus_protocol::ProtocolError;
use wsus_protocol::identity::UpdateRevision;
use wsus_protocol::metadata::RawFragment;
use wsus_protocol::soap::{
    ErrorCode, Presence, SoapFault, SoapRequest, decode_response, encode_request,
};
use wsus_protocol::wsusss::{
    DownloadFiles, GetAuthConfig, GetAuthorizationCookie, GetConfigData, GetCookie, GetDeployments,
    GetRevisionIdList, GetUpdateData, IdAndDelta, ServerAuthConfig, ServerSyncConfigData,
    ServerSyncDeploymentResult, ServerSyncFilter,
};

use super::clock::{Clock, SystemClock, parse_unix};
use super::compress::{CabMetadataDecompressor, MetadataDecompressor};
use super::config::{
    ContentFolderRule, MAX_DOWNLOAD_FILES_DIGESTS, MAX_UPDATE_RESPONSE_BYTES, WsusssConfig,
};
use super::error::WsusssError;
use super::types::{FileLocation, RevisionList, RevisionQuery, UpdateBatch, UpdateRecord};
use crate::download::{
    DownloadError, DownloadOptions, DownloadedFile, Downloader, ExpectedFile, Location, hex_encode,
};
use crate::transport::{
    ErrorKind, HttpRequest, RetryTimer, SecretBytes, SensitiveUrl, Transport, scrub_urls,
    send_with_retry,
};
use wsus_protocol::wsusss::{AuthorizationCookie, Cookie};

#[derive(Default, Clone)]
struct Session {
    auth_cookie: Option<AuthorizationCookie>,
    cookie: Option<Cookie>,
    auth_url: Option<String>,
    config: Option<ServerSyncConfigData>,
}

impl Session {
    fn reset(&mut self) {
        self.auth_cookie = None;
        self.cookie = None;
        self.auth_url = None;
    }
}

/// Downstream MS-WSUSSS client.
///
/// Owns the session (authorization cookie, cookie, upstream configuration).
/// All calls take `&mut self`, so one client runs one operation at a time.
pub struct WsusssClient<T: Transport, S: RetryTimer> {
    config: WsusssConfig,
    transport: T,
    timer: S,
    clock: Arc<dyn Clock>,
    decompressor: Arc<dyn MetadataDecompressor>,
    session: Session,
    batch_size: usize,
}

fn origin(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    match url[after_scheme..].find('/') {
        Some(i) => &url[..after_scheme + i],
        None => url,
    }
}

fn fault_error(fault: SoapFault) -> WsusssError {
    let reason = scrub_urls(&fault.reason);
    match fault.wsus {
        Some(d) => WsusssError::Fault {
            code: d.error_code,
            reason,
            message: d.message.map(|m| scrub_urls(&m)),
        },
        None => WsusssError::Fault {
            code: ErrorCode::Unknown(fault.code),
            reason,
            message: None,
        },
    }
}

impl<T: Transport, S: RetryTimer> WsusssClient<T, S> {
    /// Fork a session for bounded concurrent read-only calls. The transport
    /// pool is shared; cookies, renewal and adaptive batch limits are independent.
    pub fn fork(&self) -> WsusssClient<&T, &S> {
        WsusssClient {
            config: self.config.clone(),
            transport: &self.transport,
            timer: &self.timer,
            clock: self.clock.clone(),
            decompressor: self.decompressor.clone(),
            session: self.session.clone(),
            batch_size: self.batch_size,
        }
    }
    /// Client with the wall clock and the Cabinet metadata decompressor.
    pub fn new(config: WsusssConfig, transport: T, timer: S) -> Self {
        let batch_size = config.update_batch_size.max(1);
        Self {
            config,
            transport,
            timer,
            clock: Arc::new(SystemClock),
            decompressor: Arc::new(CabMetadataDecompressor::default()),
            session: Session::default(),
            batch_size,
        }
    }

    /// Replace the clock (tests).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Install the `XmlUpdateBlobCompressed` decoder.
    pub fn with_decompressor(mut self, decompressor: Arc<dyn MetadataDecompressor>) -> Self {
        self.decompressor = decompressor;
        self
    }

    /// Configuration in force.
    pub fn config(&self) -> &WsusssConfig {
        &self.config
    }

    /// Transport, for callers that fetch content with the same backend.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Retry timer.
    pub fn timer(&self) -> &S {
        &self.timer
    }

    /// Upstream configuration from the last `GetConfigData`.
    pub fn server_config(&self) -> Option<&ServerSyncConfigData> {
        self.session.config.as_ref()
    }

    /// Current `GetUpdateData` batch size.
    pub fn update_batch_size(&self) -> usize {
        self.update_limit().min(self.batch_size).max(1)
    }

    fn update_limit(&self) -> usize {
        match &self.session.config {
            Some(c) if c.max_number_of_updates_per_request > 0 => {
                c.max_number_of_updates_per_request as usize
            }
            _ => self.config.update_batch_size.max(1),
        }
    }

    // ---- raw call ----

    async fn post<R: SoapRequest>(
        &self,
        url: &str,
        request: &R,
    ) -> Result<R::Response, WsusssError> {
        let encoded = encode_request(self.config.soap_version, request);
        let action = R::action();
        let url = SensitiveUrl::parse(url)
            .map_err(|_| WsusssError::Config("invalid service URL".into()))?;
        let mut http = HttpRequest::soap_post(
            url,
            encoded.soap_action.as_deref().unwrap_or(&action),
            &encoded.content_type,
            encoded.body,
            self.config.request_timeout,
        )
        .idempotent();
        http.max_response_bytes = self.config.max_response_bytes;
        let response =
            send_with_retry(&self.transport, &self.timer, &self.config.retry, &http).await?;
        let success = (200..300).contains(&response.status);
        match decode_response::<R::Response>(&response.body, &self.config.limits) {
            Ok(message) if success => Ok(message),
            Ok(_) => Err(WsusssError::HttpStatus {
                status: response.status,
            }),
            Err(ProtocolError::Fault(fault)) => Err(fault_error(*fault)),
            Err(error) if success => Err(WsusssError::Protocol(error)),
            Err(_) => Err(WsusssError::HttpStatus {
                status: response.status,
            }),
        }
    }

    // ---- authorization ----

    fn resolve_service_url(&self, service_url: &str) -> Result<String, WsusssError> {
        let s = service_url.trim();
        if s.is_empty() {
            return Err(WsusssError::Config(
                "empty authorization service URL".into(),
            ));
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            // An upstream must not redirect credentials to another origin.
            if origin(s) == origin(&self.config.base_url) {
                return Ok(s.to_owned());
            }
            return Err(WsusssError::Config(
                "authorization service URL has a different origin".into(),
            ));
        }
        Ok(format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            s.trim_start_matches('/')
        ))
    }

    /// `GetAuthConfig`.
    pub async fn get_auth_config(&self) -> Result<ServerAuthConfig, WsusssError> {
        let response = self
            .post(&self.config.sync_url(), &GetAuthConfig {})
            .await?;
        response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetAuthConfigResult"))
    }

    async fn auth_url(&mut self) -> Result<String, WsusssError> {
        if let Some(u) = &self.config.auth_url {
            return Ok(u.clone());
        }
        if let Some(u) = &self.session.auth_url {
            return Ok(u.clone());
        }
        let auth = self.get_auth_config().await?;
        let plugins = auth.auth_info.into_value().unwrap_or_default();
        let url = plugins
            .iter()
            .find(|p| {
                p.plug_in_id
                    .value()
                    .is_some_and(|id| id.eq_ignore_ascii_case("DssTargeting"))
            })
            .and_then(|p| p.service_url.value().cloned())
            .ok_or(WsusssError::MissingResult("DssTargeting plug-in"))?;
        let url = self.resolve_service_url(&url)?;
        self.session.auth_url = Some(url.clone());
        Ok(url)
    }

    async fn fetch_auth_cookie(&mut self) -> Result<(), WsusssError> {
        let url = self.auth_url().await?;
        let request = GetAuthorizationCookie {
            account_name: Presence::Value(self.config.account_name.clone()),
            account_guid: Presence::Value(self.config.account_guid.clone()),
            program_keys: Presence::Absent,
        };
        let response = self.post(&url, &request).await?;
        let cookie = response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetAuthorizationCookieResult"))?;
        self.session.auth_cookie = Some(cookie);
        Ok(())
    }

    async fn fetch_cookie(&mut self) -> Result<(), WsusssError> {
        let auth = self
            .session
            .auth_cookie
            .clone()
            .ok_or(WsusssError::MissingResult("authorization cookie"))?;
        let request = GetCookie {
            auth_cookies: Presence::Value(vec![auth]),
            old_cookie: match self.session.cookie.clone() {
                Some(c) => Presence::Value(c),
                None => Presence::Absent,
            },
            protocol_version: Presence::Value(self.config.protocol_version.clone()),
        };
        let response = self.post(&self.config.sync_url(), &request).await?;
        let cookie = response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetCookieResult"))?;
        self.session.cookie = Some(cookie);
        Ok(())
    }

    /// Run the full handshake: `GetAuthConfig` (unless the authorization URL
    /// is configured), `GetAuthorizationCookie`, `GetCookie`.
    pub async fn authorize(&mut self) -> Result<(), WsusssError> {
        self.session.cookie = None;
        self.fetch_auth_cookie().await?;
        self.fetch_cookie().await
    }

    fn cookie_expired(&self, cookie: &Cookie) -> bool {
        parse_unix(&cookie.expiration)
            .is_some_and(|t| t <= self.clock.now_unix() + self.config.cookie_skew_secs)
    }

    /// Make sure a usable cookie exists. An expired cookie is renewed with the
    /// authorization cookie; if that is rejected the handshake restarts. A
    /// cookie just obtained is used even if its expiry looks past, so a skewed
    /// upstream clock cannot cause a loop.
    async fn ensure_cookie(&mut self) -> Result<(), WsusssError> {
        let fresh = self
            .session
            .cookie
            .as_ref()
            .is_some_and(|c| !self.cookie_expired(c));
        if fresh {
            return Ok(());
        }
        if self.session.auth_cookie.is_some() {
            match self.fetch_cookie().await {
                Ok(()) => return Ok(()),
                Err(e) if matches!(e.fault_code(), Some(ErrorCode::InvalidAuthorizationCookie)) => {
                    self.session.reset();
                }
                Err(e) => return Err(e),
            }
        }
        self.authorize().await
    }

    /// Issue an authorized Server Sync call with bounded recovery:
    /// `InvalidCookie` / `InvalidAuthorizationCookie` restart authorization,
    /// `ServerBusy` is retried after a delay. Everything else, including
    /// `ServerChanged`, is returned.
    async fn authorized<R: SoapRequest>(
        &mut self,
        build: impl Fn(&Cookie) -> R,
    ) -> Result<R::Response, WsusssError> {
        let mut restarts = 0u32;
        let mut busy = 0u32;
        loop {
            self.ensure_cookie().await?;
            let cookie = self
                .session
                .cookie
                .clone()
                .ok_or(WsusssError::MissingResult("cookie"))?;
            let error = match self.post(&self.config.sync_url(), &build(&cookie)).await {
                Ok(response) => return Ok(response),
                Err(e) => e,
            };
            match error.fault_code() {
                Some(ErrorCode::InvalidCookie | ErrorCode::InvalidAuthorizationCookie)
                    if restarts < self.config.max_session_restarts =>
                {
                    restarts += 1;
                    self.session.reset();
                }
                Some(ErrorCode::ServerBusy) if busy < self.config.busy_retries => {
                    busy += 1;
                    self.timer.sleep(self.config.busy_delay * busy).await;
                }
                _ => return Err(error),
            }
        }
    }

    // ---- metadata ----

    /// `GetConfigData`; stores the limits for later batching.
    pub async fn get_config_data(
        &mut self,
        anchor: Option<&str>,
    ) -> Result<ServerSyncConfigData, WsusssError> {
        let anchor = anchor.map(str::to_owned);
        let response = self
            .authorized(|cookie| GetConfigData {
                cookie: Presence::Value(cookie.clone()),
                config_anchor: match &anchor {
                    Some(a) => Presence::Value(a.clone()),
                    None => Presence::Absent,
                },
            })
            .await?;
        let data = response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetConfigDataResult"))?;
        self.session.config = Some(data.clone());
        Ok(data)
    }

    /// `GetRevisionIdList`. The upstream does not page: the whole new set is
    /// returned and the caller batches `GetUpdateData`.
    pub async fn get_revision_ids(
        &mut self,
        query: &RevisionQuery,
    ) -> Result<RevisionList, WsusssError> {
        // `Delta`: observed on a real WSUS (inventory 9.5), with an anchor a listed id sent
        // with `Delta` false makes the upstream return ALL of that id's revisions again,
        // sent with `Delta` true only the ones changed since the anchor. So an incremental
        // call (anchor present, same filter: a changed filter restarts without an anchor)
        // sends true and the first call false.
        let delta = query.anchor.is_some();
        let to_filter = |ids: &[wsus_protocol::identity::UpdateId]| {
            if ids.is_empty() {
                Presence::Absent
            } else {
                Presence::Value(
                    ids.iter()
                        .map(|u| IdAndDelta { id: u.0, delta })
                        .collect::<Vec<_>>(),
                )
            }
        };
        let filter = ServerSyncFilter {
            dss_protocol_version: Presence::Absent,
            anchor: match &query.anchor {
                Some(a) => Presence::Value(a.clone()),
                None => Presence::Absent,
            },
            get_config: query.get_config,
            // The public protocol 1.2x service requires this element. It is
            // undefined for 1.1; false requests all supported languages.
            get63_language_only: if self.config.protocol_version == "1.1" {
                Presence::Absent
            } else {
                Presence::Value(false)
            },
            categories: to_filter(&query.categories),
            classifications: to_filter(&query.classifications),
            languages: Presence::Absent,
        };
        let response = self
            .authorized(|cookie| GetRevisionIdList {
                cookie: Presence::Value(cookie.clone()),
                filter: Presence::Value(filter.clone()),
            })
            .await?;
        let list = response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetRevisionIdListResult"))?;
        Ok(RevisionList {
            anchor: list.anchor.into_value(),
            revisions: list.new_revisions.into_value().unwrap_or_default(),
        })
    }

    /// `GetUpdateData` for at most [`WsusssClient::update_batch_size`] ids
    /// (the hard bound is the upstream's `MaxNumberOfUpdatesPerRequest`).
    ///
    /// If the response is larger than the transport limit the request is
    /// split and the batch size reduced. If the metadata of a response exceeds
    /// the 2,000,000 byte Windows response limit the next batches shrink.
    pub async fn get_update_data(
        &mut self,
        ids: &[UpdateRevision],
    ) -> Result<UpdateBatch, WsusssError> {
        if ids.is_empty() {
            return Ok(UpdateBatch::default());
        }
        let limit = self.update_limit();
        if ids.len() > limit {
            return Err(WsusssError::Limit(format!(
                "{} ids exceed MaxNumberOfUpdatesPerRequest {limit}",
                ids.len()
            )));
        }
        let mut work: VecDeque<Vec<UpdateRevision>> = VecDeque::from([ids.to_vec()]);
        let mut out = UpdateBatch::default();
        while let Some(chunk) = work.pop_front() {
            match self.get_update_data_once(&chunk).await {
                Ok(batch) => {
                    out.updates.extend(batch.updates);
                    out.file_locations.extend(batch.file_locations);
                }
                Err(WsusssError::Transport(e))
                    if e.kind == ErrorKind::TooLarge && chunk.len() > 1 =>
                {
                    let (a, b) = chunk.split_at(chunk.len() / 2);
                    self.batch_size = a.len().max(1);
                    work.push_front(b.to_vec());
                    work.push_front(a.to_vec());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    async fn get_update_data_once(
        &mut self,
        ids: &[UpdateRevision],
    ) -> Result<UpdateBatch, WsusssError> {
        let response = self
            .authorized(|cookie| GetUpdateData {
                cookie: Presence::Value(cookie.clone()),
                update_ids: Presence::Value(ids.to_vec()),
            })
            .await?;
        let data = response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetUpdateDataResult"))?;
        let decompressor = Arc::clone(&self.decompressor);
        let mut batch = UpdateBatch::default();
        let mut blob_bytes = 0usize;
        for item in data.updates.into_value().unwrap_or_default() {
            let identity = item
                .id
                .value()
                .copied()
                .ok_or(WsusssError::MissingResult("update id"))?;
            blob_bytes += item.xml_update_blob.value().map_or(0, String::len)
                + item.xml_update_blob_compressed.value().map_or(0, Vec::len);
            let mut decompress_error = None;
            let fragment = RawFragment::from_server_sync(None, &item, |c| {
                decompressor.decompress(c).map_err(|e| {
                    decompress_error = Some(e.to_string());
                    ProtocolError::Metadata("decompression failed".into())
                })
            });
            let fragment = match fragment {
                Ok(Some(f)) => f,
                Ok(None) => return Err(WsusssError::MissingResult("update metadata blob")),
                Err(e) => {
                    return Err(match decompress_error {
                        Some(m) => WsusssError::Decompress(m),
                        None => WsusssError::Protocol(e),
                    });
                }
            };
            batch.updates.push(UpdateRecord {
                identity,
                fragment,
                file_digests: item.file_digest_list.into_value().unwrap_or_default(),
            });
        }
        for url in data.file_urls.into_value().unwrap_or_default() {
            let Some(digest) = url.file_digest.into_value() else {
                continue;
            };
            let parse = |p: Presence<String>| {
                p.into_value()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| Location::parse(&s).ok())
            };
            batch.file_locations.push(FileLocation {
                digest,
                mu: parse(url.mu_url),
                uss: parse(url.uss_url),
                decryption_key: url.decryption_key.into_value().map(SecretBytes::new),
            });
        }
        if blob_bytes > MAX_UPDATE_RESPONSE_BYTES && ids.len() > 1 {
            self.batch_size = (ids.len() / 2).max(1);
        }
        Ok(batch)
    }

    /// `GetDeployments`. Replica mode is out of scope; provided for the
    /// later milestone and not used by the autonomous flow.
    pub async fn get_deployments(
        &mut self,
        deployment_anchor: Option<&str>,
        sync_anchor: &str,
    ) -> Result<ServerSyncDeploymentResult, WsusssError> {
        if sync_anchor.is_empty() {
            return Err(WsusssError::Config("syncAnchor must not be empty".into()));
        }
        let da = deployment_anchor.map(str::to_owned);
        let sa = sync_anchor.to_owned();
        let response = self
            .authorized(|cookie| GetDeployments {
                cookie: Presence::Value(cookie.clone()),
                deployment_anchor: match &da {
                    Some(a) => Presence::Value(a.clone()),
                    None => Presence::Absent,
                },
                sync_anchor: Presence::Value(sa.clone()),
            })
            .await?;
        response
            .result
            .into_value()
            .ok_or(WsusssError::MissingResult("GetDeploymentsResult"))
    }

    // ---- content ----

    /// `DownloadFiles`: ask the upstream to fetch files it lacks. At most 100
    /// SHA-1 digests per call. `FileDigestsMissing` is returned as a fault.
    pub async fn download_files(&mut self, digests: &[Vec<u8>]) -> Result<(), WsusssError> {
        if digests.is_empty() {
            return Ok(());
        }
        if digests.len() > MAX_DOWNLOAD_FILES_DIGESTS {
            return Err(WsusssError::Limit(format!(
                "{} digests exceed the DownloadFiles limit of {MAX_DOWNLOAD_FILES_DIGESTS}",
                digests.len()
            )));
        }
        self.authorized(|cookie| DownloadFiles {
            cookie: Presence::Value(cookie.clone()),
            file_digest_list: Presence::Value(digests.to_vec()),
        })
        .await?;
        Ok(())
    }

    /// `Content/<folder>/<file>` URL under the configured content base, or
    /// `None` without a base or with a digest that is not a SHA-1. The file
    /// name is the hex SHA-1 plus the extension of `file_name` (lower-cased;
    /// observed only as `.exe`, inventory 9.5).
    pub fn convention_location(&self, sha1: &[u8], file_name: Option<&str>) -> Option<Location> {
        let base = self.config.content_base_url.as_ref()?;
        if sha1.len() != 20 {
            return None;
        }
        let hex = hex_encode(sha1);
        let hex = match self.config.folder_rule {
            ContentFolderRule::LastTwoHexLower => hex.to_ascii_lowercase(),
            ContentFolderRule::LastTwoHexUpper => hex.to_ascii_uppercase(),
        };
        let folder = &hex[hex.len() - 2..];
        let ext = file_name
            .and_then(|n| n.rsplit_once('.'))
            .map(|(_, e)| e)
            .filter(|e| {
                !e.is_empty() && e.len() <= 8 && e.bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .map(|e| format!(".{}", e.to_ascii_lowercase()))
            .unwrap_or_default();
        Location::parse(&format!(
            "{}/Content/{folder}/{hex}{ext}",
            base.trim_end_matches('/')
        ))
        .ok()
    }

    /// Candidate locations for a file in preference order: the upstream's own
    /// URL, the content convention, then (if allowed) the Microsoft Update URL.
    pub fn content_candidates(
        &self,
        sha1: Option<&[u8]>,
        file_name: Option<&str>,
        known: Option<&FileLocation>,
    ) -> Vec<Location> {
        let mut out = Vec::new();
        if let Some(l) = known.and_then(|k| k.uss.clone()) {
            out.push(l);
        }
        if let Some(l) = sha1.and_then(|d| self.convention_location(d, file_name)) {
            out.push(l);
        }
        if self.config.allow_mu_url
            && let Some(l) = known.and_then(|k| k.mu.clone())
        {
            out.push(l);
        }
        out
    }

    /// One pass over the candidates with the existing [`Downloader`]; no
    /// `DownloadFiles`. A 404 from every location is returned as
    /// `WsusssError::Download(DownloadError::HttpStatus { status: 404, .. })`
    /// (see [`WsusssError::is_not_found`]).
    pub async fn download_content_once(
        &self,
        downloader: &Downloader,
        expected: &ExpectedFile,
        candidates: &[Location],
        options: &DownloadOptions,
    ) -> Result<DownloadedFile, WsusssError> {
        if candidates.is_empty() {
            return Err(WsusssError::NoLocation);
        }
        let mut last = None;
        let mut not_found = None;
        for location in candidates {
            match downloader
                .download_with_retry(&self.transport, &self.timer, expected, location, options)
                .await
            {
                Ok(file) => return Ok(file),
                Err(e) => {
                    if matches!(e, DownloadError::HttpStatus { status: 404, .. })
                        && not_found.is_none()
                    {
                        not_found = Some(e);
                    } else {
                        last = Some(e);
                    }
                }
            }
        }
        // A not-found anywhere wins over a later transport error so the caller
        // can decide on `DownloadFiles`.
        match not_found.or(last) {
            Some(e) => Err(WsusssError::Download(e)),
            None => Err(WsusssError::NoLocation),
        }
    }

    /// Download one verified file from the candidates with the existing
    /// [`Downloader`]. If every location answers 404, the SHA-1 is known and
    /// `download_files_fallback` is set, `DownloadFiles` is called once and
    /// the locations are tried again.
    pub async fn download_content(
        &mut self,
        downloader: &Downloader,
        expected: &ExpectedFile,
        sha1: Option<&[u8]>,
        candidates: &[Location],
        options: &DownloadOptions,
    ) -> Result<DownloadedFile, WsusssError> {
        let first = self
            .download_content_once(downloader, expected, candidates, options)
            .await;
        match (first, sha1) {
            (Err(e), Some(d)) if e.is_not_found() && self.config.download_files_fallback => {
                self.download_files(&[d.to_vec()]).await?;
                self.timer.sleep(self.config.download_files_wait).await;
                self.download_content_once(downloader, expected, candidates, options)
                    .await
            }
            (result, _) => result,
        }
    }
}
