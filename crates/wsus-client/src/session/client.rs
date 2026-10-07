//! The MS-WUSP session state machine.
//!
//! Sequence (plan 6.1): `GetConfig`, `GetAuthorizationCookie`, `GetCookie`,
//! then `RegisterComputer` when the server requires it. The cookie is kept in
//! the [`StateStore`] and reused until it is within the renewal skew of its
//! expiry. Faults are mapped to the recovery the specification prescribes
//! (`ErrorCode::wusp_recovery`); recoveries are bounded per call and per run,
//! so a failing server cannot make the client restart a whole
//! synchronization repeatedly.
//!
//! Evidence: the sequence, fault table and message shapes are Specified
//! (MS-WUSP 38.0). No behaviour here has been validated against a real WSUS.

use super::{
    Clock, SessionConfig, SystemClock, WuspError,
    clock::{unix_to_xs, xs_to_unix},
    error::FaultInfo,
};
use crate::{
    state::{ClientState, RegistrationState, StateStore, StoredCookie},
    transport::{
        Failure, HttpRequest, HttpResponse, Idempotence, RetryPolicy, RetryTimer, SecretBytes,
        SensitiveUrl, Transport, retry::parse_retry_after,
    },
};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use uuid::Uuid;
use wsus_protocol::{
    ProtocolError,
    common::{AuthorizationCookie, Cookie},
    identity::{ComputerId, ServerId, UpdateRevision},
    soap::{
        ErrorCode, Presence, Recovery, SoapFault, SoapRequest, XsDateTime, decode_response,
        encode_request,
    },
    wusp::{Config, GetAuthorizationCookie, GetConfig, GetCookie, RefreshCache, RegisterComputer},
};

/// Counters describing what a session did; for diagnostics and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Full `GetConfig` + authorization + `GetCookie` sequences.
    pub handshakes: u32,
    /// Cookie renewals without `GetConfig` (expiry or `CookieExpired`).
    pub cookie_renewals: u32,
    /// Successful `RegisterComputer` calls.
    pub registrations: u32,
    /// Fault-driven recoveries performed.
    pub recoveries: u32,
    /// A `GetConfig` reported a different `LastChange` than the persisted one.
    pub config_changes: u32,
    /// The persisted state belonged to another server and was discarded.
    pub server_changes: u32,
    /// `RefreshCache` runs.
    pub cache_refreshes: u32,
}

/// WSUS web service an authenticated call targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// Client web service.
    Client,
    /// Reporting web service.
    Reporting,
}

/// A session with one WSUS server.
pub struct WuspSession<T: Transport, S: RetryTimer, C: Clock = SystemClock> {
    transport: T,
    timer: S,
    clock: C,
    config: SessionConfig,
    store: StateStore,
    server_id: ServerId,
    server_config: Option<Config>,
    last_change: Option<XsDateTime>,
    auth_url: Option<String>,
    exact_cookie: Option<Cookie>,
    recoveries_this_run: u32,
    stats: SessionStats,
}

impl<T: Transport, S: RetryTimer, C: Clock> std::fmt::Debug for WuspSession<T, S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WuspSession")
            .field("server_id", &self.server_id)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// Returns the identity body of a SOAP response: unchanged without a
/// `Content-Encoding` (or `identity`), Xpress-decoded for `xpress` with the
/// decoded size capped at `max_bytes`, an error for anything else.
fn decode_body(response: &HttpResponse, max_bytes: usize) -> Result<Cow<'_, [u8]>, WuspError> {
    let Some(value) = response.headers.get("content-encoding") else {
        return Ok(Cow::Borrowed(&response.body));
    };
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("identity") {
        Ok(Cow::Borrowed(&response.body))
    } else if value.eq_ignore_ascii_case("xpress") {
        let limits = wsus_protocol::xpress::Limits::with_max_total(max_bytes);
        Ok(Cow::Owned(wsus_protocol::xpress::decode(
            &response.body,
            &limits,
        )?))
    } else {
        Err(WuspError::UnsupportedEncoding)
    }
}

fn derive_server_id(base_url: &str) -> ServerId {
    let digest = Sha256::digest(format!("wsus-server-v1\0{}", base_url.to_ascii_lowercase()));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    ServerId(Uuid::from_bytes(bytes))
}

fn fault_info(fault: &SoapFault) -> FaultInfo {
    let (code, message, method) = match &fault.wsus {
        Some(w) => (w.error_code.clone(), w.message.clone(), w.method.clone()),
        None => (
            ErrorCode::Unknown(fault.code_local().to_owned()),
            None,
            None,
        ),
    };
    FaultInfo {
        code,
        reason: fault.reason.clone(),
        message,
        method,
    }
}

fn to_stored(cookie: &Cookie) -> Result<StoredCookie, WuspError> {
    let expires_unix =
        xs_to_unix(&cookie.expiration).ok_or_else(|| ProtocolError::InvalidValue {
            element: "Expiration".into(),
            kind: "dateTime",
            value: cookie.expiration.as_str().to_owned(),
        })?;
    Ok(StoredCookie {
        expires_unix,
        data: SecretBytes::new(cookie.encrypted_data.value().cloned().unwrap_or_default()),
    })
}

impl<T: Transport, S: RetryTimer, C: Clock> WuspSession<T, S, C> {
    /// Opens a session over persisted state. Creates and persists a stable
    /// computer identity; discards server-local state when the configured
    /// server differs from the persisted one.
    pub fn new(
        transport: T,
        timer: S,
        clock: C,
        config: SessionConfig,
        mut store: StateStore,
    ) -> Result<Self, WuspError> {
        let server_id = config
            .server_id
            .unwrap_or_else(|| derive_server_id(&config.base_url));
        let previous = store.state().source_server;
        let server_changed = previous.is_some_and(|p| p != server_id);
        let needs_write =
            server_changed || previous.is_none() || store.state().computer_id.is_none();
        if needs_write {
            store.update(|s| {
                if server_changed {
                    // Server-local ids, cookie and registration belong to the
                    // old server (plan section 5).
                    s.cookie = None;
                    s.registration = RegistrationState::Unregistered;
                    s.sync_checkpoint = None;
                    s.cached_revisions.clear();
                    s.config_generation = None;
                }
                s.source_server = Some(server_id);
                if s.computer_id.is_none() {
                    s.computer_id = Some(ComputerId(Uuid::new_v4()));
                }
            })?;
        }
        let stats = SessionStats {
            server_changes: u32::from(server_changed),
            ..SessionStats::default()
        };
        Ok(Self {
            transport,
            timer,
            clock,
            config,
            store,
            server_id,
            server_config: None,
            last_change: None,
            auth_url: None,
            exact_cookie: None,
            recoveries_this_run: 0,
            stats,
        })
    }

    /// Persisted client state.
    pub fn state(&self) -> &ClientState {
        self.store.state()
    }

    /// Identity of the source server.
    pub fn server_id(&self) -> ServerId {
        self.server_id
    }

    /// Session counters.
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Configuration in use.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// `Config` of the last `GetConfig` in this process, if any.
    pub fn server_config(&self) -> Option<&Config> {
        self.server_config.as_ref()
    }

    /// Transport, for content downloads that share the backend.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Retry timer.
    pub fn timer(&self) -> &S {
        &self.timer
    }

    /// Retry policy for non-SOAP operations driven by the same session.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.config.retry
    }

    /// Current time.
    pub fn now_unix(&self) -> i64 {
        self.clock.now_unix()
    }

    pub(crate) fn store_mut(&mut self) -> &mut StateStore {
        &mut self.store
    }

    /// Resets the per-run recovery budget; call at the start of each
    /// synchronization or report run.
    pub fn begin_run(&mut self) {
        self.recoveries_this_run = 0;
    }

    /// `MaxExtendedUpdatesPerRequest` from `GetConfig` (default 50). The
    /// specification says the request count MUST be below the limit; the
    /// boundary is Unverified, so one less is used.
    pub fn max_extended_updates(&self) -> usize {
        let limit = self
            .server_config
            .as_ref()
            .and_then(|c| c.properties.value())
            .and_then(|props| {
                props.iter().find(|p| {
                    p.name
                        .value()
                        .is_some_and(|n| n == "MaxExtendedUpdatesPerRequest")
                })
            })
            .and_then(|p| p.value.value())
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(50);
        limit.saturating_sub(1).max(1)
    }

    fn computer_id(&self) -> Result<ComputerId, WuspError> {
        self.store
            .state()
            .computer_id
            .ok_or(WuspError::Config("computer id missing"))
    }

    fn url(&self, service: Service) -> String {
        match service {
            Service::Client => self.config.url(&self.config.client_path),
            Service::Reporting => self.config.url(&self.config.reporting_path),
        }
    }

    fn auth_url(&self) -> String {
        self.auth_url
            .clone()
            .unwrap_or_else(|| self.config.url(&self.config.auth_path))
    }

    // ---- transport ---------------------------------------------------------

    async fn send_raw<R: SoapRequest>(
        &self,
        url: &str,
        request: &R,
        idempotence: Idempotence,
    ) -> Result<R::Response, WuspError> {
        let encoded = encode_request(self.config.soap_version, request);
        let target =
            SensitiveUrl::parse(url).map_err(|_| WuspError::Config("invalid service URL"))?;
        let mut http = HttpRequest::soap_post(
            target,
            encoded.soap_action.as_deref().unwrap_or(""),
            &encoded.content_type,
            encoded.body,
            self.config.request_timeout,
        );
        http.max_response_bytes = self.config.max_response_bytes;
        http.idempotence = idempotence;
        if self.config.accept_xpress {
            http.headers.set("Accept-Encoding", "xpress");
        }
        let mut attempt = 0u32;
        loop {
            let delay = match self.transport.send(http.clone()).await {
                Ok(response) => {
                    let success = (200..300).contains(&response.status);
                    let body = match decode_body(&response, self.config.max_response_bytes) {
                        Ok(body) => body,
                        Err(error) if success => return Err(error),
                        // An undecodable error body is treated as absent.
                        Err(_) => Cow::Borrowed(&[][..]),
                    };
                    match decode_response::<R::Response>(&body, &self.config.limits) {
                        Ok(message) if success => return Ok(message),
                        Err(ProtocolError::Fault(fault)) => {
                            return Err(WuspError::Fault(fault_info(&fault)));
                        }
                        Err(error) if success => return Err(error.into()),
                        _ => {
                            let retry_after =
                                parse_retry_after(response.headers.get("retry-after"));
                            match self.config.retry.decide(
                                idempotence,
                                attempt,
                                Failure::Status {
                                    status: response.status,
                                    retry_after,
                                },
                            ) {
                                Some(delay) => delay,
                                None => {
                                    return Err(WuspError::Http {
                                        status: response.status,
                                        retry_after,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    match self
                        .config
                        .retry
                        .decide(idempotence, attempt, Failure::Transport(&error))
                    {
                        Some(delay) => delay,
                        None => return Err(error.into()),
                    }
                }
            };
            self.timer.sleep(delay).await;
            attempt += 1;
        }
    }

    // ---- cookie and handshake ---------------------------------------------

    fn current_cookie(&self) -> Result<Cookie, WuspError> {
        let stored = self
            .store
            .state()
            .cookie
            .as_ref()
            .ok_or(WuspError::Config("no session cookie"))?;
        if let Some(exact) = &self.exact_cookie
            && to_stored(exact).is_ok_and(|s| &s == stored)
        {
            return Ok(exact.clone());
        }
        // After a restart only the stored form exists; Expiration is rebuilt
        // from the persisted instant (sub-second precision is not kept).
        Ok(Cookie {
            expiration: unix_to_xs(stored.expires_unix),
            encrypted_data: Presence::Value(stored.data.expose().to_vec()),
        })
    }

    /// Persists a cookie issued by the server (`GetCookie` or a `NewCookie`).
    pub(crate) fn adopt_cookie(&mut self, cookie: &Cookie) -> Result<(), WuspError> {
        let stored = to_stored(cookie)?;
        self.store.update(|s| s.cookie = Some(stored))?;
        self.exact_cookie = Some(cookie.clone());
        Ok(())
    }

    fn charge_recovery(
        &mut self,
        operation: &'static str,
        cause: WuspError,
    ) -> Result<(), WuspError> {
        self.recoveries_this_run += 1;
        if self.recoveries_this_run > self.config.max_recoveries_per_run {
            return Err(WuspError::RecoveryExhausted {
                operation,
                last: Box::new(cause),
            });
        }
        self.stats.recoveries += 1;
        Ok(())
    }

    async fn authorization_cookie(&self) -> Result<AuthorizationCookie, WuspError> {
        let request = GetAuthorizationCookie {
            client_id: Presence::Value(self.computer_id()?.0.hyphenated().to_string()),
            target_group_name: match &self.config.target_group {
                Some(g) => Presence::Value(g.clone()),
                None => Presence::Absent,
            },
            dns_name: Presence::Value(self.config.dns_name.clone()),
        };
        let response = self
            .send_raw(&self.auth_url(), &request, Idempotence::Idempotent)
            .await?;
        response.result.into_value().ok_or_else(|| {
            ProtocolError::MissingElement("GetAuthorizationCookieResult".into()).into()
        })
    }

    /// `GetAuthorizationCookie` then `GetCookie`; persists the cookie.
    async fn obtain_cookie(&mut self, use_old: bool) -> Result<(), WuspError> {
        let last_change = self
            .last_change
            .clone()
            .ok_or(WuspError::Config("GetCookie requires a prior GetConfig"))?;
        let auth = self.authorization_cookie().await?;
        let old = if use_old {
            self.current_cookie().ok()
        } else {
            None
        };
        let request = GetCookie {
            auth_cookies: Presence::Value(vec![auth]),
            old_cookie: old.map_or(Presence::Absent, Presence::Value),
            last_change,
            current_time: unix_to_xs(self.clock.now_unix()),
            protocol_version: Presence::Value(self.config.protocol_version.clone()),
        };
        let response = self
            .send_raw(
                &self.url(Service::Client),
                &request,
                Idempotence::Idempotent,
            )
            .await?;
        let cookie = response
            .result
            .into_value()
            .ok_or_else(|| ProtocolError::MissingElement("GetCookieResult".into()))?;
        let generation = self.last_change.as_ref().map(|c| c.as_str().to_owned());
        let stored = to_stored(&cookie)?;
        self.store.update(|s| {
            s.cookie = Some(stored);
            s.config_generation = generation;
        })?;
        self.exact_cookie = Some(cookie);
        Ok(())
    }

    async fn handshake_once(&mut self, use_old: bool) -> Result<(), WuspError> {
        let response = self
            .send_raw(
                &self.url(Service::Client),
                &GetConfig {
                    protocol_version: Presence::Value(self.config.protocol_version.clone()),
                },
                Idempotence::Idempotent,
            )
            .await?;
        let server_config = response
            .result
            .into_value()
            .ok_or_else(|| ProtocolError::MissingElement("GetConfigResult".into()))?;
        let generation = server_config.last_change.as_str().to_owned();
        if self
            .store
            .state()
            .config_generation
            .as_ref()
            .is_some_and(|g| *g != generation)
        {
            self.stats.config_changes += 1;
        }
        // Configuration discovery: the authorization service URL.
        self.auth_url = server_config
            .auth_info
            .value()
            .and_then(|plugins| plugins.first())
            .and_then(|p| p.service_url.value())
            .filter(|u| !u.trim().is_empty())
            .map(|u| self.config.url(u.trim()));
        self.last_change = Some(server_config.last_change.clone());
        self.server_config = Some(server_config);
        self.obtain_cookie(use_old).await?;
        self.stats.handshakes += 1;
        if self.registration_needed() {
            self.register().await?;
        }
        Ok(())
    }

    fn registration_needed(&self) -> bool {
        self.server_config
            .as_ref()
            .is_some_and(|c| c.is_registration_required)
            && !matches!(
                self.store.state().registration,
                RegistrationState::Registered { .. }
            )
    }

    fn is_handshake_fault(error: &WuspError) -> bool {
        matches!(
            error.fault_code(),
            Some(
                ErrorCode::ConfigChanged
                    | ErrorCode::ServerChanged
                    | ErrorCode::InvalidCookie
                    | ErrorCode::InvalidAuthorizationCookie
            )
        )
    }

    /// Full `GetConfig` / authorization / `GetCookie` (/ registration)
    /// sequence. Configuration or cookie faults inside the sequence restart it
    /// at most twice.
    pub async fn handshake(&mut self, use_old_cookie: bool) -> Result<(), WuspError> {
        let mut tries = 0u32;
        loop {
            match self.handshake_once(use_old_cookie && tries == 0).await {
                Ok(()) => return Ok(()),
                Err(error) if tries < 2 && Self::is_handshake_fault(&error) => {
                    self.charge_recovery("handshake", error)?;
                    tries += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn renew_cookie(&mut self) -> Result<(), WuspError> {
        if self.last_change.is_none() || self.server_config.is_none() {
            return self.handshake(true).await;
        }
        match self.obtain_cookie(true).await {
            Ok(()) => {
                self.stats.cookie_renewals += 1;
                Ok(())
            }
            Err(error) if Self::is_handshake_fault(&error) => {
                self.charge_recovery("renew cookie", error)?;
                self.handshake(false).await
            }
            Err(error) => Err(error),
        }
    }

    async fn register(&mut self) -> Result<(), WuspError> {
        let mut info = self.config.computer_info.clone().ok_or(WuspError::Config(
            "registration required but no computer_info",
        ))?;
        if info.dns_name.is_absent() {
            info.dns_name = Presence::Value(self.config.dns_name.clone());
        }
        let now = self.clock.now_unix();
        self.store
            .update(|s| s.registration = RegistrationState::Pending { since_unix: now })?;
        let request = RegisterComputer {
            cookie: Presence::Value(self.current_cookie()?),
            computer_info: Presence::Value(info),
        };
        match self
            .send_raw(
                &self.url(Service::Client),
                &request,
                Idempotence::NonIdempotent,
            )
            .await
        {
            Ok(_) => self.stats.registrations += 1,
            Err(error)
                if matches!(error.fault_code(), Some(ErrorCode::RegistrationNotRequired)) => {}
            Err(error) => return Err(error),
        }
        let at = self.clock.now_unix();
        self.store
            .update(|s| s.registration = RegistrationState::Registered { at_unix: at })?;
        Ok(())
    }

    /// `RefreshCache`: re-resolves server-local revision ids of every cached
    /// revision after a server change. Revisions the server no longer knows are
    /// dropped from the cache so they are fetched again.
    pub async fn refresh_cache(&mut self) -> Result<(), WuspError> {
        let cached: Vec<UpdateRevision> = self
            .store
            .state()
            .cached_revisions
            .keys()
            .copied()
            .collect();
        self.stats.cache_refreshes += 1;
        let mut known = std::collections::BTreeMap::new();
        for chunk in cached.chunks(200) {
            let request = RefreshCache {
                cookie: Presence::Value(self.current_cookie()?),
                global_ids: Presence::Value(chunk.to_vec()),
            };
            let response = self
                .send_raw(
                    &self.url(Service::Client),
                    &request,
                    Idempotence::Idempotent,
                )
                .await?;
            for result in response.result.into_value().unwrap_or_default() {
                if let Some(global) = result.global_id.into_value() {
                    known.insert(global, result.revision_id);
                }
            }
        }
        self.store.update(|s| {
            s.cached_revisions.retain(|k, _| known.contains_key(k));
            for (k, v) in s.cached_revisions.iter_mut() {
                v.local_revision_id = known.get(k).copied();
            }
            s.sync_checkpoint = None;
        })?;
        Ok(())
    }

    /// Ensures a usable cookie (and registration where required), renewing
    /// ahead of expiry. Cheap when the cookie is still valid.
    pub async fn ensure_ready(&mut self) -> Result<(), WuspError> {
        let now = self.clock.now_unix();
        let skew = self.config.renewal_skew_secs;
        let valid = self
            .store
            .state()
            .cookie
            .as_ref()
            .is_some_and(|c| !c.is_expired(now, skew));
        if valid {
            if matches!(
                self.store.state().registration,
                RegistrationState::Pending { .. }
            ) {
                // An earlier registration was not confirmed; learn the
                // server's requirement again.
                return self.handshake(true).await;
            }
            if self.registration_needed() {
                self.register().await?;
            }
            return Ok(());
        }
        if self.store.state().cookie.is_some() {
            self.renew_cookie().await
        } else {
            self.handshake(false).await
        }
    }

    // ---- authenticated calls with bounded recovery -------------------------

    async fn apply_recovery(&mut self, recovery: Recovery) -> Result<(), WuspError> {
        match recovery {
            Recovery::RenewCookie => self.renew_cookie().await,
            Recovery::RenewConfigAndCookies => self.handshake(true).await,
            Recovery::RestartHandshakeWithRefreshCache => {
                self.store.update(|s| s.cookie = None)?;
                self.exact_cookie = None;
                self.handshake(false).await?;
                self.refresh_cache().await
            }
            Recovery::Register => self.register().await,
            _ => Ok(()),
        }
    }

    /// Sends an authenticated request, building it from the current cookie and
    /// state (rebuilt after every recovery, since server-local ids may have
    /// changed) and applying fault-specific recovery. Faults with no specified recovery
    /// (including `FileLocationChanged`, handled by callers) are returned.
    pub(crate) async fn call<R, F>(
        &mut self,
        service: Service,
        operation: &'static str,
        idempotence: Idempotence,
        build: F,
    ) -> Result<R::Response, WuspError>
    where
        R: SoapRequest,
        F: Fn(&Cookie, &ClientState) -> R,
    {
        let mut recoveries = 0u32;
        let mut waits = 0u32;
        loop {
            self.ensure_ready().await?;
            let request = build(&self.current_cookie()?, self.store.state());
            let error = match self
                .send_raw(&self.url(service), &request, idempotence)
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => error,
            };
            let WuspError::Fault(fault) = &error else {
                return Err(error);
            };
            match fault.code.wusp_recovery() {
                Recovery::RetryLater => {
                    // A busy server declined the request, so replay is safe
                    // even for non-idempotent operations; an internal error
                    // may have processed it.
                    let effective = if fault.code == ErrorCode::ServerBusy {
                        Idempotence::Idempotent
                    } else {
                        idempotence
                    };
                    let delay = self.config.retry.decide(
                        effective,
                        waits,
                        Failure::Status {
                            status: 503,
                            retry_after: None,
                        },
                    );
                    match delay {
                        Some(delay) => {
                            self.timer.sleep(delay).await;
                            waits += 1;
                        }
                        None => return Err(error),
                    }
                }
                recovery @ (Recovery::RenewCookie
                | Recovery::RenewConfigAndCookies
                | Recovery::RestartHandshakeWithRefreshCache
                | Recovery::Register) => {
                    recoveries += 1;
                    if recoveries > self.config.max_recoveries_per_call {
                        return Err(WuspError::RecoveryExhausted {
                            operation,
                            last: Box::new(error),
                        });
                    }
                    self.charge_recovery(operation, error)?;
                    self.apply_recovery(recovery).await?;
                }
                _ => return Err(error),
            }
        }
    }
}
