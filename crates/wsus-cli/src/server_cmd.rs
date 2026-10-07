//! `wsus server run`: the MS-WUSP server bound to HTTP with axum.
//!
//! Only protocol routes are mounted. There is no administrative route; see
//! [`crate::secure`].

use crate::{
    config::{Config, DeliveryScopeSetting, SyncDeliverySetting},
    logging::OpFields,
    secure,
};
use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use uuid::Uuid;
use wsus_server::{
    catalog::Catalog,
    computers::Computers,
    content::{ContentStore, ReconcileReport},
    endpoints::{ServerConfig, Services, WsusServer, http},
    policy::Policy,
    reporting::Reporting,
    session::{Clock, SessionConfig, SessionManager},
    storage::Database,
};

/// Server limits from the file, over the library defaults.
pub fn server_config(config: &Config) -> ServerConfig {
    let s = &config.server;
    let base = match s.sync_delivery {
        SyncDeliverySetting::Staged => ServerConfig::default(),
        SyncDeliverySetting::Closure => ServerConfig::closure(),
    };
    let mut c = ServerConfig {
        source_name: s.source_name.clone(),
        content_base_url: s.advertised_content_url.clone(),
        allowed_event_ids: s.allowed_event_ids.clone(),
        protocol_version: s.protocol_version.clone(),
        delivery_scope: match s.delivery_scope {
            DeliveryScopeSetting::Approved => wsus_server::endpoints::DeliveryScope::Approved,
            DeliveryScopeSetting::AllNonDeclined => {
                wsus_server::endpoints::DeliveryScope::AllNonDeclined
            }
        },
        ..base
    };
    if let Some(v) = s.max_installed_non_leaf_ids {
        c.max_installed_non_leaf_ids = v;
    }
    if let Some(v) = s.out_of_scope_unsatisfied {
        c.out_of_scope_unsatisfied = v;
    }
    if let Some(v) = s.max_request_bytes {
        c.max_request_bytes = v;
    }
    if let Some(v) = s.max_array_len {
        c.max_array_len = v;
    }
    if let Some(v) = s.max_sync_new_updates {
        c.max_sync_new_updates = v;
    }
    if let Some(v) = s.max_extended_updates_per_request {
        c.max_extended_updates_per_request = v;
    }
    if let Some(v) = s.max_file_digests_per_request {
        c.max_file_digests_per_request = v;
    }
    if let Some(v) = s.max_events_per_batch {
        c.max_events_per_batch = v;
    }
    if let Some(v) = s.xpress_responses {
        c.xpress_responses = v;
    }
    c
}

fn session_config(config: &Config) -> SessionConfig {
    let mut c = SessionConfig::default();
    if let Some(v) = config.server.cookie_ttl_secs {
        c.cookie_ttl = v;
    }
    if let Some(v) = config.server.auth_cookie_ttl_secs {
        c.auth_cookie_ttl = v;
    }
    c
}

/// Opens the database with private permissions.
pub fn open_database(config: &Config) -> Result<Database> {
    let path = &config.server.database;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        secure::ensure_private_dir(dir)?;
    }
    let db =
        Database::open(path).with_context(|| format!("cannot open database {}", path.display()))?;
    secure::restrict_file(path)?;
    Ok(db)
}

/// Everything a running server consists of.
pub struct Opened {
    pub server: WsusServer,
    pub services: Services,
    pub config: ServerConfig,
    /// Result of the startup reconciliation of content with the database.
    pub reconcile: ReconcileReport,
    /// Ids of staging generations failed at startup (local and import sources).
    pub recovered_generations: Vec<i64>,
}

/// Opens storage, signing keys and content, then reconciles content after a
/// possible crash. An optional clock replaces the system clock (tests).
pub fn open(config: &Config, clock: Option<Clock>) -> Result<Opened> {
    let db = open_database(config)?;
    secure::ensure_private_dir(&config.server.content_dir)?;
    let server_config = server_config(config);
    let fingerprint = server_config.fingerprint();
    let sessions = match clock {
        Some(clock) => {
            SessionManager::open_with_clock(db.clone(), session_config(config), &fingerprint, clock)
        }
        None => SessionManager::open(db.clone(), session_config(config), &fingerprint),
    }
    .context("cannot open the session manager")?;
    let content = ContentStore::open(db.clone(), &config.server.content_dir)
        .context("cannot open the content store")?;
    // Startup recovery: complete or quarantine interrupted promotions and drop
    // stale partial uploads before any request is served.
    let reconcile = content
        .reconcile(false)
        .context("content reconciliation failed")?;
    // Staging generations nothing can resume are failed (evidence is kept).
    // Upstream ones are left alone: `wsus admin sync resume` continues one whose
    // pending checkpoint still matches. `abandon_interrupted` would fail them.
    let recovered_generations = Catalog::new(db.clone())
        .recover_after_restart()
        .context("catalog recovery failed")?
        .into_iter()
        .map(|g| g.0)
        .collect();
    let services = Services {
        catalog: Catalog::new(db.clone()),
        policy: Policy::new(db.clone()),
        computers: Computers::new(db.clone()),
        reporting: Reporting::new(db),
        content,
        sessions: Arc::new(sessions),
    };
    let server = WsusServer::new(services.clone(), server_config.clone());
    Ok(Opened {
        server,
        services,
        config: server_config,
        reconcile,
        recovered_generations,
    })
}

/// Route class for logs: never the full content path.
fn classify(path: &str) -> &'static str {
    let p = path.to_ascii_lowercase();
    if p.starts_with("/content/") {
        "content"
    } else if p.contains("/clientwebservice/") {
        "client"
    } else if p.contains("/simpleauthwebservice/") {
        "auth"
    } else if p.contains("/reportingwebservice/") {
        "reporting"
    } else {
        "other"
    }
}

pub fn fault_code_in(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let Some(at) = text.find("ErrorCode>") else {
        return String::new();
    };
    let rest = &text[at + "ErrorCode>".len()..];
    rest.split('<')
        .next()
        .unwrap_or("")
        .chars()
        .take(64)
        .collect()
}

/// Like [`fault_code_in`] for a response body that may carry
/// `Content-Encoding: xpress` (the server compresses faults for clients that
/// accept it, so the plain-text search would find nothing). A body that does
/// not decode yields an empty code.
pub fn fault_code_in_encoded(body: &[u8], content_encoding: Option<&str>) -> String {
    let is_xpress = content_encoding.is_some_and(|v| v.trim().eq_ignore_ascii_case("xpress"));
    if !is_xpress {
        return fault_code_in(body);
    }
    match wsus_protocol::xpress::decode(
        body,
        &wsus_protocol::xpress::Limits::with_max_total(1 << 20),
    ) {
        Ok(plain) => fault_code_in(&plain),
        Err(_) => String::new(),
    }
}

async fn access_log(req: Request, next: Next) -> Response {
    let started = Instant::now();
    let correlation_id = Uuid::new_v4();
    let method = req.method().as_str().to_owned();
    let route = classify(req.uri().path());
    let soap_action = req
        .headers()
        .get("soapaction")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.trim_matches('"')
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .unwrap_or_default();
    let mut response = next.run(req).await;
    let status = response.status().as_u16();
    let mut fault_code = String::new();
    if status == 500 && route != "content" {
        // Faults are small; peek at the code and put the body back.
        let (parts, body) = response.into_parts();
        let encoding = parts
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match axum::body::to_bytes(body, 1024 * 1024).await {
            Ok(bytes) => {
                fault_code = fault_code_in_encoded(&bytes, encoding.as_deref());
                response = Response::from_parts(parts, Body::from(bytes));
            }
            Err(_) => response = Response::from_parts(parts, Body::empty()),
        }
    }
    tracing::info!(
        operation = "http_request",
        correlation_id = %correlation_id,
        method = %method,
        route,
        soap_action = %soap_action,
        status,
        fault_code = %fault_code,
        duration_ms = started.elapsed().as_millis() as u64,
        "request served"
    );
    response
}

/// Protocol router with access logging.
pub fn router(server: WsusServer) -> Router {
    http::router(server).layer(middleware::from_fn(access_log))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!(operation = "server_shutdown", "shutdown requested");
}

/// Runs until interrupted. Returns the fields of the summary event.
pub async fn run(config: &Config) -> Result<OpFields> {
    let listen: SocketAddr = config.server.listen.parse().context("server.listen")?;
    if !listen.ip().is_loopback() {
        tracing::warn!(
            listen = %listen,
            "listening beyond loopback over plain HTTP; terminate TLS in front of this service"
        );
    }
    let opened = open(config, None)?;
    let r = &opened.reconcile;
    tracing::info!(
        operation = "startup_recovery",
        completed_promotions = r.completed_promotions.len(),
        quarantined_objects = r.quarantined_objects.len(),
        missing_objects = r.missing_objects.len(),
        discarded_partials = r.discarded_partials,
        failed_staging_generations = opened.recovered_generations.len(),
        "content reconciled"
    );
    if opened
        .services
        .catalog
        .source_by_name(&opened.config.source_name)?
        .is_none()
    {
        tracing::warn!(
            source = %opened.config.source_name,
            "catalog source does not exist; clients see an empty catalog until `wsus admin source add` and a synchronization"
        );
    }
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("cannot bind {listen}"))?;
    tracing::info!(listen = %listener.local_addr()?, "serving MS-WUSP over HTTP");
    axum::serve(listener, router(opened.server))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server failed")?;
    Ok(OpFields {
        counts: vec![("quarantined_at_start", r.quarantined_objects.len() as u64)],
        server_generation: None,
    })
}
