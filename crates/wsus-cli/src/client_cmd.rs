//! `wsus client ...`: the MS-WUSP client commands.
//!
//! The functions are generic over the transport, timer and clock so tests can
//! run them against an in-process server. State layout under
//! `client.state_dir`: `state.json`, `meta/revisions/`, `events/`, `content/`.

use crate::{
    config::{Config, parse_guid},
    logging::OpFields,
    output::{Output, hex, parse_update_ref, parse_update_revision},
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;
use wsus_client::{
    download::{DownloadLimits, DownloadOptions, Downloader},
    install::job::JobStore,
    reporting::{
        AppendOutcome, EventQueue, QueueConfig,
        install_events::{InstallReportOptions, catalog_title, events_for_job, reported_update},
    },
    session::{Clock, SessionConfig, WuspSession, unix_to_xs},
    state::{RegistrationState, StateStore},
    sync::{
        Catalog, ClosureOptions, FileStatus, ReportEvent, RevisionStore, SyncEngine, SyncOptions,
    },
    transport::{RetryPolicy, RetryTimer, Transport},
};
use wsus_protocol::{
    identity::UpdateRevision,
    soap::{Presence, XsDateTime},
    wusp::{ComputerInfo, XmlUpdateFragmentType},
};

/// Locations derived from `client.state_dir`.
#[derive(Debug, Clone)]
pub struct ClientPaths {
    pub state_file: PathBuf,
    pub meta_dir: PathBuf,
    pub content_dir: PathBuf,
    pub events_dir: PathBuf,
}

pub fn paths(config: &Config) -> ClientPaths {
    let dir = &config.client.state_dir;
    ClientPaths {
        state_file: dir.join("state.json"),
        meta_dir: dir.join("meta"),
        content_dir: dir.join("content"),
        events_dir: dir.join("events"),
    }
}

fn computer_info(config: &Config) -> ComputerInfo {
    let c = &config.client.computer;
    ComputerInfo {
        dns_name: Presence::Value(config.client.dns_name.clone()),
        os_major_version: c.os_major,
        os_minor_version: c.os_minor,
        os_build_number: c.os_build,
        os_service_pack_major_number: 0,
        os_service_pack_minor_number: 0,
        os_locale: Presence::Value(c.locale.clone()),
        computer_manufacturer: Presence::Absent,
        computer_model: Presence::Absent,
        bios_version: Presence::Absent,
        bios_name: Presence::Absent,
        bios_release_date: unix_to_xs(0),
        processor_architecture: Presence::Value(c.processor_architecture.clone()),
        suite_mask: 0,
        old_product_type: 1,
        new_product_type: 48,
        system_metrics: 0,
        client_version_major_number: 10,
        client_version_minor_number: 0,
        client_version_build_number: i16::try_from(c.os_build).unwrap_or(0),
        client_version_qfe_number: 0,
        os_description: Presence::Absent,
        oem: Presence::Absent,
        device_type: Presence::Absent,
        firmware_version: Presence::Absent,
        mobile_operator: Presence::Absent,
    }
}

/// Session configuration derived from the file.
pub fn session_config(config: &Config) -> Result<SessionConfig> {
    let origin = config.client_origin()?;
    let mut s = SessionConfig::new(origin, &config.client.dns_name);
    if let Some(p) = &config.client.client_path {
        s.client_path = p.clone();
    }
    if let Some(p) = &config.client.auth_path {
        s.auth_path = p.clone();
    }
    if let Some(p) = &config.client.reporting_path {
        s.reporting_path = p.clone();
    }
    s.target_group = config.client.target_group.clone();
    s.computer_info = Some(computer_info(config));
    s.request_timeout = Duration::from_secs(config.client.request_timeout_secs);
    s.max_response_bytes = config.client.max_response_bytes;
    // A SOAP document can be as large as the response that carries it (a real Windows 11
    // SyncUpdates page decoded to about 51 MB), so the XML cap follows the response cap.
    s.limits.max_body_bytes = s
        .limits
        .max_body_bytes
        .max(config.client.max_response_bytes);
    s.accept_xpress = config.client.accept_xpress;
    s.retry = RetryPolicy {
        max_retries: config.client.max_retries,
        ..RetryPolicy::default()
    };
    Ok(s)
}

/// Opens the durable stores and builds an engine.
pub fn open_engine<T: Transport, S: RetryTimer, C: Clock>(
    config: &Config,
    transport: T,
    timer: S,
    clock: C,
) -> Result<SyncEngine<T, S, C>> {
    let p = paths(config);
    let store = StateStore::open(&p.state_file).context("cannot open client state")?;
    let session = WuspSession::new(transport, timer, clock, session_config(config)?, store)
        .context("cannot open the client session")?;
    let revisions = RevisionStore::open(&p.meta_dir).context("cannot open the revision store")?;
    Ok(SyncEngine::new(session, revisions))
}

fn registration(state: &RegistrationState) -> Value {
    match state {
        RegistrationState::Unregistered => json!({"state": "unregistered"}),
        RegistrationState::Pending { since_unix } => {
            json!({"state": "pending", "since_unix": since_unix})
        }
        RegistrationState::Registered { at_unix } => {
            json!({"state": "registered", "at_unix": at_unix})
        }
    }
}

/// State summary. Cookie material is never shown, only its expiry.
pub fn state_summary<T: Transport, S: RetryTimer, C: Clock>(engine: &SyncEngine<T, S, C>) -> Value {
    let s = engine.session().state();
    json!({
        "computer_id": s.computer_id.map(|c| c.0.to_string()),
        "source_server": s.source_server.map(|c| c.0.to_string()),
        "registration": registration(&s.registration),
        "config_generation": s.config_generation,
        "cookie": s.cookie.as_ref().map(|c| json!({"present": true, "expires_unix": c.expires_unix})),
        "sync_checkpoint": s.sync_checkpoint.as_ref().map(|c| json!({
            "anchor": c.anchor, "committed_unix": c.committed_unix})),
        "cached_revisions": s.cached_revisions.len(),
        "write_counter": s.write_counter,
    })
}

fn visible_revisions<T: Transport, S: RetryTimer, C: Clock>(
    engine: &SyncEngine<T, S, C>,
    catalog: &Catalog,
) -> Vec<UpdateRevision> {
    let cached = &engine.session().state().cached_revisions;
    catalog
        .revisions()
        .filter(|r| cached.contains_key(r))
        .copied()
        .collect()
}

/// `wsus client configure`.
pub struct ConfigureArgs {
    pub origin: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub dns_name: Option<String>,
    pub target_group: Option<String>,
}

/// Applies the arguments to `config`, validates and returns the new profile.
pub fn configure(config: &mut Config, args: ConfigureArgs) -> Result<()> {
    if let Some(o) = args.origin {
        config.client.origin = Some(o);
    }
    if let Some(d) = args.state_dir {
        config.client.state_dir = d;
    }
    if let Some(n) = args.dns_name {
        config.client.dns_name = n;
    }
    if let Some(g) = args.target_group {
        config.client.target_group = Some(g);
    }
    config.validate()?;
    Ok(())
}

/// Result of `configure` after the identity was created.
pub fn configured_summary(config: &Config, computer_id: Option<String>) -> Value {
    json!({
        "origin": config.client.origin.as_deref().map(wsus_client::transport::redact_url),
        "state_dir": config.client.state_dir.display().to_string(),
        "dns_name": config.client.dns_name,
        "target_group": config.client.target_group,
        "computer_id": computer_id,
    })
}

/// `wsus client sync`: `SyncUpdates` then `Extended` fragments for every
/// software revision whose file list is still unknown.
pub async fn sync<T: Transport, S: RetryTimer, C: Clock>(
    engine: &mut SyncEngine<T, S, C>,
    config: &Config,
) -> Result<(Output, OpFields)> {
    let filter = config
        .client
        .filter_categories
        .iter()
        .map(|g| parse_guid("client.filter_categories", g))
        .collect::<Result<Vec<_>>>()?;
    let report = engine
        .sync_updates(&SyncOptions {
            filter_categories: filter,
            max_pages: config.client.max_sync_pages,
        })
        .await?;
    let catalog = engine.catalog()?;
    let visible = visible_revisions(engine, &catalog);
    let closure = catalog.acquisition_closure(&visible, &ClosureOptions::default());
    let need: Vec<UpdateRevision> = closure
        .needs_extended
        .into_iter()
        .filter(|r| visible.contains(r))
        .collect();
    let mut fragments = 0usize;
    if !need.is_empty() {
        let f = engine
            .fetch_fragments(&need, XmlUpdateFragmentType::Extended, &[])
            .await?;
        fragments = f.stored;
    }
    // Queued install and uninstall outcome events and the client status event are delivered after
    // the sync, best effort.
    let events = if config.install.report_events
        || config.install.report_uninstall_events
        || config.install.report_inventory
    {
        let mut queue = EventQueue::open(&paths(config).events_dir, QueueConfig::default())
            .context("cannot open the event queue")?;
        // The client status event of this scan: the evaluator's verdicts against the machine.
        let inventory = if config.install.report_inventory {
            let env = crate::install_cmd::SystemEnv::new(None);
            let fresh = engine.catalog()?;
            Some(
                match crate::install_cmd::queue_inventory(
                    &mut queue,
                    config,
                    &fresh,
                    &env,
                    &wsus_client::session::SystemClock,
                    None,
                    false,
                ) {
                    Ok(v) => v,
                    Err(e) => json!({"error": format!("{e:#}")}),
                },
            )
        } else {
            None
        };
        let mut v = if queue.is_empty() {
            None
        } else {
            Some(match engine.flush_events(&mut queue, 100).await {
                Ok(o) => json!({"delivered": o.delivered, "queue_pending": queue.len()}),
                Err(e) => json!({"error": e.to_string(), "queue_pending": queue.len()}),
            })
        };
        if let Some(i) = inventory {
            v.get_or_insert_with(|| json!({}))["inventory"] = i;
        }
        v
    } else {
        None
    };
    let fields = OpFields {
        counts: vec![
            ("pages", report.pages as u64),
            ("new", report.new_revisions as u64),
            ("changed", report.changed_revisions as u64),
            ("removed", report.removed_revisions as u64),
            ("extended_fragments", fragments as u64),
        ],
        server_generation: engine.session().state().config_generation.clone(),
    };
    let value = json!({
        "pages": report.pages,
        "new_revisions": report.new_revisions,
        "changed_revisions": report.changed_revisions,
        "removed_revisions": report.removed_revisions,
        "unresolved": report.unresolved,
        "unchanged": report.unchanged,
        "extended_fragments_stored": fragments,
        "visible_revisions": visible.len(),
        "session": {
            "handshakes": engine.session().stats().handshakes,
            "cookie_renewals": engine.session().stats().cookie_renewals,
            "recoveries": engine.session().stats().recoveries,
            "config_changes": engine.session().stats().config_changes,
        },
    });
    let mut value = value;
    if let Some(e) = events {
        value["events"] = e;
    }
    Ok((Output::ok(value), fields))
}

/// `wsus client inspect`.
pub fn inspect<T: Transport, S: RetryTimer, C: Clock>(
    engine: &SyncEngine<T, S, C>,
    revision: Option<&str>,
) -> Result<Output> {
    let catalog = engine.catalog()?;
    let visible = visible_revisions(engine, &catalog);
    let describe = |rev: &UpdateRevision| -> Value {
        let Some(entry) = catalog.get(rev) else {
            return json!({"identity": rev.to_string()});
        };
        json!({
            "identity": rev.to_string(),
            "type": entry.record.update_type,
            "leaf": entry.record.is_leaf,
            "deployment_action": entry.record.deployment.as_ref().map(|d| d.action.clone()),
            "extended_fetched": entry.extended.is_some(),
            "files": entry.files().iter().map(|f| json!({
                "name": f.file_name,
                "size": f.size,
                "digests": f.digests.iter().map(|d| format!("{:?}:{}", d.algorithm, hex(&d.bytes))).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    };
    let value = match revision {
        None => json!({
            "state": state_summary(engine),
            "updates": visible.iter().map(describe).collect::<Vec<_>>(),
        }),
        Some(text) => {
            let (id, rev) = parse_update_ref(text)?;
            let rev = match rev {
                Some(r) => UpdateRevision { id, revision: r },
                None => catalog
                    .latest_revision(id)
                    .with_context(|| format!("update {id} is not in the local catalog"))?,
            };
            if !visible.contains(&rev) {
                bail!("{rev} is not in the current scope of this client");
            }
            let rel = catalog.relationships(&rev);
            let mut v = describe(&rev);
            v["relationships"] = match rel {
                Some(r) => json!({
                    "prerequisites": r.prerequisites.iter().map(|p| json!({
                        "alternatives": p.clause.update_ids.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
                        "is_category": p.clause.is_category,
                        "resolved": p.resolved.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                    "bundles": r.bundles.iter().map(|b| b.revisions.iter().map(|x| x.to_string()).collect::<Vec<_>>()).collect::<Vec<_>>(),
                    "supersedes": r.superseded.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
                }),
                None => Value::Null,
            };
            v
        }
    };
    Ok(Output::ok(value))
}

/// The verified content store of the client.
pub fn open_downloader(config: &Config) -> Result<Downloader> {
    let limits = DownloadLimits {
        max_concurrent: config.client.max_concurrent_downloads,
        max_file_size: config.client.max_file_size_bytes,
        ..DownloadLimits::default()
    };
    Ok(Downloader::open(&paths(config).content_dir, limits)?)
}

/// Download options derived from the configuration.
pub fn download_options(config: &Config) -> DownloadOptions {
    DownloadOptions {
        request_timeout: Duration::from_secs(config.client.request_timeout_secs.max(60) * 10),
        retry: RetryPolicy {
            max_retries: config.client.max_retries,
            ..RetryPolicy::default()
        },
        ..DownloadOptions::default()
    }
}

/// What `wsus client download` should fetch.
pub enum Selection {
    All,
    Updates(Vec<String>),
}

/// `wsus client download`: acquisition closure, verified and resumable.
pub async fn download<T: Transport, S: RetryTimer, C: Clock>(
    engine: &mut SyncEngine<T, S, C>,
    config: &Config,
    selection: &Selection,
    include_prerequisites: bool,
) -> Result<(Output, OpFields)> {
    let catalog = engine.catalog()?;
    let visible = visible_revisions(engine, &catalog);
    let chosen: Vec<UpdateRevision> = match selection {
        Selection::All => visible.clone(),
        Selection::Updates(items) => {
            let mut out = Vec::new();
            for text in items {
                let (id, rev) = parse_update_ref(text)?;
                let rev = match rev {
                    Some(r) => UpdateRevision { id, revision: r },
                    None => catalog
                        .latest_revision(id)
                        .with_context(|| format!("update {id} is not in the local catalog"))?,
                };
                if !visible.contains(&rev) {
                    bail!(
                        "{rev} is not in the current scope of this client; run `wsus client sync`"
                    );
                }
                out.push(rev);
            }
            out
        }
    };
    let opts = ClosureOptions {
        include_prerequisite_content: include_prerequisites,
    };
    let mut closure = catalog.acquisition_closure(&chosen, &opts);
    if !closure.needs_extended.is_empty() {
        let need: Vec<_> = closure
            .needs_extended
            .iter()
            .filter(|r| engine.local_id(r).is_some())
            .copied()
            .collect();
        engine
            .fetch_fragments(&need, XmlUpdateFragmentType::Extended, &[])
            .await?;
        closure = engine.catalog()?.acquisition_closure(&chosen, &opts);
    }
    let downloader = open_downloader(config)?;
    let options = download_options(config);
    let report = engine.acquire(&closure, &downloader, &options).await?;
    let mut complete = 0u64;
    let mut failed = 0u64;
    let files: Vec<Value> = report
        .files
        .iter()
        .map(|f| match &f.status {
            FileStatus::Complete(d) => {
                complete += 1;
                json!({
                    "file": f.file_name, "status": "complete",
                    "path": d.path.display().to_string(), "length": d.length,
                    "already_complete": d.already_complete,
                    "resumed_from": d.resumed_from, "restarted": d.restarted,
                })
            }
            FileStatus::Failed(reason) => {
                failed += 1;
                json!({"file": f.file_name, "status": "failed", "reason": reason})
            }
        })
        .collect();
    let fields = OpFields {
        counts: vec![("complete", complete), ("failed", failed)],
        server_generation: engine.session().state().config_generation.clone(),
    };
    let value = json!({
        "selected": chosen.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "members": closure.members.len(),
        "unusable_files": closure.unusable_files.len(),
        "missing_references": closure.missing.len(),
        "files": files,
        "all_complete": report.all_complete() && closure.unusable_files.is_empty(),
    });
    let ok = report.all_complete();
    Ok((Output::with_ok(value, ok), fields))
}

/// `wsus client report` arguments.
pub struct ReportArgs {
    pub update: Option<String>,
    pub namespace_id: i32,
    pub event_id: i16,
    pub source_id: i16,
    pub hresult: i32,
    pub sequence: i32,
    pub instance_id: Option<Uuid>,
    pub app_name: Option<String>,
    /// Queue the outcome events of this recorded job instead of one hand-made event.
    pub job: Option<String>,
    /// Queue the client status event `156` (the evaluator's `U` and `V` lists).
    pub inventory: bool,
    /// With `inventory`: queue it again even when unchanged.
    pub force: bool,
    /// With `inventory`: facts snapshot to evaluate against instead of the machine.
    pub facts_file: Option<PathBuf>,
    /// Do not enqueue; only flush what is queued.
    pub flush_only: bool,
    /// Enqueue without contacting the server.
    pub no_flush: bool,
    pub batch_size: usize,
}

/// The title of `update` for event strings: from the stored catalog, else fetched once as the
/// `LocalizedProperties` fragment (best effort: a failure leaves the title unknown and the events
/// then name the update by its identity).
pub async fn report_title<T: Transport, S: RetryTimer, C: Clock>(
    engine: &mut SyncEngine<T, S, C>,
    update: UpdateRevision,
) -> Option<String> {
    if let Some(title) = engine
        .catalog()
        .ok()
        .and_then(|c| catalog_title(&c, update))
    {
        return Some(title);
    }
    engine
        .fetch_fragments(
            &[update],
            XmlUpdateFragmentType::LocalizedProperties,
            &["en-US".to_owned(), "en".to_owned()],
        )
        .await
        .ok()?;
    engine
        .catalog()
        .ok()
        .and_then(|c| catalog_title(&c, update))
}

/// Enqueues (de-duplicated by instance id) and flushes client events.
pub async fn report<T: Transport, S: RetryTimer, C: Clock>(
    engine: &mut SyncEngine<T, S, C>,
    config: &Config,
    args: &ReportArgs,
) -> Result<(Output, OpFields)> {
    let mut queue = EventQueue::open(&paths(config).events_dir, QueueConfig::default())
        .context("cannot open the event queue")?;
    let mut enqueue = Value::Null;
    if let Some(job) = &args.job {
        let jobs = JobStore::open(config.client.state_dir.join("jobs")).context("job store")?;
        let record = jobs
            .read(job)
            .with_context(|| format!("cannot read job record `{job}`"))?;
        let target = parse_update_revision(&record.plan.target)?;
        let update = engine
            .catalog()
            .ok()
            .map_or(target, |c| reported_update(&c, target));
        let mut titles = std::collections::BTreeMap::new();
        if let Some(title) = report_title(engine, update).await {
            titles.insert(update.to_string(), title);
        }
        let events = events_for_job(
            &record,
            &titles,
            &InstallReportOptions {
                include_uninstall: true,
                update: Some(update),
                ..InstallReportOptions::default()
            },
        );
        let mut rows = Vec::new();
        for e in &events {
            let outcome = match e.enqueue(&mut queue)? {
                AppendOutcome::Queued { seq } => json!({"outcome": "queued", "seq": seq}),
                AppendOutcome::Duplicate { seq } => {
                    json!({"outcome": "duplicate_pending", "seq": seq})
                }
                AppendOutcome::AlreadyDelivered => json!({"outcome": "already_delivered"}),
            };
            rows.push(json!({
                "event_id": e.event_id,
                "event_instance_id": e.event_instance_id.to_string(),
                "win32_hresult": e.win32_hresult,
                "result": outcome,
            }));
        }
        enqueue = json!({
            "job": job,
            "job_status": record.status,
            "events": rows,
            "note": if events.is_empty() { "this job reports no event (only succeeded, restart-required and failed jobs do)" } else { "" },
        });
    } else if args.inventory {
        let catalog = engine.catalog()?;
        let env = crate::install_cmd::SystemEnv::new(args.facts_file.clone());
        enqueue = crate::install_cmd::queue_inventory(
            &mut queue,
            config,
            &catalog,
            &env,
            &wsus_client::session::SystemClock,
            None,
            args.force,
        )?;
    } else if !args.flush_only {
        let update = match &args.update {
            Some(u) => Some(parse_update_revision(u)?),
            None => None,
        };
        let event = ReportEvent {
            event_instance_id: args.instance_id.unwrap_or_else(Uuid::new_v4),
            sequence_number: args.sequence,
            time_at_target: unix_to_xs(engine.session().now_unix()).as_str().to_owned(),
            namespace_id: args.namespace_id,
            event_id: args.event_id,
            source_id: args.source_id,
            update,
            win32_hresult: args.hresult,
            app_name: args.app_name.clone(),
            detail: None,
        };
        if XsDateTime::new(&event.time_at_target).is_none() {
            bail!("internal error: invalid event time");
        }
        enqueue = match event.enqueue(&mut queue)? {
            AppendOutcome::Queued { seq } => json!({"outcome": "queued", "seq": seq}),
            AppendOutcome::Duplicate { seq } => json!({"outcome": "duplicate_pending", "seq": seq}),
            AppendOutcome::AlreadyDelivered => json!({"outcome": "already_delivered"}),
        };
        enqueue["event_instance_id"] = json!(event.event_instance_id.to_string());
    }
    let mut delivered = 0u64;
    let mut flushed = Value::Null;
    if !args.no_flush {
        let outcome = engine.flush_events(&mut queue, args.batch_size).await?;
        delivered = outcome.delivered as u64;
        flushed = json!({
            "batches": outcome.batches,
            "delivered": outcome.delivered,
            "dropped_invalid": outcome.dropped_invalid,
            "dropped_not_allowed": outcome.dropped_not_allowed,
        });
    }
    let fields = OpFields {
        counts: vec![("delivered", delivered), ("queued", queue.len() as u64)],
        server_generation: engine.session().state().config_generation.clone(),
    };
    Ok((
        Output::ok(json!({"enqueue": enqueue, "flush": flushed, "queue_pending": queue.len()})),
        fields,
    ))
}
