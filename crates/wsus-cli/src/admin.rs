//! `wsus admin ...`: local administration.
//!
//! Administrative authority is local file access to the server database (see
//! [`crate::secure`]); it is entirely separate from protocol authorization,
//! which clients obtain through the SOAP authorization flow. Nothing here is
//! reachable over the network.
//!
//! Administration may run while `wsus server run` is serving: both use the
//! same SQLite database (write-ahead log). Policy changes take effect for the
//! next request. A changed *configuration file* is only read at server start.

use crate::{
    config::{Config, parse_guid},
    logging::OpFields,
    output::{Output, hex, parse_update_ref},
    secure,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, time::Duration};
use uuid::Uuid;
use wsus_client::{
    download::{DownloadLimits, DownloadOptions, Downloader},
    session::{unix_to_xs, xs_to_unix},
    transport::reqwest_backend::TokioTimer,
    wsusss::{WsusssClient, WsusssConfig},
};
use wsus_protocol::{
    identity::{GroupId, UpdateId},
    soap::XsDateTime,
};
use wsus_server::{
    catalog::{
        Catalog, FragmentRecord, GenerationId, GenerationState, Snapshot, Source, SourceId,
        SourceKind,
    },
    content::{ContentDescriptor, ContentStore},
    policy::{ApprovalState, DeploymentAction, Group, Policy},
    reporting::Reporting,
    storage::Database,
    upstream::{CategoryFilter, ContentSelection, SyncOutcome, UpstreamConfig, UpstreamSync},
};

/// Opened local administration context.
pub struct Admin {
    pub config: Config,
    pub db: Database,
    pub catalog: Catalog,
    pub policy: Policy,
    pub reporting: Reporting,
    pub content: ContentStore,
}

impl Admin {
    /// Checks file ownership, then opens the stores.
    pub fn open(config: &Config) -> Result<Self> {
        secure::check_admin_access(&config.server.database)?;
        let db = crate::server_cmd::open_database(config)?;
        secure::ensure_private_dir(&config.server.content_dir)?;
        let content = ContentStore::open(db.clone(), &config.server.content_dir)
            .context("cannot open the content store")?;
        Ok(Self {
            config: config.clone(),
            catalog: Catalog::new(db.clone()),
            policy: Policy::new(db.clone()),
            reporting: Reporting::new(db.clone()),
            content,
            db,
        })
    }

    pub(crate) fn source(&self, name: Option<&str>) -> Result<Source> {
        let name = name.unwrap_or(&self.config.server.source_name);
        self.catalog.source_by_name(name)?.with_context(|| {
            format!("catalog source `{name}` does not exist (`wsus admin source add`)")
        })
    }

    fn snapshot(&self, source: &Source) -> Result<Option<Snapshot>> {
        Ok(self.catalog.snapshot(source.id)?)
    }
}

fn ts(unix: i64) -> String {
    unix_to_xs(unix).as_str().to_owned()
}

fn ts_opt(unix: Option<i64>) -> Value {
    unix.map_or(Value::Null, |u| json!(ts(u)))
}

/// Finds the newest revision of an update in a snapshot.
fn find_update(
    snapshot: &Snapshot,
    id: UpdateId,
    revision: Option<u32>,
) -> Result<Option<FragmentRecord>> {
    let mut best: Option<FragmentRecord> = None;
    let mut after = None;
    loop {
        let page = snapshot.list(after, 500, true)?;
        for rec in page.items {
            if rec.identity.id != id {
                continue;
            }
            if revision.is_some_and(|r| rec.identity.revision.0 != r) {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|b| rec.identity.revision > b.identity.revision)
            {
                best = Some(rec);
            }
        }
        match page.next {
            Some(n) => after = Some(n),
            None => return Ok(best),
        }
    }
}

// ---- sources ----

pub fn source_add(admin: &Admin, name: &str, kind: &str, description: &str) -> Result<Output> {
    let kind = match kind {
        "upstream" => SourceKind::Upstream,
        "local" => SourceKind::Local,
        "import" => SourceKind::Import,
        other => bail!("unknown source kind `{other}` (upstream, local, import)"),
    };
    let id = admin.catalog.add_source(name, kind, description)?;
    Ok(Output::ok(
        json!({"source": name, "id": id.0, "kind": kind.as_str()}),
    ))
}

pub fn source_list(admin: &Admin) -> Result<Output> {
    let mut out = Vec::new();
    for s in admin.catalog.sources()? {
        let active = admin.catalog.active_generation(s.id)?;
        let fragments = match active {
            Some(g) => Some(admin.catalog.snapshot_of(g)?.count()?),
            None => None,
        };
        out.push(json!({
            "name": s.name, "id": s.id.0, "kind": s.kind.as_str(),
            "description": s.description, "created": ts(s.created_at),
            "serving": s.name == admin.config.server.source_name,
            "active_generation": active.map(|g| g.0), "fragments": fragments,
        }));
    }
    Ok(Output::ok(json!({"sources": out})))
}

// ---- synchronization ----

fn generations(admin: &Admin, source: SourceId) -> Result<Vec<GenerationId>> {
    Ok(admin.db.with_conn(|c| {
        let mut st = c.prepare("SELECT id FROM generations WHERE source_id=?1 ORDER BY id")?;
        let ids = st
            .query_map([source.0], |r| r.get::<_, i64>(0).map(GenerationId))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    })?)
}

pub fn sync_status(admin: &Admin, source: Option<&str>) -> Result<Output> {
    let source = admin.source(source)?;
    let active = admin.catalog.active_generation(source.id)?;
    let mut list = Vec::new();
    let mut staging = 0;
    for id in generations(admin, source.id)? {
        let g = admin.catalog.generation(id)?;
        if g.state == GenerationState::Staging {
            staging += 1;
        }
        let checkpoint = g
            .anchor
            .as_deref()
            .and_then(wsus_server::upstream::Checkpoint::decode);
        list.push(json!({
            "generation": g.id.0, "state": g.state.as_str(),
            "started": ts(g.started_at), "finished": ts_opt(g.finished_at),
            "activated": ts_opt(g.activated_at),
            "full": checkpoint.as_ref().map(|c| c.full),
            "has_evidence": g.evidence.is_some(),
        }));
    }
    let committed = match active {
        Some(g) => admin
            .catalog
            .generation(g)?
            .anchor
            .as_deref()
            .and_then(wsus_server::upstream::Checkpoint::decode)
            .map(|c| {
                json!({
                    "endpoint": wsus_client::transport::scrub_urls(&c.endpoint),
                    "filter": c.filter,
                    "full": c.full,
                    "has_update_anchor": c.update_anchor.is_some(),
                })
            }),
        None => None,
    };
    Ok(Output::ok(json!({
        "source": source.name,
        "active_generation": active.map(|g| g.0),
        "interrupted_staging_generations": staging,
        "committed_checkpoint": committed,
        "generations": list,
    })))
}

/// How much content to acquire after a metadata synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    None,
    All,
    Approved,
}

fn guids(items: &[String], what: &str) -> Result<Vec<UpdateId>> {
    items
        .iter()
        .map(|g| parse_guid(what, g).map(UpdateId))
        .collect()
}

/// The `UpstreamSync` for the configured `[upstream]` section. Shared by
/// `sync start|resume` and tests so both use the identical checkpoint identity.
pub type LiveUpstreamSync = UpstreamSync<
    crate::sync_progress::ProgressTransport<
        wsus_client::transport::reqwest_backend::ReqwestTransport,
    >,
    TokioTimer,
>;

/// Construct the configured upstream synchronizer with live transfer progress.
pub fn upstream_sync(admin: &Admin, source_name: &str) -> Result<LiveUpstreamSync> {
    let up = admin
        .config
        .upstream
        .as_ref()
        .context("no [upstream] section in the configuration")?;
    let mut wc = WsusssConfig::new(&up.origin, &up.account_name, &up.account_guid);
    wc.content_base_url = Some(
        up.content_base_url
            .clone()
            .unwrap_or_else(|| up.origin.clone()),
    );
    wc.download_files_fallback = up.download_files_fallback;
    wc.allow_mu_url = up.allow_mu_url;
    wc.request_timeout = Duration::from_secs(up.request_timeout_secs);
    let transport = crate::net::build_transport(&admin.config.network, Duration::from_secs(30))?;
    let client = WsusssClient::new(
        wc,
        crate::sync_progress::ProgressTransport::new(transport, up.progress),
        TokioTimer,
    );
    let mut ucfg = UpstreamConfig::new(
        source_name,
        up.endpoint_key.as_deref().unwrap_or(&up.origin),
    );
    ucfg.filter = CategoryFilter {
        products: guids(&up.products, "upstream.products")?,
        classifications: guids(&up.classifications, "upstream.classifications")?,
    };
    ucfg.send_wire_filter = up.send_wire_filter;
    ucfg.keep_superseded = up.keep_superseded_generations;
    ucfg.download_concurrency = up.download_concurrency;
    ucfg.metadata_concurrency = up.metadata_concurrency;
    let sync = UpstreamSync::new(admin.catalog.clone(), client, ucfg)?;
    Ok(if up.progress {
        sync.with_progress(std::sync::Arc::new(|stats| {
            eprintln!(
                "sync metadata: {} listed, {} fetched and staged, {} excluded by filter",
                stats.listed, stats.fetched, stats.excluded_by_filter
            );
        }))
    } else {
        sync
    })
}

/// Fetch category metadata through the configured, live upstream handshake.
pub async fn sync_categories(admin: &Admin, source: Option<&str>) -> Result<Output> {
    let mut sync = upstream_sync(admin, source.unwrap_or(&admin.config.server.source_name))?;
    let found = sync.discover_categories().await?;
    Ok(Output::ok(json!({
        "categories": found.categories.iter().map(|c| json!({
            "identity": c.identity.to_string(), "type": c.category_type, "title": c.title,
        })).collect::<Vec<_>>(),
        "detectoids": found.detectoids,
    })))
}

/// `admin sync start|resume`: metadata synchronization from the configured
/// upstream, optionally followed by content acquisition.
pub async fn sync_run(
    admin: &Admin,
    source: Option<&str>,
    resume: bool,
    content: ContentMode,
) -> Result<(Output, OpFields)> {
    if admin.config.upstream.is_none() {
        bail!("no [upstream] section in the configuration");
    }
    let source_name = source
        .unwrap_or(&admin.config.server.source_name)
        .to_owned();
    // Fail what nothing can resume (staging generations of local and import
    // sources). Upstream staging generations are kept: `UpstreamSync` resumes
    // one whose pending checkpoint still matches.
    let recovered = admin.catalog.recover_after_restart()?;
    // A staging generation that already exists means an earlier run was
    // interrupted. `start` refuses to guess; `resume` continues it.
    let staging = match admin.catalog.source_by_name(&source_name)? {
        Some(s) => {
            let mut n = 0;
            for id in generations(admin, s.id)? {
                if admin.catalog.generation(id)?.state == GenerationState::Staging {
                    n += 1;
                }
            }
            n
        }
        None => 0,
    };
    if !resume && staging > 0 {
        bail!(
            "an interrupted synchronization exists; run `wsus admin sync resume` \
             (a resume that cannot reuse it fails it and keeps it as evidence)"
        );
    }
    if resume && staging == 0 {
        return Ok((
            Output::ok(json!({"outcome": "nothing_to_resume"})),
            OpFields::default(),
        ));
    }

    let mut sync = upstream_sync(admin, &source_name)?;
    let report = sync.run().await.map_err(anyhow::Error::from)?;
    let stats = &report.stats;
    let outcome = match &report.outcome {
        SyncOutcome::NoChange => json!({"result": "no_change"}),
        SyncOutcome::Activated {
            generation,
            fragments,
            ..
        } => json!({"result": "activated", "generation": generation.0, "fragments": fragments}),
    };
    let mut value = json!({
        "outcome": outcome,
        "recovered_failed_generations": recovered.iter().map(|g| g.0).collect::<Vec<_>>(),
        "stats": {
            "resumed": stats.resumed, "listed": stats.listed, "fetched": stats.fetched,
            "carried": stats.carried, "tombstoned": stats.tombstoned,
            "excluded_by_filter": stats.excluded_by_filter,
            "pulled_by_dependency": stats.pulled_by_dependency,
            "withdrawn": stats.withdrawn,
            "files_without_descriptor": stats.files_without_descriptor,
        },
    });
    let mut ok = true;
    let mut failed_files = 0u64;
    if content != ContentMode::None {
        let selection = match content {
            ContentMode::All => ContentSelection::All,
            _ => {
                let mut ids = BTreeSet::new();
                for g in admin.policy.groups()? {
                    for a in admin.policy.approvals_for_group(g.id)? {
                        if a.state == ApprovalState::Active {
                            ids.insert(a.update);
                        }
                    }
                }
                ContentSelection::Updates(ids)
            }
        };
        let root = admin
            .config
            .server
            .content_dir
            .parent()
            .map(|p| p.join("upstream-downloads"))
            .unwrap_or_else(|| PathBuf::from("upstream-downloads"));
        let downloader = Downloader::open(&root, DownloadLimits::default())?;
        let r = sync
            .acquire_content(
                &admin.content,
                &downloader,
                &selection,
                &DownloadOptions::default(),
            )
            .await
            .map_err(anyhow::Error::from)?;
        failed_files = r.failed.len() as u64;
        ok = r.failed.is_empty();
        value["content"] = json!({
            "acquired": r.acquired, "already_present": r.already_present,
            "catalog_only": r.catalog_only,
            "failed": r.failed.iter().map(|f| json!({
                "update": f.update.to_string(), "file": f.file_name,
                "reason": wsus_client::transport::scrub_urls(&f.reason)})).collect::<Vec<_>>(),
        });
    }
    let fields = OpFields {
        counts: vec![
            ("listed", stats.listed as u64),
            ("fetched", stats.fetched as u64),
            ("carried", stats.carried as u64),
            ("failed_files", failed_files),
        ],
        server_generation: match &report.outcome {
            SyncOutcome::Activated { generation, .. } => Some(generation.0.to_string()),
            SyncOutcome::NoChange => None,
        },
    };
    Ok((Output::with_ok(value, ok), fields))
}

// ---- updates ----

pub fn updates_list(
    admin: &Admin,
    source: Option<&str>,
    after: Option<i32>,
    limit: usize,
    include_inactive: bool,
) -> Result<Output> {
    let source = admin.source(source)?;
    let Some(snapshot) = admin.snapshot(&source)? else {
        return Ok(Output::ok(
            json!({"source": source.name, "updates": [], "next": null}),
        ));
    };
    let page = snapshot.list(after, limit, include_inactive)?;
    let mut items = Vec::new();
    for rec in &page.items {
        let approvals = admin
            .policy
            .approvals_for_update(rec.identity.id)?
            .iter()
            .filter(|a| a.state == ApprovalState::Active)
            .count();
        items.push(json!({
            "identity": rec.identity.to_string(), "local_id": rec.local.id,
            "kind": rec.kind, "state": rec.state.as_str(),
            "files": snapshot.files(rec.local)?.len(), "active_approvals": approvals,
        }));
    }
    Ok(Output::ok(json!({
        "source": source.name,
        "generation": snapshot.generation().0,
        "total": snapshot.count()?,
        "updates": items,
        "next": page.next,
    })))
}

pub fn updates_inspect(admin: &Admin, source: Option<&str>, update: &str) -> Result<Output> {
    let source = admin.source(source)?;
    let (id, rev) = parse_update_ref(update)?;
    let snapshot = admin
        .snapshot(&source)?
        .context("the source has no active generation")?;
    let rec = find_update(&snapshot, id, rev.map(|r| r.0))?
        .with_context(|| format!("update {update} is not in the active generation"))?;
    let mut files = Vec::new();
    for f in snapshot.files(rec.local)? {
        let desc = ContentDescriptor {
            file_name: f.file_name.clone(),
            size: f.size,
            digests: f.digests.clone(),
        };
        files.push(json!({
            "name": f.file_name, "size": f.size,
            "digests": f.digests.iter().map(|d| format!("{:?}:{}", d.algorithm, hex(&d.bytes))).collect::<Vec<_>>(),
            "content_available": admin.content.find_available(&desc)?.is_some(),
        }));
    }
    let relationships: Vec<Value> = snapshot
        .relationships(rec.local)?
        .iter()
        .map(|r| {
            json!({
                "kind": r.kind.as_str(), "target": r.target.to_string(),
                "revision": r.revision.map(|v| v.0),
            })
        })
        .collect();
    let mut approvals = Vec::new();
    for a in admin.policy.approvals_for_update(rec.identity.id)? {
        let group = admin.policy.group(a.group)?.map(|g| g.name);
        approvals.push(json!({
            "id": a.id.0.to_string(), "group": group, "group_id": a.group.0.to_string(),
            "action": a.action.as_str(), "state": a.state.as_str(),
            "deadline": ts_opt(a.deadline),
        }));
    }
    let status: serde_json::Map<String, Value> = admin
        .reporting
        .status_counts(rec.identity.id)?
        .into_iter()
        .map(|(k, v)| (k.as_str().to_owned(), json!(v)))
        .collect();
    Ok(Output::ok(json!({
        "identity": rec.identity.to_string(), "kind": rec.kind, "state": rec.state.as_str(),
        "local_id": rec.local.id, "core_sha256": rec.core_sha256,
        "has_extended": rec.extended_xml.is_some(),
        "declined": admin.policy.is_declined(rec.identity.id)?,
        "relationships": relationships, "files": files,
        "approvals": approvals, "client_status": Value::Object(status),
    })))
}

// ---- groups and approvals ----

pub fn groups_create(admin: &Admin, name: &str, description: &str) -> Result<Output> {
    let id = admin.policy.create_group(name, description)?;
    Ok(Output::ok(json!({"group": name, "id": id.0.to_string()})))
}

pub fn groups_list(admin: &Admin) -> Result<Output> {
    let mut out = Vec::new();
    for g in admin.policy.groups()? {
        let active = admin
            .policy
            .approvals_for_group(g.id)?
            .iter()
            .filter(|a| a.state == ApprovalState::Active)
            .count();
        let members = if g.id == wsus_server::policy::ALL_COMPUTERS {
            None
        } else {
            Some(admin.policy.members(g.id)?.len())
        };
        out.push(json!({
            "name": g.name, "id": g.id.0.to_string(), "builtin": g.builtin,
            "description": g.description, "members": members, "active_approvals": active,
        }));
    }
    Ok(Output::ok(json!({"groups": out})))
}

fn resolve_group(admin: &Admin, text: &str) -> Result<Group> {
    let found = match Uuid::parse_str(text) {
        Ok(u) => admin.policy.group(GroupId(u))?,
        Err(_) => admin.policy.group_by_name(text)?,
    };
    found.with_context(|| format!("group `{text}` does not exist"))
}

fn parse_action(text: &str) -> Result<DeploymentAction> {
    match text {
        "install" => Ok(DeploymentAction::Install),
        "uninstall" => Ok(DeploymentAction::Uninstall),
        other => bail!("unknown action `{other}` (install, uninstall)"),
    }
}

/// Unix seconds or `xs:dateTime`.
fn parse_deadline(text: &str) -> Result<i64> {
    if let Ok(n) = text.parse::<i64>() {
        return Ok(n);
    }
    XsDateTime::new(text)
        .and_then(|x| xs_to_unix(&x))
        .with_context(|| format!("`{text}` is neither unix seconds nor an xs:dateTime"))
}

pub fn approval_set(
    admin: &Admin,
    source: Option<&str>,
    update: &str,
    group: &str,
    action: &str,
    deadline: Option<&str>,
) -> Result<Output> {
    let (id, _) = parse_update_ref(update)?;
    let source = admin.source(source)?;
    let snapshot = admin
        .snapshot(&source)?
        .context("the source has no active generation")?;
    let rec = find_update(&snapshot, id, None)?
        .with_context(|| format!("update {id} is not in the active generation"))?;
    let group = resolve_group(admin, group)?;
    let deadline = deadline.map(parse_deadline).transpose()?;
    let a = admin
        .policy
        .approve(rec.identity.id, group.id, parse_action(action)?, deadline)?;
    Ok(Output::ok(json!({
        "approval": a.id.0.to_string(), "update": a.update.to_string(), "group": group.name,
        "action": a.action.as_str(), "deadline": ts_opt(a.deadline), "state": a.state.as_str(),
    })))
}

pub fn approval_remove(
    admin: &Admin,
    update: &str,
    group: &str,
    action: Option<&str>,
) -> Result<Output> {
    let (id, _) = parse_update_ref(update)?;
    let group = resolve_group(admin, group)?;
    let action = action.map(parse_action).transpose()?;
    let mut withdrawn = Vec::new();
    for a in admin.policy.approvals_for_update(id)? {
        if a.group == group.id
            && a.state == ApprovalState::Active
            && action.is_none_or(|x| x == a.action)
        {
            admin.policy.withdraw(a.id)?;
            withdrawn.push(a.id.0.to_string());
        }
    }
    if withdrawn.is_empty() {
        bail!("no active approval of {id} for group `{}`", group.name);
    }
    Ok(Output::ok(
        json!({"withdrawn": withdrawn, "group": group.name}),
    ))
}

// ---- content ----

/// Reconciles content with the database (completing or quarantining interrupted
/// promotions, optionally re-hashing everything) and reports coverage of the
/// active catalog. Reconciliation repairs as it verifies.
pub fn content_verify(admin: &Admin, source: Option<&str>, deep: bool) -> Result<Output> {
    let r = admin.content.reconcile(deep)?;
    let ids =
        |v: &[wsus_server::content::ObjectId]| v.iter().map(|o| o.to_string()).collect::<Vec<_>>();
    let mut declared = 0u64;
    let mut available = 0u64;
    let mut missing = Vec::new();
    if let Ok(source) = admin.source(source)
        && let Some(snapshot) = admin.snapshot(&source)?
    {
        let mut after = None;
        loop {
            let page = snapshot.list(after, 500, false)?;
            for rec in &page.items {
                for f in snapshot.files(rec.local)? {
                    declared += 1;
                    let desc = ContentDescriptor {
                        file_name: f.file_name.clone(),
                        size: f.size,
                        digests: f.digests.clone(),
                    };
                    if admin.content.find_available(&desc)?.is_some() {
                        available += 1;
                    } else if missing.len() < 50 {
                        missing
                            .push(json!({"update": rec.identity.to_string(), "file": f.file_name}));
                    }
                }
            }
            match page.next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
    }
    let damaged = !r.corrupt_objects.is_empty() || !r.missing_objects.is_empty();
    Ok(Output::with_ok(
        json!({
            "deep": deep,
            "completed_promotions": ids(&r.completed_promotions),
            "quarantined_objects": ids(&r.quarantined_objects),
            "missing_objects": ids(&r.missing_objects),
            "corrupt_objects": ids(&r.corrupt_objects),
            "restored_objects": ids(&r.restored_objects),
            "discarded_partials": r.discarded_partials,
            "catalog_files_declared": declared,
            "catalog_files_available": available,
            "catalog_files_unavailable": declared - available,
            "unavailable_sample": missing,
        }),
        !damaged,
    ))
}
