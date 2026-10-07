//! `wsus client facts-check | scan | plan | install | uninstall`.
//!
//! EVIDENCE STATUS: host-tested with fakes only. Nothing here has run against
//! a Windows machine; see `docs/wsus-install.md`.
//!
//! The commands are generic over an [`Env`] (fact provider, process runner,
//! signature verifier, elevation) so the same code is driven by fakes in
//! tests and by the real Windows services in the binary.
use crate::{
    client_cmd::{download_options, open_downloader, paths, report_title},
    config::Config,
    logging::OpFields,
    output::{Output, parse_update_ref},
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use wsus_client::{
    install::{
        PlanOptions, PlanOutcome, RecordingFacts, build_plan, build_uninstall_plan,
        check::{self, QueriesFile},
        executor::{
            ExecConfig, Executor, Sleeper, ThreadSleeper, display_command, prepare_command,
        },
        facts::load_facts_file,
        handler_log::{HandlerLog, NoWatcher, ProcessWatcher},
        job::{JobStatus, JobStore, NoReport, PostCheck, ReportHook},
        plan::{InstallPlan, NodeStatus, Planner},
        runner::{ProcessRunner, Runner},
        safety::PathPolicy,
        signature::{SignatureVerifier, TrustPolicy},
        store::{DownloaderStore, PayloadStore},
    },
    reporting::{
        EventQueue, QueueConfig,
        install_events::{
            InstallReportLog, InstallReportOptions, InstallReporter, catalog_title, reported_update,
        },
        inventory::{
            InventoryQueued, evaluate_inventory, queue_inventory as queue_inventory_event,
        },
    },
    session::{Clock, SystemClock, unix_to_xs},
    sync::{Catalog, ClosureOptions, FileStatus, RevisionStore, SyncEngine},
    transport::{RetryTimer, Transport},
};
use wsus_protocol::{applicability::FactProvider, identity::UpdateRevision, soap::Limits};

/// The machine-facing services of the installing client.
pub trait Env {
    /// A fresh provider (called again for the post-install check).
    fn facts(&self) -> Result<Box<dyn FactProvider>>;
    /// `windows` or `file:<sha256>`.
    fn facts_source(&self) -> Result<String>;
    fn runner(&self) -> &dyn Runner;
    fn verifier(&self) -> &dyn SignatureVerifier;
    /// True when installers may really be executed here.
    fn can_execute(&self) -> bool;
    fn is_elevated(&self) -> Result<bool>;
    fn system_dir(&self) -> Option<PathBuf>;
    /// Sleeping between post-check polls.
    fn sleeper(&self) -> &dyn Sleeper {
        &ThreadSleeper
    }
    /// Lists detached helper processes (never kills).
    fn watcher(&self) -> &dyn ProcessWatcher {
        &NoWatcher
    }
    /// Handler log hook (Defender on Windows).
    fn handler_log(&self) -> Option<HandlerLog> {
        None
    }
    /// The machine state the Defender launcher packages depend on (Windows only).
    fn stub_env(&self) -> Option<wsus_client::install::defender::StubEnv> {
        None
    }
    /// The servicing stack behind `Cbs` steps (`cbs-handler` feature, Windows, live facts only);
    /// `backend` is `install.servicing_backend`.
    fn servicing(
        &self,
        _backend: &str,
    ) -> Result<Option<std::sync::Arc<dyn wsus_client::install::servicing::ServicingBackend>>> {
        Ok(None)
    }
    /// The update stack behind `OSInstaller` steps in `update_agent` mode (`osinstaller-handler`
    /// feature, Windows, live facts only).
    fn os_installer(
        &self,
        _stack_dir: Option<&str>,
    ) -> Option<std::sync::Arc<dyn wsus_client::install::servicing::OsInstallerBackend>> {
        None
    }
    /// `CBS.log`, whose growth is recorded as evidence.
    fn cbs_log(&self) -> Option<PathBuf> {
        None
    }
}

/// The real environment: Windows services on Windows, a facts file elsewhere.
pub struct SystemEnv {
    pub facts_file: Option<PathBuf>,
    runner: ProcessRunner,
    #[cfg(windows)]
    verifier: wsus_client::install::signature_windows::WinVerifyTrustVerifier,
    #[cfg(not(windows))]
    verifier: wsus_client::install::signature::UnsupportedVerifier,
}

impl SystemEnv {
    pub fn new(facts_file: Option<PathBuf>) -> Self {
        Self {
            facts_file,
            runner: ProcessRunner,
            verifier: Default::default(),
        }
    }
}

impl Env for SystemEnv {
    fn facts(&self) -> Result<Box<dyn FactProvider>> {
        if let Some(p) = &self.facts_file {
            let (facts, _) = load_facts_file(p).map_err(anyhow::Error::msg)?;
            return Ok(Box::new(facts));
        }
        #[cfg(windows)]
        {
            Ok(Box::new(
                wsus_client::install::facts_windows::WindowsFacts::new(),
            ))
        }
        #[cfg(not(windows))]
        bail!("there is no live fact provider on this platform; pass --facts-file")
    }

    fn facts_source(&self) -> Result<String> {
        match &self.facts_file {
            Some(p) => {
                let (_, hash) = load_facts_file(p).map_err(anyhow::Error::msg)?;
                Ok(format!("file:{hash}"))
            }
            None => Ok("windows".into()),
        }
    }

    fn runner(&self) -> &dyn Runner {
        &self.runner
    }

    fn verifier(&self) -> &dyn SignatureVerifier {
        &self.verifier
    }

    fn can_execute(&self) -> bool {
        cfg!(windows) && self.facts_file.is_none()
    }

    fn is_elevated(&self) -> Result<bool> {
        #[cfg(windows)]
        {
            wsus_client::install::win_util::is_elevated().map_err(anyhow::Error::msg)
        }
        #[cfg(not(windows))]
        Ok(false)
    }

    fn system_dir(&self) -> Option<PathBuf> {
        #[cfg(windows)]
        {
            wsus_client::install::win_util::system_directory().ok()
        }
        #[cfg(not(windows))]
        None
    }

    #[cfg(windows)]
    fn watcher(&self) -> &dyn ProcessWatcher {
        &wsus_client::install::win_util::ToolhelpWatcher
    }

    fn stub_env(&self) -> Option<wsus_client::install::defender::StubEnv> {
        #[cfg(windows)]
        {
            self.facts_file
                .is_none()
                .then(wsus_client::install::facts_windows::probe_stub_env)
        }
        #[cfg(not(windows))]
        None
    }

    #[cfg(all(windows, feature = "cbs-handler"))]
    fn servicing(
        &self,
        backend: &str,
    ) -> Result<Option<std::sync::Arc<dyn wsus_client::install::servicing::ServicingBackend>>> {
        use wsus_client::install::servicing::{
            dism::DismBackend, dism_api::DismApiBackend, wusa::WusaBackend,
        };
        if self.facts_file.is_some() {
            return Ok(None);
        }
        let sys = self
            .system_dir()
            .context("the Windows system directory is not known")?;
        let runner: std::sync::Arc<dyn Runner + Send + Sync> = std::sync::Arc::new(ProcessRunner);
        Ok(Some(match backend {
            "dism" => std::sync::Arc::new(DismBackend::new(runner, sys)),
            "wusa" => std::sync::Arc::new(WusaBackend::new(runner, sys)),
            "dism_api" => std::sync::Arc::new(DismApiBackend::load(&sys)?),
            other => bail!("unknown install.servicing_backend `{other}` (dism, wusa or dism_api)"),
        }))
    }

    #[cfg(all(windows, feature = "osinstaller-handler"))]
    fn os_installer(
        &self,
        stack_dir: Option<&str>,
    ) -> Option<std::sync::Arc<dyn wsus_client::install::servicing::OsInstallerBackend>> {
        self.facts_file.is_none().then(|| {
            std::sync::Arc::new(
                wsus_client::install::servicing::update_agent::UpdateAgentBackend {
                    source: stack_dir.map_or(
                        wsus_client::install::servicing::update_agent::StackSource::System,
                        |d| {
                            wsus_client::install::servicing::update_agent::StackSource::Staged(
                                d.into(),
                            )
                        },
                    ),
                },
            ) as std::sync::Arc<dyn wsus_client::install::servicing::OsInstallerBackend>
        })
    }

    fn cbs_log(&self) -> Option<PathBuf> {
        (cfg!(windows) && self.facts_file.is_none()).then(|| {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
            PathBuf::from(root).join("Logs").join("CBS").join("CBS.log")
        })
    }

    fn handler_log(&self) -> Option<HandlerLog> {
        if cfg!(windows) && self.facts_file.is_none() {
            std::env::var_os("SystemRoot").map(|r| HandlerLog::defender(std::path::Path::new(&r)))
        } else {
            None
        }
    }
}

/// Loads the stored catalog read-only.
pub fn load_catalog(config: &Config) -> Result<Catalog> {
    let store = RevisionStore::open_read_only(paths(config).meta_dir)
        .context("no stored catalog; run `wsus client sync` first")?;
    // Stored fragments were accepted at sync time under the response cap, so they load under it.
    let limits = Limits {
        max_body_bytes: Limits::default()
            .max_body_bytes
            .max(config.client.max_response_bytes),
        ..Limits::default()
    };
    Ok(Catalog::load(&store, &limits)?)
}

/// `UUID[@REVISION]` to a stored revision (the highest when no revision).
pub fn resolve_target(catalog: &Catalog, text: &str) -> Result<UpdateRevision> {
    let (id, rev) = parse_update_ref(text)?;
    let rev = match rev {
        Some(r) => UpdateRevision { id, revision: r },
        None => catalog
            .latest_revision(id)
            .with_context(|| format!("update {id} is not in the local catalog"))?,
    };
    if catalog.get(&rev).is_none() {
        bail!("{rev} is not in the local catalog");
    }
    Ok(rev)
}

fn plan_options(config: &Config, allow_unknown: bool, plan_prerequisites: bool) -> PlanOptions {
    PlanOptions {
        allow_unknown,
        msi_handler_uris: config.install.msi_handler_uris.clone(),
        plan_prerequisites: plan_prerequisites || config.install.plan_prerequisites,
        delegate_cbs_installable: config.install.delegate_cbs_installable,
        ..PlanOptions::default()
    }
}

/// Evaluates the stored catalog against the machine facts and queues the client status event `156`
/// (the `U` and `V` lists) into `queue`, de-duplicated (`force` queues a fresh event even when the
/// lists did not change). `post_check` is the finished install job's own re-evaluation.
pub fn queue_inventory(
    queue: &mut EventQueue,
    config: &Config,
    catalog: &Catalog,
    env: &dyn Env,
    clock: &dyn Clock,
    post_check: Option<&PostCheck>,
    force: bool,
) -> Result<Value> {
    let facts = env.facts()?;
    let inv = evaluate_inventory(
        catalog,
        facts.as_ref(),
        &plan_options(config, false, false),
        post_check,
    );
    drop(facts);
    let at = unix_to_xs(clock.now_unix()).as_str().to_owned();
    let queued = queue_inventory_event(
        queue,
        &paths(config).events_dir,
        &inv,
        &at,
        "wsus-client",
        force,
    )
    .context("cannot queue the client status event")?;
    let (outcome, id) = match queued {
        InventoryQueued::Queued { instance_id } => ("queued", instance_id),
        InventoryQueued::Unchanged { instance_id } => ("unchanged", instance_id),
    };
    Ok(json!({
        "outcome": outcome,
        "event_id": 156,
        "event_instance_id": id.to_string(),
        "not_installed": inv.not_installed.len(),
        "installed": inv.installed.len(),
        "left_out": inv.left_out,
        "unknown": inv.unknown,
        "digest": inv.digest(),
    }))
}

/// `wsus client facts-check`.
pub fn facts_check(args: &crate::cli::FactsCheckArgs, env: &dyn Env) -> Result<Output> {
    let q_text = std::fs::read_to_string(&args.queries)
        .with_context(|| format!("cannot read {}", args.queries.display()))?;
    let queries: QueriesFile = check::parse_queries(&q_text).map_err(anyhow::Error::msg)?;
    let (reference, ref_hash) = load_facts_file(&args.expect).map_err(anyhow::Error::msg)?;
    let ours = env.facts()?;
    let report = check::facts_check(&queries, ours.as_ref(), &reference, args.max_details);
    let ok = report.agrees();
    Ok(Output::with_ok(
        json!({
            "provider": env.facts_source()?,
            "queries_generated": queries.generated,
            "reference_sha256": ref_hash,
            "reference_collected_at": reference.collected_at(),
            "total": report.total,
            "disagree": report.disagree,
            "ours_unavailable": report.ours_unavailable,
            "reference_unavailable": report.reference_unavailable,
            "kinds": report.kinds,
            "differences": report.differences,
            "verdict": if ok { "no disagreement" } else { "DISAGREEMENT" },
        }),
        ok,
    ))
}

fn scan_roots(catalog: &Catalog, filter: &[String], all: bool) -> Result<Vec<UpdateRevision>> {
    if !filter.is_empty() {
        return filter.iter().map(|t| resolve_target(catalog, t)).collect();
    }
    Ok(catalog
        .revisions()
        .filter(|r| catalog.latest_revision(r.id) == Some(**r))
        .filter(|r| {
            let Some(e) = catalog.get(r) else {
                return false;
            };
            if !e.record.is_leaf || e.record.update_type.as_deref() != Some("Software") {
                return false;
            }
            all || matches!(
                e.record.deployment.as_ref().map(|d| d.action.as_str()),
                Some("Install" | "PreDeploymentCheck")
            )
        })
        .copied()
        .collect())
}

fn verdict_name(s: NodeStatus) -> (&'static str, Option<&'static str>) {
    match s {
        NodeStatus::Install => ("applicable", None),
        NodeStatus::AlreadyInstalled => ("installed", None),
        NodeStatus::NotApplicable => ("not_applicable", None),
        NodeStatus::Superseded => ("not_applicable", Some("superseded (Unverified rule)")),
        NodeStatus::Unknown => ("unknown", None),
    }
}

/// `wsus client scan`.
pub fn scan(config: &Config, args: &crate::cli::ScanArgs, env: &dyn Env) -> Result<Output> {
    let catalog = load_catalog(config)?;
    let roots = scan_roots(&catalog, &args.updates, args.all)?;
    let facts = env.facts()?;
    let recording = RecordingFacts::new(facts.as_ref());
    let mut planner = Planner::new(&catalog, &recording, plan_options(config, false, false));
    let mut counts = std::collections::BTreeMap::<&str, u64>::new();
    let mut rows = Vec::new();
    for rev in roots {
        let (status, blockers) = planner.verdict(rev);
        let (name, detail) = verdict_name(status);
        *counts.entry(name).or_default() += 1;
        let entry = catalog.get(&rev);
        rows.push(json!({
            "update": rev.to_string(),
            "action": entry.and_then(|e| e.record.deployment.as_ref()).map(|d| d.action.clone()),
            "verdict": name,
            "detail": detail,
            "blockers": blockers.iter().take(5).collect::<Vec<_>>(),
            "blockers_total": blockers.len(),
        }));
    }
    Ok(Output::ok(json!({
        "facts_source": env.facts_source()?,
        "facts_queries": recording.queries(),
        "summary": counts,
        "updates": rows,
    })))
}

/// `wsus client plan`.
pub fn plan(config: &Config, args: &crate::cli::PlanArgs, env: &dyn Env) -> Result<Output> {
    let catalog = load_catalog(config)?;
    let target = resolve_target(&catalog, &args.update)?;
    let facts = env.facts()?;
    let plan = build_plan(
        &catalog,
        facts.as_ref(),
        target,
        &plan_options(config, args.allow_unknown, args.plan_prerequisites),
    );
    let ok = plan.outcome != PlanOutcome::Refused;
    if let Some(out) = &args.out {
        std::fs::write(out, plan.to_json())
            .with_context(|| format!("cannot write {}", out.display()))?;
        return Ok(Output::with_ok(
            plan_summary(&plan, env, &catalog, None, config)?,
            ok,
        ));
    }
    Ok(Output::with_ok(
        serde_json::to_value(&plan).context("plan serializes")?,
        ok,
    ))
}

fn plan_summary(
    plan: &InstallPlan,
    env: &dyn Env,
    _catalog: &Catalog,
    store: Option<&dyn PayloadStore>,
    config: &Config,
) -> Result<Value> {
    let system_dir = env.system_dir();
    let root = paths(config).content_dir;
    let steps: Vec<Value> = plan
        .steps
        .iter()
        .map(|s| {
            let mut v = json!({
                "index": s.index,
                "update": s.update,
                "handler": s.spec.kind(),
                "payload": {"file": s.payload.file_name, "size": s.payload.size,
                    "digests": s.payload.digests.iter()
                        .map(|d| format!("{}:{}", d.algorithm, d.hex)).collect::<Vec<_>>()},
            });
            if plan.outcome == PlanOutcome::Uninstall {
                v["operation"] = json!("uninstall");
                v["package"] = json!(s.servicing_identity);
                if s.servicing_identity.is_none() {
                    v["package_from"] =
                        json!("the CompDB cabinet in the store, read when the plan runs");
                }
                v.as_object_mut().map(|o| o.remove("payload"));
            }
            if let Some(l) = &s.launcher {
                v["launcher"] = json!({"role": l.role, "flavor": l.flavor,
                    "from_version": l.from_version, "terminal": l.is_terminal()});
            }
            if let Some(store) = store
                && let Ok(path) = store.expected_path(&s.payload)
            {
                v["payload_in_store"] = json!(store.locate(&s.payload).ok().flatten().is_some());
                match prepare_command(s, &path, system_dir.as_deref(), &root) {
                    Ok(p) => v["command"] = json!(display_command(&p)),
                    Err(e) => v["command_error"] = json!(e),
                }
            }
            v
        })
        .collect();
    Ok(json!({
        "target": plan.target,
        "outcome": plan.outcome,
        "plan_sha256": plan.hash(),
        "allow_unknown": plan.allow_unknown,
        "facts": plan.facts,
        "decisions": plan.decisions.len(),
        "steps": steps,
        "blockers": plan.blockers,
        "notes": plan.notes,
    }))
}

/// Result of the install flow.
fn job_value(rec: &wsus_client::install::job::JobRecord, jobs: &JobStore) -> Value {
    json!({
        "job_id": rec.job_id,
        "job_record": jobs.dir().join(format!("{}.json", rec.job_id)).display().to_string(),
        "status": rec.status,
        "facts_source": rec.facts_source,
        "facts_hash": rec.facts_hash,
        "plan_sha256": rec.plan_hash,
        "trusted_signers": rec.trusted_signers,
        "flags": rec.flags,
        "recovered_interrupted_jobs": rec.recovered,
        "steps": rec.steps.iter().map(|s| json!({
            "index": s.index,
            "update": s.update,
            "state": s.state,
            "program": s.program,
            "arguments": s.arguments,
            "digest_verified": s.digest_verified,
            "signer": s.signature.as_ref().map(|i| i.organization.clone().or_else(|| i.subject_cn.clone())),
            "exit_code": s.exit_code,
            "exit_class": s.exit_class,
            "timed_out": s.timed_out,
            "refusal": s.refusal,
            "stub_result": s.stub_result,
            "servicing": s.servicing,
        })).collect::<Vec<_>>(),
        "defender": rec.defender,
        "servicing": rec.servicing,
        "post_check": rec.post_check,
        "reporting_sent": rec.reporting_sent,
    })
}

/// The install-event reporter when the configuration asks for it (`install.report_events`, and
/// `install.report_uninstall_events` for removals); `None` leaves the install path silent.
fn open_reporter(
    config: &Config,
    update: UpdateRevision,
    title: Option<String>,
    uninstall: bool,
) -> Result<Option<InstallReporter>> {
    let on = if uninstall {
        config.install.report_uninstall_events
    } else {
        config.install.report_events
    };
    if !on {
        return Ok(None);
    }
    let queue = EventQueue::open(&paths(config).events_dir, QueueConfig::default())
        .context("cannot open the event queue")?;
    let mut titles = std::collections::BTreeMap::new();
    if let Some(title) = title {
        titles.insert(update.to_string(), title);
    }
    Ok(Some(InstallReporter::new(
        queue,
        titles,
        InstallReportOptions {
            include_uninstall: config.install.report_uninstall_events,
            update: Some(update),
            ..InstallReportOptions::default()
        },
    )))
}

fn reporting_value(
    log: &InstallReportLog,
    delivered: Option<usize>,
    error: Option<String>,
) -> Value {
    json!({
        "queued": log.queued,
        "already_known": log.already_known,
        "queue_errors": log.errors,
        "delivered": delivered,
        "delivery_error": error,
    })
}

/// `wsus client install`.
pub async fn install<T: Transport, S: RetryTimer, C: Clock>(
    engine: &mut SyncEngine<T, S, C>,
    config: &Config,
    args: &crate::cli::InstallArgs,
    env: &dyn Env,
    clock: &dyn Clock,
) -> Result<(Output, OpFields)> {
    let catalog = engine.catalog()?;
    let target = resolve_target(&catalog, &args.update)?;
    let options = plan_options(config, args.allow_unknown, args.plan_prerequisites);
    let facts = env.facts()?;
    let plan = build_plan(&catalog, facts.as_ref(), target, &options);
    drop(facts);
    let content_dir = paths(config).content_dir;
    let store = DownloaderStore::new(open_downloader(config)?, &content_dir);
    let fields = OpFields::default();
    if !args.yes {
        let mut v = plan_summary(&plan, env, &catalog, Some(&store), config)?;
        v["mode"] = json!("dry_run");
        v["note"] = json!(
            "Nothing was downloaded, executed or changed. Pass --yes to download, verify, execute and re-check."
        );
        return Ok((
            Output::with_ok(v, plan.outcome != PlanOutcome::Refused),
            fields,
        ));
    }
    if !env.can_execute() {
        bail!(
            "refusing to execute: installers run only on Windows with live facts \
             (not with --facts-file); drop --yes for a dry run"
        );
    }
    if !env.is_elevated()? {
        bail!("refusing to execute: this process is not elevated (run as Administrator or SYSTEM)");
    }
    if plan.outcome == PlanOutcome::Install {
        // Acquire the payloads of the steps through the existing verified path.
        let revisions: Vec<UpdateRevision> = plan
            .steps
            .iter()
            .map(|s| crate::output::parse_update_revision(&s.update))
            .collect::<Result<_>>()?;
        let closure = catalog.acquisition_closure(&revisions, &ClosureOptions::default());
        let downloader = open_downloader(config)?;
        let report = engine
            .acquire(&closure, &downloader, &download_options(config))
            .await?;
        let failed: Vec<String> = report
            .files
            .iter()
            .filter_map(|f| match &f.status {
                FileStatus::Failed(why) => Some(format!("{}: {why}", f.file_name)),
                FileStatus::Complete(_) => None,
            })
            .collect();
        if !failed.is_empty() {
            bail!(
                "acquisition failed, nothing was executed: {}",
                failed.join("; ")
            );
        }
    }
    let jobs = JobStore::open(config.client.state_dir.join("jobs")).context("job store")?;
    let reported = reported_update(&catalog, target);
    let title = if config.install.report_events {
        report_title(engine, reported).await
    } else {
        None
    };
    let reporter = open_reporter(config, reported, title, false)?;
    let hook: &dyn ReportHook = match &reporter {
        Some(r) => r,
        None => &NoReport,
    };
    let exec = Executor {
        store: &store,
        runner: env.runner(),
        verifier: env.verifier(),
        jobs: &jobs,
        clock,
        hook,
        sleeper: env.sleeper(),
        watcher: env.watcher(),
        config: ExecConfig {
            post_check_wait: std::time::Duration::from_secs(
                args.post_check_wait_secs
                    .unwrap_or(config.install.post_check_wait_secs),
            ),
            handler_log: env.handler_log(),
            trust: TrustPolicy {
                allowed_signers: if args.trust_signers.is_empty() {
                    config.install.trust_signers.clone()
                } else {
                    args.trust_signers.clone()
                },
            },
            path_policy: PathPolicy {
                allow_writable_store: args.allow_writable_store,
            },
            timeout: std::time::Duration::from_secs(
                args.timeout_secs.unwrap_or(config.install.timeout_secs),
            ),
            system_dir: env.system_dir(),
            facts_source: env.facts_source()?,
            allow_unknown: args.allow_unknown,
            stub_env: env.stub_env(),
            servicing: env.servicing(&config.install.servicing_backend)?,
            os_installer: env.os_installer(config.install.osinstaller_stack_dir.as_deref()),
            os_installer_mode: wsus_client::install::servicing::OsInstallerMode::parse(
                &config.install.osinstaller_mode,
            )
            .with_context(|| {
                format!(
                    "unknown install.osinstaller_mode `{}` (update_agent or dism)",
                    config.install.osinstaller_mode
                )
            })?,
            cbs_log: env.cbs_log(),
            ..ExecConfig::default()
        },
    };
    let mut post = |executed: &[String]| -> PostCheck {
        let mut pc = PostCheck {
            performed: false,
            ..PostCheck::default()
        };
        let Ok(facts) = env.facts() else {
            return pc;
        };
        let recording = RecordingFacts::new(facts.as_ref());
        let mut planner = Planner::new(&catalog, &recording, options.clone());
        for u in executed {
            let Ok(rev) = crate::output::parse_update_revision(u) else {
                pc.unknown.push(u.clone());
                continue;
            };
            match planner.verdict(rev).0 {
                NodeStatus::AlreadyInstalled => pc.installed.push(u.clone()),
                NodeStatus::Unknown => pc.unknown.push(u.clone()),
                _ => pc.not_installed.push(u.clone()),
            }
        }
        pc.performed = true;
        pc.facts_hash = Some(recording.digest());
        pc
    };
    let run = exec.run(&plan, &mut post);
    drop(exec);
    // Events are delivered after the run, best effort: a delivery failure leaves them queued
    // (the next sync or report sends them) and never changes the install result.
    let inventory_on = config.install.report_inventory
        && matches!(
            &run,
            Ok(r) if matches!(r.status, JobStatus::Succeeded | JobStatus::RebootRequired | JobStatus::Failed)
        );
    let reporting = if reporter.is_some() || inventory_on {
        let (mut queue, log) = match reporter {
            Some(r) => r.finish(),
            None => (
                EventQueue::open(&paths(config).events_dir, QueueConfig::default())
                    .context("cannot open the event queue")?,
                InstallReportLog::default(),
            ),
        };
        // The state after the job: the evaluator's verdicts, with the job's own post-check
        // deciding for the updates it executed (an install waiting for a restart stays not
        // installed, as a native agent's inventory kept it until after the restart).
        let inventory = match (&run, inventory_on) {
            (Ok(r), true) => Some(
                match queue_inventory(
                    &mut queue,
                    config,
                    &catalog,
                    env,
                    clock,
                    Some(&r.post_check),
                    false,
                ) {
                    Ok(v) => v,
                    Err(e) => json!({"error": format!("{e:#}")}),
                },
            ),
            _ => None,
        };
        let (delivered, error) = if queue.is_empty() {
            (None, None)
        } else {
            match engine.flush_events(&mut queue, 100).await {
                Ok(o) => (Some(o.delivered), None),
                Err(e) => (None, Some(e.to_string())),
            }
        };
        let mut v = reporting_value(&log, delivered, error);
        if let Some(i) = inventory {
            v["inventory"] = i;
        }
        Some(v)
    } else {
        None
    };
    let record = run.context("install run")?;
    let ok = matches!(
        record.status,
        JobStatus::Succeeded | JobStatus::RebootRequired | JobStatus::NoAction
    );
    let mut v = job_value(&record, &jobs);
    v["mode"] = json!("executed");
    if let Some(r) = reporting {
        v["reporting"] = r;
    }
    Ok((Output::with_ok(v, ok), fields))
}

/// `wsus client uninstall`: plans the removal of one installed servicing update from the stored
/// catalog and live facts, then (with `--yes`) removes the package through the configured backend
/// (`dism` or `dism_api`). Nothing is downloaded and the network is not used.
pub fn uninstall(
    config: &Config,
    args: &crate::cli::UninstallArgs,
    env: &dyn Env,
    clock: &dyn Clock,
) -> Result<(Output, OpFields)> {
    let catalog = load_catalog(config)?;
    let target = resolve_target(&catalog, &args.update)?;
    let mut options = plan_options(config, false, false);
    options.allow_undeclared_uninstall = args.allow_undeclared;
    options.uninstall_package = args.package.clone();
    let facts = env.facts()?;
    let plan = build_uninstall_plan(&catalog, facts.as_ref(), target, &options);
    drop(facts);
    let fields = OpFields::default();
    let ok_plan = plan.outcome != PlanOutcome::Refused;
    if !args.yes {
        let mut v = plan_summary(&plan, env, &catalog, None, config)?;
        v["mode"] = json!("dry_run");
        v["note"] = json!(
            "Nothing was changed. Pass --yes to remove the package, then restart when asked and run the command again: a removed update reports `NothingToDoNotInstalled`."
        );
        return Ok((Output::with_ok(v, ok_plan), fields));
    }
    if !env.can_execute() {
        bail!(
            "refusing to execute: a removal runs only on Windows with live facts \
             (not with --facts-file); drop --yes for a dry run"
        );
    }
    if !env.is_elevated()? {
        bail!("refusing to execute: this process is not elevated (run as Administrator or SYSTEM)");
    }
    let content_dir = paths(config).content_dir;
    let store = DownloaderStore::new(open_downloader(config)?, &content_dir);
    let jobs = JobStore::open(config.client.state_dir.join("jobs")).context("job store")?;
    let reported = reported_update(&catalog, target);
    let title = catalog_title(&catalog, reported);
    let reporter = open_reporter(config, reported, title, true)?;
    let hook: &dyn ReportHook = match &reporter {
        Some(r) => r,
        None => &NoReport,
    };
    let exec = Executor {
        store: &store,
        runner: env.runner(),
        verifier: env.verifier(),
        jobs: &jobs,
        clock,
        hook,
        sleeper: env.sleeper(),
        watcher: env.watcher(),
        config: ExecConfig {
            post_check_wait: std::time::Duration::from_secs(
                args.post_check_wait_secs
                    .unwrap_or(config.install.post_check_wait_secs),
            ),
            timeout: std::time::Duration::from_secs(
                args.timeout_secs.unwrap_or(config.install.timeout_secs),
            ),
            system_dir: env.system_dir(),
            facts_source: env.facts_source()?,
            servicing: env.servicing(&config.install.servicing_backend)?,
            cbs_log: env.cbs_log(),
            allow_undeclared_uninstall: args.allow_undeclared,
            path_policy: PathPolicy {
                allow_writable_store: args.allow_writable_store,
            },
            ..ExecConfig::default()
        },
    };
    // The callback reports which executed updates are STILL installed (`installed`) and which are
    // not (`not_installed`); for an uninstall the executor wants the latter.
    let mut post = |executed: &[String]| -> PostCheck {
        let mut pc = PostCheck {
            performed: false,
            ..PostCheck::default()
        };
        let Ok(facts) = env.facts() else {
            return pc;
        };
        let recording = RecordingFacts::new(facts.as_ref());
        let planner = Planner::new(&catalog, &recording, options.clone());
        for u in executed {
            let Ok(rev) = crate::output::parse_update_revision(u) else {
                pc.unknown.push(u.clone());
                continue;
            };
            match planner.installed_verdict(rev).0 {
                wsus_protocol::applicability::Tri::True => pc.installed.push(u.clone()),
                wsus_protocol::applicability::Tri::Unknown => pc.unknown.push(u.clone()),
                wsus_protocol::applicability::Tri::False => pc.not_installed.push(u.clone()),
            }
        }
        pc.performed = true;
        pc.facts_hash = Some(recording.digest());
        pc
    };
    let run = exec.run(&plan, &mut post);
    drop(exec);
    // A removal has no engine (no network): its events stay queued for the next sync or report.
    let (reporting, held_queue) = match reporter {
        Some(r) => {
            let (queue, log) = r.finish();
            (Some(reporting_value(&log, None, None)), Some(queue))
        }
        None => (None, None),
    };
    // The client status event of the state after the removal: the live evaluation decides (no
    // post-check override: whether the package counts as removed before the restart is the
    // evaluator's verdict, not assumed here).
    let inventory = if config.install.report_inventory
        && matches!(
            &run,
            Ok(r) if matches!(r.status, JobStatus::Succeeded | JobStatus::RebootRequired | JobStatus::Failed)
        ) {
        let mut queue = match held_queue {
            Some(q) => q,
            None => EventQueue::open(&paths(config).events_dir, QueueConfig::default())
                .context("cannot open the event queue")?,
        };
        Some(
            match queue_inventory(&mut queue, config, &catalog, env, clock, None, false) {
                Ok(v) => v,
                Err(e) => json!({"error": format!("{e:#}")}),
            },
        )
    } else {
        None
    };
    let record = run.context("uninstall run")?;
    let ok = matches!(
        record.status,
        JobStatus::Succeeded | JobStatus::RebootRequired | JobStatus::NoAction
    );
    let mut v = job_value(&record, &jobs);
    v["mode"] = json!("executed");
    v["operation"] = json!("uninstall");
    if let Some(mut r) = reporting {
        if let Some(i) = inventory {
            r["inventory"] = i;
        }
        v["reporting"] = r;
    } else if let Some(i) = inventory {
        v["reporting"] = json!({"inventory": i});
    }
    Ok((Output::with_ok(v, ok), fields))
}

/// Re-exported for the binary.
pub fn default_clock() -> SystemClock {
    SystemClock
}
