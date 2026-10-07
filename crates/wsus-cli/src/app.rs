//! Command dispatch. Synchronous commands never start an async runtime; the
//! network commands build one at this edge.

use crate::{
    admin::{self, Admin, ContentMode},
    cli::*,
    client_cmd,
    config::Config,
    diagnostics, install_cmd,
    logging::{Op, OpFields},
    net,
    output::Output,
    server_cmd,
};
use anyhow::{Context, Result, bail};
use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};
use wsus_client::{session::SystemClock, transport::reqwest_backend::TokioTimer};

/// Default configuration file name used when `--config` is absent.
pub const DEFAULT_CONFIG: &str = "wsus.toml";

/// Resolves and loads the configuration. An explicit but missing file is an
/// error; without `--config` a missing `wsus.toml` means defaults.
pub fn load_config(explicit: Option<&Path>) -> Result<(Config, PathBuf)> {
    match explicit {
        Some(path) => Ok((Config::load(path)?, path.to_path_buf())),
        None => {
            let path = PathBuf::from(DEFAULT_CONFIG);
            if path.exists() {
                Ok((Config::load(&path)?, path))
            } else {
                Ok((Config::defaults_in(Path::new(".")), path))
            }
        }
    }
}

fn block_on<F: Future>(future: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    Ok(runtime.block_on(future))
}

fn traced(name: &'static str, f: impl FnOnce() -> Result<(Output, OpFields)>) -> Result<Output> {
    let op = Op::start(name);
    let result = f();
    match result {
        Ok((output, fields)) => {
            op.finish(&Ok(()), &fields);
            Ok(output)
        }
        Err(e) => {
            op.finish(
                &Err::<(), _>(anyhow::anyhow!("{e:#}")),
                &OpFields::default(),
            );
            Err(e)
        }
    }
}

fn plain(name: &'static str, f: impl FnOnce() -> Result<Output>) -> Result<Output> {
    traced(name, || f().map(|o| (o, OpFields::default())))
}

fn live_engine(
    config: &Config,
) -> Result<
    wsus_client::sync::SyncEngine<
        wsus_client::transport::reqwest_backend::ReqwestTransport,
        TokioTimer,
        SystemClock,
    >,
> {
    let transport = net::build_transport(
        &config.network,
        Duration::from_secs(config.client.request_timeout_secs.min(30)),
    )?;
    client_cmd::open_engine(config, transport, TokioTimer, SystemClock)
}

/// Runs one parsed command.
pub fn run(cli: &Cli, config: &Config, config_path: &Path) -> Result<Output> {
    match &cli.command {
        Command::Client(c) => run_client(c, config, config_path),
        Command::Server(ServerCmd::Run) => {
            let config = config.clone();
            traced("server.run", move || {
                block_on(async move { server_cmd::run(&config).await })
                    .and_then(|r| r.map(|f| (Output::ok(serde_json::json!({"stopped": true})), f)))
            })
        }
        Command::Admin(a) => run_admin(a, config),
    }
}

fn run_client(cmd: &ClientCmd, config: &Config, config_path: &Path) -> Result<Output> {
    match cmd {
        ClientCmd::Configure(args) => plain("client.configure", || {
            let mut config = config.clone();
            client_cmd::configure(
                &mut config,
                client_cmd::ConfigureArgs {
                    origin: args.origin.clone(),
                    state_dir: args.state_dir.clone(),
                    dns_name: args.dns_name.clone(),
                    target_group: args.target_group.clone(),
                },
            )?;
            config.save(config_path)?;
            // Opening the session creates and persists the computer identity.
            let engine = live_engine(&config)?;
            let id = engine
                .session()
                .state()
                .computer_id
                .map(|c| c.0.to_string());
            Ok(Output::ok(client_cmd::configured_summary(&config, id)))
        }),
        ClientCmd::Sync => traced("client.sync", || {
            block_on(async {
                let mut engine = live_engine(config)?;
                client_cmd::sync(&mut engine, config).await
            })?
        }),
        ClientCmd::Inspect { revision } => plain("client.inspect", || {
            let engine = live_engine(config)?;
            client_cmd::inspect(&engine, revision.as_deref())
        }),
        ClientCmd::Download(args) => traced("client.download", || {
            if !args.all && args.updates.is_empty() {
                bail!("select content with --update UUID[@REV] or --all");
            }
            let selection = if args.all {
                client_cmd::Selection::All
            } else {
                client_cmd::Selection::Updates(args.updates.clone())
            };
            block_on(async {
                let mut engine = live_engine(config)?;
                client_cmd::download(&mut engine, config, &selection, args.include_prerequisites)
                    .await
            })?
        }),
        ClientCmd::FactsCheck(args) => plain("client.facts_check", || {
            install_cmd::facts_check(args, &install_cmd::SystemEnv::new(args.facts_file.clone()))
        }),
        ClientCmd::Scan(args) => plain("client.scan", || {
            install_cmd::scan(
                config,
                args,
                &install_cmd::SystemEnv::new(args.facts_file.clone()),
            )
        }),
        ClientCmd::Plan(args) => plain("client.plan", || {
            install_cmd::plan(
                config,
                args,
                &install_cmd::SystemEnv::new(args.facts_file.clone()),
            )
        }),
        ClientCmd::Install(args) => traced("client.install", || {
            block_on(async {
                let mut engine = live_engine(config)?;
                let env = install_cmd::SystemEnv::new(args.facts_file.clone());
                install_cmd::install(&mut engine, config, args, &env, &SystemClock).await
            })?
        }),
        ClientCmd::Uninstall(args) => traced("client.uninstall", || {
            let env = install_cmd::SystemEnv::new(args.facts_file.clone());
            install_cmd::uninstall(config, args, &env, &SystemClock)
        }),
        ClientCmd::Report(args) => traced("client.report", || {
            if !args.flush_only
                && args.job.is_none()
                && !args.inventory
                && (args.namespace_id.is_none() || args.event_id.is_none())
            {
                bail!(
                    "--namespace-id and --event-id are required unless --flush-only or --job is given"
                );
            }
            let report = client_cmd::ReportArgs {
                update: args.update.clone(),
                namespace_id: args.namespace_id.unwrap_or(0),
                event_id: args.event_id.unwrap_or(0),
                source_id: args.source_id,
                hresult: args.hresult,
                sequence: args.sequence,
                instance_id: args.instance_id,
                app_name: args.app_name.clone(),
                job: args.job.clone(),
                inventory: args.inventory,
                force: args.force,
                facts_file: args.facts_file.clone(),
                flush_only: args.flush_only,
                no_flush: args.no_flush,
                batch_size: args.batch_size,
            };
            block_on(async {
                let mut engine = live_engine(config)?;
                client_cmd::report(&mut engine, config, &report).await
            })?
        }),
    }
}

fn content_mode(arg: ContentArg) -> ContentMode {
    match arg {
        ContentArg::None => ContentMode::None,
        ContentArg::All => ContentMode::All,
        ContentArg::Approved => ContentMode::Approved,
    }
}

fn run_admin(cmd: &AdminCmd, config: &Config) -> Result<Output> {
    match cmd {
        AdminCmd::Source(SourceCmd::Add {
            name,
            kind,
            description,
        }) => plain("admin.source.add", || {
            admin::source_add(&Admin::open(config)?, name, kind, description)
        }),
        AdminCmd::Source(SourceCmd::List) => plain("admin.source.list", || {
            admin::source_list(&Admin::open(config)?)
        }),
        AdminCmd::Sync(SyncCmd::Status { source }) => plain("admin.sync.status", || {
            admin::sync_status(&Admin::open(config)?, source.as_deref())
        }),
        AdminCmd::Sync(SyncCmd::Categories { source }) => plain("admin.sync.categories", || {
            block_on(admin::sync_categories(
                &Admin::open(config)?,
                source.as_deref(),
            ))?
        }),
        AdminCmd::Sync(SyncCmd::Start { source, content }) => {
            sync_run(config, source.as_deref(), false, content_mode(*content))
        }
        AdminCmd::Sync(SyncCmd::Resume { source, content }) => {
            sync_run(config, source.as_deref(), true, content_mode(*content))
        }
        AdminCmd::Catalog(CatalogCmd::Export {
            out,
            source,
            content_base_url,
        }) => plain("admin.catalog.export", || {
            crate::export::catalog_export(
                &Admin::open(config)?,
                source.as_deref(),
                out,
                content_base_url.as_deref(),
            )
        }),
        AdminCmd::Catalog(CatalogCmd::Import {
            dir,
            manifest,
            source,
            dry_run,
        }) => plain("admin.catalog.import", || {
            crate::import::catalog_import(
                &Admin::open(config)?,
                source.as_deref(),
                dir,
                manifest.as_deref(),
                *dry_run,
            )
        }),
        AdminCmd::Updates(UpdatesCmd::List {
            source,
            after,
            limit,
            all,
        }) => plain("admin.updates.list", || {
            admin::updates_list(
                &Admin::open(config)?,
                source.as_deref(),
                *after,
                *limit,
                *all,
            )
        }),
        AdminCmd::Updates(UpdatesCmd::Inspect { update, source }) => {
            plain("admin.updates.inspect", || {
                admin::updates_inspect(&Admin::open(config)?, source.as_deref(), update)
            })
        }
        AdminCmd::Groups(GroupsCmd::Create { name, description }) => {
            plain("admin.groups.create", || {
                admin::groups_create(&Admin::open(config)?, name, description)
            })
        }
        AdminCmd::Groups(GroupsCmd::List) => plain("admin.groups.list", || {
            admin::groups_list(&Admin::open(config)?)
        }),
        AdminCmd::Approval(ApprovalCmd::Set {
            update,
            group,
            action,
            deadline,
            source,
        }) => plain("admin.approval.set", || {
            admin::approval_set(
                &Admin::open(config)?,
                source.as_deref(),
                update,
                group,
                action,
                deadline.as_deref(),
            )
        }),
        AdminCmd::Approval(ApprovalCmd::Remove {
            update,
            group,
            action,
        }) => plain("admin.approval.remove", || {
            admin::approval_remove(&Admin::open(config)?, update, group, action.as_deref())
        }),
        AdminCmd::Content(ContentCmd::Verify { deep, source }) => {
            plain("admin.content.verify", || {
                admin::content_verify(&Admin::open(config)?, source.as_deref(), *deep)
            })
        }
        AdminCmd::Diagnostics(DiagnosticsCmd::Export { .. }) => {
            unreachable!("handled by run_diagnostics")
        }
    }
}

fn sync_run(
    config: &Config,
    source: Option<&str>,
    resume: bool,
    mode: ContentMode,
) -> Result<Output> {
    let name = if resume {
        "admin.sync.resume"
    } else {
        "admin.sync.start"
    };
    traced(name, || {
        let admin = Admin::open(config)?;
        block_on(admin::sync_run(&admin, source, resume, mode))?
    })
}

/// Diagnostics need the global trace file option, so they are dispatched
/// separately from the other admin commands.
pub fn run_diagnostics(cli: &Cli, config: &Config) -> Result<Output> {
    let Command::Admin(AdminCmd::Diagnostics(DiagnosticsCmd::Export {
        out,
        fixtures,
        outcomes,
        include_trace,
    })) = &cli.command
    else {
        bail!("not a diagnostics command");
    };
    plain("admin.diagnostics.export", || {
        let trace = if *include_trace {
            Some(
                cli.trace_file
                    .as_deref()
                    .context("--include-trace needs --trace-file")?,
            )
        } else {
            None
        };
        diagnostics::export(
            config,
            &diagnostics::ExportArgs {
                out_dir: out,
                fixtures,
                outcomes,
                trace_file: trace,
            },
        )
    })
}

/// True for the diagnostics export command.
pub fn is_diagnostics(cli: &Cli) -> bool {
    matches!(
        cli.command,
        Command::Admin(AdminCmd::Diagnostics(DiagnosticsCmd::Export { .. }))
    )
}
