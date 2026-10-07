//! Command line surface (clap derive).

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "wsus",
    version,
    about = "WSUS client, server and local administration",
    long_about = "WSUS client, server and local administration.\n\n\
        Host tests prove only that this client and this server agree with each other \
        and with the pinned specification text. Nothing here is validated against a real \
        WSUS server or a native Windows Update client."
)]
pub struct Cli {
    /// Configuration file (TOML). Without it, defaults relative to the current directory apply.
    #[arg(long, global = true, env = "WSUS_CONFIG")]
    pub config: Option<PathBuf>,
    /// Print results as JSON.
    #[arg(long, global = true)]
    pub json: bool,
    /// More log output (-v debug, -vv trace).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Opt in to sanitized debug tracing written to this file.
    #[arg(long, global = true)]
    pub trace_file: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// MS-WUSP client.
    #[command(subcommand)]
    Client(ClientCmd),
    /// MS-WUSP server.
    #[command(subcommand)]
    Server(ServerCmd),
    /// Local administration of the server (file-ownership authorized).
    #[command(subcommand)]
    Admin(AdminCmd),
}

#[derive(Debug, Subcommand)]
pub enum ClientCmd {
    /// Write the client profile into the configuration file and create the client identity.
    Configure(ConfigureArgs),
    /// Handshake, SyncUpdates and extended metadata.
    Sync,
    /// Show client state, or one update with `--revision`.
    Inspect {
        /// `UUID` or `UUID@REVISION`.
        #[arg(long)]
        revision: Option<String>,
    },
    /// Download verified content for the selected updates.
    Download(DownloadArgs),
    /// Queue a client event (de-duplicated) and deliver queued events.
    Report(ReportArgs),
    /// Compare the live Windows fact provider with a reference snapshot.
    FactsCheck(FactsCheckArgs),
    /// Verdict (applicable, installed, not applicable, unknown) per update.
    Scan(ScanArgs),
    /// Build the install plan of one update (nothing is executed).
    Plan(PlanArgs),
    /// Install one update: dry-run unless `--yes` (Windows, elevated).
    Install(InstallArgs),
    /// Remove one installed servicing update (a `.NET` rollup) through DISM: dry-run unless `--yes`
    /// (Windows, elevated). Monthly cumulative updates are permanent and refused by the stack.
    Uninstall(UninstallArgs),
}

#[derive(Debug, Args)]
pub struct FactsCheckArgs {
    /// `queries.json` (from scripts/wsus/applicability-queries.py).
    #[arg(long)]
    pub queries: PathBuf,
    /// Reference snapshot (`facts.json` written by collect-facts.ps1 on the same state).
    #[arg(long)]
    pub expect: PathBuf,
    /// Check this snapshot instead of the live machine (host self-test only).
    #[arg(long)]
    pub facts_file: Option<PathBuf>,
    /// Differences listed per class.
    #[arg(long, default_value_t = 20)]
    pub max_details: usize,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Facts snapshot to evaluate against (required off Windows).
    #[arg(long)]
    pub facts_file: Option<PathBuf>,
    /// Only these updates (`UUID` or `UUID@REVISION`); repeatable.
    #[arg(long = "update")]
    pub updates: Vec<String>,
    /// Every stored leaf revision, not only deployable software roots.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    /// `UUID` or `UUID@REVISION`.
    #[arg(long)]
    pub update: String,
    #[arg(long)]
    pub facts_file: Option<PathBuf>,
    /// Plan despite Unknown verdicts, skipping the Unknown nodes. RISKY: an
    /// update can be missed or a prerequisite taken as met wrongly.
    #[arg(long)]
    pub allow_unknown: bool,
    /// Write the full plan JSON here.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Plan installable prerequisite updates (a servicing stack update before a cumulative update)
    /// as earlier steps; also `install.plan_prerequisites`.
    #[arg(long)]
    pub plan_prerequisites: bool,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// `UUID` or `UUID@REVISION`.
    #[arg(long)]
    pub update: String,
    #[arg(long)]
    pub facts_file: Option<PathBuf>,
    /// Actually download, execute and verify. Without it nothing is changed.
    #[arg(long)]
    pub yes: bool,
    /// Allowed signer organisation; repeatable; REPLACES `install.trust_signers`
    /// (default `Microsoft Corporation`).
    #[arg(long = "trust-signer")]
    pub trust_signers: Vec<String>,
    /// See `plan --allow-unknown`.
    #[arg(long)]
    pub allow_unknown: bool,
    /// Skip the check that the payload and its directories are not writable by
    /// everyone (a state directory under C:\ usually is). Disposable machines only.
    #[arg(long)]
    pub allow_writable_store: bool,
    /// Timeout of one installer process, seconds (default `install.timeout_secs`).
    #[arg(long)]
    pub timeout_secs: Option<u64>,
    /// Longest wait after the last step for the evaluator to say installed
    /// (default `install.post_check_wait_secs`, 180; 0 disables waiting).
    #[arg(long)]
    pub post_check_wait_secs: Option<u64>,
    /// See `plan --plan-prerequisites`.
    #[arg(long)]
    pub plan_prerequisites: bool,
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// `UUID` or `UUID@REVISION` of the installed update to remove.
    #[arg(long)]
    pub update: String,
    #[arg(long)]
    pub facts_file: Option<PathBuf>,
    /// Actually remove the package. Without it nothing is changed.
    #[arg(long)]
    pub yes: bool,
    /// Accept an update that declares no `UninstallationBehavior` (the real `.NET` rollup leaf declares
    /// none): the removal is then the operator's own request, recorded as such in the plan.
    #[arg(long)]
    pub allow_undeclared: bool,
    /// Skip the check that the CompDB cabinet read for the package identity and its directories are not
    /// writable by everyone (a state directory under C:\ usually is). Disposable machines only.
    #[arg(long)]
    pub allow_writable_store: bool,
    /// The package identity to remove (`name~publicKeyToken~architecture~language~version`), instead of
    /// the one read from the update's metadata or its CompDB cabinet.
    #[arg(long)]
    pub package: Option<String>,
    /// Timeout of the servicing call, seconds (default `install.timeout_secs`). The call is never
    /// killed: on timeout the job is `unconfirmed` and the next run judges by fresh state.
    #[arg(long)]
    pub timeout_secs: Option<u64>,
    /// Longest wait after a removal that needs no restart for the evaluator to say the update is no
    /// longer installed (default `install.post_check_wait_secs`; 0 disables waiting).
    #[arg(long)]
    pub post_check_wait_secs: Option<u64>,
}

#[derive(Debug, Args)]
pub struct ConfigureArgs {
    /// Server origin, `http://host:port`.
    #[arg(long)]
    pub origin: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub dns_name: Option<String>,
    #[arg(long)]
    pub target_group: Option<String>,
}

#[derive(Debug, Args)]
pub struct DownloadArgs {
    /// Update to download (`UUID` or `UUID@REVISION`); repeatable.
    #[arg(long = "update")]
    pub updates: Vec<String>,
    /// Download every update in scope.
    #[arg(long, conflicts_with = "updates")]
    pub all: bool,
    /// Also include the content of prerequisites.
    #[arg(long)]
    pub include_prerequisites: bool,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Update the event is about, `UUID@REVISION`.
    #[arg(long)]
    pub update: Option<String>,
    /// Event namespace id (no defaults are invented: the table is unverified).
    #[arg(long)]
    pub namespace_id: Option<i32>,
    #[arg(long)]
    pub event_id: Option<i16>,
    #[arg(long, default_value_t = 0)]
    pub source_id: i16,
    #[arg(long, default_value_t = 0)]
    pub hresult: i32,
    #[arg(long, default_value_t = 0)]
    pub sequence: i32,
    /// Event instance id; re-using it never produces a second report.
    #[arg(long)]
    pub instance_id: Option<Uuid>,
    #[arg(long)]
    pub app_name: Option<String>,
    /// Queue the outcome events of a recorded install or uninstall job (its id, the file name of
    /// the record under `<state_dir>/jobs` without `.json`) instead of one hand-made event. The
    /// event ids are derived from the job, so a job already queued or delivered adds nothing.
    #[arg(
        long,
        conflicts_with_all = ["namespace_id", "event_id", "instance_id", "update", "flush_only"]
    )]
    pub job: Option<String>,
    /// Queue the client status event `156` (the `U` and `V` lists of updates this client evaluates
    /// as not installed and installed, from the stored catalog and the machine facts) instead of
    /// one hand-made event. An unchanged inventory is queued once; `--force` queues it again.
    /// Needs live facts (Windows) or `--facts-file`.
    #[arg(
        long,
        conflicts_with_all = ["namespace_id", "event_id", "instance_id", "update", "flush_only", "job"]
    )]
    pub inventory: bool,
    /// With `--inventory`: queue a fresh event even when the lists did not change.
    #[arg(long, requires = "inventory")]
    pub force: bool,
    /// With `--inventory`: evaluate against this facts snapshot instead of the machine.
    #[arg(long, requires = "inventory")]
    pub facts_file: Option<PathBuf>,
    /// Only deliver what is queued.
    #[arg(long)]
    pub flush_only: bool,
    /// Queue without contacting the server.
    #[arg(long, conflicts_with = "flush_only")]
    pub no_flush: bool,
    #[arg(long, default_value_t = 100)]
    pub batch_size: usize,
}

#[derive(Debug, Subcommand)]
pub enum ServerCmd {
    /// Serve MS-WUSP over HTTP until interrupted.
    Run,
}

#[derive(Debug, Subcommand)]
pub enum AdminCmd {
    /// Catalog sources.
    #[command(subcommand)]
    Source(SourceCmd),
    /// Upstream synchronization.
    #[command(subcommand)]
    Sync(SyncCmd),
    /// Populate the catalog from local files.
    #[command(subcommand)]
    Catalog(CatalogCmd),
    /// Catalog contents.
    #[command(subcommand)]
    Updates(UpdatesCmd),
    /// Computer groups.
    #[command(subcommand)]
    Groups(GroupsCmd),
    /// Approvals.
    #[command(subcommand)]
    Approval(ApprovalCmd),
    /// Content store.
    #[command(subcommand)]
    Content(ContentCmd),
    /// Evidence export.
    #[command(subcommand)]
    Diagnostics(DiagnosticsCmd),
}

#[derive(Debug, Subcommand)]
pub enum SourceCmd {
    Add {
        name: String,
        #[arg(long, default_value = "upstream")]
        kind: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ContentArg {
    /// Metadata only.
    None,
    /// Every file of the active generation.
    All,
    /// Files of updates with an active approval.
    Approved,
}

#[derive(Debug, Subcommand)]
pub enum SyncCmd {
    /// Discover upstream product/classification IDs and validate live metadata access.
    Categories {
        #[arg(long)]
        source: Option<String>,
    },
    /// Run a synchronization (refuses when an interrupted one exists).
    Start {
        #[arg(long)]
        source: Option<String>,
        #[arg(long, value_enum, default_value = "none")]
        content: ContentArg,
    },
    /// Show generations and the committed checkpoint.
    Status {
        #[arg(long)]
        source: Option<String>,
    },
    /// Continue an interrupted synchronization.
    Resume {
        #[arg(long)]
        source: Option<String>,
        #[arg(long, value_enum, default_value = "none")]
        content: ContentArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum CatalogCmd {
    /// Export an immutable catalog generation as a native WSUS metadata CAB.
    Export {
        /// New CAB package to pass to wsusutil import; existing files are refused.
        #[arg(long)]
        out: PathBuf,
        /// Source whose active generation is exported; default server.source_name.
        #[arg(long)]
        source: Option<String>,
        /// Origin serving our /Content files when metadata has no original URL.
        #[arg(long)]
        content_base_url: Option<String>,
    },
    /// Import Update XML documents and their payload files, verified, as a new
    /// generation that replaces the source's active catalog.
    Import {
        /// Directory with `*.xml` documents and `payloads/<name>` files.
        #[arg(long)]
        dir: PathBuf,
        /// `manifest.json` listing documents and payload paths (relative to --dir).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Target source (kind `local` or `import`); default `server.source_name`.
        #[arg(long)]
        source: Option<String>,
        /// Verify everything and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum UpdatesCmd {
    List {
        #[arg(long)]
        source: Option<String>,
        /// Continue after this local revision id (the `next` of a previous page).
        #[arg(long)]
        after: Option<i32>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Include withdrawn and deleted revisions.
        #[arg(long)]
        all: bool,
    },
    Inspect {
        /// `UUID` or `UUID@REVISION`.
        update: String,
        #[arg(long)]
        source: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum GroupsCmd {
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    List,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalCmd {
    /// Approve an update for a group (updates the deadline when already approved).
    Set {
        /// `UUID` or `UUID@REVISION`.
        update: String,
        /// Group name or id.
        #[arg(long)]
        group: String,
        #[arg(long, default_value = "install")]
        action: String,
        /// Unix seconds or `xs:dateTime`.
        #[arg(long)]
        deadline: Option<String>,
        #[arg(long)]
        source: Option<String>,
    },
    /// Withdraw the active approval of an update for a group.
    Remove {
        update: String,
        #[arg(long)]
        group: String,
        #[arg(long)]
        action: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ContentCmd {
    /// Reconcile content with the database and report catalog coverage.
    Verify {
        /// Re-hash every object.
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        source: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum DiagnosticsCmd {
    /// Write a sanitized evidence manifest.
    Export {
        #[arg(long)]
        out: PathBuf,
        /// Fixture file to hash; repeatable.
        #[arg(long = "fixture")]
        fixtures: Vec<PathBuf>,
        /// Test outcome `NAME=RESULT`; repeatable.
        #[arg(long = "outcome")]
        outcomes: Vec<String>,
        /// Include the (re-sanitized) trace written via `--trace-file`.
        #[arg(long)]
        include_trace: bool,
    },
}
