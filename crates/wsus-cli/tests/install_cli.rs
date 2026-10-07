//! The `client scan | plan | install | facts-check` flow with fakes. Host-only:
//! no Windows, no native agent, no network (the transport records requests so
//! the tests can prove none were made).
use anyhow::Result;
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use wsus_cli::{
    cli::{FactsCheckArgs, InstallArgs, PlanArgs, ScanArgs},
    client_cmd::{self, paths},
    config::Config,
    install_cmd::{self, Env},
};
use wsus_client::{
    install::{
        runner::{FakeRunner, RunResult, Runner},
        signature::{FakeVerifier, SignatureVerifier},
        testkit::{Child, write_bundle},
    },
    reporting::{EventQueue, QueueConfig},
    session::SystemClock,
    sync::{DeploymentSummary, RevisionStore},
    transport::{ImmediateTimer, mock::MockTransport},
};
use wsus_protocol::applicability::{FactProvider, FakeFacts};

struct FakeEnv {
    facts: Arc<Mutex<FakeFacts>>,
    runner: FakeRunner,
    verifier: FakeVerifier,
    can_execute: bool,
    elevated: bool,
}

impl Env for FakeEnv {
    fn facts(&self) -> Result<Box<dyn FactProvider>> {
        Ok(Box::new(self.facts.lock().unwrap().clone()))
    }
    fn facts_source(&self) -> Result<String> {
        Ok("fake".into())
    }
    fn runner(&self) -> &dyn Runner {
        &self.runner
    }
    fn verifier(&self) -> &dyn SignatureVerifier {
        &self.verifier
    }
    fn can_execute(&self) -> bool {
        self.can_execute
    }
    fn is_elevated(&self) -> Result<bool> {
        Ok(self.elevated)
    }
    fn system_dir(&self) -> Option<PathBuf> {
        None
    }
}

struct World {
    dir: TempDir,
    config: Config,
    state: Arc<Mutex<FakeFacts>>,
    child: Child,
    root: String,
}

fn world() -> World {
    let dir = TempDir::new().unwrap();
    let mut config = Config::defaults_in(dir.path());
    config.client.origin = Some("http://wsus.test:8530".into());
    config.client.state_dir = dir.path().join("client");
    let child = Child::new(0xA, "a.exe", b"synthetic installer payload");
    let root = write_bundle(
        &paths(&config).meta_dir,
        0x1,
        Some((0xC, "<True />")),
        &[vec![child.clone()]],
    );
    // Place the verified payload exactly where the downloader keeps it.
    let downloader = client_cmd::open_downloader(&config).unwrap();
    let expected = child.payload_ref().expected().unwrap();
    let p = downloader.complete_path(&expected);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, &child.payload).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut d = p.parent().unwrap();
        loop {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
            if d == paths(&config).content_dir {
                break;
            }
            d = d.parent().unwrap();
        }
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut facts = FakeFacts::windows11_x64();
    facts.set_dword("SOFTWARE\\Test", "Version", 1);
    World {
        dir,
        config,
        state: Arc::new(Mutex::new(facts)),
        child,
        root: root.to_string(),
    }
}

impl World {
    fn env(&self, code: i32, signer: &str) -> FakeEnv {
        let state = self.state.clone();
        FakeEnv {
            facts: self.state.clone(),
            runner: FakeRunner::new(move |_| {
                state
                    .lock()
                    .unwrap()
                    .set_dword("SOFTWARE\\Test", "Version", 2);
                Ok(RunResult {
                    exit_code: Some(code),
                    ..RunResult::default()
                })
            }),
            verifier: FakeVerifier::signed_by(signer),
            can_execute: true,
            elevated: true,
        }
    }

    fn args(&self) -> InstallArgs {
        InstallArgs {
            update: self.root.clone(),
            facts_file: None,
            yes: false,
            trust_signers: vec![],
            allow_unknown: false,
            allow_writable_store: false,
            timeout_secs: None,
            post_check_wait_secs: Some(0),
            plan_prerequisites: false,
        }
    }
}

fn run_install(
    w: &World,
    args: &InstallArgs,
    env: &FakeEnv,
    transport: MockTransport,
) -> Result<(wsus_cli::output::Output, wsus_cli::logging::OpFields)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut engine =
            client_cmd::open_engine(&w.config, transport, ImmediateTimer, SystemClock).unwrap();
        install_cmd::install(&mut engine, &w.config, args, env, &SystemClock).await
    })
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    &v[k]
}

#[test]
fn dry_run_is_the_default_and_changes_nothing() {
    let w = world();
    let env = w.env(0, "Microsoft Corporation");
    let transport = MockTransport::scripted(vec![]);
    let (out, _) = run_install(&w, &w.args(), &env, transport.clone()).unwrap();
    assert!(out.ok);
    assert_eq!(field(&out.value, "mode"), "dry_run");
    assert_eq!(field(&out.value, "outcome"), "install");
    let step = &out.value["steps"][0];
    assert_eq!(step["payload_in_store"], true);
    let cmd = step["command"].as_str().unwrap();
    assert!(cmd.ends_with("a.exe WD /q"), "{cmd}");
    assert!(env.runner.calls().is_empty(), "no process in a dry run");
    assert!(transport.requests().is_empty(), "no network in a dry run");
    assert!(
        !w.config.client.state_dir.join("jobs").exists(),
        "no job record"
    );
    // The machine state is untouched.
    assert_eq!(
        w.state.lock().unwrap().clone().reg_value(
            wsus_protocol::applicability::RegView::Native,
            "SOFTWARE\\Test",
            "Version"
        ),
        wsus_protocol::applicability::Fact::Known(wsus_protocol::applicability::RegValue::Dword(1))
    );
}

#[test]
fn yes_needs_a_windows_environment_and_elevation() {
    let w = world();
    let mut args = w.args();
    args.yes = true;
    let mut env = w.env(0, "Microsoft Corporation");
    env.can_execute = false;
    let e = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap_err();
    assert!(format!("{e:#}").contains("refusing to execute"), "{e:#}");
    let mut env = w.env(0, "Microsoft Corporation");
    env.elevated = false;
    let e = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap_err();
    assert!(format!("{e:#}").contains("not elevated"), "{e:#}");
    assert!(env.runner.calls().is_empty());
}

#[test]
fn install_drives_acquire_plan_gate_execute_and_the_post_check() {
    let w = world();
    let mut args = w.args();
    args.yes = true;
    let env = w.env(0, "Microsoft Corporation");
    let transport = MockTransport::scripted(vec![]);
    let (out, _) = run_install(&w, &args, &env, transport.clone()).unwrap();
    assert!(out.ok, "{:#}", out.value);
    assert_eq!(out.value["status"], "succeeded");
    assert_eq!(
        out.value["post_check"]["installed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(out.value["reporting_sent"], false);
    assert_eq!(env.runner.calls().len(), 1);
    assert!(
        transport.requests().is_empty(),
        "the payload was already verified"
    );
    let record = out.value["job_record"].as_str().unwrap();
    assert!(fs::metadata(record).is_ok());
    // Running it again is a no-op: the evaluator says installed.
    let (again, _) = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap();
    assert!(again.ok);
    assert_eq!(again.value["status"], "no_action");
    assert_eq!(env.runner.calls().len(), 1);
}

#[test]
fn the_signer_allowlist_can_be_overridden_explicitly() {
    let w = world();
    let mut args = w.args();
    args.yes = true;
    let env = w.env(0, "Contoso Ltd");
    let (out, _) = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap();
    assert!(!out.ok);
    assert_eq!(out.value["status"], "refused");
    assert!(env.runner.calls().is_empty());
    args.trust_signers = vec!["Contoso Ltd".into()];
    let (out, _) = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap();
    assert!(out.ok, "{:#}", out.value);
    assert_eq!(out.value["trusted_signers"][0], "Contoso Ltd");
}

#[test]
fn plan_scan_and_facts_check_commands() {
    let w = world();
    let env = w.env(0, "Microsoft Corporation");
    // plan
    let out_file = w.dir.path().join("plan.json");
    let out = install_cmd::plan(
        &w.config,
        &PlanArgs {
            update: w.root.clone(),
            facts_file: None,
            allow_unknown: false,
            out: Some(out_file.clone()),
            plan_prerequisites: false,
        },
        &env,
    )
    .unwrap();
    assert!(out.ok);
    let plan: Value = serde_json::from_slice(&fs::read(out_file).unwrap()).unwrap();
    assert_eq!(plan["outcome"], "install");
    assert_eq!(plan["steps"][0]["update"], w.child.revision().to_string());
    // scan
    let scan = install_cmd::scan(
        &w.config,
        &ScanArgs {
            facts_file: None,
            updates: vec![w.root.clone()],
            all: false,
        },
        &env,
    )
    .unwrap();
    assert_eq!(scan.value["updates"][0]["verdict"], "applicable");
    w.state
        .lock()
        .unwrap()
        .set_dword("SOFTWARE\\Test", "Version", 2);
    let scan = install_cmd::scan(
        &w.config,
        &ScanArgs {
            facts_file: None,
            updates: vec![w.root.clone()],
            all: false,
        },
        &env,
    )
    .unwrap();
    assert_eq!(scan.value["updates"][0]["verdict"], "installed");
    // facts-check against a snapshot that disagrees
    let q = w.dir.path().join("q.json");
    fs::write(
        &q,
        r#"{"schema":"wsus-applicability-queries/1","queries":[{"kind":"reg_value","view":"native","subkey":"SOFTWARE\\Test","value":"Version"}]}"#,
    )
    .unwrap();
    let expect = w.dir.path().join("f.json");
    fs::write(
        &expect,
        r#"{"schema":"wsus-applicability-facts/1","collected_at":"x","facts":[{"kind":"reg_value","view":"native","subkey":"SOFTWARE\\Test","value":"Version","result":{"state":"known","value":{"type":"REG_DWORD","data":5}}}]}"#,
    )
    .unwrap();
    let out = install_cmd::facts_check(
        &FactsCheckArgs {
            queries: q,
            expect,
            facts_file: None,
            max_details: 5,
        },
        &env,
    )
    .unwrap();
    assert!(!out.ok, "a disagreement is a failure");
    assert_eq!(out.value["disagree"], 1);
}

/// Gives the bundle root a deployment of its own, as a server delivers it (only deployed leaf
/// software updates are in the client status inventory).
fn deploy_root(w: &World) {
    let store = RevisionStore::open(paths(&w.config).meta_dir).unwrap();
    let root: wsus_protocol::identity::UpdateRevision =
        wsus_cli::output::parse_update_revision(&w.root).unwrap();
    let mut r = store.get(&root).unwrap().unwrap();
    r.deployment = Some(DeploymentSummary {
        id: 7,
        action: "Install".into(),
        is_assigned: true,
        deadline: None,
        last_change_time: "2026-10-06T00:00:00Z".into(),
    });
    store.put(&r).unwrap();
}

fn queued_misc(w: &World) -> Vec<Vec<String>> {
    let q = EventQueue::open(paths(&w.config).events_dir, QueueConfig::default()).unwrap();
    q.pending(100)
        .iter()
        .filter(|e| e.payload["event_id"] == 156)
        .map(|e| serde_json::from_value(e.payload["detail"]["misc_data"].clone()).unwrap())
        .collect()
}

#[test]
fn the_client_status_event_is_off_by_default() {
    let w = world();
    deploy_root(&w);
    let mut args = w.args();
    args.yes = true;
    let env = w.env(0, "Microsoft Corporation");
    let (out, _) = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap();
    assert!(out.ok, "{:#}", out.value);
    assert!(out.value.get("reporting").is_none(), "{:#}", out.value);
    assert!(queued_misc(&w).is_empty());
}

#[test]
fn an_install_queues_the_client_status_event_from_the_post_check() {
    let mut w = world();
    deploy_root(&w);
    w.config.install.report_inventory = true;
    let mut args = w.args();
    args.yes = true;
    let env = w.env(0, "Microsoft Corporation");
    let (out, _) = run_install(&w, &args, &env, MockTransport::scripted(vec![])).unwrap();
    assert!(out.ok, "{:#}", out.value);
    let inv = &out.value["reporting"]["inventory"];
    assert_eq!(inv["outcome"], "queued", "{:#}", out.value);
    assert_eq!(
        (inv["installed"].as_u64(), inv["not_installed"].as_u64()),
        (Some(1), Some(0))
    );
    // The deployed root is on the installed list (`V`), upper case, with the client's AppName.
    let root_id = w.root.split('@').next().unwrap().to_uppercase();
    let queued = queued_misc(&w);
    // The mock transport has no script, so delivery failed and the event stayed queued.
    assert_eq!(queued.len(), 1, "{:#}", out.value);
    assert_eq!(
        queued[0],
        [format!("V={root_id}"), "AppName=wsus-client".to_owned()]
    );
    // Evaluated again with nothing changed: the same inventory is not queued twice.
    let env = w.env(0, "Microsoft Corporation");
    let catalog = install_cmd::load_catalog(&w.config).unwrap();
    let mut q = EventQueue::open(paths(&w.config).events_dir, QueueConfig::default()).unwrap();
    let again =
        install_cmd::queue_inventory(&mut q, &w.config, &catalog, &env, &SystemClock, None, false)
            .unwrap();
    assert_eq!(again["outcome"], "unchanged");
    let forced =
        install_cmd::queue_inventory(&mut q, &w.config, &catalog, &env, &SystemClock, None, true)
            .unwrap();
    assert_eq!(forced["outcome"], "queued");
}
