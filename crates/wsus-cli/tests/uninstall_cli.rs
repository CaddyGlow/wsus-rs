//! `client uninstall` with fakes: the dry run, the execution gates and a removal that asks for a
//! restart. Host-only: no Windows, no network.
use anyhow::Result;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use uuid::Uuid;
use wsus_cli::{
    cli::UninstallArgs,
    client_cmd::paths,
    config::Config,
    install_cmd::{self, Env},
};
use wsus_client::{
    install::{
        runner::{FakeRunner, Runner},
        servicing::{FakeBackend, PackageEntry, ServicingBackend, fake::RemoveScript},
        signature::{FakeVerifier, SignatureVerifier},
    },
    session::SystemClock,
    sync::{RevisionRecord, RevisionStore, StoredFragment},
};
use wsus_protocol::{
    applicability::{FactProvider, FakeFacts},
    identity::{Revision, UpdateId, UpdateRevision},
};

const OSI_URI: &str = "http://schemas.microsoft.com/msus/2016/01/UpdateHandlers/OSInstaller";
const ID: &str = "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1";

struct FakeEnv {
    facts: Arc<Mutex<FakeFacts>>,
    backend: Arc<FakeBackend>,
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
    fn servicing(&self, _backend: &str) -> Result<Option<Arc<dyn ServicingBackend>>> {
        Ok(Some(self.backend.clone()))
    }
}

fn frag(kind: &str, xml: String) -> StoredFragment {
    StoredFragment {
        kind: kind.into(),
        locale: None,
        sha256: String::new(),
        xml,
    }
}

fn world() -> (TempDir, Config, String) {
    let dir = TempDir::new().unwrap();
    let mut config = Config::defaults_in(dir.path());
    config.client.origin = Some("http://wsus.test:8530".into());
    config.client.state_dir = dir.path().join("client");
    let rev = UpdateRevision {
        id: UpdateId(Uuid::from_u128(0x10)),
        revision: Revision(1),
    };
    let core = format!(
        r#"<UpdateIdentity UpdateID="{}" RevisionNumber="1" /><Properties UpdateType="Software" /><ApplicabilityRules><IsInstalled><CbsPackageInstalled /></IsInstalled><Metadata><CbsPackageApplicabilityMetadata><assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Package_for_DotNetRollup_481" version="10.0.9347.1" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" /><package identifier="KB1" restart="possible"></package></assembly></CbsPackageApplicabilityMetadata></Metadata></ApplicabilityRules>"#,
        rev.id
    );
    let ext = format!(
        r#"<ExtendedProperties DefaultPropertiesLanguage="en" Handler="{OSI_URI}" MaxDownloadSize="10"><InstallationBehavior RebootBehavior="CanRequestReboot" /><UninstallationBehavior RebootBehavior="CanRequestReboot" /></ExtendedProperties><Files><File Digest="AAAAAAAAAAAAAAAAAAAAAAAAAAA=" DigestAlgorithm="SHA1" FileName="x.cab" Size="10" /></Files><HandlerSpecificData type="OSInstallerMetadata"><OSInstallData InitialModule="UpdateAgent.dll" /></HandlerSpecificData>"#
    );
    let store = RevisionStore::open(paths(&config).meta_dir).unwrap();
    store
        .put(&RevisionRecord {
            identity: rev,
            is_leaf: true,
            update_type: Some("Software".into()),
            deployment: None,
            core: frag("Core", core),
            fragments: vec![frag("Extended", ext)],
        })
        .unwrap();
    (dir, config, rev.id.to_string())
}

fn env(installed: bool, backend: FakeBackend) -> FakeEnv {
    let mut facts = FakeFacts::windows11_x64();
    if installed {
        facts.set_cbs_package(ID, 112);
    }
    FakeEnv {
        facts: Arc::new(Mutex::new(facts)),
        backend: Arc::new(backend),
        runner: FakeRunner::exiting(0),
        verifier: FakeVerifier::signed_by("Nobody"),
        can_execute: true,
        elevated: true,
    }
}

fn args(update: &str, yes: bool) -> UninstallArgs {
    UninstallArgs {
        update: update.into(),
        facts_file: None,
        yes,
        allow_undeclared: false,
        allow_writable_store: false,
        package: None,
        timeout_secs: None,
        post_check_wait_secs: Some(0),
    }
}

fn listing() -> Vec<PackageEntry> {
    vec![PackageEntry {
        identity: ID.into(),
        state: "Installed".into(),
    }]
}

#[test]
fn the_dry_run_shows_the_uninstall_plan_and_changes_nothing() {
    let (_d, config, update) = world();
    let env = env(true, FakeBackend::new(listing()));
    let (out, _) =
        install_cmd::uninstall(&config, &args(&update, false), &env, &SystemClock).unwrap();
    assert!(out.ok);
    assert_eq!(out.value["mode"], "dry_run");
    assert_eq!(out.value["outcome"], "uninstall");
    assert_eq!(out.value["steps"][0]["operation"], "uninstall");
    assert_eq!(out.value["steps"][0]["package"], ID);
    assert!(out.value["steps"][0].get("payload").is_none());
    assert!(env.backend.calls().is_empty(), "the stack is not touched");
    assert!(!config.client.state_dir.join("jobs").exists());
}

#[test]
fn an_update_that_is_not_installed_plans_nothing() {
    let (_d, config, update) = world();
    let env = env(false, FakeBackend::new(vec![]));
    let (out, _) =
        install_cmd::uninstall(&config, &args(&update, false), &env, &SystemClock).unwrap();
    assert!(out.ok);
    assert_eq!(out.value["outcome"], "nothing_to_do_not_installed");
}

#[test]
fn yes_needs_windows_live_facts_and_elevation() {
    let (_d, config, update) = world();
    let mut e = env(true, FakeBackend::new(listing()));
    e.can_execute = false;
    let err = install_cmd::uninstall(&config, &args(&update, true), &e, &SystemClock).unwrap_err();
    assert!(format!("{err:#}").contains("refusing to execute"));
    let mut e = env(true, FakeBackend::new(listing()));
    e.elevated = false;
    let err = install_cmd::uninstall(&config, &args(&update, true), &e, &SystemClock).unwrap_err();
    assert!(format!("{err:#}").contains("not elevated"));
    assert!(e.backend.calls().is_empty());
}

#[test]
fn a_removal_that_needs_a_restart_is_reported_as_reboot_required() {
    let (_d, config, update) = world();
    let e = env(
        true,
        FakeBackend::new(listing()).script_remove(RemoveScript::reboot(ID)),
    );
    let (out, _) = install_cmd::uninstall(&config, &args(&update, true), &e, &SystemClock).unwrap();
    assert!(out.ok);
    assert_eq!(out.value["mode"], "executed");
    assert_eq!(out.value["operation"], "uninstall");
    assert_eq!(out.value["status"], "reboot_required");
    assert_eq!(out.value["steps"][0]["exit_code"], 3010);
    assert_eq!(out.value["servicing"]["oracles"]["packages"], "pending");
    assert!(
        e.backend
            .calls()
            .iter()
            .any(|c| c == &format!("remove {ID}"))
    );
}

#[test]
fn a_permanent_package_is_a_failed_job_and_not_ok() {
    let (_d, config, update) = world();
    let e = env(
        true,
        FakeBackend::new(listing()).script_remove(RemoveScript::permanent()),
    );
    let (out, _) = install_cmd::uninstall(&config, &args(&update, true), &e, &SystemClock).unwrap();
    assert!(!out.ok);
    assert_eq!(out.value["status"], "failed");
    assert!(
        out.value["steps"][0]["refusal"]
            .as_str()
            .unwrap()
            .starts_with("permanent package")
    );
}
