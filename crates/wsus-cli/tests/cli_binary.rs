//! The `wsus` binary end to end: a real server process, real client commands,
//! local administration, structured logs and the diagnostics export.
//!
//! EVIDENCE STATUS: this proves only that this workspace's binary, server and
//! client work together on this host. It is NOT WSUS compatibility evidence and
//! says nothing about a native Windows Update client.

mod common;

use common::*;
use serde_json::Value;
use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use wsus_cli::{admin::Admin, config::Config};

const BIN: &str = env!("CARGO_BIN_EXE_wsus");

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wsus(config: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run wsus");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(config: &Path, args: &[&str]) -> Value {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    let (code, stdout, stderr) = wsus(config, &all);
    assert_eq!(code, 0, "wsus {args:?} failed: {stderr}");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("bad JSON from {args:?}: {e}\n{stdout}"))
}

#[test]
fn binary_serves_syncs_downloads_reports_and_exports_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    let config_path = dir.path().join("wsus.toml");
    fs::write(
        &config_path,
        format!(
            "[client]\norigin = \"{origin}\"\nstate_dir = \"client\"\n\
             dns_name = \"client1.example.invalid\"\nmax_retries = 0\n\
             [server]\nlisten = \"127.0.0.1:{port}\"\nadvertised_content_url = \"{origin}\"\n\
             [logging]\nlevel = \"info\"\n"
        ),
    )
    .unwrap();

    // Local administration through the binary, then seed a bounded synthetic
    // update through the library (there is no import command yet).
    assert_eq!(
        wsus(
            &config_path,
            &["admin", "source", "add", "upstream", "--kind", "local"]
        )
        .0,
        0
    );
    let config = Config::load(&config_path).unwrap();
    let data = payload(150_000);
    let rev = seed_update(
        &Admin::open(&config).unwrap(),
        "upstream",
        9,
        "payload.bin",
        &data,
    );
    let listed = json(&config_path, &["admin", "updates", "list"]);
    assert_eq!(listed["total"], 1);
    let id = update_id(9).to_string();

    // Not approved: the update exists but cannot be approved for an unknown group.
    let (code, _, err) = wsus(
        &config_path,
        &["admin", "approval", "set", &id, "--group", "nope"],
    );
    assert_eq!(code, 1);
    assert!(err.contains("does not exist"), "{err}");
    let set = json(
        &config_path,
        &["admin", "approval", "set", &id, "--group", "All Computers"],
    );
    assert_eq!(set["state"], "active");

    // A real server process.
    let log = dir.path().join("server.log");
    let child = Command::new(BIN)
        .arg("--config")
        .arg(&config_path)
        .args(["server", "run"])
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&log).unwrap()))
        .spawn()
        .unwrap();
    let _server = Server(child);
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Client commands.
    let configured = json(
        &config_path,
        &["client", "configure", "--target-group", "Lab"],
    );
    assert!(configured["computer_id"].is_string());
    let synced = json(&config_path, &["client", "sync"]);
    assert_eq!(synced["new_revisions"], 1, "{synced}");
    let inspected = json(
        &config_path,
        &["client", "inspect", "--revision", &rev.to_string()],
    );
    assert_eq!(inspected["files"][0]["name"], "payload.bin");
    // `download` needs a selection.
    assert_eq!(wsus(&config_path, &["client", "download"]).0, 1);
    let downloaded = json(&config_path, &["client", "download", "--all"]);
    assert_eq!(downloaded["all_complete"], true, "{downloaded}");
    assert_eq!(
        fs::read(downloaded["files"][0]["path"].as_str().unwrap()).unwrap(),
        data
    );
    let reported = json(
        &config_path,
        &[
            "client",
            "report",
            "--update",
            &rev.to_string(),
            "--namespace-id",
            "1",
            "--event-id",
            "2",
        ],
    );
    assert_eq!(reported["flush"]["delivered"], 1, "{reported}");
    assert_eq!(
        wsus(&config_path, &["client", "report"]).0,
        1,
        "ids are required"
    );

    // Administration while the server runs.
    let inspect = json(&config_path, &["admin", "updates", "inspect", &id]);
    assert_eq!(inspect["files"][0]["content_available"], true);
    let verify = json(&config_path, &["admin", "content", "verify"]);
    assert_eq!(verify["catalog_files_unavailable"], 0);
    let removed = json(
        &config_path,
        &[
            "admin",
            "approval",
            "remove",
            &id,
            "--group",
            "All Computers",
        ],
    );
    assert_eq!(removed["withdrawn"].as_array().unwrap().len(), 1);
    let resynced = json(&config_path, &["client", "sync"]);
    assert_eq!(resynced["removed_revisions"], 1, "{resynced}");

    // Upstream commands report a clear error when no upstream is configured.
    let (code, _, err) = wsus(&config_path, &["admin", "sync", "start"]);
    assert_eq!(code, 1);
    assert!(err.contains("[upstream]"), "{err}");
    let status = json(&config_path, &["admin", "sync", "status"]);
    assert_eq!(status["interrupted_staging_generations"], 0);

    // Diagnostics: sanitized manifest with fixture hashes and outcomes.
    let fixture = dir.path().join("fixture.bin");
    fs::write(&fixture, b"fixture").unwrap();
    let out_dir = dir.path().join("diag");
    json(
        &config_path,
        &[
            "admin",
            "diagnostics",
            "export",
            "--out",
            out_dir.to_str().unwrap(),
            "--fixture",
            fixture.to_str().unwrap(),
            "--outcome",
            "pair=pass",
        ],
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(out_dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["fixtures"][0]["bytes"], 7);
    assert_eq!(manifest["test_outcomes"][0]["result"], "pass");
    assert_eq!(
        manifest["evidence_status"]["validated_against_real_wsus"],
        false
    );
    let text = manifest.to_string();
    assert!(
        !text.contains(dir.path().to_str().unwrap()),
        "no local paths in the manifest"
    );

    // Structured server log: operation, correlation id, duration, status.
    std::thread::sleep(Duration::from_millis(200));
    let log_text = fs::read_to_string(&log).unwrap();
    for needle in [
        "operation=\"http_request\"",
        "correlation_id=",
        "duration_ms=",
        "soap_action=",
        "status=",
    ] {
        assert!(
            log_text.contains(needle),
            "missing {needle} in server log:\n{log_text}"
        );
    }
    assert!(!log_text.contains("sig="), "no signed URL material in logs");
}
