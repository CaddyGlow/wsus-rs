//! Command surface, configuration, redaction and diagnostics. Host-only tests
//! of this crate's own behavior; no protocol compatibility is claimed.

use clap::CommandFactory;
use std::{fs, io::Write};
use wsus_cli::{
    admin::Admin,
    cli::Cli,
    config::Config,
    diagnostics::{self, ExportArgs},
    logging::{SanitizingWriter, fault_code_of},
    redact::sanitize,
    server_cmd::{fault_code_in, fault_code_in_encoded},
};
use wsus_client::session::{FaultInfo, WuspError};
use wsus_protocol::soap::ErrorCode;

#[test]
fn clap_definition_is_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn every_planned_command_is_present() {
    let cmd = Cli::command();
    let path = |parts: &[&str]| {
        let mut c = &cmd;
        for p in parts {
            c = c
                .find_subcommand(p)
                .unwrap_or_else(|| panic!("missing subcommand {parts:?}"));
        }
    };
    for client in [
        "configure",
        "sync",
        "inspect",
        "download",
        "report",
        "facts-check",
        "scan",
        "plan",
        "install",
        "uninstall",
    ] {
        path(&["client", client]);
    }
    path(&["server", "run"]);
    for p in [
        ["source", "add"],
        ["source", "list"],
        ["sync", "start"],
        ["sync", "status"],
        ["sync", "resume"],
        ["updates", "list"],
        ["updates", "inspect"],
        ["groups", "create"],
        ["groups", "list"],
        ["approval", "set"],
        ["approval", "remove"],
        ["content", "verify"],
        ["catalog", "import"],
        ["diagnostics", "export"],
    ] {
        path(&["admin", p[0], p[1]]);
    }
}

#[test]
fn configuration_rejects_typos_and_bad_origins_and_resolves_paths() {
    let dir = tempfile::tempdir().unwrap();
    let write = |text: &str| {
        let p = dir.path().join("c.toml");
        fs::write(&p, text).unwrap();
        p
    };
    assert!(
        Config::load(&write("[server]\nlisen = \"x\"\n")).is_err(),
        "unknown key"
    );
    assert!(Config::load(&write("[client]\norigin = \"ftp://h\"\n")).is_err());
    assert!(Config::load(&write("[client]\norigin = \"http://user:pw@h:1\"\n")).is_err());
    assert!(Config::load(&write("[client]\norigin = \"http://h:1/path\"\n")).is_err());
    assert!(Config::load(&write("[server]\nlisten = \"nope\"\n")).is_err());
    assert!(Config::load(&write("[logging]\nformat = \"xml\"\n")).is_err());
    let ok = Config::load(&write(
        "[client]\norigin = \"http://h:8530\"\nstate_dir = \"cs\"\n",
    ))
    .unwrap();
    assert_eq!(ok.client.state_dir, dir.path().join("cs"));
    assert!(ok.server.database.starts_with(dir.path()));
    // `sync_delivery` selects the delivery mode and its defaults; a bad value is refused.
    let staged = Config::load(&write("[server]\n")).unwrap();
    let c = wsus_cli::server_cmd::server_config(&staged);
    assert_eq!(
        c.sync_delivery,
        wsus_server::endpoints::SyncDelivery::Staged
    );
    assert_eq!(
        (c.max_sync_new_updates, c.effective_protocol_version()),
        (30, "3.2")
    );
    let closure = Config::load(&write("[server]\nsync_delivery = \"closure\"\n")).unwrap();
    let c = wsus_cli::server_cmd::server_config(&closure);
    assert_eq!(
        c.sync_delivery,
        wsus_server::endpoints::SyncDelivery::Closure
    );
    assert_eq!(
        (c.max_sync_new_updates, c.effective_protocol_version()),
        (200, "3.0")
    );
    let tuned = Config::load(&write(
        "[server]\nsync_delivery = \"closure\"\nmax_sync_new_updates = 50\nprotocol_version = \"3.2\"\n",
    ))
    .unwrap();
    let c = wsus_cli::server_cmd::server_config(&tuned);
    assert_eq!(
        (c.max_sync_new_updates, c.effective_protocol_version()),
        (50, "3.2")
    );
    assert!(Config::load(&write("[server]\nsync_delivery = \"both\"\n")).is_err());
    // The shipped example parses and validates.
    Config::load(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/wsus.example.toml"
    )))
    .unwrap();
}

#[test]
fn sanitizing_writer_removes_secrets_across_split_writes() {
    let mut out = Vec::new();
    {
        let mut w = SanitizingWriter::new(&mut out);
        w.write_all(b"GET https://host.example/Content/ab/x?sig=SECRET&e=1 coo")
            .unwrap();
        w.write_all(b"kie=ABCDEF done\n").unwrap();
        w.write_all(b"trailing authorization: Bearer-token-value")
            .unwrap();
    }
    let text = String::from_utf8(out).unwrap();
    for secret in ["SECRET", "ABCDEF", "Bearer-token-value", "/Content/ab/x"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(text.contains("host.example"));
}

#[test]
fn fault_codes_are_extracted_from_errors_and_soap_bodies() {
    let err = anyhow::Error::new(WuspError::Fault(FaultInfo {
        code: ErrorCode::InvalidCookie,
        reason: "r".into(),
        message: None,
        method: None,
    }))
    .context("while syncing");
    assert_eq!(fault_code_of(&err).as_deref(), Some("InvalidCookie"));
    assert_eq!(fault_code_of(&anyhow::anyhow!("plain")), None);
    assert_eq!(
        fault_code_in(b"<detail><ns:ErrorCode>ConfigChanged</ns:ErrorCode></detail>"),
        "ConfigChanged"
    );
    assert_eq!(fault_code_in(b"<x/>"), "");
}

/// Regression (found in the P3 run): a fault answered with Xpress to a client that accepts it
/// logged an empty `fault_code`, because the access log searched the compressed bytes.
#[test]
fn fault_code_is_read_from_xpress_encoded_fault_bodies() {
    let body = b"<soap:Fault><detail><ns:ErrorCode>ConfigChanged</ns:ErrorCode>\
        <padding>0123456789012345678901234567890123456789012345678901234567890123456789</padding>\
        </detail></soap:Fault>"
        .to_vec();
    let packed = wsus_protocol::xpress::encode(&body).expect("encode");
    assert_ne!(packed, body);
    assert_eq!(
        fault_code_in_encoded(&packed, Some("xpress")),
        "ConfigChanged"
    );
    assert_eq!(
        fault_code_in_encoded(&packed, Some(" XPRESS ")),
        "ConfigChanged"
    );
    assert_eq!(fault_code_in_encoded(&body, None), "ConfigChanged");
    assert_eq!(
        fault_code_in_encoded(&body, Some("identity")),
        "ConfigChanged"
    );
    assert_eq!(fault_code_in_encoded(b"not xpress", Some("xpress")), "");
}

#[cfg(unix)]
#[test]
fn administration_requires_a_database_others_cannot_modify() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::defaults_in(dir.path());
    config.server.database = dir.path().join("db/wsus.sqlite");
    config.server.content_dir = dir.path().join("db/content");
    Admin::open(&config).expect("fresh store is private");
    // The directory was created private.
    let mode = fs::metadata(dir.path().join("db"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
    fs::set_permissions(dir.path().join("db"), fs::Permissions::from_mode(0o777)).unwrap();
    let err = Admin::open(&config).err().expect("must refuse").to_string();
    assert!(err.contains("writable by other users"), "{err}");
}

#[test]
fn diagnostics_manifest_is_sanitized_and_hashes_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::defaults_in(dir.path());
    config.client.origin = Some("http://wsus.example:8530".into());
    let fixture = dir.path().join("f.bin");
    fs::write(&fixture, b"abc").unwrap();
    let trace = dir.path().join("trace.jsonl");
    fs::write(
        &trace,
        "{\"msg\":\"GET https://h.example/c?sig=TOPSECRET\"}\n{\"cookie\":\"COOKIEVALUE\"}\n",
    )
    .unwrap();
    let out = dir.path().join("out");
    let outcomes = vec!["pair=pass cookie=LEAK".to_string()];
    diagnostics::export(
        &config,
        &ExportArgs {
            out_dir: &out,
            fixtures: &[fixture],
            outcomes: &outcomes,
            trace_file: Some(&trace),
        },
    )
    .unwrap();
    let manifest = fs::read_to_string(out.join("manifest.json")).unwrap();
    let trace_out = fs::read_to_string(out.join("trace.jsonl")).unwrap();
    // SHA-256 of "abc".
    assert!(manifest.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    for text in [&manifest, &trace_out] {
        for secret in ["TOPSECRET", "COOKIEVALUE", "LEAK"] {
            assert!(!text.contains(secret), "{secret} leaked in {text}");
        }
    }
    assert!(manifest.contains("\"validated_against_real_wsus\": false"));
    assert!(
        diagnostics::export(
            &config,
            &ExportArgs {
                out_dir: &out,
                fixtures: &[],
                outcomes: &["bad".to_string()],
                trace_file: None
            }
        )
        .is_err()
    );
    assert_eq!(sanitize("plain text"), "plain text");
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_sync_guards_interrupted_generations_and_needs_configuration() {
    use wsus_cli::{
        admin::{self, ContentMode},
        config::UpstreamSection,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::defaults_in(dir.path());
    let admin = Admin::open(&config).unwrap();
    admin::source_add(&admin, "upstream", "upstream", "").unwrap();

    // No [upstream] section.
    let err = admin::sync_run(&admin, None, false, ContentMode::None)
        .await
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("[upstream]"));

    // An unreachable upstream (nothing listens on port 1).
    config.upstream = Some(UpstreamSection {
        origin: "http://127.0.0.1:1".into(),
        ..UpstreamSection::default()
    });
    let admin = Admin::open(&config).unwrap();
    let (out, _) = admin::sync_run(&admin, None, true, ContentMode::None)
        .await
        .unwrap();
    assert_eq!(out.value["outcome"], "nothing_to_resume");
    let failed = admin::sync_run(&admin, None, false, ContentMode::None).await;
    assert!(failed.is_err(), "unreachable upstream must fail cleanly");

    // An interrupted (staging) generation blocks `start` but not `resume`.
    let source = admin.catalog.source_by_name("upstream").unwrap().unwrap();
    admin
        .catalog
        .begin_generation(source.id, Some("pending"))
        .unwrap();
    let status = admin::sync_status(&admin, None).unwrap();
    assert_eq!(status.value["interrupted_staging_generations"], 1);
    let err = admin::sync_run(&admin, None, false, ContentMode::None)
        .await
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("wsus admin sync resume"));
    let resumed = admin::sync_run(&admin, None, true, ContentMode::None).await;
    assert!(
        resumed.is_err(),
        "resume reaches the (unreachable) upstream"
    );
}
