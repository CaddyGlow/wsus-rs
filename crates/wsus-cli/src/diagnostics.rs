//! `wsus admin diagnostics export`: a sanitized evidence manifest.
//!
//! The manifest records software versions, the configuration profile
//! (origins reduced to scheme and host, no paths, no credentials), counts from
//! the stores, SHA-256 hashes of named fixture files and caller-supplied test
//! outcomes. It deliberately states what has *not* been validated. Request and
//! response tracing is opt-in (`--trace-file`) and sanitized before it is
//! written; an existing trace file is re-sanitized line by line on export.

use crate::{admin::Admin, config::Config, output::Output, redact::sanitize, secure};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use wsus_client::session::Clock as _;
use wsus_client::session::SystemClock;

/// Arguments of the export.
pub struct ExportArgs<'a> {
    pub out_dir: &'a Path,
    pub fixtures: &'a [std::path::PathBuf],
    /// `name=result` pairs recorded verbatim (sanitized).
    pub outcomes: &'a [String],
    pub trace_file: Option<&'a Path>,
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut file =
        fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((digest, total))
}

fn client_summary(config: &Config) -> Value {
    let path = crate::client_cmd::paths(config).state_file;
    let Ok(bytes) = fs::read(&path) else {
        return Value::Null;
    };
    let Ok(state) = serde_json::from_slice::<Value>(&bytes) else {
        return json!({"state_file": "unreadable"});
    };
    json!({
        "registration": state["registration"]["state"],
        "has_cookie": !state["cookie"].is_null(),
        "cached_revisions": state["cached_revisions"].as_array().map(Vec::len),
        "has_checkpoint": !state["sync_checkpoint"].is_null(),
    })
}

fn server_summary(config: &Config) -> Result<Value> {
    if !config.server.database.exists() {
        return Ok(Value::Null);
    }
    let admin = Admin::open(config)?;
    let sources = admin.catalog.sources()?;
    let mut fragments = 0u64;
    for s in &sources {
        if let Some(g) = admin.catalog.active_generation(s.id)? {
            fragments += admin.catalog.snapshot_of(g)?.count()?;
        }
    }
    Ok(json!({
        "schema_version": admin.db.schema_version()?,
        "sources": sources.len(),
        "active_fragments": fragments,
        "groups": admin.policy.groups()?.len(),
    }))
}

/// Writes `manifest.json` (and a sanitized `trace.jsonl`) into the directory.
pub fn export(config: &Config, args: &ExportArgs<'_>) -> Result<Output> {
    secure::ensure_private_dir(args.out_dir)?;
    let mut fixtures = Vec::new();
    for path in args.fixtures {
        let (sha256, bytes) = sha256_file(path)?;
        fixtures.push(json!({
            "name": path.file_name().map(|n| n.to_string_lossy().into_owned()),
            "sha256": sha256, "bytes": bytes,
        }));
    }
    let mut outcomes = Vec::new();
    for item in args.outcomes {
        let Some((name, result)) = item.split_once('=') else {
            bail!("outcome `{item}` must be NAME=RESULT");
        };
        outcomes.push(json!({"name": sanitize(name), "result": sanitize(result)}));
    }
    let mut trace = Value::Null;
    if let Some(path) = args.trace_file {
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read trace file {}", path.display()))?;
        let clean: String = text.lines().map(|l| sanitize(l) + "\n").collect();
        let target = args.out_dir.join("trace.jsonl");
        fs::write(&target, clean.as_bytes())?;
        secure::restrict_file(&target)?;
        trace = json!({
            "included": true, "lines": clean.lines().count(),
            "sha256": format!("{:x}", Sha256::digest(clean.as_bytes())),
        });
    }
    let manifest = json!({
        "schema": 1,
        "created": wsus_client::session::unix_to_xs(SystemClock.now_unix()).as_str(),
        "software": {
            "wsus_cli": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "config_profile": config.profile(),
        "client_state": client_summary(config),
        "server_storage": server_summary(config)?,
        "fixtures": fixtures,
        "test_outcomes": outcomes,
        "trace": trace,
        "evidence_status": {
            "validated_against_real_wsus": false,
            "validated_against_native_windows_client": false,
            "note": "Host results only prove the consistency of this client and server pair \
                     and the pinned specification text. They are not compatibility evidence.",
        },
    });
    let text = serde_json::to_string_pretty(&manifest)?;
    // The manifest passes through the same sanitizer as logs.
    let text = sanitize(&text);
    let target = args.out_dir.join("manifest.json");
    fs::write(&target, text.as_bytes())?;
    secure::restrict_file(&target)?;
    Ok(Output::ok(json!({
        "manifest": target.display().to_string(),
        "fixtures": args.fixtures.len(),
        "trace_included": args.trace_file.is_some(),
    })))
}
