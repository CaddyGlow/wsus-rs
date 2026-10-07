//! `wsus admin catalog import`: a catalog populated from local files only.
//!
//! EVIDENCE STATUS: the documents here are written by these tests, not captured
//! from a WSUS server. Passing proves this workspace's importer, catalog, server
//! and client agree with each other. It is NOT WSUS compatibility evidence.

mod common;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use uuid::Uuid;
use wsus_cli::{
    admin::{self, Admin},
    client_cmd::{self, Selection},
    config::Config,
    import::catalog_import,
};
use wsus_client::transport::ImmediateTimer;

fn guid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn software_xml(n: u128, prerequisite: Option<u128>, file: Option<(&str, &[u8])>) -> String {
    let pre = prerequisite.map_or(String::new(), |p| {
        format!("<UpdateIdentity UpdateID=\"{}\"/>", guid(p))
    });
    let files = file.map_or(String::new(), |(name, data)| {
        format!(
            "<Files><File FileName=\"{name}\" Size=\"{}\" Digest=\"{}\" DigestAlgorithm=\"SHA1\">\
             <AdditionalDigest Algorithm=\"SHA256\">{}</AdditionalDigest></File></Files>",
            data.len(),
            STANDARD.encode(Sha1::digest(data)),
            STANDARD.encode(Sha256::digest(data)),
        )
    });
    format!(
        "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
         <UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>\
         <Properties UpdateType=\"Software\"/>\
         <Relationships><Prerequisites>{pre}</Prerequisites></Relationships>{files}</Update>",
        guid(n)
    )
}

fn detectoid_xml(n: u128) -> String {
    format!(
        "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
         <UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>\
         <Properties UpdateType=\"Detectoid\"/><Relationships/></Update>",
        guid(n)
    )
}

fn write(dir: &Path, rel: &str, bytes: impl AsRef<[u8]>) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

struct Env {
    _dir: tempfile::TempDir,
    admin: Admin,
    input: std::path::PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::defaults_in(dir.path());
    let admin = Admin::open(&config).unwrap();
    admin::source_add(&admin, "upstream", "import", "").unwrap();
    let input = dir.path().join("input");
    fs::create_dir_all(&input).unwrap();
    Env {
        _dir: dir,
        admin,
        input,
    }
}

fn active(env: &Env) -> Option<i64> {
    let s = env
        .admin
        .catalog
        .source_by_name("upstream")
        .unwrap()
        .unwrap();
    env.admin
        .catalog
        .active_generation(s.id)
        .unwrap()
        .map(|g| g.0)
}

fn import(env: &Env) -> anyhow::Result<wsus_cli::output::Output> {
    catalog_import(&env.admin, None, &env.input, None, false)
}

fn fails_with(env: &Env, needle: &str) {
    let before = active(env);
    let err = import(env)
        .err()
        .unwrap_or_else(|| panic!("expected failure: {needle}"));
    let text = format!("{err:#}");
    assert!(text.contains(needle), "`{needle}` not in `{text}`");
    assert_eq!(
        active(env),
        before,
        "a failed import must not activate anything"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_catalog_is_served_to_the_client_without_an_upstream() {
    let d = Deployment::new();
    let data = payload(150_000);
    let input = d.dir.path().join("input");
    write(&input, "a-detectoid.xml", detectoid_xml(0x50));
    write(
        &input,
        "b-update.xml",
        software_xml(7, Some(0x50), Some(("payload.bin", &data))),
    );
    write(&input, "payloads/payload.bin", &data);

    let out = catalog_import(&d.admin(), None, &input, None, false).unwrap();
    assert_eq!(out.value["updates"], 2, "{}", out.value);
    assert_eq!(out.value["files_verified"], 1);
    assert_eq!(out.value["content_objects_stored"], 1);
    assert_eq!(out.value["activated"], true);

    let verify = admin::content_verify(&d.admin(), None, true).unwrap();
    assert!(verify.ok);
    assert_eq!(verify.value["catalog_files_declared"], 1);
    assert_eq!(verify.value["catalog_files_unavailable"], 0);

    admin::approval_set(
        &d.admin(),
        None,
        &guid(7).to_string(),
        "All Computers",
        "install",
        None,
    )
    .unwrap();
    let mut e =
        client_cmd::open_engine(&d.config, d.bridge.clone(), ImmediateTimer, d.clock.clone())
            .unwrap();
    let synced = client_cmd::sync(&mut e, &d.config).await.unwrap().0;
    assert!(
        synced.value["new_revisions"].as_u64().unwrap() >= 1,
        "{}",
        synced.value
    );
    let got = client_cmd::download(&mut e, &d.config, &Selection::All, true)
        .await
        .unwrap()
        .0;
    assert!(got.ok, "{}", got.value);
    let path = got.value["files"][0]["path"].as_str().unwrap().to_owned();
    assert_eq!(fs::read(path).unwrap(), data);
}

#[test]
fn manifest_maps_payload_paths_and_dry_run_writes_nothing() {
    let env = env();
    let data = payload(1000);
    write(
        &env.input,
        "docs/u.xml",
        software_xml(1, None, Some(("x.cab", &data))),
    );
    write(&env.input, "blobs/anything.bin", &data);
    write(
        &env.input,
        "manifest.json",
        r#"{"updates":[{"xml":"docs/u.xml","payloads":{"x.cab":"blobs/anything.bin"}}]}"#,
    );
    let manifest = env.input.join("manifest.json");
    let dry = catalog_import(&env.admin, None, &env.input, Some(&manifest), true).unwrap();
    assert_eq!(dry.value["dry_run"], true);
    assert_eq!(dry.value["files_verified"], 1);
    assert_eq!(active(&env), None);
    let verify = admin::content_verify(&env.admin, None, false).unwrap();
    assert_eq!(verify.value["catalog_files_declared"], 0);
    let real = catalog_import(&env.admin, None, &env.input, Some(&manifest), false).unwrap();
    assert_eq!(real.value["activated"], true);
    assert!(active(&env).is_some());
}

#[test]
fn reimport_replaces_the_active_generation() {
    let env = env();
    write(&env.input, "one.xml", software_xml(1, None, None));
    let first = import(&env).unwrap().value["generation"].as_i64().unwrap();
    fs::remove_file(env.input.join("one.xml")).unwrap();
    write(&env.input, "two.xml", software_xml(2, None, None));
    let second = import(&env).unwrap().value["generation"].as_i64().unwrap();
    assert!(second > first);
    assert_eq!(active(&env), Some(second));
    let listed = admin::updates_list(&env.admin, None, None, 10, false).unwrap();
    assert_eq!(listed.value["total"], 1);
}

#[test]
fn bad_input_is_refused_and_changes_nothing() {
    let env = env();
    let data = payload(500);

    // Empty directory.
    fails_with(&env, "no update documents");

    // Malformed XML.
    write(&env.input, "bad.xml", "<Update><UpdateIdentity");
    fails_with(&env, "not a well-formed Update document");
    fs::remove_file(env.input.join("bad.xml")).unwrap();

    // Not an Update document at all.
    write(&env.input, "bad.xml", "<Other/>");
    fails_with(&env, "not a well-formed Update document");
    fs::remove_file(env.input.join("bad.xml")).unwrap();

    // Declared payload missing.
    write(
        &env.input,
        "u.xml",
        software_xml(1, None, Some(("p.bin", &data))),
    );
    fails_with(&env, "payload for `p.bin`");

    // Wrong size.
    write(&env.input, "payloads/p.bin", &data[..400]);
    fails_with(&env, "is 400 bytes but");

    // Same size, wrong content: digest mismatch.
    let mut wrong = data.clone();
    wrong[10] ^= 0xff;
    write(&env.input, "payloads/p.bin", &wrong);
    fails_with(&env, "does not match the Sha1 digest");

    // Unsafe declared file name.
    write(
        &env.input,
        "u.xml",
        software_xml(1, None, Some(("../p.bin", &data))),
    );
    fails_with(&env, "not a plain file name");

    // A payload symlink or path may not escape the directory.
    write(
        &env.input,
        "u.xml",
        software_xml(1, None, Some(("p.bin", &data))),
    );
    write(
        &env.input,
        "manifest.json",
        r#"{"updates":[{"xml":"u.xml","payloads":{"p.bin":"../outside.bin"}}]}"#,
    );
    let manifest = env.input.join("manifest.json");
    let err = catalog_import(&env.admin, None, &env.input, Some(&manifest), false)
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("inside the import directory"));
    fs::remove_file(&manifest).unwrap();

    // Duplicate identity in two documents.
    write(&env.input, "payloads/p.bin", &data);
    write(&env.input, "dup.xml", software_xml(1, None, None));
    fails_with(&env, "appears in more than one document");
    fs::remove_file(env.input.join("dup.xml")).unwrap();

    assert_eq!(active(&env), None);
}

#[test]
fn unsatisfied_prerequisite_is_rejected_and_the_old_catalog_stays_active() {
    let env = env();
    write(&env.input, "a.xml", software_xml(1, None, None));
    let good = import(&env).unwrap().value["generation"].as_i64().unwrap();
    // Prerequisite 0x99 is not part of the import.
    write(&env.input, "a.xml", software_xml(1, Some(0x99), None));
    fails_with(&env, "rejected the import");
    assert_eq!(active(&env), Some(good));
    let status = admin::sync_status(&env.admin, None).unwrap();
    assert_eq!(status.value["interrupted_staging_generations"], 0);
    let failed = status.value["generations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["state"] == "failed")
        .count();
    assert_eq!(failed, 1, "the rejected generation is kept as evidence");
}

#[test]
fn upstream_sources_are_not_import_targets() {
    let env = env();
    admin::source_add(&env.admin, "synced", "upstream", "").unwrap();
    write(&env.input, "a.xml", software_xml(1, None, None));
    let err = catalog_import(&env.admin, Some("synced"), &env.input, None, false)
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("upstream source"));
    let err = catalog_import(&env.admin, Some("missing"), &env.input, None, false)
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("does not exist"));
}
