//! `facts-check` and fact recording, host-only.
use serde_json::{Value, json};
use wsus_client::install::{
    RecordingFacts,
    check::{facts_check, parse_queries},
    load_facts_file,
};
use wsus_protocol::applicability::{
    Fact, FactProvider, FakeFacts, RecordedFacts, RegValue, RegView,
};

fn reference(facts: Value) -> RecordedFacts {
    RecordedFacts::from_json(
        &json!({
            "schema": "wsus-applicability-facts/1",
            "collected_at": "2026-10-05T00:00:00Z",
            "os": {"major": 10, "minor": 0, "build": 26200, "product_type": 1, "suite_mask": 256,
                   "architecture": 9, "language": "en-US", "mui_installed": false},
            "facts": facts,
        })
        .to_string(),
    )
    .unwrap()
}

#[test]
fn per_kind_agreement_and_every_difference_class() {
    let reference = reference(json!([
        {"kind": "reg_key", "view": "native", "subkey": "SOFTWARE\\A", "result": {"state": "known"}},
        {"kind": "reg_value", "view": "native", "subkey": "SOFTWARE\\A", "value": "Version",
         "result": {"state": "known", "value": {"type": "REG_DWORD", "data": 2}}},
        {"kind": "reg_key", "view": "native", "subkey": "SOFTWARE\\B", "result": {"state": "absent"}},
        {"kind": "system_metric", "index": 4, "result": {"state": "known", "value": 0}},
        {"kind": "reg_key", "view": "native", "subkey": "SOFTWARE\\C",
         "result": {"state": "unavailable", "reason": "denied"}},
        {"kind": "file", "location": {"kind": "absolute"}, "path": "C:\\none.dll", "result": {"state": "absent"}},
        {"kind": "reg_value", "view": "native", "subkey": "SOFTWARE\\Loop\\X\\Cfg", "value": "V",
         "result": {"state": "known", "value": {"type": "REG_SZ", "data": "on"}}},
    ]));
    let queries = parse_queries(
        &json!({
            "schema": "wsus-applicability-queries/1",
            "generated": "x",
            "queries": [
                {"kind": "reg_key", "view": "native", "subkey": "SOFTWARE\\A", "updates": ["u"]},
                {"kind": "reg_value", "view": "native", "subkey": "SOFTWARE\\A", "value": "Version"},
                {"kind": "reg_key", "view": "native", "subkey": "SOFTWARE\\B"},
                {"kind": "system_metric", "index": 4},
                {"kind": "reg_key", "view": "native", "subkey": "SOFTWARE\\C"},
                {"kind": "file", "location": {"kind": "absolute"}, "path": "C:\\none.dll"},
                {"kind": "reg_value", "view": "native", "subkey": "Cfg", "value": "V",
                 "loop_parent": "SOFTWARE\\Loop"},
            ],
        })
        .to_string(),
    )
    .unwrap();
    let mut ours = FakeFacts::windows11_x64();
    ours.set_dword("SOFTWARE\\A", "Version", 3); // differs
    ours.add_key(RegView::Native, "SOFTWARE\\B"); // reference says absent
    ours.add_key(RegView::Native, "SOFTWARE\\C"); // reference could not answer
    ours.set_sz("SOFTWARE\\Loop\\X\\Cfg", "V", "on");
    let report = facts_check(&queries, &ours, &reference, 10);
    assert_eq!(report.kinds["reg_key"].total, 3);
    assert_eq!(report.kinds["reg_key"].disagree, 1, "B: known vs absent");
    assert_eq!(report.kinds["reg_key"].reference_unavailable, 1, "C");
    assert_eq!(report.kinds["reg_value"].disagree, 1, "A.Version 2 vs 3");
    assert_eq!(report.kinds["reg_value"].agree, 1, "loop-expanded value");
    assert_eq!(report.kinds["system_metric"].ours_unavailable, 1);
    assert_eq!(report.kinds["file"].agree, 1);
    assert!(!report.agrees());
    assert_eq!(report.disagree, 2);
    assert!(report.differences.iter().all(|d| d.class != "agree"));
    // OS-wide facts were compared too.
    assert!(report.kinds.contains_key("os") && report.kinds.contains_key("architecture"));
}

#[test]
fn a_snapshot_checked_against_itself_agrees_and_unknown_schema_is_rejected() {
    assert!(parse_queries(r#"{"schema":"nope","queries":[]}"#).is_err());
    let r = reference(json!([
        {"kind": "reg_value", "view": "wow32", "subkey": "S", "value": "V",
         "result": {"state": "known", "value": {"type": "REG_MULTI_SZ", "data": ["a", "b"]}}},
    ]));
    let q = parse_queries(
        r#"{"schema":"wsus-applicability-queries/1","queries":[{"kind":"reg_value","view":"wow32","subkey":"S","value":"V"}]}"#,
    )
    .unwrap();
    let report = facts_check(&q, &r, &r, 5);
    assert!(report.agrees());
    assert_eq!(report.kinds["reg_value"].agree, 1);
}

#[test]
fn recording_digest_is_order_independent_and_answer_dependent() {
    let mut f = FakeFacts::windows11_x64();
    f.set_dword("SOFTWARE\\A", "V", 1);
    let a = RecordingFacts::new(&f);
    let _ = a.reg_value(RegView::Native, "SOFTWARE\\A", "V");
    let _ = a.reg_key_exists(RegView::Native, "software\\b");
    let b = RecordingFacts::new(&f);
    let _ = b.reg_key_exists(RegView::Native, "SOFTWARE\\B");
    let _ = b.reg_value(RegView::Native, "software\\a", "v");
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.queries(), 2);
    let first = a.digest();
    let mut g = f.clone();
    g.set_dword("SOFTWARE\\A", "V", 2);
    let c = RecordingFacts::new(&g);
    let _ = c.reg_value(RegView::Native, "SOFTWARE\\A", "V");
    let _ = c.reg_key_exists(RegView::Native, "SOFTWARE\\B");
    assert_ne!(first, c.digest());
    assert!(matches!(
        g.reg_value(RegView::Native, "SOFTWARE\\A", "V"),
        Fact::Known(RegValue::Dword(2))
    ));
}

/// The real snapshot against itself (env-gated): the comparison machinery
/// agrees on every one of the 20 thousand recorded queries.
#[test]
fn real_snapshot_agrees_with_itself() {
    let path = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join("vm-lab/wsus-m0/diff-msi3/facts.json");
    let path = std::env::var_os("WSUS_INSTALL_FACTS")
        .map(Into::into)
        .unwrap_or(path);
    if !path.is_file() {
        eprintln!("SKIP: {} absent", path.display());
        return;
    }
    let (facts, _) = load_facts_file(&path).unwrap();
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let queries: Vec<Value> = doc["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let mut q = f.clone();
            q.as_object_mut().unwrap().remove("result");
            q
        })
        .collect();
    let q = parse_queries(
        &json!({"schema": "wsus-applicability-queries/1", "queries": queries}).to_string(),
    )
    .unwrap();
    let report = facts_check(&q, &facts, &facts, 5);
    eprintln!(
        "{} queries, {} disagreements",
        report.total, report.disagree
    );
    assert!(report.agrees());
    assert!(report.total > 1000);
}
