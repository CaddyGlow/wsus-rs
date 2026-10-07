//! The real catalog: 5168 stored Core fragments from a real WSUS (WS2025
//! 10.0.26100) as kept by the WUSP client. Input is read-only and found
//! through `WSUS_REAL_REVISIONS` (default
//! `~/vm-lab/wsus-m0/client-run5/state/meta/revisions`); every test is skipped
//! with a message when it is absent.
//!
//! Run with `-- --nocapture` to print the operator table and the evaluability
//! report that docs/wsus-protocol-inventory.md ("Applicability rules")
//! records.
mod applicability_common;

use std::collections::{BTreeMap, BTreeSet};

use applicability_common::{Revision, load_revisions, revisions_dir};
use wsus_protocol::applicability::expr::{Expr, UnsupportedReason};
use wsus_protocol::applicability::operators::{OPERATORS, implemented_names};
use wsus_protocol::applicability::{
    ApplicabilityRules, FakeFacts, NoFacts, QueryItem, SectionKind, Tri, required_queries,
};
use wsus_protocol::metadata::FragmentIndex;
use wsus_protocol::soap::Limits;
use wsus_protocol::soap::xml::Element;

fn rules_of(r: &Revision) -> Option<ApplicabilityRules> {
    let idx = FragmentIndex::parse(r.core_xml.as_bytes(), &Limits::default())
        .unwrap_or_else(|e| panic!("{}: {e}", r.stem));
    ApplicabilityRules::from_fragment(&idx)
}

#[test]
fn every_real_revision_parses_and_evaluates_without_panic() {
    let Some(dir) = revisions_dir() else { return };
    let revs = load_revisions(&dir);
    assert!(
        revs.len() > 5000,
        "expected the 5168 stored revisions, got {}",
        revs.len()
    );
    let world = FakeFacts::windows11_x64();
    let (mut with_rules, mut fully, mut with_unsupported, mut none) = (0, 0, 0, 0);
    let mut unsupported_names: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_section: BTreeMap<&str, usize> = BTreeMap::new();
    let (mut definite_world, mut unknown_world) = (0, 0);
    let mut blockers_world: BTreeMap<String, usize> = BTreeMap::new();
    for r in &revs {
        let Some(rules) = rules_of(r) else {
            none += 1;
            continue;
        };
        with_rules += 1;
        assert!(rules.other.is_empty(), "{}: unexpected section", r.stem);
        for (k, s) in [
            (SectionKind::IsInstalled, &rules.is_installed),
            (SectionKind::IsInstallable, &rules.is_installable),
            (SectionKind::IsSuperseded, &rules.is_superseded),
        ] {
            if s.is_some() {
                *by_section.entry(k.name()).or_default() += 1;
            }
        }
        let un = rules.unsupported();
        if un.is_empty() {
            fully += 1;
        } else {
            with_unsupported += 1;
            for u in un {
                *unsupported_names.entry(u.name.clone()).or_default() += 1;
            }
        }
        {
            let o = rules.evaluate(SectionKind::IsInstalled, &world);
            if o.value == Tri::Unknown {
                unknown_world += 1;
                for b in &o.blockers {
                    let k = match b {
                        wsus_protocol::applicability::Blocker::Unsupported { name, .. } => {
                            format!("unsupported {name}")
                        }
                        wsus_protocol::applicability::Blocker::Unavailable { reason, .. } => {
                            format!("unavailable: {reason}")
                        }
                        wsus_protocol::applicability::Blocker::Undecidable { operator, why } => {
                            format!("undecidable {operator}: {why}")
                        }
                    };
                    *blockers_world.entry(k).or_default() += 1;
                }
            } else {
                definite_world += 1;
            }
        }
        // Evaluate against nothing and against an empty Windows 11 machine.
        for kind in [SectionKind::IsInstalled, SectionKind::IsInstallable] {
            let blind = rules.evaluate(kind, &NoFacts);
            let seen = rules.evaluate(kind, &world);
            for o in [&blind, &seen] {
                assert!(
                    o.value != Tri::Unknown || !o.blockers.is_empty(),
                    "{}",
                    r.stem
                );
                assert!(
                    o.value == Tri::Unknown || o.blockers.is_empty(),
                    "{}",
                    r.stem
                );
            }
            // Knowing more never contradicts a definite blind answer.
            if blind.value != Tri::Unknown {
                assert_eq!(blind.value, seen.value, "{} {:?}", r.stem, kind);
            }
        }
    }
    let pct = |n: usize, d: usize| 100.0 * n as f64 / d as f64;
    eprintln!("revisions: {}", revs.len());
    eprintln!("without ApplicabilityRules: {none}");
    eprintln!("with rules: {with_rules}; sections: {by_section:?}");
    eprintln!(
        "no unsupported operator in any section: {fully} of {with_rules} ({:.2}% of rules, {:.2}% of all revisions)",
        pct(fully, with_rules),
        pct(fully, revs.len())
    );
    eprintln!(
        "with at least one unsupported operator: {with_unsupported} ({:.2}% of rules)",
        pct(with_unsupported, with_rules)
    );
    eprintln!("unsupported nodes by operator: {unsupported_names:?}");
    eprintln!(
        "IsInstalled against an empty closed-world Windows 11 x64 machine: {definite_world} definite, {unknown_world} unknown ({:.2}% definite of rules)",
        pct(definite_world, with_rules)
    );
    eprintln!("blockers of those unknowns (updates blocked): {blockers_world:?}");
    assert_eq!(fully + with_unsupported, with_rules);
    // Only operators the inventory documents as unsupported may appear.
    let known_unsupported: BTreeSet<&str> = OPERATORS
        .iter()
        .filter(|o| !o.implemented)
        .map(|o| o.name)
        .collect();
    for n in unsupported_names.keys() {
        assert!(
            known_unsupported.contains(n.rsplit(['.', ':']).next().unwrap()),
            "operator {n} is unsupported but not listed as unimplemented"
        );
    }
}

fn walk_names(e: &Element, depth: usize, out: &mut Vec<(String, Vec<String>, usize)>) {
    for c in e.elements() {
        let mut attrs: Vec<String> = c.attributes.iter().map(|a| a.name.local.clone()).collect();
        attrs.sort();
        out.push((c.name.local.clone(), attrs, depth));
        walk_names(c, depth + 1, out);
    }
}

/// Ranked table of every element name and attribute set under
/// `ApplicabilityRules`, across all revisions.
#[test]
fn operator_table_of_the_real_catalog() {
    let Some(dir) = revisions_dir() else { return };
    let revs = load_revisions(&dir);
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    let mut shapes: BTreeMap<(String, Vec<String>), usize> = BTreeMap::new();
    let mut updates_using: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for r in &revs {
        let idx = FragmentIndex::parse(r.core_xml.as_bytes(), &Limits::default()).unwrap();
        let Some(ar) = &idx.applicability_rules else {
            continue;
        };
        let mut all = Vec::new();
        walk_names(ar, 0, &mut all);
        for (n, attrs, _) in all {
            *names.entry(n.clone()).or_default() += 1;
            *shapes.entry((n.clone(), attrs)).or_default() += 1;
            updates_using.entry(n).or_default().insert(&r.stem);
        }
    }
    let mut ranked: Vec<_> = names.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    eprintln!("{:>7}  {:>7}  operator", "uses", "updates");
    for (n, c) in &ranked {
        eprintln!("{c:>7}  {:>7}  {n}", updates_using[*n].len());
    }
    let mut sh: Vec<_> = shapes.iter().collect();
    sh.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    eprintln!("-- attribute sets");
    for ((n, a), c) in sh {
        eprintln!("{c:>7}  {n}  {}", a.join(","));
    }
    // Every element name in the data is either a section, a logical/base/msi
    // operator in the table, a helper child, or a name the table lists.
    let table: BTreeSet<&str> = OPERATORS.iter().map(|o| o.name).collect();
    let helpers = [
        "IsInstalled",
        "IsInstallable",
        "IsSuperseded",
        "Metadata",
        "m.Product",
        "m.Feature",
        "m.Component",
    ];
    for n in names.keys() {
        let bare = n.rsplit(['.', ':']).next().unwrap();
        assert!(
            table.contains(bare) || helpers.contains(&n.as_str()),
            "element {n} is neither in the operator table nor a known helper"
        );
    }
    assert!(implemented_names().count() > 30);
}

fn all_queries(revs: &[Revision]) -> Vec<(QueryItem, Vec<String>)> {
    let mut map: BTreeMap<String, (QueryItem, Vec<String>)> = BTreeMap::new();
    for r in revs {
        let Some(rules) = rules_of(r) else { continue };
        for k in [
            SectionKind::IsInstalled,
            SectionKind::IsInstallable,
            SectionKind::IsSuperseded,
        ] {
            let Some(s) = rules.section(k) else { continue };
            for q in required_queries(&s.expr) {
                let key = format!("{:?}", q.key());
                map.entry(key)
                    .or_insert_with(|| (q, Vec::new()))
                    .1
                    .push(r.stem.clone());
            }
        }
    }
    map.into_values().collect()
}

#[test]
fn query_listing_covers_every_fact_kind_and_matches_the_python_script() {
    let Some(dir) = revisions_dir() else { return };
    let revs = load_revisions(&dir);
    let rust = all_queries(&revs);
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for (q, _) in &rust {
        let v = serde_json::to_value(q).unwrap();
        *kinds
            .entry(v["kind"].as_str().unwrap().to_owned())
            .or_default() += 1;
    }
    eprintln!("rust: {} distinct queries {kinds:?}", rust.len());
    assert!(rust.len() > 10_000);

    // Cross-check with scripts/wsus/applicability-queries.py when python3 exists.
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/wsus/applicability-queries.py");
    let out = std::env::temp_dir().join(format!("wsus-queries-{}.json", std::process::id()));
    let run = std::process::Command::new("python3")
        .arg(&script)
        .arg("--revisions")
        .arg(&dir)
        .arg("--out")
        .arg(&out)
        .output();
    let Ok(run) = run else {
        eprintln!("SKIPPED python cross-check: python3 not available");
        return;
    };
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let _ = std::fs::remove_file(&out);
    assert_eq!(doc["schema"], "wsus-applicability-queries/1");
    let py: BTreeMap<String, BTreeSet<String>> = doc["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| {
            let item: QueryItem =
                serde_json::from_value(q.clone()).unwrap_or_else(|e| panic!("{q}: {e}"));
            let users: BTreeSet<String> = q["updates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u.as_str().unwrap().to_owned())
                .collect();
            (format!("{:?}", item.key()), users)
        })
        .collect();
    let rs: BTreeMap<String, BTreeSet<String>> = rust
        .iter()
        .map(|(q, u)| (format!("{:?}", q.key()), u.iter().cloned().collect()))
        .collect();
    let only_rust: Vec<_> = rs.keys().filter(|k| !py.contains_key(*k)).take(5).collect();
    let only_py: Vec<_> = py.keys().filter(|k| !rs.contains_key(*k)).take(5).collect();
    assert!(
        only_rust.is_empty() && only_py.is_empty(),
        "rust only {only_rust:?}\npython only {only_py:?}"
    );
    assert_eq!(rs, py, "the update lists differ");
}

/// The unsupported reasons seen in the data, for the report.
#[test]
fn unsupported_reasons_in_the_real_catalog_are_documented_ones() {
    let Some(dir) = revisions_dir() else { return };
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for r in load_revisions(&dir) {
        if let Some(rules) = rules_of(&r) {
            for u in rules.unsupported() {
                let key = match &u.reason {
                    UnsupportedReason::NoSemantics(_) => format!("{}: no semantics", u.name),
                    other => format!("{}: {other}", u.name),
                };
                *reasons.entry(key).or_default() += 1;
            }
        }
    }
    eprintln!("{reasons:?}");
    // Nothing in the real data may be malformed or unknown: only operators
    // deliberately left without semantics.
    for k in reasons.keys() {
        assert!(
            k.ends_with("no semantics"),
            "unexpected unsupported reason: {k}"
        );
    }
    let _ = Expr::True;
}

/// Prints the operator table of the inventory ("Applicability rules") as
/// Markdown: counts from the real catalog next to the operator table's
/// implementation status and evidence. Run with `--nocapture` to regenerate.
#[test]
fn inventory_operator_table_markdown() {
    let Some(dir) = revisions_dir() else { return };
    let mut uses: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    for r in load_revisions(&dir) {
        let idx = FragmentIndex::parse(r.core_xml.as_bytes(), &Limits::default()).unwrap();
        let Some(ar) = &idx.applicability_rules else {
            continue;
        };
        let mut all = Vec::new();
        walk_names(ar, 0, &mut all);
        for (n, _, _) in all {
            let bare = n.rsplit(['.', ':']).next().unwrap().to_owned();
            let e = uses.entry(bare).or_default();
            e.0 += 1;
            e.1.insert(r.stem.clone());
        }
    }
    let mut rows: Vec<_> = OPERATORS.iter().collect();
    rows.sort_by_key(|o| std::cmp::Reverse(uses.get(o.name).map_or(0, |u| u.0)));
    eprintln!("| Operator | Uses | Updates | Evaluated | Semantics and evidence |");
    eprintln!("| --- | ---: | ---: | --- | --- |");
    for o in rows {
        let (u, up) = uses.get(o.name).map_or((0, 0), |u| (u.0, u.1.len()));
        let rules: Vec<String> = o
            .rules
            .iter()
            .map(|(e, t)| format!("{}: {t}", e.label()))
            .collect();
        eprintln!(
            "| `{}` | {u} | {up} | {} | {} |",
            o.name,
            if o.implemented { "yes" } else { "no (Unknown)" },
            rules.join("; ")
        );
    }
}
