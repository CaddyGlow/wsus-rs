//! MODEL-BASED regression test for `MsiProductInstalled` (present side). THIS IS NOT NATIVE
//! EVIDENCE: the native agent cannot be the oracle for these updates (every delivered
//! MSI-gated update is a Detectoid, leaf, action Evaluate, and the agent exposes installed
//! state only through the non-leaf installed list and software-update search results).
//!
//! The expectation is derived INDEPENDENTLY of the evaluator: the Windows Installer measured
//! versions of three real MSI products (built with wixl, installed on the guest; Windows
//! Installer reported state 5 and the VersionString below) and the documented rule semantics
//! (VersionMin and VersionMax inclusive, MsiApplicabilityRules page). The test extracts
//! ProductCode, VersionMin and VersionMax from the rule text with plain string handling and
//! compares integer tuples itself; it does not call the evaluator's version code.
//!
//! Inputs (read-only, skipped with a message when absent): `WSUS_MSI3_DIR` (default
//! `~/vm-lab/wsus-m0/diff-msi3`: `facts.json` after the installs and `native/scan`) and
//! `WSUS_MSI1_DIR` (default `~/vm-lab/wsus-m0/diff-msi`: `facts.json` with the same codes at
//! 1.0.0.0). Guest: Windows 11 25H2 10.0.26200 UBR 8037, Office ProPlus2024 x64 installed.
mod applicability_common;

use std::collections::BTreeMap;

use applicability_common::lenient_update_infos;
use std::path::PathBuf;

use wsus_protocol::applicability::{ApplicabilityRules, RecordedFacts, SectionKind, Tri};
use wsus_protocol::metadata::FragmentIndex;
use wsus_protocol::soap::Limits;

/// Product code -> version Windows Installer reported after the installs.
const MEASURED: [(&str, [u32; 3]); 3] = [
    ("{99EFD904-A89C-4116-91C9-80FD7FD40DA7}", [4, 2, 1338]),
    ("{574CB555-A5C9-4E08-A2CD-FC530C17AD3F}", [4, 2, 1205]),
    ("{DFF93860-2113-4207-A7AC-3901ABCE8002}", [4, 2, 1700]),
];

fn dir(env: &str, default: &str) -> Option<PathBuf> {
    let d = std::env::var_os(env).map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("vm-lab/wsus-m0").join(default))
    });
    match d {
        Some(d) if d.join("facts.json").is_file() => Some(d),
        other => {
            eprintln!("SKIPPED: {env} not found ({other:?}); see the module documentation");
            None
        }
    }
}

fn parts(v: &str) -> Vec<u32> {
    v.split('.')
        .map(|p| p.parse().expect("numeric version part"))
        .collect()
}

/// Plain padded tuple comparison, independent of the crate.
fn cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| {
            a.get(i)
                .copied()
                .unwrap_or(0)
                .cmp(&b.get(i).copied().unwrap_or(0))
        })
        .find(|o| o.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn attr<'a>(rule: &'a str, name: &str) -> Option<&'a str> {
    let i = rule.find(&format!("{name}=\""))? + name.len() + 2;
    rule[i..].split('"').next()
}

/// Branches of a rule: the `And(MsiProductInstalled, Processor)` shape, alone or inside an
/// `Or`. Returns (product code, VersionMin, VersionMax, architecture) per branch.
type Branch = (String, Option<Vec<u32>>, Option<Vec<u32>>, u32);

fn branches(rule: &str) -> Option<Vec<Branch>> {
    let body = rule
        .strip_prefix("<Or>")
        .map_or(rule, |r| r.strip_suffix("</Or>").unwrap_or(r));
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find("<And>") {
        let j = rest[i..].find("</And>")? + i;
        let b = &rest[i + 5..j];
        if b.matches("MsiProductInstalled").count() != 1 || b.matches("Processor").count() != 1 {
            return None;
        }
        let msi = &b[b.find("<m.MsiProductInstalled")?..];
        let msi = &msi[..msi.find("/>")?];
        let cpu = &b[b.find("<b.Processor")?..];
        out.push((
            attr(msi, "ProductCode")?.to_ascii_uppercase(),
            attr(msi, "VersionMin").map(parts),
            attr(msi, "VersionMax").map(parts),
            attr(cpu, "Architecture")?.parse().ok()?,
        ));
        rest = &rest[j + 6..];
    }
    // Nothing else may be in the rule: the branches account for every product element.
    (rule.matches("MsiProductInstalled").count() == out.len() && !out.is_empty()).then_some(out)
}

/// Delivered Core fragments whose rule is such a shape and mentions one of the three codes.
fn delivered(scan: &std::path::Path) -> BTreeMap<(String, u32), String> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(scan)
        .expect("scan dir")
        .filter_map(|e| e.ok())
    {
        let Ok(body) = std::fs::read(e.path().join("response.body")) else {
            continue;
        };
        // Complete UpdateInfo elements, also from truncated captured bodies.
        for u in lenient_update_infos(&body) {
            let xml = &u.xml;
            let Some(rule) = xml
                .split("<IsInstalled>")
                .nth(1)
                .and_then(|r| r.split("</IsInstalled>").next())
            else {
                continue;
            };
            let Some(bs) = branches(rule) else { continue };
            if bs.iter().any(|b| MEASURED.iter().any(|(c, _)| *c == b.0)) {
                let id = attr(xml, "UpdateID").unwrap().to_ascii_lowercase();
                let rev: u32 = attr(xml, "RevisionNumber").unwrap().parse().unwrap();
                out.insert((id, rev), xml.clone());
            }
        }
    }
    out
}

/// Expected truth: some branch whose product is installed at `version(code)` (None: not
/// installed, which the caller asserts from the facts) inside the INCLUSIVE range, with the
/// guest's architecture (9, AMD64) equal to the branch's.
fn expected(xml: &str, version: &dyn Fn(&str) -> Option<[u32; 3]>) -> bool {
    let rule = xml
        .split("<IsInstalled>")
        .nth(1)
        .unwrap()
        .split("</IsInstalled>")
        .next()
        .unwrap();
    branches(rule)
        .unwrap()
        .into_iter()
        .any(|(code, min, max, arch)| {
            let Some(v) = version(&code) else {
                return false;
            };
            let v = v.to_vec();
            arch == 9
                && min.is_none_or(|m| cmp(&v, &m).is_ge())
                && max.is_none_or(|m| cmp(&v, &m).is_le())
        })
}

fn run(
    facts_dir: &std::path::Path,
    scan: &std::path::Path,
    versions: &dyn Fn(&str) -> Option<[u32; 3]>,
) -> (usize, usize) {
    let facts =
        RecordedFacts::from_json(&std::fs::read_to_string(facts_dir.join("facts.json")).unwrap())
            .expect("facts");
    let rules = delivered(scan);
    let (mut n_true, mut n_false) = (0, 0);
    let mut per_code: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for ((id, rev), xml) in &rules {
        let rule = xml.split("<IsInstalled>").nth(1).unwrap();
        // Products without a measured version must be absent in the facts.
        for (code, ..) in branches(rule.split("</IsInstalled>").next().unwrap()).unwrap() {
            if versions(&code).is_none() {
                use wsus_protocol::applicability::{Fact, FactProvider};
                assert_eq!(
                    facts.msi_product(&code),
                    Fact::Absent,
                    "{code} should not be installed"
                );
            }
        }
        let want = expected(xml, versions);
        let idx = FragmentIndex::parse(xml.as_bytes(), &Limits::default()).unwrap();
        let got = ApplicabilityRules::from_fragment(&idx)
            .unwrap()
            .evaluate(SectionKind::IsInstalled, &facts);
        assert_eq!(got.value, Tri::from_bool(want), "{id}-r{rev}: rule {rule}");
        let code = attr(rule, "ProductCode").unwrap().to_ascii_uppercase();
        let e = per_code.entry(code).or_default();
        if want {
            n_true += 1;
            e.0 += 1;
        } else {
            n_false += 1;
            e.1 += 1;
        }
    }
    eprintln!(
        "{} delivered rules; True {n_true}, False {n_false}; by first product code (True, False): {per_code:?}",
        rules.len()
    );
    (n_true, n_false)
}

#[test]
fn model_msi_present_side_matches_windows_installer_versions_and_documented_ranges() {
    let (Some(d3), Some(d1)) = (
        dir("WSUS_MSI3_DIR", "diff-msi3"),
        dir("WSUS_MSI1_DIR", "diff-msi"),
    ) else {
        return;
    };
    use wsus_protocol::applicability::{Fact, FactProvider};
    // The collector's msi_product facts equal what Windows Installer reported (state 5).
    let facts3 =
        RecordedFacts::from_json(&std::fs::read_to_string(d3.join("facts.json")).unwrap()).unwrap();
    for (code, v) in MEASURED {
        let Fact::Known(p) = facts3.msi_product(code) else {
            panic!("{code} not collected as installed");
        };
        assert_eq!(
            p.version,
            format!("{}.{}.{}", v[0], v[1], v[2]),
            "collector version of {code}"
        );
    }
    let scan3 = d3.join("native/scan");
    let measured = |c: &str| MEASURED.iter().find(|(m, _)| *m == c).map(|(_, v)| *v);
    let (t, f) = run(&d3, &scan3, &measured);
    assert_eq!(
        t + f,
        42,
        "the 42 delivered MSI-gated detectoids of the three products"
    );
    assert!(
        t > 0 && f > 0,
        "the delivered set mixes True and False rules"
    );
    // Boundary facts of the documented semantics, derived from the delivered rules.
    let rules = delivered(&scan3);
    let rules_of = |c: &str| -> Vec<&String> {
        rules
            .values()
            .filter(|x| {
                branches(
                    x.split("<IsInstalled>")
                        .nth(1)
                        .unwrap()
                        .split("</IsInstalled>")
                        .next()
                        .unwrap(),
                )
                .unwrap()
                .iter()
                .any(|b| b.0 == c)
            })
            .collect()
    };
    // 4.2.1205 is the lower bound of every rule of its product and, for the rule whose
    // VersionMax is also 4.2.1205.0, both bounds at once (inclusive at both ends).
    let only = |c: &'static str, v: [u32; 3]| move |code: &str| (code == c).then_some(v);
    let all_1205 = rules_of(MEASURED[1].0)
        .into_iter()
        .filter(|x| expected(x, &only(MEASURED[1].0, MEASURED[1].1)))
        .count();
    let arch9_1205 = rules_of(MEASURED[1].0)
        .into_iter()
        .filter(|x| {
            branches(
                x.split("<IsInstalled>")
                    .nth(1)
                    .unwrap()
                    .split("</IsInstalled>")
                    .next()
                    .unwrap(),
            )
            .unwrap()
            .iter()
            .all(|b| b.3 == 9)
        })
        .count();
    assert_eq!(
        all_1205, arch9_1205,
        "4.2.1205 satisfies every AMD64 rule of its product"
    );
    let both = rules_of(MEASURED[1].0).into_iter().any(|x| {
        let r = x.split("<IsInstalled>").nth(1).unwrap();
        attr(r, "VersionMax") == Some("4.2.1205.0") && attr(r, "VersionMin") == Some("4.2.1205.0")
    });
    assert!(
        both,
        "a rule with VersionMin = VersionMax = 4.2.1205.0 exists"
    );
    assert_eq!(
        rules_of(MEASURED[2].0)
            .into_iter()
            .filter(|x| expected(x, &only(MEASURED[2].0, MEASURED[2].1)))
            .count(),
        0,
        "4.2.1700 satisfies no rule"
    );
    let at_1338 = rules_of(MEASURED[0].0)
        .into_iter()
        .filter(|x| {
            attr(x.split("<IsInstalled>").nth(1).unwrap(), "VersionMax") == Some("4.2.1338.0")
        })
        .count();
    assert!(
        at_1338 > 0,
        "a rule with VersionMax exactly 4.2.1338.0 exists (inclusive boundary)"
    );
    // The 1.0.0.0 state (earlier collection of the same codes): everything False.
    let (t1, f1) = run(&d1, &scan3, &|c| {
        MEASURED.iter().find(|(m, _)| *m == c).map(|_| [1, 0, 0])
    });
    assert_eq!((t1, f1), (0, 42));
}
