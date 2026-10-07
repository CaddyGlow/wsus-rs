//! Leaf-level differential: our applicability verdicts against the ground truth of the
//! native Windows Update Agent's COM search on the same guest state.
//!
//! Candidates are the LEAF updates the native scan delivered with deployment action
//! `Install` (parsed from the decoded `SyncUpdates` responses) plus every identity in
//! `search2.json`'s `installed` list. Updates are identified by `UpdateID` +
//! `RevisionNumber` taken from their Core fragments, NEVER by server-local ids.
//! Core fragments come from the native responses first, then from the stored catalog
//! (`WSUS_REAL_REVISIONS`), also by identity.
//!
//! Ground truth (`search2.json`): `installed` = `Search("IsInstalled=1")`, `found` =
//! `Search("IsInstalled=0 and IsHidden=0")`. For each candidate we evaluate
//! `IsInstalled`, `IsInstallable` and an `applicable` prediction:
//! `(IsInstallable True or absent) AND IsInstalled False AND every prerequisite clause
//! satisfied AND not superseded`, where
//!
//! * a prerequisite clause (an `AtLeastOne` OR, `IsCategory` included, or a bare
//!   identity) is satisfied when some alternative update's `IsInstalled` evaluates True;
//!   the alternative is the highest revision known for that update id; no deeper chain
//!   is followed (Kleene logic: Unknown alternatives make the clause Unknown);
//! * SUPERSEDENCE ASSUMPTION (Implementation decision, Unverified): an update is
//!   superseded when some other known update lists it in `SupersededUpdates` and that
//!   superseding update's `IsInstalled` evaluates True on this machine. Nothing else
//!   (no deployment, no revision-expiry state) is considered.
//!
//! HOW TO RUN:
//! ```text
//! D=~/vm-lab/wsus-m0/diff-leaf
//! WSUS_FACTS_JSON=$D/facts.json WSUS_SEARCH_JSON=$D/search2.json \
//!   WSUS_NATIVE_FIXTURES=$D/native WSUS_NATIVE_SETS=scan \
//!   WSUS_REAL_REVISIONS=~/vm-lab/wsus-m0/client-run6/state/meta/revisions \
//!   cargo test -p wsus-protocol --test applicability_leaf_differential -- --ignored --nocapture
//! ```
//! Optional: `WSUS_DIFF_REPORT` (JSON report path).
mod applicability_common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use applicability_common::{lenient_update_infos, load_revisions, revisions_dir};
use wsus_protocol::applicability::expr::{Expr, Operator};
use wsus_protocol::applicability::{
    ApplicabilityRules, FactProvider, RecordedFacts, SectionKind, Tri,
};
use wsus_protocol::metadata::FragmentIndex;
use wsus_protocol::soap::Limits;

type Ident = (String, u32);

#[derive(Clone)]
struct Known {
    ident: Ident,
    xml: String,
    /// Native delivery facts (None for catalog-only updates).
    leaf_install: bool,
    delivered: bool,
}

struct Catalog {
    by_ident: BTreeMap<Ident, Known>,
}

impl Catalog {
    fn new() -> Self {
        Self {
            by_ident: BTreeMap::new(),
        }
    }

    fn add(&mut self, k: Known) {
        match self.by_ident.get_mut(&k.ident) {
            Some(old) => {
                // Native delivery info wins; the XML is the same revision either way.
                old.leaf_install |= k.leaf_install;
                old.delivered |= k.delivered;
            }
            None => {
                self.by_ident.insert(k.ident.clone(), k);
            }
        }
    }

    fn latest(&self, id: &str) -> Option<&Known> {
        self.by_ident
            .range((id.to_owned(), 0)..=(id.to_owned(), u32::MAX))
            .next_back()
            .map(|(_, v)| v)
    }
}

fn ident_of(xml: &str) -> Option<(Ident, FragmentIndex)> {
    let idx = FragmentIndex::parse(xml.as_bytes(), &Limits::default()).ok()?;
    let i = idx.identity?;
    Some(((i.id.0.hyphenated().to_string(), i.revision.0), idx))
}

fn load_native(dir: &Path, sets: &[String], cat: &mut Catalog) {
    for set in sets {
        let Ok(rd) = std::fs::read_dir(dir.join(set)) else {
            continue;
        };
        let mut names: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        names.sort();
        for n in names {
            let Ok(body) = std::fs::read(n.join("response.body")) else {
                continue;
            };
            // Complete UpdateInfo elements, also from truncated captured bodies.
            for u in lenient_update_infos(&body) {
                let Some((ident, _)) = ident_of(&u.xml) else {
                    continue;
                };
                let install = u.action.as_deref() == Some("Install");
                cat.add(Known {
                    ident,
                    xml: u.xml,
                    leaf_install: u.is_leaf && install,
                    delivered: true,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Disagree,
    Agree,
    Unknown,
}

#[derive(Debug, Clone)]
struct Row {
    ident: Ident,
    title: String,
    native: &'static str, // installed | not-installed
    is_installed: Tri,
    is_installable: Option<Tri>,
    prereq: Tri,
    superseded: Tri,
    applicable: Tri,
    installed_verdict: Verdict,
    applicable_verdict: Verdict,
    ops: BTreeSet<String>,
    blockers: Vec<String>,
}

fn op_names(e: &Expr, out: &mut BTreeSet<String>) {
    match e {
        Expr::And(v) | Expr::Or(v) => v.iter().for_each(|x| op_names(x, out)),
        Expr::Not(x) => op_names(x, out),
        Expr::RegKeyLoop(l) => {
            out.insert("RegKeyLoop".into());
            op_names(&l.body, out);
        }
        Expr::Op(o) => {
            let n = format!("{o:?}");
            let n = n.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("");
            out.insert(n.to_owned());
            let _ = Operator::MuiInstalled;
        }
        Expr::Unsupported(u) => {
            out.insert(format!("unsupported:{}", u.name));
        }
        Expr::True => {
            out.insert("True".into());
        }
        Expr::False => {
            out.insert("False".into());
        }
    }
}

fn eval_section(
    xml: &str,
    kind: SectionKind,
    facts: &dyn FactProvider,
) -> Option<wsus_protocol::applicability::Outcome> {
    let idx = FragmentIndex::parse(xml.as_bytes(), &Limits::default()).ok()?;
    let rules = ApplicabilityRules::from_fragment(&idx)?;
    rules.section(kind)?;
    Some(rules.evaluate(kind, facts))
}

/// Section verdict of an update. An update with its own rule section is evaluated
/// directly. An update WITHOUT one that has `BundledUpdates` (the Office "client update"
/// bundles: no rules of their own, the rules live in the bundled revision) takes the
/// verdict of its bundle: AND over the bundle clauses of the alternative revisions'
/// verdicts, where a clause whose alternatives disagree is Unknown (Implementation
/// decision, Unverified; a bundled revision missing
/// from the catalog is Unknown, a bundled revision without the section counts as True for
/// `IsInstallable` and Unknown for `IsInstalled`). Returns the verdict, the blockers and
/// the operator names that took part.
fn section_of(
    cat: &Catalog,
    k: &Known,
    kind: SectionKind,
    facts: &dyn FactProvider,
    depth: usize,
    ops: &mut BTreeSet<String>,
) -> (Tri, Vec<String>) {
    let Some((_, idx)) = ident_of(&k.xml) else {
        return (Tri::Unknown, vec!["unparsable fragment".into()]);
    };
    if let Some(rules) = ApplicabilityRules::from_fragment(&idx)
        && let Some(sec) = rules.section(kind)
    {
        op_names(&sec.expr, ops);
        let o = rules.evaluate(kind, facts);
        return (
            o.value,
            o.blockers.iter().map(ToString::to_string).collect(),
        );
    }
    if idx.bundled.is_empty() || depth >= 3 {
        return match kind {
            SectionKind::IsInstallable => (Tri::True, vec![]),
            _ => (Tri::Unknown, vec![format!("no {} rule", kind.name())]),
        };
    }
    let mut all = Tri::True;
    let mut blockers = Vec::new();
    for clause in &idx.bundled {
        let mut vals = Vec::new();
        for rev in &clause.revisions {
            let key = (rev.id.0.hyphenated().to_string(), rev.revision.0);
            let (t, b) = match cat.by_ident.get(&key) {
                Some(child) => section_of(cat, child, kind, facts, depth + 1, ops),
                None => (
                    Tri::Unknown,
                    vec![format!(
                        "bundled revision {}-r{} not in the catalog",
                        key.0, key.1
                    )],
                ),
            };
            if std::env::var("WSUS_DEBUG_BUNDLE").as_deref() == Ok(k.ident.0.as_str()) {
                eprintln!(
                    "  bundle {} {:?} child {}-r{} -> {t:?} {b:?}",
                    k.ident.0, kind, key.0, key.1
                );
            }
            vals.push(t);
            if t == Tri::Unknown {
                blockers.extend(b);
            }
        }
        // What an `AtLeastOne` clause means for the INSTALLED state of the bundle is not
        // established: the Defender bundle (248 alternatives, mixed True and False) is
        // not installed for the native agent while "any alternative installed" would give
        // True, so mixed clauses are Unknown; clauses whose alternatives agree take that value.
        let any = if vals.iter().all(|v| *v == Tri::True) {
            Tri::True
        } else if vals.iter().all(|v| *v == Tri::False) {
            Tri::False
        } else {
            blockers.push(format!(
                "bundle clause of {} alternatives has mixed verdicts; its meaning is unverified",
                vals.len()
            ));
            Tri::Unknown
        };
        all = all.and(any);
    }
    if all != Tri::Unknown {
        blockers.clear();
    }
    blockers.dedup();
    (all, blockers)
}

fn installed_of(
    cat: &Catalog,
    id: &str,
    facts: &dyn FactProvider,
    memo: &mut BTreeMap<String, Tri>,
) -> Tri {
    if let Some(t) = memo.get(id) {
        return *t;
    }
    let t = match cat.latest(id) {
        None => Tri::Unknown,
        Some(k) => {
            eval_section(&k.xml, SectionKind::IsInstalled, facts).map_or(Tri::Unknown, |o| o.value)
        }
    };
    memo.insert(id.to_owned(), t);
    t
}

struct Report {
    rows: Vec<Row>,
    native_found: usize,
    unresolved_installed: Vec<Ident>,
}

fn run(
    cat: &Catalog,
    facts: &dyn FactProvider,
    installed: &BTreeMap<Ident, String>,
    found: &BTreeSet<Ident>,
) -> Report {
    // Who supersedes whom (by update id), over the whole catalog.
    let mut superseded_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for k in cat.by_ident.values() {
        if let Some((_, idx)) = ident_of(&k.xml) {
            for s in &idx.superseded {
                superseded_by
                    .entry(s.0.hyphenated().to_string())
                    .or_default()
                    .insert(k.ident.0.clone());
            }
        }
    }
    let mut cands: BTreeSet<Ident> = cat
        .by_ident
        .values()
        .filter(|k| k.leaf_install)
        .map(|k| k.ident.clone())
        .collect();
    let mut unresolved = Vec::new();
    for i in installed.keys().chain(found.iter()) {
        if cat.by_ident.contains_key(i) {
            cands.insert(i.clone());
        } else {
            unresolved.push(i.clone());
        }
    }
    let mut memo = BTreeMap::new();
    let mut rows = Vec::new();
    for ident in cands {
        let k = &cat.by_ident[&ident];
        let (_, idx) = ident_of(&k.xml).expect("candidate parses");
        let mut ops = BTreeSet::new();
        let (is_installed, mut blockers) =
            section_of(cat, k, SectionKind::IsInstalled, facts, 0, &mut ops);
        let (installable_v, b2) = section_of(
            cat,
            k,
            SectionKind::IsInstallable,
            facts,
            0,
            &mut BTreeSet::new(),
        );
        blockers.extend(b2);
        let able = Some(installable_v);
        // Prerequisites: AND of clauses, each an OR of alternatives' IsInstalled.
        let mut prereq = Tri::True;
        for c in &idx.prerequisites {
            let mut clause = Tri::False;
            for a in &c.update_ids {
                clause = clause.or(installed_of(
                    cat,
                    &a.0.hyphenated().to_string(),
                    facts,
                    &mut memo,
                ));
            }
            prereq = prereq.and(clause);
        }
        // Supersedence assumption (see module docs).
        let mut superseded = Tri::False;
        for by in superseded_by.get(&ident.0).into_iter().flatten() {
            if *by != ident.0 {
                superseded = superseded.or(installed_of(cat, by, facts, &mut memo));
            }
        }
        let installable = installable_v;
        let applicable = installable.and(!is_installed).and(prereq).and(!superseded);
        let native = if installed.contains_key(&ident) {
            "installed"
        } else {
            "not-installed"
        };
        let installed_verdict = match (native, is_installed) {
            (_, Tri::Unknown) => Verdict::Unknown,
            ("installed", Tri::True) | ("not-installed", Tri::False) => Verdict::Agree,
            _ => Verdict::Disagree,
        };
        // Native found nothing: any definite True prediction is a disagreement; an
        // installed update is not "found" either.
        let applicable_verdict = match applicable {
            Tri::Unknown => Verdict::Unknown,
            Tri::False => Verdict::Agree,
            Tri::True => {
                if found.contains(&ident) {
                    Verdict::Agree
                } else {
                    Verdict::Disagree
                }
            }
        };
        blockers.dedup();
        rows.push(Row {
            title: installed.get(&ident).cloned().unwrap_or_default(),
            ident,
            native,
            is_installed,
            is_installable: able,
            prereq,
            superseded,
            applicable,
            installed_verdict,
            applicable_verdict,
            ops,
            blockers,
        });
    }
    Report {
        rows,
        native_found: found.len(),
        unresolved_installed: unresolved,
    }
}

impl Report {
    fn print(&self) {
        let mut rows: Vec<&Row> = self.rows.iter().collect();
        rows.sort_by_key(|r| {
            (
                r.installed_verdict.min(r.applicable_verdict),
                r.native,
                r.ident.clone(),
            )
        });
        eprintln!(
            "{:<12} {:<13} {:<7} {:<7} {:<7} {:<7} {:<7} {:<9} update",
            "verdict", "native", "inst", "able", "prereq", "super", "applic", "ops"
        );
        for r in rows {
            let v = if r.installed_verdict == Verdict::Disagree
                || r.applicable_verdict == Verdict::Disagree
            {
                "DISAGREE"
            } else if r.installed_verdict == Verdict::Unknown
                || r.applicable_verdict == Verdict::Unknown
            {
                "unknown"
            } else {
                "agree"
            };
            eprintln!(
                "{v:<12} {:<13} {:<7} {:<7} {:<7} {:<7} {:<7} {} {}-r{} {}{}",
                r.native,
                format!("{:?}", r.is_installed),
                r.is_installable
                    .map_or("absent".into(), |t| format!("{t:?}")),
                format!("{:?}", r.prereq),
                format!("{:?}", r.superseded),
                format!("{:?}", r.applicable),
                r.ops.iter().cloned().collect::<Vec<_>>().join(","),
                r.ident.0,
                r.ident.1,
                r.title,
                if r.blockers.is_empty() {
                    String::new()
                } else {
                    format!(" blockers: {}", r.blockers.join("; "))
                }
            );
        }
        let n = |f: &dyn Fn(&Row) -> bool| self.rows.iter().filter(|r| f(r)).count();
        let inst = |r: &Row| r.native == "installed";
        eprintln!(
            "native installed resolved {} (unresolved {:?}); candidates {}; native found {}",
            n(&inst),
            self.unresolved_installed,
            self.rows.len(),
            self.native_found
        );
        eprintln!(
            "IsInstalled vs native installed: agree {} / disagree {} / unknown {} (installed: True {}, other {}; not installed: False {}, other {})",
            n(&|r| r.installed_verdict == Verdict::Agree),
            n(&|r| r.installed_verdict == Verdict::Disagree),
            n(&|r| r.installed_verdict == Verdict::Unknown),
            n(&|r| inst(r) && r.is_installed == Tri::True),
            n(&|r| inst(r) && r.is_installed != Tri::True),
            n(&|r| !inst(r) && r.is_installed == Tri::False),
            n(&|r| !inst(r) && r.is_installed != Tri::False),
        );
        eprintln!(
            "applicable prediction vs native found: agree {} / disagree {} / unknown {}",
            n(&|r| r.applicable_verdict == Verdict::Agree),
            n(&|r| r.applicable_verdict == Verdict::Disagree),
            n(&|r| r.applicable_verdict == Verdict::Unknown),
        );
        let ni: Vec<&Row> = self.rows.iter().filter(|r| !inst(r)).collect();
        eprintln!(
            "not installed, not found ({}): IsInstalled False {}, IsInstallable False {}, IsInstallable absent {}, IsInstallable True {}, prerequisites False {}, superseded True {}",
            ni.len(),
            ni.iter().filter(|r| r.is_installed == Tri::False).count(),
            ni.iter()
                .filter(|r| r.is_installable == Some(Tri::False))
                .count(),
            ni.iter().filter(|r| r.is_installable.is_none()).count(),
            ni.iter()
                .filter(|r| r.is_installable == Some(Tri::True))
                .count(),
            ni.iter().filter(|r| r.prereq == Tri::False).count(),
            ni.iter().filter(|r| r.superseded == Tri::True).count(),
        );
        let mut by_group: BTreeMap<(&str, String), usize> = BTreeMap::new();
        for r in &self.rows {
            for o in &r.ops {
                *by_group.entry((r.native, o.clone())).or_default() += 1;
            }
        }
        eprintln!("operators in IsInstalled rules (native class, operator, updates):");
        for ((c, o), k) in by_group {
            eprintln!("  {c:<14} {o:<34} {k}");
        }
    }

    fn disagreements(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| {
                r.installed_verdict == Verdict::Disagree
                    || r.applicable_verdict == Verdict::Disagree
            })
            .count()
    }

    fn to_json(&self) -> String {
        let rows: Vec<_> = self
            .rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "update_id": r.ident.0, "revision": r.ident.1, "title": r.title,
                    "native": r.native, "is_installed": format!("{:?}", r.is_installed),
                    "is_installable": r.is_installable.map(|t| format!("{t:?}")),
                    "prerequisites": format!("{:?}", r.prereq), "superseded": format!("{:?}", r.superseded),
                    "applicable": format!("{:?}", r.applicable),
                    "installed_verdict": format!("{:?}", r.installed_verdict),
                    "applicable_verdict": format!("{:?}", r.applicable_verdict),
                    "operators": r.ops, "blockers": r.blockers,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({"rows": rows})).unwrap()
    }
}

// ---------------------------------------------------------------------------

fn core(id: &str, rev: u32, pre: &str, sup: &str, rules: &str) -> String {
    format!(
        "<UpdateIdentity UpdateID=\"{id}\" RevisionNumber=\"{rev}\" /><Properties UpdateType=\"Software\" /><Relationships>{pre}{sup}</Relationships><ApplicabilityRules>{rules}</ApplicabilityRules>"
    )
}

#[test]
fn harness_predicts_applicability_from_installed_installable_prerequisites_and_supersedence() {
    use wsus_protocol::applicability::FakeFacts;
    let g = |n: u32| format!("bbbbbbbb-0000-4000-8000-{n:012}");
    let t = "<IsInstalled><True/></IsInstalled>";
    let f = "<IsInstalled><False/></IsInstalled>";
    let able_f = "<IsInstallable><False/></IsInstallable>";
    let unk = "<IsInstalled><b.WmiQuery WqlQuery=\"select 1\"/></IsInstalled>";
    let pre = |p: u32| {
        format!(
            "<Prerequisites><AtLeastOne><UpdateIdentity UpdateID=\"{}\"/></AtLeastOne></Prerequisites>",
            g(p)
        )
    };
    let mut cat = Catalog::new();
    let mut add = |n: u32, xml: String, leaf: bool| {
        cat.add(Known {
            ident: (g(n), 100),
            xml,
            leaf_install: leaf,
            delivered: true,
        });
    };
    add(1, core(&g(1), 100, "", "", t), true); // installed, True
    add(2, core(&g(2), 100, "", "", f), true); // not installed, False; prerequisite-less: applicable -> disagreement with found=empty
    add(3, core(&g(3), 100, "", "", &format!("{f}{able_f}")), true); // not installable: not applicable
    add(4, core(&g(4), 100, &pre(9), "", f), true); // prerequisite missing from the catalog: Unknown
    add(5, core(&g(5), 100, &pre(1), "", f), true); // prerequisite installed: applicable
    add(
        6,
        core(
            &g(6),
            100,
            "",
            &format!(
                "<SupersededUpdates><UpdateIdentity UpdateID=\"{}\"/></SupersededUpdates>",
                g(7)
            ),
            t,
        ),
        false,
    );
    add(7, core(&g(7), 100, "", "", f), true); // superseded by installed 6: not applicable
    add(8, core(&g(8), 100, "", "", unk), true);
    let installed: BTreeMap<Ident, String> = [((g(1), 100), "one".to_owned())].into();
    let rep = run(
        &cat,
        &FakeFacts::windows11_x64(),
        &installed,
        &BTreeSet::new(),
    );
    let r = |n: u32| rep.rows.iter().find(|r| r.ident.0 == g(n)).unwrap();
    assert_eq!(r(1).installed_verdict, Verdict::Agree);
    assert_eq!(r(1).applicable, Tri::False);
    assert_eq!(r(2).applicable, Tri::True);
    assert_eq!(
        r(2).applicable_verdict,
        Verdict::Disagree,
        "predicted applicable, native found nothing"
    );
    assert_eq!(r(3).applicable, Tri::False);
    assert_eq!(r(4).prereq, Tri::Unknown);
    assert_eq!(
        r(4).applicable_verdict,
        Verdict::Unknown,
        "Unknown is never agreement"
    );
    assert_eq!(r(5).applicable, Tri::True);
    assert_eq!(r(7).superseded, Tri::True);
    assert_eq!(r(7).applicable, Tri::False);
    assert_eq!(r(8).installed_verdict, Verdict::Unknown);
    assert_eq!(rep.disagreements(), 2);
    rep.print();
}

#[test]
#[ignore = "needs WSUS_FACTS_JSON, WSUS_SEARCH_JSON and the native scan of the same guest state"]
fn leaf_differential_against_the_native_search() {
    let need = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("set {k} (see the module documentation for the command)"))
    };
    let facts = RecordedFacts::from_json(
        &std::fs::read_to_string(need("WSUS_FACTS_JSON")).expect("read facts"),
    )
    .unwrap_or_else(|e| panic!("facts.json: {e}"));
    eprintln!(
        "facts: {} queries, collected {}",
        facts.len(),
        facts.collected_at()
    );
    let raw = std::fs::read(need("WSUS_SEARCH_JSON")).expect("read search json");
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
    let search: serde_json::Value = serde_json::from_slice(raw).expect("search json");
    let list = |k: &str| -> Vec<(Ident, String)> {
        search[k]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|u| {
                        (
                            (
                                u["id"].as_str().unwrap().to_ascii_lowercase(),
                                u["rev"].as_u64().unwrap() as u32,
                            ),
                            u["title"].as_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let installed: BTreeMap<Ident, String> = list("installed").into_iter().collect();
    let found: BTreeSet<Ident> = list("found").into_iter().map(|(i, _)| i).collect();
    let sets: Vec<String> = std::env::var("WSUS_NATIVE_SETS")
        .unwrap_or_else(|_| "scan".into())
        .split(',')
        .map(str::to_owned)
        .collect();
    let mut cat = Catalog::new();
    load_native(&need("WSUS_NATIVE_FIXTURES"), &sets, &mut cat);
    let delivered = cat.by_ident.len();
    if let Some(dir) = revisions_dir() {
        for r in load_revisions(&dir) {
            if let Some((ident, _)) = ident_of(&r.core_xml) {
                cat.add(Known {
                    ident,
                    xml: r.core_xml,
                    leaf_install: false,
                    delivered: false,
                });
            }
        }
    }
    // Extra stored revision directories (colon separated) for bundled children that the
    // main catalog lacks, for example the Defender children kept by an earlier sync.
    for dir in std::env::var("WSUS_EXTRA_REVISIONS")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
    {
        for r in load_revisions(Path::new(dir)) {
            if let Some((ident, _)) = ident_of(&r.core_xml) {
                cat.add(Known {
                    ident,
                    xml: r.core_xml,
                    leaf_install: false,
                    delivered: false,
                });
            }
        }
    }
    eprintln!(
        "catalog: {} identities ({delivered} delivered by the native scan); search: installed {}, found {}",
        cat.by_ident.len(),
        installed.len(),
        found.len()
    );
    let rep = run(&cat, &facts, &installed, &found);
    rep.print();
    if let Some(p) = std::env::var_os("WSUS_DIFF_REPORT") {
        std::fs::write(p, rep.to_json()).expect("write report");
    }
    assert!(
        rep.unresolved_installed.is_empty(),
        "installed identities missing from the catalog: {:?}",
        rep.unresolved_installed
    );
    assert_eq!(rep.disagreements(), 0, "see the table above");
}
