//! Dry-run plan of the REAL Defender bundle a2fef9b0 rev 200 against a recorded
//! facts snapshot. Nothing is executed. Env-gated like the other real tests:
//! it skips with a message when the data is absent.
//!
//! Inputs (defaults are the lab paths):
//! * `WSUS_INSTALL_REAL_META`: the client `meta` directory holding
//!   `revisions/` (default `~/vm-lab/wsus-m0/client-run5/state/meta`);
//! * `WSUS_INSTALL_FACTS`: the facts snapshot (default
//!   `~/vm-lab/wsus-m0/diff-msi3/facts.json`).
//!
//! Run with `--nocapture` to see the plan summary and the command lines.
use std::path::PathBuf;
use wsus_client::{
    install::{PlanOptions, PlanOutcome, build_plan, handlers::HandlerSpec, load_facts_file},
    sync::{Catalog, RevisionStore},
};
use wsus_protocol::{identity::UpdateRevision, soap::Limits};

fn home(rel: &str) -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rel)
}

fn env_path(name: &str, default: PathBuf) -> PathBuf {
    std::env::var_os(name).map(PathBuf::from).unwrap_or(default)
}

const ROOT: &str = "a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe@200";

fn load() -> Option<(Catalog, wsus_protocol::applicability::RecordedFacts, String)> {
    let meta = env_path(
        "WSUS_INSTALL_REAL_META",
        home("vm-lab/wsus-m0/client-run5/state/meta"),
    );
    let facts = env_path(
        "WSUS_INSTALL_FACTS",
        home("vm-lab/wsus-m0/diff-msi3/facts.json"),
    );
    if !meta.join("revisions").is_dir() || !facts.is_file() {
        eprintln!(
            "SKIP: real data absent (meta {} / facts {})",
            meta.display(),
            facts.display()
        );
        return None;
    }
    let store = RevisionStore::open_read_only(&meta).expect("open store");
    let catalog = Catalog::load(&store, &Limits::default()).expect("load catalog");
    let (facts, hash) = load_facts_file(&facts).expect("facts");
    Some((catalog, facts, hash))
}

#[test]
fn defender_bundle_dry_run_plan() {
    let Some((catalog, facts, facts_file_hash)) = load() else {
        return;
    };
    let target: UpdateRevision = ROOT.parse_rev();
    let plan = build_plan(&catalog, &facts, target, &PlanOptions::default());
    eprintln!("facts file sha256: {facts_file_hash}");
    eprintln!("plan hash: {}", plan.hash());
    eprintln!("outcome: {:?}", plan.outcome);
    eprintln!(
        "facts: {} queries, hash {}",
        plan.facts.queries, plan.facts.hash
    );
    eprintln!("decisions: {}", plan.decisions.len());
    for b in &plan.blockers {
        eprintln!("blocker x{}: {} e.g. {:?}", b.count, b.text, b.examples);
    }
    let mut by_status: std::collections::BTreeMap<String, usize> = Default::default();
    for d in &plan.decisions {
        *by_status
            .entry(format!("{} {:?}", d.role, d.status))
            .or_default() += 1;
    }
    eprintln!("decisions by role and status: {by_status:?}");
    for s in &plan.steps {
        match &s.spec {
            HandlerSpec::CommandLine(c) => eprintln!(
                "step {} {}: {} {} (payload {} {} bytes)",
                s.index,
                s.update,
                c.program,
                c.arguments.clone().unwrap_or_default(),
                s.payload.file_name,
                s.payload.size
            ),
            #[allow(unreachable_patterns)]
            other => eprintln!("step {} {other:?}", s.index),
        }
    }
    // Which fact kinds the decision path used (what a live provider must answer).
    {
        use wsus_client::install::{RecordingFacts, plan::Planner};
        let rec = RecordingFacts::new(&facts);
        let mut planner = Planner::new(&catalog, &rec, PlanOptions::default());
        let _ = planner.plan(target, &rec);
        let mut kinds: std::collections::BTreeMap<String, usize> = Default::default();
        for (k, _) in rec.lines() {
            *kinds
                .entry(k.split('|').next().unwrap_or("").to_owned())
                .or_default() += 1;
        }
        eprintln!("fact kinds used: {kinds:?}");
    }
    // Determinism: the same inputs give the same document.
    let again = build_plan(&catalog, &facts, target, &PlanOptions::default());
    assert_eq!(plan.to_json(), again.to_json());
    // Nothing was executed: planning has no side effects by construction.
    assert!(matches!(
        plan.outcome,
        PlanOutcome::Install
            | PlanOutcome::NothingToDoInstalled
            | PlanOutcome::NothingToDoNotApplicable
            | PlanOutcome::Refused
    ));
}

trait ParseRev {
    fn parse_rev(&self) -> UpdateRevision;
}
impl ParseRev for str {
    fn parse_rev(&self) -> UpdateRevision {
        let (id, rev) = self.split_once('@').unwrap();
        UpdateRevision {
            id: wsus_protocol::identity::UpdateId(id.parse().unwrap()),
            revision: wsus_protocol::identity::Revision(rev.parse().unwrap()),
        }
    }
}

/// Every real Extended fragment that declares a handler parses into a typed
/// command-line spec whose program is the update's own single file (the schema
/// the inventory documents), or is reported.
#[test]
fn every_real_handler_spec_parses() {
    use wsus_client::install::handlers::read_handler_info;
    let Some((catalog, _, _)) = load() else {
        return;
    };
    let (mut ok, mut bad) = (0usize, Vec::new());
    let mut shapes: std::collections::BTreeMap<String, usize> = Default::default();
    for rev in catalog.revisions() {
        let entry = catalog.get(rev).unwrap();
        let Some(f) = entry.record.fragments.iter().find(|f| f.kind == "Extended") else {
            continue;
        };
        let info = read_handler_info(&f.xml).unwrap();
        if !info.is_present() {
            continue;
        }
        match info.command_line() {
            Ok(spec) => {
                let files = entry.files();
                let names: Vec<_> = files
                    .iter()
                    .filter_map(|x| x.file_name.as_deref())
                    .collect();
                if names.len() == 1 && names[0].eq_ignore_ascii_case(&spec.program) {
                    ok += 1;
                    let key = format!(
                        "args={:?} codes={:?}",
                        spec.arguments
                            .as_deref()
                            .map(|a| a.split(' ').next().unwrap_or("")),
                        spec.return_codes
                            .iter()
                            .map(|r| (r.code, r.result, r.reboot))
                            .collect::<Vec<_>>()
                    );
                    *shapes.entry(key).or_default() += 1;
                } else {
                    bad.push(format!(
                        "{rev}: program/file mismatch {names:?} vs {}",
                        spec.program
                    ));
                }
            }
            Err(e) => bad.push(format!("{rev}: {e}")),
        }
    }
    eprintln!("{ok} specs parsed, {} problems", bad.len());
    for (k, v) in &shapes {
        eprintln!("  {v:5} {k}");
    }
    for b in bad.iter().take(10) {
        eprintln!("  PROBLEM {b}");
    }
    assert!(bad.is_empty(), "{bad:?}");
}
