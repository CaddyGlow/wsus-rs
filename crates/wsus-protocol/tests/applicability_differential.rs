//! Differential test: our `IsInstalled` verdicts against what a NATIVE Windows
//! Update Agent reported as installed.
//!
//! The native client sends, in each `SyncUpdates` request, the server-local
//! revision ids it evaluated as installed (`InstalledNonLeafUpdateIDs`) and the
//! other ids it cached (`OtherCachedUpdateIDs`). Server-local ids are valid only
//! within one capture: this test maps them to update identities ONLY through the
//! updates (with their Core fragments) delivered in the responses of the same
//! capture set (the stored revisions number the same updates differently; use
//! `WSUS_DIFF_TRUST_STORED_IDS=1` to add them anyway), evaluates `IsInstalled` of every candidate with
//! facts recorded on the guest (`WSUS_FACTS_JSON`, written by
//! `scripts/wsus/collect-facts.ps1`), and reports per update:
//!
//! * `agree`: the native client reported the id installed and we say True
//!   (strong), or the native client cached the id without reporting it
//!   installed and we say False (weak: the client may simply not have
//!   evaluated it);
//! * `disagree`: the native client reported the id installed and we say
//!   False (the only disagreement that is certain);
//! * `unknown`: our answer is Unknown and the native client reported the id
//!   installed (never counted as agreement);
//! * `not-comparable`: the id is in neither list, a LEAF the client cached (it
//!   lists only non-leaf ids as installed), or a non-leaf the client cached
//!   without reporting it installed while we say True or Unknown. The
//!   last case is listed as `suspect` in the report: the client evaluates an
//!   update once, possibly before its prerequisites were installed, so
//!   "cached, not installed" is not proof of a False verdict (observed: the
//!   category with `IsInstalled` = True of server-local id 66 sits in
//!   `OtherCachedUpdateIDs` although its prerequisite was installed).
//!
//! HOW TO RUN (see also docs/wsus-validation.md):
//!
//! ```text
//! WSUS_FACTS_JSON=/path/to/facts.json \
//!   cargo test -p wsus-protocol --test applicability_differential -- --ignored --nocapture
//! ```
//!
//! Optional: `WSUS_REAL_REVISIONS` (stored revisions), `WSUS_NATIVE_REQUESTS`
//! (comma separated `set/NNNNNN` requests whose lists are united; default
//! `flow/000013`), `WSUS_NATIVE_FIXTURES` (default `docs/fixtures/wsus-m0-native`),
//! `WSUS_DIFF_SCOPE` (`nonleaf`, the default, or `all`), `WSUS_DIFF_REPORT`
//! (JSON report path, default in the temp directory).
//!
//! Caveats that the numbers inherit: the facts come from one guest at one time
//! and the native reports from an earlier run on that guest; the stored
//! revisions cover only server-local ids up to about 34000 while the native
//! lists reach 200996, so most reported ids cannot be resolved.
mod applicability_common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use applicability_common::{Revision, lenient_update_infos, load_revisions, revisions_dir};
use wsus_protocol::applicability::{
    ApplicabilityRules, FactProvider, RecordedFacts, SectionKind, Tri,
};
use wsus_protocol::metadata::FragmentIndex;
use wsus_protocol::soap::{Limits, decode_request};
use wsus_protocol::wusp::SyncUpdates;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Native {
    /// In `InstalledNonLeafUpdateIDs`.
    Installed,
    /// In `OtherCachedUpdateIDs`: not reported installed (not installed, or
    /// not evaluated).
    CachedNotReported,
    /// In neither list.
    NotInList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Verdict {
    Disagree,
    Agree,
    Unknown,
    NotComparable,
}

#[derive(Debug, Clone)]
struct Entry {
    server_id: i64,
    update: String,
    revision: u32,
    kind: String,
    leaf: bool,
    origin: &'static str,
    native: Native,
    ours: Tri,
    blockers: Vec<String>,
    verdict: Verdict,
    /// Agreement that rests on the native client's silence.
    weak: bool,
    /// Cached by the native client, not reported installed, while we say
    /// True or Unknown.
    suspect: bool,
}

#[derive(Debug, Default)]
struct Report {
    entries: Vec<Entry>,
    reported_installed: usize,
    resolved_installed: usize,
    unresolved_installed: Vec<i64>,
}

impl Report {
    fn count(&self, v: Verdict) -> usize {
        self.entries.iter().filter(|e| e.verdict == v).count()
    }

    fn print(&self) {
        let mut sorted: Vec<&Entry> = self.entries.iter().collect();
        sorted.sort_by_key(|e| (e.verdict, e.server_id));
        eprintln!(
            "native reported {} installed ids; {} resolved to an update identity, {} unresolved",
            self.reported_installed,
            self.resolved_installed,
            self.unresolved_installed.len()
        );
        for e in &sorted {
            eprintln!(
                "{:<14} id {:>7} {} r{} {} leaf={} [{}] native={:?} ours={:?}{}{}",
                format!("{:?}{}", e.verdict, if e.weak { "(weak)" } else { "" }),
                e.server_id,
                e.update,
                e.revision,
                e.kind,
                e.leaf,
                e.origin,
                e.native,
                e.ours,
                if e.suspect { " SUSPECT" } else { "" },
                if e.blockers.is_empty() {
                    String::new()
                } else {
                    format!(" blockers: {}", e.blockers.join("; "))
                }
            );
        }
        eprintln!(
            "SUMMARY candidates {}: agree {} (weak {}), disagree {}, unknown {}, not-comparable {} (suspect {})",
            self.entries.len(),
            self.count(Verdict::Agree),
            self.entries.iter().filter(|e| e.weak).count(),
            self.count(Verdict::Disagree),
            self.count(Verdict::Unknown),
            self.count(Verdict::NotComparable),
            self.entries.iter().filter(|e| e.suspect).count()
        );
    }

    fn to_json(&self) -> String {
        let rows: Vec<_> = self
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "server_id": e.server_id,
                    "update_id": e.update,
                    "revision": e.revision,
                    "update_type": e.kind,
                    "is_leaf": e.leaf,
                    "origin": e.origin,
                    "native": format!("{:?}", e.native),
                    "ours": format!("{:?}", e.ours),
                    "verdict": format!("{:?}", e.verdict),
                    "weak": e.weak,
                    "suspect": e.suspect,
                    "blockers": e.blockers,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "reported_installed": self.reported_installed,
            "resolved_installed": self.resolved_installed,
            "unresolved_installed": self.unresolved_installed,
            "agree": self.count(Verdict::Agree),
            "disagree": self.count(Verdict::Disagree),
            "unknown": self.count(Verdict::Unknown),
            "not_comparable": self.count(Verdict::NotComparable),
            "entries": rows,
        }))
        .unwrap()
    }
}

struct Source<'a> {
    rev: &'a Revision,
    origin: &'static str,
}

/// Core of the comparison; no I/O.
fn run_differential(
    sources: &[Source<'_>],
    facts: &dyn FactProvider,
    installed: &BTreeSet<i64>,
    other: &BTreeSet<i64>,
    all_scope: bool,
) -> Report {
    let mut by_id: BTreeMap<i64, &Source<'_>> = BTreeMap::new();
    for s in sources {
        by_id.entry(s.rev.server_id).or_insert(s);
    }
    let mut rep = Report {
        reported_installed: installed.len(),
        resolved_installed: installed.iter().filter(|i| by_id.contains_key(i)).count(),
        unresolved_installed: installed
            .iter()
            .filter(|i| !by_id.contains_key(i))
            .copied()
            .collect(),
        ..Report::default()
    };
    let limits = Limits::default();
    for (&id, s) in &by_id {
        let r = s.rev;
        let in_installed = installed.contains(&id);
        if !(all_scope || !r.is_leaf || in_installed) {
            continue;
        }
        let idx = FragmentIndex::parse(r.core_xml.as_bytes(), &limits)
            .unwrap_or_else(|e| panic!("{}: {e}", r.stem));
        let native = if in_installed {
            Native::Installed
        } else if other.contains(&id) {
            Native::CachedNotReported
        } else {
            Native::NotInList
        };
        let (ours, blockers) = match ApplicabilityRules::from_fragment(&idx) {
            Some(rules) => {
                let o = rules.evaluate(SectionKind::IsInstalled, facts);
                (
                    o.value,
                    o.blockers.iter().map(ToString::to_string).collect(),
                )
            }
            None => (
                Tri::Unknown,
                vec!["no ApplicabilityRules in the fragment".to_owned()],
            ),
        };
        let (verdict, weak, suspect) = match (native, ours) {
            (Native::NotInList, _) => (Verdict::NotComparable, false, false),
            (Native::Installed, Tri::Unknown) => (Verdict::Unknown, false, false),
            (Native::Installed, Tri::True) => (Verdict::Agree, false, false),
            (Native::Installed, Tri::False) => (Verdict::Disagree, false, false),
            // Observed (scan/000054: of 1,000+ delivered leaves, 191 evaluate True and
            // none is reported installed): the client lists only non-leaf ids as
            // installed, so a cached leaf says nothing about its IsInstalled verdict.
            (Native::CachedNotReported, _) if r.is_leaf => (Verdict::NotComparable, false, false),
            (Native::CachedNotReported, Tri::False) => (Verdict::Agree, true, false),
            (Native::CachedNotReported, Tri::True) => (Verdict::NotComparable, false, true),
            (Native::CachedNotReported, Tri::Unknown) => (Verdict::Unknown, false, true),
        };
        rep.entries.push(Entry {
            server_id: id,
            update: r.update_id.clone(),
            revision: r.revision,
            kind: r.update_type.clone(),
            leaf: r.is_leaf,
            origin: s.origin,
            native,
            ours,
            blockers,
            verdict,
            weak,
            suspect,
        });
    }
    rep
}

fn native_dir() -> PathBuf {
    std::env::var_os("WSUS_NATIVE_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/fixtures/wsus-m0-native")
        })
}

/// Id lists of the chosen native `SyncUpdates` requests.
fn native_lists(dir: &Path, requests: &[String]) -> (BTreeSet<i64>, BTreeSet<i64>) {
    let (mut installed, mut other) = (BTreeSet::new(), BTreeSet::new());
    for r in requests {
        let p = dir.join(r).join("request.body");
        let body = std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
        let action =
            "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates";
        let (_, req) = decode_request::<SyncUpdates>(Some(action), &body, &Limits::default())
            .unwrap_or_else(|e| panic!("{}: not a SyncUpdates request: {e:?}", p.display()));
        let params = req.parameters.value().expect("parameters");
        installed.extend(
            params
                .installed_non_leaf_update_ids
                .value()
                .into_iter()
                .flatten()
                .map(|i| i64::from(*i)),
        );
        other.extend(
            params
                .other_cached_update_ids
                .value()
                .into_iter()
                .flatten()
                .map(|i| i64::from(*i)),
        );
    }
    (installed, other)
}

/// Updates delivered in the retained native responses (they carry Core
/// fragments with server-local ids, so they resolve ids the stored revisions
/// lack).
fn native_response_revisions(dir: &Path, sets: &BTreeSet<String>) -> Vec<Revision> {
    let mut out = Vec::new();
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
                let xml = &u.xml;
                let Ok(idx) = FragmentIndex::parse(xml.as_bytes(), &Limits::default()) else {
                    continue;
                };
                let Some(identity) = idx.identity else {
                    continue;
                };
                out.push(Revision {
                    stem: format!("native-{}", u.id),
                    update_id: identity.id.0.hyphenated().to_string(),
                    revision: identity.revision.0,
                    server_id: u.id,
                    is_leaf: u.is_leaf,
                    update_type: idx
                        .properties
                        .attributes
                        .iter()
                        .find(|(k, _)| k == "UpdateType")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default(),
                    core_xml: xml.clone(),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------

/// The comparison logic on a tiny synthetic world, so the harness is tested
/// before any facts.json exists.
#[test]
fn harness_classifies_agreement_disagreement_unknown_and_not_comparable() {
    use wsus_protocol::applicability::recorded::{
        FactEntry, FactQuery, FactResult, Snapshot, SnapshotOs,
    };
    let rev = |id: i64, uid: &str, leaf: bool, pre: Option<&str>, rule: &str| {
        Revision {
        stem: format!("{uid}_1"),
        update_id: uid.to_owned(),
        revision: 1,
        server_id: id,
        is_leaf: leaf,
        update_type: "Detectoid".into(),
        core_xml: format!(
            "<UpdateIdentity UpdateID=\"{uid}\" RevisionNumber=\"1\"/><Properties UpdateType=\"Detectoid\"/>{}<ApplicabilityRules><IsInstalled>{rule}</IsInstalled></ApplicabilityRules>",
            pre.map(|p| format!("<Relationships><Prerequisites><UpdateIdentity UpdateID=\"{p}\"/></Prerequisites></Relationships>")).unwrap_or_default()
        ),
    }
    };
    let a = "aaaaaaaa-0000-4000-8000-000000000001";
    let b = "aaaaaaaa-0000-4000-8000-000000000002";
    let c = "aaaaaaaa-0000-4000-8000-000000000003";
    let d = "aaaaaaaa-0000-4000-8000-000000000004";
    let e = "aaaaaaaa-0000-4000-8000-000000000005";
    let f = "aaaaaaaa-0000-4000-8000-000000000006";
    let g = "aaaaaaaa-0000-4000-8000-000000000007";
    let t = "<True/>";
    let fl = "<False/>";
    let unknown = r#"<b.WmiQuery WqlQuery="select 1"/>"#;
    let revs = [
        rev(1, a, false, None, t),       // installed, ours True: agree
        rev(2, b, false, None, fl),      // installed, ours False: disagree
        rev(3, c, false, None, fl),      // cached only, ours False: weak agree
        rev(4, d, false, None, t),       // cached only, ours True: suspect, not comparable
        rev(5, e, false, None, unknown), // cached only, ours Unknown: unknown
        rev(6, f, false, None, unknown), // installed, ours Unknown: unknown
        rev(7, g, false, None, t),       // in neither list
    ];
    let sources: Vec<Source<'_>> = revs
        .iter()
        .map(|r| Source {
            rev: r,
            origin: "test",
        })
        .collect();
    let mut snap = Snapshot::new("t");
    snap.os = Some(SnapshotOs {
        major: 10,
        build: 26200,
        product_type: 1,
        ..SnapshotOs::default()
    });
    snap.facts.push(FactEntry {
        query: FactQuery::LicenseDword { name: "x".into() },
        result: FactResult::absent(),
    });
    let facts = RecordedFacts::from_snapshot(snap).unwrap();
    let installed: BTreeSet<i64> = [1, 2, 6, 999].into();
    let other: BTreeSet<i64> = [3, 4, 5].into();
    let rep = run_differential(&sources, &facts, &installed, &other, false);
    let e = |id: i64| rep.entries.iter().find(|e| e.server_id == id).unwrap();
    assert_eq!(e(1).verdict, Verdict::Agree);
    assert!(!e(1).weak);
    assert_eq!(e(2).verdict, Verdict::Disagree);
    assert_eq!(e(3).verdict, Verdict::Agree);
    assert!(e(3).weak);
    assert_eq!(e(4).verdict, Verdict::NotComparable);
    assert!(e(4).suspect);
    assert_eq!(e(5).verdict, Verdict::Unknown, "Unknown is never agreement");
    assert_eq!(e(6).verdict, Verdict::Unknown, "Unknown is never agreement");
    assert_eq!(e(7).verdict, Verdict::NotComparable);
    assert_eq!(rep.reported_installed, 4);
    assert_eq!(rep.resolved_installed, 3);
    assert_eq!(rep.unresolved_installed, vec![999]);
    assert_eq!(rep.count(Verdict::Agree), 2);
    let json: serde_json::Value = serde_json::from_str(&rep.to_json()).unwrap();
    assert_eq!(json["agree"], 2);
    assert_eq!(json["unknown"], 2);
    rep.print();
}

/// The native request lists decode, and the retained native responses of the same capture
/// resolve some of the installed ids. (The stored revisions are NOT used: their ids number
/// the updates differently, see the differential test.)
#[test]
fn native_installed_ids_resolve_through_the_responses_of_the_same_capture() {
    let (installed, other) = native_lists(&native_dir(), &["flow/000013".to_owned()]);
    assert_eq!(
        installed.len(),
        94,
        "InstalledNonLeafUpdateIDs of flow/000013"
    );
    assert_eq!(other.len(), 1337, "OtherCachedUpdateIDs of flow/000013");
    let sets: BTreeSet<String> = ["flow".to_owned()].into();
    let native = native_response_revisions(&native_dir(), &sets);
    let ids: BTreeSet<i64> = native.iter().map(|r| r.server_id).collect();
    let resolved = installed.iter().filter(|i| ids.contains(i)).count();
    eprintln!("installed 94: resolved by the flow responses {resolved}");
    assert!(resolved > 0);
}

#[test]
#[ignore = "needs WSUS_FACTS_JSON, a snapshot written by scripts/wsus/collect-facts.ps1 on the guest"]
fn differential_is_installed_against_the_native_agent() {
    let facts_path = std::env::var_os("WSUS_FACTS_JSON").unwrap_or_else(|| {
        panic!(
            "set WSUS_FACTS_JSON to the facts.json collected on the Windows guest:\n  \
             WSUS_FACTS_JSON=/path/to/facts.json cargo test -p wsus-protocol \
             --test applicability_differential -- --ignored --nocapture"
        )
    });
    let facts = RecordedFacts::from_json(
        &std::fs::read_to_string(&facts_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", Path::new(&facts_path).display())),
    )
    .unwrap_or_else(|e| panic!("facts.json: {e}"));
    eprintln!(
        "facts: {} recorded queries, collected {}",
        facts.len(),
        facts.collected_at()
    );
    // The stored revisions are only used to report the id-numbering mismatch.
    let dir = revisions_dir().unwrap_or_default();
    let requests: Vec<String> = std::env::var("WSUS_NATIVE_REQUESTS")
        .unwrap_or_else(|_| "flow/000013".into())
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let (installed, other) = native_lists(&native_dir(), &requests);
    // Server-local ids are only meaningful within one server state: the stored
    // revisions (an older sync) number the same updates differently (inventory
    // 12.7: 0 of 1461 updates of the scan keep their id). The only trustworthy
    // id -> identity map is the set of responses of the same capture as the
    // requests. Stored ids are used only on explicit request.
    let sets: BTreeSet<String> = requests
        .iter()
        .filter_map(|r| r.split('/').next().map(str::to_owned))
        .collect();
    let native = native_response_revisions(&native_dir(), &sets);
    let stored = if dir.is_dir() {
        load_revisions(&dir)
    } else {
        Vec::new()
    };
    let mut sources: Vec<Source<'_>> = native
        .iter()
        .map(|r| Source {
            rev: r,
            origin: "native-response",
        })
        .collect();
    if std::env::var("WSUS_DIFF_TRUST_STORED_IDS").as_deref() == Ok("1") {
        let known: BTreeSet<i64> = native.iter().map(|r| r.server_id).collect();
        sources.extend(
            stored
                .iter()
                .filter(|r| !known.contains(&r.server_id))
                .map(|r| Source {
                    rev: r,
                    origin: "stored",
                }),
        );
    }
    let by_identity: BTreeMap<(String, u32), i64> = stored
        .iter()
        .map(|r| ((r.update_id.to_ascii_lowercase(), r.revision), r.server_id))
        .collect();
    let (mut found, mut same) = (0, 0);
    for n in &native {
        if let Some(id) = by_identity.get(&(n.update_id.to_ascii_lowercase(), n.revision)) {
            found += 1;
            same += usize::from(*id == n.server_id);
        }
    }
    eprintln!(
        "id numbering: {found} of {} delivered updates exist in the stored revisions, {same} under the same server-local id",
        native.len()
    );
    let all_scope = std::env::var("WSUS_DIFF_SCOPE").as_deref() == Ok("all");
    let rep = run_differential(&sources, &facts, &installed, &other, all_scope);
    rep.print();
    let out = std::env::var_os("WSUS_DIFF_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("wsus-applicability-differential.json"));
    std::fs::write(&out, rep.to_json()).expect("write report");
    eprintln!("report: {}", out.display());
    assert!(
        rep.resolved_installed > 0,
        "no reported installed id could be resolved"
    );
    assert_eq!(
        rep.count(Verdict::Disagree),
        0,
        "{} update(s) disagree with the native agent (see the table above)",
        rep.count(Verdict::Disagree)
    );
}
