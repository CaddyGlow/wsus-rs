//! Offline model of the native Windows Update Agent's SyncUpdates behavior, driven against
//! this server in both delivery modes.
//!
//! WHAT THE MODEL IS. It follows the protocol as observed in `docs/fixtures/wsus-m0-native`
//! and in the guest's WindowsUpdate.log against this server (inventory 5.3 and 9.3):
//!
//! * it starts with no cached ids, calls `SyncUpdates`, and calls again after a truncated
//!   response or after a response that delivered a non-leaf update (MS-WUSP 3.1.5.7);
//! * it evaluates a delivered entity only when every prerequisite clause of that entity is
//!   satisfied by the installed ids it had when it SENT the request (the guest evaluated 5 of
//!   442 entities in its first, failed run against the closure delivery, exactly the five entities with no
//!   prerequisite, and reported only the two of them that evaluate as installed);
//! * an evaluated non-leaf entity whose `IsInstalled` rule is true goes into
//!   `InstalledNonLeafUpdateIDs` on the next request; everything else, leaves included, goes
//!   into `OtherCachedUpdateIDs`; ids the server answers in `OutOfScopeRevisionIDs` are
//!   dropped;
//! * "found an update" means a delivered `Install` software update whose own prerequisites
//!   are all in the installed set.
//!
//! WHAT IT IS NOT. It is not WUA. Evaluation of `IsInstalled` is the shared three-valued
//! evaluator `wsus_protocol::applicability` over a caller-provided fake machine (`FakeFacts`:
//! registry, files, OS state); an `Unknown` result (unsupported operator, fact the fake does
//! not define) makes the test fail loudly instead of being guessed. The shared evaluator's
//! semantics are themselves unverified against a native client (see inventory "Applicability
//! rules"). Leaf applicability (`IsInstallable`) is not evaluated. Whether the real agent re-evaluates unevaluated
//! entities when its installed set grows is not known; the model does not, which is what the
//! guest log of the FIRST (failed) closure run suggested. THAT PREDICTION WAS CONTRADICTED: on
//! 2026-10-04 the real agent found, downloaded and installed the bundle against this server in
//! closure mode too (`docs/wsus-protocol-inventory.md` 9.7), so this model is more conservative
//! than WUA. The model was built from the same observations as the server; it is not evidence
//! of native behavior, and its closure-mode assertions below are MODEL-ONLY (they document
//! what the model does, not what the product does). Nothing here establishes that a native
//! client converges (`docs/wsus-validation.md`, C31 and S5).
mod endpoints_common;
use endpoints_common::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use uuid::Uuid;
use wsus_protocol::applicability::{
    ApplicabilityRules, FakeFacts, FileInfo, OsInfo, SectionKind, Tri,
};
use wsus_protocol::identity::UpdateId;
use wsus_protocol::metadata::FragmentIndex;
use wsus_protocol::soap::{Limits, Presence};
use wsus_protocol::wusp::{
    CategoryIdentifier, DeploymentAction, StartCategoryScan, SyncUpdateParameters, SyncUpdates,
};
use wsus_server::catalog::{FragmentImport, RelationshipImport, RelationshipKind};
use wsus_server::endpoints::SyncDelivery;
use wsus_server::storage::Database;

// ---- fake host ------------------------------------------------------------------------

/// Caller-provided machine state the shared applicability evaluator
/// (`wsus_protocol::applicability`) reads. It is a closed-world `FakeFacts` machine: registry
/// keys, values and files that were not set are absent, which makes the operators that read them
/// false; an operator the shared evaluator cannot decide (an unsupported operator or a fact the
/// fake does not define, such as a WQL query) makes the evaluation `Unknown` and this test fail
/// loudly instead of being guessed.
#[derive(Debug, Clone)]
struct Host {
    facts: FakeFacts,
}

impl Host {
    /// Windows 11 25H2, AMD64, Microsoft Defender installed and running as the inbox
    /// antimalware product (the state under which the Defender catalog applies).
    fn defender_running() -> Self {
        let mut facts = FakeFacts::windows11_x64();
        facts.set_os(OsInfo {
            major: 10,
            minor: 0,
            build: 26200,
            sp_major: 0,
            sp_minor: 0,
            product_type: 1,
            suite_mask: 0x100,
            ..OsInfo::default()
        });
        facts.set_dword("SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start", 2);
        facts.set_dword("SOFTWARE\\Microsoft\\Windows Defender", "ProductType", 2);
        facts.add_key_both("SYSTEM\\CurrentControlSet\\Services\\WdFilter");
        facts.add_file(
            Some(38),
            "windows defender\\mpclient.dll",
            FileInfo::default(),
        );
        facts.set_sz(
            "SOFTWARE\\Microsoft\\Windows Defender",
            "InstallLocation",
            "C:\\Program Files\\Windows Defender",
        );
        facts.add_file(
            None,
            "C:\\Program Files\\Windows Defender\\mpclient.dll",
            FileInfo::default(),
        );
        Host { facts }
    }

    fn set_dword(&mut self, key: &str, value: &str, data: u32) {
        self.facts.set_dword(key, value, data);
    }

    /// Verdict of the `IsInstalled` rule of a delivered fragment. No rules or no `IsInstalled`
    /// section is "not installed" (what the model always did); anything the shared evaluator
    /// cannot decide panics with its blockers.
    fn is_installed(&self, idx: &FragmentIndex, who: &str) -> bool {
        let Some(rules) = ApplicabilityRules::from_fragment(idx) else {
            return false;
        };
        if rules.is_installed.is_none() {
            return false;
        }
        let out = rules.evaluate(SectionKind::IsInstalled, &self.facts);
        match out.value {
            Tri::True => true,
            Tri::False => false,
            Tri::Unknown => panic!(
                "{who}: cannot evaluate IsInstalled: {}",
                out.blockers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        }
    }
}

// ---- the simulated agent -------------------------------------------------------------

#[derive(Debug, Clone)]
struct Entity {
    id: i32,
    update: UpdateId,
    is_leaf: bool,
    action: DeploymentAction,
    clauses: Vec<Vec<UpdateId>>,
    update_type: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Shape {
    new: usize,
    non_leaf: usize,
    leaf: usize,
    truncated: bool,
    out_of_scope: usize,
    installed_in_request: usize,
}

#[derive(Default)]
struct Report {
    rounds: Vec<Shape>,
    entities: BTreeMap<i32, Entity>,
    installed: BTreeSet<i32>,
    evaluated: BTreeSet<i32>,
    unevaluated: BTreeSet<i32>,
    driver_not_needed: Vec<Option<String>>,
}

impl Report {
    fn ids_of(&self, u: Uuid) -> Vec<i32> {
        self.entities
            .values()
            .filter(|e| e.update.0 == u)
            .map(|e| e.id)
            .collect()
    }

    fn satisfied(&self, e: &Entity) -> bool {
        let installed: BTreeSet<UpdateId> = self
            .installed
            .iter()
            .filter_map(|i| self.entities.get(i))
            .map(|e| e.update)
            .collect();
        e.clauses
            .iter()
            .all(|c| c.iter().any(|a| installed.contains(a)))
    }

    /// Software updates the agent would report as found: a delivered `Install` deployment
    /// whose prerequisites it knows to be installed.
    fn found(&self) -> Vec<&Entity> {
        self.entities
            .values()
            .filter(|e| {
                e.action == DeploymentAction::Install
                    && e.update_type == "Software"
                    && self.satisfied(e)
            })
            .collect()
    }
}

struct Agent<'a> {
    env: &'a Env,
    client: Client,
    host: Host,
    filter: Vec<Uuid>,
}

impl<'a> Agent<'a> {
    fn new(env: &'a Env, n: u128, host: Host) -> Self {
        Agent {
            env,
            client: registered(env, n),
            host,
            filter: Vec::new(),
        }
    }

    fn request(&self, installed: &[i32], other: &[i32], skip: bool) -> SyncUpdates {
        let mut r = sync_req(&self.client.cookie, installed, other);
        if let Presence::Value(p) = &mut r.parameters {
            p.skip_software_sync = skip;
            if !self.filter.is_empty() {
                p.filter_category_ids = Presence::Value(
                    self.filter
                        .iter()
                        .map(|id| CategoryIdentifier { id: *id })
                        .collect(),
                );
            }
        }
        r
    }

    fn run(&mut self, max_rounds: usize) -> Report {
        let mut rep = Report::default();
        let (mut installed, mut other): (Vec<i32>, Vec<i32>) = (Vec::new(), Vec::new());
        loop {
            assert!(
                rep.rounds.len() < max_rounds,
                "no convergence after {max_rounds} rounds"
            );
            let info = self
                .env
                .call(&self.request(&installed, &other, false))
                .expect("SyncUpdates")
                .result
                .into_value()
                .unwrap();
            if let Some(c) = info.new_cookie.value() {
                self.client.cookie = c.clone();
            }
            rep.driver_not_needed
                .push(info.driver_sync_not_needed.value().cloned());
            let oos: Vec<i32> = info
                .out_of_scope_revision_ids
                .value()
                .cloned()
                .unwrap_or_default();
            installed.retain(|i| !oos.contains(i));
            other.retain(|i| !oos.contains(i));
            rep.installed.retain(|i| !oos.contains(i));
            let at_request: BTreeSet<UpdateId> = installed
                .iter()
                .filter_map(|i| rep.entities.get(i))
                .map(|e| e.update)
                .collect();
            let ups = info.new_updates.value().cloned().unwrap_or_default();
            let mut shape = Shape {
                new: ups.len(),
                truncated: info.truncated,
                out_of_scope: oos.len(),
                installed_in_request: installed.len(),
                ..Shape::default()
            };
            let mut newly_installed = Vec::new();
            for u in &ups {
                let xml = u.xml.value().expect("core fragment");
                let idx = FragmentIndex::parse(xml.as_bytes(), &Limits::default())
                    .unwrap_or_else(|e| panic!("delivered fragment of {} unparsable: {e}", u.id));
                let ent = Entity {
                    id: u.id,
                    update: idx.identity.expect("identity").id,
                    is_leaf: u.is_leaf,
                    action: u.deployment.value().expect("deployment").action.clone(),
                    clauses: idx
                        .prerequisites
                        .iter()
                        .map(|c| c.update_ids.clone())
                        .collect(),
                    update_type: idx
                        .properties
                        .attributes
                        .iter()
                        .find(|(k, _)| k == "UpdateType")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default(),
                };
                if u.is_leaf {
                    shape.leaf += 1;
                    other.push(u.id);
                } else {
                    shape.non_leaf += 1;
                    let ready = ent
                        .clauses
                        .iter()
                        .all(|c| c.iter().any(|a| at_request.contains(a)));
                    if ready {
                        rep.evaluated.insert(u.id);
                        let yes = self
                            .host
                            .is_installed(&idx, &format!("update {} ({})", u.id, ent.update.0));
                        if yes {
                            newly_installed.push(u.id);
                        } else {
                            other.push(u.id);
                        }
                    } else {
                        rep.unevaluated.insert(u.id);
                        other.push(u.id);
                    }
                }
                rep.entities.insert(u.id, ent);
            }
            installed.extend(&newly_installed);
            rep.installed.extend(&newly_installed);
            let again = info.truncated || shape.non_leaf > 0;
            assert!(
                !(info.truncated && ups.is_empty()),
                "truncated response without updates"
            );
            rep.rounds.push(shape);
            if !again {
                break;
            }
        }
        // The driver pass: SkipSoftwareSync with installed ids.
        let info = self
            .env
            .call(&self.request(&installed, &[], true))
            .expect("driver pass")
            .result
            .into_value()
            .unwrap();
        assert!(
            info.new_updates.value().is_none(),
            "driver pass delivers nothing"
        );
        assert!(!info.truncated);
        rep.driver_not_needed
            .push(info.driver_sync_not_needed.value().cloned());
        rep
    }
}

// ---- synthetic Defender-shaped catalog -----------------------------------------------

const UPD: &str = "http://schemas.microsoft.com/msus/2002/12/Update";
const LAR: &str = "http://schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules";
const BAR: &str = "http://schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules";

fn g(n: u128) -> String {
    Uuid::from_u128(n).hyphenated().to_string()
}

enum Pre {
    And(u128),
    Alo(Vec<u128>),
    Cat(Vec<u128>),
}

/// A whole update document in the shape the downstream importer stores, plus the relationship
/// rows the importer derives from it.
fn doc(n: u128, kind: &str, pre: &[Pre], bundle: &[u128], rule: &str) -> FragmentImport {
    let mut rel = String::new();
    let mut rows = Vec::new();
    if !pre.is_empty() {
        rel.push_str("<Prerequisites>");
        for p in pre {
            match p {
                Pre::And(t) => {
                    rel.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", g(*t)));
                    rows.push((RelationshipKind::Prerequisite, *t));
                }
                Pre::Alo(ts) | Pre::Cat(ts) => {
                    let (attr, kd) = match p {
                        Pre::Cat(_) => (" IsCategory=\"true\"", RelationshipKind::Category),
                        _ => ("", RelationshipKind::Prerequisite),
                    };
                    rel.push_str(&format!("<AtLeastOne{attr}>"));
                    for t in ts {
                        rel.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", g(*t)));
                        rows.push((kd, *t));
                    }
                    rel.push_str("</AtLeastOne>");
                }
            }
        }
        rel.push_str("</Prerequisites>");
    }
    if !bundle.is_empty() {
        rel.push_str("<BundledUpdates><AtLeastOne>");
        for t in bundle {
            rel.push_str(&format!(
                "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>",
                g(*t)
            ));
            rows.push((RelationshipKind::Bundle, *t));
        }
        rel.push_str("</AtLeastOne></BundledUpdates>");
    }
    let rel = if rel.is_empty() {
        String::new()
    } else {
        format!("<Relationships>{rel}</Relationships>")
    };
    let xml = format!(
        "<Update xmlns=\"{UPD}\" xmlns:lar=\"{LAR}\" xmlns:bar=\"{BAR}\">\
         <UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>\
         <Properties UpdateType=\"{kind}\"/>{rel}\
         <ApplicabilityRules><IsInstalled>{rule}</IsInstalled></ApplicabilityRules>\
         </Update>",
        g(n),
    );
    let mut f = FragmentImport::new(rev(n, 1), kind, xml.as_bytes());
    f.relationships = rows
        .into_iter()
        .map(|(kind, t)| RelationshipImport {
            kind,
            target: uid(t),
            revision: if kind == RelationshipKind::Bundle {
                Some(wsus_protocol::identity::Revision(1))
            } else {
                None
            },
        })
        .collect();
    f
}

const TRUE: &str = "<lar:True/>";

/// Shape of the lab Defender catalog (inventory 9.3, section "Approved update"): a category
/// chain, product and classification categories, detectoids that gate on the product, CPU
/// detectoids without prerequisites, and a bundle of software members, all behind `IsCategory`
/// and ordinary prerequisites. Ids: 1 root category, 2 mid category, 3 product category,
/// 4 classification, 5 and 6 gating detectoids, 7 AMD64 detectoid, 8 ARM detectoid, 100
/// bundle, 101 to 105 members.
fn defender_shaped() -> Vec<FragmentImport> {
    let product_rule = String::from(
        "<lar:And><bar:WindowsVersion Comparison=\"GreaterThanOrEqualTo\" MajorVersion=\"6\" \
         MinorVersion=\"1\"/><lar:Not><bar:WindowsVersion Comparison=\"EqualTo\" MajorVersion=\"6\" \
         MinorVersion=\"2\"/></lar:Not><bar:RegDword Key=\"HKEY_LOCAL_MACHINE\" \
         Subkey=\"SYSTEM\\CurrentControlSet\\Services\\WinDefend\" Value=\"Start\" \
         Comparison=\"EqualTo\" Data=\"2\"/><lar:Or><bar:RegDword Key=\"HKEY_LOCAL_MACHINE\" \
         Subkey=\"SOFTWARE\\Microsoft\\Windows Defender\" Value=\"ProductType\" \
         Comparison=\"EqualTo\" Data=\"2\"/><lar:Not><bar:RegKeyExists Key=\"HKEY_LOCAL_MACHINE\" \
         Subkey=\"SYSTEM\\CurrentControlSet\\Services\\WdFilter\"/></lar:Not></lar:Or></lar:And>",
    );
    let no_shared_root = "<lar:Not><lar:Or><bar:RegValueExists Key=\"HKEY_LOCAL_MACHINE\" \
        Subkey=\"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\" \
        Value=\"SharedSignatureRoot\"/></lar:Or></lar:Not>";
    let uup = "<lar:Or><bar:WindowsVersion Comparison=\"LessThan\" MajorVersion=\"10\" \
        MinorVersion=\"0\" BuildNumber=\"17763\"/><lar:Not><bar:RegValueExists \
        Key=\"HKEY_LOCAL_MACHINE\" Subkey=\"SOFTWARE\\Microsoft\\Windows Defender\" \
        Value=\"UUPFlags\" Type=\"REG_DWORD\"/></lar:Not><bar:RegDword Key=\"HKEY_LOCAL_MACHINE\" \
        Subkey=\"SOFTWARE\\Microsoft\\Windows Defender\" Value=\"UUPFlags\" \
        Comparison=\"EqualTo\" Data=\"0\"/></lar:Or>";
    let mut v = vec![
        doc(1, "Category", &[], &[], TRUE),
        doc(2, "Category", &[Pre::Cat(vec![1])], &[], TRUE),
        doc(3, "Category", &[Pre::Cat(vec![2])], &[], &product_rule),
        doc(4, "Category", &[], &[], TRUE),
        doc(5, "Detectoid", &[Pre::And(3)], &[], no_shared_root),
        doc(6, "Detectoid", &[Pre::And(3)], &[], uup),
        doc(
            7,
            "Detectoid",
            &[],
            &[],
            "<bar:Processor Architecture=\"9\"/>",
        ),
        doc(
            8,
            "Detectoid",
            &[],
            &[],
            "<bar:Processor Architecture=\"12\"/>",
        ),
    ];
    let members: Vec<u128> = (101..=105).collect();
    v.push(doc(
        100,
        "Software",
        &[
            Pre::And(5),
            Pre::And(6),
            Pre::Cat(vec![4]),
            Pre::Cat(vec![3]),
        ],
        &members,
        "<lar:True/>",
    ));
    for m in members {
        v.push(doc(
            m,
            "Software",
            &[
                Pre::And(5),
                Pre::And(6),
                Pre::Cat(vec![3]),
                Pre::Alo(vec![7, 8]),
            ],
            &[],
            "<lar:True/>",
        ));
    }
    v
}

fn synthetic(mode: SyncDelivery, page: usize) -> Env {
    let mut cfg = config_for(mode);
    cfg.max_sync_new_updates = page;
    let env = setup_with(cfg);
    env.publish(&defender_shaped());
    env.approve(100);
    env
}

#[test]
fn staged_delivery_converges_and_finds_the_approved_bundle_in_the_synthetic_catalog() {
    let env = synthetic(SyncDelivery::Staged, 30);
    let mut agent = Agent::new(&env, 900, Host::defender_running());
    let rep = agent.run(20);
    let found = rep.found();
    assert_eq!(
        found.len(),
        1,
        "exactly the approved bundle is found: {rep_shapes:?}",
        rep_shapes = rep.rounds
    );
    assert_eq!(found[0].update.0, Uuid::from_u128(100));
    // Bundle children arrive with the Bundle action, and are leaves.
    let member_ids: Vec<i32> = (101..=105)
        .flat_map(|n| rep.ids_of(Uuid::from_u128(n)))
        .collect();
    assert_eq!(member_ids.len(), 5);
    for id in member_ids {
        let e = &rep.entities[&id];
        assert!(e.is_leaf && e.action == DeploymentAction::Bundle);
    }
    // Dependency order: the first round holds only entities without prerequisites; nothing
    // is delivered before its prerequisites were reported installed.
    assert_eq!(rep.rounds[0].new, rep.rounds[0].non_leaf);
    for id in rep.entities.keys() {
        let e = &rep.entities[id];
        if e.update.0 != Uuid::from_u128(100) {
            continue;
        }
        assert!(rep.satisfied(e));
    }
    assert!(
        rep.unevaluated.is_empty(),
        "staged delivery never delivers an entity the agent cannot evaluate: {:?}",
        rep.unevaluated
    );
    // The AMD64 detectoid evaluates installed, the ARM one does not.
    assert!(rep.installed.contains(&rep.ids_of(Uuid::from_u128(7))[0]));
    assert!(!rep.installed.contains(&rep.ids_of(Uuid::from_u128(8))[0]));
    // Software passes say a driver pass is needed; the driver pass says it is not (Observed,
    // flow 000013 and 000014).
    let last = rep.driver_not_needed.len() - 1;
    assert!(
        rep.driver_not_needed[..last]
            .iter()
            .all(|d| d.as_deref() == Some("false"))
    );
    assert_eq!(rep.driver_not_needed[last].as_deref(), Some("true"));
}

#[test]
fn staged_delivery_withholds_dependents_when_a_gate_does_not_evaluate_installed() {
    let env = synthetic(SyncDelivery::Staged, 30);
    // Defender not running: the product category is not installed, so nothing behind it is
    // delivered and the bundle is not found.
    let mut host = Host::defender_running();
    host.set_dword("SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start", 4);
    let mut agent = Agent::new(&env, 901, host);
    let rep = agent.run(20);
    assert!(rep.found().is_empty());
    assert!(
        !rep.entities
            .values()
            .any(|e| e.update.0 == Uuid::from_u128(100)),
        "the bundle is not even delivered"
    );
    assert!(
        rep.entities
            .values()
            .any(|e| e.update.0 == Uuid::from_u128(3))
    );
}

/// MODEL-ONLY prediction, contradicted by the real agent. Under the model's rules the closure
/// delivery hands the agent everything at once, it can evaluate only the entities with no
/// prerequisite, never asks again for the rest, and finds nothing. That matches the guest's
/// first failed closure run ("Found 0 updates ... evaluated appl. rules of 5 out of 442
/// deployed entities"), but the real agent, run against closure mode after the `Deployment`,
/// `IsLeaf` and category-chain fixes, DID find, download and install the bundle (inventory
/// 9.7). The assertions below therefore pin the MODEL's behavior, not WUA's.
#[test]
fn model_only_closure_delivery_leaves_the_synthetic_bundle_unfound() {
    let env = synthetic(SyncDelivery::Closure, 200);
    let mut agent = Agent::new(&env, 902, Host::defender_running());
    let rep = agent.run(20);
    assert!(
        rep.found().is_empty(),
        "model-only: under the model's rules closure delivery is not found (the real agent \
         found it, inventory 9.7)"
    );
    assert!(
        rep.entities
            .values()
            .any(|e| e.update.0 == Uuid::from_u128(100)),
        "the bundle is delivered, but its prerequisites were never evaluated"
    );
    assert!(!rep.unevaluated.is_empty());
    let roots: BTreeSet<Uuid> = rep
        .evaluated
        .iter()
        .map(|i| rep.entities[i].update.0)
        .collect();
    assert_eq!(
        roots,
        [1u128, 4, 7, 8]
            .iter()
            .map(|n| Uuid::from_u128(*n))
            .collect()
    );
}

// ---- recorded native dialogue replayed against a same-shaped catalog ------------------

fn fixture(set: &str, n: &str, f: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/fixtures/wsus-m0-native")
        .join(set)
        .join(n)
        .join(f);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn fixture_sync(n: &str) -> SyncUpdateParameters {
    let (_, r) = wsus_protocol::soap::decode_request::<SyncUpdates>(
        Some(
            "\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates\"",
        ),
        &fixture("scan", n, "request.body"),
        &Limits::default(),
    )
    .unwrap();
    r.parameters.into_value().unwrap()
}

/// Replays `docs/fixtures/wsus-m0-native/scan` request by request. The recorded scan was a
/// category-filtered ZDP scan: root category (rev id 108226), a category requiring it
/// (108231), and a leaf category requiring that. The same chain is built as an approved
/// catalog; the fixture's id lists are translated to this server's local ids by position.
/// Compared: StartCategoryScan echo, then per request the count of updates, leaf and
/// non-leaf, Truncated and DriverSyncNotNeeded, then the driver pass.
#[test]
fn the_recorded_native_scan_dialogue_has_the_same_shape_against_a_same_shaped_catalog() {
    let env = setup_mode(SyncDelivery::Staged);
    let cat = uid(0xdd78b8a1_0b20_45c1_add6_4da72e9364cf);
    let (root, mid) = (1u128, 2u128);
    let leaf = 0xdd78b8a1_0b20_45c1_add6_4da72e9364cfu128;
    env.publish(&[
        doc(root, "Category", &[], &[], TRUE),
        doc(mid, "Category", &[Pre::Cat(vec![root])], &[], TRUE),
        doc(leaf, "Category", &[Pre::Cat(vec![mid])], &[], TRUE),
    ]);
    env.approve(leaf);
    let mut c = registered(&env, 903);
    // StartCategoryScan: request and response of scan/000005.
    let (_, req) = wsus_protocol::soap::decode_request::<StartCategoryScan>(
        Some("\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/StartCategoryScan\""),
        &fixture("scan", "000005", "request.body"),
        &Limits::default(),
    )
    .unwrap();
    let resp = env.call(&req).unwrap();
    assert_eq!(resp.preferred_category_ids.value(), Some(&vec![cat.0]));
    assert!(resp.requested_category_ids_in_error.value().is_none());

    let mut map: BTreeMap<i32, i32> = BTreeMap::new(); // fixture id -> our local id
    let expect = [
        // (fixture exchange, updates, non-leaf, leaf)
        ("000006", 1usize, 1usize, 0usize),
        ("000007", 1, 1, 0),
        ("000008", 1, 0, 1),
    ];
    let fixture_ids = [108226, 108231];
    let mut delivered_fixture_ids = fixture_ids.iter();
    for (n, count, non_leaf, leafs) in expect {
        let p = fixture_sync(n);
        // Request-side shape of the fixture, translated.
        let tr = |v: Presence<Vec<i32>>| -> Vec<i32> {
            v.value()
                .map(|v| v.iter().map(|i| map[i]).collect())
                .unwrap_or_default()
        };
        let installed = tr(p.installed_non_leaf_update_ids.clone());
        let other = tr(p.other_cached_update_ids.clone());
        let mut r = sync_req(&c.cookie, &installed, &other);
        if let Presence::Value(q) = &mut r.parameters {
            q.filter_category_ids = p.filter_category_ids.clone();
            q.need_two_group_out_of_scope_updates = p.need_two_group_out_of_scope_updates.clone();
        }
        let info = env.call(&r).unwrap().result.into_value().unwrap();
        c.cookie = info.new_cookie.value().unwrap().clone();
        let ups = info.new_updates.value().cloned().unwrap_or_default();
        assert_eq!(ups.len(), count, "{n}");
        assert_eq!(ups.iter().filter(|u| !u.is_leaf).count(), non_leaf, "{n}");
        assert_eq!(ups.iter().filter(|u| u.is_leaf).count(), leafs, "{n}");
        assert!(!info.truncated, "{n}");
        assert!(info.out_of_scope_revision_ids.value().is_none(), "{n}");
        // Recorded responses: DriverSyncNotNeeded true for this filtered scan.
        let rec = String::from_utf8(fixture("scan", n, "response.body")).unwrap();
        assert!(rec.contains("<DriverSyncNotNeeded>true</DriverSyncNotNeeded>"));
        assert_eq!(
            info.driver_sync_not_needed.value().map(String::as_str),
            Some("true"),
            "{n}"
        );
        // Deployments: every update has the observed 7-field Evaluate shape.
        assert!(rec.contains("<Action>Evaluate</Action>"));
        let d = ups[0].deployment.value().unwrap();
        let want = if ups[0].is_leaf {
            DeploymentAction::Install // our approved leaf; the recorded scan had no approval
        } else {
            DeploymentAction::Evaluate
        };
        assert_eq!(d.action, want, "{n}");
        assert!(d.is_assigned && d.last_change_time.len() == 10);
        if let Some(f) = delivered_fixture_ids.next() {
            map.insert(*f, ups[0].id);
        }
    }
    // Driver pass 000009: SkipSoftwareSync with 70 devices; response has no NewUpdates.
    let p = fixture_sync("000009");
    assert!(p.skip_software_sync);
    let installed: Vec<i32> = map.values().copied().collect();
    let mut r = sync_req(&c.cookie, &installed, &[]);
    if let Presence::Value(q) = &mut r.parameters {
        q.skip_software_sync = true;
        q.system_spec = p.system_spec.clone();
        q.computer_spec = p.computer_spec.clone();
        q.feature_score_matching_key = p.feature_score_matching_key.clone();
    }
    let info = env.call(&r).unwrap().result.into_value().unwrap();
    assert!(info.new_updates.value().is_none());
    assert!(!info.truncated);
    assert_eq!(
        info.driver_sync_not_needed.value().map(String::as_str),
        Some("true")
    );
}

/// The `flow` capture's software pass without a category filter says `DriverSyncNotNeeded`
/// false, and its driver pass (75 devices, installed ids listed) says true. Ids in the
/// recorded lists do not exist in this catalog, so they must be answered as out of scope and
/// the 400 entry cap of the real server (Observed: 401 rejected) must hold.
#[test]
fn the_recorded_native_flow_requests_get_the_recorded_response_shapes() {
    let env = synthetic(SyncDelivery::Staged, 30);
    let c = registered(&env, 904);
    let parse = |n: &str| {
        wsus_protocol::soap::decode_request::<SyncUpdates>(
            Some("\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates\""),
            &fixture("flow", n, "request.body"),
            &Limits::default(),
        )
        .unwrap()
        .1
        .parameters
        .into_value()
        .unwrap()
    };
    // 000013: software pass, 94 installed ids and 1337 others unknown here.
    let p = parse("000013");
    let mut r = sync_req(
        &c.cookie,
        p.installed_non_leaf_update_ids.value().unwrap(),
        p.other_cached_update_ids.value().unwrap(),
    );
    if let Presence::Value(q) = &mut r.parameters {
        q.need_two_group_out_of_scope_updates = p.need_two_group_out_of_scope_updates.clone();
    }
    let info = env.call(&r).unwrap().result.into_value().unwrap();
    assert_eq!(
        info.driver_sync_not_needed.value().map(String::as_str),
        Some("false")
    );
    let oos = info.out_of_scope_revision_ids.value().unwrap();
    assert_eq!(
        oos.len(),
        94 + 1337,
        "every unknown cached id is answered as out of scope"
    );
    // 000014: driver pass.
    let p = parse("000014");
    let mut r = sync_req(
        &c.cookie,
        p.installed_non_leaf_update_ids.value().unwrap(),
        &[],
    );
    if let Presence::Value(q) = &mut r.parameters {
        q.skip_software_sync = true;
        q.system_spec = p.system_spec.clone();
        q.computer_spec = p.computer_spec.clone();
        q.feature_score_matching_key = p.feature_score_matching_key.clone();
    }
    let info = env.call(&r).unwrap().result.into_value().unwrap();
    assert!(info.new_updates.value().is_none() && !info.truncated);
    assert_eq!(
        info.driver_sync_not_needed.value().map(String::as_str),
        Some("true")
    );
    // The cap: 400 accepted, 401 rejected.
    let ok: Vec<i32> = (1..=400).collect();
    assert!(env.call(&sync_req(&c.cookie, &ok, &[])).is_ok());
    let too_many: Vec<i32> = (1..=401).collect();
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &too_many, &[])),
        wsus_protocol::soap::ErrorCode::InvalidParameters
    );
}

// ---- the real-derived catalog ---------------------------------------------------------

/// Copy of the lab server database (never the original): `WSUS_SIM_DB`, else the lead's lab
/// path. The test is skipped, loudly, when neither exists.
fn real_db() -> Option<(tempfile::TempDir, Database)> {
    let src = std::env::var_os("WSUS_SIM_DB")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join("vm-lab/wsus-m0/ours/server/wsus.sqlite"))
        })
        .filter(|p| p.is_file());
    let Some(src) = src else {
        eprintln!(
            "SKIPPED: no real-derived database (set WSUS_SIM_DB to a copy of the lab \
             server's wsus.sqlite)"
        );
        return None;
    };
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("db.sqlite");
    std::fs::copy(&src, &dst).unwrap();
    let wal = PathBuf::from(format!("{}-wal", src.display()));
    if wal.is_file() {
        std::fs::copy(&wal, PathBuf::from(format!("{}-wal", dst.display()))).unwrap();
    }
    let db = Database::open(&dst).expect("open the database copy");
    Some((dir, db))
}

fn real_env(mode: SyncDelivery) -> Option<Env> {
    let (dir, db) = real_db()?;
    let mut cfg = config_for(mode);
    cfg.source_name = "lab-wsus".into(); // the source name inside the lab database
    cfg.max_sync_new_updates = if mode == SyncDelivery::Staged {
        30
    } else {
        200
    };
    let env = build(dir, db, cfg);
    Some(env)
}

#[test]
fn staged_delivery_finds_the_defender_bundle_in_the_real_derived_catalog() {
    let Some(env) = real_env(SyncDelivery::Staged) else {
        return;
    };
    let bundle = Uuid::parse_str("a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe").unwrap();
    let mut agent = Agent::new(&env, 910, Host::defender_running());
    let rep = agent.run(60);
    eprintln!("rounds: {:#?}", rep.rounds);
    let found = rep.found();
    assert_eq!(found.len(), 1, "installed {:?}", rep.installed);
    assert_eq!(found[0].update.0, bundle);
    assert_eq!(found[0].action, DeploymentAction::Install);
    let members = rep
        .entities
        .values()
        .filter(|e| e.action == DeploymentAction::Bundle)
        .count();
    assert!(
        members >= 124,
        "the bundle's 124 children are delivered with the Bundle action, got {members}"
    );
    assert!(rep.unevaluated.is_empty(), "{:?}", rep.unevaluated);
    // Real server pages 30 per response.
    assert!(rep.rounds.iter().all(|r| r.new <= 30));
}

/// MODEL-ONLY reproduction of the guest log of the first failed closure run: under the model's
/// rules only entities without prerequisites get evaluated, two or three of them evaluate as
/// installed, nothing is found. (The guest saw 5 evaluated and 2 installed, ids 50 and 4064;
/// the category-edge fix to the closure adds the root category, id 9, which is the one extra.)
/// The real agent later found the bundle in closure mode (inventory 9.7), so this is a
/// statement about the model, not a known limitation of the product.
#[test]
fn model_only_closure_delivery_leaves_the_defender_bundle_unfound_in_the_real_derived_catalog() {
    let Some(env) = real_env(SyncDelivery::Closure) else {
        return;
    };
    let mut agent = Agent::new(&env, 911, Host::defender_running());
    let rep = agent.run(60);
    eprintln!(
        "evaluated {:?} installed {:?}",
        rep.evaluated, rep.installed
    );
    assert!(
        rep.found().is_empty(),
        "model-only: the real agent found the bundle in closure mode (inventory 9.7)"
    );
    assert!(rep.installed.contains(&50) && rep.installed.contains(&4064));
    assert!(rep.evaluated.len() <= 6, "{:?}", rep.evaluated);
    assert!(rep.entities.len() > 400, "the whole closure was delivered");
}
