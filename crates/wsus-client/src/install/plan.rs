//! Install plans: decisions and steps from the stored catalog and a fact
//! provider.
//!
//! The planner reuses the evaluator exactly as the leaf-level differential
//! (`crates/wsus-protocol/tests/applicability_leaf_differential.rs`, inventory
//! 12.8) did, and adds what that differential did not need:
//!
//! * a node is a **bundle** (no installer of its own, `BundledUpdates`
//!   clauses) or an **installer** (a `HandlerSpecificData` command);
//! * the verdicts of the children decide, not a verdict derived for the
//!   bundle: an installer is installed when `IsInstallable` is True (an absent
//!   section counts as True, as in the differential), `IsInstalled` is False
//!   and every prerequisite clause is satisfied (a clause is satisfied when
//!   some alternative's latest revision evaluates `IsInstalled` True; a
//!   category is not followed deeper);
//! * a bundle is processed clause by clause and every alternative of a clause
//!   is evaluated; every alternative that qualifies is installed (the meaning
//!   of `AtLeastOne` for the INSTALL side is an Implementation decision,
//!   Unverified: the native agent installed one file per clause of the Defender
//!   bundle, see the inventory);
//! * the Unknown policy: any Unknown on a decision path refuses to plan
//!   (`PlanOutcome::Refused`, with the blockers) unless `allow_unknown`, in
//!   which case an Unknown node is skipped and the skip is recorded. This is a
//!   risk: an update that should have been installed, or a prerequisite that
//!   is not met, can be missed or acted on wrongly.
//!
//! Supersedence (Implementation decision, UNVERIFIED, never fired in the
//! differential): an update is superseded when another stored update lists it
//! in `SupersededUpdates` and that update's `IsInstalled` is True. A superseded
//! installer is skipped. An Unknown superseder state does NOT block (it is
//! recorded as a note): supersedence is not a validated part of the evaluator.
use super::{
    facts::RecordingFacts,
    handlers::{HandlerError, HandlerSpec, read_handler_info},
};
use crate::{download::ExpectedFile, sync::Catalog};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
};
use wsus_protocol::{
    applicability::{ApplicabilityRules, Blocker, Expr, FactProvider, SectionKind, Tri},
    identity::{DigestAlgorithm, FileDigest, UpdateId, UpdateRevision},
    metadata::FileEntry,
};

/// Plan document schema.
pub const PLAN_SCHEMA: &str = "wsus-install-plan/1";
/// Schema of plans made with [`PlanOptions::plan_prerequisites`]: prerequisite updates may be steps of
/// the plan (servicing stack update before a cumulative update). `/1` plans stay readable (every added
/// field has a default) and plans without the option are still written as `/1`, byte for byte.
pub const PLAN_SCHEMA_V2: &str = "wsus-install-plan/2";
/// Schema of uninstall plans ([`PlanOutcome::Uninstall`]): every step removes a CBS package, named by its
/// `servicing_identity` or, for an `OSInstaller` update without one, read from the CompDB cabinet among
/// its `extra_payloads` when the plan runs. The payloads are only the evidence the identity comes from:
/// nothing is installed from them (a step without any has an empty file name). A reader that does not know the
/// outcome value fails to read the plan, so an older client can never run it as an install.
pub const PLAN_SCHEMA_V3: &str = "wsus-install-plan/3";

/// Three-valued verdict as written in plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    True,
    False,
    Unknown,
}

impl From<Tri> for Verdict {
    fn from(t: Tri) -> Self {
        match t {
            Tri::True => Verdict::True,
            Tri::False => Verdict::False,
            Tri::Unknown => Verdict::Unknown,
        }
    }
}

/// Planner options.
#[derive(Debug, Clone)]
pub struct PlanOptions {
    /// Plan despite Unknown verdicts (skipping the Unknown nodes). Off by
    /// default; see the module documentation for the risk.
    pub allow_unknown: bool,
    /// Handler URIs the operator declares to be Windows Installer handlers
    /// (only used with the `msi-handler` feature).
    pub msi_handler_uris: Vec<String>,
    /// Maximum bundle nesting.
    pub max_depth: usize,
    /// Plan an installable prerequisite update (for example a servicing stack update) as an earlier
    /// step instead of declaring the dependent update not installable. Off by default: the Defender
    /// and MSI plans stay byte-identical.
    pub plan_prerequisites: bool,
    /// Treat `CbsPackageInstallable` (which needs the component store and so cannot be evaluated
    /// from facts) as True when planning, delegating the applicability decision to the servicing
    /// stack: the executor asks it (`/Get-PackageInfo`) just before each install and refuses a
    /// package it says is not applicable. Off by default: without it every `Cbs` update is Unknown.
    pub delegate_cbs_installable: bool,
    /// Uninstall plans only: accept an update whose metadata declares no `UninstallationBehavior`. The
    /// real `.NET` rollup leaf (`OSInstaller`, KB5126052) declares none, so without this option the very
    /// update the uninstall was designed for is refused. The plan records that the removal was an
    /// operator's explicit request, not something the server's metadata offers.
    pub allow_undeclared_uninstall: bool,
    /// Uninstall plans only: the package identity the operator names (`name~token~arch~language~version`),
    /// used instead of the one read from the update's metadata or its CompDB cabinet.
    pub uninstall_package: Option<String>,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            allow_unknown: false,
            msi_handler_uris: Vec::new(),
            max_depth: 8,
            plan_prerequisites: false,
            delegate_cbs_installable: false,
            allow_undeclared_uninstall: false,
            uninstall_package: None,
        }
    }
}

/// What a node decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// An installer that qualifies, or a bundle with at least one such
    /// descendant.
    Install,
    AlreadyInstalled,
    NotApplicable,
    /// Skipped because a stored update that supersedes it is installed
    /// (Unverified rule).
    Superseded,
    Unknown,
}

/// Overall result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOutcome {
    Install,
    NothingToDoInstalled,
    NothingToDoNotApplicable,
    /// Unknown on a decision path and `allow_unknown` is off.
    Refused,
    /// The steps REMOVE installed packages ([`PLAN_SCHEMA_V3`]).
    Uninstall,
    /// An uninstall was asked for and the update does not evaluate installed: nothing to remove.
    NothingToDoNotInstalled,
}

/// One evaluated node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub identity: String,
    /// `root`, `bundle` or `installer`.
    pub role: String,
    /// `None` when the update has no `IsInstalled` section.
    pub is_installed: Option<Verdict>,
    /// `None` when the update has no `IsInstallable` section (counts as True).
    pub is_installable: Option<Verdict>,
    pub prerequisites: Verdict,
    pub superseded: Verdict,
    pub status: NodeStatus,
    pub notes: Vec<String>,
    pub blockers: Vec<String>,
}

/// Digest of a payload as written in plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestRef {
    /// `sha1`, `sha256` or `sha512`.
    pub algorithm: String,
    pub hex: String,
}

/// The payload file of a step (as declared by the metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    pub file_name: String,
    pub size: u64,
    pub digests: Vec<DigestRef>,
    /// `PatchingType` or `PatchingTypePreferred` of the file as declared (`SelfContained`, `Metadata`,
    /// `ServicingStack`, ...); only read for `OSInstaller` updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patching: Option<String>,
}

fn alg_name(a: DigestAlgorithm) -> &'static str {
    match a {
        DigestAlgorithm::Sha1 => "sha1",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha512 => "sha512",
    }
}

impl PayloadRef {
    /// The empty reference of a step that has no payload of its own (an uninstall of a package named
    /// by the operator or by the update's metadata).
    pub fn none() -> Self {
        Self {
            file_name: String::new(),
            size: 0,
            digests: Vec::new(),
            patching: None,
        }
    }

    fn from_entry(f: &FileEntry) -> Option<Self> {
        Some(Self {
            file_name: f.file_name.clone()?,
            size: f.size?,
            digests: f
                .digests
                .iter()
                .map(|d| DigestRef {
                    algorithm: alg_name(d.algorithm).into(),
                    hex: crate::download::hex_encode(&d.bytes),
                })
                .collect(),
            patching: f
                .attributes
                .iter()
                .find(|(k, _)| k == "PatchingTypePreferred" || k == "PatchingType")
                .map(|(_, v)| v.clone()),
        })
    }

    /// The download descriptor.
    pub fn expected(&self) -> Result<ExpectedFile, String> {
        let mut digests = Vec::new();
        for d in &self.digests {
            let algorithm = match d.algorithm.as_str() {
                "sha1" => DigestAlgorithm::Sha1,
                "sha256" => DigestAlgorithm::Sha256,
                "sha512" => DigestAlgorithm::Sha512,
                other => return Err(format!("unknown digest algorithm `{other}`")),
            };
            let bytes = crate::download::hex_decode(&d.hex)
                .ok_or_else(|| "digest is not hexadecimal".to_owned())?;
            digests.push(FileDigest { algorithm, bytes });
        }
        ExpectedFile::new(&self.file_name, self.size, digests).map_err(|e| e.to_string())
    }
}

/// One installation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallStep {
    pub index: usize,
    /// `UUID@REVISION` of the installer update.
    pub update: String,
    #[serde(flatten)]
    pub spec: HandlerSpec,
    pub payload: PayloadRef,
    /// The other files of an `OSInstaller` update that must sit beside the primary payload (the
    /// `.NET` update declares its CompDB cabinet next to the KB cabinet). Empty for every other handler.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_payloads: Vec<PayloadRef>,
    /// Set when the payload is a Defender launcher package (see
    /// [`super::defender`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<super::defender::LauncherPackage>,
    /// For a `Cbs` step: the package identity the post-check must see `Installed`, derived from the
    /// update's applicability metadata (the handler data carries none). Absent for other handlers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servicing_identity: Option<String>,
}

/// Blockers grouped by text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerGroup {
    pub text: String,
    pub count: usize,
    /// First updates affected (at most three).
    pub examples: Vec<String>,
}

/// The facts the plan depended on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactsRef {
    /// SHA-256 over the canonical `query -> answer` lines the evaluation used.
    pub hash: String,
    pub queries: usize,
}

/// A deterministic install plan: the same catalog, options and facts give the
/// same bytes (no timestamps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallPlan {
    pub schema: String,
    pub target: String,
    pub allow_unknown: bool,
    pub facts: FactsRef,
    pub outcome: PlanOutcome,
    pub steps: Vec<InstallStep>,
    pub blockers: Vec<BlockerGroup>,
    pub decisions: Vec<Decision>,
    /// Plan-level statements (supersedence is unverified, etc.).
    pub notes: Vec<String>,
}

impl InstallPlan {
    /// Pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("plan serializes")
    }

    /// SHA-256 (hex) of the compact JSON.
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        crate::download::hex_encode(&Sha256::digest(
            serde_json::to_vec(self).expect("plan serializes"),
        ))
    }

    /// The decision of an identity.
    pub fn decision(&self, identity: &str) -> Option<&Decision> {
        self.decisions.iter().find(|d| d.identity == identity)
    }
}

#[derive(Clone)]
struct NodeResult {
    status: NodeStatus,
    steps: Vec<InstallStep>,
    blockers: Vec<String>,
}

type Eval = (Tri, Vec<String>);

/// The evaluator driver. One planner shares its memo over several targets
/// (the scan command asks for many roots).
pub struct Planner<'a> {
    catalog: &'a Catalog,
    facts: &'a dyn FactProvider,
    opts: PlanOptions,
    superseders: HashMap<UpdateId, Vec<UpdateId>>,
    installed_memo: RefCell<HashMap<UpdateId, Eval>>,
    results: HashMap<UpdateRevision, NodeResult>,
    in_progress: HashSet<UpdateRevision>,
    decisions: Vec<Decision>,
}

fn strings(b: Vec<Blocker>) -> Vec<String> {
    b.into_iter().map(|b| b.to_string()).collect()
}

impl<'a> Planner<'a> {
    pub fn new(catalog: &'a Catalog, facts: &'a dyn FactProvider, opts: PlanOptions) -> Self {
        let mut superseders: HashMap<UpdateId, Vec<UpdateId>> = HashMap::new();
        for rev in catalog.revisions() {
            if let Some(e) = catalog.get(rev) {
                for s in &e.index.superseded {
                    let by = superseders.entry(*s).or_default();
                    if !by.contains(&rev.id) {
                        by.push(rev.id);
                    }
                }
            }
        }
        Self {
            catalog,
            facts,
            opts,
            superseders,
            installed_memo: RefCell::new(HashMap::new()),
            results: HashMap::new(),
            in_progress: HashSet::new(),
            decisions: Vec::new(),
        }
    }

    fn rules_of(&self, rev: &UpdateRevision) -> Option<ApplicabilityRules> {
        let mut rules = self
            .catalog
            .get(rev)?
            .index
            .applicability_rules
            .as_ref()
            .map(ApplicabilityRules::from_element)?;
        if self.opts.delegate_cbs_installable
            && let Some(section) = rules.is_installable.as_mut()
        {
            let expr = std::mem::replace(&mut section.expr, Expr::True);
            section.expr = delegate_cbs_installable(expr);
        }
        Some(rules)
    }

    fn section(&self, rules: &Option<ApplicabilityRules>, kind: SectionKind) -> Option<Eval> {
        let r = rules.as_ref()?;
        r.section(kind)?;
        let o = r.evaluate(kind, self.facts);
        Some((o.value, strings(o.blockers)))
    }

    /// `IsInstalled` of the latest revision of `id` (own rule only, like the
    /// differential's `installed_of`).
    fn installed_of(&self, id: UpdateId) -> Eval {
        if let Some(v) = self.installed_memo.borrow().get(&id) {
            return v.clone();
        }
        let v = match self.catalog.latest_revision(id) {
            None => (
                Tri::Unknown,
                vec![format!("update {id} is not in the local catalog")],
            ),
            Some(rev) => {
                let rules = self.rules_of(&rev);
                self.section(&rules, SectionKind::IsInstalled)
                    .unwrap_or((Tri::Unknown, vec![format!("{rev} has no IsInstalled rule")]))
            }
        };
        self.installed_memo.borrow_mut().insert(id, v.clone());
        v
    }

    fn prerequisites(&self, rev: &UpdateRevision) -> Eval {
        let Some(entry) = self.catalog.get(rev) else {
            return (Tri::Unknown, vec![format!("{rev} is not in the catalog")]);
        };
        let mut all = Tri::True;
        let mut blockers = Vec::new();
        for clause in &entry.index.prerequisites {
            let mut any = Tri::False;
            let mut clause_blockers = Vec::new();
            for id in &clause.update_ids {
                let (t, b) = self.installed_of(*id);
                any = any.or(t);
                if t == Tri::Unknown {
                    clause_blockers.extend(b);
                }
            }
            all = all.and(any);
            if any == Tri::Unknown {
                blockers.extend(clause_blockers);
            }
        }
        if all != Tri::Unknown {
            blockers.clear();
        }
        blockers.dedup();
        (all, blockers)
    }

    /// Plans the prerequisites of `rev` as earlier steps ([`PlanOptions::plan_prerequisites`]).
    /// A clause already satisfied by an installed alternative adds nothing; otherwise the first
    /// alternative that is a software update and plans an install is scheduled. Returns the combined
    /// verdict of the clauses, the scheduled steps and the blockers of Unknown clauses.
    fn plan_prerequisites(
        &mut self,
        rev: &UpdateRevision,
        depth: usize,
    ) -> (Tri, Vec<InstallStep>, Vec<String>) {
        let clauses: Vec<Vec<UpdateId>> = self
            .catalog
            .get(rev)
            .map(|e| {
                e.index
                    .prerequisites
                    .iter()
                    .map(|c| c.update_ids.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut all = Tri::True;
        let mut steps: Vec<InstallStep> = Vec::new();
        let mut blockers: Vec<String> = Vec::new();
        for ids in clauses {
            let mut any = Tri::False;
            let mut clause_blockers = Vec::new();
            for id in &ids {
                let (t, b) = self.installed_of(*id);
                any = any.or(t);
                if t == Tri::Unknown {
                    clause_blockers.extend(b);
                }
            }
            if any == Tri::True {
                continue;
            }
            let mut scheduled: Option<Vec<InstallStep>> = None;
            for id in &ids {
                let Some(alt) = self.catalog.latest_revision(*id) else {
                    continue;
                };
                let is_update = self
                    .catalog
                    .get(&alt)
                    .is_some_and(|e| e.record.fragments.iter().any(|f| f.kind == "Extended"));
                if !is_update {
                    continue;
                }
                let r = self.visit(alt, depth + 1, false);
                if r.status == NodeStatus::Install && !r.steps.is_empty() {
                    scheduled = Some(r.steps);
                    break;
                }
            }
            match scheduled {
                Some(s) => steps.extend(s),
                None => {
                    all = all.and(any);
                    if any == Tri::Unknown {
                        blockers.extend(clause_blockers);
                    }
                }
            }
        }
        blockers.dedup();
        (all, steps, blockers)
    }

    fn superseded(&self, rev: &UpdateRevision) -> Eval {
        let mut t = Tri::False;
        let mut blockers = Vec::new();
        for by in self.superseders.get(&rev.id).into_iter().flatten() {
            if *by == rev.id {
                continue;
            }
            let (v, b) = self.installed_of(*by);
            t = t.or(v);
            if v == Tri::Unknown {
                blockers.extend(b);
            }
        }
        if t != Tri::Unknown {
            blockers.clear();
        }
        blockers.dedup();
        (t, blockers)
    }

    fn step_for(
        &self,
        rev: &UpdateRevision,
    ) -> Result<
        (
            HandlerSpec,
            super::plan::PayloadRef,
            Vec<super::plan::PayloadRef>,
        ),
        String,
    > {
        let entry = self
            .catalog
            .get(rev)
            .ok_or_else(|| format!("{rev} is not in the catalog"))?;
        let fragment = entry
            .record
            .fragments
            .iter()
            .find(|f| f.kind == "Extended")
            .ok_or_else(|| {
                "the Extended fragment has not been fetched (run `wsus client sync`)".to_owned()
            })?;
        let info = read_handler_info(&fragment.xml).map_err(|e| e.to_string())?;
        let files = entry.files();
        let pick = |name: Option<&str>| -> Result<PayloadRef, String> {
            let mut it = files.iter().filter(|f| match name {
                Some(n) => f
                    .file_name
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(n)),
                None => true,
            });
            let f = it
                .next()
                .ok_or_else(|| "payload file is not declared".to_owned())?;
            if it.next().is_some() {
                return Err("more than one candidate payload file".to_owned());
            }
            let p = PayloadRef::from_entry(f)
                .ok_or_else(|| "payload file lacks a name or size".to_owned())?;
            if !p
                .digests
                .iter()
                .any(|d| d.algorithm == "sha256" || d.algorithm == "sha1")
            {
                return Err("payload file has no SHA-1 or SHA-256 digest".to_owned());
            }
            Ok(p)
        };
        match info.command_line() {
            Ok(spec) => {
                let payload = pick(Some(&spec.program))?;
                Ok((HandlerSpec::CommandLine(spec), payload, Vec::new()))
            }
            Err(HandlerError::UnsupportedHandler(uri)) => {
                // Windows servicing: planned with its payload but never executable here.
                if uri == super::handlers::CBS_HANDLER_URI
                    || uri == super::handlers::OS_INSTALLER_HANDLER_URI
                {
                    let spec = info.servicing().map_err(|e| e.to_string())?;
                    let mut spec = spec;
                    let (payload, extras, stack) = pick_servicing_payload(files, &spec)?;
                    spec.stack_payload = stack;
                    return Ok((HandlerSpec::Servicing(spec), payload, extras));
                }
                #[cfg(feature = "msi-handler")]
                if uri == super::handlers::msi::WINDOWS_INSTALLER_HANDLER_URI
                    || self.opts.msi_handler_uris.contains(&uri)
                {
                    let payload = pick(None)?;
                    // The real WindowsInstaller handler must carry MsiData or MspData; an
                    // operator-declared URI without them falls back to the payload extension.
                    let strict = uri == super::handlers::msi::WINDOWS_INSTALLER_HANDLER_URI;
                    let spec = match info.windows_installer() {
                        Ok(spec) => spec,
                        Err(e) if strict => return Err(e.to_string()),
                        Err(_) => super::handlers::msi::MsiSpec::from_file_name(&payload.file_name)
                            .map_err(|e| e.to_string())?,
                    };
                    return Ok((HandlerSpec::Msi(spec), payload, Vec::new()));
                }
                Err(HandlerError::UnsupportedHandler(uri).to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn visit(&mut self, rev: UpdateRevision, depth: usize, root: bool) -> NodeResult {
        if let Some(r) = self.results.get(&rev) {
            return r.clone();
        }
        let unknown = |why: String| NodeResult {
            status: NodeStatus::Unknown,
            steps: Vec::new(),
            blockers: vec![why],
        };
        if depth > self.opts.max_depth {
            return unknown(format!(
                "{rev}: bundle nesting deeper than {}",
                self.opts.max_depth
            ));
        }
        if !self.in_progress.insert(rev) {
            return unknown(format!("{rev}: bundle cycle"));
        }
        let result = self.visit_inner(rev, depth, root);
        self.in_progress.remove(&rev);
        self.results.insert(rev, result.clone());
        result
    }

    fn visit_inner(&mut self, rev: UpdateRevision, depth: usize, root: bool) -> NodeResult {
        let Some(entry) = self.catalog.get(&rev) else {
            let d = Decision {
                identity: rev.to_string(),
                role: if root { "root" } else { "bundle" }.into(),
                is_installed: None,
                is_installable: None,
                prerequisites: Verdict::Unknown,
                superseded: Verdict::Unknown,
                status: NodeStatus::Unknown,
                notes: vec![],
                blockers: vec![format!("{rev} is not in the local catalog")],
            };
            let blockers = d.blockers.clone();
            self.decisions.push(d);
            return NodeResult {
                status: NodeStatus::Unknown,
                steps: vec![],
                blockers,
            };
        };
        let bundled: Vec<Vec<UpdateRevision>> = entry
            .index
            .bundled
            .iter()
            .map(|c| c.revisions.clone())
            .collect();
        let has_extended = entry.record.fragments.iter().any(|f| f.kind == "Extended");
        let handler_present = entry
            .record
            .fragments
            .iter()
            .filter(|f| f.kind == "Extended")
            .any(|f| read_handler_info(&f.xml).is_ok_and(|i| i.is_present()));
        let rules = self.rules_of(&rev);
        let installed = self.section(&rules, SectionKind::IsInstalled);
        let installable = self.section(&rules, SectionKind::IsInstallable);
        let (prereq, prereq_b) = self.prerequisites(&rev);
        let (superseded, superseded_b) = self.superseded(&rev);
        let mut notes = Vec::new();
        if superseded == Tri::Unknown {
            notes.push(format!(
                "supersedence could not be evaluated (Unverified rule, not blocking): {}",
                superseded_b.first().cloned().unwrap_or_default()
            ));
        }
        let role = if root {
            "root"
        } else if handler_present {
            "installer"
        } else {
            "bundle"
        };
        // Slot of the decision so children are listed after their parent.
        let slot = self.decisions.len();
        self.decisions.push(Decision {
            identity: rev.to_string(),
            role: role.into(),
            is_installed: installed.as_ref().map(|(t, _)| (*t).into()),
            is_installable: installable.as_ref().map(|(t, _)| (*t).into()),
            prerequisites: prereq.into(),
            superseded: superseded.into(),
            status: NodeStatus::Unknown,
            notes: Vec::new(),
            blockers: Vec::new(),
        });
        let installable_t = installable.as_ref().map_or(Tri::True, |(t, _)| *t);
        let mut blockers: Vec<String> = Vec::new();
        let mut steps: Vec<InstallStep> = Vec::new();
        let status;
        if handler_present && !bundled.is_empty() {
            blockers.push(format!(
                "{rev}: both a handler and bundled updates (not understood)"
            ));
            status = NodeStatus::Unknown;
        } else if handler_present {
            // Installer.
            let (installed_t, installed_b) = installed
                .clone()
                .unwrap_or((Tri::Unknown, vec![format!("{rev} has no IsInstalled rule")]));
            // Prerequisite updates scheduled as earlier steps (only with the option).
            let (prereq, prereq_b, mut pre_steps) =
                if self.opts.plan_prerequisites && prereq != Tri::True {
                    let (t, st, b) = self.plan_prerequisites(&rev, depth);
                    (t, if t == Tri::Unknown { b } else { Vec::new() }, st)
                } else {
                    (prereq, prereq_b.clone(), Vec::new())
                };
            if !pre_steps.is_empty() {
                notes.push(format!(
                    "prerequisite updates scheduled as earlier steps: {}",
                    pre_steps
                        .iter()
                        .map(|s| s.update.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            let t = installable_t.and(!installed_t).and(prereq);
            match t {
                Tri::True => {
                    if superseded == Tri::True {
                        status = NodeStatus::Superseded;
                    } else {
                        match self.step_for(&rev) {
                            Ok((spec, payload, extra_payloads)) => {
                                let launcher =
                                    super::defender::classify_package(&payload.file_name);
                                let servicing_identity = match &spec {
                                    HandlerSpec::Servicing(sv)
                                        if sv.kind == super::handlers::ServicingKind::Cbs =>
                                    {
                                        rules.as_ref().and_then(|r| r.cbs_package_identity())
                                    }
                                    _ => None,
                                };
                                steps.append(&mut pre_steps);
                                steps.push(InstallStep {
                                    index: 0,
                                    update: rev.to_string(),
                                    spec,
                                    payload,
                                    extra_payloads,
                                    launcher,
                                    servicing_identity,
                                });
                                status = NodeStatus::Install;
                            }
                            Err(why) => {
                                blockers.push(format!("{rev}: {why}"));
                                status = NodeStatus::Unknown;
                            }
                        }
                    }
                }
                Tri::False => {
                    status = if installed_t == Tri::True {
                        NodeStatus::AlreadyInstalled
                    } else {
                        NodeStatus::NotApplicable
                    };
                }
                Tri::Unknown => {
                    if installable_t == Tri::Unknown {
                        blockers.extend(installable.clone().map(|x| x.1).unwrap_or_default());
                    }
                    if installed_t == Tri::Unknown {
                        blockers.extend(installed_b);
                    }
                    if prereq == Tri::Unknown {
                        blockers.extend(prereq_b.clone());
                    }
                    status = NodeStatus::Unknown;
                }
            }
        } else if bundled.is_empty() {
            blockers.push(format!(
                "{rev}: neither a handler nor bundled updates{}",
                if has_extended {
                    ""
                } else {
                    " (the Extended fragment has not been fetched; run `wsus client sync`)"
                }
            ));
            status = NodeStatus::Unknown;
        } else {
            // Bundle.
            let installed_t = installed.as_ref().map(|(t, _)| *t);
            let (prereq, prereq_b, bundle_pre_steps) =
                if self.opts.plan_prerequisites && prereq != Tri::True {
                    let (t, st, b) = self.plan_prerequisites(&rev, depth);
                    (t, if t == Tri::Unknown { b } else { Vec::new() }, st)
                } else {
                    (prereq, prereq_b.clone(), Vec::new())
                };
            if !bundle_pre_steps.is_empty() {
                notes.push(format!(
                    "prerequisite updates scheduled as earlier steps: {}",
                    bundle_pre_steps
                        .iter()
                        .map(|s| s.update.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            let gate = installable_t.and(prereq);
            if installed_t == Some(Tri::True) {
                status = NodeStatus::AlreadyInstalled;
            } else if gate == Tri::False {
                status = NodeStatus::NotApplicable;
            } else if gate == Tri::Unknown {
                if installable_t == Tri::Unknown {
                    blockers.extend(installable.clone().map(|x| x.1).unwrap_or_default());
                }
                if prereq == Tri::Unknown {
                    blockers.extend(prereq_b.clone());
                }
                status = NodeStatus::Unknown;
            } else if superseded == Tri::True {
                status = NodeStatus::Superseded;
            } else {
                let mut every_clause_installed = true;
                let mut unknown_children = false;
                for clause in &bundled {
                    let mut clause_installed = false;
                    for alt in clause {
                        let r = self.visit(*alt, depth + 1, false);
                        match r.status {
                            NodeStatus::Install => steps.extend(r.steps),
                            NodeStatus::AlreadyInstalled => clause_installed = true,
                            NodeStatus::Unknown => {
                                unknown_children = true;
                                blockers.extend(r.blockers);
                            }
                            NodeStatus::NotApplicable | NodeStatus::Superseded => {}
                        }
                    }
                    every_clause_installed &= clause_installed;
                }
                if !bundle_pre_steps.is_empty() && !steps.is_empty() {
                    let mut ordered = bundle_pre_steps;
                    ordered.append(&mut steps);
                    steps = ordered;
                }
                let mut seen = HashSet::new();
                steps.retain(|s| seen.insert(s.update.clone()));
                status = if unknown_children && !self.opts.allow_unknown {
                    NodeStatus::Unknown
                } else if !steps.is_empty() {
                    NodeStatus::Install
                } else if every_clause_installed {
                    NodeStatus::AlreadyInstalled
                } else {
                    NodeStatus::NotApplicable
                };
                if unknown_children && self.opts.allow_unknown {
                    notes.push(
                        "Unknown children were skipped because --allow-unknown is on".to_owned(),
                    );
                }
            }
        }
        // allow_unknown also skips an Unknown own gate or installer.
        let mut final_status = status;
        if status == NodeStatus::Unknown && self.opts.allow_unknown {
            notes.push("Unknown verdict treated as not applicable (--allow-unknown)".to_owned());
            final_status = NodeStatus::NotApplicable;
        }
        blockers.dedup();
        let d = &mut self.decisions[slot];
        d.status = status;
        d.notes = notes;
        d.blockers = blockers.clone();
        NodeResult {
            status: final_status,
            steps,
            blockers,
        }
    }

    /// `IsInstalled` of exactly this revision (its own rule only; no installability, prerequisites or
    /// supersedence). The uninstall post-check asks this: whether the update still evaluates installed.
    pub fn installed_verdict(&self, rev: UpdateRevision) -> (Tri, Vec<String>) {
        let rules = self.rules_of(&rev);
        self.section(&rules, SectionKind::IsInstalled)
            .unwrap_or((Tri::Unknown, vec![format!("{rev} has no IsInstalled rule")]))
    }

    /// Verdict of one update without producing a document (scan).
    pub fn verdict(&mut self, rev: UpdateRevision) -> (NodeStatus, Vec<String>) {
        let r = self.visit(rev, 0, true);
        (r.status, r.blockers)
    }

    /// Plans the removal of `target` (see [`build_uninstall_plan`]).
    pub fn plan_uninstall(
        &mut self,
        target: UpdateRevision,
        recording: &RecordingFacts<'_>,
    ) -> InstallPlan {
        let mut blockers: Vec<String> = Vec::new();
        let mut steps: Vec<InstallStep> = Vec::new();
        let mut notes = vec![
            "Uninstall plan: the step removes a CBS package (its servicing_identity, or the package its CompDB cabinet names); nothing is downloaded or installed.".to_owned(),
            "Whether the package is permanent is not decided here: only the servicing stack's answer (0x800f0825) is believed, at execution time.".to_owned(),
        ];
        let mut outcome = PlanOutcome::Refused;
        let mut decision = Decision {
            identity: target.to_string(),
            role: "installer".into(),
            is_installed: None,
            is_installable: None,
            prerequisites: Verdict::Unknown,
            superseded: Verdict::Unknown,
            status: NodeStatus::Unknown,
            notes: Vec::new(),
            blockers: Vec::new(),
        };
        'plan: {
            let Some(entry) = self.catalog.get(&target) else {
                blockers.push(format!("{target} is not in the local catalog"));
                break 'plan;
            };
            if !entry.index.bundled.is_empty() {
                blockers.push(format!(
                    "{target} is a bundle: uninstall its installer updates one by one"
                ));
                break 'plan;
            }
            let Some(fragment) = entry.record.fragments.iter().find(|f| f.kind == "Extended")
            else {
                blockers.push(format!(
                    "{target}: the Extended fragment has not been fetched (run `wsus client sync`)"
                ));
                break 'plan;
            };
            let spec = match read_handler_info(&fragment.xml).and_then(|i| i.servicing()) {
                Ok(spec) => spec,
                Err(e) => {
                    blockers.push(format!(
                        "{target}: not a servicing (Cbs or OSInstaller) update, so this client has no uninstall for it: {e}"
                    ));
                    break 'plan;
                }
            };
            if spec.uninstallation.is_none() {
                if self.opts.allow_undeclared_uninstall {
                    notes.push(format!(
                        "{target} declares no UninstallationBehavior: the removal is the operator's explicit request (--allow-undeclared), not something the update's metadata offers"
                    ));
                } else {
                    blockers.push(format!(
                        "{target}: the update declares no UninstallationBehavior (the real .NET rollup leaf declares none; pass --allow-undeclared to remove it on the operator's own request)"
                    ));
                    break 'plan;
                }
            }
            let rules = self.rules_of(&target);
            // Package identity: the operator's, else the update's metadata (Cbs updates), else the
            // CompDB cabinet at execution time (OSInstaller `.NET` updates, whose metadata names none).
            let mut identity = None;
            if let Some(p) = &self.opts.uninstall_package {
                if !super::servicing::is_valid_package_identity(p) {
                    blockers.push(format!(
                        "`{p}` is not a package identity (name~token~architecture~language~version)"
                    ));
                    break 'plan;
                }
                notes.push(format!("package identity named by the operator: {p}"));
                identity = Some(p.clone());
            } else if let Some(i) = rules.as_ref().and_then(|r| r.cbs_package_identity()) {
                identity = Some(i);
            }
            let (payload, extra_payloads) = match self.step_for(&target) {
                Ok((_, payload, extras)) => (payload, extras),
                Err(_) => (PayloadRef::none(), Vec::new()),
            };
            let has_compdb = extra_payloads
                .iter()
                .any(|p| p.file_name.to_ascii_lowercase().ends_with(".xml.cab"));
            if identity.is_none() {
                if spec.kind == super::handlers::ServicingKind::OsInstaller && has_compdb {
                    notes.push(
                        "the package identity is read from the servicing CompDB cabinet when the plan runs (it must be in the store, digest-verified); no payload is installed"
                            .to_owned(),
                    );
                } else {
                    blockers.push(format!(
                        "{target}: no package identity in the update's applicability metadata and no servicing CompDB cabinet to read one from (name it with --package)"
                    ));
                    break 'plan;
                }
            }
            let installed = self.section(&rules, SectionKind::IsInstalled);
            decision.is_installed = installed.as_ref().map(|(t, _)| (*t).into());
            match installed {
                None => {
                    blockers.push(format!("{target} has no IsInstalled rule"));
                }
                Some((Tri::Unknown, b)) => {
                    blockers.extend(b);
                }
                Some((Tri::False, _)) => {
                    decision.status = NodeStatus::NotApplicable;
                    notes.push(format!(
                        "{target} does not evaluate installed: nothing to remove"
                    ));
                    outcome = PlanOutcome::NothingToDoNotInstalled;
                }
                Some((Tri::True, _)) => {
                    decision.status = NodeStatus::AlreadyInstalled;
                    steps.push(InstallStep {
                        index: 0,
                        update: target.to_string(),
                        spec: HandlerSpec::Servicing(spec),
                        payload,
                        extra_payloads,
                        launcher: None,
                        servicing_identity: identity,
                    });
                    outcome = PlanOutcome::Uninstall;
                }
            }
        }
        decision.blockers = blockers.clone();
        let mut groups: BTreeMap<String, usize> = BTreeMap::new();
        for b in &blockers {
            *groups.entry(b.clone()).or_default() += 1;
        }
        InstallPlan {
            schema: PLAN_SCHEMA_V3.into(),
            target: target.to_string(),
            allow_unknown: false,
            facts: FactsRef {
                hash: recording.digest(),
                queries: recording.queries(),
            },
            outcome,
            steps,
            blockers: groups
                .into_iter()
                .map(|(text, count)| BlockerGroup {
                    text,
                    count,
                    examples: vec![target.to_string()],
                })
                .collect(),
            decisions: vec![decision],
            notes,
        }
    }

    /// Plans `target`. The facts hash is taken from `recording`, which must
    /// be the wrapper around the provider given to [`Planner::new`].
    pub fn plan(&mut self, target: UpdateRevision, recording: &RecordingFacts<'_>) -> InstallPlan {
        let r = self.visit(target, 0, true);
        let mut steps = r.steps.clone();
        // Defender launcher packages: terminal package last, no selection that
        // would leave the stub waiting (see `defender`).
        let mut arrange_blocker: Option<String> = None;
        match super::defender::arrange(std::mem::take(&mut steps)) {
            Ok(ordered) => steps = ordered,
            Err(why) => arrange_blocker = Some(format!("{}: {why}", target)),
        }
        for (i, s) in steps.iter_mut().enumerate() {
            s.index = i;
        }
        let outcome = match (r.status, self.opts.allow_unknown) {
            _ if arrange_blocker.is_some() => PlanOutcome::Refused,
            (NodeStatus::Install, _) if !steps.is_empty() => PlanOutcome::Install,
            (NodeStatus::Unknown, false) => PlanOutcome::Refused,
            (NodeStatus::AlreadyInstalled, _) => PlanOutcome::NothingToDoInstalled,
            _ => PlanOutcome::NothingToDoNotApplicable,
        };
        if outcome == PlanOutcome::Refused {
            // A refused plan never carries steps: nothing in it may be run.
            steps.clear();
        }
        // A refusal is also needed when the root is not Unknown but a node
        // below it was (the bundle code turns that into Unknown unless
        // allowed), so `r.status` covers it.
        let mut groups: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
        for d in &self.decisions {
            for b in &d.blockers {
                let e = groups.entry(b.clone()).or_default();
                e.0 += 1;
                if e.1.len() < 3 && !e.1.contains(&d.identity) {
                    e.1.push(d.identity.clone());
                }
            }
        }
        if let Some(b) = arrange_blocker {
            let e = groups.entry(b).or_default();
            e.0 += 1;
            e.1.push(target.to_string());
        }
        let blockers = groups
            .into_iter()
            .map(|(text, (count, examples))| BlockerGroup {
                text,
                count,
                examples,
            })
            .collect();
        InstallPlan {
            schema: if self.opts.plan_prerequisites {
                PLAN_SCHEMA_V2
            } else {
                PLAN_SCHEMA
            }
            .into(),
            target: target.to_string(),
            allow_unknown: self.opts.allow_unknown,
            facts: FactsRef {
                hash: recording.digest(),
                queries: recording.queries(),
            },
            outcome,
            steps,
            blockers,
            decisions: self.decisions.clone(),
            notes: vec![
                "Supersedence is an Unverified rule: a superseded installer is skipped when a stored superseding update evaluates installed; an Unknown superseder does not block.".into(),
                "The meaning of AtLeastOne for installation is Unverified: every qualifying alternative of a bundle clause is installed.".into(),
            ]
            .into_iter()
            .chain(self.opts.delegate_cbs_installable.then(|| {
                "CbsPackageInstallable was treated as True: the servicing stack's applicability verdict (DISM /Get-PackageInfo) is asked just before each install and a package it says is not applicable is refused.".to_owned()
            }))
            .collect(),
        }
    }
}

/// Builds the UNINSTALL plan of `target` (docs/wsus-osinstaller-spike.md 18.9).
///
/// Decisions, the conservative choice where the design left one:
/// * `allow_unknown` has no effect: an Unknown verdict always refuses;
/// * the update must be an installer (no bundle, no command-line or MSI handler), a servicing handler
///   (`Cbs` or `OSInstaller`), must declare `UninstallationBehavior` and must have a package identity
///   in its applicability metadata;
/// * the update must evaluate installed; not installed is `NothingToDoNotInstalled`;
/// * whether the package is permanent is NOT guessed from its name or class: only the stack's own
///   answer (`0x800f0825`) is believed, at execution time.
pub fn build_uninstall_plan(
    catalog: &Catalog,
    facts: &dyn FactProvider,
    target: UpdateRevision,
    opts: &PlanOptions,
) -> InstallPlan {
    let recording = RecordingFacts::new(facts);
    let mut planner = Planner::new(catalog, &recording, opts.clone());
    planner.plan_uninstall(target, &recording)
}

/// Builds the plan of `target` against `facts`.
pub fn build_plan(
    catalog: &Catalog,
    facts: &dyn FactProvider,
    target: UpdateRevision,
    opts: &PlanOptions,
) -> InstallPlan {
    let recording = RecordingFacts::new(facts);
    let mut planner = Planner::new(catalog, &recording, opts.clone());
    planner.plan(target, &recording)
}

/// `CbsPackageInstallable` becomes True (the servicing stack decides at execution time).
fn delegate_cbs_installable(e: Expr) -> Expr {
    match e {
        Expr::Unsupported(u) => {
            let bare = u.name.rsplit(['.', ':']).next().unwrap_or(&u.name);
            if bare == "CbsPackageInstallable" {
                Expr::True
            } else {
                Expr::Unsupported(u)
            }
        }
        Expr::And(v) => Expr::And(v.into_iter().map(delegate_cbs_installable).collect()),
        Expr::Or(v) => Expr::Or(v.into_iter().map(delegate_cbs_installable).collect()),
        Expr::Not(b) => Expr::Not(Box::new(delegate_cbs_installable(*b))),
        other => other,
    }
}

/// Sanity bound on the total declared size of an `OSInstaller` update this client treats as one complete
/// file set. The monthly cumulative updates declare 9 to 15 GB (all of it is acquired and verified, the
/// stack's own download list then picks what it needs); a larger declaration is treated as a metadata
/// fault and the set stays incomplete (refused by the executor).
pub const OS_INSTALLER_COMPLETE_SET_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// File name of the servicing stack cabinet an `OSInstaller` update declares (`PatchingType` `ServicingStack`).
pub const OS_INSTALLER_STACK_CAB: &str = "DesktopDeployment.cab";

/// The payloads a servicing step names. A CBS update declares one `.cab`. An OS installer update
/// declares several files: when every one of them has a name, a size and a SHA-1 or SHA-256 digest (and
/// the total is within `OS_INSTALLER_COMPLETE_SET_MAX_BYTES`) all of them are payloads of the step, primary
/// first: the `.NET` updates (KB cabinet and CompDB cabinet, 74 to 97 MB) and the monthly cumulative updates
/// (19 files, 14.3 GB for 26200.9457), whose download list only the stack itself can name, so every
/// declared file is acquired and handed over. The primary payload is the largest `.cab` or `.msu` that is
/// not `Metadata`, else the largest file that is not `Metadata`. A set in which a file lacks a name, a size
/// or a digest is NOT complete: the step names the largest file only and the executor refuses it.
///
/// An `OSInstaller` update's `DesktopDeployment.cab` (`ServicingStack`) is never a payload of the step: it
/// is returned separately (only when it carries a SHA-1 or SHA-256 digest) for the executor to fetch and
/// extract as the update stack.
fn pick_servicing_payload(
    files: &[wsus_protocol::metadata::FileEntry],
    spec: &super::handlers::ServicingSpec,
) -> Result<(PayloadRef, Vec<PayloadRef>, Option<PayloadRef>), String> {
    use super::handlers::ServicingKind;
    let is_stack = |p: &PayloadRef| {
        spec.kind == ServicingKind::OsInstaller
            && p.file_name.eq_ignore_ascii_case(OS_INSTALLER_STACK_CAB)
            && p.patching.as_deref() == Some("ServicingStack")
    };
    let mut candidates: Vec<PayloadRef> = files.iter().filter_map(PayloadRef::from_entry).collect();
    let every_file_named = candidates.len() == files.len();
    let mut stack = None;
    candidates.retain(|p| {
        if is_stack(p) {
            if p.digests
                .iter()
                .any(|d| d.algorithm == "sha256" || d.algorithm == "sha1")
            {
                stack = Some(p.clone());
            }
            false
        } else {
            true
        }
    });
    if candidates.is_empty() {
        return Err("payload file is not declared or lacks a name or size".to_owned());
    }
    if spec.kind == ServicingKind::Cbs && candidates.len() != 1 {
        return Err("a CBS update must declare exactly one payload file".to_owned());
    }
    let has_digest = |p: &PayloadRef| {
        p.digests
            .iter()
            .any(|d| d.algorithm == "sha256" || d.algorithm == "sha1")
    };
    candidates.sort_by_key(|p| std::cmp::Reverse(p.size));
    let total: u64 = candidates.iter().map(|p| p.size).sum();
    if spec.kind == ServicingKind::OsInstaller
        && every_file_named
        && total <= OS_INSTALLER_COMPLETE_SET_MAX_BYTES
    {
        if let Some(bad) = candidates.iter().find(|p| !has_digest(p)) {
            return Err(format!("{} has no SHA-1 or SHA-256 digest", bad.file_name));
        }
        let is_package = |p: &PayloadRef| {
            let n = p.file_name.to_ascii_lowercase();
            p.patching.as_deref() != Some("Metadata")
                && (n.ends_with(".cab") || n.ends_with(".msu"))
        };
        let pos = candidates
            .iter()
            .position(is_package)
            .or_else(|| {
                candidates
                    .iter()
                    .position(|p| p.patching.as_deref() != Some("Metadata"))
            })
            .unwrap_or(0);
        let primary = candidates.remove(pos);
        candidates.sort_by(|a, b| a.file_name.cmp(&b.file_name));
        return Ok((primary, candidates, stack));
    }
    let p = candidates.remove(0);
    if !has_digest(&p) {
        return Err("payload file has no SHA-1 or SHA-256 digest".to_owned());
    }
    Ok((p, Vec::new(), stack))
}
