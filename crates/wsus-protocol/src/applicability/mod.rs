//! Portable evaluator of Windows Update applicability rules.
//!
//! The `ApplicabilityRules` element of a Core fragment holds up to four rule
//! sections (`IsInstalled`, `IsInstallable`, `IsSuperseded`, `Metadata`; the
//! first two occur in the real data, see the inventory). This module parses
//! them into typed [`Expr`] trees, evaluates the boolean sections against a
//! [`FactProvider`] and answers with a three-valued [`Outcome`]:
//!
//! * `True` / `False` only when every operand that mattered was answered;
//! * `Unknown` when an unsupported operator or an unavailable fact stands
//!   between the facts and a definite answer, with the list of those
//!   [`Blocker`]s, so unsupported rules stay visible.
//!
//! Unknown is never promoted: [`Tri`] is Kleene's strong logic and every
//! operator whose semantics are uncertain returns `Unknown` when the
//! uncertainty matters. This is not Windows Update: it is a model checked
//! against the public schema pages and the stored catalog, and each operator
//! carries an evidence label ([`Evidence`]) in [`OPERATORS`]. Nothing here
//! has been compared with a native client until a differential run exists
//! (`tests/applicability_differential.rs`).
//!
//! * [`expr`]: expressions, parser;
//! * [`facts`]: provider trait, [`FakeFacts`], [`NoFacts`];
//! * [`recorded`]: snapshot format and [`RecordedFacts`];
//! * [`eval`]: [`Tri`], [`Outcome`], [`evaluate`];
//! * [`queries`]: static listing of the queries an expression needs;
//! * [`operators`]: the operator/evidence table.
pub mod eval;
pub mod expr;
pub mod facts;
pub mod operators;
pub mod queries;
pub mod recorded;
pub mod value;

pub use eval::{Blocker, Outcome, Tri, evaluate};
pub use expr::{Expr, Family, Operator, RegView, Unsupported, UnsupportedReason};
pub use facts::{Fact, FactProvider, FakeFacts, FileInfo, FileLocation, NoFacts, OsInfo, RegValue};
pub use operators::{Evidence, OPERATORS};
pub use queries::{QueryItem, required_queries};
pub use recorded::{FactQuery, RecordedFacts, Snapshot, SnapshotError};

use self::expr::MsiProductRule;
use self::value::canon_guid;
use crate::metadata::FragmentIndex;
use crate::soap::xml::Element;

/// Rule section names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    IsInstalled,
    IsInstallable,
    IsSuperseded,
}

impl SectionKind {
    /// Element name.
    pub fn name(self) -> &'static str {
        match self {
            SectionKind::IsInstalled => "IsInstalled",
            SectionKind::IsInstallable => "IsInstallable",
            SectionKind::IsSuperseded => "IsSuperseded",
        }
    }
}

/// A boolean rule section: its children combined as one expression.
///
/// A section with several child expressions is their conjunction (the "EXE
/// detection logic" example of the WSUS SDK lists two sibling rules in
/// `IsInstallable`; Specified by example). An empty section is kept as an
/// unsupported node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub expr: Expr,
}

impl Section {
    fn parse(el: &Element) -> Section {
        let mut kids: Vec<Expr> = el.elements().map(Expr::parse).collect();
        let expr = match kids.len() {
            0 => Expr::Unsupported(Box::new(Unsupported {
                name: el.name.local.clone(),
                reason: UnsupportedReason::Malformed("empty rule section".into()),
                element: el.clone(),
            })),
            1 => kids.remove(0),
            _ => Expr::And(kids),
        };
        Section { expr }
    }
}

/// Parsed `ApplicabilityRules`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplicabilityRules {
    pub is_installed: Option<Section>,
    pub is_installable: Option<Section>,
    pub is_superseded: Option<Section>,
    /// `Metadata` children, kept verbatim (not interpreted).
    pub metadata: Vec<Element>,
    /// Every other child of `ApplicabilityRules` (unknown sections,
    /// duplicate sections), kept verbatim.
    pub other: Vec<Element>,
}

impl ApplicabilityRules {
    /// Parse an `ApplicabilityRules` element. Never fails and never drops a
    /// child.
    pub fn from_element(el: &Element) -> Self {
        let mut out = Self::default();
        for c in el.elements() {
            let local = c.name.local.as_str();
            let bare = local.rsplit(['.', ':']).next().unwrap_or(local);
            let slot = match bare {
                "IsInstalled" => Some(&mut out.is_installed),
                "IsInstallable" => Some(&mut out.is_installable),
                "IsSuperseded" => Some(&mut out.is_superseded),
                "Metadata" => {
                    out.metadata.push(c.clone());
                    continue;
                }
                _ => None,
            };
            match slot {
                Some(s) if s.is_none() => *s = Some(Section::parse(c)),
                _ => out.other.push(c.clone()),
            }
        }
        out.resolve_msi_application();
        out.resolve_msi_patch();
        out.resolve_cbs_package();
        out
    }

    /// Product code of `Metadata/MsiApplicationMetadata/ProductCode`, canonical `{UPPER}` form.
    fn msi_application_product(&self) -> Option<String> {
        fn bare(el: &Element) -> &str {
            let l = el.name.local.as_str();
            l.rsplit(['.', ':']).next().unwrap_or(l)
        }
        self.metadata
            .iter()
            .flat_map(|m| m.elements())
            .filter(|m| bare(m) == "MsiApplicationMetadata")
            .flat_map(|m| m.elements())
            .find(|c| bare(c) == "ProductCode")
            .map(|c| canon_guid(c.text().trim()))
    }

    /// `MsiApplicationInstalled` and `MsiApplicationInstallable` take no attributes: the product is
    /// named by the update's own `Metadata` (OBSERVED on a real WSUS 10.0.26100 publishing an MSI:
    /// `<m.MsiApplicationMetadata><m.ProductCode>{...}</m.ProductCode>`). They are resolved against
    /// that product code. Implementation decision, Unverified against a native agent (MSI-gated
    /// updates are not observable through it): Installed is the product being installed
    /// (`MsiProductInstalled` with no version bounds) and Installable is its negation.
    /// `MsiApplicationSuperseded` stays unsupported (supersedence is carried by the relationships).
    fn resolve_msi_application(&mut self) {
        let Some(product) = self.msi_application_product() else {
            return;
        };
        let installed = || {
            Expr::Op(Operator::MsiProductInstalled(MsiProductRule {
                product: product.clone(),
                version_min: None,
                exclude_version_min: false,
                version_max: None,
                exclude_version_max: false,
                language: None,
            }))
        };
        for s in [
            &mut self.is_installed,
            &mut self.is_installable,
            &mut self.is_superseded,
        ]
        .into_iter()
        .flatten()
        {
            s.expr = resolve_expr(std::mem::replace(&mut s.expr, Expr::True), &installed);
        }
    }

    /// `MsiPatchInstalled` and `MsiPatchInstallable` take no attributes either: the patch and its
    /// targets come from `Metadata/MsiPatchMetadata/MsiPatch` (OBSERVED on a real WSUS 10.0.26100
    /// publishing a WiX-built `.msp`: `PatchGUID`, one `TargetProduct` per target with
    /// `TargetProductCode` and a `TargetVersion` that has `ComparisonType` and `ComparisonFilter`).
    /// Implementation decisions, Unverified against a native agent (MSI-gated updates are not
    /// observable through it):
    /// * Installed: the patch is applied to any of the target products
    ///   (`MsiPatchInstalledForProduct`);
    /// * Installable: a target product is installed within its `TargetVersion` bounds and the patch
    ///   is not installed.
    ///
    /// `MsiPatchSuperseded` stays unsupported (it needs the patch sequence of the patch family).
    fn resolve_msi_patch(&mut self) {
        let Some(patch) = self.msi_patch_metadata() else {
            return;
        };
        let installed = || {
            let v: Vec<Expr> = patch
                .targets
                .iter()
                .map(|t| {
                    Expr::Op(Operator::MsiPatchInstalledForProduct {
                        patch: patch.code.clone(),
                        product: t.product.clone(),
                    })
                })
                .collect();
            if v.len() == 1 {
                v.into_iter().next().unwrap_or(Expr::False)
            } else {
                Expr::Or(v)
            }
        };
        let installable = || {
            let targets: Vec<Expr> = patch
                .targets
                .iter()
                .map(|t| Expr::Op(Operator::MsiProductInstalled(t.rule())))
                .collect();
            Expr::And(vec![Expr::Or(targets), Expr::Not(Box::new(installed()))])
        };
        for s in [
            &mut self.is_installed,
            &mut self.is_installable,
            &mut self.is_superseded,
        ]
        .into_iter()
        .flatten()
        {
            s.expr = resolve_patch_expr(
                std::mem::replace(&mut s.expr, Expr::True),
                &installed,
                &installable,
            );
        }
    }

    fn msi_patch_metadata(&self) -> Option<MsiPatchTargets> {
        fn bare(el: &Element) -> &str {
            let l = el.name.local.as_str();
            l.rsplit(['.', ':']).next().unwrap_or(l)
        }
        let patch = self
            .metadata
            .iter()
            .flat_map(|m| m.elements())
            .filter(|m| bare(m) == "MsiPatchMetadata")
            .flat_map(|m| m.elements())
            .find(|p| bare(p) == "MsiPatch")?;
        let code = canon_guid(patch.attr("PatchGUID")?.trim());
        let mut targets = Vec::new();
        for tp in patch.elements().filter(|e| bare(e) == "TargetProduct") {
            let Some(product) = tp
                .elements()
                .find(|e| bare(e) == "TargetProductCode")
                .map(|e| canon_guid(e.text().trim()))
            else {
                continue;
            };
            let mut t = MsiPatchTarget {
                product,
                version: None,
            };
            if let Some(v) = tp.elements().find(|e| bare(e) == "TargetVersion")
                && v.attr("Validate")
                    .is_none_or(|x| x.eq_ignore_ascii_case("true"))
            {
                t.version = Some((
                    v.attr("ComparisonType").unwrap_or("Equal").to_owned(),
                    v.attr("ComparisonFilter").map(str::to_owned),
                    v.text().trim().to_owned(),
                ));
            }
            targets.push(t);
        }
        if targets.is_empty() {
            targets = patch
                .elements()
                .filter(|e| bare(e) == "TargetProductCode")
                .map(|e| MsiPatchTarget {
                    product: canon_guid(e.text().trim()),
                    version: None,
                })
                .collect();
        }
        (!targets.is_empty()).then_some(MsiPatchTargets { code, targets })
    }

    /// Identity of the CBS package an update installs, from
    /// `Metadata/CbsPackageApplicabilityMetadata/assembly/assemblyIdentity` (OBSERVED on a real
    /// Windows 11 catalog): `name~publicKeyToken~processorArchitecture~language~version`, with the
    /// language `neutral` written as an empty field (the format of the identities of
    /// `CbsPackageInstalledByIdentity`, for example `Package_for_KB4474419~31bf3856ad364e35~amd64~~6.1.3.2`).
    pub fn cbs_package_identity(&self) -> Option<String> {
        fn bare(el: &Element) -> &str {
            let l = el.name.local.as_str();
            l.rsplit(['.', ':']).next().unwrap_or(l)
        }
        let id = self
            .metadata
            .iter()
            .flat_map(|m| m.elements())
            .filter(|m| bare(m) == "CbsPackageApplicabilityMetadata")
            .flat_map(|m| m.elements())
            .filter(|a| bare(a) == "assembly")
            .flat_map(|a| a.elements())
            .find(|i| bare(i) == "assemblyIdentity")?;
        let get = |n: &str| id.attr(n).map(str::trim).filter(|v| !v.is_empty());
        let language = match get("language") {
            Some("neutral") | None => "",
            Some(l) => l,
        };
        Some(format!(
            "{}~{}~{}~{}~{}",
            get("name")?,
            get("publicKeyToken")?,
            get("processorArchitecture")?,
            language,
            get("version")?
        ))
    }

    /// `CbsPackageInstalled` takes no attributes: the package is named by the update's own metadata.
    /// Implementation decision, Unverified against a native agent: it is `CbsPackageInstalledByIdentity`
    /// of that identity. `CbsPackageInstallable` stays unsupported (it needs the component store).
    fn resolve_cbs_package(&mut self) {
        let Some(identity) = self.cbs_package_identity() else {
            return;
        };
        if let Some(s) = self.is_installed.as_mut() {
            s.expr = resolve_cbs_expr(std::mem::replace(&mut s.expr, Expr::True), &identity);
        }
    }

    /// Parse the rules of a fragment index; `None` when it has none.
    pub fn from_fragment(index: &FragmentIndex) -> Option<Self> {
        index.applicability_rules.as_ref().map(Self::from_element)
    }

    /// The section of `kind`.
    pub fn section(&self, kind: SectionKind) -> Option<&Section> {
        match kind {
            SectionKind::IsInstalled => self.is_installed.as_ref(),
            SectionKind::IsInstallable => self.is_installable.as_ref(),
            SectionKind::IsSuperseded => self.is_superseded.as_ref(),
        }
    }

    /// Evaluate a section. A missing section is `Unknown` with an
    /// [`Blocker::Undecidable`] saying so: the pages do not define what a
    /// missing `IsInstalled` means.
    pub fn evaluate(&self, kind: SectionKind, facts: &dyn FactProvider) -> Outcome {
        match self.section(kind) {
            Some(s) => evaluate(&s.expr, facts),
            None => Outcome {
                value: Tri::Unknown,
                blockers: vec![Blocker::Undecidable {
                    operator: kind.name().to_owned(),
                    why: "rule section absent; its meaning is not specified".into(),
                }],
            },
        }
    }

    /// All unsupported nodes of the boolean sections.
    pub fn unsupported(&self) -> Vec<&Unsupported> {
        [
            &self.is_installed,
            &self.is_installable,
            &self.is_superseded,
        ]
        .into_iter()
        .flatten()
        .flat_map(|s| s.expr.unsupported())
        .collect()
    }

    /// True when the sections hold no unsupported node and nothing was kept
    /// in `other`.
    pub fn is_fully_supported(&self) -> bool {
        self.other.is_empty() && self.unsupported().is_empty()
    }
}

/// The patch and the products it targets, from `MsiPatchMetadata`.
struct MsiPatchTargets {
    /// Canonical `{UPPER}` patch code.
    code: String,
    targets: Vec<MsiPatchTarget>,
}

struct MsiPatchTarget {
    product: String,
    /// `(ComparisonType, ComparisonFilter, version)` of `TargetVersion` when it is validated.
    version: Option<(String, Option<String>, String)>,
}

impl MsiPatchTarget {
    /// The product filter: the product, within the `TargetVersion` bounds.
    ///
    /// `ComparisonFilter` says how many fields take part in an `Equal` comparison (`Major`,
    /// `MajorMinor`, `MajorMinorUpdate`, default all). An MSI `ProductVersion` has three fields
    /// (255.255.65535), which bounds the ranges. Other comparison types use the whole version.
    fn rule(&self) -> MsiProductRule {
        let mut r = MsiProductRule {
            product: self.product.clone(),
            version_min: None,
            exclude_version_min: false,
            version_max: None,
            exclude_version_max: false,
            language: None,
        };
        let Some((ty, filter, text)) = &self.version else {
            return r;
        };
        let parts: Vec<&str> = text.split('.').collect();
        let field = |i: usize| parts.get(i).copied().unwrap_or("0");
        let ver = |s: String| value::MsiVersion::parse(&s);
        match ty.as_str() {
            "Equal" => {
                let (lo, hi) = match filter.as_deref() {
                    Some("Major") => (
                        format!("{}.0.0", field(0)),
                        format!("{}.255.65535", field(0)),
                    ),
                    Some("MajorMinor") => (
                        format!("{}.{}.0", field(0), field(1)),
                        format!("{}.{}.65535", field(0), field(1)),
                    ),
                    Some("MajorMinorUpdate") => (
                        format!("{}.{}.{}", field(0), field(1), field(2)),
                        format!("{}.{}.{}", field(0), field(1), field(2)),
                    ),
                    _ => (text.clone(), text.clone()),
                };
                r.version_min = ver(lo);
                r.version_max = ver(hi);
            }
            "GreaterThanOrEqual" => r.version_min = ver(text.clone()),
            "GreaterThan" => {
                r.version_min = ver(text.clone());
                r.exclude_version_min = true;
            }
            "LessThanOrEqual" => r.version_max = ver(text.clone()),
            "LessThan" => {
                r.version_max = ver(text.clone());
                r.exclude_version_max = true;
            }
            _ => {}
        }
        r
    }
}

fn resolve_patch_expr(
    e: Expr,
    installed: &dyn Fn() -> Expr,
    installable: &dyn Fn() -> Expr,
) -> Expr {
    match e {
        Expr::Unsupported(u) => {
            let bare = u.name.rsplit(['.', ':']).next().unwrap_or(&u.name);
            match bare {
                "MsiPatchInstalled" => installed(),
                "MsiPatchInstallable" => installable(),
                _ => Expr::Unsupported(u),
            }
        }
        Expr::And(v) => Expr::And(
            v.into_iter()
                .map(|x| resolve_patch_expr(x, installed, installable))
                .collect(),
        ),
        Expr::Or(v) => Expr::Or(
            v.into_iter()
                .map(|x| resolve_patch_expr(x, installed, installable))
                .collect(),
        ),
        Expr::Not(b) => Expr::Not(Box::new(resolve_patch_expr(*b, installed, installable))),
        other => other,
    }
}

fn resolve_cbs_expr(e: Expr, identity: &str) -> Expr {
    match e {
        Expr::Unsupported(u) => {
            let bare = u.name.rsplit(['.', ':']).next().unwrap_or(&u.name);
            if bare == "CbsPackageInstalled" {
                Expr::Op(Operator::CbsPackageInstalled {
                    identity: identity.to_owned(),
                })
            } else {
                Expr::Unsupported(u)
            }
        }
        Expr::And(v) => Expr::And(
            v.into_iter()
                .map(|x| resolve_cbs_expr(x, identity))
                .collect(),
        ),
        Expr::Or(v) => Expr::Or(
            v.into_iter()
                .map(|x| resolve_cbs_expr(x, identity))
                .collect(),
        ),
        Expr::Not(b) => Expr::Not(Box::new(resolve_cbs_expr(*b, identity))),
        other => other,
    }
}

fn resolve_expr(e: Expr, installed: &dyn Fn() -> Expr) -> Expr {
    match e {
        Expr::Unsupported(u) => {
            let bare = u.name.rsplit(['.', ':']).next().unwrap_or(&u.name);
            match bare {
                "MsiApplicationInstalled" => installed(),
                "MsiApplicationInstallable" => Expr::Not(Box::new(installed())),
                _ => Expr::Unsupported(u),
            }
        }
        Expr::And(v) => Expr::And(v.into_iter().map(|x| resolve_expr(x, installed)).collect()),
        Expr::Or(v) => Expr::Or(v.into_iter().map(|x| resolve_expr(x, installed)).collect()),
        Expr::Not(b) => Expr::Not(Box::new(resolve_expr(*b, installed))),
        other => other,
    }
}

#[cfg(test)]
mod msi_application_tests {
    use super::*;
    use crate::soap::Limits;
    use crate::soap::xml::parse_fragments;

    /// The `ApplicabilityRules` of an MSI update as a real WSUS 10.0.26100 serves it.
    const REAL_RULES: &str = r#"<ApplicabilityRules><IsInstalled><m.MsiApplicationInstalled /></IsInstalled><IsSuperseded><m.MsiApplicationSuperseded /></IsSuperseded><IsInstallable><m.MsiApplicationInstallable /></IsInstallable><Metadata><m.MsiApplicationMetadata><m.ProductCode>{a1b2c3d4-0001-4000-8000-000000000100}</m.ProductCode></m.MsiApplicationMetadata></Metadata></ApplicabilityRules>"#;

    fn rules() -> ApplicabilityRules {
        let els = parse_fragments(REAL_RULES.as_bytes(), &Limits::default()).unwrap();
        ApplicabilityRules::from_element(&els[0])
    }

    #[test]
    fn msi_application_operators_resolve_against_the_metadata_product_code() {
        let r = rules();
        assert_eq!(
            r.is_installed.as_ref().unwrap().expr,
            Expr::Op(Operator::MsiProductInstalled(MsiProductRule {
                product: "{A1B2C3D4-0001-4000-8000-000000000100}".into(),
                version_min: None,
                exclude_version_min: false,
                version_max: None,
                exclude_version_max: false,
                language: None,
            }))
        );
        assert!(matches!(
            r.is_installable.as_ref().unwrap().expr,
            Expr::Not(_)
        ));
        // supersedence is not decided by this operator
        assert_eq!(r.unsupported().len(), 1);
    }

    #[test]
    fn msi_application_without_metadata_stays_unsupported() {
        let xml = r#"<ApplicabilityRules><IsInstalled><m.MsiApplicationInstalled /></IsInstalled></ApplicabilityRules>"#;
        let els = parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
        let r = ApplicabilityRules::from_element(&els[0]);
        assert_eq!(r.unsupported().len(), 1);
    }

    #[test]
    fn installed_and_installable_follow_live_msi_facts() {
        use super::facts::FakeFacts;
        let r = rules();
        let none = FakeFacts::default();
        assert_eq!(
            r.evaluate(SectionKind::IsInstalled, &none).value,
            Tri::False
        );
        assert_eq!(
            r.evaluate(SectionKind::IsInstallable, &none).value,
            Tri::True
        );
    }
}

#[cfg(test)]
mod msi_patch_tests {
    use super::facts::FakeFacts;
    use super::*;
    use crate::soap::Limits;
    use crate::soap::xml::parse_fragments;

    const PRODUCT: &str = "{A1B2C3D4-0007-4000-8000-000000000700}";
    const PATCH: &str = "{7FF3F06A-EB31-4490-98F1-BDD5803E2C36}";

    /// The `ApplicabilityRules` of an MSP update as a real WSUS 10.0.26100 serves it.
    const REAL_RULES: &str = r#"<ApplicabilityRules><IsInstalled><m.MsiPatchInstalled /></IsInstalled><IsSuperseded><m.MsiPatchSuperseded /></IsSuperseded><IsInstallable><m.MsiPatchInstallable /></IsInstallable><Metadata><m.MsiPatchMetadata><MsiPatch SchemaVersion="1.0.0.0" PatchGUID="{7FF3F06A-EB31-4490-98F1-BDD5803E2C36}" MinMsiVersion="5" xmlns="http://www.microsoft.com/msi/patch_applicability.xsd"><TargetProduct MinMsiVersion="200"><TargetProductCode Validate="true">{A1B2C3D4-0007-4000-8000-000000000700}</TargetProductCode><TargetVersion Validate="true" ComparisonType="Equal" ComparisonFilter="MajorMinorUpdate">1.0.0</TargetVersion><TargetLanguage Validate="false">1033</TargetLanguage><UpdatedLanguages>1033</UpdatedLanguages><UpgradeCode Validate="true">{6F1A2B3C-4D5E-4F60-8A71-92B3C4D5E703}</UpgradeCode></TargetProduct><TargetProductCode>{A1B2C3D4-0007-4000-8000-000000000700}</TargetProductCode><SequenceData><PatchFamily>WsusPatchFamily</PatchFamily><Sequence>1.0.0.1</Sequence><Attributes>1</Attributes></SequenceData></MsiPatch></m.MsiPatchMetadata></Metadata></ApplicabilityRules>"#;

    fn rules() -> ApplicabilityRules {
        let els = parse_fragments(REAL_RULES.as_bytes(), &Limits::default()).unwrap();
        ApplicabilityRules::from_element(&els[0])
    }

    fn facts(version: Option<&str>, patched: bool) -> FakeFacts {
        let mut f = FakeFacts::default();
        if let Some(v) = version {
            f.add_msi_product(PRODUCT, v, Some(1033));
        }
        if patched {
            f.add_msi_patch(PRODUCT, PATCH);
        }
        f
    }

    #[test]
    fn msi_patch_operators_resolve_against_the_patch_metadata() {
        let r = rules();
        assert_eq!(
            r.is_installed.as_ref().unwrap().expr,
            Expr::Op(Operator::MsiPatchInstalledForProduct {
                patch: PATCH.into(),
                product: PRODUCT.into()
            })
        );
        // supersedence is not decided here
        assert_eq!(r.unsupported().len(), 1);
    }

    #[test]
    fn installed_when_the_patch_is_applied_to_the_target() {
        let r = rules();
        assert_eq!(
            r.evaluate(SectionKind::IsInstalled, &facts(Some("1.0.0"), true))
                .value,
            Tri::True
        );
        assert_eq!(
            r.evaluate(SectionKind::IsInstalled, &facts(Some("1.0.0"), false))
                .value,
            Tri::False
        );
    }

    #[test]
    fn installable_needs_the_target_product_in_range_and_no_patch() {
        let r = rules();
        let installable = |f: &FakeFacts| r.evaluate(SectionKind::IsInstallable, f).value;
        assert_eq!(installable(&facts(Some("1.0.0"), false)), Tri::True);
        assert_eq!(installable(&facts(Some("1.0.0"), true)), Tri::False);
        assert_eq!(installable(&facts(None, false)), Tri::False);
        // MajorMinorUpdate equality: another update level is out of range
        assert_eq!(installable(&facts(Some("1.0.1"), false)), Tri::False);
    }

    #[test]
    fn major_minor_filter_and_ordering_comparisons_set_the_bounds() {
        let t = |ty: &str, filter: Option<&str>| MsiPatchTarget {
            product: PRODUCT.into(),
            version: Some((ty.into(), filter.map(str::to_owned), "2.3.4".into())),
        };
        let r = t("Equal", Some("MajorMinor")).rule();
        assert_eq!(r.version_min, value::MsiVersion::parse("2.3.0"));
        assert_eq!(r.version_max, value::MsiVersion::parse("2.3.65535"));
        let r = t("GreaterThan", None).rule();
        assert!(r.exclude_version_min && r.version_max.is_none());
        let r = t("LessThanOrEqual", None).rule();
        assert!(!r.exclude_version_max && r.version_max == value::MsiVersion::parse("2.3.4"));
    }

    #[test]
    fn patch_without_metadata_stays_unsupported() {
        let xml = r#"<ApplicabilityRules><IsInstalled><m.MsiPatchInstalled /></IsInstalled></ApplicabilityRules>"#;
        let els = parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
        assert_eq!(
            ApplicabilityRules::from_element(&els[0])
                .unsupported()
                .len(),
            1
        );
    }
}

#[cfg(test)]
mod windows_servicing_tests {
    use super::*;
    use crate::metadata::{
        FragmentOrigin, FragmentSource, RawFragment, SLIMMED_DESCENDANTS_ATTR, UpdateIndex,
    };
    use crate::soap::Limits;

    // Real Core fragments of a Windows 11 catalog synced from a Windows Server 2025 WSUS on 2026-10-05.
    // The two CBS cores are the real XML with the package manifest reduced to its identity (the
    // fixture README gives the original sizes).
    const DOTNET_CORE: &str =
        include_str!("../../../../docs/fixtures/wsus-m0-cbs/cbs-dotnet-core-reduced.xml");
    const ROLLUP_CORE: &str =
        include_str!("../../../../docs/fixtures/wsus-m0-cbs/cbs-rollupfix-core-reduced.xml");
    const OSI_CORE: &str =
        include_str!("../../../../docs/fixtures/wsus-m0-cbs/osinstaller-core.xml");

    fn index(xml: &str) -> UpdateIndex {
        let raw = RawFragment::from_xml_text(
            FragmentOrigin::new(FragmentSource::Other("test".into())),
            xml,
        );
        UpdateIndex::from_fragments([&raw], None, &Limits::default()).unwrap()
    }

    fn rules(xml: &str) -> ApplicabilityRules {
        ApplicabilityRules::from_element(index(xml).applicability_rules.as_ref().unwrap())
    }

    #[test]
    fn cbs_package_identity_comes_from_the_manifest_metadata() {
        assert_eq!(
            rules(ROLLUP_CORE).cbs_package_identity().as_deref(),
            Some("Package_for_RollupFix~31bf3856ad364e35~arm64~~22000.1936.1.9")
        );
        // attribute order differs between manifests; the identity does not depend on it
        assert_eq!(
            rules(DOTNET_CORE).cbs_package_identity().as_deref(),
            Some("Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9082.7")
        );
    }

    #[test]
    fn cbs_installed_follows_the_package_state_and_the_reoffer_flag() {
        let r = rules(ROLLUP_CORE);
        let id = r.cbs_package_identity().unwrap();
        let mut facts = FakeFacts::default();
        facts.set_cbs_package(&id, facts::CBS_STATE_INSTALLED);
        // the LCUReoffer registry value is absent: installed
        let o = r.evaluate(SectionKind::IsInstalled, &facts);
        assert_eq!(o.value, Tri::True, "{:?}", o.blockers);
        // the package is absent: not installed (the registry operand is not needed)
        let none = FakeFacts::default();
        assert_ne!(r.evaluate(SectionKind::IsInstalled, &none).value, Tri::True);
    }

    #[test]
    fn cbs_installable_stays_unsupported_with_its_reason() {
        let r = rules(DOTNET_CORE);
        let o = r.evaluate(SectionKind::IsInstallable, &FakeFacts::default());
        assert_eq!(o.value, Tri::Unknown);
        assert!(
            o.blockers
                .iter()
                .any(|b| b.to_string().contains("CbsPackageInstallable")),
            "{:?}",
            o.blockers
        );
    }

    #[test]
    fn os_installer_rules_parse_and_decide_by_os_build() {
        let r = rules(OSI_CORE);
        // ProductReleaseInstalled is an implemented operator now
        assert!(
            r.unsupported()
                .iter()
                .all(|u| u.name != "ProductReleaseInstalled")
        );
        let mut facts = FakeFacts::default();
        facts.set_os(OsInfo {
            major: 10,
            minor: 0,
            build: 26200,
            product_type: 1,
            ..OsInfo::default()
        });
        // the update is for builds 22621.x only: a 26200 machine is definitely not in range, whatever
        // the SKU (Kleene And with a False operand)
        let o = r.evaluate(SectionKind::IsInstallable, &facts);
        assert_eq!(o.value, Tri::False, "{:?}", o.blockers);
        // on a 22621 machine whose revision and SKU are not facts the answer is Unknown
        let mut facts = FakeFacts::default();
        facts.set_os(OsInfo {
            major: 10,
            minor: 0,
            build: 22621,
            product_type: 1,
            ..OsInfo::default()
        });
        assert_eq!(
            r.evaluate(SectionKind::IsInstallable, &facts).value,
            Tri::Unknown
        );
    }

    fn os_machine(build: u32, ubr: Option<u32>, sku: Option<u32>, arch: u32) -> FakeFacts {
        let mut f = FakeFacts::default();
        f.set_os(OsInfo {
            major: 10,
            minor: 0,
            build,
            product_type: 1,
            sku,
            ubr,
            ..OsInfo::default()
        });
        f.set_architecture(arch);
        f
    }

    #[test]
    fn real_os_installer_installability_uses_the_sku_and_the_revision() {
        // OSI_CORE is a real ARM64 update for builds 22621.1 to 22622.0 and SKUs 4, 188, 27, 72, 121,
        // 122, 175, 136 (and not 119).
        let r = rules(OSI_CORE);
        let at = |sku: Option<u32>, ubr: Option<u32>| {
            r.evaluate(SectionKind::IsInstallable, &os_machine(22621, ubr, sku, 12))
                .value
        };
        assert_eq!(at(Some(4), Some(6000)), Tri::True);
        assert_eq!(
            at(Some(48), Some(6000)),
            Tri::False,
            "Pro is not in the SKU list"
        );
        assert_eq!(at(Some(119), Some(6000)), Tri::False);
        assert_eq!(at(None, Some(6000)), Tri::Unknown, "the SKU is not a fact");
        assert_eq!(
            at(Some(4), None),
            Tri::Unknown,
            "the revision is not a fact"
        );
    }

    #[test]
    fn product_release_installed_for_client_os_compares_the_os_version() {
        // the real ARM64 update: IsInstalled is Client.OS.RS2.ARM64 10.0.22621.5909
        let r = rules(OSI_CORE);
        let installed = |build, ubr, arch| {
            r.evaluate(
                SectionKind::IsInstalled,
                &os_machine(build, ubr, Some(4), arch),
            )
            .value
        };
        assert_eq!(installed(22621, Some(5909), 12), Tri::True);
        assert_eq!(installed(22621, Some(6000), 12), Tri::True);
        assert_eq!(installed(22621, Some(5000), 12), Tri::False);
        assert_eq!(
            installed(26200, Some(1), 12),
            Tri::True,
            "a newer build is at least as new"
        );
        assert_eq!(
            installed(22621, Some(6000), 9),
            Tri::False,
            "another architecture"
        );
        assert_eq!(
            installed(22621, None, 12),
            Tri::Unknown,
            "the revision is not a fact"
        );
    }

    #[test]
    fn recorded_pre_and_post_reboot_states_of_the_dotnet_rollup_read_as_observed() {
        let fx: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/fixtures/wsus-m0-osinstaller/dotnet-cbs-state.json"
        ))
        .unwrap();
        let base = fx["base"].as_str().unwrap();
        let (pkg, old) = (
            fx["package"].as_str().unwrap(),
            fx["old_package"].as_str().unwrap(),
        );
        let installed_rule = r#"<ApplicabilityRules><IsInstalled><ProductReleaseInstalled Name="Microsoft.NetFX.amd64" Version="2400.26200.9347.1" /></IsInstalled></ApplicabilityRules>"#;
        let present_rule = r#"<ApplicabilityRules><IsInstalled><ProductReleaseVersion Name="Microsoft.NetFX.amd64" Version="0.0.0.0" Comparison="greaterthan" /></IsInstalled></ApplicabilityRules>"#;
        let rule = |x: &str| {
            let els = crate::soap::xml::parse_fragments(x.as_bytes(), &Limits::default()).unwrap();
            ApplicabilityRules::from_element(&els[0])
        };
        let (inst, pres) = (rule(installed_rule), rule(present_rule));
        for st in fx["states"].as_array().unwrap() {
            let mut f = os_machine(26200, Some(8037), Some(48), 9);
            for (id, key) in [(pkg, "package_current_state"), (old, "old_current_state")] {
                let sub = format!("{base}\\Packages\\{id}");
                f.add_key(RegView::Native, &sub);
                f.set_value(
                    RegView::Native,
                    &sub,
                    "CurrentState",
                    RegValue::Dword(st[key].as_u64().unwrap() as u32),
                );
            }
            if st["packages_pending_lists_package"].as_bool() == Some(true) {
                f.add_key(RegView::Native, &format!("{base}\\PackagesPending\\{pkg}"));
            }
            let want_installed = st["dism_state"] == "Installed";
            let got = inst.evaluate(SectionKind::IsInstalled, &f).value;
            assert_eq!(got == Tri::True, want_installed, "{}", st["name"]);
            assert_eq!(
                pres.evaluate(SectionKind::IsInstalled, &f).value,
                Tri::True,
                "{}: .NET is present in every state",
                st["name"]
            );
        }
    }

    #[test]
    fn product_release_version_greaterthan_zero_reads_the_product_as_present() {
        let rule = |name: &str| {
            let xml = format!(
                r#"<ApplicabilityRules><IsInstalled><ProductReleaseVersion Name="{name}" Version="0.0.0.0" Comparison="greaterthan" /></IsInstalled></ApplicabilityRules>"#
            );
            let els =
                crate::soap::xml::parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
            ApplicabilityRules::from_element(&els[0])
        };
        let eval =
            |name: &str, f: &FakeFacts| rule(name).evaluate(SectionKind::IsInstalled, f).value;
        let client_x64 = os_machine(26200, Some(8037), Some(48), 9);
        assert_eq!(eval("Client.OS.RS2.AMD64", &client_x64), Tri::True);
        assert_eq!(eval("Client.OS.RS2.ARM64", &client_x64), Tri::False);
        assert_eq!(eval("Server.OS.amd64", &client_x64), Tri::False);
        assert_eq!(
            eval("Windows.EmergencyUpdate.amd64", &client_x64),
            Tri::Unknown
        );
        assert_eq!(
            eval("Microsoft.NetFX.amd64", &client_x64),
            Tri::False,
            "no rollup installed"
        );
        let other = r#"<ApplicabilityRules><IsInstalled><ProductReleaseVersion Name="Client.OS.RS2.AMD64" Version="1.0.0.0" Comparison="greaterthan" /></IsInstalled></ApplicabilityRules>"#;
        let els = crate::soap::xml::parse_fragments(other.as_bytes(), &Limits::default()).unwrap();
        assert_ne!(
            ApplicabilityRules::from_element(&els[0])
                .evaluate(SectionKind::IsInstalled, &client_x64)
                .value,
            Tri::True,
            "only the 0.0.0.0 reading is implemented"
        );
    }

    #[test]
    fn product_release_installed_for_netfx_reads_the_installed_rollup_packages() {
        let xml = r#"<ApplicabilityRules><IsInstalled><ProductReleaseInstalled Name="Microsoft.NetFX.amd64" Version="2400.26200.9347.1" /></IsInstalled></ApplicabilityRules>"#;
        let els = crate::soap::xml::parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
        let r = ApplicabilityRules::from_element(&els[0]);
        const KEY: &str =
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";
        let with = |version: &str, state: u32, arch: &str| {
            let mut f = os_machine(26200, Some(8037), Some(48), 9);
            let sub =
                format!("{KEY}\\Package_for_DotNetRollup_481~31bf3856ad364e35~{arch}~~{version}");
            f.add_key(RegView::Native, &sub);
            f.set_value(
                RegView::Native,
                &sub,
                "CurrentState",
                RegValue::Dword(state),
            );
            f
        };
        let eval = |f: &FakeFacts| r.evaluate(SectionKind::IsInstalled, f).value;
        assert_eq!(eval(&with("10.0.9347.1", 112, "amd64")), Tri::True);
        let mut pending = with("10.0.9347.1", 112, "amd64");
        pending.add_key(
            RegView::Native,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending\\Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9347.1",
        );
        assert_eq!(
            eval(&pending),
            Tri::False,
            "a package listed under PackagesPending is not installed yet"
        );
        assert_eq!(
            eval(&with("10.0.9400.2", 112, "amd64")),
            Tri::True,
            "a newer rollup is enough"
        );
        assert_eq!(
            eval(&with("10.0.9321.3", 112, "amd64")),
            Tri::False,
            "the older rollup"
        );
        assert_eq!(
            eval(&with("10.0.9347.1", 64, "amd64")),
            Tri::False,
            "install pending is not installed"
        );
        assert_eq!(
            eval(&with("10.0.9347.1", 112, "arm64")),
            Tri::False,
            "another architecture"
        );
        assert_eq!(
            eval(&os_machine(26200, Some(8037), Some(48), 9)),
            Tri::False,
            "no rollup at all"
        );
    }

    #[test]
    fn device_attribute_product_type_maps_registry_strings() {
        let xml = |v: &str| {
            format!(
                r#"<ApplicabilityRules><IsInstallable><DeviceAttribute Name="ProductType" Type="String" Comparison="EqualTo" Value="{v}" /></IsInstallable></ApplicabilityRules>"#
            )
        };
        let mut facts = FakeFacts::default();
        facts.set_os(OsInfo {
            product_type: 3,
            ..OsInfo::default()
        });
        for (value, want) in [
            ("ServerNT", Tri::True),
            ("WinNT", Tri::False),
            ("LanmanNT", Tri::False),
        ] {
            let els = crate::soap::xml::parse_fragments(xml(value).as_bytes(), &Limits::default())
                .unwrap();
            let r = ApplicabilityRules::from_element(&els[0]);
            assert_eq!(
                r.evaluate(SectionKind::IsInstallable, &facts).value,
                want,
                "{value}"
            );
        }
    }

    #[test]
    fn oversized_cbs_manifest_is_slimmed_in_the_index() {
        // a manifest with 20,000 component elements stands for the real 47 MB ones
        let mut body = String::new();
        for i in 0..20_000 {
            body.push_str(&format!(
                r#"<component><assemblyIdentity name="c{i}" /></component>"#
            ));
        }
        let xml = format!(
            r#"<UpdateIdentity UpdateID="11111111-2222-3333-4444-555555555555" RevisionNumber="1" /><Properties UpdateType="Software" /><ApplicabilityRules><IsInstalled><CbsPackageInstalled /></IsInstalled><Metadata><CbsPackageApplicabilityMetadata><assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Package_for_X" version="1.2.3.4" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" /><package identifier="KB1" restart="possible">{body}</package></assembly></CbsPackageApplicabilityMetadata></Metadata></ApplicabilityRules>"#
        );
        let idx = index(&xml);
        let el = idx.applicability_rules.as_ref().unwrap();
        let meta = el.elements().find(|e| e.name.local == "Metadata").unwrap();
        let cbs = meta.elements().next().unwrap();
        let dropped: u64 = cbs.attr(SLIMMED_DESCENDANTS_ATTR).unwrap().parse().unwrap();
        assert!(dropped >= 40_000, "dropped {dropped}");
        let assembly = cbs.elements().next().unwrap();
        assert_eq!(assembly.elements().count(), 2); // identity and a childless package
        let r = ApplicabilityRules::from_element(el);
        assert_eq!(
            r.cbs_package_identity().as_deref(),
            Some("Package_for_X~31bf3856ad364e35~amd64~~1.2.3.4")
        );
    }
}
