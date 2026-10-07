//! Three-valued evaluation of applicability expressions.
//!
//! [`Tri`] follows Kleene's strong three-valued logic: `False and x` is
//! `False`, `True or x` is `True`, `not Unknown` is `Unknown`, and nothing
//! else turns an `Unknown` into a definite value. An [`Outcome`] carries the
//! blockers (unsupported operators, unavailable facts, undecidable
//! comparisons) that kept the answer from being definite; a definite answer
//! reached through a short-circuit carries none.
//!
//! The per-operator rules, with their evidence labels, are in
//! [`operators`](super::operators) and in `docs/wsus-protocol-inventory.md`
//! ("Applicability rules").
use std::cmp::Ordering;

use super::expr::{
    DeviceAttributeType, Expr, FileBase, FileRef, MsiProductRule, Operator, RegKeyLoop, RegKeyRef,
    RegValueRef, RegView, Unsupported, WindowsVersion,
};
use super::facts::{CBS_STATE_INSTALLED, Fact, FactProvider, FileInfo, FileLocation, RegValue};
use super::value::{Comparison, LoopLogic, MsiVersion, StringComparison, Version, canon_guid};

/// Kleene truth value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    /// From a definite boolean.
    pub fn from_bool(b: bool) -> Self {
        if b { Tri::True } else { Tri::False }
    }

    /// Kleene conjunction.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Tri::False, _) | (_, Tri::False) => Tri::False,
            (Tri::True, Tri::True) => Tri::True,
            _ => Tri::Unknown,
        }
    }

    /// Kleene disjunction.
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Tri::True, _) | (_, Tri::True) => Tri::True,
            (Tri::False, Tri::False) => Tri::False,
            _ => Tri::Unknown,
        }
    }

    /// `Some` for a definite value.
    pub fn definite(self) -> Option<bool> {
        match self {
            Tri::True => Some(true),
            Tri::False => Some(false),
            Tri::Unknown => None,
        }
    }
}

/// Kleene negation.
impl std::ops::Not for Tri {
    type Output = Tri;

    fn not(self) -> Tri {
        match self {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        }
    }
}

/// Something that kept an expression from a definite answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Blocker {
    /// An [`Expr::Unsupported`] node was reached.
    Unsupported { name: String, reason: String },
    /// The fact provider could not answer.
    Unavailable { fact: String, reason: String },
    /// The facts are there but the operator's semantics leave the answer
    /// open (type mismatch, unverified comparison rule, ...).
    Undecidable { operator: String, why: String },
}

impl std::fmt::Display for Blocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Blocker::Unsupported { name, reason } => write!(f, "unsupported {name}: {reason}"),
            Blocker::Unavailable { fact, reason } => write!(f, "unavailable {fact}: {reason}"),
            Blocker::Undecidable { operator, why } => write!(f, "undecidable {operator}: {why}"),
        }
    }
}

/// Result of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub value: Tri,
    /// Unique blockers behind an `Unknown`; empty for a definite value.
    pub blockers: Vec<Blocker>,
}

impl Outcome {
    fn definite(b: bool) -> Self {
        Self {
            value: Tri::from_bool(b),
            blockers: Vec::new(),
        }
    }

    fn unknown(b: Blocker) -> Self {
        Self {
            value: Tri::Unknown,
            blockers: vec![b],
        }
    }

    fn tri(value: Tri, blockers: Vec<Blocker>) -> Self {
        if value == Tri::Unknown {
            Self { value, blockers }
        } else {
            Self {
                value,
                blockers: Vec::new(),
            }
        }
    }

    fn undecidable(op: &str, why: impl Into<String>) -> Self {
        Self::unknown(Blocker::Undecidable {
            operator: op.to_owned(),
            why: why.into(),
        })
    }

    fn not(self) -> Self {
        Self {
            value: !self.value,
            blockers: self.blockers,
        }
    }

    /// Operators of the unsupported kind among the blockers.
    pub fn unsupported_names(&self) -> Vec<&str> {
        self.blockers
            .iter()
            .filter_map(|b| match b {
                Blocker::Unsupported { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }
}

fn push_unique(into: &mut Vec<Blocker>, from: Vec<Blocker>) {
    for b in from {
        if !into.contains(&b) {
            into.push(b);
        }
    }
}

/// Kleene conjunction of outcomes.
fn all(items: impl IntoIterator<Item = Outcome>) -> Outcome {
    let mut value = Tri::True;
    let mut blockers = Vec::new();
    for o in items {
        value = value.and(o.value);
        if value == Tri::False {
            return Outcome::definite(false);
        }
        push_unique(&mut blockers, o.blockers);
    }
    Outcome::tri(value, blockers)
}

/// Kleene disjunction of outcomes.
fn any(items: impl IntoIterator<Item = Outcome>) -> Outcome {
    let mut value = Tri::False;
    let mut blockers = Vec::new();
    for o in items {
        value = value.or(o.value);
        if value == Tri::True {
            return Outcome::definite(true);
        }
        push_unique(&mut blockers, o.blockers);
    }
    Outcome::tri(value, blockers)
}

/// Evaluate an expression against a fact provider.
pub fn evaluate(expr: &Expr, facts: &dyn FactProvider) -> Outcome {
    Ctx {
        facts,
        loop_target: None,
    }
    .eval(expr)
}

struct Ctx<'a> {
    facts: &'a dyn FactProvider,
    /// (view, canonical-or-raw sub-key path) of the key a `RegKeyLoop` is on.
    loop_target: Option<(RegView, String)>,
}

fn unavailable<T>(fact: &str, f: &Fact<T>) -> Option<Outcome> {
    match f {
        Fact::Unavailable(r) => Some(Outcome::unknown(Blocker::Unavailable {
            fact: fact.to_owned(),
            reason: r.clone(),
        })),
        _ => None,
    }
}

/// Compare strings with the case rule left open: if the ordinal and the
/// case-folded comparisons agree the answer is definite, otherwise it is
/// `Unknown` (the pages do not say whether registry data compares ordinally).
fn string_compare(op: &str, c: StringComparison, have: &str, want: &str) -> Outcome {
    let strict = c.test(have, want);
    let folded = c.test(&have.to_lowercase(), &want.to_lowercase());
    if strict == folded {
        Outcome::definite(strict)
    } else {
        Outcome::undecidable(
            op,
            "result depends on case sensitivity, which is unverified",
        )
    }
}

fn ordering_outcome(c: Comparison, o: Ordering) -> Outcome {
    Outcome::definite(c.test(o))
}

impl Ctx<'_> {
    fn eval(&self, e: &Expr) -> Outcome {
        match e {
            Expr::True => Outcome::definite(true),
            Expr::False => Outcome::definite(false),
            Expr::And(v) => all(v.iter().map(|x| self.eval(x))),
            Expr::Or(v) => any(v.iter().map(|x| self.eval(x))),
            Expr::Not(x) => self.eval(x).not(),
            Expr::Op(op) => self.op(op),
            Expr::RegKeyLoop(l) => self.key_loop(l),
            Expr::Unsupported(u) => Outcome::unknown(blocker_of(u)),
        }
    }

    /// Resolve a key reference to a concrete (view, sub-key).
    fn key(&self, k: &RegKeyRef, op: &str) -> Result<(RegView, String), Outcome> {
        if !k.loop_target {
            return Ok((k.view, k.subkey.clone()));
        }
        match &self.loop_target {
            Some((view, base)) => Ok((*view, format!("{base}\\{}", k.subkey))),
            None => Err(Outcome::undecidable(
                op,
                "HKEY_LOOP_TARGET outside a RegKeyLoop",
            )),
        }
    }

    fn reg(&self, v: &RegValueRef, op: &str) -> Result<Fact<RegValue>, Outcome> {
        let (view, sub) = self.key(&v.key, op)?;
        Ok(self.facts.reg_value(view, &sub, &v.value))
    }

    fn file(&self, f: &FileRef, op: &str) -> Result<Fact<FileInfo>, Outcome> {
        let loc = match &f.base {
            FileBase::Csidl(c) => FileLocation::Csidl { csidl: *c },
            FileBase::None => {
                if f.path.contains('%') {
                    return Err(Outcome::undecidable(
                        op,
                        "environment variable in an absolute path is not expanded",
                    ));
                }
                FileLocation::Absolute
            }
            FileBase::RegSz(v) => {
                let (view, sub) = self.key(&v.key, op)?;
                FileLocation::RegSz {
                    view,
                    subkey: sub,
                    value: v.value.clone(),
                }
            }
        };
        Ok(self.facts.file(&loc, &f.path))
    }

    #[inline(never)]
    fn op(&self, op: &Operator) -> Outcome {
        match self.op_inner(op) {
            Ok(o) | Err(o) => o,
        }
    }

    #[inline(never)]
    fn op_inner(&self, op: &Operator) -> Result<Outcome, Outcome> {
        Ok(match op {
            Operator::RegKeyExists(k) => {
                let (view, sub) = self.key(k, "RegKeyExists")?;
                match self.facts.reg_key_exists(view, &sub) {
                    Fact::Known(()) => Outcome::definite(true),
                    Fact::Absent => Outcome::definite(false),
                    Fact::Unavailable(r) => Outcome::unknown(Blocker::Unavailable {
                        fact: format!("registry key {sub}"),
                        reason: r,
                    }),
                }
            }
            Operator::RegValueExists { value, ty } => {
                let f = self.reg(value, "RegValueExists")?;
                let what = format!("registry value {}\\{}", value.key.subkey, value.value);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match (f, ty) {
                    (Fact::Known(_), None) => Outcome::definite(true),
                    (Fact::Known(v), Some(t)) => Outcome::definite(v.is_type(t)),
                    _ => Outcome::definite(false),
                }
            }
            Operator::RegDword {
                value,
                comparison,
                data,
            } => {
                let f = self.reg(value, "RegDword")?;
                let what = format!("registry value {}\\{}", value.key.subkey, value.value);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(RegValue::Dword(d)) => ordering_outcome(*comparison, d.cmp(data)),
                    Fact::Known(_) => Outcome::undecidable(
                        "RegDword",
                        "value exists with a type other than REG_DWORD",
                    ),
                    _ => Outcome::definite(false),
                }
            }
            Operator::RegSz {
                value,
                comparison,
                data,
            } => {
                let f = self.reg(value, "RegSz")?;
                let what = format!("registry value {}\\{}", value.key.subkey, value.value);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(RegValue::Sz(s)) => string_compare("RegSz", *comparison, &s, data),
                    Fact::Known(_) => {
                        Outcome::undecidable("RegSz", "value exists with a type other than REG_SZ")
                    }
                    _ => Outcome::definite(false),
                }
            }
            Operator::RegExpandSz {
                value,
                comparison,
                data,
            } => {
                let f = self.reg(value, "RegExpandSz")?;
                let what = format!("registry value {}\\{}", value.key.subkey, value.value);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(RegValue::ExpandSz(s)) => {
                        if s.contains('%') {
                            Outcome::undecidable(
                                "RegExpandSz",
                                "value contains an environment reference; whether the client compares the expanded text is unverified",
                            )
                        } else {
                            string_compare("RegExpandSz", *comparison, &s, data)
                        }
                    }
                    Fact::Known(_) => Outcome::undecidable(
                        "RegExpandSz",
                        "value exists with a type other than REG_EXPAND_SZ",
                    ),
                    _ => Outcome::definite(false),
                }
            }
            Operator::RegSzToVersion {
                value,
                comparison,
                data,
            } => {
                let f = self.reg(value, "RegSzToVersion")?;
                let what = format!("registry value {}\\{}", value.key.subkey, value.value);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(RegValue::Sz(s)) => match Version::parse_padded(&s) {
                        Some(v) => ordering_outcome(*comparison, v.cmp(data)),
                        None => Outcome::undecidable(
                            "RegSzToVersion",
                            format!(
                                "`{s}` is not a one to four part numeric version; the client's handling is unverified"
                            ),
                        ),
                    },
                    Fact::Known(_) => Outcome::undecidable(
                        "RegSzToVersion",
                        "value exists with a type other than REG_SZ",
                    ),
                    _ => Outcome::definite(false),
                }
            }
            Operator::FileExists {
                file,
                size,
                version,
            } => {
                let f = self.file(file, "FileExists")?;
                let what = format!("file {}", file.path);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(info) => {
                        let mut checks = Vec::new();
                        if let Some(s) = size {
                            checks.push(match info.size {
                                Some(have) => Outcome::definite(have == *s),
                                None => {
                                    Outcome::undecidable("FileExists", "file size not recorded")
                                }
                            });
                        }
                        if let Some(v) = version {
                            checks.push(match info.version {
                                Some(have) => Outcome::definite(have == *v),
                                None => {
                                    Outcome::undecidable("FileExists", "file version not recorded")
                                }
                            });
                        }
                        all(checks)
                    }
                    _ => Outcome::definite(false),
                }
            }
            Operator::FileVersion {
                file,
                comparison,
                version,
            } => {
                let f = self.file(file, "FileVersion")?;
                let what = format!("file {}", file.path);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    // "The file version evaluation implies that the file
                    // exists" (Specified): a missing file is false.
                    Fact::Known(info) => match info.version {
                        Some(have) => ordering_outcome(*comparison, have.cmp(version)),
                        None => Outcome::undecidable(
                            "FileVersion",
                            "file exists but has no version resource recorded",
                        ),
                    },
                    _ => Outcome::definite(false),
                }
            }
            Operator::FileCreated {
                file,
                comparison,
                time,
            }
            | Operator::FileModified {
                file,
                comparison,
                time,
            } => {
                let created = matches!(op, Operator::FileCreated { .. });
                let name = if created {
                    "FileCreated"
                } else {
                    "FileModified"
                };
                let f = self.file(file, name)?;
                let what = format!("file {}", file.path);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(info) => match if created { info.created } else { info.modified } {
                        Some(have) => ordering_outcome(*comparison, have.cmp(time)),
                        None => Outcome::undecidable(name, "file time not recorded"),
                    },
                    _ => Outcome::definite(false),
                }
            }
            Operator::FileSize {
                file,
                comparison,
                size,
            } => {
                let f = self.file(file, "FileSize")?;
                let what = format!("file {}", file.path);
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(info) => match info.size {
                        Some(have) => ordering_outcome(*comparison, have.cmp(size)),
                        None => Outcome::undecidable("FileSize", "file size not recorded"),
                    },
                    _ => Outcome::definite(false),
                }
            }
            Operator::WindowsVersion(w) => self.windows_version(w),
            Operator::WindowsLanguage { language } => self.windows_language(language),
            Operator::MuiInstalled => match self.facts.mui_installed() {
                Fact::Known(b) => Outcome::definite(b),
                Fact::Absent => Outcome::definite(false),
                Fact::Unavailable(r) => Outcome::unknown(Blocker::Unavailable {
                    fact: "MUI state".into(),
                    reason: r,
                }),
            },
            Operator::Processor { architecture } => match self.facts.processor_architecture() {
                Fact::Known(a) => Outcome::definite(a == *architecture),
                Fact::Absent => Outcome::undecidable("Processor", "architecture reported absent"),
                Fact::Unavailable(r) => Outcome::unknown(Blocker::Unavailable {
                    fact: "processor architecture".into(),
                    reason: r,
                }),
            },
            Operator::SystemMetric {
                comparison,
                index,
                value,
            } => {
                let f = self.facts.system_metric(*index);
                let what = format!("system metric {index}");
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(have) => ordering_outcome(*comparison, have.cmp(value)),
                    _ => Outcome::undecidable("SystemMetric", "metric reported absent"),
                }
            }
            Operator::LicenseDword {
                name,
                comparison,
                data,
            } => {
                let f = self.facts.license_dword(name);
                let what = format!("licensing value {name}");
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(have) => ordering_outcome(*comparison, have.cmp(data)),
                    _ => Outcome::definite(false),
                }
            }
            Operator::WmiQuery { namespace, query } => {
                let ns = namespace.as_deref().unwrap_or("root\\cimv2");
                let f = self.facts.wmi_query(ns, query);
                let what = format!("WQL {ns}: {query}");
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(b) => Outcome::definite(b),
                    _ => Outcome::definite(false),
                }
            }
            Operator::MsiProductInstalled(r) => self.msi_product(r),
            Operator::MsiFeatureInstalledForProduct {
                features,
                products,
                all_features,
                all_products,
            } => self.msi_matrix(
                "MsiFeatureInstalledForProduct",
                products,
                features,
                *all_features,
                *all_products,
                |p, f| self.facts.msi_feature(p, f),
            ),
            Operator::MsiComponentInstalledForProduct {
                components,
                products,
                all_components,
                all_products,
            } => self.msi_matrix(
                "MsiComponentInstalledForProduct",
                products,
                components,
                *all_components,
                *all_products,
                |p, c| self.facts.msi_component(p, c),
            ),
            Operator::MsiPatchInstalledForProduct { patch, product } => {
                let f = self.facts.msi_patch(product, patch);
                let what = format!("MSI patch {patch} for {product}");
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(b) => Outcome::definite(b),
                    _ => Outcome::definite(false),
                }
            }
            Operator::DeviceAttribute {
                name,
                kind,
                comparison,
                value,
            } => self.device_attribute(name, *kind, *comparison, value),
            Operator::ProductReleaseInstalled { name, version } => {
                self.product_release_installed(name, version)
            }
            Operator::ProductReleaseVersion {
                name,
                version,
                comparison,
            } => self.product_release_present(name, version, *comparison),
            Operator::CbsPackageInstalled { identity } => {
                let f = self.facts.cbs_package(identity);
                let what = format!("CBS package {identity}");
                if let Some(o) = unavailable(&what, &f) {
                    return Ok(o);
                }
                match f {
                    Fact::Known(CBS_STATE_INSTALLED) => Outcome::definite(true),
                    Fact::Known(s) => Outcome::undecidable(
                        "CbsPackageInstalledByIdentity",
                        format!(
                            "package state {s} is not the installed state; meaning of other states is unverified"
                        ),
                    ),
                    _ => Outcome::definite(false),
                }
            }
        })
    }

    /// `DeviceAttribute`. Implementation decisions, Unverified against a native agent:
    /// `OSVersion`/`DL_OSVersion` compare the first three components (major, minor, build) of the
    /// OS identity and are `Unknown` when those are equal because the revision (UBR) is not a fact;
    /// `ProductType` maps the registry strings `WinNT`, `LanmanNT`, `ServerNT` to product types 1, 2, 3;
    /// every other attribute (`OSSkuId`, `sku`, `IsRemoteDesktopSessionHost`, `CurrentBranch`) has no
    /// fact source and is `Unknown`.
    fn device_attribute(
        &self,
        name: &str,
        kind: DeviceAttributeType,
        comparison: Comparison,
        value: &str,
    ) -> Outcome {
        let op = "DeviceAttribute";
        let known = matches!(
            name,
            "OSVersion" | "DL_OSVersion" | "ProductType" | "OSSkuId" | "sku"
        );
        if !known {
            return Outcome::unknown(Blocker::Unavailable {
                fact: format!("DeviceAttribute {name}"),
                reason: "no fact source for this device attribute".into(),
            });
        }
        let os = match self.facts.os() {
            Fact::Known(o) => o,
            Fact::Absent => return Outcome::undecidable(op, "OS reported absent"),
            Fact::Unavailable(r) => {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: "OS version".into(),
                    reason: r,
                });
            }
        };
        if name == "OSSkuId" || name == "sku" {
            // The real catalog writes both names with the same decimal `PRODUCT_*` value
            // (Implementation decision, Unverified: `GetProductInfo` of this machine).
            if kind != DeviceAttributeType::String || comparison != Comparison::EqualTo {
                return Outcome::undecidable(
                    op,
                    "OSSkuId and sku are only read as string equality",
                );
            }
            let Some(sku) = os.sku else {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: format!("DeviceAttribute {name}"),
                    reason: "the OS product type (GetProductInfo) was not read".into(),
                });
            };
            return Outcome::definite(value.trim() == sku.to_string());
        }
        if name == "ProductType" {
            if kind != DeviceAttributeType::String || comparison != Comparison::EqualTo {
                return Outcome::undecidable(op, "ProductType is only read as a string equality");
            }
            let want = match value {
                "WinNT" => 1,
                "LanmanNT" => 2,
                "ServerNT" => 3,
                _ => {
                    return Outcome::undecidable(
                        op,
                        format!("unknown ProductType value `{value}`"),
                    );
                }
            };
            return Outcome::definite(os.product_type == want);
        }
        if kind != DeviceAttributeType::Version {
            return Outcome::undecidable(op, "OSVersion is only read as a version");
        }
        let parts: Vec<u32> = value
            .split('.')
            .map(|p| p.parse::<u32>().unwrap_or(u32::MAX))
            .collect();
        if parts.len() != 4 || parts.contains(&u32::MAX) {
            return Outcome::undecidable(op, format!("`{value}` is not a four part version"));
        }
        match [os.major, os.minor, os.build].as_slice().cmp(&parts[..3]) {
            Ordering::Equal => match os.ubr {
                // Same build: the revision decides when it is a fact.
                Some(ubr) => ordering_outcome(comparison, ubr.cmp(&parts[3])),
                None => Outcome::undecidable(
                    op,
                    "the OS build equals the compared build and the revision (UBR) is not a fact",
                ),
            },
            ord => ordering_outcome(comparison, ord),
        }
    }

    /// `ProductReleaseVersion greaterthan 0.0.0.0`: is the product present (see the operator table).
    fn product_release_present(
        &self,
        name: &str,
        version: &str,
        comparison: Comparison,
    ) -> Outcome {
        let op = "ProductReleaseVersion";
        if comparison != Comparison::GreaterThan || version != "0.0.0.0" {
            return Outcome::undecidable(op, "only `greaterthan 0.0.0.0` is read");
        }
        let arch_matches = |this: &Self, suffix: &str| -> Option<bool> {
            let want = match suffix.to_ascii_lowercase().as_str() {
                "amd64" | "x64" => 9u32,
                "arm64" => 12,
                "x86" => 0,
                _ => return None,
            };
            match this.facts.processor_architecture() {
                Fact::Known(a) => Some(a == want),
                _ => None,
            }
        };
        let os = |this: &Self| match this.facts.os() {
            Fact::Known(o) => Ok(o),
            Fact::Absent => Err(Outcome::undecidable(op, "OS reported absent")),
            Fact::Unavailable(r) => Err(Outcome::unknown(Blocker::Unavailable {
                fact: "OS version".into(),
                reason: r,
            })),
        };
        for (prefix, client) in [("Client.OS.", true), ("Server.OS.", false)] {
            if let Some(rest) = name.strip_prefix(prefix) {
                let suffix = rest.rsplit('.').next().unwrap_or(rest);
                let o = match os(self) {
                    Ok(o) => o,
                    Err(e) => return e,
                };
                return match arch_matches(self, suffix) {
                    Some(m) => Outcome::definite(m && (o.product_type == 1) == client),
                    None => Outcome::unknown(Blocker::Unavailable {
                        fact: "processor architecture".into(),
                        reason: "not provided or not a known suffix".into(),
                    }),
                };
            }
        }
        if let Some(arch) = name.strip_prefix("Microsoft.NetFX.") {
            // Present when an installed rollup package of that architecture exists (version 0.0 is
            // enough: any build qualifies).
            return self.netfx_present(arch);
        }
        Outcome::unknown(Blocker::Unavailable {
            fact: format!("ProductReleaseVersion {name}"),
            reason: "no fact source for this product name".into(),
        })
    }

    /// `Microsoft.NetFX.<arch>` is present when any `Package_for_DotNetRollup_*` CBS package of that
    /// architecture has a CurrentState other than absent, whatever the state (OBSERVED states: 112
    /// installed, 80 superseded, 96 and 64 install pending, 5 uninstall pending): a machine in the reboot
    /// window after an install still has .NET.
    fn netfx_present(&self, arch: &str) -> Outcome {
        const KEY: &str =
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";
        let subkeys = match self.facts.reg_subkeys(RegView::Native, KEY) {
            Fact::Known(v) => v,
            Fact::Absent => Vec::new(),
            Fact::Unavailable(r) => {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: "CBS package list".into(),
                    reason: r,
                });
            }
        };
        let present = subkeys.iter().any(|sk| {
            let parts: Vec<&str> = sk.split('~').collect();
            parts.len() == 5
                && parts[0].starts_with("Package_for_DotNetRollup_")
                && parts[2].eq_ignore_ascii_case(arch)
                && matches!(
                    self.facts.reg_value(RegView::Native, &format!("{KEY}\\{sk}"), "CurrentState"),
                    Fact::Known(RegValue::Dword(d)) if d != 0
                )
        });
        Outcome::definite(present)
    }

    /// `ProductReleaseInstalled`. Implementation decisions, Unverified against a native agent (see the
    /// operator table): `Client.OS.*` compares the OS version with the release version;
    /// `Microsoft.NetFX.<arch>` reads the installed `Package_for_DotNetRollup_*` CBS packages.
    fn product_release_installed(&self, name: &str, version: &str) -> Outcome {
        let op = "ProductReleaseInstalled";
        let want: Vec<u32> = version
            .split('.')
            .map(|p| p.parse::<u32>().unwrap_or(u32::MAX))
            .collect();
        if want.len() != 4 || want.contains(&u32::MAX) {
            return Outcome::undecidable(op, format!("`{version}` is not a four part version"));
        }
        let arch_of = |suffix: &str| match suffix.to_ascii_lowercase().as_str() {
            "amd64" | "x64" => Some(9u32),
            "arm64" => Some(12),
            "x86" => Some(0),
            _ => None,
        };
        let machine_arch = |this: &Self| match this.facts.processor_architecture() {
            Fact::Known(a) => Some(a),
            _ => None,
        };
        if let Some(rest) = name.strip_prefix("Client.OS.") {
            let suffix = rest.rsplit('.').next().unwrap_or(rest);
            let os = match self.facts.os() {
                Fact::Known(o) => o,
                Fact::Absent => return Outcome::undecidable(op, "OS reported absent"),
                Fact::Unavailable(r) => {
                    return Outcome::unknown(Blocker::Unavailable {
                        fact: "OS version".into(),
                        reason: r,
                    });
                }
            };
            let Some(ubr) = os.ubr else {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: "OS revision (UBR)".into(),
                    reason: "the update build revision was not read".into(),
                });
            };
            if let (Some(want_arch), Some(have)) = (arch_of(suffix), machine_arch(self))
                && want_arch != have
            {
                return Outcome::definite(false);
            }
            let have = [os.major, os.minor, os.build, ubr];
            return Outcome::definite(have.as_slice() >= want.as_slice());
        }
        if let Some(arch) = name.strip_prefix("Microsoft.NetFX.") {
            let Some(want_arch) = arch_of(arch) else {
                return Outcome::undecidable(op, format!("unknown NetFX architecture `{arch}`"));
            };
            if let Some(have) = machine_arch(self)
                && have != want_arch
            {
                return Outcome::definite(false);
            }
            const KEY: &str =
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";
            let subkeys = match self.facts.reg_subkeys(RegView::Native, KEY) {
                Fact::Known(v) => v,
                Fact::Absent => Vec::new(),
                Fact::Unavailable(r) => {
                    return Outcome::unknown(Blocker::Unavailable {
                        fact: "CBS package list".into(),
                        reason: r,
                    });
                }
            };
            // OBSERVED (fixture dotnet-cbs-state.json): after `dism /Add-Package` and before the reboot the
            // package is `Install Pending` with CurrentState 96 and is listed under PackagesPending; the
            // native agent's pending install has CurrentState 64 and no PackagesPending entry. Neither is
            // CurrentState 112, so both read as not installed; the PackagesPending test below is redundant
            // with that and kept as a guard.
            const PENDING: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending";
            let pending: Vec<String> = match self.facts.reg_subkeys(RegView::Native, PENDING) {
                Fact::Known(v) => v.into_iter().map(|n| n.to_ascii_lowercase()).collect(),
                _ => Vec::new(),
            };
            let wanted_arch = arch.to_ascii_lowercase();
            for sk in subkeys {
                if pending.contains(&sk.to_ascii_lowercase()) {
                    continue;
                }
                let parts: Vec<&str> = sk.split('~').collect();
                if parts.len() != 5
                    || !parts[0].starts_with("Package_for_DotNetRollup_")
                    || !parts[2].eq_ignore_ascii_case(&wanted_arch)
                {
                    continue;
                }
                let have: Vec<u32> = parts[4]
                    .split('.')
                    .map(|p| p.parse::<u32>().unwrap_or(u32::MAX))
                    .collect();
                if have.len() != 4 || have.contains(&u32::MAX) {
                    continue;
                }
                if have[2..] < want[2..] {
                    continue;
                }
                let key = format!("{KEY}\\{sk}");
                if let Fact::Known(RegValue::Dword(CBS_STATE_INSTALLED)) =
                    self.facts.reg_value(RegView::Native, &key, "CurrentState")
                {
                    return Outcome::definite(true);
                }
            }
            return Outcome::definite(false);
        }
        Outcome::unknown(Blocker::Unavailable {
            fact: format!("ProductReleaseInstalled {name}"),
            reason: "no fact source for this product name".into(),
        })
    }

    fn windows_version(&self, w: &WindowsVersion) -> Outcome {
        let os = match self.facts.os() {
            Fact::Known(o) => o,
            Fact::Absent => return Outcome::undecidable("WindowsVersion", "OS reported absent"),
            Fact::Unavailable(r) => {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: "OS version".into(),
                    reason: r,
                });
            }
        };
        let c = w.comparison.unwrap_or(Comparison::EqualTo);
        let mut parts = Vec::new();
        // Major, minor, service pack: hierarchical (lexicographic) as
        // VerifyVersionInfo does (Specified for that API).
        let mut have = Vec::new();
        let mut want = Vec::new();
        for (h, x) in [
            (os.major, w.major),
            (os.minor, w.minor),
            (os.sp_major, w.sp_major),
            (os.sp_minor, w.sp_minor),
        ] {
            if let Some(x) = x {
                have.push(h);
                want.push(x);
            }
        }
        if !have.is_empty() {
            parts.push(ordering_outcome(c, have.cmp(&want)));
        }
        // Build number: an independent test with the same comparison
        // (Implementation decision, Unverified).
        if let Some(b) = w.build {
            parts.push(ordering_outcome(c, os.build.cmp(&b)));
        }
        if let Some(t) = w.product_type {
            // ProductType is tested for equality whatever the Comparison says
            // (Observed: a native agent reported installed three updates whose
            // rule is `GreaterThan ... ProductType=1` on a ProductType 1 client,
            // where a comparison would be False; one machine, Unverified beyond).
            parts.push(Outcome::definite(os.product_type == t));
        }
        if let Some(m) = w.suite_mask {
            let hit = os.suite_mask & m;
            parts.push(Outcome::definite(if w.all_suites_must_be_present {
                hit == m
            } else {
                hit != 0
            }));
        }
        all(parts)
    }

    fn windows_language(&self, want: &str) -> Outcome {
        let have = match self.facts.windows_language() {
            Fact::Known(l) => l,
            Fact::Absent => {
                return Outcome::undecidable("WindowsLanguage", "language reported absent");
            }
            Fact::Unavailable(r) => {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: "OS language".into(),
                    reason: r,
                });
            }
        };
        let want_l = want.to_ascii_lowercase();
        let have_l = have.to_ascii_lowercase();
        let m = if want_l == have_l {
            Outcome::definite(true)
        } else if !want_l.contains('-') && have_l.split('-').next() == Some(want_l.as_str()) {
            Outcome::undecidable(
                "WindowsLanguage",
                "neutral language against a specific OS language: whether it matches is unverified",
            )
        } else {
            Outcome::definite(false)
        };
        // "Always returns false if the Windows Multilanguage User Interface
        // (MUI) is installed" (Specified).
        let mui = match self.facts.mui_installed() {
            Fact::Known(b) => Outcome::definite(!b),
            Fact::Absent => Outcome::definite(true),
            Fact::Unavailable(r) => Outcome::unknown(Blocker::Unavailable {
                fact: "MUI state".into(),
                reason: r,
            }),
        };
        all([m, mui])
    }

    fn msi_product(&self, r: &MsiProductRule) -> Outcome {
        let f = self.facts.msi_product(&r.product);
        let what = format!("MSI product {}", r.product);
        if let Some(o) = unavailable(&what, &f) {
            return o;
        }
        let Fact::Known(p) = f else {
            return Outcome::definite(false);
        };
        let mut checks = Vec::new();
        if r.version_min.is_some() || r.version_max.is_some() {
            match MsiVersion::parse(&p.version) {
                None => checks.push(Outcome::undecidable(
                    "MsiProductInstalled",
                    format!("installed version `{}` is not numeric", p.version),
                )),
                Some(have) => {
                    if let Some(min) = &r.version_min {
                        let o = have.cmp_padded(min);
                        checks.push(Outcome::definite(if r.exclude_version_min {
                            o == Ordering::Greater
                        } else {
                            o != Ordering::Less
                        }));
                    }
                    if let Some(max) = &r.version_max {
                        let o = have.cmp_padded(max);
                        checks.push(Outcome::definite(if r.exclude_version_max {
                            o == Ordering::Less
                        } else {
                            o != Ordering::Greater
                        }));
                    }
                }
            }
        }
        if let Some(l) = r.language {
            checks.push(match p.language {
                Some(have) => Outcome::definite(have == l),
                None => {
                    Outcome::undecidable("MsiProductInstalled", "product language not recorded")
                }
            });
        }
        all(checks)
    }

    fn msi_matrix(
        &self,
        op: &str,
        products: &[String],
        items: &[String],
        all_items: bool,
        all_products: bool,
        q: impl Fn(&str, &str) -> Fact<bool>,
    ) -> Outcome {
        let mut per_product = Vec::new();
        for p in products {
            let p = canon_guid(p);
            let mut per_item = Vec::new();
            for i in items {
                let f = q(&p, i);
                let what = format!("{op} {i} of {p}");
                per_item.push(match f {
                    Fact::Known(b) => Outcome::definite(b),
                    Fact::Absent => Outcome::definite(false),
                    Fact::Unavailable(r) => Outcome::unknown(Blocker::Unavailable {
                        fact: what,
                        reason: r,
                    }),
                });
            }
            per_product.push(if all_items {
                all(per_item)
            } else {
                any(per_item)
            });
        }
        if all_products {
            all(per_product)
        } else {
            any(per_product)
        }
    }

    fn key_loop(&self, l: &RegKeyLoop) -> Outcome {
        let (view, base) = match self.key(&l.key, "RegKeyLoop") {
            Ok(x) => x,
            Err(o) => return o,
        };
        let names = match self.facts.reg_subkeys(view, &base) {
            Fact::Known(n) => n,
            // A missing key behaves as a key with no sub-keys (Implementation
            // decision, Unverified).
            Fact::Absent => Vec::new(),
            Fact::Unavailable(r) => {
                return Outcome::unknown(Blocker::Unavailable {
                    fact: format!("sub-keys of {base}"),
                    reason: r,
                });
            }
        };
        let results = names.iter().map(|n| {
            Ctx {
                facts: self.facts,
                loop_target: Some((view, format!("{base}\\{n}"))),
            }
            .eval(&l.body)
        });
        match l.true_if {
            LoopLogic::Any => any(results),
            LoopLogic::None => any(results).not(),
            LoopLogic::All => {
                if names.is_empty() {
                    Outcome::undecidable(
                        "RegKeyLoop",
                        "TrueIf=All over zero sub-keys: vacuous truth is unverified",
                    )
                } else {
                    all(results)
                }
            }
        }
    }
}

fn blocker_of(u: &Unsupported) -> Blocker {
    Blocker::Unsupported {
        name: u.name.clone(),
        reason: u.reason.to_string(),
    }
}
