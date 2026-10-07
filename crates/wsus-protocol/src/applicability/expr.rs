//! Typed applicability expressions and the parser from the opaque
//! `ApplicabilityRules` element tree kept by
//! [`FragmentIndex`](crate::metadata::FragmentIndex).
//!
//! # Name forms accepted
//!
//! Core fragments carry operators as `b.RegDword`, `m.MsiProductInstalled`,
//! `d.*` (MS-WUSP 3.1.1.1) and unprefixed `And`, `Or`, `Not`, `True`,
//! `False`, `CbsPackageInstalledByIdentity`, `ProductReleaseVersion`; full
//! documents (MS-WSUSSS `GetUpdateData`) carry `bar:`/`lar:` prefixes bound to
//! the schema namespaces. The operator is identified by its local name after
//! stripping a known prefix (`b`, `bar`, `m`, `msiar`, `d`, `drv`, `l`, `lar`)
//! or by its namespace when one is bound. A prefix or namespace that
//! contradicts the operator's family (`m.RegDword`) or is unknown
//! (`urn:example:rules`) yields an [`Expr::Unsupported`] node, never a guess.
//! Unprefixed known names are accepted for any family (Implementation
//! decision, the real data has no unprefixed base operators).
//!
//! # Never dropped
//!
//! Every element that is not understood, and every known operator whose
//! attributes or children do not match what this crate evaluates, becomes an
//! [`Unsupported`] node that keeps the raw [`Element`]. Attributes this crate
//! does not model make the whole operator unsupported (for example
//! `FileExists/@Language`) so they can never be silently ignored.
use super::value::{
    Comparison, FileTime, LoopLogic, MsiVersion, StringComparison, Version, canon_guid,
};
use crate::soap::xml::Element;

/// Maximum expression nesting; deeper input becomes an unsupported node.
pub const MAX_DEPTH: usize = 64;

const NS_BASE: &str = "schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules";
const NS_MSI: &str = "schemas.microsoft.com/msus/2002/12/MsiApplicabilityRules";
const NS_LOGICAL: &str = "schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules";
const NS_DRIVER: &str = "schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsDriver";
const NS_UPDATE: &str = "schemas.microsoft.com/msus/2002/12/Update";

/// Operator family named by a prefix or namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Logical,
    Base,
    Msi,
    Driver,
}

/// 32-bit or native registry view (`@RegType32`, Specified: "RegType32
/// boolean default false"). `Native` is the view of the 64-bit client on a
/// 64-bit OS, an Implementation decision (the schema page does not name the
/// WOW64 flag; `RegType32="true"` is read as `KEY_WOW64_32KEY`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RegView {
    #[default]
    Native,
    Wow32,
}

/// `Key` + `Subkey` + `RegType32`. `Key` is `HKEY_LOCAL_MACHINE` or
/// `HKEY_LOOP_TARGET` (Specified: `bt:RegistryKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegKeyRef {
    /// `Key="HKEY_LOOP_TARGET"`: the sub-key is relative to the key a
    /// surrounding `RegKeyLoop` is currently visiting.
    pub loop_target: bool,
    pub subkey: String,
    pub view: RegView,
}

/// A registry key plus a value name (`""` is the default value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValueRef {
    pub key: RegKeyRef,
    pub value: String,
}

/// Where a file path is rooted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileBase {
    /// `@Csidl`: `SHGetFolderPath(csidl)` is prepended (Specified).
    Csidl(i32),
    /// No `@Csidl`: the path is used as written.
    None,
    /// `...PrependRegSz`: a `REG_SZ` value is prepended (Specified).
    RegSz(RegValueRef),
}

/// A file reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    pub base: FileBase,
    pub path: String,
}

/// `REG_*` value type named by `RegValueExists/@Type`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegValueType {
    Dword,
    Qword,
    Sz,
    ExpandSz,
    MultiSz,
    Binary,
    /// Any other `REG_*` token, verbatim upper-cased.
    Other(String),
}

impl RegValueType {
    fn parse(s: &str) -> Option<Self> {
        let u = s.trim().to_ascii_uppercase();
        Some(match u.as_str() {
            "REG_DWORD" => Self::Dword,
            "REG_QWORD" => Self::Qword,
            "REG_SZ" => Self::Sz,
            "REG_EXPAND_SZ" => Self::ExpandSz,
            "REG_MULTI_SZ" => Self::MultiSz,
            "REG_BINARY" => Self::Binary,
            _ if u.starts_with("REG_") => Self::Other(u),
            _ => return None,
        })
    }
}

/// `b.WindowsVersion` (Specified: "Implemented using Win32
/// VerifyVersionInfo()").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowsVersion {
    /// Omitted means `EqualTo` (Specified).
    pub comparison: Option<Comparison>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub build: Option<u32>,
    pub sp_major: Option<u32>,
    pub sp_minor: Option<u32>,
    pub product_type: Option<u32>,
    pub suite_mask: Option<u32>,
    pub all_suites_must_be_present: bool,
}

/// `m.MsiProductInstalled` filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiProductRule {
    /// Canonical `{UPPER}` product code.
    pub product: String,
    pub version_min: Option<MsiVersion>,
    pub exclude_version_min: bool,
    pub version_max: Option<MsiVersion>,
    pub exclude_version_max: bool,
    pub language: Option<u32>,
}

/// A leaf predicate with typed attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operator {
    RegKeyExists(RegKeyRef),
    RegValueExists {
        value: RegValueRef,
        ty: Option<RegValueType>,
    },
    RegDword {
        value: RegValueRef,
        comparison: Comparison,
        data: u32,
    },
    RegSz {
        value: RegValueRef,
        comparison: StringComparison,
        data: String,
    },
    RegExpandSz {
        value: RegValueRef,
        comparison: StringComparison,
        data: String,
    },
    RegSzToVersion {
        value: RegValueRef,
        comparison: Comparison,
        data: Version,
    },
    FileExists {
        file: FileRef,
        size: Option<u64>,
        version: Option<Version>,
    },
    FileVersion {
        file: FileRef,
        comparison: Comparison,
        version: Version,
    },
    FileCreated {
        file: FileRef,
        comparison: Comparison,
        time: FileTime,
    },
    FileModified {
        file: FileRef,
        comparison: Comparison,
        time: FileTime,
    },
    FileSize {
        file: FileRef,
        comparison: Comparison,
        size: u64,
    },
    WindowsVersion(WindowsVersion),
    WindowsLanguage {
        language: String,
    },
    MuiInstalled,
    Processor {
        architecture: u32,
    },
    SystemMetric {
        comparison: Comparison,
        index: i32,
        value: i32,
    },
    /// `b.LicenseDword`: not in the public schema pages (Observed only).
    LicenseDword {
        name: String,
        comparison: Comparison,
        data: u32,
    },
    WmiQuery {
        namespace: Option<String>,
        query: String,
    },
    MsiProductInstalled(MsiProductRule),
    MsiFeatureInstalledForProduct {
        features: Vec<String>,
        products: Vec<String>,
        all_features: bool,
        all_products: bool,
    },
    MsiComponentInstalledForProduct {
        components: Vec<String>,
        products: Vec<String>,
        all_components: bool,
        all_products: bool,
    },
    MsiPatchInstalledForProduct {
        patch: String,
        product: String,
    },
    /// `CbsPackageInstalledByIdentity`: not in the public schema pages
    /// (Observed only).
    CbsPackageInstalled {
        identity: String,
    },
    /// `ProductReleaseInstalled` (OBSERVED on 297 OS installer updates; not in the public schema pages):
    /// the named product release (`Client.OS.RS2.AMD64`, `Microsoft.NetFX.amd64`) is installed at
    /// `version` or later. The reading is an Implementation decision, Unverified against a native agent.
    ProductReleaseInstalled {
        name: String,
        version: String,
    },
    /// `ProductReleaseVersion` (OBSERVED on 17 detectoids as `Comparison="greaterthan" Version="0.0.0.0"`;
    /// not in the public schema pages): the installed release version of the named product compares
    /// with `version`. Only the "product is present" reading (`greaterthan 0.0.0.0`) is implemented.
    ProductReleaseVersion {
        name: String,
        version: String,
        comparison: Comparison,
    },
    /// `DeviceAttribute` (OBSERVED in 2459 uses of a real Windows 11 catalog, never in the public schema
    /// pages): a comparison of one named device attribute with a literal.
    DeviceAttribute {
        name: String,
        kind: DeviceAttributeType,
        comparison: Comparison,
        value: String,
    },
}

/// `DeviceAttribute/@Type` (OBSERVED values `String` and `Version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAttributeType {
    String,
    Version,
}

/// Why an element is not an evaluable expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// No semantics are implemented for this operator name.
    UnknownOperator,
    /// The element is bound to a namespace that is not a rule namespace.
    UnknownNamespace(String),
    /// The prefix names an unknown family.
    UnknownPrefix(String),
    /// The prefix or namespace contradicts the operator's family.
    WrongFamily { expected: &'static str },
    /// Known operator, required attribute missing or value unparsable.
    Malformed(String),
    /// Known operator carrying an attribute this crate does not model.
    UnexpectedAttribute(String),
    /// Known operator with a child shape this crate does not model.
    UnexpectedChildren(String),
    /// Operator is known but its semantics are not available to this crate
    /// (documented in the schema, no fact source, or no stable definition).
    NoSemantics(&'static str),
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl std::fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOperator => f.write_str("unknown operator"),
            Self::UnknownNamespace(n) => write!(f, "unknown namespace {n}"),
            Self::UnknownPrefix(p) => write!(f, "unknown prefix {p}"),
            Self::WrongFamily { expected } => {
                write!(f, "operator belongs to the {expected} family")
            }
            Self::Malformed(m) => write!(f, "malformed: {m}"),
            Self::UnexpectedAttribute(a) => write!(f, "unexpected attribute {a}"),
            Self::UnexpectedChildren(c) => write!(f, "unexpected children: {c}"),
            Self::NoSemantics(why) => write!(f, "no semantics: {why}"),
            Self::TooDeep => f.write_str("nesting too deep"),
        }
    }
}

/// An element kept verbatim because it cannot be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    /// Operator name as written in the document (prefix included).
    pub name: String,
    pub reason: UnsupportedReason,
    /// The element, losslessly.
    pub element: Element,
}

/// `RegKeyLoop`: evaluates `body` once per sub-key of `key` (Specified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegKeyLoop {
    pub key: RegKeyRef,
    pub true_if: LoopLogic,
    pub body: Expr,
}

/// A typed applicability expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    True,
    False,
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Op(Operator),
    RegKeyLoop(Box<RegKeyLoop>),
    Unsupported(Box<Unsupported>),
}

impl Expr {
    /// Parse one expression element. Never fails and never drops input.
    pub fn parse(el: &Element) -> Expr {
        parse_depth(el, 0)
    }

    /// Every [`Unsupported`] node in the tree, depth first.
    pub fn unsupported(&self) -> Vec<&Unsupported> {
        let mut out = Vec::new();
        self.collect_unsupported(&mut out);
        out
    }

    fn collect_unsupported<'a>(&'a self, out: &mut Vec<&'a Unsupported>) {
        match self {
            Expr::And(v) | Expr::Or(v) => v.iter().for_each(|e| e.collect_unsupported(out)),
            Expr::Not(e) => e.collect_unsupported(out),
            Expr::RegKeyLoop(l) => l.body.collect_unsupported(out),
            Expr::Unsupported(u) => out.push(u),
            Expr::True | Expr::False | Expr::Op(_) => {}
        }
    }

    /// True when the tree has no unsupported node (the evaluator can answer
    /// definitely, given facts).
    pub fn is_fully_supported(&self) -> bool {
        self.unsupported().is_empty()
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        match self {
            Expr::And(v) | Expr::Or(v) => 1 + v.iter().map(Expr::node_count).sum::<usize>(),
            Expr::Not(e) => 1 + e.node_count(),
            Expr::RegKeyLoop(l) => 1 + l.body.node_count(),
            _ => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

fn family_of_prefix(p: &str) -> Option<Family> {
    Some(match p.to_ascii_lowercase().as_str() {
        "b" | "bar" => Family::Base,
        "m" | "msiar" | "msi" => Family::Msi,
        "d" | "drv" => Family::Driver,
        "l" | "lar" => Family::Logical,
        _ => return None,
    })
}

fn family_of_ns(ns: &str) -> Option<Option<Family>> {
    let n = ns
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    Some(match n {
        NS_BASE => Some(Family::Base),
        NS_MSI => Some(Family::Msi),
        NS_LOGICAL => Some(Family::Logical),
        NS_DRIVER => Some(Family::Driver),
        // Documents bound to the update namespace by default: unqualified.
        NS_UPDATE => None,
        _ => return Option::None,
    })
}

/// (declared family, bare local name) or the reason the name is unusable.
fn classify(el: &Element) -> Result<(Option<Family>, &str), UnsupportedReason> {
    let local = el.name.local.as_str();
    let (prefix, bare) = match local.find(['.', ':']) {
        Some(i) => (Some(&local[..i]), &local[i + 1..]),
        None => (None, local),
    };
    let from_prefix = match prefix {
        Some(p) => match family_of_prefix(p) {
            Some(f) => Some(f),
            None => return Err(UnsupportedReason::UnknownPrefix(p.to_owned())),
        },
        None => None,
    };
    let from_ns = match el.name.ns.as_deref() {
        Some(ns) => match family_of_ns(ns) {
            Some(f) => f,
            None => return Err(UnsupportedReason::UnknownNamespace(ns.to_owned())),
        },
        None => None,
    };
    match (from_prefix, from_ns) {
        (Some(a), Some(b)) if a != b => Err(UnsupportedReason::Malformed(
            "prefix and namespace name different families".into(),
        )),
        (a, b) => Ok((a.or(b), bare)),
    }
}

fn expected_family(bare: &str) -> Option<Option<Family>> {
    Some(match bare {
        "And" | "Or" | "Not" | "True" | "False" => Some(Family::Logical),
        "RegKeyExists"
        | "RegValueExists"
        | "RegDword"
        | "RegSz"
        | "RegExpandSz"
        | "RegSzToVersion"
        | "RegKeyLoop"
        | "FileExists"
        | "FileExistsPrependRegSz"
        | "FileVersion"
        | "FileVersionPrependRegSz"
        | "FileCreated"
        | "FileCreatedPrependRegSz"
        | "FileModified"
        | "FileModifiedPrependRegSz"
        | "FileSize"
        | "FileSizePrependRegSz"
        | "WindowsVersion"
        | "WindowsLanguage"
        | "MuiInstalled"
        | "MuiLanguageInstalled"
        | "SystemMetric"
        | "Processor"
        | "Platform"
        | "NumberOfProcessors"
        | "ClusteredOS"
        | "ClusterResourceOwner"
        | "WmiQuery"
        | "InstalledOnce"
        | "GenericQuery"
        | "LicenseDword" => Some(Family::Base),
        "MsiProductInstalled"
        | "MsiFeatureInstalledForProduct"
        | "MsiComponentInstalledForProduct"
        | "MsiPatchInstalledForProduct"
        | "MsiPatchInstalled"
        | "MsiPatchSuperseded"
        | "MsiPatchInstallable"
        | "MsiApplicationInstalled"
        | "MsiApplicationSuperseded"
        | "MsiApplicationInstallable" => Some(Family::Msi),
        "CbsPackageInstalledByIdentity"
        | "ProductReleaseVersion"
        | "ProductReleaseInstalled"
        | "DeviceAttribute"
        | "CbsPackageInstalled"
        | "CbsPackageInstallable" => None,
        _ => return Option::None,
    })
}

fn family_name(f: Family) -> &'static str {
    match f {
        Family::Logical => "logical",
        Family::Base => "base",
        Family::Msi => "msi",
        Family::Driver => "driver",
    }
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

type PResult<T> = Result<T, UnsupportedReason>;

struct Attrs<'a> {
    el: &'a Element,
    seen: Vec<&'static str>,
}

impl<'a> Attrs<'a> {
    fn new(el: &'a Element) -> Self {
        Self {
            el,
            seen: Vec::new(),
        }
    }

    fn opt(&mut self, n: &'static str) -> Option<&'a str> {
        self.seen.push(n);
        self.el.attr(n)
    }

    fn req(&mut self, n: &'static str) -> PResult<&'a str> {
        self.opt(n)
            .ok_or_else(|| UnsupportedReason::Malformed(format!("missing @{n}")))
    }

    fn parsed<T>(&mut self, n: &'static str, f: impl Fn(&str) -> Option<T>) -> PResult<Option<T>> {
        match self.opt(n) {
            None => Ok(None),
            Some(v) => f(v)
                .map(Some)
                .ok_or_else(|| UnsupportedReason::Malformed(format!("bad @{n} `{v}`"))),
        }
    }

    fn req_parsed<T>(&mut self, n: &'static str, f: impl Fn(&str) -> Option<T>) -> PResult<T> {
        self.parsed(n, f)?
            .ok_or_else(|| UnsupportedReason::Malformed(format!("missing @{n}")))
    }

    fn boolean(&mut self, n: &'static str) -> PResult<bool> {
        Ok(self.parsed(n, parse_bool)?.unwrap_or(false))
    }

    /// Fails when the element carries an unqualified attribute that was never
    /// asked for.
    fn finish(self) -> PResult<()> {
        for a in &self.el.attributes {
            if a.name.ns.is_none() && !self.seen.contains(&a.name.local.as_str()) {
                return Err(UnsupportedReason::UnexpectedAttribute(a.name.local.clone()));
            }
        }
        Ok(())
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

fn dec<T: std::str::FromStr>(s: &str) -> Option<T> {
    let t = s.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

fn dec_signed(s: &str) -> Option<i32> {
    s.trim().parse().ok()
}

fn cmp_of(s: &str) -> Option<Comparison> {
    Comparison::parse(s)
}

fn reg_key(a: &mut Attrs<'_>) -> PResult<RegKeyRef> {
    let key = a.req("Key")?;
    let loop_target = match key.trim() {
        "HKEY_LOCAL_MACHINE" => false,
        "HKEY_LOOP_TARGET" => true,
        other => {
            return Err(UnsupportedReason::Malformed(format!(
                "unsupported @Key `{other}`"
            )));
        }
    };
    let subkey = a.req("Subkey")?.to_owned();
    let view = if a.boolean("RegType32")? {
        RegView::Wow32
    } else {
        RegView::Native
    };
    Ok(RegKeyRef {
        loop_target,
        subkey,
        view,
    })
}

fn reg_value(a: &mut Attrs<'_>) -> PResult<RegValueRef> {
    let key = reg_key(a)?;
    let value = a.req("Value")?.to_owned();
    Ok(RegValueRef { key, value })
}

fn file_ref(a: &mut Attrs<'_>, prepend: bool) -> PResult<FileRef> {
    let path = a.req("Path")?.to_owned();
    if prepend {
        let v = reg_value(a)?;
        if v.key.loop_target {
            return Err(UnsupportedReason::Malformed(
                "HKEY_LOOP_TARGET in a PrependRegSz operator".into(),
            ));
        }
        return Ok(FileRef {
            base: FileBase::RegSz(v),
            path,
        });
    }
    let base = match a.parsed("Csidl", dec_signed)? {
        Some(c) => FileBase::Csidl(c),
        None => FileBase::None,
    };
    Ok(FileRef { base, path })
}

fn no_children(el: &Element) -> PResult<()> {
    if el.elements().next().is_some() {
        Err(UnsupportedReason::UnexpectedChildren(
            "operator takes no child elements".into(),
        ))
    } else {
        Ok(())
    }
}

fn text_list(el: &Element, name: &str) -> PResult<Vec<String>> {
    let mut out = Vec::new();
    for c in el.elements() {
        let local = c.name.local.as_str();
        let bare = local.rsplit(['.', ':']).next().unwrap_or(local);
        if bare != name {
            continue;
        }
        let t = c.text();
        let t = t.trim();
        if t.is_empty() {
            return Err(UnsupportedReason::Malformed(format!("empty <{name}>")));
        }
        out.push(t.to_owned());
    }
    if out.is_empty() {
        return Err(UnsupportedReason::Malformed(format!("no <{name}> element")));
    }
    Ok(out)
}

fn only_children_named(el: &Element, names: &[&str]) -> PResult<()> {
    for c in el.elements() {
        let local = c.name.local.as_str();
        let bare = local.rsplit(['.', ':']).next().unwrap_or(local);
        if !names.contains(&bare) {
            return Err(UnsupportedReason::UnexpectedChildren(format!(
                "child {local}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn unsupported(el: &Element, reason: UnsupportedReason) -> Expr {
    Expr::Unsupported(Box::new(Unsupported {
        name: el.name.local.clone(),
        reason,
        element: el.clone(),
    }))
}

fn parse_depth(el: &Element, depth: usize) -> Expr {
    if depth >= MAX_DEPTH {
        return unsupported(el, UnsupportedReason::TooDeep);
    }
    let (declared, bare) = match classify(el) {
        Ok(x) => x,
        Err(r) => return unsupported(el, r),
    };
    let Some(expected) = expected_family(bare) else {
        return unsupported(el, UnsupportedReason::UnknownOperator);
    };
    if let (Some(d), Some(e)) = (declared, expected)
        && d != e
    {
        return unsupported(
            el,
            UnsupportedReason::WrongFamily {
                expected: family_name(e),
            },
        );
    }
    let parsed = match bare {
        "And" | "Or" | "Not" | "RegKeyLoop" => parse_composite(el, bare, depth),
        _ => parse_leaf(el, bare),
    };
    match parsed {
        Ok(e) => e,
        Err(r) => unsupported(el, r),
    }
}

fn kids(el: &Element, depth: usize) -> Vec<Expr> {
    el.elements().map(|c| parse_depth(c, depth + 1)).collect()
}

/// And, Or, Not, RegKeyLoop: the only recursive parsers. Kept small so the
/// stack cost per nesting level stays low (the big attribute `match` of
/// [`parse_leaf`] is not on the recursion path).
fn parse_composite(el: &Element, bare: &str, depth: usize) -> PResult<Expr> {
    let mut a = Attrs::new(el);
    let expr = match bare {
        "And" | "Or" => {
            let k = kids(el, depth);
            if k.is_empty() {
                return Err(UnsupportedReason::Malformed(
                    "And/Or without operands".into(),
                ));
            }
            if bare == "And" {
                Expr::And(k)
            } else {
                Expr::Or(k)
            }
        }
        "Not" => {
            let mut k = kids(el, depth);
            if k.len() != 1 {
                return Err(UnsupportedReason::Malformed(
                    "Not needs exactly one operand".into(),
                ));
            }
            Expr::Not(Box::new(k.remove(0)))
        }
        _ => {
            let key = reg_key(&mut a)?;
            let true_if = a.req_parsed("TrueIf", LoopLogic::parse)?;
            let mut k = kids(el, depth);
            if k.len() != 1 {
                return Err(UnsupportedReason::Malformed(
                    "RegKeyLoop needs exactly one body expression".into(),
                ));
            }
            Expr::RegKeyLoop(Box::new(RegKeyLoop {
                key,
                true_if,
                body: k.remove(0),
            }))
        }
    };
    a.finish()?;
    Ok(expr)
}

fn parse_leaf(el: &Element, bare: &str) -> PResult<Expr> {
    let mut a = Attrs::new(el);
    let expr = match bare {
        "True" | "False" => {
            no_children(el)?;
            if bare == "True" {
                Expr::True
            } else {
                Expr::False
            }
        }
        "RegKeyExists" => {
            no_children(el)?;
            Expr::Op(Operator::RegKeyExists(reg_key(&mut a)?))
        }
        "RegValueExists" => {
            no_children(el)?;
            let key = reg_key(&mut a)?;
            let value = a.opt("Value").unwrap_or("").to_owned();
            let ty = a.parsed("Type", RegValueType::parse)?;
            Expr::Op(Operator::RegValueExists {
                value: RegValueRef { key, value },
                ty,
            })
        }
        "RegDword" => {
            no_children(el)?;
            let value = reg_value(&mut a)?;
            Expr::Op(Operator::RegDword {
                value,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                data: a.req_parsed("Data", dec::<u32>)?,
            })
        }
        "RegSz" | "RegExpandSz" => {
            no_children(el)?;
            let value = reg_value(&mut a)?;
            let comparison = a.req_parsed("Comparison", StringComparison::parse)?;
            let data = a.req("Data")?.to_owned();
            if bare == "RegSz" {
                Expr::Op(Operator::RegSz {
                    value,
                    comparison,
                    data,
                })
            } else {
                Expr::Op(Operator::RegExpandSz {
                    value,
                    comparison,
                    data,
                })
            }
        }
        "RegSzToVersion" => {
            no_children(el)?;
            let value = reg_value(&mut a)?;
            Expr::Op(Operator::RegSzToVersion {
                value,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                data: a.req_parsed("Data", Version::parse)?,
            })
        }
        "FileExists" | "FileExistsPrependRegSz" => {
            no_children(el)?;
            let file = file_ref(&mut a, bare.ends_with("RegSz"))?;
            Expr::Op(Operator::FileExists {
                file,
                size: a.parsed("Size", dec::<u64>)?,
                version: a.parsed("Version", Version::parse)?,
            })
        }
        "FileVersion" | "FileVersionPrependRegSz" => {
            no_children(el)?;
            let file = file_ref(&mut a, bare.ends_with("RegSz"))?;
            Expr::Op(Operator::FileVersion {
                file,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                version: a.req_parsed("Version", Version::parse)?,
            })
        }
        "FileCreated" | "FileCreatedPrependRegSz" => {
            no_children(el)?;
            let file = file_ref(&mut a, bare.ends_with("RegSz"))?;
            Expr::Op(Operator::FileCreated {
                file,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                time: a.req_parsed("Created", FileTime::parse)?,
            })
        }
        "FileModified" | "FileModifiedPrependRegSz" => {
            no_children(el)?;
            let file = file_ref(&mut a, bare.ends_with("RegSz"))?;
            Expr::Op(Operator::FileModified {
                file,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                time: a.req_parsed("Modified", FileTime::parse)?,
            })
        }
        "FileSize" | "FileSizePrependRegSz" => {
            no_children(el)?;
            let file = file_ref(&mut a, bare.ends_with("RegSz"))?;
            Expr::Op(Operator::FileSize {
                file,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                size: a.req_parsed("Size", dec::<u64>)?,
            })
        }
        "WindowsVersion" => {
            no_children(el)?;
            let w = WindowsVersion {
                comparison: a.parsed("Comparison", cmp_of)?,
                major: a.parsed("MajorVersion", dec::<u32>)?,
                minor: a.parsed("MinorVersion", dec::<u32>)?,
                build: a.parsed("BuildNumber", dec::<u32>)?,
                sp_major: a.parsed("ServicePackMajor", dec::<u32>)?,
                sp_minor: a.parsed("ServicePackMinor", dec::<u32>)?,
                all_suites_must_be_present: a.boolean("AllSuitesMustBePresent")?,
                suite_mask: a.parsed("SuiteMask", dec::<u32>)?,
                product_type: a.parsed("ProductType", dec::<u32>)?,
            };
            Expr::Op(Operator::WindowsVersion(w))
        }
        "WindowsLanguage" => {
            no_children(el)?;
            Expr::Op(Operator::WindowsLanguage {
                language: a.req("Language")?.trim().to_owned(),
            })
        }
        "MuiInstalled" => {
            no_children(el)?;
            Expr::Op(Operator::MuiInstalled)
        }
        "Processor" => {
            no_children(el)?;
            Expr::Op(Operator::Processor {
                architecture: a.req_parsed("Architecture", dec::<u32>)?,
            })
        }
        "SystemMetric" => {
            no_children(el)?;
            Expr::Op(Operator::SystemMetric {
                comparison: a.req_parsed("Comparison", cmp_of)?,
                index: a.req_parsed("Index", dec_signed)?,
                value: a.req_parsed("Value", dec_signed)?,
            })
        }
        "LicenseDword" => {
            no_children(el)?;
            Expr::Op(Operator::LicenseDword {
                name: a.req("Value")?.to_owned(),
                comparison: a.req_parsed("Comparison", cmp_of)?,
                data: a.req_parsed("Data", dec::<u32>)?,
            })
        }
        "WmiQuery" => {
            no_children(el)?;
            Expr::Op(Operator::WmiQuery {
                namespace: a.opt("Namespace").map(str::to_owned),
                query: a.req("WqlQuery")?.to_owned(),
            })
        }
        "MsiProductInstalled" => {
            no_children(el)?;
            let product = canon_guid(a.req("ProductCode")?);
            Expr::Op(Operator::MsiProductInstalled(MsiProductRule {
                product,
                version_min: a.parsed("VersionMin", MsiVersion::parse)?,
                exclude_version_min: a.boolean("ExcludeVersionMin")?,
                version_max: a.parsed("VersionMax", MsiVersion::parse)?,
                exclude_version_max: a.boolean("ExcludeVersionMax")?,
                language: a.parsed("Language", dec::<u32>)?,
            }))
        }
        "MsiFeatureInstalledForProduct" => {
            only_children_named(el, &["Feature", "Product"])?;
            let features = text_list(el, "Feature")?;
            let products = text_list(el, "Product")?
                .iter()
                .map(|p| canon_guid(p))
                .collect();
            Expr::Op(Operator::MsiFeatureInstalledForProduct {
                features,
                products,
                all_features: a.boolean("AllFeaturesRequired")?,
                all_products: a.boolean("AllProductsRequired")?,
            })
        }
        "MsiComponentInstalledForProduct" => {
            only_children_named(el, &["Component", "Product"])?;
            let components = text_list(el, "Component")?
                .iter()
                .map(|p| canon_guid(p))
                .collect();
            let products = text_list(el, "Product")?
                .iter()
                .map(|p| canon_guid(p))
                .collect();
            Expr::Op(Operator::MsiComponentInstalledForProduct {
                components,
                products,
                all_components: a.boolean("AllComponentsRequired")?,
                all_products: a.boolean("AllProductsRequired")?,
            })
        }
        "MsiPatchInstalledForProduct" => {
            no_children(el)?;
            Expr::Op(Operator::MsiPatchInstalledForProduct {
                patch: canon_guid(a.req("PatchCode")?),
                product: canon_guid(a.req("ProductCode")?),
            })
        }
        "CbsPackageInstalledByIdentity" => {
            no_children(el)?;
            Expr::Op(Operator::CbsPackageInstalled {
                identity: a.req("PackageIdentity")?.trim().to_owned(),
            })
        }
        "DeviceAttribute" => {
            no_children(el)?;
            let kind = match a.req("Type")?.trim() {
                "String" => DeviceAttributeType::String,
                "Version" => DeviceAttributeType::Version,
                _ => {
                    return Err(UnsupportedReason::NoSemantics(
                        "DeviceAttribute Type other than String or Version was never observed",
                    ));
                }
            };
            Expr::Op(Operator::DeviceAttribute {
                name: a.req("Name")?.trim().to_owned(),
                kind,
                comparison: a.req_parsed("Comparison", cmp_of)?,
                value: a.req("Value")?.trim().to_owned(),
            })
        }
        "ProductReleaseInstalled" => {
            no_children(el)?;
            Expr::Op(Operator::ProductReleaseInstalled {
                name: a.req("Name")?.trim().to_owned(),
                version: a.req("Version")?.trim().to_owned(),
            })
        }
        "CbsPackageInstalled" => {
            return Err(UnsupportedReason::NoSemantics(
                "takes no attributes; resolved to CbsPackageInstalledByIdentity from Metadata/CbsPackageApplicabilityMetadata when present",
            ));
        }
        "CbsPackageInstallable" => {
            return Err(UnsupportedReason::NoSemantics(
                "CBS applicability (the package's parent assemblies against the component store) has no fact source",
            ));
        }
        "ProductReleaseVersion" => {
            no_children(el)?;
            Expr::Op(Operator::ProductReleaseVersion {
                name: a.req("Name")?.trim().to_owned(),
                version: a.req("Version")?.trim().to_owned(),
                comparison: a.req_parsed("Comparison", cmp_of)?,
            })
        }
        "Platform" => {
            return Err(UnsupportedReason::NoSemantics(
                "not in the public schema pages; PlatformID=Windows is the only value seen and its meaning is unverified",
            ));
        }
        "MuiLanguageInstalled"
        | "NumberOfProcessors"
        | "ClusteredOS"
        | "ClusterResourceOwner"
        | "InstalledOnce"
        | "GenericQuery"
        | "MsiPatchInstalled"
        | "MsiPatchSuperseded"
        | "MsiPatchInstallable"
        | "MsiApplicationInstalled"
        | "MsiApplicationSuperseded"
        | "MsiApplicationInstallable" => {
            return Err(UnsupportedReason::NoSemantics(
                "documented in the schema but not implemented (no fact source)",
            ));
        }
        _ => return Err(UnsupportedReason::UnknownOperator),
    };
    a.finish()?;
    Ok(expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::Limits;
    use crate::soap::xml::parse_fragments;

    fn parse(xml: &str) -> Expr {
        let els = parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
        assert_eq!(els.len(), 1);
        Expr::parse(&els[0])
    }

    #[test]
    fn dotted_names_parse_and_unknown_operators_are_kept() {
        let e = parse(
            r#"<And><b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="S\K" Value="V" Comparison="GreaterThan" Data="0"/><x.Weird A="1"/><Frobnicate/></And>"#,
        );
        let Expr::And(v) = &e else { panic!("{e:?}") };
        assert!(matches!(
            &v[0],
            Expr::Op(Operator::RegDword { data: 0, .. })
        ));
        let Expr::Unsupported(u) = &v[1] else {
            panic!()
        };
        assert!(matches!(u.reason, UnsupportedReason::UnknownPrefix(_)));
        assert_eq!(u.element.attr("A"), Some("1"));
        let Expr::Unsupported(u) = &v[2] else {
            panic!()
        };
        assert_eq!(u.reason, UnsupportedReason::UnknownOperator);
        assert_eq!(e.unsupported().len(), 2);
    }

    #[test]
    fn wrong_family_and_extra_attributes_are_unsupported() {
        assert!(matches!(
            parse(r#"<m.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="a"/>"#),
            Expr::Unsupported(u) if matches!(u.reason, UnsupportedReason::WrongFamily { .. })
        ));
        assert!(matches!(
            parse(r#"<b.FileExists Path="a" Csidl="37" Language="1033"/>"#),
            Expr::Unsupported(u) if matches!(u.reason, UnsupportedReason::UnexpectedAttribute(_))
        ));
        assert!(matches!(
            parse(r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="a" Value="v" Comparison="EqualTo" Data="x"/>"#),
            Expr::Unsupported(u) if matches!(u.reason, UnsupportedReason::Malformed(_))
        ));
        assert!(matches!(parse("<Not/>"), Expr::Unsupported(_)));
        assert!(matches!(parse("<And/>"), Expr::Unsupported(_)));
    }

    #[test]
    fn strict_documents_resolve_namespaces() {
        let xml = r#"<ApplicabilityRules xmlns:lar="http://schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules" xmlns:bar="http://schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules"><lar:And><bar:Processor Architecture="9"/><lar:True/></lar:And></ApplicabilityRules>"#;
        let root = crate::soap::xml::parse(xml.as_bytes(), &Limits::default()).unwrap();
        let e = Expr::parse(root.elements().next().unwrap());
        assert!(e.is_fully_supported(), "{e:?}");
        let foreign =
            r#"<ApplicabilityRules><b:True xmlns:b="urn:example:rules"/></ApplicabilityRules>"#;
        let root = crate::soap::xml::parse(foreign.as_bytes(), &Limits::default()).unwrap();
        let e = Expr::parse(root.elements().next().unwrap());
        assert!(
            matches!(e, Expr::Unsupported(u) if matches!(u.reason, UnsupportedReason::UnknownNamespace(_)))
        );
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let n = MAX_DEPTH + 10;
        let xml = format!("{}<True/>{}", "<Not>".repeat(n), "</Not>".repeat(n));
        let limits = Limits {
            max_depth: 1000,
            ..Limits::default()
        };
        let els = parse_fragments(xml.as_bytes(), &limits).unwrap();
        let e = Expr::parse(&els[0]);
        assert!(!e.is_fully_supported());
    }
}
