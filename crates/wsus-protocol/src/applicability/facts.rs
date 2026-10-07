//! Fact providers: how the evaluator learns about the machine.
//!
//! A provider answers typed queries with a [`Fact`]: `Known(value)`,
//! `Absent` (the thing does not exist on the machine) or `Unavailable` (the
//! provider cannot say). The distinction is the point of the design:
//! `Absent` is a definite answer (a missing registry value makes `RegDword`
//! false), `Unavailable` makes the dependent operator `Unknown`.
//!
//! Registry key and value names are case-insensitive, files are looked up
//! case-insensitively on NTFS; providers receive the names as written in the
//! rule and must fold case themselves ([`FakeFacts`] and
//! [`RecordedFacts`](super::RecordedFacts) do, through
//! [`canon_key`](super::value::canon_key) and friends).
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub use super::expr::RegView;
use super::value::{FileTime, Version, canon_guid, canon_key, canon_path, canon_value_name};

/// Answer to one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact<T> {
    /// The value.
    Known(T),
    /// The queried object does not exist.
    Absent,
    /// The provider cannot answer; the reason is kept for the report.
    Unavailable(String),
}

impl<T> Fact<T> {
    /// Shorthand for `Unavailable` with a reason.
    pub fn unavailable(why: impl Into<String>) -> Self {
        Fact::Unavailable(why.into())
    }

    /// Map the known value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Fact<U> {
        match self {
            Fact::Known(v) => Fact::Known(f(v)),
            Fact::Absent => Fact::Absent,
            Fact::Unavailable(r) => Fact::Unavailable(r),
        }
    }
}

/// A registry value with its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Dword(u32),
    Qword(u64),
    Sz(String),
    /// Unexpanded `REG_EXPAND_SZ` data.
    ExpandSz(String),
    MultiSz(Vec<String>),
    Binary(Vec<u8>),
    /// Any other type, by `REG_*` name.
    Other(String),
}

impl RegValue {
    /// Does the value have this type.
    pub fn is_type(&self, t: &super::expr::RegValueType) -> bool {
        use super::expr::RegValueType as T;
        matches!(
            (self, t),
            (RegValue::Dword(_), T::Dword)
                | (RegValue::Qword(_), T::Qword)
                | (RegValue::Sz(_), T::Sz)
                | (RegValue::ExpandSz(_), T::ExpandSz)
                | (RegValue::MultiSz(_), T::MultiSz)
                | (RegValue::Binary(_), T::Binary)
        ) || matches!((self, t), (RegValue::Other(a), T::Other(b)) if a.eq_ignore_ascii_case(b))
    }
}

/// Where a file query is rooted. Resolution is the provider's job: the
/// evaluator never builds paths (the join rule for `...PrependRegSz` is an
/// Implementation decision documented on [`FakeFacts`] and in the inventory).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileLocation {
    /// `SHGetFolderPath(csidl)` prepended to the path.
    Csidl { csidl: i32 },
    /// The path as written.
    Absolute,
    /// The `REG_SZ` value prepended to the path.
    RegSz {
        view: RegView,
        subkey: String,
        value: String,
    },
}

/// What is known about an existing file.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FileInfo {
    pub size: Option<u64>,
    /// `VS_FIXEDFILEINFO` file version; `None` for a file without a version
    /// resource.
    pub version: Option<Version>,
    pub modified: Option<FileTime>,
    pub created: Option<FileTime>,
    /// The path the provider actually looked at (evidence only).
    pub resolved_path: Option<String>,
}

/// Operating system identity (`RtlGetVersion`, not the manifest-shimmed
/// `GetVersionEx`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub sp_major: u32,
    pub sp_minor: u32,
    /// `VER_NT_WORKSTATION` 1, `VER_NT_DOMAIN_CONTROLLER` 2, `VER_NT_SERVER` 3.
    pub product_type: u32,
    /// `wSuiteMask`.
    pub suite_mask: u32,
    /// `GetProductInfo` product type (`PRODUCT_*`), the value the real catalog's `OSSkuId` and `sku`
    /// device attributes compare as a decimal string. `None` when not read.
    pub sku: Option<u32>,
    /// The update build revision (`UBR`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`), the
    /// fourth component of the OS version. `None` when not read.
    pub ubr: Option<u32>,
}

/// Installed Windows Installer product.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MsiProduct {
    pub version: String,
    pub language: Option<u32>,
}

/// `CurrentState` of a CBS package, as stored under
/// `...\Component Based Servicing\Packages\<identity>`. 112 (0x70) is
/// "Installed" (Unverified recollection; the evaluator treats every other
/// state as not decidable).
pub type CbsState = u32;

/// `CurrentState` value the evaluator reads as installed.
pub const CBS_STATE_INSTALLED: CbsState = 112;

/// Machine facts. Object safe and synchronous; every method has an
/// `Unavailable` default so partial providers are easy to write.
pub trait FactProvider {
    /// Does `HKLM\<subkey>` exist in `view`.
    fn reg_key_exists(&self, _view: RegView, _subkey: &str) -> Fact<()> {
        Fact::unavailable("registry not provided")
    }
    /// Value `name` (empty means the default value) under `HKLM\<subkey>`.
    /// `Absent` covers a missing key as well as a missing value.
    fn reg_value(&self, _view: RegView, _subkey: &str, _name: &str) -> Fact<RegValue> {
        Fact::unavailable("registry not provided")
    }
    /// Names of the immediate sub-keys; `Absent` when the key does not exist.
    fn reg_subkeys(&self, _view: RegView, _subkey: &str) -> Fact<Vec<String>> {
        Fact::unavailable("registry not provided")
    }
    /// File lookup; `Absent` when the file (or the registry base of a
    /// `RegSz` location) does not exist.
    fn file(&self, _loc: &FileLocation, _path: &str) -> Fact<FileInfo> {
        Fact::unavailable("file system not provided")
    }
    /// Windows version.
    fn os(&self) -> Fact<OsInfo> {
        Fact::unavailable("OS version not provided")
    }
    /// `SYSTEM_INFO.wProcessorArchitecture` of the native machine (9 is
    /// AMD64, 12 ARM64, 0 x86).
    fn processor_architecture(&self) -> Fact<u32> {
        Fact::unavailable("processor architecture not provided")
    }
    /// `GetSystemMetrics(index)`.
    fn system_metric(&self, _index: i32) -> Fact<i32> {
        Fact::unavailable("system metrics not provided")
    }
    /// Language of the OS installation, a BCP 47 tag such as `en-US`.
    fn windows_language(&self) -> Fact<String> {
        Fact::unavailable("OS language not provided")
    }
    /// Is the Multilingual User Interface installed.
    fn mui_installed(&self) -> Fact<bool> {
        Fact::unavailable("MUI state not provided")
    }
    /// `SLGetWindowsInformationDWORD(name)`.
    fn license_dword(&self, _name: &str) -> Fact<u32> {
        Fact::unavailable("software licensing values not provided")
    }
    /// Does the WQL query return at least one row.
    fn wmi_query(&self, _namespace: &str, _wql: &str) -> Fact<bool> {
        Fact::unavailable("WMI not provided")
    }
    /// Installed MSI product (canonical `{UPPER}` code).
    fn msi_product(&self, _product: &str) -> Fact<MsiProduct> {
        Fact::unavailable("Windows Installer not provided")
    }
    /// Is the feature installed (local, source or default) for the product.
    fn msi_feature(&self, _product: &str, _feature: &str) -> Fact<bool> {
        Fact::unavailable("Windows Installer features not provided")
    }
    /// Is the component installed for the product.
    fn msi_component(&self, _product: &str, _component: &str) -> Fact<bool> {
        Fact::unavailable("Windows Installer components not provided")
    }
    /// Is the patch applied to the product.
    fn msi_patch(&self, _product: &str, _patch: &str) -> Fact<bool> {
        Fact::unavailable("Windows Installer patches not provided")
    }
    /// `CurrentState` of the CBS package with this identity.
    fn cbs_package(&self, _identity: &str) -> Fact<CbsState> {
        Fact::unavailable("CBS package state not provided")
    }
}

/// Provider that knows nothing: every query is `Unavailable`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFacts;

impl FactProvider for NoFacts {}

// ---------------------------------------------------------------------------
// FakeFacts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct FakeKey {
    display: String,
    values: HashMap<String, RegValue>,
}

/// In-memory machine for tests.
///
/// Closed world: registry, files, MSI and CBS answers are `Absent` when
/// nothing was set (the fake models a complete machine, unlike a snapshot).
/// OS version, architecture, system metrics, language, MUI and WMI are
/// `Unavailable` until set. Creating a value or key also creates every
/// parent key. Registry views are separate namespaces; the `*_both`
/// helpers write both.
///
/// `RegSz` file locations resolve through this fake's registry; the base and
/// path are joined with exactly one backslash (Implementation decision: the
/// schema says only "prepend").
#[derive(Debug, Clone, Default)]
pub struct FakeFacts {
    keys: BTreeMap<(RegView, String), FakeKey>,
    files: HashMap<(FileKey, String), FileInfo>,
    os: Option<OsInfo>,
    arch: Option<u32>,
    metrics: HashMap<i32, i32>,
    language: Option<String>,
    mui: Option<bool>,
    licenses: HashMap<String, u32>,
    wmi: HashMap<(String, String), bool>,
    msi_products: HashMap<String, MsiProduct>,
    msi_features: BTreeSet<(String, String)>,
    msi_components: BTreeSet<(String, String)>,
    msi_patches: BTreeSet<(String, String)>,
    cbs: HashMap<String, CbsState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FileKey {
    Csidl(i32),
    Absolute,
}

impl FakeFacts {
    /// Empty machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Typical Windows 11 x64 client: 10.0.26200, workstation, AMD64, English.
    pub fn windows11_x64() -> Self {
        let mut f = Self::new();
        f.set_os(OsInfo {
            major: 10,
            minor: 0,
            build: 26200,
            sp_major: 0,
            sp_minor: 0,
            product_type: 1,
            suite_mask: 0x100,
            sku: Some(48),
            ubr: Some(8037),
        });
        f.set_architecture(9);
        f.set_language("en-US");
        f.set_mui_installed(false);
        f
    }

    fn ensure_key(&mut self, view: RegView, subkey: &str) -> &mut FakeKey {
        let canon = canon_key(subkey);
        let mut acc = String::new();
        let mut disp = String::new();
        let shown = subkey.split(['\\', '/']).filter(|p| !p.is_empty());
        for (c, d) in canon.split('\\').zip(shown) {
            if !acc.is_empty() {
                acc.push('\\');
                disp.push('\\');
            }
            acc.push_str(c);
            disp.push_str(d);
            self.keys
                .entry((view, acc.clone()))
                .or_insert_with(|| FakeKey {
                    display: disp.clone(),
                    values: HashMap::new(),
                });
        }
        self.keys.entry((view, canon)).or_default()
    }

    /// Create a key (and parents) in `view`.
    pub fn add_key(&mut self, view: RegView, subkey: &str) -> &mut Self {
        self.ensure_key(view, subkey);
        self
    }

    /// Create a key in both views.
    pub fn add_key_both(&mut self, subkey: &str) -> &mut Self {
        self.add_key(RegView::Native, subkey);
        self.add_key(RegView::Wow32, subkey)
    }

    /// Set a value in `view`.
    pub fn set_value(&mut self, view: RegView, subkey: &str, name: &str, v: RegValue) -> &mut Self {
        self.ensure_key(view, subkey)
            .values
            .insert(canon_value_name(name), v);
        self
    }

    /// Set a value in both views.
    pub fn set_value_both(&mut self, subkey: &str, name: &str, v: RegValue) -> &mut Self {
        self.set_value(RegView::Native, subkey, name, v.clone());
        self.set_value(RegView::Wow32, subkey, name, v)
    }

    /// `REG_DWORD` in both views.
    pub fn set_dword(&mut self, subkey: &str, name: &str, d: u32) -> &mut Self {
        self.set_value_both(subkey, name, RegValue::Dword(d))
    }

    /// `REG_SZ` in both views.
    pub fn set_sz(&mut self, subkey: &str, name: &str, s: &str) -> &mut Self {
        self.set_value_both(subkey, name, RegValue::Sz(s.to_owned()))
    }

    /// Add a file reachable as `csidl`-relative (`Some`) or absolute (`None`).
    pub fn add_file(&mut self, csidl: Option<i32>, path: &str, info: FileInfo) -> &mut Self {
        let key = csidl.map_or(FileKey::Absolute, FileKey::Csidl);
        self.files.insert((key, canon_path(path)), info);
        self
    }

    /// Set the OS identity.
    pub fn set_os(&mut self, os: OsInfo) -> &mut Self {
        self.os = Some(os);
        self
    }

    /// Set the processor architecture.
    pub fn set_architecture(&mut self, arch: u32) -> &mut Self {
        self.arch = Some(arch);
        self
    }

    /// Set a system metric.
    pub fn set_metric(&mut self, index: i32, v: i32) -> &mut Self {
        self.metrics.insert(index, v);
        self
    }

    /// Set the OS language tag.
    pub fn set_language(&mut self, tag: &str) -> &mut Self {
        self.language = Some(tag.to_owned());
        self
    }

    /// Set MUI state.
    pub fn set_mui_installed(&mut self, b: bool) -> &mut Self {
        self.mui = Some(b);
        self
    }

    /// Set a licensing DWORD.
    pub fn set_license_dword(&mut self, name: &str, v: u32) -> &mut Self {
        self.licenses.insert(name.to_lowercase(), v);
        self
    }

    /// Define the answer of a WQL query.
    pub fn set_wmi(&mut self, namespace: &str, wql: &str, rows: bool) -> &mut Self {
        self.wmi
            .insert((canon_wmi_ns(namespace), wql.to_owned()), rows);
        self
    }

    /// Install an MSI product.
    pub fn add_msi_product(
        &mut self,
        code: &str,
        version: &str,
        language: Option<u32>,
    ) -> &mut Self {
        self.msi_products.insert(
            canon_guid(code),
            MsiProduct {
                version: version.to_owned(),
                language,
            },
        );
        self
    }

    /// Mark an MSI feature installed.
    pub fn add_msi_feature(&mut self, product: &str, feature: &str) -> &mut Self {
        self.msi_features
            .insert((canon_guid(product), feature.to_lowercase()));
        self
    }

    /// Mark an MSI component installed.
    pub fn add_msi_component(&mut self, product: &str, component: &str) -> &mut Self {
        self.msi_components
            .insert((canon_guid(product), canon_guid(component)));
        self
    }

    /// Mark an MSI patch applied.
    pub fn add_msi_patch(&mut self, product: &str, patch: &str) -> &mut Self {
        self.msi_patches
            .insert((canon_guid(product), canon_guid(patch)));
        self
    }

    /// Set the CBS `CurrentState` of a package.
    pub fn set_cbs_package(&mut self, identity: &str, state: CbsState) -> &mut Self {
        self.cbs.insert(identity.to_lowercase(), state);
        self
    }
}

fn canon_wmi_ns(ns: &str) -> String {
    canon_key(ns)
}

/// Join a registry base and a relative path with exactly one backslash.
pub fn join_prepend(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('\\');
    let path = path.trim_start_matches('\\');
    format!("{base}\\{path}")
}

impl FactProvider for FakeFacts {
    fn reg_key_exists(&self, view: RegView, subkey: &str) -> Fact<()> {
        if self.keys.contains_key(&(view, canon_key(subkey))) {
            Fact::Known(())
        } else {
            Fact::Absent
        }
    }

    fn reg_value(&self, view: RegView, subkey: &str, name: &str) -> Fact<RegValue> {
        match self
            .keys
            .get(&(view, canon_key(subkey)))
            .and_then(|k| k.values.get(&canon_value_name(name)))
        {
            Some(v) => Fact::Known(v.clone()),
            None => Fact::Absent,
        }
    }

    fn reg_subkeys(&self, view: RegView, subkey: &str) -> Fact<Vec<String>> {
        let parent = canon_key(subkey);
        if !self.keys.contains_key(&(view, parent.clone())) {
            return Fact::Absent;
        }
        let prefix = format!("{parent}\\");
        let names = self
            .keys
            .iter()
            .filter(|((v, k), _)| {
                *v == view && k.starts_with(&prefix) && !k[prefix.len()..].contains('\\')
            })
            .map(|(_, key)| key.display.rsplit('\\').next().unwrap_or("").to_owned())
            .collect();
        Fact::Known(names)
    }

    fn file(&self, loc: &FileLocation, path: &str) -> Fact<FileInfo> {
        let (key, p) = match loc {
            FileLocation::Csidl { csidl: c } => (FileKey::Csidl(*c), canon_path(path)),
            FileLocation::Absolute => (FileKey::Absolute, canon_path(path)),
            FileLocation::RegSz {
                view,
                subkey,
                value,
            } => match self.reg_value(*view, subkey, value) {
                Fact::Known(RegValue::Sz(b) | RegValue::ExpandSz(b)) => {
                    (FileKey::Absolute, canon_path(&join_prepend(&b, path)))
                }
                Fact::Known(_) => return Fact::unavailable("base registry value is not a string"),
                Fact::Absent => return Fact::Absent,
                Fact::Unavailable(r) => return Fact::Unavailable(r),
            },
        };
        match self.files.get(&(key, p)) {
            Some(i) => Fact::Known(i.clone()),
            None => Fact::Absent,
        }
    }

    fn os(&self) -> Fact<OsInfo> {
        self.os
            .clone()
            .map_or_else(|| Fact::unavailable("OS not set"), Fact::Known)
    }

    fn processor_architecture(&self) -> Fact<u32> {
        self.arch
            .map_or_else(|| Fact::unavailable("architecture not set"), Fact::Known)
    }

    fn system_metric(&self, index: i32) -> Fact<i32> {
        self.metrics
            .get(&index)
            .copied()
            .map_or_else(|| Fact::unavailable("metric not set"), Fact::Known)
    }

    fn windows_language(&self) -> Fact<String> {
        self.language
            .clone()
            .map_or_else(|| Fact::unavailable("language not set"), Fact::Known)
    }

    fn mui_installed(&self) -> Fact<bool> {
        self.mui
            .map_or_else(|| Fact::unavailable("MUI not set"), Fact::Known)
    }

    fn license_dword(&self, name: &str) -> Fact<u32> {
        self.licenses
            .get(&name.to_lowercase())
            .copied()
            .map_or(Fact::Absent, Fact::Known)
    }

    fn wmi_query(&self, namespace: &str, wql: &str) -> Fact<bool> {
        self.wmi
            .get(&(canon_wmi_ns(namespace), wql.to_owned()))
            .copied()
            .map_or_else(|| Fact::unavailable("WQL result not defined"), Fact::Known)
    }

    fn msi_product(&self, product: &str) -> Fact<MsiProduct> {
        self.msi_products
            .get(&canon_guid(product))
            .cloned()
            .map_or(Fact::Absent, Fact::Known)
    }

    fn msi_feature(&self, product: &str, feature: &str) -> Fact<bool> {
        Fact::Known(
            self.msi_features
                .contains(&(canon_guid(product), feature.to_lowercase())),
        )
    }

    fn msi_component(&self, product: &str, component: &str) -> Fact<bool> {
        Fact::Known(
            self.msi_components
                .contains(&(canon_guid(product), canon_guid(component))),
        )
    }

    fn msi_patch(&self, product: &str, patch: &str) -> Fact<bool> {
        Fact::Known(
            self.msi_patches
                .contains(&(canon_guid(product), canon_guid(patch))),
        )
    }

    fn cbs_package(&self, identity: &str) -> Fact<CbsState> {
        self.cbs
            .get(&identity.to_lowercase())
            .copied()
            .map_or(Fact::Absent, Fact::Known)
    }
}
