//! Fact recording and file-backed providers.
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, path::Path};
use wsus_protocol::applicability::{
    Fact, FactProvider, FileInfo, FileLocation, RecordedFacts, RegValue, RegView,
    facts::{CbsState, MsiProduct, OsInfo},
    value::{canon_guid, canon_key, canon_path},
};

/// Loads a `wsus-applicability-facts/1` snapshot (the format written by
/// `scripts/wsus/collect-facts.ps1`) for host dry-runs. Returns the provider
/// and the SHA-256 (hex) of the file bytes.
pub fn load_facts_file(path: &Path) -> Result<(RecordedFacts, String), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let facts = RecordedFacts::from_json(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((facts, crate::download::hex_encode(&Sha256::digest(&bytes))))
}

/// Wraps a provider and records every query with its answer. The recording
/// is canonical (names case-folded, sorted), so [`RecordingFacts::digest`]
/// identifies the facts a decision actually depended on and is stable for the
/// same machine state, whatever order the evaluator asked in.
pub struct RecordingFacts<'a> {
    inner: &'a dyn FactProvider,
    log: RefCell<BTreeMap<String, String>>,
}

impl<'a> RecordingFacts<'a> {
    pub fn new(inner: &'a dyn FactProvider) -> Self {
        Self {
            inner,
            log: RefCell::new(BTreeMap::new()),
        }
    }

    fn note<T: std::fmt::Debug>(&self, key: String, fact: Fact<T>) -> Fact<T> {
        self.log.borrow_mut().insert(key, format!("{fact:?}"));
        fact
    }

    /// Number of distinct queries answered so far.
    pub fn queries(&self) -> usize {
        self.log.borrow().len()
    }

    /// SHA-256 (hex) over the sorted `query -> answer` lines.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"wsus-facts-v1\n");
        for (k, v) in self.log.borrow().iter() {
            h.update(k.as_bytes());
            h.update(b"\t");
            h.update(v.as_bytes());
            h.update(b"\n");
        }
        crate::download::hex_encode(&h.finalize())
    }

    /// The recorded `query -> answer` lines (evidence).
    pub fn lines(&self) -> Vec<(String, String)> {
        self.log
            .borrow()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

fn loc_key(loc: &FileLocation) -> String {
    match loc {
        FileLocation::Csidl { csidl } => format!("csidl:{csidl}"),
        FileLocation::Absolute => "absolute".into(),
        FileLocation::RegSz {
            view,
            subkey,
            value,
        } => format!(
            "regsz:{view:?}:{}:{}",
            canon_key(subkey),
            value.to_lowercase()
        ),
    }
}

impl FactProvider for RecordingFacts<'_> {
    fn reg_key_exists(&self, view: RegView, subkey: &str) -> Fact<()> {
        self.note(
            format!("reg_key|{view:?}|{}", canon_key(subkey)),
            self.inner.reg_key_exists(view, subkey),
        )
    }
    fn reg_value(&self, view: RegView, subkey: &str, name: &str) -> Fact<RegValue> {
        self.note(
            format!(
                "reg_value|{view:?}|{}|{}",
                canon_key(subkey),
                name.to_lowercase()
            ),
            self.inner.reg_value(view, subkey, name),
        )
    }
    fn reg_subkeys(&self, view: RegView, subkey: &str) -> Fact<Vec<String>> {
        let f = self.inner.reg_subkeys(view, subkey).map(|mut v| {
            v.sort_by_key(|s| s.to_lowercase());
            v
        });
        self.note(format!("reg_subkeys|{view:?}|{}", canon_key(subkey)), f)
    }
    fn file(&self, loc: &FileLocation, path: &str) -> Fact<FileInfo> {
        self.note(
            format!("file|{}|{}", loc_key(loc), canon_path(path)),
            self.inner.file(loc, path),
        )
    }
    fn os(&self) -> Fact<OsInfo> {
        self.note("os".into(), self.inner.os())
    }
    fn processor_architecture(&self) -> Fact<u32> {
        self.note("arch".into(), self.inner.processor_architecture())
    }
    fn system_metric(&self, index: i32) -> Fact<i32> {
        self.note(format!("metric|{index}"), self.inner.system_metric(index))
    }
    fn windows_language(&self) -> Fact<String> {
        self.note("language".into(), self.inner.windows_language())
    }
    fn mui_installed(&self) -> Fact<bool> {
        self.note("mui".into(), self.inner.mui_installed())
    }
    fn license_dword(&self, name: &str) -> Fact<u32> {
        self.note(
            format!("license|{}", name.to_lowercase()),
            self.inner.license_dword(name),
        )
    }
    fn wmi_query(&self, namespace: &str, wql: &str) -> Fact<bool> {
        self.note(
            format!("wmi|{}|{}", canon_key(namespace), wql.trim()),
            self.inner.wmi_query(namespace, wql),
        )
    }
    fn msi_product(&self, product: &str) -> Fact<MsiProduct> {
        self.note(
            format!("msi_product|{}", canon_guid(product)),
            self.inner.msi_product(product),
        )
    }
    fn msi_feature(&self, product: &str, feature: &str) -> Fact<bool> {
        self.note(
            format!(
                "msi_feature|{}|{}",
                canon_guid(product),
                feature.to_lowercase()
            ),
            self.inner.msi_feature(product, feature),
        )
    }
    fn msi_component(&self, product: &str, component: &str) -> Fact<bool> {
        self.note(
            format!(
                "msi_component|{}|{}",
                canon_guid(product),
                canon_guid(component)
            ),
            self.inner.msi_component(product, component),
        )
    }
    fn msi_patch(&self, product: &str, patch: &str) -> Fact<bool> {
        self.note(
            format!("msi_patch|{}|{}", canon_guid(product), canon_guid(patch)),
            self.inner.msi_patch(product, patch),
        )
    }
    fn cbs_package(&self, identity: &str) -> Fact<CbsState> {
        self.note(
            format!("cbs|{}", identity.to_lowercase()),
            self.inner.cbs_package(identity),
        )
    }
}
