//! Recorded fact snapshots: the JSON format written by
//! `scripts/wsus/collect-facts.ps1` and read by [`RecordedFacts`].
//!
//! ```json
//! {
//!   "schema": "wsus-applicability-facts/1",
//!   "collected_at": "2026-10-04T12:00:00Z",
//!   "machine": { "computer": "...", "is_64bit_process": true },
//!   "os": { "major": 10, "minor": 0, "build": 26200, "sp_major": 0, "sp_minor": 0,
//!           "product_type": 1, "suite_mask": 256, "architecture": 9,
//!           "language": "en-US", "mui_installed": false },
//!   "facts": [
//!     { "kind": "reg_value", "view": "native", "subkey": "SOFTWARE\\X", "value": "V",
//!       "result": { "state": "known", "value": { "type": "REG_DWORD", "data": 1 } } },
//!     { "kind": "reg_key", "view": "wow32", "subkey": "SOFTWARE\\Y",
//!       "result": { "state": "absent" } }
//!   ]
//! }
//! ```
//!
//! `result.state` is `known` (with `value`), `absent` or `unavailable` (with
//! `reason`). The query fields are the same ones `queries.json` carries, so a
//! collector echoes each query and adds `result`. A query that is not in the
//! snapshot is `Unavailable`, never `Absent`: a snapshot is an open world.
//!
//! Value shapes by kind: `reg_key` none; `reg_value` an object with `type`
//! (`REG_DWORD` data number, `REG_QWORD` data decimal string, `REG_SZ` and
//! `REG_EXPAND_SZ` data string, `REG_MULTI_SZ` data array of strings,
//! `REG_BINARY` data lower-case hex, anything else `{"type":"OTHER","name":..}`);
//! `reg_subkeys` an array of names; `file` an object with optional `size`,
//! `version` (`a.b.c.d`), `modified`, `created` (RFC 3339 UTC) and
//! `resolved_path`; `system_metric` an integer; `license_dword` an unsigned
//! integer; `wmi_query`, `msi_feature`, `msi_component`, `msi_patch` a boolean;
//! `msi_product` `{"version": "...", "language": 1033}`; `cbs_package` the
//! `CurrentState` number.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::facts::{
    CbsState, Fact, FactProvider, FileInfo, FileLocation, MsiProduct, OsInfo, RegValue, RegView,
};
use super::value::{canon_guid, canon_key, canon_path, canon_value_name};

/// Snapshot schema identifier.
pub const SNAPSHOT_SCHEMA: &str = "wsus-applicability-facts/1";

/// Error loading a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported snapshot schema `{0}`")]
    Schema(String),
    #[error("fact {index}: {message}")]
    Fact { index: usize, message: String },
}

/// One fact query. Doubles as the query format of `queries.json` and as the
/// key of a recorded fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactQuery {
    RegKey {
        view: RegView,
        subkey: String,
    },
    RegValue {
        view: RegView,
        subkey: String,
        value: String,
    },
    RegSubkeys {
        view: RegView,
        subkey: String,
    },
    File {
        location: FileLocation,
        path: String,
    },
    SystemMetric {
        index: i32,
    },
    LicenseDword {
        name: String,
    },
    WmiQuery {
        namespace: String,
        query: String,
    },
    MsiProduct {
        product: String,
    },
    MsiFeature {
        product: String,
        feature: String,
    },
    MsiComponent {
        product: String,
        component: String,
    },
    MsiPatch {
        product: String,
        patch: String,
    },
    CbsPackage {
        identity: String,
    },
}

impl FactQuery {
    /// Case-folded, canonical form used for lookups and de-duplication.
    pub fn normalized(&self) -> FactQuery {
        match self {
            Self::RegKey { view, subkey } => Self::RegKey {
                view: *view,
                subkey: canon_key(subkey),
            },
            Self::RegValue {
                view,
                subkey,
                value,
            } => Self::RegValue {
                view: *view,
                subkey: canon_key(subkey),
                value: canon_value_name(value),
            },
            Self::RegSubkeys { view, subkey } => Self::RegSubkeys {
                view: *view,
                subkey: canon_key(subkey),
            },
            Self::File { location, path } => Self::File {
                location: match location {
                    FileLocation::RegSz {
                        view,
                        subkey,
                        value,
                    } => FileLocation::RegSz {
                        view: *view,
                        subkey: canon_key(subkey),
                        value: canon_value_name(value),
                    },
                    other => other.clone(),
                },
                path: canon_path(path),
            },
            Self::SystemMetric { index } => Self::SystemMetric { index: *index },
            Self::LicenseDword { name } => Self::LicenseDword {
                name: name.to_lowercase(),
            },
            Self::WmiQuery { namespace, query } => Self::WmiQuery {
                namespace: canon_key(namespace),
                query: query.trim().to_owned(),
            },
            Self::MsiProduct { product } => Self::MsiProduct {
                product: canon_guid(product),
            },
            Self::MsiFeature { product, feature } => Self::MsiFeature {
                product: canon_guid(product),
                feature: feature.to_lowercase(),
            },
            Self::MsiComponent { product, component } => Self::MsiComponent {
                product: canon_guid(product),
                component: canon_guid(component),
            },
            Self::MsiPatch { product, patch } => Self::MsiPatch {
                product: canon_guid(product),
                patch: canon_guid(patch),
            },
            Self::CbsPackage { identity } => Self::CbsPackage {
                identity: identity.to_lowercase(),
            },
        }
    }
}

/// Result of one recorded query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactResult {
    /// `known`, `absent` or `unavailable`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl FactResult {
    /// `known` with a value.
    pub fn known(value: Value) -> Self {
        Self {
            state: "known".into(),
            reason: None,
            value: Some(value),
        }
    }

    /// `known` with no value (key existence).
    pub fn known_unit() -> Self {
        Self {
            state: "known".into(),
            reason: None,
            value: None,
        }
    }

    /// `absent`.
    pub fn absent() -> Self {
        Self {
            state: "absent".into(),
            reason: None,
            value: None,
        }
    }

    /// `unavailable` with a reason.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: "unavailable".into(),
            reason: Some(reason.into()),
            value: None,
        }
    }
}

/// One query and its recorded result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactEntry {
    #[serde(flatten)]
    pub query: FactQuery,
    pub result: FactResult,
}

/// OS-wide facts of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnapshotOs {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    #[serde(default)]
    pub sp_major: u32,
    #[serde(default)]
    pub sp_minor: u32,
    pub product_type: u32,
    #[serde(default)]
    pub suite_mask: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mui_installed: Option<bool>,
}

/// The on-disk snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    pub collected_at: String,
    /// Free-form collector description (computer, build string, PowerShell
    /// version, bitness); not interpreted.
    #[serde(default)]
    pub machine: serde_json::Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<SnapshotOs>,
    #[serde(default)]
    pub facts: Vec<FactEntry>,
}

impl Snapshot {
    /// Empty snapshot with the current schema.
    pub fn new(collected_at: impl Into<String>) -> Self {
        Self {
            schema: SNAPSHOT_SCHEMA.into(),
            collected_at: collected_at.into(),
            machine: serde_json::Map::new(),
            os: None,
            facts: Vec::new(),
        }
    }

    /// Pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("snapshot serializes")
    }

    /// Parse JSON.
    pub fn from_json(text: &str) -> Result<Self, SnapshotError> {
        let s: Snapshot = serde_json::from_str(text)?;
        if s.schema != SNAPSHOT_SCHEMA {
            return Err(SnapshotError::Schema(s.schema));
        }
        Ok(s)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum RegValueJson {
    #[serde(rename = "REG_DWORD")]
    Dword { data: u32 },
    #[serde(rename = "REG_QWORD")]
    Qword { data: String },
    #[serde(rename = "REG_SZ")]
    Sz { data: String },
    #[serde(rename = "REG_EXPAND_SZ")]
    ExpandSz { data: String },
    #[serde(rename = "REG_MULTI_SZ")]
    MultiSz { data: Vec<String> },
    #[serde(rename = "REG_BINARY")]
    Binary { data: String },
    #[serde(rename = "OTHER")]
    Other { name: String },
}

/// JSON encoding of a [`RegValue`] (used by tests and tools that write
/// snapshots).
pub fn reg_value_to_json(v: &RegValue) -> Value {
    use serde_json::json;
    match v {
        RegValue::Dword(d) => json!({"type": "REG_DWORD", "data": d}),
        RegValue::Qword(q) => json!({"type": "REG_QWORD", "data": q.to_string()}),
        RegValue::Sz(s) => json!({"type": "REG_SZ", "data": s}),
        RegValue::ExpandSz(s) => json!({"type": "REG_EXPAND_SZ", "data": s}),
        RegValue::MultiSz(v) => json!({"type": "REG_MULTI_SZ", "data": v}),
        RegValue::Binary(b) => {
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            json!({"type": "REG_BINARY", "data": hex})
        }
        RegValue::Other(n) => json!({"type": "OTHER", "name": n}),
    }
}

fn decode_reg_value(v: Value) -> Result<RegValue, String> {
    let j: RegValueJson = serde_json::from_value(v).map_err(|e| e.to_string())?;
    Ok(match j {
        RegValueJson::Dword { data } => RegValue::Dword(data),
        RegValueJson::Qword { data } => {
            RegValue::Qword(data.parse().map_err(|_| format!("bad qword `{data}`"))?)
        }
        RegValueJson::Sz { data } => RegValue::Sz(data),
        RegValueJson::ExpandSz { data } => RegValue::ExpandSz(data),
        RegValueJson::MultiSz { data } => RegValue::MultiSz(data),
        RegValueJson::Binary { data } => {
            if data.len() % 2 != 0 || !data.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("binary data must be hex".into());
            }
            RegValue::Binary(
                (0..data.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&data[i..i + 2], 16).expect("checked hex"))
                    .collect(),
            )
        }
        RegValueJson::Other { name } => RegValue::Other(name),
    })
}

#[derive(Debug, Clone)]
enum Stored {
    Unit,
    Reg(RegValue),
    Names(Vec<String>),
    File(FileInfo),
    Int(i64),
    Flag(bool),
    Msi(MsiProduct),
}

fn decode(query: &FactQuery, r: FactResult) -> Result<Fact<Stored>, String> {
    match r.state.as_str() {
        "absent" => return Ok(Fact::Absent),
        "unavailable" => {
            return Ok(Fact::Unavailable(
                r.reason.unwrap_or_else(|| "unavailable".into()),
            ));
        }
        "known" => {}
        other => return Err(format!("unknown state `{other}`")),
    }
    let need = |v: Option<Value>| v.ok_or_else(|| "known result without value".to_owned());
    let s = |e: serde_json::Error| e.to_string();
    Ok(Fact::Known(match query {
        FactQuery::RegKey { .. } => Stored::Unit,
        FactQuery::RegValue { .. } => Stored::Reg(decode_reg_value(need(r.value)?)?),
        FactQuery::RegSubkeys { .. } => {
            Stored::Names(serde_json::from_value(need(r.value)?).map_err(s)?)
        }
        FactQuery::File { .. } => Stored::File(serde_json::from_value(need(r.value)?).map_err(s)?),
        FactQuery::SystemMetric { .. }
        | FactQuery::LicenseDword { .. }
        | FactQuery::CbsPackage { .. } => {
            Stored::Int(serde_json::from_value(need(r.value)?).map_err(s)?)
        }
        FactQuery::WmiQuery { .. }
        | FactQuery::MsiFeature { .. }
        | FactQuery::MsiComponent { .. }
        | FactQuery::MsiPatch { .. } => {
            Stored::Flag(serde_json::from_value(need(r.value)?).map_err(s)?)
        }
        FactQuery::MsiProduct { .. } => {
            Stored::Msi(serde_json::from_value(need(r.value)?).map_err(s)?)
        }
    }))
}

/// A [`FactProvider`] backed by a [`Snapshot`]. Queries missing from the
/// snapshot are `Unavailable`.
#[derive(Debug, Clone)]
pub struct RecordedFacts {
    os: Option<SnapshotOs>,
    facts: HashMap<FactQuery, Fact<Stored>>,
    collected_at: String,
}

impl RecordedFacts {
    /// Validate and index a snapshot. Duplicate queries with different
    /// results are an error.
    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self, SnapshotError> {
        if snapshot.schema != SNAPSHOT_SCHEMA {
            return Err(SnapshotError::Schema(snapshot.schema));
        }
        let mut facts: HashMap<FactQuery, Fact<Stored>> = HashMap::new();
        for (index, e) in snapshot.facts.into_iter().enumerate() {
            let key = e.query.normalized();
            let f = decode(&e.query, e.result)
                .map_err(|message| SnapshotError::Fact { index, message })?;
            if let Some(old) = facts.get(&key)
                && !same(old, &f)
            {
                return Err(SnapshotError::Fact {
                    index,
                    message: "duplicate query with a different result".into(),
                });
            }
            facts.insert(key, f);
        }
        Ok(Self {
            os: snapshot.os,
            facts,
            collected_at: snapshot.collected_at,
        })
    }

    /// Parse and index snapshot JSON.
    pub fn from_json(text: &str) -> Result<Self, SnapshotError> {
        Self::from_snapshot(Snapshot::from_json(text)?)
    }

    /// When the snapshot was collected (as written by the collector).
    pub fn collected_at(&self) -> &str {
        &self.collected_at
    }

    /// Number of recorded queries.
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// True when no query is recorded.
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    fn get(&self, q: FactQuery) -> Fact<&Stored> {
        match self.facts.get(&q.normalized()) {
            Some(Fact::Known(s)) => Fact::Known(s),
            Some(Fact::Absent) => Fact::Absent,
            Some(Fact::Unavailable(r)) => Fact::Unavailable(r.clone()),
            None => Fact::unavailable(format!("not in snapshot: {}", describe(&q))),
        }
    }
}

fn same(a: &Fact<Stored>, b: &Fact<Stored>) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

/// Compact one-line description of a query (used in unavailability reasons).
pub fn describe(q: &FactQuery) -> String {
    serde_json::to_string(q).unwrap_or_else(|_| format!("{q:?}"))
}

macro_rules! pick {
    ($fact:expr, $pat:pat => $out:expr) => {
        match $fact {
            Fact::Known($pat) => Fact::Known($out),
            Fact::Known(_) => Fact::unavailable("snapshot value has the wrong shape"),
            Fact::Absent => Fact::Absent,
            Fact::Unavailable(r) => Fact::Unavailable(r),
        }
    };
}

impl FactProvider for RecordedFacts {
    fn reg_key_exists(&self, view: RegView, subkey: &str) -> Fact<()> {
        pick!(
            self.get(FactQuery::RegKey { view, subkey: subkey.into() }),
            Stored::Unit => ()
        )
    }

    fn reg_value(&self, view: RegView, subkey: &str, name: &str) -> Fact<RegValue> {
        pick!(
            self.get(FactQuery::RegValue { view, subkey: subkey.into(), value: name.into() }),
            Stored::Reg(v) => v.clone()
        )
    }

    fn reg_subkeys(&self, view: RegView, subkey: &str) -> Fact<Vec<String>> {
        pick!(
            self.get(FactQuery::RegSubkeys { view, subkey: subkey.into() }),
            Stored::Names(v) => v.clone()
        )
    }

    fn file(&self, loc: &FileLocation, path: &str) -> Fact<FileInfo> {
        pick!(
            self.get(FactQuery::File { location: loc.clone(), path: path.into() }),
            Stored::File(i) => i.clone()
        )
    }

    fn os(&self) -> Fact<OsInfo> {
        match &self.os {
            Some(o) => Fact::Known(OsInfo {
                major: o.major,
                minor: o.minor,
                build: o.build,
                sp_major: o.sp_major,
                sp_minor: o.sp_minor,
                product_type: o.product_type,
                suite_mask: o.suite_mask,
                sku: None,
                ubr: None,
            }),
            None => Fact::unavailable("snapshot has no os section"),
        }
    }

    fn processor_architecture(&self) -> Fact<u32> {
        self.os.as_ref().and_then(|o| o.architecture).map_or_else(
            || Fact::unavailable("snapshot has no architecture"),
            Fact::Known,
        )
    }

    fn system_metric(&self, index: i32) -> Fact<i32> {
        pick!(
            self.get(FactQuery::SystemMetric { index }),
            Stored::Int(v) => i32::try_from(*v).unwrap_or(i32::MAX)
        )
    }

    fn windows_language(&self) -> Fact<String> {
        self.os
            .as_ref()
            .and_then(|o| o.language.clone())
            .map_or_else(
                || Fact::unavailable("snapshot has no language"),
                Fact::Known,
            )
    }

    fn mui_installed(&self) -> Fact<bool> {
        self.os.as_ref().and_then(|o| o.mui_installed).map_or_else(
            || Fact::unavailable("snapshot has no MUI state"),
            Fact::Known,
        )
    }

    fn license_dword(&self, name: &str) -> Fact<u32> {
        pick!(
            self.get(FactQuery::LicenseDword { name: name.into() }),
            Stored::Int(v) => u32::try_from(*v).unwrap_or(u32::MAX)
        )
    }

    fn wmi_query(&self, namespace: &str, wql: &str) -> Fact<bool> {
        pick!(
            self.get(FactQuery::WmiQuery { namespace: namespace.into(), query: wql.into() }),
            Stored::Flag(b) => *b
        )
    }

    fn msi_product(&self, product: &str) -> Fact<MsiProduct> {
        pick!(
            self.get(FactQuery::MsiProduct { product: product.into() }),
            Stored::Msi(p) => p.clone()
        )
    }

    fn msi_feature(&self, product: &str, feature: &str) -> Fact<bool> {
        pick!(
            self.get(FactQuery::MsiFeature { product: product.into(), feature: feature.into() }),
            Stored::Flag(b) => *b
        )
    }

    fn msi_component(&self, product: &str, component: &str) -> Fact<bool> {
        pick!(
            self.get(FactQuery::MsiComponent { product: product.into(), component: component.into() }),
            Stored::Flag(b) => *b
        )
    }

    fn msi_patch(&self, product: &str, patch: &str) -> Fact<bool> {
        pick!(
            self.get(FactQuery::MsiPatch { product: product.into(), patch: patch.into() }),
            Stored::Flag(b) => *b
        )
    }

    fn cbs_package(&self, identity: &str) -> Fact<CbsState> {
        pick!(
            self.get(FactQuery::CbsPackage { identity: identity.into() }),
            Stored::Int(v) => u32::try_from(*v).unwrap_or(u32::MAX)
        )
    }
}
