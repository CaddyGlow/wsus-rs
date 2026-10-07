//! `facts-check`: runs a fact provider over a `queries.json` and compares it
//! with a reference snapshot (the one `scripts/wsus/collect-facts.ps1`
//! produced on the same machine state). This is how a provider such as the
//! Windows one is validated against the PowerShell reference.
//!
//! Agreement is judged per query kind. States are `known`, `absent`,
//! `unavailable`. A pair counts as
//!
//! * `agree`: same state and, for `known`, equal values;
//! * `disagree`: both definite (`known` or `absent`) and different;
//! * `ours_unavailable`: the provider under test cannot answer a query the
//!   reference answered (a coverage gap, not a wrong answer);
//! * `reference_unavailable`: the reference could not answer (or does not
//!   hold the query) while the provider under test did.
//!
//! Only `disagree` is a failure.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wsus_protocol::applicability::{
    Fact, FactProvider, FactQuery, QueryItem, RecordedFacts, RegView, recorded::reg_value_to_json,
};

/// A provider answer in comparable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Answer {
    /// `known`, `absent` or `unavailable`.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn conv<T>(f: Fact<T>, to: impl FnOnce(T) -> Option<Value>) -> Answer {
    match f {
        Fact::Known(v) => Answer {
            state: "known",
            value: to(v),
            reason: None,
        },
        Fact::Absent => Answer {
            state: "absent",
            value: None,
            reason: None,
        },
        Fact::Unavailable(r) => Answer {
            state: "unavailable",
            value: None,
            reason: Some(r),
        },
    }
}

fn to_value<T: Serialize>(v: &T) -> Option<Value> {
    serde_json::to_value(v).ok()
}

/// Asks `p` the query `q`.
pub fn answer(p: &dyn FactProvider, q: &FactQuery) -> Answer {
    match q {
        FactQuery::RegKey { view, subkey } => conv(p.reg_key_exists(*view, subkey), |()| None),
        FactQuery::RegValue {
            view,
            subkey,
            value,
        } => conv(p.reg_value(*view, subkey, value), |v| {
            Some(reg_value_to_json(&v))
        }),
        FactQuery::RegSubkeys { view, subkey } => conv(p.reg_subkeys(*view, subkey), |mut v| {
            v.sort_by_key(|s| s.to_lowercase());
            to_value(&v)
        }),
        FactQuery::File { location, path } => conv(p.file(location, path), |i| to_value(&i)),
        FactQuery::SystemMetric { index } => conv(p.system_metric(*index), |v| Some(json!(v))),
        FactQuery::LicenseDword { name } => conv(p.license_dword(name), |v| Some(json!(v))),
        FactQuery::WmiQuery { namespace, query } => {
            conv(p.wmi_query(namespace, query), |v| Some(json!(v)))
        }
        FactQuery::MsiProduct { product } => conv(p.msi_product(product), |v| to_value(&v)),
        FactQuery::MsiFeature { product, feature } => {
            conv(p.msi_feature(product, feature), |v| Some(json!(v)))
        }
        FactQuery::MsiComponent { product, component } => {
            conv(p.msi_component(product, component), |v| Some(json!(v)))
        }
        FactQuery::MsiPatch { product, patch } => {
            conv(p.msi_patch(product, patch), |v| Some(json!(v)))
        }
        FactQuery::CbsPackage { identity } => conv(p.cbs_package(identity), |v| Some(json!(v))),
    }
}

/// `queries.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct QueriesFile {
    pub schema: String,
    #[serde(default)]
    pub generated: Option<String>,
    pub queries: Vec<QueryItem>,
}

/// Schema of `queries.json`.
pub const QUERIES_SCHEMA: &str = "wsus-applicability-queries/1";

/// Query kind name (`reg_value`, `file`, ...).
pub fn kind_of(q: &FactQuery) -> &'static str {
    match q {
        FactQuery::RegKey { .. } => "reg_key",
        FactQuery::RegValue { .. } => "reg_value",
        FactQuery::RegSubkeys { .. } => "reg_subkeys",
        FactQuery::File { .. } => "file",
        FactQuery::SystemMetric { .. } => "system_metric",
        FactQuery::LicenseDword { .. } => "license_dword",
        FactQuery::WmiQuery { .. } => "wmi_query",
        FactQuery::MsiProduct { .. } => "msi_product",
        FactQuery::MsiFeature { .. } => "msi_feature",
        FactQuery::MsiComponent { .. } => "msi_component",
        FactQuery::MsiPatch { .. } => "msi_patch",
        FactQuery::CbsPackage { .. } => "cbs_package",
    }
}

/// Counts for one kind.
#[derive(Debug, Clone, Default, Serialize)]
pub struct KindReport {
    pub total: u64,
    pub agree: u64,
    pub disagree: u64,
    pub ours_unavailable: u64,
    pub reference_unavailable: u64,
}

/// One disagreement or gap, with enough detail to investigate.
#[derive(Debug, Clone, Serialize)]
pub struct Difference {
    pub kind: &'static str,
    pub class: &'static str,
    pub query: Value,
    pub ours: Answer,
    pub reference: Answer,
}

/// Result of [`facts_check`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct CheckReport {
    pub kinds: BTreeMap<String, KindReport>,
    pub total: u64,
    pub disagree: u64,
    pub ours_unavailable: u64,
    pub reference_unavailable: u64,
    /// Up to `max_details` differences per class, in query order.
    pub differences: Vec<Difference>,
}

impl CheckReport {
    /// True when no query disagreed.
    pub fn agrees(&self) -> bool {
        self.disagree == 0
    }
}

fn same_value(kind: &str, ours: &Option<Value>, reference: &Option<Value>) -> bool {
    if kind == "file" {
        // `resolved_path` is evidence only and compared case-insensitively
        // (NTFS); every other field must be equal.
        let norm = |v: &Option<Value>| {
            let mut v = v.clone();
            if let Some(Value::Object(m)) = &mut v
                && let Some(Value::String(s)) = m.get_mut("resolved_path")
            {
                *s = s.to_lowercase();
            }
            v
        };
        return norm(ours) == norm(reference);
    }
    ours == reference
}

fn classify(kind: &str, ours: &Answer, reference: &Answer) -> &'static str {
    match (ours.state, reference.state) {
        ("unavailable", "unavailable") => "agree",
        ("unavailable", _) => "ours_unavailable",
        (_, "unavailable") => "reference_unavailable",
        (a, b) if a != b => "disagree",
        ("known", _) => {
            if same_value(kind, &ours.value, &reference.value) {
                "agree"
            } else {
                "disagree"
            }
        }
        _ => "agree",
    }
}

/// Expands loop templates like the collector does (children of the loop key,
/// as the provider under test sees them), then answers every query with `ours`
/// and `reference` and compares.
pub fn facts_check(
    queries: &QueriesFile,
    ours: &dyn FactProvider,
    reference: &RecordedFacts,
    max_details: usize,
) -> CheckReport {
    let mut report = CheckReport::default();
    let mut detail_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut expanded: Vec<FactQuery> = Vec::new();
    for item in &queries.queries {
        match &item.loop_parent {
            None => expanded.push(item.query.clone()),
            Some(parent) => {
                let view = match &item.query {
                    FactQuery::RegKey { view, .. }
                    | FactQuery::RegValue { view, .. }
                    | FactQuery::RegSubkeys { view, .. } => *view,
                    _ => RegView::Native,
                };
                let Fact::Known(children) = ours.reg_subkeys(view, parent) else {
                    continue;
                };
                for child in children {
                    let rel = match &item.query {
                        FactQuery::RegKey { subkey, .. }
                        | FactQuery::RegValue { subkey, .. }
                        | FactQuery::RegSubkeys { subkey, .. } => subkey.clone(),
                        _ => continue,
                    };
                    let full = format!(
                        "{}\\{}\\{}",
                        parent.trim_matches('\\'),
                        child,
                        rel.trim_matches('\\')
                    );
                    expanded.push(match item.query.clone() {
                        FactQuery::RegKey { view, .. } => FactQuery::RegKey { view, subkey: full },
                        FactQuery::RegValue { view, value, .. } => FactQuery::RegValue {
                            view,
                            subkey: full,
                            value,
                        },
                        FactQuery::RegSubkeys { view, .. } => {
                            FactQuery::RegSubkeys { view, subkey: full }
                        }
                        other => other,
                    });
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for q in expanded {
        if !seen.insert(q.normalized()) {
            continue;
        }
        let kind = kind_of(&q);
        let a = answer(ours, &q);
        let b = answer(reference, &q);
        let class = classify(kind, &a, &b);
        let k = report.kinds.entry(kind.to_owned()).or_default();
        k.total += 1;
        report.total += 1;
        match class {
            "agree" => k.agree += 1,
            "disagree" => {
                k.disagree += 1;
                report.disagree += 1;
            }
            "ours_unavailable" => {
                k.ours_unavailable += 1;
                report.ours_unavailable += 1;
            }
            _ => {
                k.reference_unavailable += 1;
                report.reference_unavailable += 1;
            }
        }
        if class != "agree" {
            let n = detail_counts.entry(class).or_default();
            if *n < max_details {
                *n += 1;
                report.differences.push(Difference {
                    kind,
                    class,
                    query: serde_json::to_value(&q).unwrap_or(Value::Null),
                    ours: a,
                    reference: b,
                });
            }
        }
    }
    // OS-wide facts the collector records outside the query list.
    let os_pairs: [(&'static str, Answer, Answer); 4] = [
        (
            "os",
            conv(ours.os(), |o| {
                Some(json!({"major": o.major, "minor": o.minor, "build": o.build,
                    "sp_major": o.sp_major, "sp_minor": o.sp_minor,
                    "product_type": o.product_type, "suite_mask": o.suite_mask}))
            }),
            conv(reference.os(), |o| {
                Some(json!({"major": o.major, "minor": o.minor, "build": o.build,
                    "sp_major": o.sp_major, "sp_minor": o.sp_minor,
                    "product_type": o.product_type, "suite_mask": o.suite_mask}))
            }),
        ),
        (
            "architecture",
            conv(ours.processor_architecture(), |v| Some(json!(v))),
            conv(reference.processor_architecture(), |v| Some(json!(v))),
        ),
        (
            "language",
            conv(ours.windows_language(), |v| Some(json!(v))),
            conv(reference.windows_language(), |v| Some(json!(v))),
        ),
        (
            "mui_installed",
            conv(ours.mui_installed(), |v| Some(json!(v))),
            conv(reference.mui_installed(), |v| Some(json!(v))),
        ),
    ];
    for (kind, a, b) in os_pairs {
        let class = classify(kind, &a, &b);
        let k = report.kinds.entry(kind.to_owned()).or_default();
        k.total += 1;
        report.total += 1;
        match class {
            "agree" => k.agree += 1,
            "disagree" => {
                k.disagree += 1;
                report.disagree += 1;
            }
            "ours_unavailable" => {
                k.ours_unavailable += 1;
                report.ours_unavailable += 1;
            }
            _ => {
                k.reference_unavailable += 1;
                report.reference_unavailable += 1;
            }
        }
        if class != "agree" {
            report.differences.push(Difference {
                kind,
                class,
                query: json!({"kind": kind}),
                ours: a,
                reference: b,
            });
        }
    }
    report
}

/// Parses a `queries.json` text.
pub fn parse_queries(text: &str) -> Result<QueriesFile, String> {
    let q: QueriesFile = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("queries file: {e}"))?;
    if q.schema != QUERIES_SCHEMA {
        return Err(format!("unsupported queries schema `{}`", q.schema));
    }
    Ok(q)
}
