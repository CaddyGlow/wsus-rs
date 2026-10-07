//! Static listing of the fact queries an expression can issue.
//!
//! Used to build `queries.json` for a collector (see
//! `scripts/wsus/applicability-queries.py`, which implements the same walk
//! over the stored revisions and is cross-checked against this one by
//! `tests/applicability_real.rs`).
//!
//! Queries inside a `RegKeyLoop` body that name `HKEY_LOOP_TARGET` depend on
//! the sub-keys found at collection time; they are listed as templates with
//! `loop_parent` set to the loop key and a `subkey` relative to each child.
//! The evaluator asks for `<loop_parent>\<child>\<subkey>`.
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::expr::{Expr, FileBase, FileRef, Operator, RegKeyRef, RegValueRef, RegView};
use super::facts::FileLocation;
use super::recorded::FactQuery;

/// One query, possibly a loop template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryItem {
    #[serde(flatten)]
    pub query: FactQuery,
    /// Set for templates: the loop key whose children replace the loop
    /// target; `query`'s sub-key is relative to each child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loop_parent: Option<String>,
}

impl QueryItem {
    /// De-duplication key.
    pub fn key(&self) -> (FactQuery, Option<String>) {
        (
            self.query.normalized(),
            self.loop_parent.as_deref().map(super::value::canon_key),
        )
    }
}

/// Collect every query `expr` can issue, in first-seen order, without
/// duplicates.
pub fn required_queries(expr: &Expr) -> Vec<QueryItem> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk(expr, None, &mut |q| {
        if seen.insert(q.key()) {
            out.push(q);
        }
    });
    out
}

fn key_query(k: &RegKeyRef, loop_parent: Option<&(RegView, String)>) -> Option<QueryItem> {
    let (view, subkey, parent) = match (k.loop_target, loop_parent) {
        (false, _) => (k.view, k.subkey.clone(), None),
        (true, Some((v, base))) => (*v, k.subkey.clone(), Some(base.clone())),
        (true, None) => return None,
    };
    Some(QueryItem {
        query: FactQuery::RegKey { view, subkey },
        loop_parent: parent,
    })
}

fn value_query(v: &RegValueRef, lp: Option<&(RegView, String)>) -> Option<QueryItem> {
    let k = key_query(&v.key, lp)?;
    let FactQuery::RegKey { view, subkey } = k.query else {
        return None;
    };
    Some(QueryItem {
        query: FactQuery::RegValue {
            view,
            subkey,
            value: v.value.clone(),
        },
        loop_parent: k.loop_parent,
    })
}

fn file_query(f: &FileRef) -> QueryItem {
    let location = match &f.base {
        FileBase::Csidl(c) => FileLocation::Csidl { csidl: *c },
        FileBase::None => FileLocation::Absolute,
        FileBase::RegSz(v) => FileLocation::RegSz {
            view: v.key.view,
            subkey: v.key.subkey.clone(),
            value: v.value.clone(),
        },
    };
    QueryItem {
        query: FactQuery::File {
            location,
            path: f.path.clone(),
        },
        loop_parent: None,
    }
}

fn walk(e: &Expr, lp: Option<&(RegView, String)>, emit: &mut impl FnMut(QueryItem)) {
    let q = |query: FactQuery| QueryItem {
        query,
        loop_parent: None,
    };
    match e {
        Expr::And(v) | Expr::Or(v) => v.iter().for_each(|x| walk(x, lp, emit)),
        Expr::Not(x) => walk(x, lp, emit),
        Expr::RegKeyLoop(l) => {
            if let Some(item) = key_query(&l.key, lp)
                && item.loop_parent.is_none()
            {
                let FactQuery::RegKey { view, subkey } = item.query else {
                    return;
                };
                emit(q(FactQuery::RegSubkeys {
                    view,
                    subkey: subkey.clone(),
                }));
                walk(&l.body, Some(&(view, subkey)), emit);
            }
        }
        Expr::Op(op) => match op {
            Operator::RegKeyExists(k) => {
                if let Some(i) = key_query(k, lp) {
                    emit(i);
                }
            }
            Operator::RegValueExists { value, .. }
            | Operator::RegDword { value, .. }
            | Operator::RegSz { value, .. }
            | Operator::RegExpandSz { value, .. }
            | Operator::RegSzToVersion { value, .. } => {
                if let Some(i) = value_query(value, lp) {
                    emit(i);
                }
            }
            Operator::FileExists { file, .. }
            | Operator::FileVersion { file, .. }
            | Operator::FileCreated { file, .. }
            | Operator::FileModified { file, .. }
            | Operator::FileSize { file, .. } => emit(file_query(file)),
            Operator::SystemMetric { index, .. } => {
                emit(q(FactQuery::SystemMetric { index: *index }))
            }
            Operator::LicenseDword { name, .. } => {
                emit(q(FactQuery::LicenseDword { name: name.clone() }));
            }
            Operator::WmiQuery { namespace, query } => emit(q(FactQuery::WmiQuery {
                namespace: namespace.clone().unwrap_or_else(|| "root\\cimv2".into()),
                query: query.clone(),
            })),
            Operator::MsiProductInstalled(r) => emit(q(FactQuery::MsiProduct {
                product: r.product.clone(),
            })),
            Operator::MsiFeatureInstalledForProduct {
                features, products, ..
            } => {
                for p in products {
                    for f in features {
                        emit(q(FactQuery::MsiFeature {
                            product: p.clone(),
                            feature: f.clone(),
                        }));
                    }
                }
            }
            Operator::MsiComponentInstalledForProduct {
                components,
                products,
                ..
            } => {
                for p in products {
                    for c in components {
                        emit(q(FactQuery::MsiComponent {
                            product: p.clone(),
                            component: c.clone(),
                        }));
                    }
                }
            }
            Operator::MsiPatchInstalledForProduct { patch, product } => {
                emit(q(FactQuery::MsiPatch {
                    product: product.clone(),
                    patch: patch.clone(),
                }));
            }
            Operator::CbsPackageInstalled { identity } => emit(q(FactQuery::CbsPackage {
                identity: identity.clone(),
            })),
            // OS-wide facts, always collected.
            Operator::WindowsVersion(_)
            | Operator::WindowsLanguage { .. }
            | Operator::MuiInstalled
            | Operator::DeviceAttribute { .. }
            | Operator::ProductReleaseInstalled { .. }
            | Operator::ProductReleaseVersion { .. }
            | Operator::Processor { .. } => {}
        },
        Expr::True | Expr::False | Expr::Unsupported(_) => {}
    }
}
