//! Reporting service.
use serde_json::json;
use wsus_protocol::identity::UpdateRevision;
use wsus_protocol::soap::{ErrorCode, Presence};
use wsus_protocol::wusp::{ReportEventBatch, ReportEventBatchResponse};

use super::Ctx;
use super::fault::{ApiError, invalid};
use super::time::parse_xs;
use crate::reporting::{EventKind, Inventory, NewEvent};
use crate::session::CookieKind;
use crate::storage;

pub(crate) fn report_event_batch(
    cx: &Ctx<'_>,
    req: ReportEventBatch,
) -> Result<ReportEventBatchResponse, ApiError> {
    let claims = cx
        .inner
        .svc
        .sessions
        .validate(req.cookie.value(), CookieKind::Session)?;
    let events = match &req.event_batch {
        Presence::Value(v) => v.as_slice(),
        _ => &[],
    };
    if events.len() > cx.inner.config.max_events_per_batch {
        return Err(invalid("too many events in one batch"));
    }
    // Validate and convert the whole batch first so a malformed event stores nothing.
    let mut batch = Vec::with_capacity(events.len());
    let mut inventories: Vec<Option<Inventory>> = Vec::with_capacity(events.len());
    let snapshot = if events.iter().any(|e| {
        e.basic_data.value().is_some_and(|b| {
            cx.inner.config.event_kinds.get(&b.event_id) == Some(&EventKind::ClientStatus)
        })
    }) {
        super::client::snapshot(cx, 0)?
    } else {
        None
    };
    for e in events {
        let b = e
            .basic_data
            .value()
            .ok_or(invalid("BasicData is required"))?;
        let at = parse_xs(b.time_at_target.as_str()).ok_or(invalid("bad TimeAtTarget"))?;
        let update = b
            .update_id
            .value()
            .filter(|u| !u.id.0.is_nil())
            .map(|u| UpdateRevision {
                id: u.id,
                revision: u.revision,
            });
        let strings = |p: Option<&Presence<Vec<String>>>| -> Vec<String> {
            match p {
                Some(Presence::Value(v)) => v.clone(),
                _ => Vec::new(),
            }
        };
        let raw = json!({
            "event_id": b.event_id,
            "source_id": b.source_id,
            "namespace_id": b.namespace_id,
            "sequence_number": b.sequence_number,
            "win32_hresult": b.win32_hresult,
            "app_name": b.app_name.value(),
            "event_instance_id": b.event_instance_id.hyphenated().to_string(),
            "time_at_target": b.time_at_target.as_str(),
            "update": update.map(|u| u.to_string()),
            "replacement_strings": strings(e.extended_data.value().map(|x| &x.replacement_strings)),
            "misc_data": strings(e.extended_data.value().map(|x| &x.misc_data)),
        });
        let kind = cx
            .inner
            .config
            .event_kinds
            .get(&b.event_id)
            .copied()
            .unwrap_or(EventKind::Other);
        inventories.push((kind == EventKind::ClientStatus).then(|| {
            let misc = strings(e.extended_data.value().map(|x| &x.misc_data));
            parse_inventory(&misc, snapshot.as_ref())
        }));
        batch.push(NewEvent {
            computer: claims.computer,
            update,
            kind,
            result_code: Some(i64::from(b.win32_hresult)),
            event_time: at,
            dedup_key: Some(b.event_instance_id.hyphenated().to_string()),
            raw: raw.to_string(),
        });
    }
    for (e, inventory) in batch.iter().zip(&inventories) {
        let recorded = match inventory {
            Some(inv) => cx.inner.svc.reporting.record_inventory(e, inv),
            None => cx.inner.svc.reporting.record(e),
        };
        match recorded {
            Ok(_) => {}
            Err(storage::Error::NotFound(_)) => {
                return Err(ApiError::Code(
                    ErrorCode::RegistrationRequired,
                    "registration required",
                ));
            }
            Err(_) => return Err(ApiError::Internal),
        }
    }
    Ok(ReportEventBatchResponse { result: true })
}

/// The `U` and `V` lists of a client status event (`MiscData` strings `U=<ids>` and `V=<ids>`, update
/// ids joined by `;`) resolved to the latest revision of each update in the active catalog. An id
/// that is malformed or not in the catalog is skipped: a status row needs a revision.
fn parse_inventory(misc: &[String], snapshot: Option<&crate::catalog::Snapshot>) -> Inventory {
    let list = |key: &str| -> Vec<wsus_protocol::identity::UpdateRevision> {
        let Some(snapshot) = snapshot else {
            return Vec::new();
        };
        let prefix = format!("{key}=");
        let mut out = Vec::new();
        for entry in misc.iter().filter_map(|m| m.strip_prefix(&prefix)) {
            for text in entry.split(';').filter(|t| !t.is_empty()) {
                let Ok(id) = uuid::Uuid::parse_str(text.trim()) else {
                    continue;
                };
                let id = wsus_protocol::identity::UpdateId(id);
                if let Ok(Some(revision)) = snapshot.latest_revision(id) {
                    out.push(wsus_protocol::identity::UpdateRevision { id, revision });
                }
            }
        }
        out
    };
    Inventory {
        installed: list("V"),
        not_installed: list("U"),
    }
}
