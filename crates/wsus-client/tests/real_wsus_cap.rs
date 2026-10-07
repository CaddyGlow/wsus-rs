//! Probe of a real WSUS above the 400-entry `InstalledNonLeafUpdateIDs` cap (docs/wsus-validation.md
//! C52, docs/wsus-protocol-inventory.md 9.9). Ignored by default and read-only on the server except
//! for the one throwaway computer registration it causes.
//!
//! `WSUS_REAL_ORIGIN` names the (recording proxy in front of the) lab WSUS, `WSUS400_OUT` a local
//! directory for the JSON results (default `/data/cache/wsus400`), `WSUS400_NAME` the throwaway
//! computer's DNS name. Run with
//! `cargo test -p wsus-client --features reqwest-async --test real_wsus_cap -- --ignored --nocapture`.
//!
//! The driver does the handshake with a throwaway computer identity, a catalog sync with this
//! project's engine (which never lists more than 400 installed ids, so it supplies the real ids),
//! keeps the session cookie of two anchors (fresh and after 60 pages) and then sends hand-built
//! `SyncUpdates` requests that reuse those cookies with a controlled `InstalledNonLeafUpdateIDs`
//! list. Observed 2026-10-06: the two anchors gave the same `NewUpdates` and out-of-scope ids and
//! differed only in `ChangedUpdates`. `WSUS400_STATE_DIR` and `WSUS400_CATALOG_DIR` reuse a
//! prepared identity and an already synced catalog (see the function below).
#![cfg(feature = "reqwest-async")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tempfile::TempDir;
use wsus_client::{
    session::{SessionConfig, SystemClock, WuspSession, unix_to_xs},
    state::StateStore,
    sync::{RevisionStore, SyncEngine, SyncError, SyncOptions},
    transport::{
        HttpRequest, SensitiveUrl, Transport,
        reqwest_backend::{ReqwestTransport, TokioTimer},
    },
};
use wsus_protocol::{
    ProtocolError,
    common::Cookie,
    soap::{Presence, SoapRequest, decode_response, encode_request},
    wusp::{
        ComputerInfo, GetExtendedUpdateInfo, SyncUpdateParameters, SyncUpdates,
        SyncUpdatesResponse, XmlUpdateFragmentType,
    },
};

fn computer_info(name: &str) -> ComputerInfo {
    ComputerInfo {
        dns_name: Presence::Value(name.into()),
        os_major_version: 10,
        os_minor_version: 0,
        os_build_number: 26100,
        os_service_pack_major_number: 0,
        os_service_pack_minor_number: 0,
        os_locale: Presence::Value("en-US".into()),
        computer_manufacturer: Presence::Absent,
        computer_model: Presence::Absent,
        bios_version: Presence::Absent,
        bios_name: Presence::Absent,
        bios_release_date: unix_to_xs(0),
        processor_architecture: Presence::Value("9".into()),
        suite_mask: 0,
        old_product_type: 1,
        new_product_type: 48,
        system_metrics: 0,
        client_version_major_number: 10,
        client_version_minor_number: 0,
        client_version_build_number: 26100_i16,
        client_version_qfe_number: 0,
        os_description: Presence::Absent,
        oem: Presence::Absent,
        device_type: Presence::Absent,
        firmware_version: Presence::Absent,
        mobile_operator: Presence::Absent,
    }
}

type Engine = SyncEngine<ReqwestTransport, TokioTimer, SystemClock>;

fn cookie_of(engine: &Engine) -> Cookie {
    let stored = engine.session().state().cookie.as_ref().unwrap();
    Cookie {
        expiration: unix_to_xs(stored.expires_unix),
        encrypted_data: Presence::Value(stored.data.expose().to_vec()),
    }
}

struct Answer {
    status: u16,
    wire_bytes: usize,
    body: Vec<u8>,
}

async fn post<R: SoapRequest>(
    transport: &ReqwestTransport,
    engine: &Engine,
    request: &R,
) -> (Answer, usize) {
    let config = engine.session().config();
    let encoded = encode_request(config.soap_version, request);
    let request_bytes = encoded.body.len();
    let url = SensitiveUrl::parse(&format!(
        "{}/{}",
        config.base_url,
        config.client_path.trim_start_matches('/')
    ))
    .unwrap();
    let mut http = HttpRequest::soap_post(
        url,
        encoded.soap_action.as_deref().unwrap_or(""),
        &encoded.content_type,
        encoded.body,
        Duration::from_secs(120),
    );
    http.max_response_bytes = config.max_response_bytes;
    http.headers.set("Accept-Encoding", "xpress");
    let response = transport.send(http).await.expect("transport");
    let wire_bytes = response.body.len();
    let body = if response
        .headers
        .get("content-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("xpress"))
    {
        wsus_protocol::xpress::decode(&response.body, &Default::default()).expect("xpress")
    } else {
        response.body
    };
    (
        Answer {
            status: response.status,
            wire_bytes,
            body,
        },
        request_bytes,
    )
}

fn fault_json(error: &ProtocolError) -> Value {
    match error {
        ProtocolError::Fault(f) => json!({
            "faultcode": f.code,
            "faultstring": f.reason,
            "error_code": f.wsus.as_ref().map(|w| format!("{:?}", w.error_code)),
            "message": f.wsus.as_ref().and_then(|w| w.message.clone()),
        }),
        other => json!({ "decode_error": other.to_string() }),
    }
}

fn digest(lines: &mut [String]) -> String {
    lines.sort();
    let mut h = Sha256::new();
    for l in lines.iter() {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    format!("{:x}", h.finalize())
}

#[allow(clippy::too_many_arguments)]
async fn probe(
    transport: &ReqwestTransport,
    engine: &Engine,
    anchor: &str,
    cookie: &Cookie,
    variant: &str,
    installed: &[i32],
    other: &[i32],
    rep: u32,
) -> Value {
    let request = SyncUpdates {
        cookie: Presence::Value(cookie.clone()),
        parameters: Presence::Value(SyncUpdateParameters {
            express_query: false,
            installed_non_leaf_update_ids: Presence::Value(installed.to_vec()),
            other_cached_update_ids: Presence::Value(other.to_vec()),
            system_spec: Presence::Absent,
            cached_driver_ids: Presence::Value(Vec::new()),
            skip_software_sync: false,
            filter_category_ids: Presence::Absent,
            need_two_group_out_of_scope_updates: Presence::Absent,
            computer_spec: Presence::Absent,
            feature_score_matching_key: Presence::Absent,
        }),
    };
    let limits = engine.session().config().limits.clone();
    let (answer, request_bytes) = post(transport, engine, &request).await;
    let mut out = json!({
        "anchor": anchor, "variant": variant, "rep": rep,
        "installed": installed.len(), "other": other.len(),
        "request_bytes": request_bytes, "http_status": answer.status,
        "response_wire_bytes": answer.wire_bytes, "response_decoded_bytes": answer.body.len(),
    });
    match decode_response::<SyncUpdatesResponse>(&answer.body, &limits) {
        Err(error) => {
            out["fault"] = fault_json(&error);
        }
        Ok(response) => {
            out["fault"] = Value::Null;
            let info = response.result.into_value().expect("SyncUpdatesResult");
            let new = info.new_updates.value().cloned().unwrap_or_default();
            let changed = info.changed_updates.value().cloned().unwrap_or_default();
            let oos = info
                .out_of_scope_revision_ids
                .value()
                .cloned()
                .unwrap_or_default();
            let deployed_oos = info
                .deployed_out_of_scope_revision_ids
                .value()
                .cloned()
                .unwrap_or_default();
            let mut actions: BTreeMap<String, usize> = BTreeMap::new();
            let mut lines = Vec::new();
            for u in &new {
                let action = u
                    .deployment
                    .value()
                    .map_or("none".to_owned(), |d| format!("{:?}", d.action));
                *actions.entry(action.clone()).or_default() += 1;
                lines.push(format!("{}:{}:{}", u.id, action, u.is_leaf));
            }
            let new_ids: Vec<i32> = new.iter().map(|u| u.id).collect();
            out["new_updates"] = json!(new.len());
            out["new_non_leaf"] = json!(new.iter().filter(|u| !u.is_leaf).count());
            out["changed_updates"] = json!(changed.len());
            out["out_of_scope"] = json!(oos.len());
            out["deployed_out_of_scope"] = json!(deployed_oos.len());
            out["truncated"] = json!(info.truncated);
            out["has_new_cookie"] = json!(info.new_cookie.value().is_some());
            out["driver_sync_not_needed"] = json!(info.driver_sync_not_needed.value());
            out["actions"] = json!(actions);
            out["new_ids_digest"] = json!(digest(&mut lines));
            let mut oos_lines: Vec<String> = oos.iter().map(|i| i.to_string()).collect();
            out["oos_digest"] = json!(digest(&mut oos_lines));
            // ExtendedUpdateInfo for the first delivered ids (a fixed prefix of the answer).
            let take: Vec<i32> = new_ids.iter().copied().take(49).collect();
            if !take.is_empty() {
                let ext = GetExtendedUpdateInfo {
                    cookie: Presence::Value(cookie.clone()),
                    revision_ids: Presence::Value(take.clone()),
                    info_types: Presence::Value(vec![XmlUpdateFragmentType::Extended]),
                    locales: Presence::Absent,
                    geo_id: Presence::Absent,
                    caller_attributes: Presence::Absent,
                };
                let (a, _) = post(transport, engine, &ext).await;
                let mut e = json!({ "asked": take.len(), "http_status": a.status });
                match decode_response::<wsus_protocol::wusp::GetExtendedUpdateInfoResponse>(
                    &a.body, &limits,
                ) {
                    Err(error) => e["fault"] = fault_json(&error),
                    Ok(r) => {
                        let r = r.result.into_value().expect("result");
                        e["updates"] = json!(r.updates.value().map_or(0, Vec::len));
                        e["file_locations"] = json!(r.file_locations.value().map_or(0, Vec::len));
                        e["out_of_scope"] =
                            json!(r.out_of_scope_revision_ids.value().map_or(0, Vec::len));
                    }
                }
                out["extended_info"] = e;
            }
        }
    }
    out
}

#[tokio::test]
#[ignore = "needs WSUS_REAL_ORIGIN pointing at a lab WSUS (through a recording proxy)"]
async fn real_wsus_above_the_400_installed_id_cap() {
    let Ok(origin) = std::env::var("WSUS_REAL_ORIGIN") else {
        eprintln!("WSUS_REAL_ORIGIN is not set; nothing to do");
        return;
    };
    let out_dir = std::env::var("WSUS400_OUT").unwrap_or_else(|_| "/data/cache/wsus400".into());
    let name = std::env::var("WSUS400_NAME").expect("WSUS400_NAME (throwaway computer DNS name)");

    // `WSUS400_STATE_DIR` reuses a prepared state directory (the throwaway computer's identity, no
    // cached revisions) and `WSUS400_CATALOG_DIR` an already synced one, read offline for the ids.
    let temp = TempDir::new().unwrap();
    let state_dir = std::env::var("WSUS400_STATE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| temp.path().to_path_buf());
    let catalog_dir = std::env::var("WSUS400_CATALOG_DIR")
        .ok()
        .map(std::path::PathBuf::from);
    let transport = ReqwestTransport::new().unwrap();
    let open = |dir: &std::path::Path| -> Engine {
        let mut config = SessionConfig::new(&origin, &name);
        config.computer_info = Some(computer_info(&name));
        let state = StateStore::open(dir.join("state").join("state.json")).unwrap();
        let session =
            WuspSession::new(transport.clone(), TokioTimer, SystemClock, config, state).unwrap();
        SyncEngine::new(session, RevisionStore::open(dir.join("meta")).unwrap())
    };
    let mut engine = open(&state_dir);
    let computer_id = engine.session().state().computer_id;
    eprintln!("throwaway computer {name} id {computer_id:?}");

    // Anchor 0: the cookie of a fresh, registered session (no sync yet).
    engine.session_mut().handshake(false).await.unwrap();
    let anchor0 = cookie_of(&engine);

    // Anchor 1: after 60 pages of this project's own sync (which lists at most 400 installed ids).
    let err = engine
        .sync_updates(&SyncOptions {
            max_pages: 60,
            ..SyncOptions::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::TooManyPages(60)), "{err}");
    let anchor1 = cookie_of(&engine);
    let held_at_anchor1 = engine.session().state().cached_revisions.len();
    if catalog_dir.is_none() {
        let report = engine.sync_updates(&SyncOptions::default()).await.unwrap();
        eprintln!(
            "catalog: pages(after anchor)={} new={}",
            report.pages, report.new_revisions
        );
    }
    let catalog_engine = catalog_dir.as_deref().map(open);
    let engine_ids = catalog_engine.as_ref().unwrap_or(&engine);

    // The catalog's non-leaf, non-driver ids (what this client lists as installed) and the leaves.
    let catalog = engine_ids.catalog().unwrap();
    let (mut non_leaf, mut leaves, mut drivers) = (BTreeSet::new(), BTreeSet::new(), 0usize);
    for rev in catalog.revisions() {
        let entry = catalog.get(rev).unwrap();
        let Some(id) = engine_ids.local_id(rev) else {
            continue;
        };
        if entry.record.update_type.as_deref() == Some("Driver") {
            drivers += 1;
        } else if entry.record.is_leaf {
            leaves.insert(id.0);
        } else {
            non_leaf.insert(id.0);
        }
    }
    eprintln!(
        "ids: non_leaf={} leaves={} drivers={} held_at_anchor1={held_at_anchor1}",
        non_leaf.len(),
        leaves.len(),
        drivers
    );
    // Controlled list: every real non-leaf id (ascending), then real leaf ids (ascending) as padding
    // when the catalog has fewer non-leaf ids than the size asked for.
    let list: Vec<i32> = non_leaf.iter().chain(leaves.iter()).copied().collect();
    let universe: Vec<i32> = list.clone();
    let mut results = Vec::new();
    let sizes = [399usize, 400, 401, 450, 600, 1000];
    for (anchor_name, anchor) in [("fresh", &anchor0), ("page60", &anchor1)] {
        for &n in &sizes {
            assert!(list.len() >= n, "catalog too small for {n}");
            // I(n): n ids in InstalledNonLeafUpdateIDs, OtherCachedUpdateIDs empty.
            // O(n): the first 400 in Installed, the rest of the first n in Other.
            // IL(n): n in Installed, every other known id in Other (realistic shape).
            let mut variants: Vec<(String, Vec<i32>, Vec<i32>)> =
                vec![(format!("I{n}"), list[..n].to_vec(), Vec::new())];
            if n > 400 {
                variants.push((format!("O{n}"), list[..400].to_vec(), list[400..n].to_vec()));
            }
            if n == 401 {
                // D401: 400 distinct ids plus a repeat of the first (401 entries, 400 distinct).
                let mut dup = list[..400].to_vec();
                dup.push(list[0]);
                variants.push(("D401".into(), dup, Vec::new()));
                // R401: 400 non-leaf ids plus one real leaf id (the first leaf).
                let mut leaf = list[..400].to_vec();
                leaf.push(*leaves.iter().next().unwrap());
                variants.push(("R401".into(), leaf, Vec::new()));
            }
            if [400, 401, 1000].contains(&n) {
                let set: BTreeSet<i32> = list[..n].iter().copied().collect();
                variants.push((
                    format!("IL{n}"),
                    list[..n].to_vec(),
                    universe
                        .iter()
                        .copied()
                        .filter(|i| !set.contains(i))
                        .collect(),
                ));
            }
            for (variant, installed, other) in variants {
                for rep in 1..=2 {
                    let r = probe(
                        &transport,
                        &engine,
                        anchor_name,
                        anchor,
                        &variant,
                        &installed,
                        &other,
                        rep,
                    )
                    .await;
                    eprintln!(
                        "{anchor_name} {variant} rep{rep}: status={} fault={} new={} oos={} trunc={}",
                        r["http_status"],
                        r["fault"]["error_code"],
                        r["new_updates"],
                        r["out_of_scope"],
                        r["truncated"]
                    );
                    results.push(r);
                }
            }
        }
    }
    std::fs::create_dir_all(&out_dir).unwrap();
    let summary = json!({
        "computer_name": name,
        "computer_id": computer_id.map(|c| c.0.hyphenated().to_string()),
        "non_leaf_ids": non_leaf.len(), "leaf_ids": leaves.len(), "driver_revisions": drivers,
        "held_at_anchor_page60": held_at_anchor1,
        "list_composition": "all real non-leaf ids ascending, then real leaf ids ascending as padding",
        "results": results,
    });
    std::fs::write(
        format!("{out_dir}/results.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
}
