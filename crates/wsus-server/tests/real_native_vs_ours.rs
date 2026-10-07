//! Header- and shape-level checks over sanitized captures of a REAL native Windows Update Agent
//! talking to THIS project's server (`docs/fixtures/wsus-m0-ours/`), set against the shapes the
//! same client saw from the real WSUS (`docs/fixtures/wsus-m0-native/`).
//!
//! Provenance: on 2026-10-04 an unmodified Windows Update Agent 1507.2601.30012.0 (Windows 11
//! 25H2, OS 10.0.26200.8037) found, downloaded and installed the approved Defender definitions
//! bundle from this server in both delivery modes (`docs/wsus-protocol-inventory.md` 9.7,
//! validation ledger C31). The fixtures were extracted from two local pcaps with tshark (the
//! Xpress bodies decoded by tshark) and sanitized with `scripts/wsus/sanitize-capture.py`; the
//! README in that directory has the details. The server run was a working tree at commit
//! `fd2a126` plus uncommitted staged-delivery work (exact tree not recorded).
//!
//! What these tests are. They decode the committed fixtures with the `wsus-protocol` decoders
//! and pin SHAPES: the `Deployment` object on every `UpdateInfo`, the date-only
//! `LastChangeTime`, page sizes, the advertised `ProtocolVersion`, the closed-range `206`
//! contract on content headers, and the report event ids with the answers they got. They do not
//! show that the install worked (that rests on the operator's COM results and the guest's
//! `Get-MpComputerStatus`, which are not in the repository), they do not exercise the server
//! (it is not started here), and they say nothing about any other client build, TLS, several
//! clients or other updates.
//!
//! Not in the fixtures, deliberately: payload bytes (content exchanges are header-only), the
//! decoded response bodies of the two largest closure rounds (851,505 and 1,125,833 bytes; the
//! request side and response headers are kept), and any `StartCategoryScan`: neither capture
//! contains one (asserted below). The `StartCategoryScan` echo against a native request is
//! pinned elsewhere (`native_sim.rs`, `endpoints_staged.rs`).
use std::collections::BTreeSet;
use std::path::PathBuf;

use base64::Engine as _;
use wsus_protocol::soap::{Limits, SoapMessage, SoapRequest, decode_request, decode_response};
use wsus_protocol::wusp::{
    GetConfigResponse, GetExtendedUpdateInfo, GetExtendedUpdateInfoResponse, ReportEventBatch,
    ReportEventBatchResponse, SyncInfo, SyncUpdates, SyncUpdatesResponse, UpdateInfo,
    XmlUpdateFragmentType,
};

const REPORT_ACTION: &str = "http://www.microsoft.com/SoftwareDistribution/ReportEventBatch";
const MIB: u64 = 1_048_576;

fn root(set: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/fixtures")
        .join(set)
}

fn read(set: &str, n: &str, f: &str) -> Vec<u8> {
    let p = root(set).join(n).join(f);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn text(set: &str, n: &str, f: &str) -> String {
    String::from_utf8(read(set, n, f)).expect("utf-8 fixture")
}

fn header(set: &str, n: &str, f: &str, name: &str) -> Option<String> {
    text(set, n, f).lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_owned())
    })
}

fn header_names(set: &str, n: &str, f: &str) -> Vec<String> {
    text(set, n, f)
        .lines()
        .skip(1)
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, _)| k.trim().to_ascii_lowercase())
        })
        .collect()
}

/// A small string-valued JSON field of `meta.json` (the files are flat).
fn meta_str(set: &str, n: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(&read(set, n, "meta.json")).unwrap();
    match &v[key] {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn meta_u64(set: &str, n: &str, key: &str) -> u64 {
    meta_str(set, n, key)
        .unwrap_or_else(|| panic!("{set}/{n}: no {key}"))
        .parse()
        .unwrap()
}

fn request<R: SoapRequest>(set: &str, n: &str) -> R {
    let action = header(set, n, "request.headers", "soapaction").expect("soapaction");
    decode_request::<R>(
        Some(&action),
        &read(set, n, "request.body"),
        &Limits::default(),
    )
    .unwrap_or_else(|e| panic!("{set}/{n} request: {e:?}"))
    .1
}

fn response<M: SoapMessage>(set: &str, n: &str) -> M {
    decode_response::<M>(&read(set, n, "response.body"), &Limits::default())
        .unwrap_or_else(|e| panic!("{set}/{n} response: {e:?}"))
}

fn sync_info(set: &str, n: &str) -> SyncInfo {
    let r: SyncUpdatesResponse = response(set, n);
    r.result.into_value().expect("SyncUpdatesResult")
}

fn updates(info: &SyncInfo) -> Vec<&UpdateInfo> {
    info.new_updates
        .value()
        .map(|v| v.iter().collect())
        .unwrap_or_default()
}

/// Exchange directories of one fixture set, sorted.
fn exchanges(set: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(root(set))
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.chars().all(|c| c.is_ascii_digit()).then_some(n)
        })
        .collect();
    v.sort();
    v
}

fn is_content(set: &str, n: &str) -> bool {
    text(set, n, "request.headers").starts_with("GET /Content/")
}

/// Last path segment of the quoted `SOAPAction` URI (the operation name).
fn soap_action_name(set: &str, n: &str) -> Option<String> {
    let a = header(set, n, "request.headers", "soapaction")?;
    a.trim_matches('"').rsplit('/').next().map(str::to_owned)
}

const STAGED: &str = "wsus-m0-ours/staged";
const CLOSURE: &str = "wsus-m0-ours/closure";
const NATIVE: &str = "wsus-m0-native";

/// (set, exchange, expected software-round shape) of the retained SyncUpdates exchanges whose
/// response body is kept. Counts were taken from the full local pcaps and are checked here
/// against the bodies.
const SYNC_BODIES: [(&str, &str); 5] = [
    (STAGED, "000005"),
    (STAGED, "000008"),
    (STAGED, "000010"),
    (STAGED, "000014"),
    (CLOSURE, "000007"),
];

// ---------------------------------------------------------------------------
// Fixture inventory and HTTP framing
// ---------------------------------------------------------------------------

#[test]
fn fixtures_hold_the_selected_exchanges_and_no_start_category_scan() {
    assert_eq!(
        exchanges(STAGED),
        [
            "000001", "000002", "000003", "000004", "000005", "000008", "000010", "000014",
            "000015", "000016", "000017", "000124", "000134", "000232", "000233"
        ]
    );
    assert_eq!(
        exchanges(CLOSURE),
        [
            "000001", "000002", "000003", "000004", "000005", "000006", "000007", "000008",
            "000009", "000010", "000047", "000117", "000225", "000226"
        ]
    );
    for set in [STAGED, CLOSURE] {
        let actions: BTreeSet<String> = exchanges(set)
            .iter()
            .filter(|n| !is_content(set, n))
            .filter_map(|n| soap_action_name(set, n))
            .collect();
        // Neither capture contains a StartCategoryScan (not in the pcap, not in the server
        // log): the guest did not call it in this run. Why is not established.
        assert_eq!(
            actions.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "GetAuthorizationCookie",
                "GetConfig",
                "GetCookie",
                "GetExtendedUpdateInfo",
                "RegisterComputer",
                "ReportEventBatch",
                "SyncUpdates"
            ],
            "{set}"
        );
    }
}

#[test]
fn requests_are_the_native_agent_on_the_lowercase_client_path() {
    for set in [STAGED, CLOSURE] {
        for n in exchanges(set).iter().filter(|n| !is_content(set, n)) {
            let head = text(set, n, "request.headers");
            let first = head.lines().next().unwrap();
            let path = if soap_action_name(set, n).as_deref() == Some("ReportEventBatch") {
                "/ReportingWebService/ReportingWebService.asmx"
            } else if soap_action_name(set, n).as_deref() == Some("GetAuthorizationCookie") {
                "/SimpleAuthWebService/SimpleAuth.asmx"
            } else {
                "/ClientWebService/client.asmx"
            };
            assert_eq!(first, format!("POST {path} HTTP/1.1"), "{set}/{n}");
            assert_eq!(
                header(set, n, "request.headers", "user-agent").as_deref(),
                Some("Windows-Update-Agent/1507.2601.30012.0 Client-Protocol/2.90"),
                "{set}/{n}"
            );
            assert_eq!(
                header(set, n, "request.headers", "accept-encoding").as_deref(),
                Some("xpress"),
                "{set}/{n}"
            );
            assert_eq!(
                header(set, n, "request.headers", "content-type").as_deref(),
                Some("text/xml; charset=utf-8"),
                "{set}/{n}"
            );
            assert_eq!(
                header(set, n, "request.headers", "host").as_deref(),
                Some("192.0.2.1:18540"),
                "redacted server address and the lab port, {set}/{n}"
            );
            let mut want = vec![
                "cache-control",
                "connection",
                "pragma",
                "content-type",
                "accept-encoding",
                "user-agent",
                "soapaction",
                "ms-cv",
                "content-length",
                "host",
            ];
            if matches!(
                soap_action_name(set, n).as_deref(),
                Some("GetAuthorizationCookie" | "ReportEventBatch")
            ) {
                // The SimpleAuth and Reporting requests carry no MS-CV; the real-WSUS captures
                // agree (`wsus-m0-native/scan/000002`, `flow/000016`).
                want.retain(|h| *h != "ms-cv");
            }
            assert_eq!(header_names(set, n, "request.headers"), want, "{set}/{n}");
        }
    }
}

#[test]
fn soap_responses_are_200_and_xpress_except_the_small_register_computer_answer() {
    for set in [STAGED, CLOSURE] {
        for n in exchanges(set).iter().filter(|n| !is_content(set, n)) {
            let h = text(set, n, "response.headers");
            assert!(h.starts_with("HTTP/1.1 200 OK"), "{set}/{n}");
            assert_eq!(
                header(set, n, "response.headers", "content-type").as_deref(),
                Some("text/xml; charset=utf-8")
            );
            // The fixture holds the DECODED body: content-length is the decoded length and the
            // wire encoding and length live in meta.json (same convention as wsus-m0-native).
            let decoded = read(set, n, "response.body").len() as u64;
            let wire_len = meta_u64(set, n, "wire_response_content_length");
            let enc = meta_str(set, n, "wire_response_content_encoding");
            let omitted = meta_str(set, n, "response_body_omitted").is_some();
            if soap_action_name(set, n).as_deref() == Some("RegisterComputer") {
                // 252 bytes: below the server's compression threshold, sent identity.
                assert_eq!(enc, None, "{set}/{n}");
                assert_eq!(wire_len, 252);
                assert_eq!(decoded, 252);
            } else {
                // Accept-Encoding: xpress was sent on every request and every answer but the
                // small one carries Content-Encoding: xpress and is smaller than its decoded
                // body. A native agent decoded all of them (the exchanges continued).
                assert_eq!(enc.as_deref(), Some("xpress"), "{set}/{n}");
                if omitted {
                    assert!(meta_u64(set, n, "response_body_original_size") > wire_len);
                } else {
                    assert!(decoded > wire_len, "{set}/{n}: {decoded} vs {wire_len}");
                    assert_eq!(
                        header(set, n, "response.headers", "content-length")
                            .unwrap()
                            .parse::<u64>()
                            .unwrap(),
                        decoded
                    );
                }
                assert!(
                    header(set, n, "response.headers", "content-encoding").is_none(),
                    "decoded fixture drops the header, {set}/{n}"
                );
            }
            assert_eq!(
                header(set, n, "response.headers", "vary").as_deref(),
                Some("Accept-Encoding"),
                "{set}/{n}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

fn props(set: &str) -> Vec<(String, String)> {
    let r: GetConfigResponse = response(set, "000001");
    r.result
        .value()
        .unwrap()
        .properties
        .value()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p.name.value().unwrap().clone(),
                p.value.value().unwrap().clone(),
            )
        })
        .collect()
}

#[test]
fn protocol_version_is_3_2_in_staged_mode_and_3_0_in_closure_mode() {
    let get = |set: &str, k: &str| {
        props(set)
            .into_iter()
            .find(|p| p.0 == k)
            .unwrap_or_else(|| panic!("{set}: no {k}"))
            .1
    };
    assert_eq!(get(STAGED, "ProtocolVersion"), "3.2");
    assert_eq!(get(CLOSURE, "ProtocolVersion"), "3.0");
    // Not an error that the native client sent 2.90 in both: it advertises its own protocol.
    let req: wsus_protocol::wusp::GetConfig = request(STAGED, "000001");
    assert_eq!(
        req.protocol_version.value().map(String::as_str),
        Some("2.90")
    );
    // The real WSUS answered 3.2 (inventory 9.3).
    let real: GetConfigResponse = response(NATIVE, "scan/000001");
    let real_v = real
        .result
        .value()
        .unwrap()
        .properties
        .value()
        .unwrap()
        .iter()
        .find(|p| p.name.value().map(String::as_str) == Some("ProtocolVersion"))
        .and_then(|p| p.value.value().cloned());
    assert_eq!(real_v.as_deref(), Some("3.2"));
}

// ---------------------------------------------------------------------------
// SyncUpdates
// ---------------------------------------------------------------------------

#[test]
fn every_update_info_has_a_deployment_with_the_real_seven_field_shape_and_date_only_time() {
    let mut total = 0usize;
    let mut actions = BTreeSet::new();
    for (set, n) in SYNC_BODIES {
        let info = sync_info(set, n);
        for u in updates(&info) {
            total += 1;
            let d = u
                .deployment
                .value()
                .unwrap_or_else(|| panic!("{set}/{n}: update {} has no Deployment", u.id));
            actions.insert(format!("{:?}", d.action));
            assert!(d.is_assigned, "{set}/{n}");
            // Date only (`2026-10-04`), as the real WSUS sent it; no time of day.
            let t = d.last_change_time.as_str();
            let b = t.as_bytes();
            assert!(
                t.len() == 10
                    && b[4] == b'-'
                    && b[7] == b'-'
                    && b.iter()
                        .enumerate()
                        .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()),
                "{set}/{n}: LastChangeTime {t:?}"
            );
            // Seven fields: ID, Action, IsAssigned, LastChangeTime, AutoSelect, AutoDownload,
            // SupersedenceBehavior. Nothing else (no deadline, priority, hardware ids, flags).
            assert_eq!(d.auto_select.value().map(String::as_str), Some("0"));
            assert_eq!(d.auto_download.value().map(String::as_str), Some("0"));
            assert_eq!(
                d.supersedence_behavior.value().map(String::as_str),
                Some("0")
            );
            assert!(d.deadline.is_absent());
            assert!(d.download_priority.is_absent());
            assert!(d.hardware_ids.is_absent());
            assert!(d.flag_bitmask.is_absent());
            assert!(d.client_behaviors.is_absent());
            assert!(u.xml.value().is_some_and(|x| x.contains("UpdateIdentity")));
        }
    }
    // 6 + 30 + 30 + 11 (staged) + 44 (closure)
    assert_eq!(total, 121);
    // Software children carry Bundle, categories and detectoids Evaluate; the approved bundle
    // itself (Install) is on a page not retained here.
    assert!(
        actions.is_subset(
            &["Evaluate", "Bundle", "Install", "PreDeploymentCheck"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        )
    );
    assert!(actions.contains("Evaluate") && actions.contains("Bundle"));
}

#[test]
fn deployment_shape_equals_the_one_the_real_wsus_sent_to_the_same_client() {
    // Same optional-field pattern as the real server's page of 30 (wsus-m0-native flow/000003).
    let real: SyncUpdatesResponse = response(NATIVE, "flow/000003");
    let real_info = real.result.value().unwrap();
    let real_first = updates(real_info)[0].deployment.value().unwrap();
    let ours = sync_info(STAGED, "000008");
    let ours_first = updates(&ours)[0].deployment.value().unwrap();
    macro_rules! same_presence {
        ($($f:ident),*) => { $(assert_eq!(
            real_first.$f.is_absent(), ours_first.$f.is_absent(), stringify!($f));)* };
    }
    same_presence!(
        deadline,
        download_priority,
        hardware_ids,
        auto_select,
        auto_download,
        supersedence_behavior,
        flag_bitmask,
        client_behaviors
    );
    assert_eq!(
        real_first.last_change_time.len(),
        ours_first.last_change_time.len()
    );
}

#[test]
fn staged_pages_hold_at_most_thirty_and_follow_the_installed_list() {
    // First round: the three cached-id arrays are omitted, 6 updates, all non-leaf
    // (no prerequisite), not truncated.
    let q: SyncUpdates = request(STAGED, "000005");
    let p = q.parameters.value().unwrap();
    assert!(p.installed_non_leaf_update_ids.is_absent());
    assert!(p.other_cached_update_ids.is_absent());
    assert!(!p.skip_software_sync);
    let first = sync_info(STAGED, "000005");
    assert_eq!(updates(&first).len(), 6);
    assert!(updates(&first).iter().all(|u| !u.is_leaf));
    assert!(!first.truncated);
    assert_eq!(
        first.driver_sync_not_needed.value().map(String::as_str),
        Some("false")
    );
    assert!(first.new_cookie.is_value());

    // A page of 30 (28 leaves, 2 non-leaf) with 5 installed ids and 3 other cached ids sent.
    let q: SyncUpdates = request(STAGED, "000008");
    let p = q.parameters.value().unwrap();
    assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 5);
    assert_eq!(p.other_cached_update_ids.value().unwrap().len(), 3);
    let page = sync_info(STAGED, "000008");
    assert_eq!(updates(&page).len(), 30);
    assert_eq!(updates(&page).iter().filter(|u| u.is_leaf).count(), 28);
    assert!(!page.truncated, "a full page with Truncated false occurs");

    // A page of 30 leaves, truncated, 8 installed ids and 31 other cached ids.
    let q: SyncUpdates = request(STAGED, "000010");
    let p = q.parameters.value().unwrap();
    assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 8);
    assert_eq!(p.other_cached_update_ids.value().unwrap().len(), 31);
    let page = sync_info(STAGED, "000010");
    assert_eq!(updates(&page).len(), 30);
    assert!(updates(&page).iter().all(|u| u.is_leaf));
    assert!(page.truncated);

    // Last software page: 11 leaves, not truncated, 151 other ids cached by then.
    let q: SyncUpdates = request(STAGED, "000014");
    let p = q.parameters.value().unwrap();
    assert_eq!(p.other_cached_update_ids.value().unwrap().len(), 151);
    let page = sync_info(STAGED, "000014");
    assert_eq!(updates(&page).len(), 11);
    assert!(!page.truncated);

    // No page of any retained response exceeds 30.
    for n in ["000005", "000008", "000010", "000014"] {
        assert!(updates(&sync_info(STAGED, n)).len() <= 30, "{n}");
    }
}

#[test]
fn the_driver_pass_skips_software_and_answers_driver_sync_not_needed() {
    for (set, n) in [(STAGED, "000015"), (CLOSURE, "000008")] {
        let q: SyncUpdates = request(set, n);
        let p = q.parameters.value().unwrap();
        assert!(p.skip_software_sync, "{set}/{n}");
        assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 8);
        assert!(p.other_cached_update_ids.is_absent());
        let info = sync_info(set, n);
        assert!(updates(&info).is_empty());
        assert!(!info.truncated);
        assert_eq!(
            info.driver_sync_not_needed.value().map(String::as_str),
            Some("true")
        );
    }
}

#[test]
fn closure_mode_delivers_the_whole_closure_in_pages_of_200_and_ignores_the_installed_list() {
    // Rounds 1 and 2: the decoded response bodies (851,505 and 1,125,833 bytes) are not kept;
    // their requests, response headers and original sizes are. The third round is the final
    // 44-update page.
    let q1: SyncUpdates = request(CLOSURE, "000005");
    assert!(
        q1.parameters
            .value()
            .unwrap()
            .installed_non_leaf_update_ids
            .is_absent()
    );
    let q2: SyncUpdates = request(CLOSURE, "000006");
    let p2 = q2.parameters.value().unwrap();
    assert_eq!(p2.installed_non_leaf_update_ids.value().unwrap().len(), 8);
    assert_eq!(p2.other_cached_update_ids.value().unwrap().len(), 192);
    let q3: SyncUpdates = request(CLOSURE, "000007");
    let p3 = q3.parameters.value().unwrap();
    assert_eq!(p3.installed_non_leaf_update_ids.value().unwrap().len(), 8);
    assert_eq!(p3.other_cached_update_ids.value().unwrap().len(), 392);
    // 200 + 200 + 44 = 444 revisions in three software rounds (the 200 per page is the
    // server's `max_sync_new_updates` default for closure mode; it is not checkable from the
    // retained bodies, only the 44 is).
    let last = sync_info(CLOSURE, "000007");
    assert_eq!(updates(&last).len(), 44);
    assert!(!last.truncated);
    assert_eq!(
        meta_u64(CLOSURE, "000005", "response_body_original_size"),
        851_505
    );
    assert_eq!(
        meta_u64(CLOSURE, "000006", "response_body_original_size"),
        1_125_833
    );
    // The cached-id arrays the client sent grow by what it was given: 192 others after the
    // first 200 revisions (8 reported installed), 392 after the second 200.
    assert_eq!(192 + 200, 392);
}

// ---------------------------------------------------------------------------
// GetExtendedUpdateInfo
// ---------------------------------------------------------------------------

#[test]
fn extended_update_info_returns_file_locations_at_the_url_rule_the_real_server_used() {
    for (set, n) in [(STAGED, "000016"), (CLOSURE, "000009")] {
        let q: GetExtendedUpdateInfo = request(set, n);
        assert_eq!(q.revision_ids.value().unwrap().len(), 24);
        assert!(
            q.info_types
                .value()
                .unwrap()
                .contains(&XmlUpdateFragmentType::Extended)
        );
        let r: GetExtendedUpdateInfoResponse = response(set, n);
        let info = r.result.value().unwrap();
        let locs = info.file_locations.value().unwrap();
        assert_eq!(locs.len(), 4, "{set}");
        for l in locs {
            let digest = l.file_digest.value().unwrap();
            assert_eq!(digest.len(), 20);
            let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
            assert_eq!(
                l.url.value().unwrap(),
                &format!(
                    "http://192.0.2.1:18540/Content/{}/{}.exe",
                    &hex[hex.len() - 2..],
                    hex
                ),
                "same rule as the real server: last two hex chars upper case, SHA-1 upper case"
            );
            assert!(l.pieces_hash_url.is_absent());
            assert!(l.block_map_url.is_absent());
            assert!(l.decryption_information.is_absent());
        }
        // Every location has a Files entry in the Extended fragments of the same response.
        let xml: String = info
            .updates
            .value()
            .unwrap()
            .iter()
            .filter_map(|u| u.xml.value().cloned())
            .collect();
        for l in locs {
            let b64 =
                base64::engine::general_purpose::STANDARD.encode(l.file_digest.value().unwrap());
            assert!(xml.contains(&format!("<File Digest=\"{b64}\"")), "{set}");
        }
    }
}

// ---------------------------------------------------------------------------
// Content (headers only)
// ---------------------------------------------------------------------------

fn span(v: &str) -> (u64, u64, Option<u64>) {
    let v = v.trim_start_matches("bytes").trim_start_matches([' ', '=']);
    let (range, total) = match v.split_once('/') {
        Some((r, t)) => (r, Some(t.parse().unwrap())),
        None => (v, None),
    };
    let (a, b) = range.split_once('-').unwrap();
    (a.parse().unwrap(), b.parse().unwrap(), total)
}

#[test]
fn content_responses_are_206_with_the_content_range_equal_to_the_request() {
    let sets = [
        (STAGED, ["000017", "000124", "000134"]),
        (CLOSURE, ["000010", "000117", "000047"]),
    ];
    for (set, ns) in sets {
        for n in ns {
            assert!(is_content(set, n));
            let rq = "request.headers";
            let rs = "response.headers";
            assert!(
                text(set, n, rs).starts_with("HTTP/1.1 206 Partial Content"),
                "{set}/{n}"
            );
            // Request: the Delivery Optimization agent, a closed range, keep-alive, no
            // validators, no Accept-Encoding (content is never compressed).
            assert_eq!(
                header(set, n, rq, "user-agent").as_deref(),
                Some("Microsoft-Delivery-Optimization/10.1")
            );
            assert_eq!(
                header_names(set, n, rq),
                [
                    "connection",
                    "accept",
                    "range",
                    "user-agent",
                    "ms-cv",
                    "content-length",
                    "host"
                ]
            );
            let (a, b, none) = span(&header(set, n, rq, "range").unwrap());
            assert!(none.is_none() && a <= b);
            let (ca, cb, total) = span(&header(set, n, rs, "content-range").unwrap());
            let total = total.expect("Content-Range total");
            // 206 + Content-Range equal to the request, Content-Length = b - a + 1.
            assert_eq!((ca, cb), (a, b), "{set}/{n}");
            assert!(b < total);
            assert_eq!(
                header(set, n, rs, "content-length").unwrap(),
                (b - a + 1).to_string()
            );
            assert_eq!(
                meta_u64(set, n, "wire_response_content_length"),
                b - a + 1,
                "wire length equals the range length"
            );
            assert_eq!(meta_str(set, n, "wire_response_content_encoding"), None);
            // Response header set of OUR server, in wire order. Differences from the real
            // WSUS (inventory 9.4): no Last-Modified, Server, X-Powered-By; the ETag is a
            // 64-hex-digit quoted strong tag.
            assert_eq!(
                header_names(set, n, rs),
                [
                    "content-type",
                    "content-length",
                    "etag",
                    "accept-ranges",
                    "content-range",
                    "date"
                ],
                "{set}/{n}"
            );
            assert_eq!(
                header(set, n, rs, "content-type").as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(
                header(set, n, rs, "accept-ranges").as_deref(),
                Some("bytes")
            );
            let etag = header(set, n, rs, "etag").unwrap();
            assert!(etag.starts_with('"') && etag.ends_with('"') && !etag.starts_with("W/"));
            assert_eq!(etag.len(), 66);
            assert!(header(set, n, rs, "content-encoding").is_none());
            assert!(header(set, n, rs, "last-modified").is_none());
        }
    }
}

#[test]
fn content_ranges_are_one_mebibyte_pieces_and_the_last_one_ends_at_size_minus_one() {
    // Same piece geometry as against the real WSUS (inventory 9.4): the middle range is a full
    // 1 MiB piece at a multiple of 1 MiB; the final piece of the 204,745,168 byte file ends at
    // size - 1.
    for (set, mid, fin) in [(STAGED, "000124", "000134"), (CLOSURE, "000117", "000047")] {
        let (a, b, total) = span(&header(set, mid, "request.headers", "range").unwrap());
        assert_eq!((a % MIB, b - a + 1), (0, MIB), "{set}/{mid}");
        assert_eq!(
            meta_str(set, mid, "path").unwrap(),
            "/Content/AB/2F88DF42DA48AA980FB748D13BAA2DE49CD154AB.exe"
        );
        assert!(total.is_none());
        let (_, _, total) = span(&header(set, mid, "response.headers", "content-range").unwrap());
        assert_eq!(total, Some(204_745_168));

        let (a, b, _) = span(&header(set, fin, "request.headers", "range").unwrap());
        assert_eq!((a, b), (204_472_320, 204_745_167), "{set}/{fin}");
        assert_eq!(b - a + 1, 272_848);
    }
}

// ---------------------------------------------------------------------------
// ReportEventBatch
// ---------------------------------------------------------------------------

fn event_ids(set: &str, n: &str) -> Vec<(i16, i32)> {
    let q: ReportEventBatch = request(set, n);
    q.event_batch
        .value()
        .unwrap()
        .iter()
        .map(|e| {
            let b = e.basic_data.value().unwrap();
            assert_eq!(b.namespace_id, 1);
            assert_eq!(b.sequence_number, 0);
            assert_eq!(b.source_id, 101);
            (b.event_id, b.win32_hresult)
        })
        .collect()
}

#[test]
fn report_events_as_sent_by_the_native_client_are_accepted_with_true() {
    for (set, a, b) in [(STAGED, "000232", "000233"), (CLOSURE, "000225", "000226")] {
        for n in [a, b] {
            assert_eq!(
                header(set, n, "request.headers", "soapaction")
                    .unwrap()
                    .trim_matches('"'),
                REPORT_ACTION
            );
            assert!(
                text(set, n, "request.headers")
                    .starts_with("POST /ReportingWebService/ReportingWebService.asmx HTTP/1.1")
            );
            let r: ReportEventBatchResponse = response(set, n);
            assert!(r.result, "{set}/{n}");
        }
        // The same ids, in the same order, as the native client sent to the real WSUS in its
        // successful run (inventory 9.4), every Win32HResult 0: only the answer differs in
        // origin, not in value. The event NAMES are not established.
        let first = event_ids(set, a);
        assert_eq!(
            first.iter().map(|e| e.0).collect::<Vec<_>>(),
            [147, 156, 167, 162, 181]
        );
        assert!(first.iter().all(|e| e.1 == 0));
        let second = event_ids(set, b);
        assert_eq!(second, [(183, 0)]);
    }
}

#[test]
fn event_162_carries_the_byte_total_of_the_ranges_this_server_served() {
    // MiscData `B=` of event 162: 223,014,168 = 6,662,560 + 204,745,168 + 11,606,440, the three
    // files of the run (MpSigStub.exe, 918,944 bytes, was not requested from this server).
    for (set, n) in [(STAGED, "000232"), (CLOSURE, "000225")] {
        assert!(
            text(set, n, "request.body").contains("<string>B=223014168</string>"),
            "{set}"
        );
    }
    assert_eq!(6_662_560u64 + 204_745_168 + 11_606_440, 223_014_168);
}
