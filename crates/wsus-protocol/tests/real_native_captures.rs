//! Decode tests over sanitized REAL NATIVE Windows Update Agent captures.
//!
//! Provenance: `docs/fixtures/wsus-m0-native/` holds exchanges recorded on
//! 2026-10-04 between an unmodified Windows Update Agent (client 1507.2601.
//! 30012.0 on Windows 11 25H2, OS 10.0.26200) and the lab WSUS (Windows
//! Server 2025, 10.0.26100, `ProtocolVersion` 3.2), plain HTTP on port 8530.
//! Unlike `real_captures.rs` (this project's own driver), the REQUESTS here
//! were produced by Microsoft's client. Raw pcaps stay local; the fixtures
//! were extracted with tshark and sanitized with
//! `scripts/wsus/sanitize-capture.py`. See the README in that directory.
//!
//! Wire note: the server sent every response with
//! `Content-Encoding: xpress`; the fixtures hold the DECODED bodies (the
//! `response.headers` files drop that header and carry the decoded length,
//! `meta.json` records the wire encoding and length). The Xpress decoder
//! (`wsus_protocol::xpress`) is exercised by its own tests; none here uses it.
//!
//! Scope: these tests show that this crate's decoders accept what the native
//! client sent and what the server answered for the listed exchanges, and pin
//! the concrete facts the inventory records. They do not validate download,
//! install or any behavior beyond that pair and those builds (see
//! `docs/wsus-validation.md`).

use std::path::PathBuf;

use uuid::Uuid;
use wsus_protocol::soap::{
    Limits, SoapMessage, SoapRequest, SoapVersion, decode_request, decode_response,
};
use wsus_protocol::wusp::{
    DeploymentAction, GetAuthorizationCookie, GetAuthorizationCookieResponse, GetConfig,
    GetConfigResponse, GetCookie, GetCookieResponse, GetExtendedUpdateInfo,
    GetExtendedUpdateInfoResponse, ProcessorArchitecture, RegisterComputer,
    RegisterComputerResponse, ReportEventBatch, ReportEventBatchResponse, StartCategoryScan,
    StartCategoryScanResponse, SyncUpdates, SyncUpdatesResponse, XmlUpdateFragmentType,
};

const CLIENT_ACTION_PREFIX: &str =
    "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/";
const REPORT_ACTION: &str = "http://www.microsoft.com/SoftwareDistribution/ReportEventBatch";
/// Client id used by the native client in the `scan` capture (random GUID, kept).
const SCAN_CLIENT_ID: &str = "e1da06a3-5601-43c9-bac3-52d5db701494";

fn dir(set: &str, n: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/fixtures/wsus-m0-native")
        .join(set)
        .join(n)
}

fn read(set: &str, n: &str, f: &str) -> Vec<u8> {
    let p = dir(set, n).join(f);
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

fn soap_action(set: &str, n: &str) -> String {
    header(set, n, "request.headers", "soapaction").expect("soapaction header")
}

fn request<R: SoapRequest>(set: &str, n: &str) -> R {
    let (v, r) = decode_request::<R>(
        Some(&soap_action(set, n)),
        &read(set, n, "request.body"),
        &Limits::default(),
    )
    .unwrap_or_else(|e| panic!("{set}/{n} request: {e:?}"));
    assert_eq!(v, SoapVersion::V11, "{set}/{n}");
    r
}

fn response<M: SoapMessage>(set: &str, n: &str) -> M {
    decode_response::<M>(&read(set, n, "response.body"), &Limits::default())
        .unwrap_or_else(|e| panic!("{set}/{n} response: {e:?}"))
}

fn meta(set: &str, n: &str) -> String {
    text(set, n, "meta.json")
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Hex of the base64 SHA-1 digest, upper case.
fn digest_hex_upper(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

// ---------------------------------------------------------------------------
// HTTP framing
// ---------------------------------------------------------------------------

#[test]
fn native_requests_use_lowercase_client_path_and_the_native_header_set() {
    for (set, n, path) in [
        ("scan", "000001", "/ClientWebService/client.asmx"),
        ("scan", "000003", "/ClientWebService/client.asmx"),
        ("scan", "000006", "/ClientWebService/client.asmx"),
        ("flow", "000013", "/ClientWebService/client.asmx"),
        (
            "flow",
            "000016",
            "/ReportingWebService/ReportingWebService.asmx",
        ),
    ] {
        let head = text(set, n, "request.headers");
        let first = head.lines().next().unwrap();
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
            header(set, n, "request.headers", "cache-control").as_deref(),
            Some("no-cache"),
            "{set}/{n}"
        );
        assert_eq!(
            header(set, n, "request.headers", "pragma").as_deref(),
            Some("no-cache"),
            "{set}/{n}"
        );
        // SOAPAction is quoted on the wire.
        assert!(soap_action(set, n).starts_with('"'), "{set}/{n}");
        // The server address is in Host with the port (redacted to a
        // documentation address by the sanitizer).
        assert_eq!(
            header(set, n, "request.headers", "host").as_deref(),
            Some("192.0.2.1:8530"),
            "{set}/{n}"
        );
        // No XML declaration, `s:` prefix, SOAP 1.1 envelope.
        let body = text(set, n, "request.body");
        assert!(
            body.starts_with("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"),
            "{set}/{n}"
        );
    }
    // Client-service requests carry a correlation vector; the Reporting call
    // does not.
    assert!(header("scan", "000001", "request.headers", "ms-cv").is_some());
    assert!(header("flow", "000016", "request.headers", "ms-cv").is_none());
}

#[test]
fn every_selected_exchange_returned_200_and_the_fixtures_hold_decoded_bodies() {
    for (set, ns) in [
        (
            "scan",
            &[
                "000001", "000002", "000003", "000004", "000005", "000006", "000007", "000008",
                "000009", "000010",
            ][..],
        ),
        (
            "flow",
            &[
                "000001", "000003", "000012", "000013", "000014", "000015", "000016", "000017",
                "000018",
            ][..],
        ),
    ] {
        for n in ns {
            let m = meta(set, n);
            assert!(m.contains("\"status\": 200"), "{set}/{n}");
            assert!(
                m.contains("\"wire_response_content_encoding\": \"Content-Encoding: xpress\""),
                "{set}/{n}"
            );
            // The decoded body is what the fixture stores; the stored header
            // set has no Content-Encoding.
            assert!(header(set, n, "response.headers", "content-encoding").is_none());
            assert_eq!(
                header(set, n, "response.headers", "server").as_deref(),
                Some("Microsoft-IIS/10.0"),
                "{set}/{n}"
            );
            let len: usize = header(set, n, "response.headers", "content-length")
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(len, read(set, n, "response.body").len(), "{set}/{n}");
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake (scan capture, first scan after boot, OOBE ZDP caller)
// ---------------------------------------------------------------------------

#[test]
fn native_get_config_advertises_protocol_2_90_and_gets_the_same_answer_as_our_driver() {
    let req: GetConfig = request("scan", "000001");
    assert_eq!(
        req.protocol_version.value().map(String::as_str),
        Some("2.90")
    );
    assert_eq!(
        soap_action("scan", "000001").trim_matches('"'),
        format!("{CLIENT_ACTION_PREFIX}GetConfig")
    );

    let r: GetConfigResponse = response("scan", "000001");
    let c = r.result.value().expect("GetConfigResult");
    assert_eq!(c.last_change.as_str(), "2026-10-04T13:17:07.59Z");
    assert!(c.is_registration_required);
    assert!(c.allowed_event_ids.is_absent());
    let auth = c.auth_info.value().expect("AuthInfo");
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].plug_in_id.value().unwrap(), "SimpleTargeting");
    assert_eq!(
        auth[0].service_url.value().unwrap(),
        "SimpleAuthWebService/SimpleAuth.asmx"
    );
    let props: Vec<(&str, &str)> = c
        .properties
        .value()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p.name.value().unwrap().as_str(),
                p.value.value().unwrap().as_str(),
            )
        })
        .collect();
    let names: Vec<&str> = props.iter().map(|p| p.0).collect();
    assert_eq!(
        names,
        [
            "MaxExtendedUpdatesPerRequest",
            "PackageServerShare",
            "ProtocolVersion",
            "IsInventoryRequired",
            "ClientReportingLevel"
        ]
    );
    let get = |k: &str| props.iter().find(|p| p.0 == k).unwrap().1;
    assert_eq!(get("MaxExtendedUpdatesPerRequest"), "50");
    assert_eq!(get("ProtocolVersion"), "3.2");
    assert_eq!(get("IsInventoryRequired"), "0");
    assert_eq!(get("ClientReportingLevel"), "2");
}

#[test]
fn native_get_authorization_cookie_sends_a_random_client_id_and_dns_name_only() {
    let req: GetAuthorizationCookie = request("scan", "000002");
    assert_eq!(
        req.client_id.value().map(String::as_str),
        Some(SCAN_CLIENT_ID)
    );
    assert!(req.dns_name.is_value());
    assert!(req.target_group_name.is_absent());
    // SimpleAuth is addressed at its own path and namespace.
    let head = text("scan", "000002", "request.headers");
    assert!(
        head.starts_with("POST /SimpleAuthWebService/SimpleAuth.asmx HTTP/1.1"),
        "{head}"
    );
    assert_eq!(
        soap_action("scan", "000002").trim_matches('"'),
        "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"
    );

    let r: GetAuthorizationCookieResponse = response("scan", "000002");
    let c = r.result.value().unwrap();
    assert_eq!(c.plug_in_id.value().unwrap(), "SimpleTargeting");
    // Redacted to base64 zeros; the original was 496 bytes (same as run 1).
    let data = c.cookie_data.value().unwrap();
    assert_eq!(data.len(), 496);
    assert!(data.iter().all(|b| *b == 0));
}

#[test]
fn native_get_cookie_sends_an_expiration_only_old_cookie() {
    let req: GetCookie = request("scan", "000003");
    assert_eq!(req.auth_cookies.value().unwrap().len(), 1);
    assert_eq!(req.last_change.as_str(), "2026-10-04T13:17:07.59Z");
    assert_eq!(req.current_time.as_str(), "2026-10-04T15:03:36Z");
    assert_eq!(
        req.protocol_version.value().map(String::as_str),
        Some("2.90")
    );
    // Unlike our driver, the native client sends `oldCookie` on the very
    // first call, holding only `Expiration` (= currentTime) and no
    // `EncryptedData`.
    let old = req.old_cookie.value().expect("oldCookie");
    assert_eq!(old.expiration.as_str(), "2026-10-04T15:03:36Z");
    assert!(old.encrypted_data.is_absent());

    let r: GetCookieResponse = response("scan", "000003");
    let c = r.result.value().unwrap();
    // One hour ahead, seven fractional digits (.NET round trip).
    assert_eq!(c.expiration.as_str(), "2026-10-04T16:03:35.9967236Z");
    assert!(!c.encrypted_data.value().unwrap().is_empty());
}

#[test]
fn native_register_computer_describes_the_windows_11_client() {
    let req: RegisterComputer = request("scan", "000004");
    let i = req.computer_info.value().unwrap();
    assert_eq!(i.os_major_version, 10);
    assert_eq!(i.os_minor_version, 0);
    assert_eq!(i.os_build_number, 26200);
    assert_eq!(i.os_service_pack_major_number, 0);
    assert_eq!(i.os_locale.value().map(String::as_str), Some("en-US"));
    // RegisterComputer carries the free string "AMD64" (our driver sent "9").
    assert_eq!(
        i.processor_architecture.value().map(String::as_str),
        Some("AMD64")
    );
    assert_eq!(i.suite_mask, 256);
    assert_eq!(i.old_product_type, 1);
    assert_eq!(i.new_product_type, 48);
    assert_eq!(i.system_metrics, 0);
    assert_eq!(
        (
            i.client_version_major_number,
            i.client_version_minor_number,
            i.client_version_build_number,
            i.client_version_qfe_number
        ),
        (1507, 2601, 30012, 0)
    );
    // Windows 11 25H2 still describes itself as "Windows 10 Pro".
    assert_eq!(
        i.os_description.value().map(String::as_str),
        Some("Windows 10 Pro")
    );
    assert_eq!(i.oem.value().map(String::as_str), Some("QEMU"));
    assert_eq!(
        i.mobile_operator.value().map(String::as_str),
        Some("Not Present")
    );
    assert_eq!(i.bios_version.value().map(String::as_str), Some("unknown"));
    assert!(req.cookie.is_value());
    let _: RegisterComputerResponse = response("scan", "000004");
}

#[test]
fn native_start_category_scan_decodes_in_both_directions() {
    // Observed: sent after RegisterComputer and before the first SyncUpdates, without a
    // cookie, against a server whose ProtocolVersion is 3.2.
    assert_eq!(
        soap_action("scan", "000005").trim_matches('"'),
        format!("{CLIENT_ACTION_PREFIX}StartCategoryScan")
    );
    let cat = Uuid::parse_str("dd78b8a1-0b20-45c1-add6-4da72e9364cf").unwrap();
    let req: StartCategoryScan = request("scan", "000005");
    let rel = req.requested_categories.value().expect("categories");
    assert_eq!(rel.len(), 1);
    assert_eq!((rel[0].index_of_and_group, rel[0].category_id), (0, cat));
    let resp: StartCategoryScanResponse = response("scan", "000005");
    assert_eq!(resp.preferred_category_ids.value().unwrap(), &vec![cat]);
    assert!(resp.requested_category_ids_in_error.value().is_none());
}

#[test]
fn start_category_scan_roundtrips_with_errors_and_empty_lists() {
    use wsus_protocol::soap::{Presence, encode_request, encode_response};
    use wsus_protocol::wusp::CategoryRelationship;
    let a = Uuid::from_u128(1);
    let b = Uuid::from_u128(2);
    let req = StartCategoryScan {
        requested_categories: Presence::Value(vec![
            CategoryRelationship {
                index_of_and_group: 0,
                category_id: a,
            },
            CategoryRelationship {
                index_of_and_group: 1,
                category_id: b,
            },
        ]),
    };
    let enc = encode_request(SoapVersion::V11, &req);
    let (_, back) = decode_request::<StartCategoryScan>(
        enc.soap_action.as_deref(),
        &enc.body,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(back, req);
    let resp = StartCategoryScanResponse {
        preferred_category_ids: Presence::Value(vec![a]),
        requested_category_ids_in_error: Presence::Value(vec![b]),
    };
    let bytes = encode_response(SoapVersion::V11, &resp).body;
    let back: StartCategoryScanResponse = decode_response(&bytes, &Limits::default()).unwrap();
    assert_eq!(back, resp);
    let empty = StartCategoryScanResponse {
        preferred_category_ids: Presence::Absent,
        requested_category_ids_in_error: Presence::Absent,
    };
    let bytes = encode_response(SoapVersion::V11, &empty).body;
    let back: StartCategoryScanResponse = decode_response(&bytes, &Limits::default()).unwrap();
    assert_eq!(back, empty);
}

// ---------------------------------------------------------------------------
// SyncUpdates, scan capture (category-filtered ZDP scan)
// ---------------------------------------------------------------------------

fn ids(v: Option<&Vec<i32>>) -> Option<Vec<i32>> {
    v.cloned()
}

#[test]
fn native_first_sync_omits_the_cached_id_arrays_instead_of_sending_empty_ones() {
    let q = text("scan", "000006", "request.body");
    assert!(!q.contains("InstalledNonLeafUpdateIDs"));
    assert!(!q.contains("OtherCachedUpdateIDs"));
    assert!(!q.contains("CachedDriverIDs"));

    let req: SyncUpdates = request("scan", "000006");
    let p = req.parameters.value().unwrap();
    assert!(!p.express_query);
    assert!(!p.skip_software_sync);
    assert!(p.installed_non_leaf_update_ids.is_absent());
    assert!(p.other_cached_update_ids.is_absent());
    assert!(p.cached_driver_ids.is_absent());
    assert!(p.system_spec.is_absent());
    let filter = p.filter_category_ids.value().unwrap();
    assert_eq!(filter.len(), 1);
    assert_eq!(
        filter[0].id,
        Uuid::parse_str("dd78b8a1-0b20-45c1-add6-4da72e9364cf").unwrap()
    );
    assert_eq!(
        p.need_two_group_out_of_scope_updates.value().copied(),
        Some(true)
    );
    // ComputerSpec is present and empty on the software pass.
    assert!(q.contains("<ComputerSpec/>"));
    // Elements this crate's SyncUpdateParameters does not model.
    assert!(q.contains("<AlsoPerformRegularSync>false</AlsoPerformRegularSync>"));
    assert!(
        q.contains("<ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>")
    );
    assert!(q.contains("<Products/>"));
    assert!(q.contains("<CallerAttributes>Interactive=0;SheddingAware=1;Id=OOBE ZDP;"));
    // The order the native client emits.
    let pos = |s: &str| q.find(s).unwrap_or_else(|| panic!("{s}"));
    assert!(pos("<ExpressQuery>") < pos("<SkipSoftwareSync>"));
    assert!(pos("<SkipSoftwareSync>") < pos("<FilterCategoryIds>"));
    assert!(pos("<FilterCategoryIds>") < pos("<NeedTwoGroupOutOfScopeUpdates>"));
    assert!(pos("<NeedTwoGroupOutOfScopeUpdates>") < pos("<AlsoPerformRegularSync>"));
    assert!(pos("<AlsoPerformRegularSync>") < pos("<ComputerSpec/>"));
    assert!(pos("<ComputerSpec/>") < pos("<ProductsParameters>"));

    let r: SyncUpdatesResponse = response("scan", "000006");
    let info = r.result.value().unwrap();
    assert!(!info.truncated);
    assert_eq!(info.new_updates.value().unwrap().len(), 1);
    let u = &info.new_updates.value().unwrap()[0];
    assert_eq!(u.id, 108226);
    assert!(!u.is_leaf);
    assert_eq!(
        info.driver_sync_not_needed.value().map(String::as_str),
        Some("true")
    );
}

#[test]
fn native_scan_continues_after_non_leaf_results_and_feeds_them_back_as_installed() {
    // Not truncated but the response held a non-leaf update, so the client
    // calls again (MS-WUSP 3.1.5.7), listing the non-leaf id as installed.
    let r6: SyncUpdatesResponse = response("scan", "000006");
    assert!(!r6.result.value().unwrap().truncated);
    let p7 = request::<SyncUpdates>("scan", "000007");
    assert_eq!(
        ids(p7
            .parameters
            .value()
            .unwrap()
            .installed_non_leaf_update_ids
            .value()),
        Some(vec![108226])
    );
    let p8 = request::<SyncUpdates>("scan", "000008");
    assert_eq!(
        ids(p8
            .parameters
            .value()
            .unwrap()
            .installed_non_leaf_update_ids
            .value()),
        Some(vec![108226, 108231])
    );
    // The third response held a leaf; it was NOT added to OtherCachedUpdateIDs
    // in the following (driver) request of this scan.
    let r8: SyncUpdatesResponse = response("scan", "000008");
    let u = &r8.result.value().unwrap().new_updates.value().unwrap()[0];
    assert_eq!((u.id, u.is_leaf), (72571, true));
    let p9 = request::<SyncUpdates>("scan", "000009");
    assert!(
        p9.parameters
            .value()
            .unwrap()
            .other_cached_update_ids
            .is_absent()
    );
}

#[test]
fn native_driver_pass_has_system_spec_and_the_feature_score_key() {
    let q = text("scan", "000009", "request.body");
    let req: SyncUpdates = request("scan", "000009");
    let p = req.parameters.value().unwrap();
    assert!(p.skip_software_sync);
    assert_eq!(
        ids(p.installed_non_leaf_update_ids.value()),
        Some(vec![108226, 108231])
    );
    let devices = p.system_spec.value().unwrap();
    assert_eq!(devices.len(), 70);
    assert_eq!(count(&q, "<ExtensionDriver>"), 1);
    assert_eq!(
        p.computer_spec
            .value()
            .unwrap()
            .hardware_ids
            .value()
            .unwrap()
            .len(),
        6
    );
    assert_eq!(
        p.feature_score_matching_key.value().map(String::as_str),
        Some("AMD64.10.0")
    );
    // The driver pass keeps the category filter and the same trailing
    // ProductsParameters block.
    assert_eq!(p.filter_category_ids.value().unwrap().len(), 1);
    assert!(q.contains("<AlsoPerformRegularSync>false</AlsoPerformRegularSync>"));

    let r: SyncUpdatesResponse = response("scan", "000009");
    let info = r.result.value().unwrap();
    assert!(!info.truncated);
    assert!(info.new_updates.is_absent() || info.new_updates.value().unwrap().is_empty());
    assert_eq!(
        info.driver_sync_not_needed.value().map(String::as_str),
        Some("true")
    );
}

#[test]
fn native_get_extended_update_info_for_categories_has_no_file_locations() {
    let req: GetExtendedUpdateInfo = request("scan", "000010");
    assert_eq!(
        req.revision_ids.value().cloned(),
        Some(vec![72571, 108226, 108231])
    );
    assert_eq!(
        req.info_types.value().cloned(),
        Some(vec![
            XmlUpdateFragmentType::Extended,
            XmlUpdateFragmentType::LocalizedProperties
        ])
    );
    assert_eq!(
        req.locales.value().cloned(),
        Some(vec!["en-US".to_owned(), "en".to_owned()])
    );
    assert_eq!(req.geo_id.value().map(String::as_str), Some("USA"));
    assert_eq!(
        req.caller_attributes.value().map(String::as_str),
        Some("Interactive=0;SheddingAware=1;Id=OOBE ZDP;AADDeviceTokenState=WU:0x00248002;")
    );
    // Element order on the wire: cookie, revisionIDs, infoTypes, locales,
    // deviceAttributes, GeoId, callerAttributes. `deviceAttributes` is an
    // element this crate does not model; the decoder ignores it.
    let q = text("scan", "000010", "request.body");
    assert!(q.contains("<deviceAttributes>"));
    assert!(q.contains("UpdateServiceUrl=http://192.0.2.1:8530;"));

    let r: GetExtendedUpdateInfoResponse = response("scan", "000010");
    let info = r.result.value().unwrap();
    let updates = info.updates.value().unwrap();
    // One Extended and one LocalizedProperties fragment per revision.
    assert_eq!(updates.len(), 6);
    assert!(info.file_locations.is_absent());
    assert!(
        updates[0]
            .xml
            .value()
            .unwrap()
            .contains("UpdateHandlers/Category")
    );
}

// ---------------------------------------------------------------------------
// SyncUpdates, flow capture (cached lists, approved update)
// ---------------------------------------------------------------------------

#[test]
fn native_cached_lists_split_installed_non_leaf_from_other_cached() {
    // (exchange, installed ids, other cached ids) as sent by the native client.
    // The cookie was reused from the earlier scan, so no handshake is in this
    // capture. Installed non-leaf stays small (87 to 94, never near the
    // 400-entry cap of the server); every returned leaf is added to
    // OtherCachedUpdateIDs, 30 per full page.
    for (n, installed, other) in [
        ("000001", 87usize, 1029usize),
        ("000003", 94, 1037),
        ("000012", 94, 1307),
        ("000013", 94, 1337),
    ] {
        let req: SyncUpdates = request("flow", n);
        let p = req.parameters.value().unwrap();
        assert_eq!(
            p.installed_non_leaf_update_ids.value().unwrap().len(),
            installed,
            "{n}"
        );
        assert_eq!(
            p.other_cached_update_ids.value().unwrap().len(),
            other,
            "{n}"
        );
        assert!(p.cached_driver_ids.is_absent(), "{n}");
        assert!(!p.skip_software_sync, "{n}");
        assert!(!p.express_query, "{n}");
        // No category filter on this scan: it came from an API client
        // (powershell.exe), not from OOBE.
        assert!(p.filter_category_ids.is_absent(), "{n}");
        assert_eq!(
            p.need_two_group_out_of_scope_updates.value().copied(),
            Some(true),
            "{n}"
        );
        let q = text("flow", n, "request.body");
        // Regular sync flag is true here (false in the OOBE scan).
        assert!(
            q.contains("<AlsoPerformRegularSync>true</AlsoPerformRegularSync>"),
            "{n}"
        );
        assert!(
            q.contains("Id=&lt;&lt;PROCESS&gt;&gt;: powershell.exe;"),
            "{n}"
        );
    }
}

#[test]
fn native_pages_hold_thirty_updates_and_the_last_page_is_not_truncated() {
    let first: SyncUpdatesResponse = response("flow", "000001");
    let i = first.result.value().unwrap();
    assert_eq!(i.new_updates.value().unwrap().len(), 6);
    assert!(!i.truncated);

    let mid: SyncUpdatesResponse = response("flow", "000003");
    let i = mid.result.value().unwrap();
    assert_eq!(i.new_updates.value().unwrap().len(), 30);
    assert!(i.truncated);
    assert!(
        i.new_updates
            .value()
            .unwrap()
            .iter()
            .all(|u| u.is_leaf && u.deployment.value().unwrap().action == DeploymentAction::Bundle)
    );

    let last: SyncUpdatesResponse = response("flow", "000013");
    let i = last.result.value().unwrap();
    assert_eq!(i.new_updates.value().unwrap().len(), 30);
    // A full page of 30 updates with Truncated false: the page size is not an
    // end marker. The native client made one more call (the driver pass).
    assert!(!i.truncated);
    assert!(i.new_cookie.is_value());
    assert_eq!(
        i.driver_sync_not_needed.value().map(String::as_str),
        Some("false")
    );
}

#[test]
fn native_flow_page_with_the_approved_update_carries_action_install() {
    let r: SyncUpdatesResponse = response("flow", "000012");
    let ups = r.result.value().unwrap().new_updates.value().unwrap();
    let installs: Vec<_> = ups
        .iter()
        .filter(|u| u.deployment.value().unwrap().action == DeploymentAction::Install)
        .collect();
    assert_eq!(installs.len(), 1);
    let u = installs[0];
    assert_eq!(u.id, 200996);
    assert!(u.is_leaf);
    let d = u.deployment.value().unwrap();
    assert!(d.is_assigned);
    // The approval did not turn on AutoSelect, AutoDownload or a deadline.
    assert_eq!(d.auto_select.value().map(String::as_str), Some("0"));
    assert_eq!(d.auto_download.value().map(String::as_str), Some("0"));
    assert!(d.deadline.is_absent());
    let xml = u.xml.value().unwrap();
    assert!(xml.contains("a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe"));
    assert!(xml.contains("RevisionNumber=\"200\""));
    // The Core fragment of an approved Software update carries more
    // Properties attributes than the catalog pages of run 1 did.
    assert!(xml.contains(
        "UpdateType=\"Software\" ExplicitlyDeployable=\"true\" AutoSelectOnWebSites=\"true\""
    ));
}

#[test]
fn native_final_driver_pass_has_75_devices_and_skips_other_cached_ids() {
    let req: SyncUpdates = request("flow", "000014");
    let p = req.parameters.value().unwrap();
    assert!(p.skip_software_sync);
    assert_eq!(p.system_spec.value().unwrap().len(), 70 + 5);
    assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 94);
    // Software ids are not repeated in the driver pass.
    assert!(p.other_cached_update_ids.is_absent());
    assert!(p.cached_driver_ids.is_absent());
    assert_eq!(
        p.feature_score_matching_key.value().map(String::as_str),
        Some("AMD64.10.0")
    );
    let r: SyncUpdatesResponse = response("flow", "000014");
    let info = r.result.value().unwrap();
    assert!(!info.truncated);
    assert_eq!(
        info.driver_sync_not_needed.value().map(String::as_str),
        Some("true")
    );
}

// ---------------------------------------------------------------------------
// GetExtendedUpdateInfo with FileLocations (flow capture)
// ---------------------------------------------------------------------------

#[test]
fn native_get_extended_update_info_for_the_approved_batch_returns_file_locations() {
    let req: GetExtendedUpdateInfo = request("flow", "000015");
    let revs = req.revision_ids.value().unwrap();
    assert_eq!(revs.len(), 18);
    // Fewer than MaxExtendedUpdatesPerRequest (50); ascending ids; includes
    // the approved revision.
    assert!(revs.windows(2).all(|w| w[0] < w[1]));
    assert!(revs.contains(&200996));
    // The request asks for Extended and LocalizedProperties only: it does not
    // name a file-URL info type; the Extended fragment carries `Files` and the
    // response adds `FileLocations`.
    assert_eq!(
        req.info_types.value().cloned(),
        Some(vec![
            XmlUpdateFragmentType::Extended,
            XmlUpdateFragmentType::LocalizedProperties
        ])
    );
    assert_eq!(
        req.locales.value().cloned(),
        Some(vec!["en-US".to_owned(), "en".to_owned()])
    );
    assert_eq!(req.geo_id.value().map(String::as_str), Some("USA"));

    let r: GetExtendedUpdateInfoResponse = response("flow", "000015");
    let info = r.result.value().unwrap();
    let updates = info.updates.value().unwrap();
    assert_eq!(updates.len(), 36);
    let distinct: std::collections::BTreeSet<i32> = updates.iter().map(|u| u.id).collect();
    assert_eq!(distinct.len(), 18);
    assert!(info.out_of_scope_revision_ids.is_absent());

    let locs = info.file_locations.value().unwrap();
    assert_eq!(locs.len(), 9);
    for l in locs {
        let digest = l.file_digest.value().unwrap();
        assert_eq!(digest.len(), 20);
        let hex = digest_hex_upper(digest);
        let url = l.url.value().unwrap();
        // The observed rule: Content/<last two hex chars, upper case>/<SHA-1
        // hex, upper case>.exe, scheme and host:port of the request.
        assert_eq!(
            url,
            &format!(
                "http://192.0.2.1:8530/Content/{}/{}.exe",
                &hex[hex.len() - 2..],
                hex
            )
        );
        // No other FileLocation fields on this build.
        assert!(l.pieces_hash_url.is_absent());
        assert!(l.block_map_url.is_absent());
        assert!(l.decryption_information.is_absent());
        assert!(l.file_digest_algorithm.is_absent());
    }
    // Every digest named by a `Files` element of an Extended fragment has a
    // location, and the approved update's file (from its Extended fragment)
    // is among them.
    let xml_all: String = updates
        .iter()
        .filter_map(|u| u.xml.value())
        .cloned()
        .collect::<Vec<_>>()
        .join("");
    assert!(xml_all.contains("Handlers/CommandLineInstallation"));
    assert!(xml_all.contains("DigestAlgorithm=\"SHA1\""));
    assert!(xml_all.contains("<AdditionalDigest Algorithm=\"SHA256\">"));
    assert_eq!(count(&xml_all, "<File Digest="), 9);
    use base64::Engine as _;
    for l in locs {
        let b64 = base64::engine::general_purpose::STANDARD.encode(l.file_digest.value().unwrap());
        assert!(
            xml_all.contains(&format!("<File Digest=\"{b64}\"")),
            "no Files entry for {b64}"
        );
    }
}

// ---------------------------------------------------------------------------
// ReportEventBatch (Reporting service)
// ---------------------------------------------------------------------------

/// (event id, Win32HResult, update id, revision) of every event of a batch.
fn events(n: &str) -> Vec<(i16, i32, String, u32)> {
    let (v, req) = decode_request::<ReportEventBatch>(
        Some(&soap_action("flow", n)),
        &read("flow", n, "request.body"),
        &Limits::default(),
    )
    .unwrap_or_else(|e| panic!("flow/{n}: {e:?}"));
    assert_eq!(v, SoapVersion::V11);
    req.event_batch
        .value()
        .unwrap()
        .iter()
        .map(|e| {
            let b = e.basic_data.value().unwrap();
            let u = b.update_id.value().unwrap();
            (
                b.event_id,
                b.win32_hresult,
                u.id.0.to_string().to_ascii_lowercase(),
                u.revision.0,
            )
        })
        .collect()
}

#[test]
fn native_report_event_batches_use_the_reporting_path_and_decode() {
    for n in ["000016", "000017", "000018"] {
        assert_eq!(
            soap_action("flow", n).trim_matches('"'),
            REPORT_ACTION,
            "{n}"
        );
        let req: ReportEventBatch = request("flow", n);
        assert!(req.cookie.is_value());
        let batch = req.event_batch.value().unwrap();
        let t = req.client_time.as_str();
        assert!(t.starts_with("2026-10-04T15:20:47."), "{t}");
        for e in batch {
            let b = e.basic_data.value().unwrap();
            // Specified constants, observed holding.
            assert_eq!(b.namespace_id, 1);
            assert_eq!(b.sequence_number, 0);
            assert_eq!(b.source_id, 101);
            // TargetID.Sid is the client id GUID (not a SID).
            assert_eq!(
                b.target_id.value().unwrap().sid.value().map(String::as_str),
                Some(SCAN_CLIENT_ID)
            );
            assert!(Uuid::parse_str(&b.event_instance_id.to_string()).is_ok());
            let x = e.extended_data.value().unwrap();
            assert_eq!(
                x.processor_architecture,
                ProcessorArchitecture::Amd64Compatible
            );
            assert_eq!(x.os_version.major, 10);
            assert_eq!(x.os_version.build, 26200);
            assert_eq!(x.os_version.revision, 65792);
            assert_eq!(x.os_locale_id, 1033);
            assert_eq!(x.computer_brand.value().map(String::as_str), Some("QEMU"));
            // PrivateData is present and empty.
            assert!(e.private_data.is_value());
        }
        let r: ReportEventBatchResponse = response("flow", n);
        assert!(r.result);
    }
}

#[test]
fn native_event_id_table_as_observed() {
    const ZERO: &str = "00000000-0000-0000-0000-000000000000";
    const DEF_SIG: &str = "a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe";
    const MP_STUB: &str = "0daf8592-9e3f-4a8a-9141-d83fafebd09f";
    let b1 = events("000016");
    assert_eq!(
        b1.iter().map(|e| e.0).collect::<Vec<_>>(),
        [147, 148, 148, 148]
    );
    // 147: hresult 0, no update; 148: hresult 0x80240438 (-2145123272), no
    // update, replacement string "0x80240438" (names of the events are not
    // asserted: only ids, hresults, update ids and strings were observed).
    assert_eq!(b1[0].1, 0);
    assert!(b1[1..].iter().all(|e| e.1 == -2145123272));
    assert!(b1.iter().all(|e| e.2 == ZERO && e.3 == 0));

    let b2 = events("000017");
    assert_eq!(
        b2.iter().map(|e| e.0).collect::<Vec<_>>(),
        [148, 148, 147, 156, 147, 156, 161, 161, 181]
    );
    // 156: hresult 0, no update. 161: hresult 0x80004002 (-2147467262)
    // for each of the two revision-200 updates; 181: hresult 0 for the
    // Defender signature update.
    assert_eq!((b2[3].1, b2[3].2.as_str()), (0, ZERO));
    assert_eq!(
        (b2[6].0, b2[6].1, b2[6].2.as_str(), b2[6].3),
        (161, -2147467262, MP_STUB, 200)
    );
    assert_eq!(
        (b2[7].0, b2[7].1, b2[7].2.as_str(), b2[7].3),
        (161, -2147467262, DEF_SIG, 200)
    );
    assert_eq!(
        (b2[8].0, b2[8].1, b2[8].2.as_str(), b2[8].3),
        (181, 0, DEF_SIG, 200)
    );

    let b3 = events("000018");
    // 182: hresult 0x80246007 (-2145099769) for both updates.
    assert_eq!(
        b3.iter().map(|e| (e.0, e.1)).collect::<Vec<_>>(),
        [(182, -2145099769), (182, -2145099769)]
    );
    assert_eq!(b3[0].2, MP_STUB);
    assert_eq!(b3[1].2, DEF_SIG);

    // ReplacementStrings of the update events: the update title; for 182 of
    // the approved update the hresult text comes first.
    let req: ReportEventBatch = request("flow", "000018");
    let rs = |i: usize| -> Vec<String> {
        req.event_batch.value().unwrap()[i]
            .extended_data
            .value()
            .unwrap()
            .replacement_strings
            .value()
            .cloned()
            .unwrap_or_default()
    };
    assert!(rs(0).is_empty());
    assert_eq!(rs(1)[0], "0x80246007");
    assert!(
        rs(1)[1].starts_with(
            "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602"
        )
    );
}

#[test]
fn native_report_event_batch_encoder_output_round_trips() {
    use wsus_protocol::soap::encode_request;
    let req: ReportEventBatch = request("flow", "000017");
    let enc = encode_request(SoapVersion::V11, &req);
    let (_, back): (SoapVersion, ReportEventBatch) =
        decode_request(enc.soap_action.as_deref(), &enc.body, &Limits::default()).unwrap();
    assert_eq!(back, req);
}
