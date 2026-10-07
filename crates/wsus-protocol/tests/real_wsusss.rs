//! Decode tests over sanitized REAL MS-WSUSSS exchanges (milestone M5, first real contact).
//!
//! Provenance: `docs/fixtures/wsus-m0-wsusss/` holds exchanges recorded on 2026-10-04 against
//! the lab WSUS acting as an UPSTREAM server (Windows Server 2025 build 10.0.26100, WSUS role,
//! WSUS configuration `LazySync` true). `exchanges/` was produced by the probe script
//! `scripts/wsus/probe-wsusss.py` (plain SOAP 1.1 POSTs, not a downstream WSUS and not this
//! project's client); `exchanges-client/` is this project's downstream importer
//! (`wsus admin sync start`). Both went through `scripts/wsus/capture-proxy.py` and
//! `scripts/wsus/sanitize-capture.py`; cookie material is replaced by base64 `A` runs; the very
//! long `GetRevisionIdList` answers were cut to their first 30 revisions BEFORE sanitizing (the
//! README in that directory lists the original sizes and hashes).
//!
//! Scope: these tests show that this crate's MS-WSUSSS decoders accept what that one server
//! build sent for the listed operations and pin the facts the inventory records in 9.5. They do
//! not validate any other server, build or configuration (`docs/wsus-validation.md`).
use std::path::PathBuf;

use wsus_protocol::ProtocolError;
use wsus_protocol::metadata::UpdateIndex;
use wsus_protocol::soap::{
    Body, Envelope, ErrorCode, Limits, Recovery, SoapMessage, SoapRequest, SoapVersion,
    decode_request, decode_response,
};
use wsus_protocol::wsusss::{
    GetAuthConfig, GetAuthConfigResponse, GetAuthorizationCookie, GetAuthorizationCookieResponse,
    GetConfigData, GetConfigDataResponse, GetCookie, GetCookieResponse, GetRevisionIdList,
    GetRevisionIdListResponse, GetUpdateData, GetUpdateDataResponse,
};

fn uuid_of(s: &str) -> uuid::Uuid {
    s.parse().unwrap()
}

const PRODUCT: &str = "8c3fcc84-7410-4a95-8b89-a166a0190486";
const CLASSIFICATION: &str = "e0789628-ce08-4437-be74-2495b842f43b";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/fixtures/wsus-m0-wsusss")
}

fn read(set: &str, n: &str, f: &str) -> Vec<u8> {
    let p = root().join(set).join(n).join(f);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn soap_action(set: &str, n: &str) -> String {
    let text = String::from_utf8(read(set, n, "request.headers")).unwrap();
    text.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("soapaction")
                .then(|| v.trim().to_owned())
        })
        .expect("soapaction header")
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

#[test]
fn get_auth_config_names_the_dss_targeting_plug_in_with_a_relative_service_url() {
    let _: GetAuthConfig = request("exchanges", "000001");
    let r: GetAuthConfigResponse = response("exchanges", "000001");
    let cfg = r.result.value().unwrap();
    let plugins = cfg.auth_info.value().unwrap();
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].plug_in_id.value().unwrap(), "DssTargeting");
    // Relative, and spelled `DssAuthWebService/DssAuthWebService.asmx` (inventory 3.2).
    assert_eq!(
        plugins[0].service_url.value().unwrap(),
        "DssAuthWebService/DssAuthWebService.asmx"
    );
    assert!(cfg.allowed_event_ids.value().is_none());
}

#[test]
fn dss_authorization_cookie_uses_the_dss_auth_namespace_and_returns_dss_targeting() {
    let req: GetAuthorizationCookie = request("exchanges", "000002");
    assert_eq!(
        req.account_name.value().unwrap(),
        "probe.lab.invalid",
        "accountName is a FQDN-valid string"
    );
    assert!(
        req.account_guid
            .value()
            .unwrap()
            .parse::<uuid::Uuid>()
            .is_ok()
    );
    assert!(req.program_keys.value().is_none());
    assert!(
        soap_action("exchanges", "000002")
            .contains("/Server/DssAuthWebService/GetAuthorizationCookie")
    );
    let r: GetAuthorizationCookieResponse = response("exchanges", "000002");
    let c = r.result.value().unwrap();
    assert_eq!(c.plug_in_id.value().unwrap(), "DssTargeting");
    assert!(!c.cookie_data.value().unwrap().is_empty());
}

#[test]
fn get_cookie_with_protocol_version_1_20_returns_a_four_hour_cookie() {
    let req: GetCookie = request("exchanges", "000003");
    assert_eq!(req.protocol_version.value().unwrap(), "1.20");
    assert_eq!(req.auth_cookies.value().unwrap().len(), 1);
    assert!(req.old_cookie.value().is_none());
    let r: GetCookieResponse = response("exchanges", "000003");
    let c = r.result.value().unwrap();
    // `Expiration` is `xs:dateTime` with up to seven fractional digits; four hours after the
    // call (the call was at 16:33 UTC, the cookie expired at 20:33 UTC; the WSUSSS text says
    // 240 minutes in Windows).
    let exp = c.expiration.as_str();
    assert!(exp.starts_with("2026-10-04T20:3"), "{exp}");
    assert!(exp.ends_with('Z'));
}

#[test]
fn get_config_data_reports_lazy_sync_a_100_update_limit_and_a_timestamped_anchor() {
    let r: GetConfigDataResponse = response("exchanges", "000005");
    let c = r.result.value().unwrap();
    assert!(!c.catalog_only_sync);
    assert!(c.lazy_sync, "LazySync is true on the lab WSUS");
    assert!(!c.server_hosts_psf_files);
    assert_eq!(c.max_number_of_updates_per_request, 100);
    assert_eq!(c.max_number_of_computer_ids_in_request, 0);
    assert_eq!(c.protocol_version.value().unwrap(), "1.20");
    // `<revision counter>,<yyyy-MM-dd HH:mm:ss.fff>`: the Windows anchor form (inventory 6.2).
    let anchor = c.new_config_anchor.value().unwrap();
    let (n, ts) = anchor.split_once(',').expect("comma");
    assert!(n.parse::<u32>().is_ok(), "{anchor}");
    assert_eq!(ts.len(), "2026-10-04 16:09:27.167".len(), "{anchor}");
    // 63 languages, LanguageID 0 meaning `all`.
    let langs = c.language_update_list.value().unwrap();
    assert!(langs.len() > 30, "{}", langs.len());
    assert_eq!(langs[0].language_id, 0);
    assert_eq!(langs[0].short_language.value().unwrap(), "all");
    assert!(
        langs
            .iter()
            .any(|l| l.short_language.value().is_some_and(|s| s == "en") && l.enabled),
        "English is enabled"
    );
    // A request with a `configAnchor` is accepted and answers with a (new) anchor.
    let r: GetConfigData = request("exchanges", "000004");
    assert_eq!(
        r.config_anchor.value().unwrap(),
        "9438,2026-10-04 16:09:27.167"
    );
    let r: GetConfigDataResponse = response("exchanges", "000004");
    assert!(r.result.value().is_some());
}

#[test]
fn revision_lists_hold_one_update_identity_per_revision_and_an_anchor() {
    let r: GetRevisionIdListResponse = response("exchanges", "000006");
    let list = r.result.value().unwrap();
    assert_eq!(list.new_revisions.value().unwrap().len(), 30);
    assert!(list.anchor.value().unwrap().starts_with("9438,2026-10-04 "));
    // The real answer held 4275 revisions (categories, classifications, detectoids); revision
    // numbers 1 and 100 appear for the same root category (inventory 9.5).
    let revs = list.new_revisions.value().unwrap();
    assert!(revs.iter().any(|r| r.revision.0 == 100));
    assert!(revs.iter().any(|r| r.revision.0 == 1));
}

#[test]
fn wire_filter_semantics_as_observed() {
    // product only, then product plus another classification: nothing.
    for n in ["000007", "000008"] {
        let r: GetRevisionIdListResponse = response("exchanges", n);
        assert!(
            r.result.value().unwrap().new_revisions.value().is_none()
                || r.result
                    .value()
                    .unwrap()
                    .new_revisions
                    .value()
                    .unwrap()
                    .is_empty(),
            "{n}"
        );
    }
    let only_product: GetRevisionIdList = request("exchanges", "000007");
    let f = only_product.filter.value().unwrap();
    assert_eq!(f.categories.value().unwrap().len(), 1);
    assert!(f.classifications.value().is_none());
    assert_eq!(f.categories.value().unwrap()[0].id, uuid_of(PRODUCT));

    // product and classification: the revisions (30 kept of 24,509).
    let both: GetRevisionIdList = request("exchanges", "000009");
    let f = both.filter.value().unwrap();
    assert_eq!(f.categories.value().unwrap()[0].id, uuid_of(PRODUCT));
    assert_eq!(
        f.classifications.value().unwrap()[0].id,
        uuid_of(CLASSIFICATION)
    );
    assert!(!f.get_config);
    let r: GetRevisionIdListResponse = response("exchanges", "000009");
    assert_eq!(
        r.result
            .value()
            .unwrap()
            .new_revisions
            .value()
            .unwrap()
            .len(),
        30
    );
}

#[test]
fn delta_decides_whether_an_incremental_call_repeats_every_revision() {
    // Same anchor, same filter ids. Delta=false: everything again (trimmed to 30 here);
    // Delta=true: nothing changed.
    let again: GetRevisionIdList = request("exchanges", "000010");
    let f = again.filter.value().unwrap();
    assert!(f.anchor.value().is_some());
    assert!(!f.categories.value().unwrap()[0].delta);
    let r: GetRevisionIdListResponse = response("exchanges", "000010");
    assert_eq!(
        r.result
            .value()
            .unwrap()
            .new_revisions
            .value()
            .unwrap()
            .len(),
        30
    );

    let delta: GetRevisionIdList = request("exchanges", "000011");
    let f = delta.filter.value().unwrap();
    assert!(f.categories.value().unwrap()[0].delta);
    assert!(f.classifications.value().unwrap()[0].delta);
    let r: GetRevisionIdListResponse = response("exchanges", "000011");
    let list = r.result.value().unwrap();
    assert!(
        list.new_revisions.value().is_none_or(Vec::is_empty),
        "no change since the anchor"
    );
    // The anchor still advances.
    assert!(list.anchor.value().is_some());

    // Our downstream importer after the fix sends Delta=true on the incremental call.
    let ours: GetRevisionIdList = request("exchanges-client", "001046");
    assert!(ours.filter.value().unwrap().categories.value().unwrap()[0].delta);
    // ... and before the fix sent false and got everything again.
    let before: GetRevisionIdList = request("exchanges-client", "000625");
    assert!(!before.filter.value().unwrap().categories.value().unwrap()[0].delta);
    let r: GetRevisionIdListResponse = response("exchanges-client", "000625");
    assert_eq!(
        r.result
            .value()
            .unwrap()
            .new_revisions
            .value()
            .unwrap()
            .len(),
        30
    );
}

#[test]
fn an_unfiltered_call_with_an_anchor_returns_only_changes() {
    let r: GetRevisionIdListResponse = response("exchanges", "000012");
    assert!(
        r.result
            .value()
            .unwrap()
            .new_revisions
            .value()
            .is_none_or(Vec::is_empty)
    );
}

#[test]
fn get_update_data_returns_a_cabinet_blob_for_large_documents_and_text_for_small_ones() {
    // Bundle (about 35 KB of XML): compressed.
    let r: GetUpdateDataResponse = response("exchanges", "000013");
    let data = r.result.value().unwrap();
    let u = &data.updates.value().unwrap()[0];
    assert!(u.xml_update_blob.value().is_none());
    let blob = u.xml_update_blob_compressed.value().unwrap();
    assert_eq!(&blob[..4], b"MSCF", "the blob is a Microsoft Cabinet");
    assert!(
        u.file_digest_list.value().is_none(),
        "a bundle has no files"
    );
    assert!(data.file_urls.value().is_none_or(Vec::is_empty));

    // Leaf with one file: compressed, one SHA-1 digest, one `fileUrls` entry with an MU URL
    // and an EMPTY UssUrl.
    let r: GetUpdateDataResponse = response("exchanges", "000014");
    let data = r.result.value().unwrap();
    let u = &data.updates.value().unwrap()[0];
    assert!(u.xml_update_blob_compressed.value().is_some());
    let digests = u.file_digest_list.value().unwrap();
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].len(), 20);
    let urls = data.file_urls.value().unwrap();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].file_digest.value().unwrap(), &digests[0]);
    assert!(
        urls[0]
            .mu_url
            .value()
            .unwrap()
            .starts_with("http://download.windowsupdate.com/")
    );
    assert!(urls[0].uss_url.value().is_none_or(|s| s.is_empty()));
    assert!(urls[0].decryption_key.value().is_none());

    // A small document (1432 characters) arrives as `XmlUpdateBlob` text, already unescaped by
    // the SOAP layer; a 4917 character category is compressed again. Across the whole lab
    // catalog (24,509 software revisions) the 28 uncompressed documents were at most 2469
    // characters (4938 bytes as UTF-16) and the smallest compressed one 2700 characters (5400
    // bytes): consistent with the specified 5,120 byte threshold (inventory 9.5).
    let r: GetUpdateDataResponse = response("exchanges", "000015");
    let u = &r.result.value().unwrap().updates.value().unwrap()[0];
    let xml = u.xml_update_blob.value().unwrap();
    assert!(u.xml_update_blob_compressed.value().is_none());
    assert!(xml.starts_with("<upd:Update ") && xml.contains("MpSigStub"));
    UpdateIndex::parse(xml.as_bytes(), &Limits::default()).unwrap();
    let r: GetUpdateDataResponse = response("exchanges", "000016");
    let u = &r.result.value().unwrap().updates.value().unwrap()[0];
    assert!(u.xml_update_blob.value().is_none());
    assert_eq!(&u.xml_update_blob_compressed.value().unwrap()[..4], b"MSCF");
}

#[test]
fn decoded_update_documents_are_strict_single_documents_with_declared_namespaces() {
    for name in std::fs::read_dir(root().join("docs")).unwrap() {
        let p = name.unwrap().path();
        let bytes = std::fs::read(&p).unwrap();
        let ix = UpdateIndex::parse(&bytes, &Limits::default())
            .unwrap_or_else(|e| panic!("{}: {e:?}", p.display()));
        // The file name carries `<update id>-r<revision>`.
        let stem = p.file_stem().unwrap().to_str().unwrap();
        assert_eq!(
            format!("{}-r{}", ix.identity.id.0, ix.identity.revision.0),
            stem.to_lowercase()
        );
    }
}

#[test]
fn real_faults_use_soap_client_or_server_with_the_wsusss_error_codes() {
    // Unknown update id: `InternalServerError`, `soap:Server`, empty Message.
    let cases = [
        ("000017", "Server", ErrorCode::InternalServerError, Some("")),
        (
            "000018",
            "Client",
            ErrorCode::InvalidParameters,
            Some("filter"),
        ),
        ("000019", "Client", ErrorCode::InvalidCookie, Some("")),
    ];
    for (n, code, want, msg) in cases {
        let body = read("exchanges", n, "response.body");
        let env = Envelope::decode(&body, &Limits::default()).unwrap();
        let Body::Fault(f) = env.body else {
            panic!("{n}: expected a fault")
        };
        assert_eq!(f.code_local(), code, "{n}");
        assert_eq!(f.reason, "Fault occurred", "{n}");
        let w = f.wsus.as_ref().expect("ErrorCode detail");
        assert_eq!(w.error_code, want, "{n}");
        assert_eq!(w.message.as_deref(), msg, "{n}");
        assert!(
            w.method
                .as_deref()
                .unwrap()
                .contains("SoftwareDistribution/Get")
        );
        // They also decode as the typed responses' error.
        let err = if n == "000017" {
            decode_response::<GetUpdateDataResponse>(&body, &Limits::default()).unwrap_err()
        } else {
            decode_response::<GetRevisionIdListResponse>(&body, &Limits::default()).unwrap_err()
        };
        assert!(matches!(err, ProtocolError::Fault(_)), "{n}");
    }
    // The WUSP recovery table classes the same code as a handshake restart; the WSUSSS table
    // (inventory 4.3) says restart from authorization, which is what the importer does.
    assert_eq!(
        ErrorCode::InvalidCookie.wusp_recovery(),
        Recovery::RestartHandshakeWithRefreshCache
    );
}

#[test]
fn our_importer_requests_decode_with_the_same_types() {
    // The Rust importer's own requests (exchanges-client) decode with the shared types.
    let _: GetAuthConfig = request("exchanges-client", "000001");
    let a: GetAuthorizationCookie = request("exchanges-client", "000002");
    assert_eq!(a.account_name.value().unwrap(), "m5.lab.invalid");
    let g: GetCookie = request("exchanges-client", "000003");
    assert_eq!(g.protocol_version.value().unwrap(), "1.20");
    let f: GetRevisionIdList = request("exchanges-client", "000013");
    assert_eq!(
        f.filter.value().unwrap().categories.value().unwrap().len(),
        1
    );
    let _: GetUpdateData = request("exchanges", "000013");
}
