//! Decode tests over sanitized REAL captures (milestone M0).
//!
//! Provenance: `docs/fixtures/wsus-m0/` holds exchanges recorded on
//! 2026-10-04 between this project's WUSP client (as a plain SOAP 1.1 POST
//! driver) and a real Windows Server 2025 build 10.0.26100 WSUS (role
//! installed, ProtocolVersion 3.2), sanitized with
//! `scripts/wsus/sanitize-capture.py --redact`. Cookie material is replaced by
//! base64 `A` runs; host names and addresses are redacted. See the README in
//! that directory.
//!
//! Scope: these tests show that this crate's decoders accept what that one
//! server build sent for the listed operations. They do not validate
//! compatibility beyond that pair and build (see `docs/wsus-validation.md`).

use std::path::PathBuf;

use wsus_protocol::identity::Revision;
use wsus_protocol::metadata::{FragmentSource, RawFragment, UpdateIndex, UpdateType};
use wsus_protocol::soap::{
    Body, Envelope, ErrorCode, Limits, Recovery, SoapVersion, decode_request, decode_response,
};
use wsus_protocol::wusp::{
    GetAuthorizationCookie, GetAuthorizationCookieResponse, GetConfig, GetConfigResponse,
    GetCookie, GetCookieResponse, RegisterComputer, RegisterComputerResponse, SyncUpdates,
    SyncUpdatesResponse,
};
use wsus_protocol::{ProtocolError, soap::SoapMessage};

const CLIENT_ACTION_PREFIX: &str =
    "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/";

fn dir(n: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/fixtures/wsus-m0")
        .join(n)
}

fn read(n: &str, f: &str) -> Vec<u8> {
    let p = dir(n).join(f);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn header(n: &str, f: &str, name: &str) -> Option<String> {
    let text = String::from_utf8(read(n, f)).unwrap();
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_owned())
    })
}

fn soap_action(n: &str) -> String {
    header(n, "request.headers", "soapaction").expect("soapaction header")
}

fn request<R: wsus_protocol::soap::SoapRequest>(n: &str) -> R {
    let (v, r) = decode_request::<R>(
        Some(&soap_action(n)),
        &read(n, "request.body"),
        &Limits::default(),
    )
    .unwrap_or_else(|e| panic!("exchange {n} request: {e:?}"));
    assert_eq!(v, SoapVersion::V11);
    r
}

fn response<M: SoapMessage>(n: &str) -> M {
    decode_response::<M>(&read(n, "response.body"), &Limits::default())
        .unwrap_or_else(|e| panic!("exchange {n} response: {e:?}"))
}

fn meta_status(n: &str) -> u64 {
    let text = String::from_utf8(read(n, "meta.json")).unwrap();
    let rest = text.split("\"status\":").nth(1).expect("status key");
    rest.trim_start()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

// ---------------------------------------------------------------------------

#[test]
fn http_framing_of_every_fixture_matches_the_observed_server() {
    for n in [
        "000001", "000002", "000003", "000004", "000005", "000070", "000140",
    ] {
        assert_eq!(meta_status(n), 200, "{n}");
        assert_eq!(
            header(n, "response.headers", "content-type").as_deref(),
            Some("text/xml; charset=utf-8"),
            "{n}"
        );
        assert_eq!(
            header(n, "response.headers", "server").as_deref(),
            Some("Microsoft-IIS/10.0"),
            "{n}"
        );
        // Not compressed: the client sent no Accept-Encoding.
        assert!(header(n, "response.headers", "content-encoding").is_none());
    }
    assert_eq!(meta_status("000141"), 500);
    // SOAPAction is quoted on the wire.
    assert!(soap_action("000001").starts_with('"'));
}

#[test]
fn get_config_request_and_response_decode() {
    let req: GetConfig = request("000001");
    assert_eq!(
        req.protocol_version.value().map(String::as_str),
        Some("1.8")
    );
    assert_eq!(
        soap_action("000001").trim_matches('"'),
        format!("{CLIENT_ACTION_PREFIX}GetConfig")
    );

    let r: GetConfigResponse = response("000001");
    let c = r.result.value().expect("GetConfigResult");
    assert_eq!(c.last_change.as_str(), "2026-10-04T13:17:07.59Z");
    assert!(c.is_registration_required);
    // No AllowedEventIds element in this build's response.
    assert!(c.allowed_event_ids.is_absent());

    let auth = c.auth_info.value().expect("AuthInfo");
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].plug_in_id.value().unwrap(), "SimpleTargeting");
    // Relative service URL, empty Parameter element.
    assert_eq!(
        auth[0].service_url.value().unwrap(),
        "SimpleAuthWebService/SimpleAuth.asmx"
    );
    assert_eq!(auth[0].parameter.value().map(String::as_str), Some(""));

    let props: Vec<(&str, &str)> = c
        .properties
        .value()
        .expect("Properties")
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
    assert!(get("PackageServerShare").ends_with("\\UpdateServicesPackages"));
}

#[test]
fn get_authorization_cookie_decodes() {
    let req: GetAuthorizationCookie = request("000002");
    let id = req.client_id.value().unwrap();
    assert_eq!(id.len(), 36);
    assert!(uuid::Uuid::parse_str(id).is_ok());
    assert!(req.dns_name.is_value());
    // The client sent no targetGroupName.
    assert!(req.target_group_name.is_absent());

    let r: GetAuthorizationCookieResponse = response("000002");
    let c = r.result.value().unwrap();
    assert_eq!(c.plug_in_id.value().unwrap(), "SimpleTargeting");
    // Redacted to base64 of zero bytes; the original was 496 bytes of
    // ciphertext (base64 length is preserved by the sanitizer).
    let data = c.cookie_data.value().unwrap();
    assert_eq!(data.len(), 496);
    assert!(data.iter().all(|b| *b == 0));
}

#[test]
fn get_cookie_decodes() {
    let req: GetCookie = request("000003");
    assert_eq!(req.auth_cookies.value().unwrap().len(), 1);
    assert_eq!(req.last_change.as_str(), "2026-10-04T13:17:07.59Z");
    assert_eq!(req.current_time.as_str(), "2026-10-04T14:49:05Z");
    assert!(req.old_cookie.is_absent());
    assert_eq!(
        req.protocol_version.value().map(String::as_str),
        Some("1.8")
    );

    let r: GetCookieResponse = response("000003");
    let c = r.result.value().unwrap();
    // Seven fractional digits (.NET DateTime round trip), one hour ahead.
    assert_eq!(c.expiration.as_str(), "2026-10-04T15:49:04.9425733Z");
    assert!(!c.encrypted_data.value().unwrap().is_empty());
}

#[test]
fn register_computer_decodes_and_the_response_is_empty() {
    let req: RegisterComputer = request("000004");
    let info = req.computer_info.value().unwrap();
    assert_eq!(info.os_major_version, 10);
    assert_eq!(info.os_build_number, 26100);
    assert_eq!(info.new_product_type, 48);
    assert_eq!(
        info.processor_architecture.value().map(String::as_str),
        Some("9")
    );
    assert!(req.cookie.is_value());
    let _: RegisterComputerResponse = response("000004");
    // Registration was required (GetConfig) and succeeded without a fault.
    assert_eq!(meta_status("000004"), 200);
}

fn fragments(n: &str) -> (SyncUpdatesResponse, Vec<RawFragment>) {
    let r: SyncUpdatesResponse = response(n);
    let info = r.result.value().unwrap();
    let frags = info
        .new_updates
        .value()
        .unwrap()
        .iter()
        .map(|u| RawFragment::from_update_info(None, u).expect("Xml present"))
        .collect();
    (r, frags)
}

#[test]
fn first_sync_updates_request_has_empty_cache_arrays() {
    let req: SyncUpdates = request("000005");
    let p = req.parameters.value().unwrap();
    assert!(!p.express_query);
    assert!(!p.skip_software_sync);
    assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 0);
    assert_eq!(p.other_cached_update_ids.value().unwrap().len(), 0);
    assert_eq!(p.cached_driver_ids.value().unwrap().len(), 0);
}

#[test]
fn sync_updates_pages_have_thirty_updates_and_are_truncated() {
    for n in ["000005", "000070", "000140"] {
        let (r, frags) = fragments(n);
        let info = r.result.value().unwrap();
        assert_eq!(info.new_updates.value().unwrap().len(), 30, "{n}");
        assert_eq!(frags.len(), 30, "{n}");
        assert!(info.truncated, "{n}");
        assert!(info.new_cookie.is_value(), "{n}");
        assert_eq!(
            info.driver_sync_not_needed.value().map(String::as_str),
            Some("false"),
            "{n}"
        );
        assert!(info.changed_updates.is_absent(), "{n}");
        assert!(info.out_of_scope_revision_ids.is_absent(), "{n}");
        for u in info.new_updates.value().unwrap() {
            let d = u.deployment.value().unwrap();
            assert!(d.is_assigned);
            assert_eq!(d.last_change_time, "2026-10-04");
            assert_eq!(d.auto_select.value().map(String::as_str), Some("0"));
            assert_eq!(d.auto_download.value().map(String::as_str), Some("0"));
            assert_eq!(
                d.supersedence_behavior.value().map(String::as_str),
                Some("0")
            );
        }
    }
}

#[test]
fn first_page_cookie_keeps_the_original_expiration() {
    let (r, _) = fragments("000005");
    let c = r.result.value().unwrap().new_cookie.value().unwrap();
    assert_eq!(c.expiration.as_str(), "2026-10-04T15:49:04.9425733Z");
}

#[test]
fn core_fragments_of_real_pages_parse_leniently() {
    let mut types = std::collections::BTreeMap::<String, usize>::new();
    let mut with_prereqs = 0;
    let mut with_rules = 0;
    for n in ["000005", "000070", "000140"] {
        let (_, frags) = fragments(n);
        for f in &frags {
            assert_eq!(f.origin.source, FragmentSource::WuspSyncUpdates);
            // Fragments are not well-formed documents (no single root and
            // b./m. prefixes), so the strict parser must refuse the
            // multi-root ones while the lenient one accepts all of them.
            let ix = f
                .fragment_index(&Limits::default())
                .unwrap_or_else(|e| panic!("{n}: {e:?}\n{}", String::from_utf8_lossy(f.xml())));
            let id = ix.identity.expect("Core has UpdateIdentity");
            assert!(id.revision.0 >= 1);
            let t = match ix.properties.update_type.clone().expect("UpdateType") {
                UpdateType::Software => "Software",
                UpdateType::Category => "Category",
                UpdateType::Detectoid => "Detectoid",
                other => panic!("unexpected {other:?}"),
            };
            *types.entry(t.into()).or_default() += 1;
            // Core carries no files or handler data.
            assert!(ix.files.is_empty());
            assert!(ix.handler_specific_data.is_none());
            if !ix.prerequisites.is_empty() {
                with_prereqs += 1;
            }
            if ix.applicability_rules.is_some() {
                with_rules += 1;
            }
            let full = UpdateIndex::from_fragments([f], None, &Limits::default())
                .unwrap_or_else(|e| panic!("{n}: from_fragments {e:?}"));
            assert_eq!(full.identity, id);
        }
    }
    assert!(types.get("Category").copied().unwrap_or(0) > 0, "{types:?}");
    assert!(
        types.get("Detectoid").copied().unwrap_or(0) > 0,
        "{types:?}"
    );
    assert!(with_prereqs > 0);
    assert!(with_rules > 0);
}

#[test]
fn first_page_starts_with_the_root_category() {
    let (r, frags) = fragments("000005");
    let first = &r.result.value().unwrap().new_updates.value().unwrap()[0];
    assert_eq!(first.id, 18);
    assert!(first.is_leaf);
    let ix = frags[0].fragment_index(&Limits::default()).unwrap();
    let id = ix.identity.unwrap();
    assert_eq!(
        id.id.0.to_string().to_ascii_lowercase(),
        "5c9376ab-8ce6-464a-b136-22113dd69801"
    );
    assert_eq!(id.revision, Revision(2));
    assert_eq!(ix.properties.update_type, Some(UpdateType::Category));
}

#[test]
fn last_successful_page_request_carries_398_and_3652_cached_ids() {
    let req: SyncUpdates = request("000140");
    let p = req.parameters.value().unwrap();
    assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 398);
    assert_eq!(p.other_cached_update_ids.value().unwrap().len(), 3652);
}

#[test]
fn over_cap_request_decodes_with_401_installed_ids() {
    let req: SyncUpdates = request("000141");
    let p = req.parameters.value().unwrap();
    assert_eq!(p.installed_non_leaf_update_ids.value().unwrap().len(), 401);
    assert_eq!(p.other_cached_update_ids.value().unwrap().len(), 3679);
}

#[test]
fn invalid_parameters_fault_decodes_independently_of_http_status() {
    let body = read("000141", "response.body");
    let env = Envelope::decode(&body, &Limits::default()).unwrap();
    let Body::Fault(f) = env.body else {
        panic!("expected fault")
    };
    assert_eq!(f.version, SoapVersion::V11);
    assert_eq!(f.code_local(), "Client");
    assert_eq!(f.reason, "Fault occurred");
    assert!(f.actor.is_none());
    let w = f.wsus.as_ref().expect("ErrorCode detail");
    assert_eq!(w.error_code, ErrorCode::InvalidParameters);
    assert_eq!(
        w.message.as_deref(),
        Some("parameters.InstalledNonLeafUpdateIDs")
    );
    assert_eq!(w.id.as_deref().map(str::len), Some(36));
    assert_eq!(
        w.method.as_deref(),
        Some(
            "\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates\""
        )
    );
    assert_eq!(w.error_code.wusp_recovery(), Recovery::FixParameters);

    match decode_response::<SyncUpdatesResponse>(&body, &Limits::default()).unwrap_err() {
        ProtocolError::Fault(f) => {
            assert_eq!(f.wsus.unwrap().error_code, ErrorCode::InvalidParameters)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn real_core_fragments_are_not_strict_documents_and_carry_relationships() {
    use wsus_protocol::wusp::DeploymentAction;
    let (r, frags) = fragments("000140");
    let ups = r.result.value().unwrap().new_updates.value().unwrap();
    let mut bundles = 0;
    let mut superseding = 0;
    let mut non_leaf = 0;
    for (u, f) in ups.iter().zip(&frags) {
        // Several top-level elements and b./m. prefixes: the strict
        // single-document parser refuses every real Core fragment.
        assert!(UpdateIndex::parse(f.xml(), &Limits::default()).is_err());
        let ix = f.fragment_index(&Limits::default()).unwrap();
        // The Core fragment of this build contains only the UpdateType
        // attribute on Properties and no Files or HandlerSpecificData.
        assert_eq!(ix.properties.attributes.len(), 1);
        assert!(ix.extensions.is_empty(), "{:?}", ix.extensions);
        if !u.is_leaf {
            non_leaf += 1;
        }
        if u.deployment.value().unwrap().action == DeploymentAction::Bundle {
            bundles += 1;
            assert_eq!(ix.properties.update_type, Some(UpdateType::Software));
            // Prerequisites include an AtLeastOne group without IsCategory.
            assert!(ix.prerequisites.iter().any(|c| !c.is_category));
        }
        if !ix.superseded.is_empty() {
            superseding += 1;
        }
    }
    assert_eq!(bundles, 5);
    assert_eq!(superseding, 5);
    assert_eq!(non_leaf, 3);
}

#[test]
fn real_responses_survive_a_reencode_decode_cycle() {
    use wsus_protocol::soap::encode_response;
    let r: GetConfigResponse = response("000001");
    let enc = encode_response(SoapVersion::V11, &r);
    let back: GetConfigResponse = decode_response(&enc.body, &Limits::default()).unwrap();
    assert_eq!(back, r);

    let r: SyncUpdatesResponse = response("000070");
    let enc = encode_response(SoapVersion::V11, &r);
    let back: SyncUpdatesResponse = decode_response(&enc.body, &Limits::default()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn encoder_output_for_the_captured_requests_decodes_to_the_same_values() {
    use wsus_protocol::soap::encode_request;
    let req: GetCookie = request("000003");
    let enc = encode_request(SoapVersion::V11, &req);
    let (_, back): (SoapVersion, GetCookie) =
        decode_request(enc.soap_action.as_deref(), &enc.body, &Limits::default()).unwrap();
    assert_eq!(back, req);
}
