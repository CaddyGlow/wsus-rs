//! MS-WSUSSS upstream server: raw protocol behaviour through the neutral handler.
//!
//! Self-consistency only. These tests encode this project's reading of the specification
//! and prove nothing about a real downstream WSUS server.
mod upstream_server_common;
use upstream_server_common::*;

use base64::Engine as _;
use wsus_protocol::identity::UpdateRevision;
use wsus_protocol::soap::{ErrorCode, Presence, SoapVersion, encode_request};
use wsus_protocol::wsusss::*;
use wsus_server::catalog::*;
use wsus_server::endpoints::HttpRequestParts;
use wsus_server::endpoints::wsusss::{
    AccountState, DownstreamAccess, Surface, UpstreamServerConfig, server_server_content_port,
};
use wsus_server::session::CookieKind;

// ---- routing and authorization -----------------------------------------------------

#[test]
fn get_auth_config_advertises_the_dss_targeting_plug_in() {
    let f = fixture();
    let c = f
        .call(&GetAuthConfig {})
        .unwrap()
        .result
        .into_value()
        .unwrap();
    let p = &c.auth_info.value().unwrap()[0];
    assert_eq!(p.plug_in_id.value().unwrap(), "DssTargeting");
    assert_eq!(
        p.service_url.value().unwrap(),
        "DssAuthWebService/DssAuthWebService.asmx"
    );
}

#[test]
fn paths_are_case_insensitive_and_unsupported_services_fail_cleanly() {
    let f = fixture();
    let enc = encode_request(SoapVersion::V11, &GetAuthConfig {});
    for p in [
        "/serversyncwebservice/serversyncwebservice.asmx",
        "/SERVERSYNCWEBSERVICE/ServerSyncProxy.asmx",
    ] {
        assert_eq!(f.post(p, enc.clone()).status, 200, "{p}");
    }
    assert_eq!(f.post("/nope", enc.clone()).status, 404);
    // Reporting is not implemented.
    let r = f.post("/ReportingWebService/ReportingWebService.asmx", enc.clone());
    assert_eq!(r.status, 404);
    // GET on a SOAP service.
    let r = f
        .server
        .handle(HttpRequestParts::new("GET", SYNC_PATH).with_header("Host", "x"));
    assert_eq!(r.status, 405);
    // An operation of the other service on this path, and an unsupported operation.
    let r = f.post(
        AUTH_PATH,
        encode_request(SoapVersion::V11, &GetAuthConfig {}),
    );
    assert_eq!(fault_envelope(r).0, 500);
    let c = f.cookie();
    let r = f.post(
        SYNC_PATH,
        encode_request(
            SoapVersion::V11,
            &GetDeployments {
                cookie: Presence::Value(c),
                deployment_anchor: Presence::Absent,
                sync_anchor: Presence::Value("1,2026-01-01 00:00:00.000".into()),
            },
        ),
    );
    let (status, fault) = fault_envelope(r);
    assert_eq!(status, 500);
    assert!(fault.reason.contains("unsupported operation"));
}

#[test]
fn soap_12_requests_work() {
    let f = fixture();
    let enc = encode_request(SoapVersion::V12, &GetAuthConfig {});
    let r = f.post(SYNC_PATH, enc);
    assert_eq!(r.status, 200);
}

#[test]
fn authorization_validates_account_name_and_guid_and_enrolls_on_first_contact() {
    let f = fixture();
    let ok = GetAuthorizationCookie {
        account_name: Presence::Value(ACCOUNT.into()),
        account_guid: Presence::Value(ACCOUNT_GUID.into()),
        program_keys: Presence::Absent,
    };
    assert!(f.downstreams_empty());
    f.call(&ok).unwrap();
    f.call(&ok).unwrap();
    let list = f.server.downstreams().list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, ACCOUNT);
    assert_eq!(list[0].state, AccountState::Enabled);
    for (name, guid) in [
        (None, Some(ACCOUNT_GUID)),
        (Some("  "), Some(ACCOUNT_GUID)),
        (Some("bad name!"), Some(ACCOUNT_GUID)),
        (Some(ACCOUNT), None),
        (Some(ACCOUNT), Some("not a guid")),
    ] {
        let mut r = ok.clone();
        r.account_name = name.map_or(Presence::Absent, |n| Presence::Value(n.into()));
        r.account_guid = guid.map_or(Presence::Absent, |n| Presence::Value(n.into()));
        assert_eq!(
            f.fault_code(&r),
            ErrorCode::InvalidParameters,
            "{name:?} {guid:?}"
        );
    }
}

impl Fixture {
    fn downstreams_empty(&self) -> bool {
        self.server.downstreams().list().unwrap().is_empty()
    }
}

#[test]
fn get_cookie_validates_parameters_and_cookies() {
    let f = fixture();
    let auth = f.auth_cookie(ACCOUNT, ACCOUNT_GUID);
    // Exactly one authorization cookie.
    let mut none = f.get_cookie_req(auth.clone(), "1.20");
    none.auth_cookies = Presence::Value(vec![]);
    assert_eq!(f.fault_code(&none), ErrorCode::InvalidParameters);
    let mut two = f.get_cookie_req(auth.clone(), "1.20");
    two.auth_cookies = Presence::Value(vec![auth.clone(), auth.clone()]);
    assert_eq!(f.fault_code(&two), ErrorCode::InvalidParameters);
    // Version: x.y required, major must be 1.
    for v in ["", "1", "1.", "a.b", "1.2.3"] {
        assert_eq!(
            f.fault_code(&f.get_cookie_req(auth.clone(), v)),
            ErrorCode::InvalidParameters,
            "{v:?}"
        );
    }
    assert_eq!(
        f.fault_code(&f.get_cookie_req(auth.clone(), "2.0")),
        ErrorCode::IncompatibleProtocolVersion
    );
    assert!(f.call(&f.get_cookie_req(auth.clone(), "1.0")).is_ok());
    // Forged and foreign cookies.
    let mut forged = auth.clone();
    let mut data = forged.cookie_data.value().unwrap().clone();
    let n = data.len();
    data[n - 1] ^= 1;
    forged.cookie_data = Presence::Value(data);
    assert_eq!(
        f.fault_code(&f.get_cookie_req(forged, "1.20")),
        ErrorCode::InvalidAuthorizationCookie
    );
    let mut wrong_plugin = auth.clone();
    wrong_plugin.plug_in_id = Presence::Value("SimpleTargeting".into());
    assert_eq!(
        f.fault_code(&f.get_cookie_req(wrong_plugin, "1.20")),
        ErrorCode::InvalidAuthorizationCookie
    );
    // A session cookie is not an authorization cookie.
    let session = f.cookie();
    let as_auth = AuthorizationCookie {
        plug_in_id: Presence::Value("DssTargeting".into()),
        cookie_data: session.encrypted_data.clone(),
    };
    assert_eq!(
        f.fault_code(&f.get_cookie_req(as_auth, "1.20")),
        ErrorCode::InvalidAuthorizationCookie
    );
}

#[test]
fn downstream_cookies_never_validate_as_wusp_cookies_and_the_reverse() {
    use wsus_server::session::CookieClaims;
    let f = fixture();
    let session = f.cookie();
    let sessions = &f.sessions;
    for kind in [CookieKind::Authorization, CookieKind::Session] {
        assert!(sessions.validate(Some(&session), kind).is_err());
    }
    assert!(
        sessions
            .validate(Some(&session), CookieKind::DownstreamSession)
            .is_ok()
    );
    // A WUSP session cookie is refused by the Server Sync service.
    let wusp = sessions.issue(&CookieClaims::new(
        CookieKind::Session,
        wsus_protocol::identity::ComputerId(uuid::Uuid::from_u128(1)),
    ));
    assert_eq!(
        f.fault_code(&revision_req(&wusp, None, true)),
        ErrorCode::InvalidCookie
    );
}

#[test]
fn missing_empty_and_expired_cookies_are_invalid_cookie() {
    let f = fixture();
    f.seed(1);
    let c = f.cookie();
    let mut absent = revision_req(&c, None, true);
    absent.cookie = Presence::Absent;
    assert_eq!(f.fault_code(&absent), ErrorCode::InvalidCookie);
    let mut empty = revision_req(&c, None, true);
    empty.cookie = Presence::Value(wsus_protocol::common::Cookie {
        expiration: c.expiration.clone(),
        encrypted_data: Presence::Value(vec![]),
    });
    assert_eq!(f.fault_code(&empty), ErrorCode::InvalidCookie);
    assert!(f.call(&revision_req(&c, None, true)).is_ok());
    // Expiry is enforced from the signed value, not the wire field.
    f.advance(241 * 60);
    assert_eq!(
        f.fault_code(&revision_req(&c, None, true)),
        ErrorCode::InvalidCookie
    );
    assert_eq!(
        f.fault_code(&GetConfigData {
            cookie: Presence::Value(c.clone()),
            config_anchor: Presence::Absent
        }),
        ErrorCode::InvalidCookie
    );
    // A fresh handshake works again while the authorization cookie lives.
    let c2 = f.cookie();
    assert!(f.call(&revision_req(&c2, None, true)).is_ok());
    // Past the authorization cookie's life a new one is needed.
    let auth = f.auth_cookie(ACCOUNT, ACCOUNT_GUID);
    f.advance(25 * 3600);
    assert_eq!(
        f.fault_code(&f.get_cookie_req(auth, "1.20")),
        ErrorCode::InvalidAuthorizationCookie
    );
}

#[test]
fn allowlist_admits_only_enrolled_enabled_accounts() {
    let cfg = UpstreamServerConfig {
        access: DownstreamAccess::Allowlist,
        ..config()
    };
    let f = fixture_with(cfg);
    // Unknown account: an authorization cookie is issued, GetCookie refuses it.
    let auth = f.auth_cookie(ACCOUNT, ACCOUNT_GUID);
    assert_eq!(
        f.fault_code(&f.get_cookie_req(auth.clone(), "1.20")),
        ErrorCode::InvalidAuthorizationCookie
    );
    assert!(f.server.downstreams().list().unwrap().is_empty());
    let guid = uuid::Uuid::parse_str(ACCOUNT_GUID).unwrap();
    f.server.downstreams().enroll(guid, ACCOUNT).unwrap();
    assert!(f.call(&f.get_cookie_req(auth.clone(), "1.20")).is_ok());
    f.server
        .downstreams()
        .set_state(guid, AccountState::Blocked)
        .unwrap();
    assert_eq!(
        f.fault_code(&f.get_cookie_req(auth, "1.20")),
        ErrorCode::InvalidAuthorizationCookie
    );
}

// ---- GetConfigData -----------------------------------------------------------------

#[test]
fn config_data_advertises_limits_and_a_stable_anchor_that_survives_restarts() {
    let f = fixture();
    f.seed(1);
    let c = f.cookie();
    let d = f.config_data(&c, None);
    assert!(!d.catalog_only_sync && !d.lazy_sync && !d.server_hosts_psf_files);
    assert_eq!(d.max_number_of_updates_per_request, 100);
    let anchor = d.new_config_anchor.value().unwrap().clone();
    assert_eq!(
        f.config_data(&c, Some(&anchor)).new_config_anchor.value(),
        Some(&anchor)
    );
    // Same configuration after a restart: same anchor.
    let f = f.restart();
    let c = f.cookie();
    assert_eq!(
        f.config_data(&c, Some(&anchor)).new_config_anchor.value(),
        Some(&anchor)
    );
    // A changed configuration advances the anchor; the old one is still accepted.
    let cfg = UpstreamServerConfig {
        max_updates_per_request: 7,
        ..config()
    };
    let f = f.restart_with(cfg);
    let c = f.cookie();
    let d = f.config_data(&c, Some(&anchor));
    assert_eq!(d.max_number_of_updates_per_request, 7);
    assert_ne!(d.new_config_anchor.value(), Some(&anchor));
    // Malformed and foreign anchors.
    let bad = |a: &str| {
        f.fault_code(&GetConfigData {
            cookie: Presence::Value(c.clone()),
            config_anchor: Presence::Value(a.into()),
        })
    };
    assert_eq!(bad("garbage"), ErrorCode::InvalidParameters);
    assert_eq!(bad("1,not a stamp"), ErrorCode::InvalidParameters);
    assert_eq!(
        bad("999999,2026-01-01 00:00:00.000"),
        ErrorCode::ServerChanged
    );
}

// ---- GetRevisionIdList -------------------------------------------------------------

#[test]
fn initial_listing_separates_configuration_from_software_and_incremental_listing_is_a_delta() {
    let f = fixture();
    f.seed(3);
    let c = f.cookie();
    let cfg = f.revision_list(&c, None, true);
    assert_eq!(
        ids(&cfg),
        vec![rev(PRODUCT, 1), rev(CLASSIFICATION, 1), rev(DETECTOID, 1)]
    );
    let sw = f.revision_list(&c, None, false);
    assert_eq!(ids(&sw), vec![rev(1, 1), rev(2, 1), rev(3, 1)]);
    let anchor = sw.anchor.value().unwrap().clone();
    // Anchor shape: `nnnn,yyyy-MM-dd HH:mm:ss.fff`.
    let (n, stamp) = anchor.split_once(',').unwrap();
    assert!(n.parse::<u32>().unwrap() >= 1);
    assert_eq!(stamp.len(), 23);
    // Unchanged catalog: same anchor, empty delta.
    let again = f.revision_list(&c, Some(&anchor), false);
    assert!(ids(&again).is_empty());
    assert_eq!(again.anchor.value(), Some(&anchor));
    // A refresh adds one update and revises another.
    f.refresh(&[Doc::software(4, 1), Doc::software(2, 2)]);
    let delta = f.revision_list(&c, Some(&anchor), false);
    assert_eq!(ids(&delta), vec![rev(2, 2), rev(4, 1)]);
    assert_ne!(delta.anchor.value(), Some(&anchor));
    // Chained: the new anchor sees nothing further.
    let next = delta.anchor.value().unwrap().clone();
    assert!(ids(&f.revision_list(&c, Some(&next), false)).is_empty());
    // A full listing offers the highest revision only, one entry per GUID.
    assert_eq!(
        ids(&f.revision_list(&c, None, false)),
        vec![rev(1, 1), rev(2, 2), rev(3, 1), rev(4, 1)]
    );
    // The configuration class is unaffected by software changes.
    assert!(ids(&f.revision_list(&c, Some(&cfg.anchor.value().unwrap().clone()), true)).is_empty());
}

#[test]
fn withdrawn_revisions_are_listed_and_served_with_their_document() {
    let f = fixture();
    f.seed(2);
    let c = f.cookie();
    let anchor = f
        .revision_list(&c, None, false)
        .anchor
        .value()
        .unwrap()
        .clone();
    let mut gone = Doc::software(2, 2);
    gone.expired = true;
    f.refresh(&[gone]);
    let d = f.revision_list(&c, Some(&anchor), false);
    assert_eq!(ids(&d), vec![rev(2, 2)]);
    let data = f.update_data(&c, &[rev(2, 2)]);
    let blob = data.updates.value().unwrap()[0]
        .xml_update_blob
        .value()
        .unwrap();
    assert!(blob.contains("PublicationState=\"Expired\""));
}

#[test]
fn anchors_survive_restarts_and_catalog_refreshes() {
    let f = fixture();
    f.seed(2);
    let c = f.cookie();
    let a1 = f
        .revision_list(&c, None, false)
        .anchor
        .value()
        .unwrap()
        .clone();
    f.refresh(&[Doc::software(3, 1)]);
    let a2 = f
        .revision_list(&c, Some(&a1), false)
        .anchor
        .value()
        .unwrap()
        .clone();
    let f = f.restart();
    f.refresh(&[Doc::software(4, 1)]);
    let c = f.cookie();
    // Both pre-restart anchors still resolve to their generations.
    assert_eq!(
        ids(&f.revision_list(&c, Some(&a1), false)),
        vec![rev(3, 1), rev(4, 1)]
    );
    assert_eq!(ids(&f.revision_list(&c, Some(&a2), false)), vec![rev(4, 1)]);
    // Anchors are minted per generation and never reused for another one.
    let a3 = f
        .revision_list(&c, None, false)
        .anchor
        .value()
        .unwrap()
        .clone();
    assert!(a3 != a1 && a3 != a2);
    // The wire anchor never contains a generation id: sequence numbers come from a counter
    // that is independent of generation ids.
    let seq = |a: &str| a.split_once(',').unwrap().0.parse::<i64>().unwrap();
    assert!(seq(&a1) < seq(&a2) && seq(&a2) < seq(&a3));
}

#[test]
fn unusable_anchors_are_parameter_errors_or_server_changed() {
    let f = fixture();
    f.seed(1);
    let c = f.cookie();
    let good = f
        .revision_list(&c, None, false)
        .anchor
        .value()
        .unwrap()
        .clone();
    let (n, stamp) = good.split_once(',').unwrap();
    let list = |a: &str| f.fault_code(&revision_req(&c, Some(a), false));
    for a in [
        "x",
        "1",
        ",",
        "0,2026-01-01 00:00:00.000",
        "01,2026-01-01 00:00:00.000",
        "+1,2026-01-01 00:00:00.000",
    ] {
        assert_eq!(list(a), ErrorCode::InvalidParameters, "{a:?}");
    }
    // A timestamp that is not the issued one.
    assert_eq!(
        list(&format!("{n},2001-01-01 00:00:00.000")),
        ErrorCode::InvalidParameters
    );
    // Never issued.
    assert_eq!(
        list("2147483647,2026-01-01 00:00:00.000"),
        ErrorCode::ServerChanged
    );
    // Missing filter.
    let mut nofilter = revision_req(&c, None, false);
    nofilter.filter = Presence::Absent;
    assert_eq!(f.fault_code(&nofilter), ErrorCode::InvalidParameters);
    // Pruned generation: the anchor can no longer be honoured.
    f.refresh(&[Doc::software(2, 1)]);
    f.refresh(&[Doc::software(3, 1)]);
    f.catalog.prune_superseded(f.source, 0).unwrap();
    assert_eq!(list(&good), ErrorCode::ServerChanged);
    assert!(stamp.len() == 23);
}

#[test]
fn an_empty_server_offers_nothing_and_wusp_form_records_are_not_enumerated() {
    let f = fixture();
    let c = f.cookie();
    let l = f.revision_list(&c, None, false);
    assert!(l.anchor.value().is_none() && ids(&l).is_empty());
    assert!(f.server.summary().unwrap().is_none());
    // One whole document and one record already in WUSP form (a Core fragment sequence).
    let wusp = FragmentImport::new(
        rev(9, 1),
        "Software",
        b"<UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000009\" RevisionNumber=\"1\"/>",
    );
    f.activate(&[Doc::bare(1, 1).record(), wusp]);
    let s = f.server.summary().unwrap().unwrap();
    assert_eq!(s.offered, 1);
    assert_eq!(s.not_offered, 1);
    assert_eq!(ids(&f.revision_list(&c, None, false)), vec![rev(1, 1)]);
    assert_eq!(
        f.fault_code(&GetUpdateData {
            cookie: Presence::Value(c),
            update_ids: Presence::Value(vec![rev(9, 1)]),
        }),
        ErrorCode::InvalidParameters
    );
}

// ---- GetUpdateData -----------------------------------------------------------------

#[test]
fn update_data_returns_stored_documents_verbatim_with_digests_and_content_urls() {
    let f = fixture();
    let data = b"payload bytes";
    f.publish(&[
        Doc::config(PRODUCT, "Category"),
        Doc::config(CLASSIFICATION, "Category"),
        Doc::config(DETECTOID, "Detectoid"),
        Doc::software(1, 1).with_file("a.cab", data),
        Doc::software(2, 1),
    ]);
    let c = f.cookie();
    let r = f.update_data(&c, &[rev(1, 1), rev(2, 1), rev(1, 1)]);
    let ups = r.updates.value().unwrap();
    assert_eq!(ups.len(), 2, "a repeated id is served once");
    assert_eq!(ups[0].id.value(), Some(&rev(1, 1)));
    assert_eq!(
        ups[0].xml_update_blob.value().unwrap().as_bytes(),
        Doc::software(1, 1)
            .with_file("a.cab", data)
            .xml()
            .as_bytes()
    );
    assert!(ups[0].xml_update_blob_compressed.value().is_none());
    assert_eq!(ups[0].file_digest_list.value().unwrap(), &vec![sha1(data)]);
    assert!(ups[1].file_digest_list.value().is_none());
    let urls = r.file_urls.value().unwrap();
    assert_eq!(urls.len(), 1);
    let hex: String = sha1(data).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        urls[0].uss_url.value().unwrap(),
        &format!("http://uss.test:80/Content/{}/{hex}", &hex[38..])
    );
    assert!(urls[0].mu_url.value().is_none() && urls[0].decryption_key.value().is_none());
    assert_eq!(urls[0].file_digest.value().unwrap(), &sha1(data));
}

#[test]
fn update_data_rejects_unknown_empty_and_oversized_count() {
    let cfg = UpstreamServerConfig {
        max_updates_per_request: 3,
        ..config()
    };
    let f = fixture_with(cfg);
    f.seed(5);
    let c = f.cookie();
    assert_eq!(f.config_data(&c, None).max_number_of_updates_per_request, 3);
    let req = |ids: Vec<UpdateRevision>| GetUpdateData {
        cookie: Presence::Value(c.clone()),
        update_ids: Presence::Value(ids),
    };
    assert_eq!(f.fault_code(&req(vec![])), ErrorCode::InvalidParameters);
    assert_eq!(
        f.fault_code(&req(vec![rev(777, 1)])),
        ErrorCode::InvalidParameters
    );
    // A revision that does not exist is unknown even if another revision of it does.
    assert_eq!(
        f.fault_code(&req(vec![rev(1, 9)])),
        ErrorCode::InvalidParameters
    );
    assert_eq!(
        f.fault_code(&req(vec![rev(1, 1), rev(2, 1), rev(3, 1), rev(4, 1)])),
        ErrorCode::InvalidParameters
    );
    assert!(f.call(&req(vec![rev(1, 1), rev(2, 1), rev(3, 1)])).is_ok());
}

#[test]
fn the_advertised_batch_limit_keeps_responses_under_the_byte_limit() {
    let f = fixture();
    let mut docs = vec![
        Doc::config(PRODUCT, "Category"),
        Doc::config(CLASSIFICATION, "Category"),
        Doc::config(DETECTOID, "Detectoid"),
    ];
    docs.extend((1..=3).map(|i| Doc::software(i, 1).padded(900_000)));
    f.publish(&docs);
    let c = f.cookie();
    let advertised = f.config_data(&c, None).max_number_of_updates_per_request;
    assert_eq!(advertised, 2, "2,000,000 / ~900,100 bytes");
    let s = f.server.summary().unwrap().unwrap();
    assert_eq!(s.advertised_batch_limit, 2);
    assert!(s.max_blob_bytes > 900_000);
    let ok = f.update_data(&c, &[rev(1, 1), rev(2, 1)]);
    let total: usize = ok
        .updates
        .value()
        .unwrap()
        .iter()
        .map(|u| u.xml_update_blob.value().unwrap().len())
        .sum();
    assert!(total <= 2_000_000);
    assert_eq!(
        f.fault_code(&GetUpdateData {
            cookie: Presence::Value(c),
            update_ids: Presence::Value(vec![rev(1, 1), rev(2, 1), rev(3, 1)]),
        }),
        ErrorCode::InvalidParameters
    );
}

#[test]
fn an_unsplittable_oversized_update_is_served_alone_and_the_limit_drops_to_one() {
    let f = fixture();
    f.publish(&[Doc::bare(1, 1).padded(2_100_000), Doc::bare(2, 1)]);
    let c = f.cookie();
    assert_eq!(f.config_data(&c, None).max_number_of_updates_per_request, 1);
    let r = f.update_data(&c, &[rev(1, 1)]);
    assert!(
        r.updates.value().unwrap()[0]
            .xml_update_blob
            .value()
            .unwrap()
            .len()
            > 2_000_000
    );
}

#[test]
fn update_data_is_still_served_after_a_refresh_replaced_the_active_generation() {
    let f = fixture();
    f.seed(2);
    let c = f.cookie();
    let listed = ids(&f.revision_list(&c, None, false));
    f.refresh(&[Doc::software(3, 1)]);
    f.refresh(&[Doc::software(4, 1)]);
    // Revisions listed before the refreshes are carried into the new generations and are
    // served from the active one; the lookup also falls back to superseded generations.
    assert_eq!(f.update_data(&c, &listed).updates.value().unwrap().len(), 2);
}

#[test]
fn revisions_that_only_an_older_generation_holds_are_found_in_superseded_generations() {
    let f = fixture();
    f.seed(2);
    let c = f.cookie();
    // The next generation drops update 2 entirely (a catalog rebuilt without it).
    f.publish(&[
        Doc::config(PRODUCT, "Category"),
        Doc::config(CLASSIFICATION, "Category"),
        Doc::config(DETECTOID, "Detectoid"),
        Doc::software(1, 1),
    ]);
    let r = f.update_data(&c, &[rev(2, 1)]);
    assert_eq!(r.updates.value().unwrap().len(), 1);
    // After pruning, it is gone.
    f.catalog.prune_superseded(f.source, 0).unwrap();
    assert_eq!(
        f.fault_code(&GetUpdateData {
            cookie: Presence::Value(c),
            update_ids: Presence::Value(vec![rev(2, 1)]),
        }),
        ErrorCode::InvalidParameters
    );
}

#[test]
fn file_urls_use_the_host_and_content_port_when_no_base_url_is_configured() {
    let cfg = UpstreamServerConfig {
        content_base_url: None,
        ..config().with_ports(8531, true)
    };
    assert_eq!(cfg.content_port, Some(8530));
    let f = fixture_with(cfg);
    f.publish(&[Doc::bare(1, 1).with_file("a.cab", b"x")]);
    let c = f.cookie();
    let r = f.update_data(&c, &[rev(1, 1)]);
    assert!(
        r.file_urls.value().unwrap()[0]
            .uss_url
            .value()
            .unwrap()
            .starts_with("http://uss.test:8530/Content/")
    );
}

// ---- DownloadFiles -----------------------------------------------------------------

fn download(c: &wsus_protocol::common::Cookie, digests: Vec<Vec<u8>>) -> DownloadFiles {
    DownloadFiles {
        cookie: Presence::Value(c.clone()),
        file_digest_list: Presence::Value(digests),
    }
}

#[test]
fn download_files_reports_unknown_digests_and_queues_missing_content() {
    let f = fixture();
    let have = b"present content";
    let lack = b"described but not downloaded";
    f.publish(&[Doc::bare(1, 1)
        .with_file("a.cab", have)
        .with_file("b.cab", lack)]);
    f.put_content("a.cab", have);
    let c = f.cookie();
    // Known digests succeed; only the one without content is queued.
    f.call(&download(&c, vec![sha1(have), sha1(lack)])).unwrap();
    assert_eq!(f.server.drain_download_requests(), vec![sha1(lack)]);
    assert!(f.server.drain_download_requests().is_empty());
    // Unknown digests: FileDigestsMissing, Message lists them (Base64) separated by `|`.
    let unknown = vec![9u8; 20];
    let other = vec![8u8; 20];
    let (code, msg) = f.fault(&download(
        &c,
        vec![sha1(have), unknown.clone(), other.clone()],
    ));
    assert_eq!(code, ErrorCode::FileDigestsMissing);
    let b = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
    assert_eq!(msg.unwrap(), format!("{}|{}", b(&unknown), b(&other)));
    // Nothing was queued by the failed call.
    assert!(f.server.drain_download_requests().is_empty());
}

#[test]
fn download_files_enforces_its_limits() {
    let f = fixture();
    f.seed(1);
    let c = f.cookie();
    let many: Vec<Vec<u8>> = (0..101u8).map(|i| vec![i; 20]).collect();
    assert_eq!(
        f.fault_code(&download(&c, many)),
        ErrorCode::InvalidParameters
    );
    assert_eq!(
        f.fault_code(&download(&c, vec![vec![1u8; 19]])),
        ErrorCode::InvalidParameters
    );
    // Exactly 100 unknown digests reach the digest check.
    let hundred: Vec<Vec<u8>> = (0..100u8).map(|i| vec![i; 20]).collect();
    assert_eq!(
        f.fault_code(&download(&c, hundred)),
        ErrorCode::FileDigestsMissing
    );
    assert!(f.call(&download(&c, vec![])).is_ok());
}

// ---- content path and ports --------------------------------------------------------

#[test]
fn content_is_served_on_the_server_server_path_and_surfaces_are_separable() {
    let f = fixture();
    let data = b"0123456789";
    f.publish(&[Doc::bare(1, 1).with_file("a.cab", data)]);
    f.put_content("a.cab", data);
    let hex: String = sha1(data).iter().map(|b| format!("{b:02x}")).collect();
    let path = format!("/Content/{}/{hex}", &hex[38..]);
    let get = |surface, extra: Option<(&str, &str)>| {
        let mut r = HttpRequestParts::new("GET", &path);
        if let Some((k, v)) = extra {
            r = r.with_header(k, v);
        }
        f.server.handle_on(surface, r)
    };
    let r = get(Surface::Content, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("Content-Length"), Some("10"));
    assert_eq!(r.into_bytes().unwrap(), data);
    let r = get(Surface::All, Some(("Range", "bytes=2-4")));
    assert_eq!(r.status, 206);
    assert_eq!(r.into_bytes().unwrap(), b"234");
    // Services-only listeners do not serve content; content-only listeners do not serve SOAP.
    assert_eq!(get(Surface::Services, None).status, 404);
    let soap = HttpRequestParts::new("POST", SYNC_PATH).with_header("Content-Type", "text/xml");
    assert_eq!(f.server.handle_on(Surface::Content, soap).status, 404);
    // Wrong folder and unknown digest.
    let wrong = format!("/Content/00/{hex}");
    assert_eq!(
        f.server.handle(HttpRequestParts::new("GET", &wrong)).status,
        404
    );
}

#[test]
fn content_port_follows_the_specified_server_server_rule() {
    assert_eq!(server_server_content_port(8530, false), Some(80));
    assert_eq!(server_server_content_port(80, false), Some(80));
    assert_eq!(server_server_content_port(443, true), Some(80));
    assert_eq!(server_server_content_port(8531, true), Some(8530));
    assert_eq!(server_server_content_port(1, true), None);
    assert_eq!(config().with_ports(443, true).content_port, Some(80));
}

#[test]
fn oversized_and_malformed_requests_are_protocol_faults() {
    let cfg = UpstreamServerConfig {
        max_request_bytes: 2048,
        ..config()
    };
    let f = fixture_with(cfg);
    let big = HttpRequestParts::new("POST", SYNC_PATH)
        .with_header("Content-Type", "text/xml")
        .with_body(vec![b' '; 4096]);
    assert_eq!(f.server.handle(big).status, 413);
    let bad = HttpRequestParts::new("POST", SYNC_PATH)
        .with_header("Content-Type", "text/xml")
        .with_body(b"<not-soap".to_vec());
    let (status, fault) = fault_envelope(f.server.handle(bad));
    assert_eq!(status, 500);
    assert!(fault.wsus.is_none());
    let wrong_type = HttpRequestParts::new("POST", SYNC_PATH)
        .with_header("Content-Type", "application/json")
        .with_body(b"{}".to_vec());
    assert_eq!(f.server.handle(wrong_type).status, 415);
}
