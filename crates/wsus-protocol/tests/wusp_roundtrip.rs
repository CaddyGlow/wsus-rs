mod common;

use common::*;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{Limits, Presence, SoapVersion, decode_response, validate_action};
use wsus_protocol::wusp::*;

fn cookie() -> Cookie {
    Cookie {
        expiration: dt("2024-05-06T10:20:30Z"),
        encrypted_data: some(vec![1, 2, 3, 4, 5]),
    }
}

fn auth_cookie() -> AuthorizationCookie {
    AuthorizationCookie {
        plug_in_id: s("SimpleTargeting"),
        cookie_data: some(vec![9, 8, 7]),
    }
}

fn rev(n: u8, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(guid(n)),
        revision: Revision(r),
    }
}

fn deployment() -> Deployment {
    Deployment {
        id: 42,
        action: DeploymentAction::Install,
        deadline: s("2024-06-01T00:00:00Z"),
        is_assigned: true,
        last_change_time: "2024-05-01T00:00:00".into(),
        download_priority: s("Normal"),
        hardware_ids: some(vec!["PCI\\VEN_8086".into()]),
        auto_select: Presence::Nil,
        auto_download: s(""),
        supersedence_behavior: Presence::Absent,
        flag_bitmask: s("0"),
        client_behaviors: some(vec![ClientMetadata {
            metadata_type: MetadataType::Audience,
            metadata: "<a/>".into(),
            verification: some(Verification {
                timestamp: dt("2024-05-01T00:00:00Z"),
                leaf_certificate_id: 7,
                signature: vec![1, 2, 3],
                algorithm: "RSA".into(),
            }),
        }]),
    }
}

#[test]
fn get_config_roundtrip() {
    roundtrip_pair(
        &GetConfig {
            protocol_version: s("1.8"),
        },
        &GetConfigResponse {
            result: some(Config {
                last_change: dt("2024-05-01T10:20:30.123Z"),
                is_registration_required: true,
                auth_info: some(vec![AuthPlugInInfo {
                    plug_in_id: s("SimpleTargeting"),
                    service_url: s("SimpleAuthWebService/SimpleAuth.asmx"),
                    parameter: Presence::Nil,
                }]),
                allowed_event_ids: some(vec![]),
                properties: some(vec![ConfigurationProperty {
                    name: s("MaxExtendedUpdatesPerRequest"),
                    value: s("50"),
                }]),
            }),
        },
    );
}

#[test]
fn get_authorization_cookie_roundtrip() {
    roundtrip_pair(
        &GetAuthorizationCookie {
            client_id: s("client-1"),
            target_group_name: s("Unassigned Computers"),
            dns_name: s("pc.example.test"),
        },
        &GetAuthorizationCookieResponse {
            result: some(auth_cookie()),
        },
    );
}

#[test]
fn get_cookie_roundtrip() {
    roundtrip_pair(
        &GetCookie {
            auth_cookies: some(vec![auth_cookie()]),
            old_cookie: Presence::Nil,
            last_change: dt("2024-05-01T10:20:30.123Z"),
            current_time: dt("2024-05-01T10:25:00+02:00"),
            protocol_version: s("1.8"),
        },
        &GetCookieResponse {
            result: some(cookie()),
        },
    );
}

#[test]
fn register_computer_roundtrip() {
    let info = ComputerInfo {
        dns_name: s("pc.example.test"),
        os_major_version: 10,
        os_minor_version: 0,
        os_build_number: 26100,
        os_service_pack_major_number: 0,
        os_service_pack_minor_number: 0,
        os_locale: s("en-US"),
        computer_manufacturer: s("Contoso"),
        computer_model: Presence::Absent,
        bios_version: s("1.0"),
        bios_name: Presence::Nil,
        bios_release_date: dt("2023-01-01T00:00:00"),
        processor_architecture: s("9"),
        suite_mask: 272,
        old_product_type: 1,
        new_product_type: 48,
        system_metrics: 0,
        client_version_major_number: 10,
        client_version_minor_number: 0,
        client_version_build_number: 26100,
        client_version_qfe_number: 1,
        os_description: Presence::Absent,
        oem: Presence::Absent,
        device_type: Presence::Absent,
        firmware_version: Presence::Absent,
        mobile_operator: Presence::Absent,
    };
    roundtrip_pair(
        &RegisterComputer {
            cookie: some(cookie()),
            computer_info: some(info),
        },
        &RegisterComputerResponse {},
    );
}

#[test]
fn sync_updates_roundtrip_with_continuation_and_cache() {
    let params = SyncUpdateParameters {
        express_query: false,
        installed_non_leaf_update_ids: some(vec![1, 2, 3]),
        other_cached_update_ids: some(vec![]),
        system_spec: some(vec![Device {
            hardware_ids: some(vec!["PCI\\VEN_1".into(), "PCI\\VEN_1&DEV_2".into()]),
            compatible_ids: Presence::Absent,
            installed_driver: some(InstalledDriver {
                matching_id: s("PCI\\VEN_1"),
                driver_ver_date: dt("2020-01-01T00:00:00Z"),
                driver_ver_version: 281474976710656,
                class: s("Net"),
                manufacturer: s("M"),
                provider: s("P"),
                model: s("Mod"),
                matching_computer_hwid: Presence::Nil,
                driver_rank: 3,
            }),
            extension_driver: some(vec![ExtensionDriver {
                extension_id: "ext".into(),
                driver_ver_date: dt("2021-01-01T00:00:00Z"),
                driver_ver_version: 5,
                class: "Ext".into(),
                driver_rank: 1,
                matching_computer_hwid: some(guid(3)),
            }]),
            driver_recovery_ids: some(vec!["r1".into()]),
            device_flags: some(2),
        }]),
        cached_driver_ids: some(vec![10]),
        skip_software_sync: true,
        filter_category_ids: some(vec![CategoryIdentifier { id: guid(4) }]),
        need_two_group_out_of_scope_updates: some(true),
        computer_spec: some(ComputerHardwareSpecification {
            hardware_ids: some(vec![guid(5), guid(6)]),
        }),
        feature_score_matching_key: s("key"),
    };
    let resp = SyncUpdatesResponse {
        result: some(SyncInfo {
            new_updates: some(vec![
                UpdateInfo {
                    id: 100,
                    deployment: some(deployment()),
                    is_leaf: true,
                    xml: s("<Update>&amp; text</Update>"),
                },
                UpdateInfo {
                    id: 101,
                    deployment: Presence::Absent,
                    is_leaf: false,
                    xml: Presence::Absent,
                },
            ]),
            out_of_scope_revision_ids: some(vec![5, 6]),
            changed_updates: some(vec![]),
            truncated: true,
            new_cookie: some(cookie()),
            deployed_out_of_scope_revision_ids: Presence::Absent,
            driver_sync_not_needed: s("true"),
        }),
    };
    roundtrip_pair(
        &SyncUpdates {
            cookie: some(cookie()),
            parameters: some(params),
        },
        &resp,
    );
}

#[test]
fn refresh_cache_roundtrip() {
    roundtrip_pair(
        &RefreshCache {
            cookie: some(cookie()),
            global_ids: some(vec![rev(1, 2), rev(3, 0)]),
        },
        &RefreshCacheResponse {
            result: some(vec![RefreshCacheResult {
                revision_id: 9,
                global_id: some(rev(1, 2)),
                is_leaf: true,
                deployment: some(deployment()),
            }]),
        },
    );
}

fn file_location() -> FileLocation {
    FileLocation {
        file_digest: some(vec![0xAA; 20]),
        url: s("http://wsus.example.test:8530/Content/AA/file.cab"),
        pieces_hash_url: Presence::Absent,
        block_map_url: Presence::Nil,
        decryption_information: Presence::Absent,
        file_digest_algorithm: s("SHA1"),
        encrypted_file_digest: Presence::Absent,
        encrypted_file_digest_algorithm: Presence::Absent,
    }
}

#[test]
fn get_extended_update_info_roundtrip() {
    roundtrip_pair(
        &GetExtendedUpdateInfo {
            cookie: some(cookie()),
            revision_ids: some(vec![100, 101]),
            info_types: some(vec![
                XmlUpdateFragmentType::Extended,
                XmlUpdateFragmentType::FileUrl,
                XmlUpdateFragmentType::Unknown("Future".into()),
            ]),
            locales: some(vec!["en".into()]),
            geo_id: s("244"),
            caller_attributes: Presence::Absent,
        },
        &GetExtendedUpdateInfoResponse {
            result: some(ExtendedUpdateInfo {
                updates: some(vec![UpdateData {
                    id: 100,
                    xml: s("<Update/>"),
                }]),
                file_locations: some(vec![file_location()]),
                out_of_scope_revision_ids: some(vec![7]),
            }),
        },
    );
}

#[test]
fn get_extended_update_info2_roundtrip() {
    let dec = FileDecryption {
        file_digest: some(vec![1; 20]),
        decryption_key: some(vec![2; 16]),
        security_data: some(vec![vec![3, 4], vec![5]]),
    };
    roundtrip_pair(
        &GetExtendedUpdateInfo2 {
            cookie: some(cookie()),
            update_ids: some(vec![rev(1, 1)]),
            info_types: some(vec![XmlUpdateFragmentType::FileDecryption]),
            locales: Presence::Absent,
            caller_attributes: s("attrs"),
        },
        &GetExtendedUpdateInfo2Response {
            result: some(ExtendedUpdateInfo2 {
                updates: Presence::Absent,
                file_locations: some(vec![file_location()]),
                file_decryption_data: some(vec![dec.clone()]),
                file_decryption_data2: some(vec![FileDecryption2(dec)]),
                update_encryption_details: some(vec![UpdateEncryptionDetail {
                    update_identity: rev(1, 1),
                    has_encrypted_files: true,
                }]),
            }),
        },
    );
}

#[test]
fn get_file_locations_roundtrip() {
    roundtrip_pair(
        &GetFileLocations {
            cookie: some(cookie()),
            file_digests: some(vec![vec![0xAA; 20], vec![0xBB; 20]]),
        },
        &GetFileLocationsResponse {
            result: some(GetFileLocationsResults {
                file_locations: some(vec![file_location()]),
                new_cookie: some(cookie()),
            }),
        },
    );
}

#[test]
fn report_event_batch_roundtrip() {
    let ev = ReportingEvent {
        basic_data: some(BasicData {
            target_id: some(ComputerTargetIdentifier {
                sid: s("S-1-5-21-1"),
            }),
            sequence_number: 3,
            time_at_target: dt("2024-05-01T10:00:00Z"),
            event_instance_id: guid(8),
            namespace_id: 2,
            event_id: 147,
            source_id: 301,
            update_id: some(rev(1, 3)),
            win32_hresult: -2145124329,
            app_name: s("AutomaticUpdates"),
        }),
        extended_data: some(ExtendedData {
            replacement_strings: some(vec!["a".into(), "b".into()]),
            misc_data: Presence::Absent,
            computer_brand: s("Contoso"),
            computer_model: Presence::Absent,
            bios_revision: Presence::Absent,
            processor_architecture: ProcessorArchitecture::Amd64Compatible,
            os_version: DetailedVersion {
                major: 10,
                minor: 0,
                build: 26100,
                revision: 1,
                service_pack_major: 0,
                service_pack_minor: 0,
            },
            os_locale_id: 1033,
            device_id: Presence::Absent,
        }),
        private_data: some(PrivateData {
            computer_dns_name: s("pc.example.test"),
            user_account_name: Presence::Nil,
        }),
    };
    roundtrip_pair(
        &ReportEventBatch {
            cookie: some(cookie()),
            client_time: dt("2024-05-01T10:30:00Z"),
            event_batch: some(vec![ev]),
        },
        &ReportEventBatchResponse { result: true },
    );
}

#[test]
fn spec_derived_fixture_get_config_response_decodes() {
    let r: GetConfigResponse = decode_response(
        &fixture("wusp_getconfig_response_soap11.xml"),
        &Limits::default(),
    )
    .unwrap();
    let c = r.result.value().unwrap();
    assert!(!c.is_registration_required);
    assert_eq!(c.last_change.as_str(), "2024-05-01T10:20:30.123Z");
    assert_eq!(c.allowed_event_ids.value().unwrap(), &vec![10, 11]);
    assert_eq!(
        c.auth_info.value().unwrap()[0].plug_in_id.value().unwrap(),
        "SimpleTargeting"
    );
}

#[test]
fn alternate_prefixes_decode_identically() {
    let r: GetConfigResponse = decode_response(
        &fixture("wusp_getconfig_response_alt_prefix.xml"),
        &Limits::default(),
    )
    .unwrap();
    let c = r.result.value().unwrap();
    assert!(c.is_registration_required); // "1" is a valid xs:boolean
    assert_eq!(c.allowed_event_ids.value().unwrap(), &vec![7]);
    assert!(c.auth_info.is_absent());
}

#[test]
fn nil_empty_and_absent_are_distinguished() {
    let req: GetCookie = wsus_protocol::soap::decode_request(
        None,
        &fixture("wusp_getcookie_request_soap12.xml"),
        &Limits::default(),
    )
    .unwrap()
    .1;
    assert!(req.old_cookie.is_nil());
    assert_eq!(req.protocol_version, Presence::Value(String::new()));
    assert!(req.auth_cookies.is_value());

    let req: GetFileLocations = wsus_protocol::soap::decode_request(
        None,
        &fixture("wusp_nil_empty_absent.xml"),
        &Limits::default(),
    )
    .unwrap()
    .1;
    assert!(req.cookie.is_nil());
    assert_eq!(req.file_digests, Presence::Value(vec![]));
    // Re-encoding preserves all three states.
    let enc = wsus_protocol::soap::encode_request(SoapVersion::V11, &req);
    let text = String::from_utf8(enc.body).unwrap();
    assert!(text.contains("xsi:nil=\"true\""));
    assert!(text.contains("<fileDigests/>"));
}

#[test]
fn soap_encoded_arrays_are_accepted() {
    let r: SyncUpdatesResponse = decode_response(
        &fixture("wusp_syncupdates_response_encoded_array.xml"),
        &Limits::default(),
    )
    .unwrap();
    let info = r.result.value().unwrap();
    assert_eq!(info.out_of_scope_revision_ids.value().unwrap(), &vec![5, 6]);
    assert!(info.truncated);
    assert!(info.new_updates.is_absent());
}

#[test]
fn cookie_children_in_other_wsus_namespace_are_accepted() {
    let r: GetCookieResponse = decode_response(
        &fixture("wusp_cookie_alt_namespace_children.xml"),
        &Limits::default(),
    )
    .unwrap();
    let c = r.result.value().unwrap();
    assert_eq!(c.expiration.as_str(), "2024-05-06T10:20:30Z");
    assert_eq!(c.encrypted_data.value().unwrap(), &vec![0, 1, 2]);
}

#[test]
fn out_of_order_sequence_is_rejected_unless_relaxed() {
    let xml = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
        <GetConfigResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><GetConfigResult>
        <IsRegistrationRequired>true</IsRegistrationRequired><LastChange>2024-05-01T10:20:30Z</LastChange>
        </GetConfigResult></GetConfigResponse></soap:Body></soap:Envelope>"#;
    let err = decode_response::<GetConfigResponse>(xml, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, wsus_protocol::ProtocolError::OutOfOrder { .. }),
        "{err:?}"
    );
    let relaxed = Limits {
        strict_sequence_order: false,
        ..Limits::default()
    };
    assert!(decode_response::<GetConfigResponse>(xml, &relaxed).is_ok());
}

#[test]
fn missing_required_element_is_reported() {
    let xml = br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
        <GetConfigResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><GetConfigResult>
        <LastChange>2024-05-01T10:20:30Z</LastChange>
        </GetConfigResult></GetConfigResponse></soap:Body></soap:Envelope>"#;
    let err = decode_response::<GetConfigResponse>(xml, &Limits::default()).unwrap_err();
    assert_eq!(
        err,
        wsus_protocol::ProtocolError::MissingElement("IsRegistrationRequired".into())
    );
}

#[test]
fn invalid_scalars_are_rejected() {
    for bad in ["not-a-date", "2024-13", "2024-05-01"] {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
            <GetConfigResponse xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><GetConfigResult>
            <LastChange>{bad}</LastChange><IsRegistrationRequired>true</IsRegistrationRequired>
            </GetConfigResult></GetConfigResponse></soap:Body></soap:Envelope>"#
        );
        let err =
            decode_response::<GetConfigResponse>(xml.as_bytes(), &Limits::default()).unwrap_err();
        assert!(
            matches!(err, wsus_protocol::ProtocolError::InvalidValue { .. }),
            "{bad}: {err:?}"
        );
    }
}

#[test]
fn actions_follow_namespace_and_operation() {
    use wsus_protocol::soap::SoapRequest;
    assert_eq!(
        GetConfig::action(),
        "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"
    );
    assert_eq!(
        GetAuthorizationCookie::action(),
        "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"
    );
    assert_eq!(
        ReportEventBatch::action(),
        "http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"
    );
    let e = wsus_protocol::soap::encode_request(SoapVersion::V11, &GetConfig::default_for_test());
    assert_eq!(
        e.soap_action.as_deref(),
        Some("\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig\"")
    );
    let q = wsus_protocol::soap::xml::QName::new(CLIENT_NS, "GetConfig");
    assert!(validate_action(Some("\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig\""), &q).is_ok());
    assert!(
        validate_action(
            Some("http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"),
            &q
        )
        .is_err()
    );
    assert!(validate_action(None, &q).is_ok());
}

trait DefaultForTest {
    fn default_for_test() -> Self;
}
impl DefaultForTest for GetConfig {
    fn default_for_test() -> Self {
        GetConfig {
            protocol_version: Presence::Absent,
        }
    }
}
