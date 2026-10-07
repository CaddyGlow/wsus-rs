mod common;

use common::*;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{Limits, Presence, SoapRequest};
use wsus_protocol::soap::{SoapVersion, decode_response, encode_response};
use wsus_protocol::wsusss::*;

fn cookie() -> Cookie {
    Cookie {
        expiration: dt("2024-05-06T10:20:30Z"),
        encrypted_data: some(vec![1, 2, 3]),
    }
}

fn rev(n: u8, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(guid(n)),
        revision: Revision(r),
    }
}

#[test]
fn actions() {
    assert_eq!(
        GetRevisionIdList::action(),
        "http://www.microsoft.com/SoftwareDistribution/GetRevisionIdList"
    );
    assert_eq!(
        GetAuthorizationCookie::action(),
        "http://www.microsoft.com/SoftwareDistribution/Server/DssAuthWebService/GetAuthorizationCookie"
    );
}

#[test]
fn get_auth_config_roundtrip() {
    roundtrip_pair(
        &GetAuthConfig {},
        &GetAuthConfigResponse {
            result: some(ServerAuthConfig {
                last_change: dt("2024-05-01T00:00:00Z"),
                auth_info: some(vec![AuthPlugInInfo {
                    plug_in_id: s("DssTargeting"),
                    service_url: s("DssAuthWebService/DssAuthWebService.asmx"),
                    parameter: Presence::Absent,
                }]),
                allowed_event_ids: Presence::Absent,
            }),
        },
    );
}

#[test]
fn dss_get_authorization_cookie_roundtrip() {
    roundtrip_pair(
        &GetAuthorizationCookie {
            account_name: s("DOMAIN\\dss$"),
            account_guid: s("6e8d0c3a-3f1e-4b66-9d3e-0a1b2c3d4e5f"),
            program_keys: some(vec![guid(1), guid(2)]),
        },
        &GetAuthorizationCookieResponse {
            result: some(AuthorizationCookie {
                plug_in_id: s("DssTargeting"),
                cookie_data: some(vec![4, 5]),
            }),
        },
    );
}

#[test]
fn get_cookie_roundtrip() {
    roundtrip_pair(
        &GetCookie {
            auth_cookies: some(vec![AuthorizationCookie {
                plug_in_id: s("x"),
                cookie_data: Presence::Nil,
            }]),
            old_cookie: Presence::Absent,
            protocol_version: s("1.3"),
        },
        &GetCookieResponse {
            result: some(cookie()),
        },
    );
}

#[test]
fn get_config_data_roundtrip() {
    roundtrip_pair(
        &GetConfigData {
            cookie: some(cookie()),
            config_anchor: Presence::Nil,
        },
        &GetConfigDataResponse {
            result: some(ServerSyncConfigData {
                catalog_only_sync: false,
                lazy_sync: true,
                server_hosts_psf_files: false,
                max_number_of_computer_ids_in_request: 10,
                max_number_of_driver_sets_per_request: 20,
                max_number_of_pnp_hardware_ids_in_request: 30,
                max_number_of_updates_per_request: 100,
                new_config_anchor: s("anchor-1"),
                protocol_version: s("1.3"),
                language_update_list: some(vec![ServerSyncLanguageData {
                    language_id: 1033,
                    short_language: s("en"),
                    long_language: s("English"),
                    enabled: true,
                }]),
                max_updates_per_request_in_get_update_decryption_data: 50,
            }),
        },
    );
}

#[test]
fn get_revision_id_list_roundtrip() {
    let filter = ServerSyncFilter {
        dss_protocol_version: Presence::Absent,
        anchor: Presence::Absent,
        get_config: false,
        get63_language_only: some(true),
        categories: some(vec![IdAndDelta {
            id: guid(1),
            delta: false,
        }]),
        classifications: some(vec![IdAndDelta {
            id: guid(2),
            delta: true,
        }]),
        languages: some(vec![LanguageAndDelta {
            id: 1033,
            delta: false,
        }]),
    };
    roundtrip_pair(
        &GetRevisionIdList {
            cookie: some(cookie()),
            filter: some(filter),
        },
        &GetRevisionIdListResponse {
            result: some(RevisionIdList {
                anchor: s("a2"),
                new_revisions: some(vec![rev(1, 1), rev(2, 7)]),
            }),
        },
    );
}

#[test]
fn get_update_data_roundtrip_text_and_compressed() {
    roundtrip_pair(
        &GetUpdateData {
            cookie: some(cookie()),
            update_ids: some(vec![rev(1, 1)]),
        },
        &GetUpdateDataResponse {
            result: some(ServerUpdateData {
                updates: some(vec![
                    ServerSyncUpdateData {
                        id: some(rev(1, 1)),
                        xml_update_blob: s("<Update xmlns=\"x\">&amp;</Update>"),
                        file_digest_list: some(vec![vec![0xAA; 20]]),
                        xml_update_blob_compressed: Presence::Absent,
                    },
                    ServerSyncUpdateData {
                        id: some(rev(2, 1)),
                        xml_update_blob: Presence::Absent,
                        file_digest_list: Presence::Absent,
                        xml_update_blob_compressed: some(vec![0x4D, 0x53, 0x43, 0x46]),
                    },
                ]),
                file_urls: some(vec![ServerSyncUrlData {
                    file_digest: some(vec![0xAA; 20]),
                    mu_url: s("http://download.example.test/a.cab"),
                    uss_url: Presence::Absent,
                    decryption_key: Presence::Nil,
                }]),
            }),
        },
    );
}

#[test]
fn get_update_decryption_data_roundtrip() {
    roundtrip_pair(
        &GetUpdateDecryptionData {
            cookie: some(cookie()),
            update_ids: some(vec![rev(3, 2)]),
        },
        &GetUpdateDecryptionDataResponse {
            result: some(ServerDecryptionData {
                update_file_decryption_data: some(vec![ServerSyncUpdateFileDecryption {
                    update_id: some(rev(3, 2)),
                    file_decryption_data: some(vec![ServerSyncFileDecryption {
                        file_digest: some(vec![1; 20]),
                        decryption_key: some(vec![2; 16]),
                    }]),
                }]),
            }),
        },
    );
}

#[test]
fn download_files_roundtrip() {
    roundtrip_pair(
        &DownloadFiles {
            cookie: some(cookie()),
            file_digest_list: some(vec![vec![0xAB; 20]]),
        },
        &DownloadFilesResponse {},
    );
}

#[test]
fn get_deployments_roundtrip() {
    roundtrip_pair(
        &GetDeployments {
            cookie: some(cookie()),
            deployment_anchor: s("d1"),
            sync_anchor: s("s1"),
        },
        &GetDeploymentsResponse {
            result: some(ServerSyncDeploymentResult {
                anchor: s("d2"),
                groups: some(vec![ServerSyncTargetGroup {
                    target_group_id: guid(1),
                    parent_group_id: guid(2),
                    name: s("All Computers"),
                    is_builtin: true,
                }]),
                deployments: some(vec![ServerSyncDeployment {
                    update_id: guid(3),
                    revision_number: 4,
                    action: 0,
                    admin_name: s("admin"),
                    deadline: dt("9999-12-31T23:59:59Z"),
                    is_assigned: false,
                    go_live_time: dt("2024-05-01T00:00:00Z"),
                    deployment_guid: guid(5),
                    target_group_id: guid(1),
                    download_priority: 2,
                }]),
                dead_deployments: some(vec![guid(6)]),
                hidden_updates: some(vec![]),
                accepted_eulas: Presence::Absent,
            }),
        },
    );
}

#[test]
fn get_related_revisions_roundtrip() {
    roundtrip_pair(
        &GetRelatedRevisionsForUpdates {
            cookie: some(cookie()),
            update_ids: some(vec![guid(1), guid(2)]),
        },
        &GetRelatedRevisionsForUpdatesResponse {
            result: some(vec![rev(1, 1), rev(1, 2)]),
        },
    );
}

#[test]
fn empty_get_auth_config_has_no_children() {
    let enc = encode_response(SoapVersion::V11, &GetAuthConfig {});
    let text = String::from_utf8(enc.body).unwrap();
    assert!(
        text.contains("<GetAuthConfig xmlns=\"http://www.microsoft.com/SoftwareDistribution\"/>"),
        "{text}"
    );
    let _ = decode_response::<GetAuthConfig>(text.as_bytes(), &Limits::default()).unwrap();
}

#[test]
fn microsoft_public_config_sequence_decodes_without_relaxing_duplicate_checks() {
    let bytes = include_bytes!("fixtures/microsoft_sync_config_20261006.xml");
    let envelope = decode_response::<GetConfigDataResponse>(bytes, &Limits::default()).unwrap();
    let value = envelope.result.into_value().unwrap();
    assert_eq!(value.max_number_of_updates_per_request, 100);
    assert!(value.catalog_only_sync);
    let duplicate = String::from_utf8(bytes.to_vec()).unwrap().replace(
        "</GetConfigDataResult>",
        "<MaxNumberOfUpdatesPerRequest>100</MaxNumberOfUpdatesPerRequest></GetConfigDataResult>",
    );
    assert!(
        decode_response::<GetConfigDataResponse>(duplicate.as_bytes(), &Limits::default()).is_err()
    );
}
