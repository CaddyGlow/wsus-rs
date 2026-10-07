//! MS-WSUSSS client tests against a fake upstream written here.
//!
//! Nothing here is validated against a real WSUS server: the fake encodes the
//! same reading of the specification as the client.
mod common;

use common::{block_on, expected_for, sample};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use wsus_client::{
    download::{DownloadLimits, DownloadOptions, Downloader, Location},
    transport::{
        ErrorKind, HttpRequest, HttpResponse, ImmediateTimer, Method, Phase, RetryPolicy,
        TransportError,
        mock::{MockStep, MockTransport},
    },
    wsusss::{
        Clock, DecompressError, MetadataDecompressor, RevisionQuery, WsusssClient, WsusssConfig,
        WsusssError,
    },
};
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{Body, SoapMessage};
use wsus_protocol::soap::{
    Envelope, ErrorCode, Limits, Presence, SoapFault, SoapVersion, decode_payload, encode_fault,
    encode_response,
};
use wsus_protocol::wsusss::*;

const BASE: &str = "http://upstream.test:8530";

fn dt(unix: i64) -> wsus_protocol::soap::XsDateTime {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    wsus_protocol::soap::XsDateTime::new(&format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    ))
    .unwrap()
}

fn rev(n: u128, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(uuid::Uuid::from_u128(n)),
        revision: Revision(r),
    }
}

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct State {
    ops: Vec<String>,
    /// Faults to answer the next calls of the named operation with.
    faults: VecDeque<(String, ErrorCode, Option<String>)>,
    cookie_serial: u32,
    auth_serial: u32,
    /// Responses for GetUpdateData larger than this many ids fail as too large.
    compressed: bool,
    max_ids: usize,
    max_updates_limit: i32,
    content_missing_until_download_files: bool,
    download_files_called: bool,
    content: Vec<u8>,
}

struct Fake {
    state: Mutex<State>,
    clock: Arc<TestClock>,
}

impl Fake {
    fn new(clock: Arc<TestClock>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                max_ids: usize::MAX,
                max_updates_limit: 100,
                ..State::default()
            }),
            clock,
        })
    }

    fn ops(&self) -> Vec<String> {
        self.state.lock().unwrap().ops.clone()
    }

    fn count(&self, op: &str) -> usize {
        self.ops().iter().filter(|o| *o == op).count()
    }

    fn fault(&self, op: &str, code: ErrorCode, message: Option<&str>) {
        self.state
            .lock()
            .unwrap()
            .faults
            .push_back((op.into(), code, message.map(str::to_owned)));
    }

    fn respond<M: SoapMessage>(&self, m: &M) -> MockStep {
        let enc = encode_response(SoapVersion::V11, m);
        MockStep::Respond(HttpResponse::new(200, enc.body))
    }

    fn handle(&self, req: &HttpRequest) -> MockStep {
        if req.method == Method::Get {
            return self.content(req);
        }
        let limits = Limits::default();
        let env = Envelope::decode(&req.body, &limits).expect("envelope");
        let Body::Payload(p) = env.body else {
            panic!("fault request")
        };
        let op = p.name.local.clone();
        let mut st = self.state.lock().unwrap();
        st.ops.push(op.clone());
        if let Some(pos) = st.faults.iter().position(|(o, _, _)| *o == op) {
            let (_, code, message) = st.faults.remove(pos).unwrap();
            let f = SoapFault::application(
                SoapVersion::V11,
                code,
                "fault",
                message.as_deref(),
                None,
                Some(&op),
            );
            return MockStep::Respond(HttpResponse::new(500, encode_fault(&f).body));
        }
        let now = self.clock.now_unix();
        match op.as_str() {
            "GetAuthConfig" => self.respond(&GetAuthConfigResponse {
                result: Presence::Value(ServerAuthConfig {
                    last_change: dt(now),
                    auth_info: Presence::Value(vec![AuthPlugInInfo {
                        plug_in_id: "DssTargeting".into(),
                        service_url: "DssAuthWebService/DssAuthWebService.asmx".into(),
                        parameter: Presence::Absent,
                    }]),
                    allowed_event_ids: Presence::Absent,
                }),
            }),
            "GetAuthorizationCookie" => {
                assert!(
                    req.url
                        .expose()
                        .ends_with("/DssAuthWebService/DssAuthWebService.asmx"),
                    "auth URL resolved against the base"
                );
                st.auth_serial += 1;
                self.respond(&GetAuthorizationCookieResponse {
                    result: Presence::Value(AuthorizationCookie {
                        plug_in_id: "DssTargeting".into(),
                        cookie_data: Presence::Value(vec![st.auth_serial as u8]),
                    }),
                })
            }
            "GetCookie" => {
                st.cookie_serial += 1;
                self.respond(&GetCookieResponse {
                    result: Presence::Value(Cookie {
                        expiration: dt(now + 3600),
                        encrypted_data: Presence::Value(vec![st.cookie_serial as u8]),
                    }),
                })
            }
            "GetConfigData" => self.respond(&GetConfigDataResponse {
                result: Presence::Value(ServerSyncConfigData {
                    catalog_only_sync: false,
                    lazy_sync: false,
                    server_hosts_psf_files: false,
                    max_number_of_computer_ids_in_request: 1,
                    max_number_of_driver_sets_per_request: 1,
                    max_number_of_pnp_hardware_ids_in_request: 1,
                    max_number_of_updates_per_request: st.max_updates_limit,
                    new_config_anchor: "cfg-1".into(),
                    protocol_version: "1.20".into(),
                    language_update_list: Presence::Absent,
                    max_updates_per_request_in_get_update_decryption_data: 1,
                }),
            }),
            "GetRevisionIdList" => {
                let r = decode_payload::<GetRevisionIdList>(&p, &limits).unwrap();
                let filter = r.filter.value().unwrap();
                let anchor = filter.anchor.value().cloned();
                self.respond(&GetRevisionIdListResponse {
                    result: Presence::Value(RevisionIdList {
                        anchor: Presence::Value(format!(
                            "{}>{}",
                            anchor.unwrap_or_default(),
                            filter.get_config
                        )),
                        new_revisions: Presence::Value(vec![rev(1, 1), rev(2, 1)]),
                    }),
                })
            }
            "GetUpdateData" => {
                let r = decode_payload::<GetUpdateData>(&p, &limits).unwrap();
                let ids = r.update_ids.value().unwrap().clone();
                if ids.len() > st.max_ids {
                    return MockStep::Fail(TransportError::new(
                        ErrorKind::TooLarge,
                        Phase::MaybeSent,
                        "too large",
                    ));
                }
                let updates = ids
                    .iter()
                    .map(|id| {
                        let xml = format!(
                            "<Update><UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"{}\"/>\
                             <Properties UpdateType=\"Software\"/></Update>",
                            id.id.0.hyphenated(),
                            id.revision.0
                        );
                        let (blob, compressed) = if st.compressed {
                            let mut b = xml.clone().into_bytes();
                            b.reverse();
                            (Presence::Absent, Presence::Value(b))
                        } else {
                            (Presence::Value(xml), Presence::Absent)
                        };
                        ServerSyncUpdateData {
                            id: Presence::Value(*id),
                            xml_update_blob: blob,
                            file_digest_list: Presence::Absent,
                            xml_update_blob_compressed: compressed,
                        }
                    })
                    .collect();
                self.respond(&GetUpdateDataResponse {
                    result: Presence::Value(ServerUpdateData {
                        updates: Presence::Value(updates),
                        file_urls: Presence::Value(vec![ServerSyncUrlData {
                            file_digest: Presence::Value(vec![9; 20]),
                            mu_url: Presence::Value("https://mu.test/f?sig=SIGNEDSECRET".into()),
                            uss_url: Presence::Absent,
                            decryption_key: Presence::Absent,
                        }]),
                    }),
                })
            }
            "DownloadFiles" => {
                st.download_files_called = true;
                self.respond(&DownloadFilesResponse {})
            }
            other => panic!("unexpected operation {other}"),
        }
    }

    fn content(&self, req: &HttpRequest) -> MockStep {
        let st = self.state.lock().unwrap();
        if st.content_missing_until_download_files && !st.download_files_called {
            return MockStep::Respond(HttpResponse::new(404, Vec::new()));
        }
        MockStep::Respond(HttpResponse::new(200, st.content.clone()))
            .tap_url(req.url.expose().to_owned())
    }
}

trait Tap {
    fn tap_url(self, url: String) -> Self;
}
impl Tap for MockStep {
    fn tap_url(self, _url: String) -> Self {
        self
    }
}

fn client(
    fake: &Arc<Fake>,
    config: WsusssConfig,
) -> (WsusssClient<MockTransport, ImmediateTimer>, MockTransport) {
    let f = Arc::clone(fake);
    let transport = MockTransport::with_handler(move |r| f.handle(r));
    let client =
        WsusssClient::new(config, transport.clone(), ImmediateTimer).with_clock(fake.clock.clone());
    (client, transport)
}

fn config() -> WsusssConfig {
    let mut c = WsusssConfig::new(BASE, "DOMAIN\\dss$", "6e8d0c3a-3f1e-4b66-9d3e-0a1b2c3d4e5f");
    c.retry = RetryPolicy::none();
    c.busy_delay = Duration::ZERO;
    c
}

fn setup() -> (
    Arc<Fake>,
    WsusssClient<MockTransport, ImmediateTimer>,
    MockTransport,
) {
    let clock = Arc::new(TestClock(AtomicI64::new(1_800_000_000)));
    let fake = Fake::new(clock);
    let (c, t) = client(&fake, config());
    (fake, c, t)
}

#[test]
fn handshake_then_metadata_calls_use_one_session() {
    let (fake, mut c, transport) = setup();
    block_on(async {
        let cfg = c.get_config_data(None).await.unwrap();
        assert_eq!(cfg.max_number_of_updates_per_request, 100);
        let list = c
            .get_revision_ids(&RevisionQuery {
                anchor: Some("a".into()),
                get_config: true,
                ..RevisionQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(list.anchor.as_deref(), Some("a>true"));
        assert_eq!(list.revisions, vec![rev(1, 1), rev(2, 1)]);
        let batch = c.get_update_data(&list.revisions).await.unwrap();
        assert_eq!(batch.updates.len(), 2);
        assert_eq!(batch.updates[0].identity, rev(1, 1));
    });
    assert_eq!(
        fake.ops(),
        [
            "GetAuthConfig",
            "GetAuthorizationCookie",
            "GetCookie",
            "GetConfigData",
            "GetRevisionIdList",
            "GetUpdateData"
        ]
    );
    let requests = transport.requests();
    assert_eq!(
        requests[3].headers.get("soapaction"),
        Some("\"http://www.microsoft.com/SoftwareDistribution/GetConfigData\"")
    );
}

#[test]
fn update_data_respects_count_limit_and_shrinks_on_oversize_responses() {
    let (fake, mut c, _t) = setup();
    fake.state.lock().unwrap().max_updates_limit = 4;
    block_on(async {
        c.get_config_data(None).await.unwrap();
        let ids: Vec<_> = (1..=5).map(|n| rev(n, 1)).collect();
        assert!(matches!(
            c.get_update_data(&ids).await,
            Err(WsusssError::Limit(_))
        ));
        assert_eq!(c.update_batch_size(), 4);
        // The upstream's transport cannot carry four metadata documents at
        // once: the client splits the request and remembers.
        fake.state.lock().unwrap().max_ids = 2;
        let batch = c.get_update_data(&ids[..4]).await.unwrap();
        assert_eq!(
            batch.updates.iter().map(|u| u.identity).collect::<Vec<_>>(),
            ids[..4]
        );
        assert_eq!(c.update_batch_size(), 2);
    });
    assert_eq!(
        fake.count("GetUpdateData"),
        3,
        "1 oversize attempt + 2 halves"
    );
}

struct Reverse;
impl MetadataDecompressor for Reverse {
    fn decompress(&self, compressed: &[u8]) -> Result<Vec<u8>, DecompressError> {
        let mut v = compressed.to_vec();
        v.reverse();
        Ok(v)
    }
}

#[test]
fn compressed_metadata_goes_through_the_injected_hook() {
    let (fake, c, _t) = setup();
    fake.state.lock().unwrap().compressed = true;
    // The default hook reads the observed Cabinet form and refuses anything else honestly.
    let (mut plain, _) = client(&fake, config());
    block_on(async {
        let err = plain.get_update_data(&[rev(1, 1)]).await.unwrap_err();
        assert!(matches!(err, WsusssError::Decompress(m) if m.contains("cabinet")));
    });
    let mut c = c.with_decompressor(Arc::new(Reverse));
    block_on(async {
        let batch = c.get_update_data(&[rev(1, 1)]).await.unwrap();
        let record = &batch.updates[0];
        assert!(record.fragment.xml().starts_with(b"<Update>"));
        assert_eq!(
            record.fragment.representation,
            wsus_protocol::metadata::Representation::Compressed
        );
    });
}

#[test]
fn invalid_cookie_restarts_authorization_once_and_is_bounded() {
    let (fake, mut c, _t) = setup();
    block_on(async {
        c.get_config_data(None).await.unwrap();
        fake.fault("GetRevisionIdList", ErrorCode::InvalidCookie, None);
        c.get_revision_ids(&RevisionQuery::default()).await.unwrap();
    });
    assert_eq!(fake.count("GetAuthorizationCookie"), 2);
    assert_eq!(fake.count("GetRevisionIdList"), 2);

    // A persistent fault ends after the configured number of restarts.
    for _ in 0..10 {
        fake.fault("GetConfigData", ErrorCode::InvalidAuthorizationCookie, None);
    }
    let before = fake.count("GetAuthorizationCookie");
    block_on(async {
        let err = c.get_config_data(None).await.unwrap_err();
        assert_eq!(
            err.fault_code(),
            Some(&ErrorCode::InvalidAuthorizationCookie)
        );
    });
    assert_eq!(fake.count("GetAuthorizationCookie") - before, 2);
}

#[test]
fn expired_cookie_is_renewed_with_the_authorization_cookie() {
    let (fake, mut c, _t) = setup();
    block_on(async {
        c.get_config_data(None).await.unwrap();
        fake.clock.0.fetch_add(7200, Ordering::SeqCst);
        c.get_revision_ids(&RevisionQuery::default()).await.unwrap();
    });
    assert_eq!(fake.count("GetAuthorizationCookie"), 1);
    assert_eq!(fake.count("GetCookie"), 2);
}

#[test]
fn busy_is_retried_a_bounded_number_of_times() {
    let (fake, mut c, _t) = setup();
    fake.fault("GetConfigData", ErrorCode::ServerBusy, None);
    block_on(async { c.get_config_data(None).await.unwrap() });
    assert_eq!(fake.count("GetConfigData"), 2);
    for _ in 0..5 {
        fake.fault("GetConfigData", ErrorCode::ServerBusy, None);
    }
    block_on(async {
        let err = c.get_config_data(None).await.unwrap_err();
        assert_eq!(err.fault_code(), Some(&ErrorCode::ServerBusy));
    });
    assert_eq!(
        fake.count("GetConfigData"),
        2 + 3,
        "initial attempt plus two retries"
    );
}

#[test]
fn server_changed_and_missing_digests_are_surfaced_to_the_caller() {
    let (fake, mut c, _t) = setup();
    fake.fault("GetRevisionIdList", ErrorCode::ServerChanged, None);
    fake.fault(
        "DownloadFiles",
        ErrorCode::FileDigestsMissing,
        Some("aaa|bbb"),
    );
    block_on(async {
        let err = c
            .get_revision_ids(&RevisionQuery::default())
            .await
            .unwrap_err();
        assert!(err.is_server_changed());
        let err = c.download_files(&[vec![1; 20]]).await.unwrap_err();
        assert_eq!(err.missing_digests(), ["aaa", "bbb"]);
        assert!(matches!(
            c.download_files(&vec![vec![1; 20]; 101]).await,
            Err(WsusssError::Limit(_))
        ));
    });
}

#[test]
fn signed_urls_stay_out_of_debug_output_and_errors() {
    let (_fake, mut c, _t) = setup();
    block_on(async {
        let batch = c.get_update_data(&[rev(1, 1)]).await.unwrap();
        let text = format!("{:?}", batch.file_locations);
        assert!(
            !text.contains("SIGNEDSECRET") && !text.contains("sig="),
            "{text}"
        );
        assert!(text.contains("mu.test"));
    });
}

#[test]
fn content_not_found_triggers_download_files_then_succeeds() {
    let (fake, mut c, _t) = setup();
    let body = sample(5000);
    {
        let mut st = fake.state.lock().unwrap();
        st.content = body.clone();
        st.content_missing_until_download_files = true;
    }
    let dir = tempfile::tempdir().unwrap();
    let downloader = Downloader::open(dir.path(), DownloadLimits::default()).unwrap();
    let expected = expected_for("a.bin", &body);
    let sha1 = expected.digests()[0].bytes.clone();
    let options = DownloadOptions {
        retry: RetryPolicy::none(),
        ..DownloadOptions::default()
    };
    let locations = vec![Location::parse("http://upstream.test/Content/ab/aa").unwrap()];
    let file =
        block_on(c.download_content(&downloader, &expected, Some(&sha1), &locations, &options))
            .unwrap();
    assert_eq!(std::fs::read(&file.path).unwrap(), body);
    assert!(fake.state.lock().unwrap().download_files_called);
}

#[test]
fn convention_location_follows_the_configured_folder_rule() {
    let mut cfg = config();
    cfg.content_base_url = Some("http://upstream.test:80/".into());
    let (c, _t) = {
        let clock = Arc::new(TestClock(AtomicI64::new(0)));
        client(&Fake::new(clock), cfg.clone())
    };
    let mut digest = vec![0xab; 20];
    digest[19] = 0x0f;
    let loc = c.convention_location(&digest, Some("AM_Base.EXE")).unwrap();
    let text = format!("{loc:?}");
    assert!(text.contains("upstream.test:80"), "{text}");
    assert!(c.convention_location(&[1; 19], None).is_none());
    assert!(c.config().content_base_url.is_some());
    assert_eq!(c.content_candidates(Some(&digest), None, None).len(), 1);
}

fn request_text(r: &wsus_client::transport::HttpRequest) -> String {
    String::from_utf8(r.body.clone()).unwrap()
}

#[test]
fn revision_list_filter_sends_delta_true_exactly_when_an_anchor_is_present() {
    // Observed on a real WSUS (inventory 9.5): Delta=false with an anchor returns every
    // matching revision again, Delta=true only the changed ones.
    let (_fake, mut c, transport) = setup();
    let product = UpdateId(uuid::Uuid::from_u128(0x77));
    let class = UpdateId(uuid::Uuid::from_u128(0x88));
    block_on(async {
        c.get_config_data(None).await.unwrap();
        for anchor in [None, Some("1,2026-10-04 16:09:27.371".to_string())] {
            c.get_revision_ids(&RevisionQuery {
                anchor,
                get_config: false,
                categories: vec![product],
                classifications: vec![class],
            })
            .await
            .unwrap();
        }
    });
    let sent: Vec<String> = transport
        .requests()
        .iter()
        .map(request_text)
        .filter(|b| b.contains("<GetRevisionIdList"))
        .collect();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].matches("<Delta>false</Delta>").count(),
        2,
        "{}",
        sent[0]
    );
    assert_eq!(
        sent[1].matches("<Delta>true</Delta>").count(),
        2,
        "{}",
        sent[1]
    );
}

#[test]
fn convention_url_is_upper_case_hex_with_the_file_extension_as_observed_on_a_real_wsus() {
    let mut cfg = config();
    cfg.content_base_url = Some("http://upstream.test:8530".into());
    let (fake, c, transport) = {
        let clock = Arc::new(TestClock(AtomicI64::new(0)));
        let fake = Fake::new(clock);
        let (c, t) = client(&fake, cfg);
        (fake, c, t)
    };
    let body = sample(2000);
    fake.state.lock().unwrap().content = body.clone();
    let expected = expected_for("AM_Base.exe", &body);
    let sha1 = expected.digests()[0].bytes.clone();
    let candidates = c.content_candidates(Some(&sha1), Some("AM_Base.exe"), None);
    assert_eq!(candidates.len(), 1);
    let dir = tempfile::tempdir().unwrap();
    let downloader = Downloader::open(dir.path(), DownloadLimits::default()).unwrap();
    let options = DownloadOptions {
        retry: RetryPolicy::none(),
        ..DownloadOptions::default()
    };
    block_on(c.download_content_once(&downloader, &expected, &candidates, &options)).unwrap();
    let hex = sha1.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let want = format!("http://upstream.test:8530/Content/{}/{hex}.exe", &hex[38..]);
    let urls: Vec<String> = transport
        .requests()
        .iter()
        .map(|r| r.url.expose().to_owned())
        .collect();
    assert!(urls.contains(&want), "{urls:?} lacks {want}");
}

#[test]
fn download_files_fallback_can_be_switched_off() {
    let mut cfg = config();
    cfg.download_files_fallback = false;
    let clock = Arc::new(TestClock(AtomicI64::new(1_800_000_000)));
    let fake = Fake::new(clock);
    let (mut c, _t) = client(&fake, cfg);
    let body = sample(3000);
    {
        let mut st = fake.state.lock().unwrap();
        st.content = body.clone();
        st.content_missing_until_download_files = true;
    }
    let dir = tempfile::tempdir().unwrap();
    let downloader = Downloader::open(dir.path(), DownloadLimits::default()).unwrap();
    let expected = expected_for("a.bin", &body);
    let sha1 = expected.digests()[0].bytes.clone();
    let options = DownloadOptions {
        retry: RetryPolicy::none(),
        ..DownloadOptions::default()
    };
    let locations = vec![Location::parse("http://upstream.test/Content/ab/aa").unwrap()];
    let err =
        block_on(c.download_content(&downloader, &expected, Some(&sha1), &locations, &options))
            .unwrap_err();
    assert!(err.is_not_found(), "{err}");
    assert!(!fake.state.lock().unwrap().download_files_called);
}
