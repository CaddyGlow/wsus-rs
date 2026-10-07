//! `WsusssClient` and the Cabinet decompressor replayed over sanitized REAL responses.
//!
//! Provenance: `docs/fixtures/wsus-m0-wsusss/` (README there): responses of the lab WSUS acting
//! as an upstream server (Windows Server 2025 10.0.26100, 2026-10-04). The transport here is a
//! mock that answers each request with the recorded response of the same operation, so these
//! tests show that this client's session handling, request building, anchor and filter
//! handling and `XmlUpdateBlobCompressed` decoding accept what that server sent. They are not a
//! live run (the ignored `real_wsusss.rs` is) and validate nothing about other servers.
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use common::block_on;
use wsus_client::transport::{
    HttpRequest, HttpResponse, ImmediateTimer, RetryPolicy,
    mock::{MockStep, MockTransport},
};
use wsus_client::wsusss::{
    CabMetadataDecompressor, Clock, MetadataDecompressor, RevisionQuery, WsusssClient, WsusssConfig,
};
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::soap::{Limits, decode_response};
use wsus_protocol::wsusss::GetUpdateDataResponse;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/fixtures/wsus-m0-wsusss")
}

fn read(rel: &str) -> Vec<u8> {
    let p = root().join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

struct Fixed(AtomicI64);
impl Clock for Fixed {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn updates() -> Vec<(&'static str, u32)> {
    vec![
        ("a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe", 200),
        ("266f6222-c89d-43f2-9f8a-69340271e677", 200),
        ("ccb78947-6453-4ecc-9de8-bc0305c98f2d", 200),
        ("56309036-4c77-4dd9-951a-99ee9c246a94", 101),
    ]
}

/// Which recorded response answers `request` (by operation, filter and first update id).
fn recorded(request: &HttpRequest) -> Option<&'static str> {
    let body = String::from_utf8_lossy(&request.body).into_owned();
    let has = |s: &str| body.contains(s);
    if has("<GetAuthConfig") {
        Some("exchanges/000001")
    } else if has("<GetAuthorizationCookie") {
        Some("exchanges/000002")
    } else if has("<GetCookie") {
        Some("exchanges/000003")
    } else if has("<GetConfigData") {
        Some("exchanges/000005")
    } else if has("<GetRevisionIdList") {
        if has("<GetConfig>true</GetConfig>") {
            Some("exchanges/000006")
        } else if has("<Delta>true</Delta>") {
            Some("exchanges/000011")
        } else if has("<Categories>") {
            Some("exchanges/000009")
        } else {
            Some("exchanges/000012")
        }
    } else if has("<GetUpdateData") {
        updates().iter().enumerate().find_map(|(i, (id, _))| {
            has(id).then_some(
                [
                    "exchanges/000013",
                    "exchanges/000014",
                    "exchanges/000015",
                    "exchanges/000016",
                ][i],
            )
        })
    } else {
        None
    }
}

fn client() -> (WsusssClient<MockTransport, ImmediateTimer>, MockTransport) {
    let transport = MockTransport::with_handler(move |req: &HttpRequest| match recorded(req) {
        Some(dir) => MockStep::Respond(HttpResponse::new(
            200,
            read(&format!("{dir}/response.body")),
        )),
        None => MockStep::Respond(HttpResponse::new(404, Vec::new())),
    });
    let mut config = WsusssConfig::new(
        "http://upstream.test:8530",
        "m5.lab.invalid",
        "6f1c2f6e-3f0b-4d3a-9b1e-0d2f6a1c5e11",
    );
    config.retry = RetryPolicy::none();
    // 2026-10-04T16:34:00Z: before the recorded cookie's expiry (20:33Z).
    let clock = Arc::new(Fixed(AtomicI64::new(1_791_131_640)));
    let client = WsusssClient::new(config, transport.clone(), ImmediateTimer).with_clock(clock);
    (client, transport)
}

fn rev(id: &str, r: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(id.parse().unwrap()),
        revision: Revision(r),
    }
}

#[test]
fn the_recorded_handshake_config_and_lists_drive_the_client() {
    let (mut c, transport) = client();
    block_on(async {
        let cfg = c.get_config_data(None).await.unwrap();
        assert!(cfg.lazy_sync);
        assert_eq!(c.update_batch_size(), 100);
        let cats = c
            .get_revision_ids(&RevisionQuery {
                get_config: true,
                ..RevisionQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(cats.revisions.len(), 30);
        assert!(cats.anchor.as_deref().unwrap().starts_with("9438,"));
        let filtered = c
            .get_revision_ids(&RevisionQuery {
                anchor: Some("9438,2026-10-04 16:09:27.371".into()),
                get_config: false,
                categories: vec![UpdateId(
                    "8c3fcc84-7410-4a95-8b89-a166a0190486".parse().unwrap(),
                )],
                classifications: vec![UpdateId(
                    "e0789628-ce08-4437-be74-2495b842f43b".parse().unwrap(),
                )],
            })
            .await
            .unwrap();
        assert!(
            filtered.revisions.is_empty(),
            "Delta=true selects the delta answer"
        );
    });
    // GetAuthConfig, GetAuthorizationCookie, GetCookie, GetConfigData, then two lists.
    let sent: Vec<String> = transport
        .requests()
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert_eq!(sent.len(), 6);
    assert!(sent[1].contains("DssAuthWebService") || sent[1].contains("<accountName>"));
    assert!(sent[5].contains("<Delta>true</Delta>"));
}

#[test]
fn recorded_get_update_data_decodes_into_the_stored_documents() {
    let (mut c, _t) = client();
    block_on(async {
        c.get_config_data(None).await.unwrap();
        for (id, r) in updates() {
            let batch = c.get_update_data(&[rev(id, r)]).await.unwrap();
            assert_eq!(batch.updates.len(), 1, "{id}");
            let record = &batch.updates[0];
            assert_eq!(record.identity, rev(id, r));
            let want = read(&format!("docs/{id}-r{r}.xml"));
            // Compressed blobs are decoded to UTF-8; text blobs are already text.
            assert_eq!(
                String::from_utf8_lossy(record.fragment.xml()),
                String::from_utf8_lossy(&want),
                "{id}"
            );
            // The strict parser accepts it and the identity matches the response.
            let index = record.fragment.index(&Limits::default()).unwrap();
            assert_eq!(index.identity, rev(id, r));
        }
        // The leaf: one SHA-1 digest listed, an MU URL and no USS URL.
        let batch = c
            .get_update_data(&[rev("266f6222-c89d-43f2-9f8a-69340271e677", 200)])
            .await
            .unwrap();
        assert_eq!(batch.updates[0].file_digests.len(), 1);
        assert_eq!(batch.file_locations.len(), 1);
        assert!(
            batch.file_locations[0].mu.is_some(),
            "an MU URL is listed (not used unless allow_mu_url)"
        );
        assert!(batch.file_locations[0].uss.is_none(), "UssUrl was empty");
    });
}

#[test]
fn the_cabinet_decompressor_reads_every_recorded_compressed_blob() {
    let mut seen = 0;
    for n in ["000013", "000014", "000016"] {
        let body = read(&format!("exchanges/{n}/response.body"));
        let r: GetUpdateDataResponse = decode_response(&body, &Limits::default()).unwrap();
        for u in r.result.value().unwrap().updates.value().unwrap() {
            let blob = u.xml_update_blob_compressed.value().unwrap();
            let xml = CabMetadataDecompressor::default().decompress(blob).unwrap();
            assert!(xml.starts_with(b"<upd:Update "), "{n}");
            assert!(std::str::from_utf8(&xml).is_ok());
            seen += 1;
            // A tiny limit refuses the member instead of decoding it.
            assert!(
                CabMetadataDecompressor { max_bytes: 100 }
                    .decompress(blob)
                    .is_err()
            );
        }
    }
    assert_eq!(seen, 3);
}

#[test]
fn a_blob_that_is_not_a_cabinet_is_refused() {
    let err = CabMetadataDecompressor::default()
        .decompress(b"MSCF-but-not-really")
        .unwrap_err();
    assert!(err.to_string().contains("cabinet"), "{err}");
}
