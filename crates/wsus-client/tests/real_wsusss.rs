//! `WsusssClient` against a REAL upstream WSUS. Ignored by default; set `WSUS_REAL_ORIGIN`
//! (for example `http://10.83.20.149:8530`) and run
//! `cargo test -p wsus-client --features reqwest-async --test real_wsusss -- --ignored`.
//!
//! Observed on the lab WSUS (Windows Server 2025 10.0.26100, 2026-10-04; inventory 9.5): the
//! assertions describe that server and day. Read-only: the test sends `GetAuthorizationCookie`
//! (the upstream records the downstream account), `GetCookie`, `GetConfigData`,
//! `GetRevisionIdList` and `GetUpdateData`; no `DownloadFiles`, no content request.
#![cfg(feature = "reqwest-async")]

use wsus_client::transport::reqwest_backend::{ReqwestTransport, TokioTimer};
use wsus_client::wsusss::{RevisionQuery, WsusssClient, WsusssConfig};
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};

const PRODUCT: &str = "8c3fcc84-7410-4a95-8b89-a166a0190486";
const CLASSIFICATION: &str = "e0789628-ce08-4437-be74-2495b842f43b";

fn uid(s: &str) -> UpdateId {
    UpdateId(s.parse().unwrap())
}

#[tokio::test]
#[ignore = "needs WSUS_REAL_ORIGIN pointing at a disposable lab WSUS"]
async fn real_upstream_handshake_filter_semantics_delta_and_cabinet_metadata() {
    let Ok(origin) = std::env::var("WSUS_REAL_ORIGIN") else {
        eprintln!("WSUS_REAL_ORIGIN not set; nothing to do");
        return;
    };
    let config = WsusssConfig::new(
        &origin,
        "real-test.lab.invalid",
        "6f1c2f6e-3f0b-4d3a-9b1e-0d2f6a1c5e22",
    );
    let mut c = WsusssClient::new(config, ReqwestTransport::new().unwrap(), TokioTimer);

    // GetAuthConfig names the DSS authorization service; the handshake and the configuration
    // follow.
    let auth = c.get_auth_config().await.expect("GetAuthConfig");
    assert_eq!(
        auth.auth_info.value().unwrap()[0]
            .plug_in_id
            .value()
            .unwrap(),
        "DssTargeting"
    );
    let cfg = c.get_config_data(None).await.expect("GetConfigData");
    assert_eq!(cfg.max_number_of_updates_per_request, 100);
    assert!(cfg.new_config_anchor.value().is_some());

    // Categories: all of them, no filter.
    let cats = c
        .get_revision_ids(&RevisionQuery {
            get_config: true,
            ..RevisionQuery::default()
        })
        .await
        .expect("categories");
    assert!(cats.revisions.len() > 1000, "{}", cats.revisions.len());
    assert!(
        cats.anchor.as_deref().unwrap().contains(','),
        "anchor `n,timestamp`"
    );

    // Wire filter: product alone and classification alone select nothing, both select the
    // updates (a lab catalog that holds only Defender updates returns all of them).
    let query = |anchor: Option<String>, products: bool, classes: bool| RevisionQuery {
        anchor,
        get_config: false,
        categories: if products { vec![uid(PRODUCT)] } else { vec![] },
        classifications: if classes {
            vec![uid(CLASSIFICATION)]
        } else {
            vec![]
        },
    };
    let only_product = c.get_revision_ids(&query(None, true, false)).await.unwrap();
    assert!(
        only_product.revisions.is_empty(),
        "one-sided filter selects nothing"
    );
    let both = c.get_revision_ids(&query(None, true, true)).await.unwrap();
    assert!(both.revisions.len() > 24_000, "{}", both.revisions.len());

    // Delta: with the anchor just returned, Delta=true (the client sends it for an
    // incremental call) returns nothing; Delta=false would repeat every revision.
    let anchor = both.anchor.clone();
    let incremental = c
        .get_revision_ids(&query(anchor, true, true))
        .await
        .unwrap();
    assert!(
        incremental.revisions.is_empty(),
        "{}",
        incremental.revisions.len()
    );

    // GetUpdateData for the approved bundle: a Cabinet blob decoded to the update document.
    let bundle = UpdateRevision {
        id: uid("a2fef9b0-7951-4c2c-a42b-9e351dd1c1fe"),
        revision: Revision(200),
    };
    let batch = c.get_update_data(&[bundle]).await.expect("GetUpdateData");
    let record = &batch.updates[0];
    let xml = std::str::from_utf8(record.fragment.xml()).unwrap();
    assert!(
        xml.starts_with("<upd:Update "),
        "{}",
        &xml[..40.min(xml.len())]
    );
    assert!(xml.contains("KB2267602"));
    let index = record.fragment.index(&Default::default()).unwrap();
    assert_eq!(index.identity, bundle);
    assert_eq!(
        index.bundled.len(),
        4,
        "four alternative groups of bundled revisions"
    );
    assert!(batch.file_locations.is_empty(), "a bundle has no files");
}
