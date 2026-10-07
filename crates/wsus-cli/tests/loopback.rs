//! Our client against our server over a real loopback TCP socket: the axum
//! binding (with the CLI's access-log layer) on one side and the reqwest
//! adapter on the other.
//!
//! EVIDENCE STATUS: this proves only that this workspace's HTTP binding and
//! this workspace's HTTP client agree with each other. It is NOT WSUS
//! compatibility evidence and says nothing about a native Windows Update client.

mod common;

use common::*;
use std::fs;
use wsus_cli::{
    admin,
    client_cmd::{self, ReportArgs, Selection},
    config::Config,
    net, server_cmd,
};
use wsus_client::{session::SystemClock, transport::reqwest_backend::TokioTimer};

#[tokio::test(flavor = "multi_thread")]
async fn sync_download_and_report_over_a_real_socket() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());

    let mut config = Config::defaults_in(dir.path());
    config.client.origin = Some(origin.clone());
    config.client.dns_name = "client1.example.invalid".into();
    config.server.advertised_content_url = Some(origin);
    config.server.max_request_bytes = Some(64 * 1024);
    let opened = server_cmd::open(&config, None).unwrap();
    let admin = admin::Admin::open(&config).unwrap();
    admin::source_add(&admin, "upstream", "local", "synthetic").unwrap();
    let data = payload(300_000);
    let rev = seed_update(&admin, "upstream", 7, "payload.bin", &data);
    admin::approval_set(
        &admin,
        None,
        &update_id(7).to_string(),
        "All Computers",
        "install",
        None,
    )
    .unwrap();

    let router = server_cmd::router(opened.server.clone());
    let serving = tokio::spawn(async move { axum::serve(listener, router).await });

    let transport =
        net::build_transport(&config.network, std::time::Duration::from_secs(5)).unwrap();
    let mut engine = client_cmd::open_engine(&config, transport, TokioTimer, SystemClock).unwrap();

    let (out, fields) = client_cmd::sync(&mut engine, &config).await.unwrap();
    assert_eq!(out.value["new_revisions"], 1, "{}", out.value);
    assert!(fields.counts.contains(&("new", 1)));

    let (out, _) = client_cmd::download(&mut engine, &config, &Selection::All, false)
        .await
        .unwrap();
    assert!(out.ok, "{}", out.value);
    let path = out.value["files"][0]["path"].as_str().unwrap();
    assert_eq!(fs::read(path).unwrap(), data);

    let args = ReportArgs {
        update: Some(rev.to_string()),
        namespace_id: 1,
        event_id: 2,
        source_id: 0,
        hresult: 0,
        sequence: 1,
        instance_id: None,
        app_name: None,
        job: None,
        inventory: false,
        force: false,
        facts_file: None,
        flush_only: false,
        no_flush: false,
        batch_size: 10,
    };
    let (out, _) = client_cmd::report(&mut engine, &config, &args)
        .await
        .unwrap();
    assert_eq!(out.value["flush"]["delivered"], 1, "{}", out.value);
    let computer = engine.session().state().computer_id.unwrap();
    assert_eq!(
        opened
            .services
            .reporting
            .events_for_computer(computer, None, 10)
            .unwrap()
            .len(),
        1
    );

    // Approval removal hides the update over the socket as well.
    admin::approval_remove(&admin, &update_id(7).to_string(), "All Computers", None).unwrap();
    let (out, _) = client_cmd::sync(&mut engine, &config).await.unwrap();
    assert_eq!(out.value["removed_revisions"], 1, "{}", out.value);

    // Oversized request bodies become protocol faults, not framework errors.
    let big = reqwest::Client::new()
        .post(format!(
            "{}/ClientWebService/client.asmx",
            config.client.origin.as_ref().unwrap()
        ))
        .header("content-type", "text/xml")
        .body(vec![b' '; 70 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status().as_u16(), 413);
    assert!(big.text().await.unwrap().contains("Fault"));

    serving.abort();
}
