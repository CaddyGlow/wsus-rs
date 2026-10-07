//! Startup and admin recovery of interrupted staging generations.
//!
//! An interrupted upstream staging generation must survive a CLI restart and
//! be resumed by `admin sync resume`; staging generations of local and import
//! sources cannot be resumed and are failed (evidence kept).
//!
//! EVIDENCE STATUS: the upstream here is this workspace's own MS-WSUSSS server
//! on a loopback socket and the downstream is this workspace's own importer.
//! This is self-consistency only. It is NOT WSUS compatibility evidence.

use std::sync::Arc;
use uuid::Uuid;
use wsus_cli::{
    admin::{self, Admin, ContentMode},
    config::{Config, UpstreamSection},
    server_cmd,
};
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_server::{
    catalog::{
        ActivateOutcome, Catalog, FragmentImport, GenerationState, RelationshipImport,
        RelationshipKind, SourceKind,
    },
    content::ContentStore,
    endpoints::wsusss::{UpstreamServer, UpstreamServerConfig, UpstreamServices, http},
    session::{SessionConfig, SessionManager},
    storage::Database,
    upstream::StageOutcome,
};

fn rev(n: u128) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(Uuid::from_u128(n)),
        revision: Revision(1),
    }
}

fn doc(n: u128, kind: &str, category: Option<u128>) -> String {
    let rel = category.map_or(String::new(), |c| {
        format!(
            "<AtLeastOne IsCategory=\"true\"><UpdateIdentity UpdateID=\"{}\"/></AtLeastOne>",
            Uuid::from_u128(c)
        )
    });
    format!(
        "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">\
         <UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>\
         <Properties UpdateType=\"{kind}\"/>\
         <Relationships><Prerequisites>{rel}</Prerequisites></Relationships></Update>",
        Uuid::from_u128(n)
    )
}

/// A loopback MS-WSUSSS upstream with one category and three software updates.
async fn upstream(dir: &std::path::Path) -> String {
    let db = Database::open(&dir.join("upstream.sqlite")).unwrap();
    let sessions = Arc::new(
        SessionManager::open(db.clone(), SessionConfig::default(), "restart-recovery").unwrap(),
    );
    let catalog = Catalog::new(db.clone());
    let source = catalog
        .add_source("serving", SourceKind::Import, "")
        .unwrap();
    let content = ContentStore::open(db, &dir.join("upstream-content")).unwrap();
    let g = catalog.begin_generation(source, None).unwrap();
    let mut frags = vec![FragmentImport::new(
        rev(0x100),
        "Category",
        doc(0x100, "Category", None).as_bytes(),
    )];
    for n in 1..=3u128 {
        let mut f = FragmentImport::new(
            rev(n),
            "Software",
            doc(n, "Software", Some(0x100)).as_bytes(),
        );
        f.relationships.push(RelationshipImport {
            kind: RelationshipKind::Category,
            target: rev(0x100).id,
            revision: None,
        });
        frags.push(f);
    }
    catalog.import_fragments(g, &frags).unwrap();
    assert!(matches!(
        catalog.activate(g).unwrap(),
        ActivateOutcome::Activated { .. }
    ));
    let server = UpstreamServer::open(
        UpstreamServices {
            catalog,
            content,
            sessions,
        },
        UpstreamServerConfig {
            source_name: "serving".into(),
            ..UpstreamServerConfig::default()
        },
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(http::serve_one(listener, server));
    origin
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_upstream_generation_survives_a_restart_and_resumes() {
    let up_dir = tempfile::tempdir().unwrap();
    let origin = upstream(up_dir.path()).await;

    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::defaults_in(dir.path());
    config.upstream = Some(UpstreamSection {
        origin,
        ..UpstreamSection::default()
    });

    // Process 1: stage a generation from the upstream, then "crash" before
    // activation.
    let staged_generation = {
        let admin = Admin::open(&config).unwrap();
        admin::source_add(&admin, "upstream", "upstream", "").unwrap();
        // A local-source staging generation, which nothing can resume.
        let local = admin
            .catalog
            .add_source("scratch", SourceKind::Local, "")
            .unwrap();
        let abandoned = admin.catalog.begin_generation(local, None).unwrap();
        let mut sync = admin::upstream_sync(&admin, "upstream").unwrap();
        let StageOutcome::Staged(staged) = sync.stage().await.unwrap() else {
            panic!("expected a staged generation");
        };
        let info = admin.catalog.generation(staged.generation).unwrap();
        assert_eq!(info.state, GenerationState::Staging);
        (staged.generation, abandoned)
    };
    let (staged, abandoned) = staged_generation;

    // Process 2: server startup recovery.
    let opened = server_cmd::open(&config, None).unwrap();
    assert_eq!(opened.recovered_generations, vec![abandoned.0]);
    drop(opened);

    let admin = Admin::open(&config).unwrap();
    assert_eq!(
        admin.catalog.generation(staged).unwrap().state,
        GenerationState::Staging,
        "the resumable upstream generation must not be failed at startup"
    );
    let failed = admin.catalog.generation(abandoned).unwrap();
    assert_eq!(failed.state, GenerationState::Failed);
    assert!(failed.evidence.unwrap().contains("interrupted"));
    let status = admin::sync_status(&admin, None).unwrap();
    assert_eq!(status.value["interrupted_staging_generations"], 1);

    // `start` refuses to guess; `resume` continues the same generation.
    let err = admin::sync_run(&admin, None, false, ContentMode::None)
        .await
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("wsus admin sync resume"));
    assert_eq!(
        admin.catalog.generation(staged).unwrap().state,
        GenerationState::Staging
    );
    let (out, _) = admin::sync_run(&admin, None, true, ContentMode::None)
        .await
        .unwrap();
    assert_eq!(out.value["outcome"]["result"], "activated");
    assert_eq!(out.value["outcome"]["generation"], staged.0);
    assert_eq!(out.value["stats"]["resumed"], true);
    assert_eq!(out.value["stats"]["fetched"], 0, "nothing is fetched twice");
    let source = admin.catalog.source_by_name("upstream").unwrap().unwrap();
    assert_eq!(
        admin.catalog.active_generation(source.id).unwrap(),
        Some(staged)
    );
    assert_eq!(
        admin
            .catalog
            .snapshot(source.id)
            .unwrap()
            .unwrap()
            .count()
            .unwrap(),
        4
    );
}
