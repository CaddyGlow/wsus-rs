//! Startup recovery of staging generations: interrupted upstream staging must stay
//! resumable. Fakes and in-process servers only.
mod upstream_server_common;
use upstream_server_common::*;

use wsus_client::transport::ImmediateTimer;
use wsus_server::catalog::*;
use wsus_server::storage::Database;
use wsus_server::upstream::{StageOutcome, UpstreamConfig, UpstreamSync};

fn frag(n: u128) -> FragmentImport {
    FragmentImport::new(rev(n, 1), "Software", b"<Update/>")
}

fn staged(cat: &Catalog, name: &str, kind: SourceKind) -> (SourceId, GenerationId) {
    let s = cat.add_source(name, kind, "").unwrap();
    let g = cat.begin_generation(s, Some("anchor")).unwrap();
    cat.import_fragments(g, &[frag(1)]).unwrap();
    (s, g)
}

fn state(cat: &Catalog, g: GenerationId) -> GenerationState {
    cat.generation(g).unwrap().state
}

#[test]
fn recover_after_restart_leaves_upstream_staging_alone_and_fails_the_rest() {
    let cat = Catalog::new(Database::open_in_memory().unwrap());
    let (_, up) = staged(&cat, "up", SourceKind::Upstream);
    let (_, local) = staged(&cat, "local", SourceKind::Local);
    let (_, import) = staged(&cat, "import", SourceKind::Import);
    let failed = cat.recover_after_restart().unwrap();
    assert_eq!(failed, vec![local, import]);
    assert_eq!(state(&cat, up), GenerationState::Staging);
    assert_eq!(state(&cat, local), GenerationState::Failed);
    // The evidence stays.
    assert!(
        cat.generation(local)
            .unwrap()
            .evidence
            .unwrap()
            .contains("interrupted")
    );
    // The old behaviour is still available explicitly and fails everything left.
    assert_eq!(cat.abandon_interrupted().unwrap(), vec![up]);
}

#[test]
fn abandon_scopes_select_by_kind_and_by_source() {
    let cat = Catalog::new(Database::open_in_memory().unwrap());
    let (_, up) = staged(&cat, "up", SourceKind::Upstream);
    let (s_local, local) = staged(&cat, "local", SourceKind::Local);
    let (_, import) = staged(&cat, "import", SourceKind::Import);
    assert_eq!(
        cat.abandon_interrupted_in(&AbandonScope::Kinds(vec![SourceKind::Import]))
            .unwrap(),
        vec![import]
    );
    assert_eq!(
        cat.abandon_interrupted_in(&AbandonScope::Source(s_local))
            .unwrap(),
        vec![local]
    );
    assert_eq!(state(&cat, up), GenerationState::Staging);
    assert!(
        cat.abandon_interrupted_in(&AbandonScope::SkipUpstream)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        cat.abandon_interrupted_in(&AbandonScope::All).unwrap(),
        vec![up]
    );
}

#[test]
fn an_interrupted_upstream_synchronization_resumes_after_startup_recovery() {
    let f = fixture();
    f.seed(3);
    let down = Catalog::new(Database::open_in_memory().unwrap());
    let mk = |down: &Catalog| {
        UpstreamSync::new(
            down.clone(),
            client(&f.server),
            UpstreamConfig::new("downstream", "uss.test"),
        )
        .unwrap()
    };
    let mut o: UpstreamSync<_, ImmediateTimer> = mk(&down);
    // Stage but never activate: the process "dies" here.
    let StageOutcome::Staged(s1) = block_on(o.stage()).unwrap() else {
        panic!("expected a staged generation");
    };
    drop(o);

    // Startup recovery that spares upstream sources: the next run resumes the generation.
    assert!(down.recover_after_restart().unwrap().is_empty());
    let mut o = mk(&down);
    let StageOutcome::Staged(s2) = block_on(o.stage()).unwrap() else {
        panic!("expected a staged generation");
    };
    assert_eq!(s2.generation, s1.generation);
    assert!(s2.stats.resumed);
    assert_eq!(s2.stats.fetched, 0, "nothing is fetched again");
    o.activate(s2).unwrap();
    drop(o);

    // The all-sources variant would have destroyed that work.
    f.refresh(&[Doc::software(4, 1)]);
    let mut o = mk(&down);
    let StageOutcome::Staged(s3) = block_on(o.stage()).unwrap() else {
        panic!("expected a staged generation");
    };
    drop(o);
    assert_eq!(down.abandon_interrupted().unwrap(), vec![s3.generation]);
    let mut o = mk(&down);
    let StageOutcome::Staged(s4) = block_on(o.stage()).unwrap() else {
        panic!("expected a staged generation");
    };
    assert_ne!(s4.generation, s3.generation);
    assert!(!s4.stats.resumed);
}
