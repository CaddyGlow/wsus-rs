//! Real-server flow against a disposable lab WSUS. Ignored by default; set
//! `WSUS_REAL_ORIGIN` (for example `http://10.83.20.149:8530`) and run with
//! `cargo test -p wsus-client --features reqwest-async --test real_wsus -- --ignored`.
//!
//! Observed (lab WSUS, Windows Server 2025, protocol 3.2): see the cap policy
//! in `wsus_client::sync` (400 installed non-leaf ids accepted, 401 rejected).
#![cfg(feature = "reqwest-async")]

use std::collections::BTreeSet;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
use wsus_client::{
    session::{SessionConfig, SystemClock, WuspSession, unix_to_xs},
    state::StateStore,
    sync::{RevisionStore, SyncEngine, SyncError, SyncOptions},
    transport::{
        HttpRequest, HttpResponse, Transport, TransportError,
        reqwest_backend::{ReqwestTransport, TokioTimer},
    },
};
use wsus_protocol::{identity::UpdateRevision, soap::Presence, wusp::ComputerInfo};

type Engine = SyncEngine<Counting, TokioTimer, SystemClock>;

/// Counts response bytes on the wire against their Xpress-decoded size.
#[derive(Clone, Default)]
struct Counting {
    inner: Option<ReqwestTransport>,
    wire: Arc<AtomicUsize>,
    decoded: Arc<AtomicUsize>,
    xpress: Arc<AtomicUsize>,
    responses: Arc<AtomicUsize>,
}

impl Transport for Counting {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let response = self.inner.as_ref().unwrap().send(request).await?;
        self.responses.fetch_add(1, Ordering::Relaxed);
        self.wire.fetch_add(response.body.len(), Ordering::Relaxed);
        let decoded = if response
            .headers
            .get("content-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("xpress"))
        {
            self.xpress.fetch_add(1, Ordering::Relaxed);
            let r = wsus_protocol::xpress::decode(&response.body, &Default::default());
            r.map_or(0, |d| d.len())
        } else {
            response.body.len()
        };
        self.decoded.fetch_add(decoded, Ordering::Relaxed);
        Ok(response)
    }
}

fn computer_info() -> ComputerInfo {
    ComputerInfo {
        dns_name: Presence::Value("realtest.lab.invalid".into()),
        os_major_version: 10,
        os_minor_version: 0,
        os_build_number: 26100,
        os_service_pack_major_number: 0,
        os_service_pack_minor_number: 0,
        os_locale: Presence::Value("en-US".into()),
        computer_manufacturer: Presence::Absent,
        computer_model: Presence::Absent,
        bios_version: Presence::Absent,
        bios_name: Presence::Absent,
        bios_release_date: unix_to_xs(0),
        processor_architecture: Presence::Value("9".into()),
        suite_mask: 0,
        old_product_type: 1,
        new_product_type: 48,
        system_metrics: 0,
        client_version_major_number: 10,
        client_version_minor_number: 0,
        client_version_build_number: 26100_i16,
        client_version_qfe_number: 0,
        os_description: Presence::Absent,
        oem: Presence::Absent,
        device_type: Presence::Absent,
        firmware_version: Presence::Absent,
        mobile_operator: Presence::Absent,
    }
}

fn engine(origin: &str, dir: &TempDir) -> Engine {
    engine_with(origin, dir, Counting::default(), true)
}

fn engine_with(origin: &str, dir: &TempDir, mut counting: Counting, xpress: bool) -> Engine {
    counting.inner = Some(ReqwestTransport::new().unwrap());
    let mut config = SessionConfig::new(origin, "realtest.lab.invalid");
    config.accept_xpress = xpress;
    config.computer_info = Some(computer_info());
    let state = StateStore::open(dir.path().join("state").join("state.json")).unwrap();
    let session = WuspSession::new(counting, TokioTimer, SystemClock, config, state).unwrap();
    SyncEngine::new(
        session,
        RevisionStore::open(dir.path().join("meta")).unwrap(),
    )
}

fn held(e: &Engine) -> BTreeSet<UpdateRevision> {
    e.session()
        .state()
        .cached_revisions
        .keys()
        .copied()
        .collect()
}

#[tokio::test]
#[ignore = "needs WSUS_REAL_ORIGIN pointing at a disposable lab WSUS"]
async fn full_incremental_and_resumed_sync_converge_on_a_real_wsus() {
    let Ok(origin) = std::env::var("WSUS_REAL_ORIGIN") else {
        eprintln!("WSUS_REAL_ORIGIN is not set; nothing to do");
        return;
    };

    // Full sync from an empty state.
    let full_dir = TempDir::new().unwrap();
    let mut full = engine(&origin, &full_dir);
    let report = full.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(report.pages > 1, "expected a truncated, multi-page sync");
    assert!(report.new_revisions > 0);
    let all = held(&full);
    eprintln!(
        "pages={} new={} removed={} held={}",
        report.pages,
        report.new_revisions,
        report.removed_revisions,
        all.len()
    );
    // Revisions declared out of scope are dropped (and may be delivered
    // again), so the held set is deliveries minus removals.
    assert_eq!(all.len(), report.new_revisions - report.removed_revisions);

    // Incremental: nothing changed, one request.
    let again = full.sync_updates(&SyncOptions::default()).await.unwrap();
    assert!(again.unchanged);
    assert_eq!(again.pages, 1);

    // Interrupt after three pages, drop the engine, resume from disk.
    let part_dir = TempDir::new().unwrap();
    {
        let mut part = engine(&origin, &part_dir);
        let err = part
            .sync_updates(&SyncOptions {
                max_pages: 3,
                ..SyncOptions::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::TooManyPages(3)), "{err}");
        assert!(!held(&part).is_empty());
    }
    let mut resumed = engine(&origin, &part_dir);
    let before = held(&resumed);
    resumed.sync_updates(&SyncOptions::default()).await.unwrap();
    let after = held(&resumed);
    assert!(before.is_subset(&after));
    assert_eq!(after, all, "resumed run converges on the same revisions");
}

/// `GetFileLocations` and `GetExtendedUpdateInfo2` against the lab WSUS. The first is asserted (a
/// location per requested SHA-1); the second is only reported, because its availability depends on
/// the server build and is an observation, not a requirement.
#[tokio::test]
#[ignore = "needs WSUS_REAL_ORIGIN pointing at a disposable lab WSUS"]
async fn file_locations_and_extended_info2_answer_on_a_real_wsus() {
    use wsus_client::sync::ClosureOptions;
    use wsus_protocol::wusp::XmlUpdateFragmentType;
    let Ok(origin) = std::env::var("WSUS_REAL_ORIGIN") else {
        eprintln!("WSUS_REAL_ORIGIN is not set; nothing to do");
        return;
    };
    let dir = TempDir::new().unwrap();
    let mut e = engine(&origin, &dir);
    e.sync_updates(&SyncOptions::default()).await.unwrap();
    let all: Vec<UpdateRevision> = held(&e).into_iter().collect();
    e.fetch_fragments(&all, XmlUpdateFragmentType::Extended, &[])
        .await
        .unwrap();
    let catalog = e.catalog().unwrap();
    let (revision, closure) = all
        .iter()
        .map(|r| {
            (
                *r,
                catalog.acquisition_closure(&[*r], &ClosureOptions::default()),
            )
        })
        .find(|(_, c)| !c.files.is_empty())
        .expect("a revision with files in the lab catalog");
    let digests: Vec<Vec<u8>> = closure
        .files
        .iter()
        .filter_map(|f| f.sha1.clone())
        .collect();
    assert!(!digests.is_empty());
    let locations = e.file_locations(&digests).await.unwrap();
    eprintln!(
        "GetFileLocations: {} digests asked, {} locations returned",
        digests.len(),
        locations.len()
    );
    assert_eq!(locations.len(), digests.len());
    for kind in [
        XmlUpdateFragmentType::Extended,
        XmlUpdateFragmentType::FileUrl,
    ] {
        match e.fetch_fragments2(&[revision], kind.clone(), &[]).await {
            Ok(r) => eprintln!(
                "GetExtendedUpdateInfo2 {kind:?}: ok, stored={}, locations={}, decryption_entries={}",
                r.stored,
                r.locations.len(),
                r.decryption_entries
            ),
            Err(error) => eprintln!("GetExtendedUpdateInfo2 {kind:?}: {error}"),
        }
    }
}

/// Full sync with xpress on (the default) against the lab WSUS, with wire and
/// decoded byte totals; then the same sync with xpress off must converge on
/// the same revisions.
#[tokio::test]
#[ignore = "needs WSUS_REAL_ORIGIN pointing at a disposable lab WSUS"]
async fn full_sync_with_xpress_matches_identity_and_reports_byte_totals() {
    let Ok(origin) = std::env::var("WSUS_REAL_ORIGIN") else {
        eprintln!("WSUS_REAL_ORIGIN is not set; nothing to do");
        return;
    };
    let dir = TempDir::new().unwrap();
    let counting = Counting::default();
    let mut on = engine_with(&origin, &dir, counting.clone(), true);
    on.sync_updates(&SyncOptions::default()).await.unwrap();
    let (wire, decoded, xpress, total) = (
        counting.wire.load(Ordering::Relaxed),
        counting.decoded.load(Ordering::Relaxed),
        counting.xpress.load(Ordering::Relaxed),
        counting.responses.load(Ordering::Relaxed),
    );
    eprintln!(
        "xpress on: responses={total} xpress_responses={xpress} wire_bytes={wire} decoded_bytes={decoded}"
    );
    assert!(xpress > 0, "server never used Content-Encoding: xpress");
    assert!(decoded > wire);

    let dir_off = TempDir::new().unwrap();
    let off_counting = Counting::default();
    let mut off = engine_with(&origin, &dir_off, off_counting.clone(), false);
    off.sync_updates(&SyncOptions::default()).await.unwrap();
    eprintln!(
        "xpress off: responses={} xpress_responses={} wire_bytes={}",
        off_counting.responses.load(Ordering::Relaxed),
        off_counting.xpress.load(Ordering::Relaxed),
        off_counting.wire.load(Ordering::Relaxed)
    );
    assert_eq!(held(&on), held(&off));
}
