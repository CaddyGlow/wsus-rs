use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, Revision, UpdateId, UpdateRevision};
use wsus_server::computers::{ComputerDetails, Computers};
use wsus_server::policy::*;
use wsus_server::reporting::*;
use wsus_server::storage::Database;

fn u(n: u128) -> UpdateId {
    UpdateId(Uuid::from_u128(n))
}
fn c(n: u128) -> ComputerId {
    ComputerId(Uuid::from_u128(n))
}

fn setup() -> (Database, Computers, Policy, Reporting) {
    let db = Database::open_in_memory().unwrap();
    (
        db.clone(),
        Computers::new(db.clone()),
        Policy::new(db.clone()),
        Reporting::new(db),
    )
}

#[test]
fn nothing_is_visible_without_explicit_approval() {
    let (_db, computers, policy, _) = setup();
    computers
        .register(c(1), &ComputerDetails::default(), None)
        .unwrap();
    assert!(policy.visible_to(c(1)).unwrap().is_empty());
    assert_eq!(
        policy.groups_of(c(1)).unwrap(),
        vec![ALL_COMPUTERS, UNASSIGNED_COMPUTERS]
    );
}

#[test]
fn approval_scoping_by_group_and_unregistered_computers() {
    let (_db, computers, policy, _) = setup();
    computers
        .register(c(1), &ComputerDetails::default(), None)
        .unwrap();
    computers
        .register(c(2), &ComputerDetails::default(), Some("Pilot"))
        .unwrap();
    let pilot = policy.create_group("Pilot", "").unwrap();
    // c(2) registered before the group existed, so it is Unassigned; add explicitly.
    policy.add_member(pilot, c(2)).unwrap();

    policy
        .approve(u(10), pilot, DeploymentAction::Install, Some(1000))
        .unwrap();
    policy
        .approve(u(11), ALL_COMPUTERS, DeploymentAction::Install, None)
        .unwrap();

    let v1: Vec<_> = policy
        .visible_to(c(1))
        .unwrap()
        .iter()
        .map(|v| v.update)
        .collect();
    assert_eq!(v1, vec![u(11)]);
    let v2 = policy.visible_to(c(2)).unwrap();
    assert_eq!(
        v2.iter().map(|v| v.update).collect::<Vec<_>>(),
        vec![u(10), u(11)]
    );
    assert_eq!(v2[0].deadline, Some(1000));
    assert!(policy.visible_to(c(99)).unwrap().is_empty());

    policy.remove_member(pilot, c(2)).unwrap();
    assert!(!policy.is_visible(c(2), u(10)).unwrap());
}

#[test]
fn registration_honors_existing_requested_group() {
    let (_db, computers, policy, _) = setup();
    let g = policy.create_group("Servers", "").unwrap();
    computers
        .register(c(1), &ComputerDetails::default(), Some("Servers"))
        .unwrap();
    assert!(policy.groups_of(c(1)).unwrap().contains(&g));
    assert!(
        !policy
            .groups_of(c(1))
            .unwrap()
            .contains(&UNASSIGNED_COMPUTERS)
    );
    // Re-registration keeps memberships.
    computers
        .register(c(1), &ComputerDetails::default(), Some("Other"))
        .unwrap();
    assert!(policy.groups_of(c(1)).unwrap().contains(&g));
}

#[test]
fn deadlines_merge_to_earliest_and_withdraw_and_decline_hide() {
    let (_db, computers, policy, _) = setup();
    computers
        .register(c(1), &ComputerDetails::default(), None)
        .unwrap();
    let g = policy.create_group("G", "").unwrap();
    policy.add_member(g, c(1)).unwrap();
    let a1 = policy
        .approve(u(1), ALL_COMPUTERS, DeploymentAction::Install, Some(500))
        .unwrap();
    policy
        .approve(u(1), g, DeploymentAction::Install, Some(100))
        .unwrap();
    let v = policy.visible_to(c(1)).unwrap();
    assert_eq!(
        (v.len(), v[0].deadline, v[0].approvals.len()),
        (1, Some(100), 2)
    );

    // Re-approval updates the same record.
    let again = policy
        .approve(u(1), ALL_COMPUTERS, DeploymentAction::Install, Some(900))
        .unwrap();
    assert_eq!(again.id, a1.id);
    assert_eq!(again.deadline, Some(900));

    policy.withdraw(a1.id).unwrap();
    assert_eq!(policy.visible_to(c(1)).unwrap()[0].deadline, Some(100));
    assert!(policy.withdraw(a1.id).is_err());

    policy.decline(u(1)).unwrap();
    assert!(policy.visible_to(c(1)).unwrap().is_empty());
    assert!(
        policy
            .approve(u(1), g, DeploymentAction::Install, None)
            .is_err()
    );
    policy.undecline(u(1)).unwrap();
    assert!(
        policy.visible_to(c(1)).unwrap().is_empty(),
        "approvals stay withdrawn"
    );
}

#[test]
fn group_rules() {
    let (_db, _c, policy, _) = setup();
    assert!(policy.delete_group(ALL_COMPUTERS).is_err());
    assert!(policy.add_member(ALL_COMPUTERS, c(1)).is_err());
    let g = policy.create_group("X", "").unwrap();
    assert!(policy.create_group("X", "").is_err());
    policy
        .approve(u(1), g, DeploymentAction::Install, None)
        .unwrap();
    assert!(policy.delete_group(g).is_err());
}

#[test]
fn approval_is_durable_before_visibility_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let gen_before;
    {
        let db = Database::open(&path).unwrap();
        let computers = Computers::new(db.clone());
        let policy = Policy::new(db);
        computers
            .register(c(1), &ComputerDetails::default(), None)
            .unwrap();
        gen_before = policy.generation().unwrap();
        policy
            .approve(u(5), ALL_COMPUTERS, DeploymentAction::Install, None)
            .unwrap();
        assert!(policy.generation().unwrap() > gen_before);
    }
    let policy = Policy::new(Database::open(&path).unwrap());
    assert_eq!(policy.visible_to(c(1)).unwrap().len(), 1);
}

fn ev(kind: EventKind, update: Option<UpdateRevision>, t: i64, key: Option<&str>) -> NewEvent {
    NewEvent {
        computer: c(1),
        update,
        kind,
        result_code: None,
        event_time: t,
        dedup_key: key.map(str::to_owned),
        raw: "<Event/>".into(),
    }
}

#[test]
fn events_dedup_and_derive_status_in_time_order() {
    let (_db, computers, _, reporting) = setup();
    computers
        .register(c(1), &ComputerDetails::default(), None)
        .unwrap();
    let up = UpdateRevision {
        id: u(7),
        revision: Revision(1),
    };

    let r = reporting
        .record(&ev(EventKind::DownloadCompleted, Some(up), 10, Some("k1")))
        .unwrap();
    assert!(matches!(r, RecordOutcome::Recorded { .. }));
    assert_eq!(
        reporting
            .record(&ev(EventKind::DownloadCompleted, Some(up), 10, Some("k1")))
            .unwrap(),
        RecordOutcome::Duplicate
    );
    // Same key for a different computer is not a duplicate.
    computers
        .register(c(2), &ComputerDetails::default(), None)
        .unwrap();
    let mut other = ev(EventKind::DownloadCompleted, Some(up), 10, Some("k1"));
    other.computer = c(2);
    assert!(matches!(
        reporting.record(&other).unwrap(),
        RecordOutcome::Recorded { .. }
    ));

    let mut done = ev(EventKind::InstallSucceeded, Some(up), 30, None);
    done.result_code = Some(0);
    reporting.record(&done).unwrap();
    // Late-arriving older event must not regress status, but is stored raw.
    reporting
        .record(&ev(EventKind::InstallStarted, Some(up), 20, None))
        .unwrap();
    let st = reporting.status(c(1), up).unwrap().unwrap();
    assert_eq!(
        (st.status, st.result_code),
        (UpdateStatus::Installed, Some(0))
    );
    assert_eq!(
        reporting
            .events_for_computer(c(1), None, 100)
            .unwrap()
            .len(),
        3
    );

    // Events without an update or kind Other store but leave status alone.
    reporting
        .record(&ev(EventKind::Other, Some(up), 99, None))
        .unwrap();
    reporting
        .record(&ev(EventKind::InstallFailed, None, 99, None))
        .unwrap();
    assert_eq!(
        reporting.status(c(1), up).unwrap().unwrap().status,
        UpdateStatus::Installed
    );
    let counts = reporting.status_counts(u(7)).unwrap();
    assert_eq!(counts[&UpdateStatus::Installed], 1);
    assert_eq!(counts[&UpdateStatus::Downloaded], 1);

    let mut unknown = ev(EventKind::Other, None, 1, None);
    unknown.computer = c(404);
    assert!(reporting.record(&unknown).is_err());
}
