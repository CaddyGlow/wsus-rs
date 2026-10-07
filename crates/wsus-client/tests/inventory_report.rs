//! The client status event `156` (the `U` and `V` lists): evaluated from a synthetic catalog and a
//! fake fact provider, queued durably, de-duplicated, delivered by the existing flush against the
//! fake server. The wire shape is the one recorded from a native Windows Update Agent (inventory
//! 9.11, ledger C77 and C78); the catalog, the facts and the fake server are models, not evidence.

mod session_common;

use session_common::*;
use std::path::Path;
use tempfile::TempDir;
use uuid::Uuid;
use wsus_client::{
    install::{
        PlanOptions,
        job::PostCheck,
        testkit::{Child, rev, write_bundle},
    },
    reporting::{
        EventQueue, QueueConfig,
        inventory::{
            CLIENT_STATUS, Inventory, InventoryQueued, evaluate_inventory, inventory_event,
            inventory_scope, queue_inventory,
        },
    },
    sync::{Catalog, DeploymentSummary, RevisionStore},
};
use wsus_protocol::{
    applicability::{FactProvider, FakeFacts},
    identity::UpdateId,
    soap::Limits,
};

const ROOT_INSTALLED: u128 = 0x10;
const ROOT_MISSING: u128 = 0x20;
const ROOT_NOT_APPLICABLE: u128 = 0x30;
const CHILD_INSTALLED: u128 = 0x11;
const CHILD_MISSING: u128 = 0x21;
const CHILD_NOT_APPLICABLE: u128 = 0x31;

fn child(id: u128, installed_at: u32, applicable: bool) -> Child {
    let mut c = Child::new(id, &format!("c{id}.exe"), b"payload");
    c.installed = format!(
        r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Test" Value="Version" Comparison="GreaterThanOrEqualTo" Data="{installed_at}" />"#
    );
    c.installable = Some(if applicable {
        r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Test" />"#.into()
    } else {
        r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Absent" />"#.into()
    });
    c
}

/// Three deployed bundle roots (leaf software updates) with one non-leaf installer child each: one
/// whose child evaluates installed at Version 2, one that needs Version 5, one never applicable.
fn catalog(dir: &Path) -> Catalog {
    prepare(dir);
    load(dir)
}

fn load(dir: &Path) -> Catalog {
    let ro = RevisionStore::open_read_only(dir).unwrap();
    Catalog::load(&ro, &Limits::default()).unwrap()
}

fn prepare(dir: &Path) {
    let kids = [
        (ROOT_INSTALLED, child(CHILD_INSTALLED, 2, true)),
        (ROOT_MISSING, child(CHILD_MISSING, 5, true)),
        (ROOT_NOT_APPLICABLE, child(CHILD_NOT_APPLICABLE, 99, false)),
    ];
    for (root, c) in &kids {
        write_bundle(dir, *root, None, &[vec![c.clone()]]);
    }
    let store = RevisionStore::open(dir).unwrap();
    for (root, c) in &kids {
        let mut r = store.get(&c.revision()).unwrap().unwrap();
        r.is_leaf = false;
        store.put(&r).unwrap();
        let mut r = store.get(&rev(*root)).unwrap().unwrap();
        r.deployment = Some(DeploymentSummary {
            id: 7,
            action: "Install".into(),
            is_assigned: true,
            deadline: None,
            last_change_time: "2026-10-06T00:00:00Z".into(),
        });
        store.put(&r).unwrap();
    }
}

fn facts(version: u32) -> FakeFacts {
    let mut f = FakeFacts::windows11_x64();
    f.set_dword("SOFTWARE\\Test", "Version", version);
    f
}

fn id(n: u128) -> UpdateId {
    rev(n).id
}

fn evaluate(cat: &Catalog, f: &dyn FactProvider, pc: Option<&PostCheck>) -> Inventory {
    evaluate_inventory(cat, f, &PlanOptions::default(), pc)
}

#[test]
fn only_the_leaf_software_updates_are_in_scope_and_split_by_the_verdicts() {
    let dir = TempDir::new().unwrap();
    let cat = catalog(dir.path());
    // The three roots only: the installer children are not leaves.
    assert_eq!(inventory_scope(&cat).len(), 3);
    let inv = evaluate(&cat, &facts(3), None);
    assert_eq!(inv.installed, [id(ROOT_INSTALLED)]);
    assert_eq!(inv.not_installed, [id(ROOT_MISSING)]);
    assert_eq!((inv.left_out, inv.unknown), (1, 0));
    // The wire strings: update ids (not revisions), upper case, one string per list.
    let misc = inv.misc_lists();
    assert_eq!(misc.len(), 2);
    assert_eq!(misc[0], format!("U={}", id(ROOT_MISSING)).to_uppercase());
    assert_eq!(misc[1], format!("V={}", id(ROOT_INSTALLED)).to_uppercase());
    // Once the update is installed it moves between the lists.
    let inv = evaluate(&cat, &facts(5), None);
    assert!(inv.not_installed.is_empty());
    assert_eq!(inv.installed, [id(ROOT_INSTALLED), id(ROOT_MISSING)]);
}

#[test]
fn bundle_deployments_are_not_in_scope() {
    let dir = TempDir::new().unwrap();
    prepare(dir.path());
    // The updates other deployed updates bundle arrive as `Bundle` deployments: a native agent
    // listed none of them (ledger C77).
    let store = RevisionStore::open(dir.path()).unwrap();
    let mut r = store.get(&rev(ROOT_MISSING)).unwrap().unwrap();
    r.deployment.as_mut().unwrap().action = "Bundle".into();
    store.put(&r).unwrap();
    // An update without a deployment of its own is out of scope too.
    let mut r = store.get(&rev(ROOT_INSTALLED)).unwrap().unwrap();
    r.deployment = None;
    store.put(&r).unwrap();
    let cat = load(dir.path());
    assert_eq!(inventory_scope(&cat), [rev(ROOT_NOT_APPLICABLE)]);
}

#[test]
fn an_installed_update_superseded_by_an_installed_update_is_in_neither_list() {
    let dir = TempDir::new().unwrap();
    prepare(dir.path());
    // A newer root (its child installs at Version 2 as well) that supersedes the installed one.
    let newer = child(0x41, 2, true);
    write_bundle(dir.path(), 0x40, None, &[vec![newer.clone()]]);
    let store = RevisionStore::open(dir.path()).unwrap();
    let mut r = store.get(&newer.revision()).unwrap().unwrap();
    r.is_leaf = false;
    store.put(&r).unwrap();
    let mut r = store.get(&rev(0x40)).unwrap().unwrap();
    r.deployment = Some(DeploymentSummary {
        id: 8,
        action: "Install".into(),
        is_assigned: true,
        deadline: None,
        last_change_time: "2026-10-06T00:00:00Z".into(),
    });
    // The superseding root has no IsInstalled rule of its own: it counts as installed through the
    // planner's verdict (its installer child evaluates installed), as the lists' verdicts do.
    r.core.xml = r.core.xml.replace(
        "</Relationships>",
        &format!(
            r#"<SupersededUpdates><UpdateIdentity UpdateID="{}" /></SupersededUpdates></Relationships>"#,
            id(ROOT_INSTALLED)
        ),
    );
    store.put(&r).unwrap();
    let cat = load(dir.path());
    let inv = evaluate(&cat, &facts(3), None);
    // The old one is gone from the lists, the newer one is installed, the missing one stays.
    assert_eq!(inv.installed, [id(0x40)]);
    assert_eq!(inv.not_installed, [id(ROOT_MISSING)]);
    // Not installed superseder: the old update stays on the installed list.
    let inv = evaluate(&cat, &facts(1), None);
    assert!(inv.installed.is_empty());
}

#[test]
fn a_missing_fact_is_left_out_not_guessed() {
    let dir = TempDir::new().unwrap();
    let cat = catalog(dir.path());
    // A provider that answers nothing: every verdict is Unknown, nothing is listed.
    struct NoFacts;
    impl FactProvider for NoFacts {}
    let inv = evaluate(&cat, &NoFacts, None);
    assert!(inv.installed.is_empty() && inv.not_installed.is_empty());
    assert_eq!((inv.left_out, inv.unknown), (3, 3));
    assert!(inv.misc_lists().is_empty());
}

#[test]
fn the_job_post_check_decides_for_the_updates_it_executed() {
    let dir = TempDir::new().unwrap();
    let cat = catalog(dir.path());
    // Version 5: the live facts say the update is installed, but the job's own check (an install
    // waiting for a restart) said not installed: it stays on the not-installed list.
    let pc = PostCheck {
        performed: true,
        not_installed: vec![rev(CHILD_MISSING).to_string()],
        ..PostCheck::default()
    };
    let inv = evaluate(&cat, &facts(5), Some(&pc));
    assert_eq!(inv.not_installed, [id(ROOT_MISSING)]);
    assert_eq!(inv.installed, [id(ROOT_INSTALLED)]);
    // The other way round: the job saw it installed (the child maps to the deployed root).
    let pc = PostCheck {
        performed: true,
        installed: vec![rev(CHILD_MISSING).to_string()],
        ..PostCheck::default()
    };
    let inv = evaluate(&cat, &facts(3), Some(&pc));
    assert!(inv.not_installed.is_empty());
    assert_eq!(inv.installed, [id(ROOT_INSTALLED), id(ROOT_MISSING)]);
    // A post-check that was not performed changes nothing.
    let pc = PostCheck {
        performed: false,
        installed: vec![rev(CHILD_MISSING).to_string()],
        ..PostCheck::default()
    };
    assert_eq!(
        evaluate(&cat, &facts(3), Some(&pc)).not_installed,
        [id(ROOT_MISSING)]
    );
}

#[test]
fn the_event_has_the_native_156_shape() {
    let inv = Inventory {
        not_installed: vec![id(2)],
        installed: vec![id(1)],
        ..Inventory::default()
    };
    let e = inventory_event(
        &inv,
        "2026-10-06T14:56:40Z",
        "wsus-client",
        Uuid::from_u128(9),
    );
    assert_eq!(
        (e.namespace_id, e.event_id, e.source_id, e.sequence_number),
        (1, CLIENT_STATUS, 101, 0)
    );
    assert_eq!(e.win32_hresult, 0);
    let u = e.update.unwrap();
    assert_eq!((u.id.0, u.revision.0), (Uuid::nil(), 0));
    let d = e.detail.unwrap();
    assert!(d.replacement_strings.is_empty());
    assert_eq!(d.misc_data.len(), 3);
    assert!(d.misc_data[0].starts_with("U=00000000-0000-0000-0000-000000000002"));
    assert!(d.misc_data[1].starts_with("V=00000000-0000-0000-0000-000000000001"));
    assert_eq!(d.misc_data[2], "AppName=wsus-client");
}

fn queue(h: &Harness) -> EventQueue {
    EventQueue::open(h.dir.path().join("events"), QueueConfig::default()).unwrap()
}

fn inv(u: &[u128], v: &[u128]) -> Inventory {
    Inventory {
        not_installed: u.iter().map(|n| id(*n)).collect(),
        installed: v.iter().map(|n| id(*n)).collect(),
        ..Inventory::default()
    }
}

fn q(h: &Harness, queue: &mut EventQueue, i: &Inventory, force: bool) -> InventoryQueued {
    queue_inventory(
        queue,
        &h.dir.path().join("events"),
        i,
        "2026-10-06T14:56:40Z",
        "wsus-client",
        force,
    )
    .unwrap()
}

#[tokio::test]
async fn the_inventory_is_queued_once_delivered_once_and_requeued_when_it_changes() {
    let h = Harness::new();
    let mut queue = queue(&h);
    let a = inv(&[2], &[1]);
    assert!(matches!(
        q(&h, &mut queue, &a, false),
        InventoryQueued::Queued { .. }
    ));
    // Evaluated again before delivery: nothing new.
    assert!(matches!(
        q(&h, &mut queue, &a, false),
        InventoryQueued::Unchanged { .. }
    ));
    assert_eq!(queue.len(), 1);

    let mut e = h.engine();
    let out = e.flush_events(&mut queue, 10).await.unwrap();
    assert_eq!((out.batches, out.delivered), (1, 1));
    {
        let f = h.fake();
        let w = f.reported_events[0].basic_data.value().unwrap();
        assert_eq!((w.event_id, w.namespace_id, w.source_id), (156, 1, 101));
        let u = w.update_id.value().unwrap();
        assert_eq!((u.id.0, u.revision.0), (Uuid::nil(), 0));
        let x = f.reported_events[0].extended_data.value().unwrap();
        assert!(x.replacement_strings.value().is_none());
        let misc = x.misc_data.value().unwrap();
        assert!(misc[0].starts_with("U=") && misc[1].starts_with("V="));
        assert_eq!(misc[2], "AppName=wsus-client");
        assert!(f.reported_events[0].private_data.value().is_some());
    }

    // Delivered and unchanged: still nothing to send.
    assert!(matches!(
        q(&h, &mut queue, &a, false),
        InventoryQueued::Unchanged { .. }
    ));
    assert!(queue.is_empty());

    // The update moved to the installed list: a new event.
    let b = inv(&[], &[1, 2]);
    assert!(matches!(
        q(&h, &mut queue, &b, false),
        InventoryQueued::Queued { .. }
    ));
    let out = e.flush_events(&mut queue, 10).await.unwrap();
    assert_eq!(out.delivered, 1);
    {
        let f = h.fake();
        let x = f.reported_events[1].extended_data.value().unwrap();
        let misc = x.misc_data.value().unwrap();
        // The empty list has no entry at all.
        assert_eq!(misc.len(), 2);
        assert!(misc[0].starts_with("V="));
    }

    // Back to the first inventory (installed, removed): sent again, not suppressed as delivered.
    assert!(matches!(
        q(&h, &mut queue, &a, false),
        InventoryQueued::Queued { .. }
    ));
    // An explicit resend of an unchanged inventory is a fresh event.
    let before = queue.len();
    assert!(matches!(
        q(&h, &mut queue, &a, true),
        InventoryQueued::Queued { .. }
    ));
    assert_eq!(queue.len(), before + 1);
    let out = e.flush_events(&mut queue, 10).await.unwrap();
    assert_eq!(out.delivered, 2);
    let ids: std::collections::BTreeSet<Uuid> = h.fake().reported.iter().copied().collect();
    assert_eq!(ids.len(), 4);
}

#[tokio::test]
async fn a_lost_response_resends_the_same_instance_id() {
    let h = Harness::new();
    let mut queue = queue(&h);
    let a = inv(&[2], &[1]);
    let InventoryQueued::Queued { instance_id } = q(&h, &mut queue, &a, false) else {
        panic!("queued");
    };
    // Queued, not delivered (offline): a later evaluation of the same lists does not add a second.
    assert!(matches!(
        q(&h, &mut queue, &a, false),
        InventoryQueued::Unchanged { .. }
    ));
    assert_eq!(
        queue.pending(10)[0].dedup_key,
        instance_id.hyphenated().to_string()
    );
    assert_eq!(queue.len(), 1);
}
