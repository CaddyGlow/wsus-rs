//! `[server] delivery_scope = "all_non_declined"` over a catalog shaped like the real Windows 11
//! catalog. Real evidence (inventory 12.19, a fresh client against the lab WSUS with nothing
//! approved for Windows 11): every non-declined update arrived (5,224 revisions), deployment
//! `Action` `Evaluate` for detectoids and categories, `PreDeploymentCheck` for the 441 unapproved
//! bundle parents, `Bundle` for the 561 bundle members and `Install` for the approved ones; 0 of
//! the 3,982 declined updates arrived. The `approved` scope is pinned by
//! `endpoints_windows_shape.rs`. Nothing here is validated against a native agent.
mod endpoints_common;
use endpoints_common::*;

use wsus_protocol::wusp::{DeploymentAction, UpdateInfo};
use wsus_server::catalog::{FragmentImport, FragmentState, RelationshipImport, RelationshipKind};
use wsus_server::endpoints::{DeliveryScope, ServerConfig, SyncDelivery};
use wsus_server::policy::{DeploymentAction as PolicyAction, UNASSIGNED_COMPUTERS};

const PRODUCT: u128 = 10;
const OS_DETECTOID: u128 = 11;
const CBS_PARENT: u128 = 20;
const CBS_CHILD: u128 = 21;
const OSI_PARENT: u128 = 30;
const OSI_CHILD: u128 = 31;
const OSI_CHILD_WITHDRAWN: u128 = 32;
const SHARED_CHILD: u128 = 40;
const PARENT_A: u128 = 41;
const PARENT_B: u128 = 42;
const STANDALONE: u128 = 50;
const NEEDS_UNINSTALLED: u128 = 60;
const OTHER_DETECTOID: u128 = 61;

fn config(mode: SyncDelivery, scope: DeliveryScope) -> ServerConfig {
    ServerConfig {
        delivery_scope: scope,
        ..config_for(mode)
    }
}

fn node(n: u128, kind: &str, prereqs: &[u128], bundled: &[u128]) -> FragmentImport {
    let mut xml = format!(
        "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/><Properties UpdateType=\"{kind}\"/>",
        uid(n).0
    );
    let mut f = FragmentImport::new(rev(n, 1), kind, b"");
    if !prereqs.is_empty() || !bundled.is_empty() {
        xml.push_str("<Relationships>");
        if !prereqs.is_empty() {
            xml.push_str("<Prerequisites>");
            for t in prereqs {
                xml.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", uid(*t).0));
                f.relationships.push(RelationshipImport {
                    kind: RelationshipKind::Prerequisite,
                    target: uid(*t),
                    revision: None,
                });
            }
            xml.push_str("</Prerequisites>");
        }
        if !bundled.is_empty() {
            xml.push_str("<BundledUpdates>");
            for t in bundled {
                xml.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", uid(*t).0));
                f.relationships.push(RelationshipImport {
                    kind: RelationshipKind::Bundle,
                    target: uid(*t),
                    revision: None,
                });
            }
            xml.push_str("</BundledUpdates>");
        }
        xml.push_str("</Relationships>");
    }
    f.core_xml = xml.into_bytes();
    f
}

fn catalog() -> Vec<FragmentImport> {
    let mut gone = node(OSI_CHILD_WITHDRAWN, "Software", &[OS_DETECTOID], &[]);
    gone.state = FragmentState::Withdrawn;
    vec![
        node(PRODUCT, "Category", &[], &[]),
        node(OS_DETECTOID, "Detectoid", &[PRODUCT], &[]),
        node(OTHER_DETECTOID, "Detectoid", &[PRODUCT], &[]),
        node(CBS_PARENT, "Software", &[OS_DETECTOID], &[CBS_CHILD]),
        with_file(
            node(CBS_CHILD, "Software", &[OS_DETECTOID], &[]),
            "kb1.cab",
            b"cab",
        ),
        node(
            OSI_PARENT,
            "Software",
            &[OS_DETECTOID],
            &[OSI_CHILD, OSI_CHILD_WITHDRAWN],
        ),
        node(OSI_CHILD, "Software", &[OS_DETECTOID], &[]),
        gone,
        node(PARENT_A, "Software", &[OS_DETECTOID], &[SHARED_CHILD]),
        node(PARENT_B, "Software", &[OS_DETECTOID], &[SHARED_CHILD]),
        node(SHARED_CHILD, "Software", &[OS_DETECTOID], &[]),
        node(STANDALONE, "Software", &[OS_DETECTOID], &[]),
        node(NEEDS_UNINSTALLED, "Software", &[OTHER_DETECTOID], &[]),
    ]
}

fn env(mode: SyncDelivery, scope: DeliveryScope) -> Env {
    let e = setup_with(config(mode, scope));
    e.publish(&catalog());
    e
}

fn delivered(e: &Env, n: u128) -> Vec<UpdateInfo> {
    let mut c = registered(e, n);
    sync_rounds(e, &mut c).into_iter().flatten().collect()
}

fn find<'a>(all: &'a [UpdateInfo], e: &Env, n: u128) -> Option<&'a UpdateInfo> {
    let l = local(e, n);
    all.iter().find(|u| u.id == l)
}

fn action(u: &UpdateInfo) -> DeploymentAction {
    u.deployment.value().expect("deployment").action.clone()
}

fn approve(e: &Env, n: u128) {
    e.policy
        .approve(uid(n), UNASSIGNED_COMPUTERS, PolicyAction::Install, None)
        .unwrap();
}

#[test]
fn with_nothing_approved_every_non_declined_update_is_offered_with_the_real_actions() {
    for mode in MODES {
        let e = env(mode, DeliveryScope::AllNonDeclined);
        let all = delivered(&e, 1);
        for n in [PRODUCT, OS_DETECTOID, OTHER_DETECTOID] {
            let u = find(&all, &e, n).unwrap_or_else(|| panic!("{n} {mode:?}"));
            assert_eq!(action(u), DeploymentAction::Evaluate, "{n} {mode:?}");
        }
        for n in [CBS_PARENT, OSI_PARENT, PARENT_A, PARENT_B, STANDALONE] {
            let u = find(&all, &e, n).unwrap_or_else(|| panic!("{n} {mode:?}"));
            assert_eq!(
                action(u),
                DeploymentAction::PreDeploymentCheck,
                "{n} {mode:?}"
            );
            assert!(u.is_leaf, "{n}: software is a leaf");
        }
        for n in [CBS_CHILD, OSI_CHILD, SHARED_CHILD] {
            let u = find(&all, &e, n).unwrap_or_else(|| panic!("{n} {mode:?}"));
            assert_eq!(action(u), DeploymentAction::Bundle, "{n} {mode:?}");
        }
        assert!(
            find(&all, &e, OSI_CHILD_WITHDRAWN).is_none(),
            "withdrawn metadata is not offered"
        );
    }
}

#[test]
fn an_approval_still_decides_the_action_of_that_update_only() {
    for mode in MODES {
        let e = env(mode, DeliveryScope::AllNonDeclined);
        approve(&e, CBS_PARENT);
        let all = delivered(&e, 2);
        assert_eq!(
            action(find(&all, &e, CBS_PARENT).unwrap()),
            DeploymentAction::Install,
            "{mode:?}"
        );
        assert_eq!(
            action(find(&all, &e, OSI_PARENT).unwrap()),
            DeploymentAction::PreDeploymentCheck,
            "{mode:?}: the unapproved parent is still offered"
        );
        assert_eq!(
            action(find(&all, &e, CBS_CHILD).unwrap()),
            DeploymentAction::Bundle,
            "{mode:?}"
        );
    }
}

#[test]
fn a_declined_update_and_the_members_only_it_bundles_are_not_offered() {
    for mode in MODES {
        let e = env(mode, DeliveryScope::AllNonDeclined);
        e.policy.decline(uid(OSI_PARENT)).unwrap();
        let all = delivered(&e, 3);
        assert!(find(&all, &e, OSI_PARENT).is_none(), "{mode:?}");
        assert!(
            find(&all, &e, OSI_CHILD).is_none(),
            "{mode:?}: members of a declined bundle only"
        );
        assert!(find(&all, &e, CBS_PARENT).is_some(), "{mode:?}");
        e.policy.undecline(uid(OSI_PARENT)).unwrap();
        let again = delivered(&e, 4);
        assert!(
            find(&again, &e, OSI_PARENT).is_some(),
            "{mode:?}: undecline"
        );
        assert!(find(&again, &e, OSI_CHILD).is_some(), "{mode:?}");
    }
}

#[test]
fn a_member_stays_while_any_of_its_bundles_is_not_declined() {
    for mode in MODES {
        let e = env(mode, DeliveryScope::AllNonDeclined);
        e.policy.decline(uid(PARENT_A)).unwrap();
        let all = delivered(&e, 5);
        assert!(find(&all, &e, PARENT_A).is_none(), "{mode:?}");
        assert!(
            find(&all, &e, SHARED_CHILD).is_some(),
            "{mode:?}: PARENT_B is live"
        );
        e.policy.decline(uid(PARENT_B)).unwrap();
        let none = delivered(&e, 6);
        assert!(
            find(&none, &e, SHARED_CHILD).is_none(),
            "{mode:?}: both declined"
        );
    }
}

#[test]
fn staged_delivery_still_waits_for_installed_prerequisites() {
    // The first call reports nothing installed: only updates without unsatisfied prerequisite
    // clauses arrive. Everything behind the unevaluated detectoids stays back, which is how the
    // real WSUS did not deliver 29 non-declined updates to the fresh client (INFERRED cause).
    let e = env(SyncDelivery::Staged, DeliveryScope::AllNonDeclined);
    let mut c = registered(&e, 7);
    let first = sync(&e, &mut c, &[], &[]);
    let ids = new_ids(&first);
    assert!(ids.contains(&local(&e, PRODUCT)), "no prerequisites");
    assert!(
        !ids.contains(&local(&e, NEEDS_UNINSTALLED)) && !ids.contains(&local(&e, CBS_PARENT)),
        "prerequisites not installed yet"
    );
    // A client that says the detectoid is not installed never receives its dependents.
    let installed = vec![local(&e, PRODUCT)];
    let second = sync(&e, &mut c, &installed, &[]);
    let ids2 = new_ids(&second);
    assert!(ids2.contains(&local(&e, OS_DETECTOID)) && ids2.contains(&local(&e, OTHER_DETECTOID)));
    assert!(!ids2.contains(&local(&e, NEEDS_UNINSTALLED)));
    let third = sync(
        &e,
        &mut c,
        &[local(&e, PRODUCT), local(&e, OS_DETECTOID)],
        &[],
    );
    let ids3 = new_ids(&third);
    assert!(ids3.contains(&local(&e, CBS_PARENT)));
    assert!(
        !ids3.contains(&local(&e, NEEDS_UNINSTALLED)),
        "its detectoid is still not reported installed"
    );
}

#[test]
fn the_default_scope_is_unchanged_and_never_emits_pre_deployment_check() {
    for mode in MODES {
        let e = env(mode, DeliveryScope::Approved);
        assert!(
            delivered(&e, 8).is_empty(),
            "{mode:?}: nothing approved, nothing offered"
        );
        approve(&e, CBS_PARENT);
        let all = delivered(&e, 9);
        assert!(
            all.iter()
                .all(|u| action(u) != DeploymentAction::PreDeploymentCheck),
            "{mode:?}"
        );
        assert!(find(&all, &e, OSI_PARENT).is_none(), "{mode:?}");
    }
    assert_eq!(
        ServerConfig::default().delivery_scope,
        DeliveryScope::Approved
    );
}

#[test]
fn the_scope_changes_the_configuration_fingerprint_only_when_it_is_not_the_default() {
    let base = config(SyncDelivery::Staged, DeliveryScope::Approved).fingerprint();
    assert_eq!(base, ServerConfig::default().fingerprint());
    let all = config(SyncDelivery::Staged, DeliveryScope::AllNonDeclined).fingerprint();
    assert_ne!(base, all);
}

#[test]
fn delivery_scope_names_round_trip_and_unknown_values_are_rejected() {
    for s in [DeliveryScope::Approved, DeliveryScope::AllNonDeclined] {
        assert_eq!(s.as_str().parse::<DeliveryScope>().unwrap(), s);
    }
    assert!("everything".parse::<DeliveryScope>().is_err());
}

#[test]
fn a_new_approval_after_an_earlier_sync_changes_the_deployment_without_redelivery() {
    // The cached index is keyed by the policy generation: an approval after the first sync must
    // be visible to the next call (as a changed deployment), not hidden by a stale cache.
    let e = env(SyncDelivery::Staged, DeliveryScope::AllNonDeclined);
    let mut c = registered(&e, 10);
    let first: Vec<UpdateInfo> = sync_rounds(&e, &mut c).into_iter().flatten().collect();
    assert_eq!(
        action(find(&first, &e, CBS_PARENT).unwrap()),
        DeploymentAction::PreDeploymentCheck
    );
    approve(&e, CBS_PARENT);
    let installed: Vec<i32> = first.iter().filter(|u| !u.is_leaf).map(|u| u.id).collect();
    let other: Vec<i32> = first.iter().filter(|u| u.is_leaf).map(|u| u.id).collect();
    let info = sync(&e, &mut c, &installed, &other);
    assert!(new_ids(&info).is_empty(), "nothing is offered twice");
    let changed = info.changed_updates.value().cloned().unwrap_or_default();
    let u = changed
        .iter()
        .find(|u| u.id == local(&e, CBS_PARENT))
        .expect("the approval is reported as a changed deployment");
    assert_eq!(action(u), DeploymentAction::Install);
}

#[test]
fn file_locations_for_content_that_was_never_downloaded_follow_the_scope() {
    // Observed on the real WSUS (inventory 12.17): `GetFileLocations` answered with a location for
    // the file of an update it had never downloaded (the URL then returned 404). The default scope
    // keeps announcing only content that verified.
    use wsus_protocol::soap::Presence;
    use wsus_protocol::wusp::GetFileLocations;
    let data = b"never downloaded";
    for (scope, expected) in [
        (DeliveryScope::Approved, 0usize),
        (DeliveryScope::AllNonDeclined, 1),
    ] {
        let e = setup_with(config(SyncDelivery::Staged, scope));
        e.publish(&[with_file(node(1, "Software", &[], &[]), "x.cab", data)]);
        approve(&e, 1);
        let c = registered(&e, 11);
        let r = e
            .call(&GetFileLocations {
                cookie: Presence::Value(c.cookie.clone()),
                file_digests: Presence::Value(vec![sha1_of(data)]),
            })
            .unwrap()
            .result
            .into_value()
            .unwrap();
        let n = r.file_locations.value().map_or(0, |v| v.len());
        assert_eq!(n, expected, "{scope:?}");
    }
}
