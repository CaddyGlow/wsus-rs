//! `SyncUpdates` scope over catalogs shaped like the real Windows 11 catalog (inventory 12.17):
//! a product category and a detectoid chain as prerequisites, bundle parents whose children use
//! the `Cbs` and `OSInstaller` handlers, a withdrawn bundle member, and approvals made for the
//! `Unassigned Computers` group (the group a freshly registered client is in) by `UUID@REVISION`.
//! Observed in the real catalog on 2026-10-05: 297 `OSInstaller` and 180 `Cbs` children, all
//! with deployment action `Bundle`; 43 bundle edges point at withdrawn children. Nothing here is
//! validated against a native Windows Update Agent.
mod endpoints_common;
use endpoints_common::*;

use uuid::Uuid;
use wsus_protocol::identity::{Revision, UpdateId, UpdateRevision};
use wsus_protocol::wusp::{DeploymentAction, UpdateInfo};
use wsus_server::catalog::{FragmentImport, FragmentState, RelationshipImport, RelationshipKind};
use wsus_server::endpoints::SyncDelivery;
use wsus_server::policy::{DeploymentAction as PolicyAction, UNASSIGNED_COMPUTERS};

const MODES: [SyncDelivery; 2] = [SyncDelivery::Staged, SyncDelivery::Closure];

fn edge(f: &mut FragmentImport, kind: RelationshipKind, target: u128) {
    f.relationships.push(RelationshipImport {
        kind,
        target: uid(target),
        revision: None,
    });
}

/// A Core fragment in the WUSP shape with prerequisite clauses (a bare id is a clause of one).
fn node(n: u128, kind: &str, prereqs: &[u128], bundled: &[u128]) -> FragmentImport {
    let mut xml = format!(
        "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>",
        uid(n).0
    );
    xml.push_str(&format!("<Properties UpdateType=\"{kind}\"/>"));
    let mut f = FragmentImport::new(rev(n, 1), kind, b"");
    if !prereqs.is_empty() || !bundled.is_empty() {
        xml.push_str("<Relationships>");
        if !prereqs.is_empty() {
            xml.push_str("<Prerequisites>");
            for t in prereqs {
                xml.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", uid(*t).0));
                edge(&mut f, RelationshipKind::Prerequisite, *t);
            }
            xml.push_str("</Prerequisites>");
        }
        if !bundled.is_empty() {
            xml.push_str("<BundledUpdates>");
            for t in bundled {
                xml.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", uid(*t).0));
                edge(&mut f, RelationshipKind::Bundle, *t);
            }
            xml.push_str("</BundledUpdates>");
        }
        xml.push_str("</Relationships>");
    }
    f.core_xml = xml.into_bytes();
    f
}

const PRODUCT: u128 = 10;
const OS_DETECTOID: u128 = 11;
const ARCH_DETECTOID: u128 = 12;
const CBS_PARENT: u128 = 20;
const CBS_CHILD: u128 = 21;
const OSI_PARENT: u128 = 30;
const OSI_CHILD: u128 = 31;
const OSI_CHILD_WITHDRAWN: u128 = 32;

/// Category and detectoids shared by every update, a `Cbs` bundle (parent plus one child) and an
/// `OSInstaller` bundle (parent, a child and a withdrawn child).
fn windows_like_catalog() -> Vec<FragmentImport> {
    let mut gone = with_file(
        node(OSI_CHILD_WITHDRAWN, "Software", &[OS_DETECTOID], &[]),
        "withdrawn.psf",
        b"withdrawn",
    );
    gone.state = FragmentState::Withdrawn;
    vec![
        node(PRODUCT, "Category", &[], &[]),
        node(OS_DETECTOID, "Detectoid", &[PRODUCT], &[]),
        node(ARCH_DETECTOID, "Detectoid", &[PRODUCT], &[]),
        node(CBS_PARENT, "Software", &[OS_DETECTOID], &[CBS_CHILD]),
        with_file(
            node(CBS_CHILD, "Software", &[OS_DETECTOID, ARCH_DETECTOID], &[]),
            "windows11.0-kb5000001-x64.cab",
            b"cbs cab",
        ),
        node(
            OSI_PARENT,
            "Software",
            &[OS_DETECTOID],
            &[OSI_CHILD, OSI_CHILD_WITHDRAWN],
        ),
        with_file(
            node(OSI_CHILD, "Software", &[OS_DETECTOID], &[]),
            "windows11.0-kb5000002-x64.psf",
            b"osinstaller psf",
        ),
        gone,
    ]
}

fn approve_unassigned(env: &Env, n: u128) {
    env.policy
        .approve(uid(n), UNASSIGNED_COMPUTERS, PolicyAction::Install, None)
        .unwrap();
}

fn delivered(env: &Env, n: u128) -> Vec<UpdateInfo> {
    let mut c = registered(env, n);
    sync_rounds(env, &mut c).into_iter().flatten().collect()
}

fn find<'a>(all: &'a [UpdateInfo], env: &Env, n: u128) -> Option<&'a UpdateInfo> {
    let l = local(env, n);
    all.iter().find(|u| u.id == l)
}

fn action(u: &UpdateInfo) -> DeploymentAction {
    u.deployment
        .value()
        .expect("every UpdateInfo has a Deployment")
        .action
        .clone()
}

#[test]
fn approving_a_bundle_parent_for_the_unassigned_group_delivers_the_whole_bundle() {
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&windows_like_catalog());
        approve_unassigned(&env, CBS_PARENT);
        let all = delivered(&env, 1);
        for n in [PRODUCT, OS_DETECTOID, ARCH_DETECTOID] {
            let u = find(&all, &env, n).unwrap_or_else(|| panic!("{n} missing in {mode:?}"));
            assert!(!u.is_leaf, "{n}: prerequisite targets are non-leaf");
            assert_eq!(action(u), DeploymentAction::Evaluate, "{n}");
        }
        let parent = find(&all, &env, CBS_PARENT).expect("approved parent");
        assert_eq!(action(parent), DeploymentAction::Install, "{mode:?}");
        assert!(parent.is_leaf);
        let child = find(&all, &env, CBS_CHILD).expect("bundle child");
        assert_eq!(action(child), DeploymentAction::Bundle, "{mode:?}");
        assert!(child.is_leaf, "bundle members are leaves");
        assert!(
            find(&all, &env, OSI_PARENT).is_none() && find(&all, &env, OSI_CHILD).is_none(),
            "the other bundle was not approved"
        );
    }
}

#[test]
fn approving_a_single_child_delivers_it_with_its_prerequisites_but_not_its_parent() {
    // Observed: the two updates a lab approval used (`f1ff1e3d...@200` and `f97b86e6...@100`) are
    // bundle children in the real catalog. The server's rule is by update id, so a child is
    // offered on its own with action `Install`.
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&windows_like_catalog());
        approve_unassigned(&env, OSI_CHILD);
        let all = delivered(&env, 2);
        let child = find(&all, &env, OSI_CHILD).unwrap_or_else(|| panic!("child in {mode:?}"));
        assert_eq!(action(child), DeploymentAction::Install);
        assert!(find(&all, &env, OS_DETECTOID).is_some() && find(&all, &env, PRODUCT).is_some());
        assert!(
            find(&all, &env, OSI_PARENT).is_none(),
            "{mode:?}: edges point parent to child"
        );
    }
}

#[test]
fn a_withdrawn_bundle_member_is_dropped_and_the_rest_of_the_bundle_still_arrives() {
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&windows_like_catalog());
        approve_unassigned(&env, OSI_PARENT);
        let all = delivered(&env, 3);
        assert!(find(&all, &env, OSI_PARENT).is_some(), "{mode:?}");
        assert!(find(&all, &env, OSI_CHILD).is_some(), "{mode:?}");
        assert!(
            find(&all, &env, OSI_CHILD_WITHDRAWN).is_none(),
            "{mode:?}: withdrawn metadata is not offered"
        );
    }
}

#[test]
fn an_unapproved_bundle_parent_is_not_offered() {
    // Implementation decision, and a known difference from the real WSUS: with nothing approved
    // the real lab WSUS still delivered every Windows 11 bundle parent to the client (441
    // revisions, deployment action `PreDeploymentCheck`) next to 477 `Bundle` children. This
    // server offers an update only when it is approved for the computer or a dependency of an
    // approved update. The test pins the current rule so a change is deliberate.
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&windows_like_catalog());
        assert!(
            delivered(&env, 4).is_empty(),
            "{mode:?}: nothing approved, nothing offered"
        );
        approve_unassigned(&env, CBS_PARENT);
        let all = delivered(&env, 5);
        assert!(find(&all, &env, OSI_PARENT).is_none(), "{mode:?}");
    }
}

#[test]
fn a_new_approval_reaches_a_client_that_synchronized_before_it() {
    // The path a lab run takes: sync, approve with the admin command, sync again. The second
    // call carries the first sync's cookie and cached ids and must deliver only the new update.
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&windows_like_catalog());
        approve_unassigned(&env, CBS_PARENT);
        let mut c = registered(&env, 6);
        let first: Vec<UpdateInfo> = sync_rounds(&env, &mut c).into_iter().flatten().collect();
        assert!(find(&first, &env, CBS_PARENT).is_some());
        approve_unassigned(&env, OSI_PARENT);
        let installed: Vec<i32> = first.iter().filter(|u| !u.is_leaf).map(|u| u.id).collect();
        let other: Vec<i32> = first.iter().filter(|u| u.is_leaf).map(|u| u.id).collect();
        let info = sync(&env, &mut c, &installed, &other);
        let ids = new_ids(&info);
        assert!(
            ids.contains(&local(&env, OSI_PARENT)),
            "{mode:?}: new approval offered"
        );
        assert!(
            ids.contains(&local(&env, OSI_CHILD)),
            "{mode:?}: its child offered"
        );
        assert!(
            !ids.contains(&local(&env, CBS_PARENT)),
            "{mode:?}: nothing offered twice"
        );
    }
}

/// Real Core fragment of the OS installer update `f97b86e6-5c6c-4366-b948-b5426295a5a7@100`
/// (`docs/fixtures/wsus-m0-cbs`): prerequisites are two categories (`AtLeastOne IsCategory`)
/// and two detectoids.
const REAL_OSINSTALLER_CORE: &str =
    include_str!("../../../docs/fixtures/wsus-m0-cbs/osinstaller-core.xml");

fn real(id: &str, revision: u32) -> UpdateRevision {
    UpdateRevision {
        id: UpdateId(Uuid::parse_str(id).unwrap()),
        revision: Revision(revision),
    }
}

#[test]
fn the_real_os_installer_core_fragment_is_offered_unchanged_after_an_unassigned_group_approval() {
    let update = "f97b86e6-5c6c-4366-b948-b5426295a5a7";
    let prereqs = [
        ("72e7624a-5b00-45d2-b92f-e561c0a6a160", "Category"),
        ("0fa1201d-4330-4fa8-8ae9-b877473b6441", "Category"),
        ("e657ef08-e43d-4326-aa4c-6fee197e8192", "Detectoid"),
        ("03aa8476-15b7-4288-bf9b-286b31f99bd6", "Detectoid"),
    ];
    for mode in MODES {
        let env = setup_mode(mode);
        let mut frags: Vec<FragmentImport> = prereqs
            .iter()
            .map(|(id, kind)| {
                FragmentImport::new(
                    real(id, 100),
                    kind,
                    format!("<UpdateIdentity UpdateID=\"{id}\" RevisionNumber=\"100\"/>")
                        .as_bytes(),
                )
            })
            .collect();
        let mut f = FragmentImport::new(
            real(update, 100),
            "Software",
            REAL_OSINSTALLER_CORE.as_bytes(),
        );
        for (id, kind) in &prereqs {
            f.relationships.push(RelationshipImport {
                kind: if *kind == "Category" {
                    RelationshipKind::Category
                } else {
                    RelationshipKind::Prerequisite
                },
                target: UpdateId(Uuid::parse_str(id).unwrap()),
                revision: None,
            });
        }
        frags.push(f);
        env.publish(&frags);
        env.policy
            .approve(
                UpdateId(Uuid::parse_str(update).unwrap()),
                UNASSIGNED_COMPUTERS,
                PolicyAction::Install,
                None,
            )
            .unwrap();
        let all = delivered(&env, 7);
        let l = env
            .catalog
            .find_local_id(real(update, 100))
            .unwrap()
            .unwrap()
            .id;
        let u = all
            .iter()
            .find(|u| u.id == l)
            .unwrap_or_else(|| panic!("real update missing in {mode:?}"));
        assert_eq!(action(u), DeploymentAction::Install);
        assert_eq!(
            u.xml.value().map(String::as_str),
            Some(REAL_OSINSTALLER_CORE),
            "{mode:?}: the Core fragment is served exactly as stored"
        );
        assert_eq!(
            all.len(),
            5,
            "{mode:?}: the update and its four prerequisites"
        );
    }
}
