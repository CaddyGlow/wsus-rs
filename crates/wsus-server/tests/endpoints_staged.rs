//! Staged `SyncUpdates` delivery, `StartCategoryScan`, the advertised `ProtocolVersion` and the
//! closure mode's differences. Observations cited here are from the real WSUS (WS2025
//! 10.0.26100) and native client captures in `docs/fixtures/wsus-m0-native` (inventory 5.3,
//! 9.1, 9.3). Nothing here is validated against a native Windows Update Agent.
mod endpoints_common;
use endpoints_common::*;

use uuid::Uuid;
use wsus_protocol::identity::Revision;
use wsus_protocol::soap::{ErrorCode, Presence};
use wsus_protocol::wusp::{CategoryRelationship, StartCategoryScan};
use wsus_server::catalog::{FragmentImport, RelationshipImport, RelationshipKind};
use wsus_server::endpoints::{ServerConfig, SyncDelivery};

fn prop(c: &wsus_protocol::wusp::Config, name: &str) -> String {
    c.properties
        .value()
        .unwrap()
        .iter()
        .find(|p| p.name.value().map(String::as_str) == Some(name))
        .and_then(|p| p.value.value().cloned())
        .unwrap()
}

#[test]
fn protocol_version_follows_the_delivery_mode_and_can_be_overridden() {
    // Staged delivery serves what 3.2 clients expect (StartCategoryScan, installed-list driven
    // delivery), as the real server does; closure delivery keeps the earlier 3.0.
    assert_eq!(
        prop(
            &get_config(&setup_mode(SyncDelivery::Staged)),
            "ProtocolVersion"
        ),
        "3.2"
    );
    assert_eq!(
        prop(
            &get_config(&setup_mode(SyncDelivery::Closure)),
            "ProtocolVersion"
        ),
        "3.0"
    );
    let mut cfg = config_for(SyncDelivery::Staged);
    cfg.protocol_version = Some("3.0".into());
    assert_eq!(
        prop(&get_config(&setup_with(cfg)), "ProtocolVersion"),
        "3.0"
    );
    // The advertised version is part of the configuration fingerprint (clients re-handshake).
    assert_ne!(
        ServerConfig::default().fingerprint(),
        ServerConfig::closure().fingerprint()
    );
}

fn relationship(f: &mut FragmentImport, kind: RelationshipKind, target: u128) {
    f.relationships.push(RelationshipImport {
        kind,
        target: uid(target),
        revision: None,
    });
}

/// Update `n` whose Core slot holds a WUSP fragment with the given prerequisite clauses, and
/// the matching flattened relationship rows (what the importer would store).
fn with_clauses(n: u128, clauses: &[&[u128]]) -> FragmentImport {
    let mut xml = format!(
        "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/>",
        uid(n).0
    );
    xml.push_str("<Properties UpdateType=\"Software\"/>");
    let mut f = FragmentImport::new(rev(n, 1), "Software", b"");
    if !clauses.is_empty() {
        xml.push_str("<Relationships><Prerequisites>");
        for c in clauses {
            if c.len() == 1 {
                xml.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", uid(c[0]).0));
            } else {
                xml.push_str("<AtLeastOne>");
                for t in *c {
                    xml.push_str(&format!("<UpdateIdentity UpdateID=\"{}\"/>", uid(*t).0));
                }
                xml.push_str("</AtLeastOne>");
            }
            for t in *c {
                relationship(&mut f, RelationshipKind::Prerequisite, *t);
            }
        }
        xml.push_str("</Prerequisites></Relationships>");
    }
    f.core_xml = xml.into_bytes();
    f
}

#[test]
fn a_leaf_is_delivered_only_when_every_prerequisite_clause_is_satisfied_by_the_installed_list() {
    // 4 needs (1) AND (2 OR 3). The AtLeastOne structure is read from the Core fragment; the
    // relationship table alone cannot express it.
    let env = setup_mode(SyncDelivery::Staged);
    env.publish(&[
        with_clauses(1, &[]),
        with_clauses(2, &[]),
        with_clauses(3, &[]),
        with_clauses(4, &[&[1], &[2, 3]]),
    ]);
    env.approve(4);
    let (l1, l2, l3, l4) = (
        local(&env, 1),
        local(&env, 2),
        local(&env, 3),
        local(&env, 4),
    );
    let mut c = registered(&env, 1001);
    let first = sync(&env, &mut c, &[], &[]);
    assert_eq!(
        new_ids(&first),
        vec![l1, l2, l3],
        "the three roots, non-leaf, by id"
    );
    let ask =
        |env: &Env, c: &mut Client, inst: &[i32], oth: &[i32]| new_ids(&sync(env, c, inst, oth));
    // 1 installed, 2 and 3 evaluated not installed: the AND group is open, 4 is withheld.
    assert!(ask(&env, &mut c, &[l1], &[l2, l3]).is_empty());
    // 2 installed but 1 not: the OR group is satisfied, the AND group is not.
    assert!(ask(&env, &mut c, &[l2], &[l1, l3]).is_empty());
    // Either alternative of the OR group completes it.
    assert_eq!(ask(&env, &mut c, &[l1, l2], &[l3]), vec![l4]);
    assert_eq!(ask(&env, &mut c, &[l1, l3], &[l2]), vec![l4]);
    // Cached but not "installed" does not count (Observed: a prerequisite is satisfied only
    // when its id is in InstalledNonLeafUpdateIDs).
    assert!(ask(&env, &mut c, &[], &[l1, l2, l3]).is_empty());
}

#[test]
fn cached_revisions_with_unsatisfied_prerequisites_are_answered_out_of_scope() {
    // Lab observation recorded in the inventory (raw exchange not retained): a cached
    // revision whose prerequisite is not in the installed list comes back in
    // OutOfScopeRevisionIDs.
    let env = setup_mode(SyncDelivery::Staged);
    env.publish(&[with_clauses(1, &[]), with_clauses(2, &[&[1]])]);
    env.approve(2);
    let (l1, l2) = (local(&env, 1), local(&env, 2));
    let mut c = registered(&env, 1002);
    let info = sync(&env, &mut c, &[], &[l1, l2]);
    assert_eq!(info.out_of_scope_revision_ids.value().unwrap(), &vec![l2]);
    assert!(new_ids(&info).is_empty());
    // With the prerequisite listed, nothing is out of scope and nothing is new.
    let info = sync(&env, &mut c, &[l1], &[l2]);
    assert!(info.out_of_scope_revision_ids.value().is_none());
    assert!(new_ids(&info).is_empty());
    // The switch turns the rule off.
    let mut cfg = config_for(SyncDelivery::Staged);
    cfg.out_of_scope_unsatisfied = false;
    let env = setup_with(cfg);
    env.publish(&[with_clauses(1, &[]), with_clauses(2, &[&[1]])]);
    env.approve(2);
    let mut c = registered(&env, 1003);
    let info = sync(&env, &mut c, &[], &[local(&env, 1), local(&env, 2)]);
    assert!(info.out_of_scope_revision_ids.value().is_none());
}

#[test]
fn installed_non_leaf_ids_are_capped_at_the_observed_400() {
    // Observed on the real WSUS: 400 accepted, 401 rejected with InvalidParameters naming
    // parameters.InstalledNonLeafUpdateIDs. OtherCachedUpdateIDs is not capped (3679 accepted).
    let env = setup_mode(SyncDelivery::Staged);
    let c = registered(&env, 1004);
    let ids = |n: i32| (1..=n).collect::<Vec<_>>();
    assert!(env.call(&sync_req(&c.cookie, &ids(400), &[])).is_ok());
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &ids(401), &[])),
        ErrorCode::InvalidParameters
    );
    assert!(env.call(&sync_req(&c.cookie, &[], &ids(3679))).is_ok());
    // Closure delivery ignores the installed list, so it does not enforce the cap.
    let env = setup_mode(SyncDelivery::Closure);
    let c = registered(&env, 1005);
    assert!(env.call(&sync_req(&c.cookie, &ids(401), &[])).is_ok());
}

#[test]
fn installed_non_leaf_cap_counts_list_entries_not_distinct_or_non_leaf_ids() {
    // Observed on the real WSUS (ledger C59): 401 entries made of 400 distinct ids plus a
    // repeat, and 400 non-leaf ids plus one leaf id, are rejected like a plain 401.
    let env = setup_mode(SyncDelivery::Staged);
    env.publish(&[with_clauses(1, &[]), with_clauses(2, &[&[1]])]);
    env.approve(2);
    let leaf = local(&env, 2);
    let c = registered(&env, 1006);
    let mut dup: Vec<i32> = (1..=400).collect();
    dup.push(1);
    assert_eq!(dup.len(), 401);
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &dup, &[])),
        ErrorCode::InvalidParameters
    );
    // 400 ids that are not the leaf, then the leaf (a real leaf revision id) as the 401st.
    let mut mixed: Vec<i32> = (1..=401).filter(|i| *i != leaf).take(400).collect();
    mixed.push(leaf);
    assert_eq!(mixed.len(), 401);
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &mixed, &[])),
        ErrorCode::InvalidParameters
    );
    // 400 entries with a repeat inside are still within the cap.
    let mut ok: Vec<i32> = (1..=399).collect();
    ok.push(1);
    assert!(env.call(&sync_req(&c.cookie, &ok, &[])).is_ok());
}

#[test]
fn a_category_prerequisite_is_non_leaf_in_scope_and_unlocks_in_order() {
    // Observed (scan 000006 to 000008): root category, a category behind an IsCategory clause,
    // then the leaf category; the middle one is IsLeaf=false although only an IsCategory
    // clause refers to it.
    let env = setup_mode(SyncDelivery::Staged);
    let mut mid = with_clauses(2, &[]);
    mid.core_xml = format!(
        "<UpdateIdentity UpdateID=\"{}\" RevisionNumber=\"1\"/><Properties UpdateType=\"Category\"/>\
         <Relationships><Prerequisites><AtLeastOne IsCategory=\"true\">\
         <UpdateIdentity UpdateID=\"{}\"/></AtLeastOne></Prerequisites></Relationships>",
        uid(2).0,
        uid(1).0
    )
    .into_bytes();
    relationship(&mut mid, RelationshipKind::Category, 1);
    let mut top = with_clauses(3, &[]);
    let top_xml = String::from_utf8(top.core_xml.clone())
        .unwrap()
        .replace(&uid(2).0.to_string(), &uid(3).0.to_string())
        .replace(&uid(1).0.to_string(), &uid(2).0.to_string());
    top.core_xml = top_xml.into_bytes();
    relationship(&mut top, RelationshipKind::Category, 2);
    env.publish(&[with_clauses(1, &[]), mid, top]);
    env.approve(3);
    let (l1, l2, l3) = (local(&env, 1), local(&env, 2), local(&env, 3));
    let mut c = registered(&env, 1006);
    let r1 = sync(&env, &mut c, &[], &[]);
    assert_eq!(new_ids(&r1), vec![l1]);
    let r2 = sync(&env, &mut c, &[l1], &[]);
    assert_eq!(new_ids(&r2), vec![l2]);
    assert!(!r2.new_updates.value().unwrap()[0].is_leaf);
    let r3 = sync(&env, &mut c, &[l1, l2], &[]);
    assert_eq!(new_ids(&r3), vec![l3]);
    assert!(r3.new_updates.value().unwrap()[0].is_leaf);
}

#[test]
fn closure_follows_category_edges_so_the_whole_chain_is_in_scope() {
    // Regression: the closure used to skip `category` relationships, which left the middle of
    // the Defender category chain (6964AAB4, 56309036) out of what a client could evaluate.
    for mode in MODES {
        let env = setup_mode(mode);
        let mut top = with_clauses(2, &[]);
        relationship(&mut top, RelationshipKind::Category, 1);
        env.publish(&[with_clauses(1, &[]), top]);
        env.approve(2);
        let mut c = registered(&env, 1007);
        let all: Vec<i32> = sync_all(&env, &mut c).concat();
        assert_eq!(all, vec![local(&env, 1), local(&env, 2)], "{mode:?}");
    }
}

#[test]
fn a_new_generation_does_not_split_a_staged_sequence() {
    // The pin lasts while the sequence goes on, including the extra request after a
    // complete response that delivered a non-leaf update (MS-WUSP 3.1.5.7).
    let env = setup_mode(SyncDelivery::Staged);
    env.publish(&[with_clauses(1, &[]), with_clauses(2, &[&[1]])]);
    env.approve(2);
    let (l1, l2) = (local(&env, 1), local(&env, 2));
    let mut c = registered(&env, 1008);
    let r1 = sync(&env, &mut c, &[], &[]);
    assert_eq!(new_ids(&r1), vec![l1]);
    assert!(!r1.truncated);
    // A new generation changes update 2 while the sequence is in progress.
    let mut v2 = with_clauses(2, &[&[1]]);
    v2.identity.revision = Revision(2);
    env.publish(&[with_clauses(1, &[]), with_clauses(2, &[&[1]]), v2]);
    let r2 = sync(&env, &mut c, &[l1], &[]);
    assert_eq!(new_ids(&r2), vec![l2], "still reads the pinned generation");
    // The response was final (a leaf, not truncated), so the pin is released and the next call
    // reads the new generation: revision 2 replaces the cached revision 1.
    let r3 = sync(&env, &mut c, &[l1], &[l2]);
    let l2b = env.catalog.find_local_id(rev(2, 2)).unwrap().unwrap().id;
    assert_eq!(new_ids(&r3), vec![l2b]);
    assert_eq!(r3.out_of_scope_revision_ids.value().unwrap(), &vec![l2]);
}

#[test]
fn a_page_never_ends_a_staged_sequence_early_and_truncation_counts_deliverable_updates() {
    let mut cfg = config_for(SyncDelivery::Staged);
    cfg.max_sync_new_updates = 2;
    let env = setup_with(cfg);
    // 1 root; 2..=6 leaves behind it.
    let mut frags = vec![with_clauses(1, &[])];
    frags.extend((2..=6u128).map(|n| with_clauses(n, &[&[1]])));
    env.publish(&frags);
    for n in 2..=6 {
        env.approve(n);
    }
    let mut c = registered(&env, 1010);
    // Round 1: only the root is deliverable; the five leaves wait, so no truncation.
    let r1 = sync(&env, &mut c, &[], &[]);
    assert_eq!(new_ids(&r1).len(), 1);
    assert!(!r1.truncated);
    let l1 = local(&env, 1);
    // Round 2: five deliverable leaves, page size two.
    let mut other = vec![];
    let mut pages = vec![];
    loop {
        let r = sync(&env, &mut c, &[l1], &other);
        let ids = new_ids(&r);
        pages.push((ids.len(), r.truncated));
        other.extend(ids);
        if !r.truncated {
            break;
        }
    }
    assert_eq!(pages, vec![(2, true), (2, true), (1, false)]);
}

#[test]
fn driver_pass_answers_driver_sync_not_needed_and_nothing_else() {
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&[with_clauses(1, &[])]);
        env.approve(1);
        let mut c = registered(&env, 1011);
        // Software pass: false (no category filter), updates present.
        let sw = sync(&env, &mut c, &[], &[]);
        assert_eq!(
            sw.driver_sync_not_needed.value().map(String::as_str),
            Some("false")
        );
        assert!(!new_ids(&sw).is_empty());
        // Driver pass (Observed flow 000014): no NewUpdates element, Truncated false.
        let mut req = sync_req(&c.cookie, &[local(&env, 1)], &[]);
        if let Presence::Value(p) = &mut req.parameters {
            p.skip_software_sync = true;
        }
        let info = env.call(&req).unwrap().result.into_value().unwrap();
        assert!(
            info.new_updates.value().is_none() && !info.truncated,
            "{mode:?}"
        );
        assert!(info.out_of_scope_revision_ids.value().is_none());
        assert_eq!(
            info.driver_sync_not_needed.value().map(String::as_str),
            Some("true")
        );
        // A category-filtered software pass says true (Observed on the OOBE scan capture).
        let mut filtered = sync_req(&c.cookie, &[], &[]);
        if let Presence::Value(p) = &mut filtered.parameters {
            p.filter_category_ids =
                Presence::Value(vec![wsus_protocol::wusp::CategoryIdentifier {
                    id: Uuid::from_u128(5),
                }]);
        }
        let info = env.call(&filtered).unwrap().result.into_value().unwrap();
        assert_eq!(
            info.driver_sync_not_needed.value().map(String::as_str),
            Some("true")
        );
    }
}

fn scan(cats: &[(i32, u128)]) -> StartCategoryScan {
    StartCategoryScan {
        requested_categories: Presence::Value(
            cats.iter()
                .map(|(g, c)| CategoryRelationship {
                    index_of_and_group: *g,
                    category_id: Uuid::from_u128(*c),
                })
                .collect(),
        ),
    }
}

#[test]
fn start_category_scan_prefers_known_categories_and_reports_unknown_ones() {
    for mode in MODES {
        let env = setup_mode(mode);
        // No catalog yet: nothing is known.
        let r = env.call(&scan(&[(0, 7)])).unwrap();
        assert!(r.preferred_category_ids.value().is_none());
        assert_eq!(
            r.requested_category_ids_in_error.value().unwrap(),
            &vec![Uuid::from_u128(7)]
        );
        env.publish(&[with_clauses(1, &[]), with_clauses(2, &[])]);
        // Observed (scan 000005): the requested category is echoed in preferredCategoryIds;
        // order of first appearance, duplicates removed, DNF groups irrelevant.
        let r = env.call(&scan(&[(0, 2), (0, 1), (1, 2), (1, 9)])).unwrap();
        assert_eq!(
            r.preferred_category_ids.value().unwrap(),
            &vec![Uuid::from_u128(2), Uuid::from_u128(1)]
        );
        assert_eq!(
            r.requested_category_ids_in_error.value().unwrap(),
            &vec![Uuid::from_u128(9)]
        );
    }
}

#[test]
fn start_category_scan_validates_its_request() {
    let env = setup();
    // Needs no cookie (Observed). Empty and over-long lists are InvalidParameters; the spec
    // records that WSUS 3.0 SP2 rejects 200 or more categories.
    assert_eq!(
        env.fault_code(&StartCategoryScan {
            requested_categories: Presence::Absent
        }),
        ErrorCode::InvalidParameters
    );
    let many: Vec<(i32, u128)> = (0..200).map(|i| (0, i as u128 + 1)).collect();
    assert_eq!(env.fault_code(&scan(&many)), ErrorCode::InvalidParameters);
    let ok: Vec<(i32, u128)> = (0..199).map(|i| (0, i as u128 + 1)).collect();
    assert!(env.call(&scan(&ok)).is_ok());
    assert_eq!(
        env.fault_code(&scan(&[(-1, 1)])),
        ErrorCode::InvalidParameters
    );
}

#[test]
fn unapproved_updates_are_never_delivered_in_either_mode() {
    // Visibility rules are shared: an unapproved update stays hidden even when the installed
    // list claims its prerequisites, and an approval withdrawn hides everything again.
    for mode in MODES {
        let env = setup_mode(mode);
        env.publish(&[
            with_clauses(1, &[]),
            with_clauses(2, &[&[1]]),
            with_clauses(3, &[&[1]]),
        ]);
        let a = env
            .policy
            .approve(
                uid(2),
                wsus_server::policy::ALL_COMPUTERS,
                wsus_server::policy::DeploymentAction::Install,
                None,
            )
            .unwrap();
        let mut c = registered(&env, 1012);
        let all: Vec<i32> = sync_all(&env, &mut c).concat();
        assert!(
            all.contains(&local(&env, 2)) && !all.contains(&local(&env, 3)),
            "{mode:?}"
        );
        env.policy.withdraw(a.id).unwrap();
        let mut c = registered(&env, 1013);
        assert!(sync_all(&env, &mut c).is_empty(), "{mode:?}");
        let info = sync(&env, &mut c, &[local(&env, 1)], &[local(&env, 2)]);
        assert_eq!(info.out_of_scope_revision_ids.value().unwrap().len(), 2);
    }
}

#[test]
fn bundle_children_are_delivered_with_the_bundle_in_staged_mode() {
    // Observed (flow): the approved bundle (Install) and its members (Bundle action, leaves)
    // are delivered once their own prerequisites hold; members are not prerequisites.
    let env = setup_mode(SyncDelivery::Staged);
    let mut bundle = with_clauses(10, &[&[1]]);
    relationship(&mut bundle, RelationshipKind::Bundle, 11);
    relationship(&mut bundle, RelationshipKind::Bundle, 12);
    env.publish(&[
        with_clauses(1, &[]),
        bundle,
        with_clauses(11, &[&[1]]),
        with_clauses(12, &[&[1]]),
    ]);
    env.approve(10);
    let mut c = registered(&env, 1014);
    let rounds = sync_rounds(&env, &mut c);
    assert_eq!(rounds[0].len(), 1, "only the shared prerequisite first");
    let flat: Vec<_> = rounds.concat();
    use wsus_protocol::wusp::DeploymentAction as A;
    let action = |n: u128| {
        let id = local(&env, n);
        flat.iter()
            .find(|u| u.id == id)
            .unwrap()
            .deployment
            .value()
            .unwrap()
            .action
            .clone()
    };
    assert_eq!(action(10), A::Install);
    assert_eq!(action(11), A::Bundle);
    assert_eq!(action(12), A::Bundle);
}
