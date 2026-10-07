//! MS-WUSP operations end to end through the neutral handler, against a temp database.
//! Nothing here is validated against a native Windows Update client.
mod endpoints_common;
use endpoints_common::*;

use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, UpdateRevision};
use wsus_protocol::soap::{ErrorCode, Presence, SoapVersion, XsDateTime};
use wsus_protocol::wusp::*;
use wsus_server::catalog::*;
use wsus_server::endpoints::SyncDelivery;
use wsus_server::policy::{ALL_COMPUTERS, DeploymentAction as PolicyAction};

/// Runs a test body once per delivery mode, as two tests (`<name>_staged`, `<name>_closure`),
/// for behaviour both modes must share.
macro_rules! both_modes {
    (mod $group:ident; $(fn $name:ident($mode:ident: SyncDelivery) $body:block)*) => {
        mod $group {
            use super::*;
            $(
                mod $name {
                    use super::*;
                    fn run($mode: SyncDelivery) $body
                    #[test]
                    fn staged() { run(SyncDelivery::Staged) }
                    #[test]
                    fn closure() { run(SyncDelivery::Closure) }
                }
            )*
        }
    };
}

#[test]
fn get_config_advertises_limits_registration_and_the_auth_plugin() {
    let mut cfg = default_config();
    cfg.allowed_event_ids = vec![147, 148];
    let env = setup_with(cfg);
    let c = get_config(&env);
    assert!(c.is_registration_required);
    let auth = &c.auth_info.value().unwrap()[0];
    assert_eq!(auth.plug_in_id.value().unwrap(), "SimpleTargeting");
    assert_eq!(
        auth.service_url.value().unwrap(),
        "SimpleAuthWebService/SimpleAuth.asmx"
    );
    assert_eq!(c.allowed_event_ids.value().unwrap(), &vec![147, 148]);
    let props: Vec<(String, String)> = c
        .properties
        .value()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p.name.value().unwrap().clone(),
                p.value.value().unwrap().clone(),
            )
        })
        .collect();
    assert!(props.contains(&("MaxExtendedUpdatesPerRequest".into(), "50".into())));
    assert!(props.contains(&("IsInventoryRequired".into(), "0".into())));
    // LastChange is stable between calls.
    assert_eq!(get_config(&env).last_change, c.last_change);
}

#[test]
fn authorization_requires_client_id_and_dns_name() {
    let env = setup();
    let base = GetAuthorizationCookie {
        client_id: Presence::Value(Uuid::from_u128(1).to_string()),
        target_group_name: Presence::Absent,
        dns_name: Presence::Value("a.example".into()),
    };
    assert!(env.call(&base).is_ok());
    let mut no_id = base.clone();
    no_id.client_id = Presence::Absent;
    assert_eq!(env.fault_code(&no_id), ErrorCode::InvalidParameters);
    let mut no_dns = base.clone();
    no_dns.dns_name = Presence::Value("  ".into());
    assert_eq!(env.fault_code(&no_dns), ErrorCode::InvalidParameters);
    // A non-GUID client id is accepted and maps deterministically.
    let mut odd = base;
    odd.client_id = Presence::Value("not-a-guid".into());
    assert!(env.call(&odd).is_ok());
}

#[test]
fn registration_is_required_stored_and_idempotent() {
    let env = setup();
    env.publish(&[frag(1)]);
    env.approve(1);
    let c = handshake(&env, Uuid::from_u128(21), Some("Workstations"));
    // Not registered yet: sync is refused with RegistrationRequired.
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &[], &[])),
        ErrorCode::RegistrationRequired
    );
    env.call(&register_req(&c.cookie)).unwrap();
    let id = ComputerId(Uuid::from_u128(21));
    let stored = env.computers.get(id).unwrap().expect("registered");
    assert_eq!(stored.details.dns_name.as_deref(), Some("pc1.example"));
    assert_eq!(stored.details.os_version.as_deref(), Some("10.0.26100"));
    assert_eq!(
        stored.details.client_version.as_deref(),
        Some("10.0.26100.1")
    );
    assert_eq!(stored.requested_group.as_deref(), Some("Workstations"));
    assert!(env.call(&sync_req(&c.cookie, &[], &[])).is_ok());
    // Registering again does not duplicate or change group memberships.
    let before = env.policy.groups_of(id).unwrap();
    env.call(&register_req(&c.cookie)).unwrap();
    assert_eq!(env.policy.groups_of(id).unwrap(), before);
}

#[test]
fn registration_joins_the_requested_group_when_it_exists() {
    let env = setup();
    let g = env.policy.create_group("Workstations", "").unwrap();
    let c = handshake(&env, Uuid::from_u128(22), Some("Workstations"));
    env.call(&register_req(&c.cookie)).unwrap();
    assert!(
        env.policy
            .groups_of(ComputerId(Uuid::from_u128(22)))
            .unwrap()
            .contains(&g)
    );
}

#[test]
fn registration_rejects_dns_name_that_differs_from_authorization() {
    let env = setup();
    let c = handshake(&env, Uuid::from_u128(23), None);
    let mut req = register_req(&c.cookie);
    if let Presence::Value(i) = &mut req.computer_info {
        i.dns_name = Presence::Value("other.example".into());
    }
    assert_eq!(env.fault_code(&req), ErrorCode::InvalidParameters);
    let mut missing = register_req(&c.cookie);
    missing.computer_info = Presence::Absent;
    assert_eq!(env.fault_code(&missing), ErrorCode::InvalidParameters);
}

both_modes! {
mod shared;
fn unapproved_update_is_invisible_approval_reveals_it_with_prerequisites_and_removal_hides_it(mode: SyncDelivery) {
    let env = setup_mode(mode);
    // 3 depends on 2 depends on 1; 4 is unrelated and never approved.
    env.publish(&[
        frag(1),
        with_prereq(frag(2), 1),
        with_prereq(frag(3), 2),
        frag(4),
    ]);
    let mut c = registered(&env, 31);

    // Nothing approved: nothing visible, not even prerequisite metadata.
    let info = sync(&env, &mut c, &[], &[]);
    assert!(new_ids(&info).is_empty());
    assert!(!info.truncated);

    // Approve the leaf only: leaf plus its whole prerequisite chain is delivered.
    let approval = env
        .policy
        .approve(
            uid(3),
            ALL_COMPUTERS,
            PolicyAction::Install,
            Some(1_900_000_000),
        )
        .unwrap();
    // Staged delivery (Observed, scan 000006 to 000008): one dependency level per round,
    // each unlocked by the installed list; closure delivery sends the chain at once.
    let (l1, l2, l3, l4) = (
        local(&env, 1),
        local(&env, 2),
        local(&env, 3),
        local(&env, 4),
    );
    let rounds = {
        let mut probe = registered(&env, 310);
        match mode {
            SyncDelivery::Closure => {
                let first = sync(&env, &mut probe, &[], &[]);
                assert_eq!(new_ids(&first), vec![l1, l2, l3]);
                vec![first.new_updates.into_value().unwrap()]
            }
            SyncDelivery::Staged => {
                let r1 = sync(&env, &mut probe, &[], &[]);
                assert_eq!(new_ids(&r1), vec![l1], "only the root has no prerequisite");
                assert!(!r1.truncated);
                let r2 = sync(&env, &mut probe, &[l1], &[]);
                assert_eq!(new_ids(&r2), vec![l2]);
                // A prerequisite that is cached but not listed as installed does not unlock.
                let held = sync(&env, &mut probe, &[], &[l1, l2]);
                assert!(new_ids(&held).is_empty(), "l1 is not in the installed list");
                assert_eq!(
                    held.out_of_scope_revision_ids.value().unwrap(),
                    &vec![l2],
                    "l2's prerequisite is not installed, so the server drops it from the cache"
                );
                let r3 = sync(&env, &mut probe, &[l1, l2], &[]);
                assert_eq!(new_ids(&r3), vec![l3]);
                vec![
                    r1.new_updates.into_value().unwrap(),
                    r2.new_updates.into_value().unwrap(),
                    r3.new_updates.into_value().unwrap(),
                ]
            }
        }
    };
    let updates: Vec<&UpdateInfo> = rounds.iter().flatten().collect();
    assert!(!updates.iter().any(|u| u.id == l4), "4 stays hidden");
    let by = |id: i32| *updates.iter().find(|u| u.id == id).unwrap();
    assert!(!by(l1).is_leaf && !by(l2).is_leaf && by(l3).is_leaf);
    // Observed on a real WSUS (2026-10-04): every update carries a Deployment (159 of 159) and
    // a native Windows Update Agent fails with E_INVALIDARG when one is missing. Only the
    // approved update is `Install`; metadata-only updates are `Evaluate` (or `Bundle`).
    for l in [l1, l2] {
        let d = by(l)
            .deployment
            .value()
            .expect("every update has a deployment");
        assert!(
            matches!(
                d.action,
                DeploymentAction::Evaluate | DeploymentAction::Bundle
            ),
            "metadata-only update must not be an install: {:?}",
            d.action
        );
        assert!(d.is_assigned);
        assert_eq!(d.id, l, "deployment id is the local revision id");
        assert_eq!(d.last_change_time.len(), 10, "date-only LastChangeTime");
    }
    let d = by(l3).deployment.value().unwrap();
    assert_eq!(d.action, DeploymentAction::Install);
    assert!(d.is_assigned);
    assert!(d.deadline.value().unwrap().starts_with("2030-03-17"));
    assert!(d.id > 0);
    // Observed on a real WSUS (2026-10-04): LastChangeTime is date-only and a native Windows
    // Update Agent fails with E_INVALIDARG on the full dateTime form; AutoSelect, AutoDownload
    // and SupersedenceBehavior are present with value 0.
    let lct = d.last_change_time.as_str();
    assert!(
        lct.len() == 10
            && lct.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }),
        "LastChangeTime must be YYYY-MM-DD, got {lct}"
    );
    assert_eq!(d.auto_select.value().map(String::as_str), Some("0"));
    assert_eq!(d.auto_download.value().map(String::as_str), Some("0"));
    assert_eq!(
        d.supersedence_behavior.value().map(String::as_str),
        Some("0")
    );
    // Metadata is delivered verbatim.
    assert_eq!(by(l3).xml.value().unwrap(), "<Update n=\"3\"/>");

    // Withdrawing the approval makes everything out of scope again.
    env.policy.withdraw(approval.id).unwrap();
    let cached = vec![l1, l2, l3];
    let info = sync(&env, &mut c, &[l1], &[l2, l3]);
    assert!(new_ids(&info).is_empty());
    assert_eq!(info.out_of_scope_revision_ids.value().unwrap(), &cached);
    // And a fresh client sees nothing.
    let mut c2 = registered(&env, 32);
    assert!(new_ids(&sync(&env, &mut c2, &[], &[])).is_empty());
}

fn approval_is_per_group_and_declined_updates_disappear(mode: SyncDelivery) {
    let env = setup_mode(mode);
    env.publish(&[frag(1), frag(2)]);
    let g = env.policy.create_group("Pilot", "").unwrap();
    env.policy
        .approve(uid(1), g, PolicyAction::Install, None)
        .unwrap();
    let mut outsider = registered(&env, 41);
    assert!(new_ids(&sync(&env, &mut outsider, &[], &[])).is_empty());
    env.policy
        .add_member(g, ComputerId(Uuid::from_u128(41)))
        .unwrap();
    assert_eq!(
        new_ids(&sync(&env, &mut outsider, &[], &[])),
        vec![local(&env, 1)]
    );
    env.approve(2);
    env.policy.decline(uid(2)).unwrap();
    let have = vec![local(&env, 1)];
    assert!(new_ids(&sync(&env, &mut outsider, &[], &have)).is_empty());
}

fn deployment_change_is_reported_for_cached_revisions(mode: SyncDelivery) {
    let env = setup_mode(mode);
    env.publish(&[frag(1)]);
    env.approve(1);
    let mut c = registered(&env, 51);
    let ids = new_ids(&sync(&env, &mut c, &[], &[]));
    // No change yet.
    let info = sync(&env, &mut c, &[], &ids);
    assert!(info.changed_updates.value().is_none());
    // A deadline appears.
    env.policy
        .approve(
            uid(1),
            ALL_COMPUTERS,
            PolicyAction::Install,
            Some(1_900_000_000),
        )
        .unwrap();
    let info = sync(&env, &mut c, &[], &ids);
    let ch = info.changed_updates.value().unwrap();
    assert_eq!(ch.len(), 1);
    assert_eq!(ch[0].id, ids[0]);
    assert!(ch[0].deployment.value().unwrap().deadline.value().is_some());
    assert!(
        ch[0].xml.value().is_none(),
        "changed updates carry no metadata"
    );
}

fn newer_revision_replaces_the_cached_one(mode: SyncDelivery) {
    let env = setup_mode(mode);
    env.publish(&[frag(1)]);
    env.approve(1);
    let mut c = registered(&env, 52);
    let old = new_ids(&sync(&env, &mut c, &[], &[]));
    let mut v2 = FragmentImport::new(rev(1, 2), "Software", b"<Update n=\"1\" r=\"2\"/>");
    v2.relationships = vec![];
    env.publish(&[v2]);
    let info = sync(&env, &mut c, &[], &old);
    assert_eq!(info.out_of_scope_revision_ids.value().unwrap(), &old);
    assert_eq!(new_ids(&info).len(), 1);
    assert_ne!(new_ids(&info), old);
}

fn withdrawn_metadata_is_not_offered(mode: SyncDelivery) {
    let env = setup_mode(mode);
    let mut gone = frag(1);
    gone.state = FragmentState::Withdrawn;
    env.publish(&[gone, frag(2)]);
    env.approve(1);
    env.approve(2);
    let mut c = registered(&env, 53);
    assert_eq!(new_ids(&sync(&env, &mut c, &[], &[])), vec![local(&env, 2)]);
}

fn paging_boundaries_around_the_truncation_limit(mode: SyncDelivery) {
    for (total, limit, expect_pages) in [
        (3u128, 3usize, vec![3usize]),
        (4, 3, vec![3, 1]),
        (6, 3, vec![3, 3]),
        (7, 3, vec![3, 3, 1]),
        (1, 3, vec![1]),
    ] {
        let mut cfg = config_for(mode);
        cfg.max_sync_new_updates = limit;
        let env = setup_with(cfg);
        let frags: Vec<_> = (1..=total).map(frag).collect();
        env.publish(&frags);
        for n in 1..=total {
            env.approve(n);
        }
        let mut c = registered(&env, 70);
        // Check the Truncated flag on the first call explicitly.
        let first = sync(&env, &mut c, &[], &[]);
        assert_eq!(first.truncated, total as usize > limit, "total {total}");
        let mut c = registered(&env, 71);
        let pages = sync_all(&env, &mut c);
        assert_eq!(
            pages.iter().map(Vec::len).collect::<Vec<_>>(),
            expect_pages,
            "total {total}"
        );
        let mut all: Vec<i32> = pages.concat();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n, "no update delivered twice");
        assert_eq!(n as u128, total);
    }
}

fn paging_is_stable_when_the_catalog_changes_between_pages(mode: SyncDelivery) {
    let mut cfg = config_for(mode);
    cfg.max_sync_new_updates = 2;
    let env = setup_with(cfg);
    env.publish(&[frag(1), frag(2), frag(3), frag(4)]);
    for n in 1..=4 {
        env.approve(n);
    }
    let mut c = registered(&env, 73);
    let first = sync(&env, &mut c, &[], &[]);
    assert!(first.truncated);
    let mut have = new_ids(&first);
    // A new generation (different content for 3) activates mid-sequence.
    let mut changed = FragmentImport::new(rev(3, 2), "Software", b"<Update n=\"3\" r=\"2\"/>");
    changed.relationships = vec![];
    env.publish(&[frag(1), frag(2), changed, frag(4), frag(5)]);
    env.approve(5);
    // The in-progress sequence keeps reading the pinned generation.
    let second = sync(&env, &mut c, &[], &have);
    have.extend(new_ids(&second));
    assert_eq!(have.len(), 4);
    assert!(!second.truncated);
    assert!(have.contains(&local(&env, 3)));
    // A new sequence (first call) sees the new generation.
    let mut c2 = registered(&env, 74);
    let all: Vec<i32> = sync_all(&env, &mut c2).concat();
    assert!(all.contains(&env.catalog.find_local_id(rev(3, 2)).unwrap().unwrap().id));
    assert!(all.contains(&local(&env, 5)));
}

fn empty_catalog_and_missing_source_are_empty_not_errors(mode: SyncDelivery) {
    let env = setup_mode(mode);
    // Source exists, no active generation.
    let mut c = registered(&env, 61);
    let info = sync(&env, &mut c, &[], &[]);
    assert!(new_ids(&info).is_empty() && !info.truncated);
    assert!(info.new_cookie.value().is_some());
    // Source missing entirely.
    let mut cfg = config_for(mode);
    cfg.source_name = "nonexistent".into();
    let env2 = setup_with(cfg);
    let mut c2 = registered(&env2, 62);
    assert!(new_ids(&sync(&env2, &mut c2, &[], &[])).is_empty());
    // A staging (unactivated) generation is invisible.
    let g = env.catalog.begin_generation(env.source, None).unwrap();
    env.catalog.import_fragments(g, &[frag(1)]).unwrap();
    env.approve(1);
    assert!(new_ids(&sync(&env, &mut c, &[], &[])).is_empty());
}
}

#[test]
fn default_page_size_is_thirty_staged_and_two_hundred_closure() {
    // Observed on the real WSUS (WS2025 10.0.26100, inventory 9.1): 30 NewUpdates per page.
    // The closure mode keeps the earlier 200.
    for (mode, page) in [
        (SyncDelivery::Staged, 30usize),
        (SyncDelivery::Closure, 200),
    ] {
        let env = setup_mode(mode);
        let total = page as u128 + 1;
        let frags: Vec<_> = (1..=total).map(frag).collect();
        env.publish(&frags);
        for n in 1..=total {
            env.approve(n);
        }
        let mut c = registered(&env, 72);
        let first = sync(&env, &mut c, &[], &[]);
        assert_eq!(new_ids(&first).len(), page, "{mode:?}");
        assert!(first.truncated);
        let have = new_ids(&first);
        let second = sync(&env, &mut c, &[], &have);
        assert_eq!(new_ids(&second).len(), 1);
        assert!(!second.truncated);
    }
}
#[test]
fn sync_parameter_validation() {
    let env = setup();
    let c = registered(&env, 80);
    let mut express = sync_req(&c.cookie, &[], &[]);
    if let Presence::Value(p) = &mut express.parameters {
        p.express_query = true;
    }
    assert_eq!(env.fault_code(&express), ErrorCode::InvalidParameters);
    let mut spec = sync_req(&c.cookie, &[], &[]);
    if let Presence::Value(p) = &mut spec.parameters {
        p.system_spec = Presence::Value(vec![Device {
            hardware_ids: Presence::Value(vec!["PCI\\VEN_8086".into()]),
            compatible_ids: Presence::Absent,
            installed_driver: Presence::Absent,
            extension_driver: Presence::Absent,
            driver_recovery_ids: Presence::Absent,
            device_flags: Presence::Absent,
        }]);
    }
    assert_eq!(env.fault_code(&spec.clone()), ErrorCode::InvalidParameters);
    // Driver pass with SkipSoftwareSync is answered with an empty result.
    if let Presence::Value(p) = &mut spec.parameters {
        p.skip_software_sync = true;
    }
    let info = env.call(&spec).unwrap().result.into_value().unwrap();
    assert!(new_ids(&info).is_empty() && !info.truncated);
    let mut none = sync_req(&c.cookie, &[], &[]);
    none.parameters = Presence::Absent;
    assert_eq!(env.fault_code(&none), ErrorCode::InvalidParameters);
}

#[test]
fn refresh_cache_maps_only_in_scope_identities() {
    let env = setup();
    env.publish(&[frag(1), frag(2)]);
    env.approve(1);
    let c = registered(&env, 90);
    let resp = env
        .call(&RefreshCache {
            cookie: Presence::Value(c.cookie.clone()),
            global_ids: Presence::Value(vec![rev(1, 1), rev(2, 1), rev(99, 1)]),
        })
        .unwrap();
    let r = resp.result.into_value().unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].revision_id, local(&env, 1));
    assert!(r[0].deployment.value().is_some());
}

fn extended_req(
    c: &Client,
    ids: Vec<i32>,
    types: Vec<XmlUpdateFragmentType>,
) -> GetExtendedUpdateInfo {
    GetExtendedUpdateInfo {
        cookie: Presence::Value(c.cookie.clone()),
        revision_ids: Presence::Value(ids),
        info_types: Presence::Value(types),
        locales: Presence::Value(vec!["en".into()]),
        geo_id: Presence::Absent,
        caller_attributes: Presence::Absent,
    }
}

#[test]
fn extended_update_info_scope_types_and_limits() {
    let env = setup();
    let data = b"payload bytes";
    env.publish(&[with_file(frag(1), "a.cab", data), frag(2)]);
    env.approve(1);
    put_content(&env, "a.cab", data);
    let c = registered(&env, 100);
    let (l1, l2) = (local(&env, 1), local(&env, 2));
    use XmlUpdateFragmentType::*;
    let r = env
        .call(&extended_req(&c, vec![l1, l2, 4242], vec![Core, Extended]))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    let ups = r.updates.value().unwrap();
    assert_eq!(
        ups.len(),
        2,
        "core and extended fragments of the in-scope update"
    );
    assert!(ups.iter().all(|u| u.id == l1));
    assert_eq!(ups[1].xml.value().unwrap(), "<Extended n=\"1\"/>");
    assert_eq!(
        r.out_of_scope_revision_ids.value().unwrap(),
        &vec![l2, 4242]
    );
    let loc = &r.file_locations.value().unwrap()[0];
    assert_eq!(loc.file_digest.value().unwrap(), &sha1_of(data));
    assert!(
        loc.url
            .value()
            .unwrap()
            .starts_with("http://wsus.test:8530/Content/")
    );
    // Core only: no file locations.
    let r = env
        .call(&extended_req(&c, vec![l1], vec![Core]))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    assert!(r.file_locations.value().is_none());
    // Locales are mandatory for Eula / LocalizedProperties.
    let mut bad = extended_req(&c, vec![l1], vec![Eula]);
    bad.locales = Presence::Absent;
    assert_eq!(env.fault_code(&bad), ErrorCode::InvalidParameters);
    // Limit.
    let many: Vec<i32> = (1..=51).collect();
    assert_eq!(
        env.fault_code(&extended_req(&c, many, vec![Core])),
        ErrorCode::InvalidParameters
    );
    let fifty: Vec<i32> = (1..=50).collect();
    assert!(env.call(&extended_req(&c, fifty, vec![Core])).is_ok());
}

#[test]
fn extended_update_info2_uses_identities() {
    let env = setup();
    let data = b"second payload";
    env.publish(&[with_file(frag(1), "b.exe", data), frag(2)]);
    env.approve(1);
    put_content(&env, "b.exe", data);
    let c = registered(&env, 101);
    let r = env
        .call(&GetExtendedUpdateInfo2 {
            cookie: Presence::Value(c.cookie.clone()),
            update_ids: Presence::Value(vec![rev(1, 1), rev(2, 1)]),
            info_types: Presence::Value(vec![
                XmlUpdateFragmentType::Extended,
                XmlUpdateFragmentType::FileUrl,
            ]),
            locales: Presence::Value(vec!["en".into()]),
            caller_attributes: Presence::Absent,
        })
        .unwrap()
        .result
        .into_value()
        .unwrap();
    assert_eq!(r.updates.value().unwrap().len(), 1);
    let loc = &r.file_locations.value().unwrap()[0];
    assert_eq!(loc.file_digest_algorithm.value().unwrap(), "SHA1");
    assert!(loc.url.value().unwrap().ends_with(".exe"));
    assert_eq!(r.update_encryption_details.value().unwrap().len(), 1);
}

#[test]
fn file_locations_require_scope_and_verified_content() {
    let env = setup();
    let (have, missing, hidden) = (
        b"have this one".as_slice(),
        b"metadata only".as_slice(),
        b"not approved".as_slice(),
    );
    let mut a = with_file(frag(1), "have.cab", have);
    a.files.push(descriptor("missing.cab", missing));
    env.publish(&[a, with_file(frag(2), "hidden.cab", hidden)]);
    env.approve(1);
    put_content(&env, "have.cab", have);
    put_content(&env, "hidden.cab", hidden); // available, but not in this computer's scope
    let c = registered(&env, 110);
    let req = |digests: Vec<Vec<u8>>| GetFileLocations {
        cookie: Presence::Value(c.cookie.clone()),
        file_digests: Presence::Value(digests),
    };
    let r = env
        .call(&req(vec![
            sha1_of(have),
            sha1_of(missing),
            sha1_of(hidden),
            vec![0; 20],
            sha1_of(have),
        ]))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    let locs = r.file_locations.value().unwrap();
    assert_eq!(
        locs.len(),
        1,
        "only the in-scope, verified-available file; duplicates collapsed"
    );
    assert_eq!(locs[0].file_digest.value().unwrap(), &sha1_of(have));
    assert!(r.new_cookie.value().is_some());
    // Fetching the advertised URL works.
    let url = locs[0].url.value().unwrap();
    let path = url.strip_prefix("http://wsus.test:8530").unwrap();
    let got = env.get(path);
    assert_eq!(got.status, 200);
    assert_eq!(got.into_bytes().unwrap(), have);
    // Malformed digest lengths and oversized lists are parameter errors.
    assert_eq!(
        env.fault_code(&req(vec![vec![1; 19]])),
        ErrorCode::InvalidParameters
    );
    assert_eq!(
        env.fault_code(&req((0..101).map(|_| vec![1; 20]).collect())),
        ErrorCode::InvalidParameters
    );
    // The metadata becomes locatable only after the content verifies.
    let data = b"metadata only";
    put_content(&env, "missing.cab", data);
    let r = env
        .call(&req(vec![sha1_of(missing)]))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    assert_eq!(r.file_locations.value().unwrap().len(), 1);
}

#[test]
fn file_url_without_configured_base_uses_the_host_header() {
    let mut cfg = default_config();
    cfg.content_base_url = None;
    let env = setup_with(cfg);
    let data = b"host based";
    env.publish(&[with_file(frag(1), "h.cab", data)]);
    env.approve(1);
    put_content(&env, "h.cab", data);
    let c = registered(&env, 111);
    let enc = wsus_protocol::soap::encode_request(
        SoapVersion::V11,
        &GetFileLocations {
            cookie: Presence::Value(c.cookie.clone()),
            file_digests: Presence::Value(vec![sha1_of(data)]),
        },
    );
    let mk = |host: Option<&str>| {
        let mut r = wsus_server::endpoints::HttpRequestParts::new("POST", CLIENT_PATH)
            .with_header("Content-Type", &enc.content_type)
            .with_header("SOAPAction", enc.soap_action.as_deref().unwrap())
            .with_body(enc.body.clone());
        if let Some(h) = host {
            r = r.with_header("Host", h);
        }
        env.server.handle(r)
    };
    let ok = mk(Some("wsus.lan:8530")).into_bytes().unwrap();
    assert!(String::from_utf8_lossy(&ok).contains("http://wsus.lan:8530/Content/"));
    // No usable Host: a protocol fault, not a bogus URL.
    assert_eq!(mk(None).status, 500);
    assert_eq!(mk(Some("evil host/../x")).status, 500);
}

fn event(n: u128, event_id: i16, update: Option<UpdateRevision>) -> ReportingEvent {
    ReportingEvent {
        basic_data: Presence::Value(BasicData {
            target_id: Presence::Absent,
            sequence_number: 0,
            time_at_target: xs("2026-10-04T12:00:00Z"),
            event_instance_id: Uuid::from_u128(n),
            namespace_id: 1,
            event_id,
            source_id: 202,
            update_id: update.map_or(Presence::Absent, Presence::Value),
            win32_hresult: 0,
            app_name: Presence::Value("AutomaticUpdates".into()),
        }),
        extended_data: Presence::Absent,
        private_data: Presence::Absent,
    }
}

fn report(c: &Client, events: Vec<ReportingEvent>) -> ReportEventBatch {
    ReportEventBatch {
        cookie: Presence::Value(c.cookie.clone()),
        client_time: xs("2026-10-04T12:00:05Z"),
        event_batch: Presence::Value(events),
    }
}

#[test]
fn reports_are_recorded_deduplicated_and_replays_are_harmless() {
    let mut cfg = default_config();
    cfg.event_kinds
        .insert(19, wsus_server::reporting::EventKind::InstallSucceeded);
    let env = setup_with(cfg);
    let c = registered(&env, 120);
    let id = ComputerId(Uuid::from_u128(120));
    let batch = report(&c, vec![event(1, 19, Some(rev(7, 1))), event(2, 147, None)]);
    assert!(env.call(&batch).unwrap().result);
    // Replay of the same batch, then a mixed batch with one new event.
    assert!(env.call(&batch).unwrap().result);
    assert!(
        env.call(&report(
            &c,
            vec![event(2, 147, None), event(3, 19, Some(rev(7, 1)))]
        ))
        .unwrap()
        .result
    );
    let events = env.reporting.events_for_computer(id, None, 100).unwrap();
    assert_eq!(events.len(), 3, "each EventInstanceID stored once");
    let st = env
        .reporting
        .status(id, rev(7, 1))
        .unwrap()
        .expect("status derived");
    assert_eq!(st.status, wsus_server::reporting::UpdateStatus::Installed);
    // Empty batch is fine.
    assert!(env.call(&report(&c, vec![])).unwrap().result);
}

/// A native-shaped event (namespace 1, source 101, `ExtendedData` and empty `PrivateData`), the
/// shape recorded from a native Windows Update Agent (inventory 9.10).
fn native_event(
    n: u128,
    event_id: i16,
    hresult: i32,
    update: UpdateRevision,
    repl: &[&str],
    misc: &[&str],
    at: &str,
) -> ReportingEvent {
    let mut e = event(n, event_id, Some(update));
    if let Presence::Value(b) = &mut e.basic_data {
        b.source_id = 101;
        b.win32_hresult = hresult;
        b.time_at_target = xs(at);
    }
    e.extended_data = Presence::Value(wsus_protocol::wusp::ExtendedData {
        replacement_strings: Presence::Value(repl.iter().map(|s| (*s).to_owned()).collect()),
        misc_data: Presence::Value(misc.iter().map(|s| (*s).to_owned()).collect()),
        computer_brand: Presence::Absent,
        computer_model: Presence::Absent,
        bios_revision: Presence::Absent,
        processor_architecture: wsus_protocol::wusp::ProcessorArchitecture::Amd64Compatible,
        os_version: wsus_protocol::wusp::DetailedVersion {
            major: 10,
            minor: 0,
            build: 26200,
            revision: 0,
            service_pack_major: 0,
            service_pack_minor: 0,
        },
        os_locale_id: 1033,
        device_id: Presence::Absent,
    });
    e.private_data = Presence::Value(wsus_protocol::wusp::PrivateData {
        computer_dns_name: Presence::Absent,
        user_account_name: Presence::Absent,
    });
    e
}

#[test]
fn default_event_kinds_derive_failed_from_182_and_nothing_from_the_pending_sequence() {
    // The real WSUS (inventory 9.10): a native 182 set the update's status to Failed; the
    // observed 181 and 201 of an install that needed a restart left it unchanged.
    let env = setup();
    let c = registered(&env, 130);
    let id = ComputerId(Uuid::from_u128(130));
    let pending = rev(8, 100);
    let batch = report(
        &c,
        vec![
            native_event(
                1,
                181,
                0,
                pending,
                &["Title"],
                &["AppName=wsus-client"],
                "2026-10-06T14:56:40Z",
            ),
            native_event(
                2,
                201,
                2_359_301,
                pending,
                &["Title"],
                &["D=1", "AppName=wsus-client"],
                "2026-10-06T14:57:39Z",
            ),
        ],
    );
    assert!(env.call(&batch).unwrap().result);
    assert!(
        env.reporting.status(id, pending).unwrap().is_none(),
        "181 and 201 derive nothing, as on the real WSUS"
    );
    let failed = rev(9, 1);
    let batch = report(
        &c,
        vec![
            native_event(
                3,
                181,
                0,
                failed,
                &["Title"],
                &["AppName=wsus-client"],
                "2026-10-06T15:03:08Z",
            ),
            native_event(
                4,
                182,
                -2_145_099_769,
                failed,
                &["0x80246007", "Title"],
                &["C=1", "F=-2145099769", "AppName=wsus-client"],
                "2026-10-06T15:03:09Z",
            ),
        ],
    );
    assert!(env.call(&batch).unwrap().result);
    // A resent batch (same instance ids) changes nothing.
    assert!(env.call(&batch).unwrap().result);
    let st = env.reporting.status(id, failed).unwrap().expect("derived");
    assert_eq!(
        st.status,
        wsus_server::reporting::UpdateStatus::InstallFailed
    );
    assert_eq!(st.result_code, Some(-2_145_099_769));
    let events = env.reporting.events_for_computer(id, None, 100).unwrap();
    assert_eq!(events.len(), 4);
    // The detail records are kept verbatim in the raw payload.
    let raw: serde_json::Value = serde_json::from_str(&events[1].event.raw).unwrap();
    assert_eq!(raw["event_id"], 201);
    assert_eq!(raw["win32_hresult"], 2_359_301);
    assert_eq!(
        raw["misc_data"],
        serde_json::json!(["D=1", "AppName=wsus-client"])
    );
    assert_eq!(raw["replacement_strings"], serde_json::json!(["Title"]));
}

/// The native client status event (`156`): the zero update, `U` and `V` lists, nothing else that
/// matters here. `u` and `v` are update numbers of the test catalog.
fn status_event(n: u128, u: &[u128], v: &[u128], at: &str) -> ReportingEvent {
    let list = |key: &str, ids: &[u128]| {
        (!ids.is_empty()).then(|| {
            let joined: Vec<String> = ids
                .iter()
                .map(|i| uid(*i).0.hyphenated().to_string().to_uppercase())
                .collect();
            format!("{key}={}", joined.join(";"))
        })
    };
    let mut misc: Vec<String> = [list("U", u), list("V", v)].into_iter().flatten().collect();
    misc.push("AppName=osi-rs-native".into());
    let misc: Vec<&str> = misc.iter().map(String::as_str).collect();
    native_event(
        n,
        156,
        0,
        UpdateRevision {
            id: wsus_protocol::identity::UpdateId(Uuid::nil()),
            revision: wsus_protocol::identity::Revision(0),
        },
        &[],
        &misc,
        at,
    )
}

fn wsus_server_time(text: &str) -> i64 {
    // The event times of these tests are whole seconds `YYYY-MM-DDTHH:MM:SSZ` (UTC).
    let d = |a: usize, b: usize| text[a..b].parse::<i64>().unwrap();
    let (y, m, day) = (d(0, 4), d(5, 7), d(8, 10));
    let (y2, m2) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let days = 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 + (153 * (m2 - 3) + 2) / 5 + day - 719_469;
    days * 86_400 + d(11, 13) * 3600 + d(14, 16) * 60 + d(17, 19)
}

#[test]
fn a_client_status_event_derives_installed_and_not_installed_as_the_real_wsus_did() {
    use wsus_server::reporting::UpdateStatus as S;
    // The real WSUS (inventory 9.11, ledger C77 and C79): the per-update rows of a computer were the ids of
    // the native `156` lists, `U` NotInstalled and `V` Installed; a later event moved an update
    // between the lists and the rows of updates it no longer named disappeared.
    let env = setup();
    env.publish(&[frag(21), frag(22), frag(23), frag(24)]);
    let c = registered(&env, 140);
    let id = ComputerId(Uuid::from_u128(140));
    let batch = report(
        &c,
        vec![status_event(1, &[21, 22], &[23], "2026-10-06T19:31:57Z")],
    );
    assert!(env.call(&batch).unwrap().result);
    let st = |n: u128| {
        env.reporting
            .status(id, rev(n, 1))
            .unwrap()
            .map(|r| r.status)
    };
    assert_eq!(st(21), Some(S::NotInstalled));
    assert_eq!(st(22), Some(S::NotInstalled));
    assert_eq!(st(23), Some(S::Installed));
    assert_eq!(st(24), None);
    // The zero update id is not stored as an update; the event is kept raw as kind client_status.
    let events = env.reporting.events_for_computer(id, None, 100).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].event.kind,
        wsus_server::reporting::EventKind::ClientStatus
    );
    assert!(events[0].event.update.is_none());

    // A failure the client reported is not removed by a status event that omits the update.
    let failed = native_event(
        2,
        182,
        -2_145_099_769,
        rev(24, 1),
        &["0x80246007", "Title"],
        &["C=1"],
        "2026-10-06T19:40:00Z",
    );
    assert!(env.call(&report(&c, vec![failed])).unwrap().result);
    assert_eq!(st(24), Some(S::InstallFailed));

    // The update 22 moved to the installed list, 23 is no longer listed (a replay changes nothing).
    let batch = report(
        &c,
        vec![status_event(3, &[21], &[22], "2026-10-06T20:35:57Z")],
    );
    assert!(env.call(&batch).unwrap().result);
    assert!(env.call(&batch).unwrap().result);
    assert_eq!(st(21), Some(S::NotInstalled));
    assert_eq!(st(22), Some(S::Installed));
    assert_eq!(st(23), None, "an omitted update's inventory row is removed");
    assert_eq!(st(24), Some(S::InstallFailed));
    // The row that did not change keeps its time (the real server kept LastChangeTime).
    let r21 = env.reporting.status(id, rev(21, 1)).unwrap().unwrap();
    assert_eq!(
        r21.last_event_time,
        wsus_server_time("2026-10-06T19:31:57Z"),
        "an unchanged row keeps the time of its change"
    );
    let r22 = env.reporting.status(id, rev(22, 1)).unwrap().unwrap();
    assert_eq!(
        r22.last_event_time,
        wsus_server_time("2026-10-06T20:35:57Z")
    );

    // An update the catalog does not know cannot be keyed and is skipped; an older event does not
    // overwrite a newer status.
    let stale = status_event(4, &[], &[21, 999], "2026-10-06T10:00:00Z");
    assert!(env.call(&report(&c, vec![stale])).unwrap().result);
    assert_eq!(st(21), Some(S::NotInstalled));
    assert_eq!(st(999), None);
}

#[test]
fn reports_validate_cookie_registration_and_size() {
    let env = setup();
    let unregistered = handshake(&env, Uuid::from_u128(121), None);
    assert_eq!(
        env.fault_code(&report(&unregistered, vec![event(1, 1, None)])),
        ErrorCode::RegistrationRequired
    );
    let c = registered(&env, 122);
    let mut forged = report(&c, vec![event(1, 1, None)]);
    if let Presence::Value(ck) = &mut forged.cookie {
        ck.encrypted_data = Presence::Value(vec![0; 70]);
    }
    assert_eq!(env.fault_code(&forged), ErrorCode::InvalidCookie);
    let big: Vec<_> = (0..501).map(|n| event(n as u128 + 1000, 1, None)).collect();
    assert_eq!(
        env.fault_code(&report(&c, big)),
        ErrorCode::InvalidParameters
    );
    let mut no_basic = event(5, 1, None);
    no_basic.basic_data = Presence::Absent;
    assert_eq!(
        env.fault_code(&report(&c, vec![no_basic])),
        ErrorCode::InvalidParameters
    );
    // A rejected batch stores nothing.
    let id = ComputerId(Uuid::from_u128(122));
    let mut bad = event(6, 1, None);
    if let Presence::Value(b) = &mut bad.basic_data {
        b.time_at_target = XsDateTime::new("2026-10-04T12:00:00Z").unwrap();
    }
    let mixed = report(
        &c,
        vec![bad, {
            let mut e = event(7, 1, None);
            e.basic_data = Presence::Absent;
            e
        }],
    );
    assert!(env.call(&mixed).is_err());
    assert!(
        env.reporting
            .events_for_computer(id, None, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn soap12_clients_get_soap12_responses() {
    let env = setup();
    let resp = env.raw(
        SoapVersion::V12,
        &GetConfig {
            protocol_version: Presence::Value("1.8".into()),
        },
    );
    assert_eq!(resp.status, 200);
    assert!(
        resp.header("Content-Type")
            .unwrap()
            .starts_with("application/soap+xml")
    );
    let body = resp.into_bytes().unwrap();
    assert!(String::from_utf8_lossy(&body).contains("http://www.w3.org/2003/05/soap-envelope"));
}

// Observed on a real WSUS (2026-10-04): `IsLeaf` is false exactly for updates that are a
// prerequisite of something anywhere in the catalog, bundle members are leaves, and members
// carry `Action=Bundle`. A native Windows Update Agent given bundle members as non-leaf
// reported only 2 non-leaf updates installed and evaluated 5 of 442 delivered entities.
both_modes! {
mod bundles;
fn bundle_members_are_leaves_and_leafness_is_global_not_per_client(mode: SyncDelivery) {
    use wsus_protocol::wusp::DeploymentAction as WireAction;
    use wsus_server::catalog::{RelationshipImport, RelationshipKind};
    let env = setup_mode(mode);
    let mut bundle = with_prereq(frag(10), 13);
    for member in [11u128, 12] {
        bundle.relationships.push(RelationshipImport {
            kind: RelationshipKind::Bundle,
            target: uid(member),
            revision: None,
        });
    }
    // 14 is never approved, so a client never sees it, but its prerequisite on 12 makes 12
    // non-leaf for every client.
    env.publish(&[
        bundle,
        frag(11),
        frag(12),
        frag(13),
        with_prereq(frag(14), 12),
    ]);
    env.approve(10);
    let mut c = registered(&env, 41);
    let updates: Vec<UpdateInfo> = sync_rounds(&env, &mut c).concat();
    let updates = &updates;
    let by = |n: u128| {
        let id = local(&env, n);
        updates.iter().find(|u| u.id == id).expect("delivered")
    };
    assert!(by(10).is_leaf, "the bundle parent is a leaf");
    assert!(by(11).is_leaf, "a bundle member nothing requires is a leaf");
    assert!(
        !by(12).is_leaf,
        "a prerequisite of a hidden update is non-leaf for everyone"
    );
    assert!(!by(13).is_leaf, "a prerequisite is non-leaf");
    let action = |n: u128| by(n).deployment.value().unwrap().action.clone();
    assert_eq!(action(10), WireAction::Install);
    assert_eq!(action(11), WireAction::Bundle);
    assert_eq!(action(12), WireAction::Bundle);
    assert_eq!(action(13), WireAction::Evaluate);
    assert_eq!(updates.len(), 4, "14 is not in scope");
}
}
