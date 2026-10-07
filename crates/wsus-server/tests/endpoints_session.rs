//! Session cookies: forgery, expiry, rotation, restart, server and config binding.
mod endpoints_common;
use endpoints_common::*;

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use uuid::Uuid;
use wsus_protocol::common::Cookie;
use wsus_protocol::identity::ComputerId;
use wsus_protocol::soap::{ErrorCode, Presence};
use wsus_server::session::*;
use wsus_server::storage::Database;

fn session_claims() -> CookieClaims {
    let mut c = CookieClaims::new(CookieKind::Session, ComputerId(Uuid::from_u128(7)));
    c.target_group = Some("Workstations".into());
    c.dns_name = Some("pc1.example".into());
    c.catalog_generation = 3;
    c.policy_generation = 9;
    c
}

fn bytes_of(c: &Cookie) -> Vec<u8> {
    c.encrypted_data.value().cloned().unwrap()
}

fn with_bytes(c: &Cookie, b: Vec<u8>) -> Cookie {
    Cookie {
        expiration: c.expiration.clone(),
        encrypted_data: Presence::Value(b),
    }
}

#[test]
fn round_trip_preserves_claims_and_sets_expiry_from_the_clock() {
    let env = setup();
    let c = env.sessions.issue(&session_claims());
    let got = env
        .sessions
        .validate(Some(&c), CookieKind::Session)
        .unwrap();
    let want = session_claims();
    assert_eq!(got.computer, want.computer);
    assert_eq!(got.target_group, want.target_group);
    assert_eq!(got.dns_name, want.dns_name);
    assert_eq!(got.catalog_generation, 3);
    assert_eq!(got.policy_generation, 9);
    assert_eq!(
        got.expires_at - got.issued_at,
        SessionConfig::default().cookie_ttl
    );
}

#[test]
fn forged_truncated_and_garbage_cookies_are_invalid() {
    let env = setup();
    let c = env.sessions.issue(&session_claims());
    let good = bytes_of(&c);
    // Flip every single byte position in turn: none may validate.
    for i in 0..good.len() {
        let mut b = good.clone();
        b[i] ^= 0x01;
        assert_eq!(
            env.sessions
                .validate(Some(&with_bytes(&c, b)), CookieKind::Session),
            Err(CookieError::Invalid),
            "byte {i}"
        );
    }
    for b in [
        vec![],
        vec![0; 3],
        good[..good.len() - 1].to_vec(),
        vec![0xAA; 4096],
        {
            let mut x = good.clone();
            x.push(0);
            x
        },
    ] {
        assert_eq!(
            env.sessions
                .validate(Some(&with_bytes(&c, b)), CookieKind::Session),
            Err(CookieError::Invalid)
        );
    }
    assert_eq!(
        env.sessions.validate(None, CookieKind::Session),
        Err(CookieError::Invalid)
    );
}

#[test]
fn wire_expiration_field_is_not_trusted() {
    let env = setup();
    let c = env.sessions.issue(&session_claims());
    let lying = Cookie {
        expiration: xs("2999-01-01T00:00:00Z"),
        encrypted_data: c.encrypted_data.clone(),
    };
    env.advance(SessionConfig::default().cookie_ttl + 1);
    assert_eq!(
        env.sessions.validate(Some(&lying), CookieKind::Session),
        Err(CookieError::Expired)
    );
}

#[test]
fn cookie_expires_exactly_at_its_signed_expiry() {
    let env = setup();
    let c = env.sessions.issue(&session_claims());
    let ttl = SessionConfig::default().cookie_ttl;
    env.advance(ttl - 1);
    assert!(env.sessions.validate(Some(&c), CookieKind::Session).is_ok());
    env.advance(1);
    assert_eq!(
        env.sessions.validate(Some(&c), CookieKind::Session),
        Err(CookieError::Expired)
    );
}

#[test]
fn kinds_are_not_interchangeable() {
    let env = setup();
    let mut a = session_claims();
    a.kind = CookieKind::Authorization;
    let auth = env.sessions.issue(&a);
    assert_eq!(
        env.sessions.validate(Some(&auth), CookieKind::Session),
        Err(CookieError::Invalid)
    );
    let sess = env.sessions.issue(&session_claims());
    assert_eq!(
        env.sessions
            .validate(Some(&sess), CookieKind::Authorization),
        Err(CookieError::Invalid)
    );
}

#[test]
fn rotation_without_retention_invalidates_and_with_retention_allows_one_generation() {
    let env = setup();
    let c0 = env.sessions.issue(&session_claims());
    env.sessions.rotate(false).unwrap();
    assert_eq!(
        env.sessions.validate(Some(&c0), CookieKind::Session),
        Err(CookieError::Invalid)
    );
    let c1 = env.sessions.issue(&session_claims());
    assert!(
        env.sessions
            .validate(Some(&c1), CookieKind::Session)
            .is_ok()
    );

    env.sessions.rotate(true).unwrap();
    assert!(
        env.sessions
            .validate(Some(&c1), CookieKind::Session)
            .is_ok(),
        "previous key retained"
    );
    let c2 = env.sessions.issue(&session_claims());
    env.sessions.rotate(true).unwrap();
    assert!(
        env.sessions
            .validate(Some(&c2), CookieKind::Session)
            .is_ok()
    );
    assert_eq!(
        env.sessions.validate(Some(&c1), CookieKind::Session),
        Err(CookieError::Invalid),
        "two rotations retire the oldest key"
    );
}

#[test]
fn config_bump_yields_config_changed_and_server_flow_recovers() {
    let env = setup();
    let c = env.sessions.issue(&session_claims());
    env.sessions.bump_config().unwrap();
    assert_eq!(
        env.sessions.validate(Some(&c), CookieKind::Session),
        Err(CookieError::ConfigChanged)
    );
    // A new cookie works, and LastChange moved forward.
    let c2 = env.sessions.issue(&session_claims());
    assert!(
        env.sessions
            .validate(Some(&c2), CookieKind::Session)
            .is_ok()
    );
}

#[test]
fn cookie_from_another_server_with_the_same_key_reports_server_changed() {
    let a = setup();
    let b = setup();
    // Share the signing key (for example a restored key file with a rebuilt database).
    let key =
        a.db.with_conn(|c| {
            Ok(c.query_row(
                "SELECT value FROM meta WHERE key='wusp_session_key_current'",
                [],
                |r| r.get::<_, String>(0),
            )?)
        })
        .unwrap();
    b.db.with_conn(|c| {
        c.execute(
            "UPDATE meta SET value=?1 WHERE key='wusp_session_key_current'",
            [&key],
        )?;
        Ok(())
    })
    .unwrap();
    let b2 = SessionManager::open(
        b.db.clone(),
        SessionConfig::default(),
        &default_config().fingerprint(),
    )
    .unwrap();
    let c = a.sessions.issue(&session_claims());
    // Same generation numbers on both sides, different server ids.
    assert_eq!(
        b2.validate(Some(&c), CookieKind::Session),
        Err(CookieError::ServerChanged)
    );
    // Without the shared key the cookie is simply invalid.
    assert_eq!(
        b.sessions.validate(Some(&c), CookieKind::Session),
        Err(CookieError::Invalid)
    );
}

#[test]
fn key_and_generation_survive_restart_and_config_change_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let fp = default_config().fingerprint();
    let (cookie, last_change) = {
        let db = Database::open(&path).unwrap();
        let m = SessionManager::open(db, SessionConfig::default(), &fp).unwrap();
        (m.issue(&session_claims()), m.state().config_last_change)
    };
    {
        let db = Database::open(&path).unwrap();
        let m = SessionManager::open(db, SessionConfig::default(), &fp).unwrap();
        assert!(
            m.validate(Some(&cookie), CookieKind::Session).is_ok(),
            "same key after restart"
        );
        assert_eq!(m.state().config_last_change, last_change);
        // Rotation persists too.
        m.rotate(true).unwrap();
    }
    {
        let db = Database::open(&path).unwrap();
        let m = SessionManager::open(db, SessionConfig::default(), &fp).unwrap();
        assert!(
            m.validate(Some(&cookie), CookieKind::Session).is_ok(),
            "retained previous key survives restart"
        );
        let fresh = m.issue(&session_claims());
        drop(m);
        // Changed wire-visible configuration advances the generation at startup.
        let db = Database::open(&path).unwrap();
        let mut cfg = default_config();
        cfg.max_extended_updates_per_request = 7;
        let m = SessionManager::open(db, SessionConfig::default(), &cfg.fingerprint()).unwrap();
        assert_eq!(
            m.validate(Some(&fresh), CookieKind::Session),
            Err(CookieError::ConfigChanged)
        );
        assert!(m.state().config_last_change > last_change);
    }
}

#[test]
fn key_file_material_is_not_printed() {
    let env = setup();
    let dbg = format!("{:?}", env.sessions);
    assert!(!dbg.contains("wusp_session_key"));
}

#[test]
fn validation_needs_no_database_access() {
    let env = setup();
    let good = env.sessions.issue(&session_claims());
    let forged = with_bytes(&good, vec![9; 80]);
    let sessions = env.sessions.clone();
    let (tx, rx) = mpsc::channel();
    // Hold the database lock; if validate touched the database it could not finish.
    env.db
        .with_conn(|_| {
            let s = Arc::clone(&sessions);
            let g = good.clone();
            std::thread::spawn(move || {
                let _ = tx.send((
                    s.validate(Some(&g), CookieKind::Session).is_ok(),
                    s.validate(Some(&forged), CookieKind::Session).is_err(),
                ));
            });
            let got = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("validate blocked on the database");
            assert_eq!(got, (true, true));
            Ok(())
        })
        .unwrap();
}

#[test]
fn endpoints_reject_bad_cookies_before_any_data_access() {
    let env = setup();
    env.publish(&[frag(1)]);
    env.approve(1);
    let c = registered(&env, 11);
    let server = env.server.clone();
    let mut bad = c.cookie.clone();
    bad.encrypted_data = Presence::Value(vec![1; 90]);
    let req = sync_req(&bad, &[], &[]);
    let enc = wsus_protocol::soap::encode_request(wsus_protocol::soap::SoapVersion::V11, &req);
    let (tx, rx) = mpsc::channel();
    env.db
        .with_conn(|_| {
            let http = wsus_server::endpoints::HttpRequestParts::new("POST", CLIENT_PATH)
                .with_header("Content-Type", &enc.content_type)
                .with_header("SOAPAction", enc.soap_action.as_deref().unwrap())
                .with_body(enc.body.clone());
            std::thread::spawn(move || {
                let _ = tx.send(server.handle(http).status);
            });
            let status = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("handler touched the database before validating the cookie");
            assert_eq!(status, 500);
            Ok(())
        })
        .unwrap();
}

#[test]
fn protocol_level_cookie_faults_map_to_the_specified_error_codes() {
    let env = setup();
    env.publish(&[frag(1)]);
    env.approve(1);
    let c = registered(&env, 12);

    // forged
    let mut forged = c.cookie.clone();
    if let Presence::Value(b) = &mut forged.encrypted_data {
        b[10] ^= 1;
    }
    assert_eq!(
        env.fault_code(&sync_req(&forged, &[], &[])),
        ErrorCode::InvalidCookie
    );
    // absent
    let mut absent = sync_req(&c.cookie, &[], &[]);
    absent.cookie = Presence::Absent;
    assert_eq!(env.fault_code(&absent), ErrorCode::InvalidCookie);
    // rotated
    env.sessions.rotate(false).unwrap();
    assert_eq!(
        env.fault_code(&sync_req(&c.cookie, &[], &[])),
        ErrorCode::InvalidCookie
    );
    // fresh handshake after rotation works and then expires
    let c2 = handshake(&env, Uuid::from_u128(12), None);
    assert!(env.call(&sync_req(&c2.cookie, &[], &[])).is_ok());
    env.advance(SessionConfig::default().cookie_ttl + 1);
    assert_eq!(
        env.fault_code(&sync_req(&c2.cookie, &[], &[])),
        ErrorCode::CookieExpired
    );
    // config change
    let c3 = handshake(&env, Uuid::from_u128(12), None);
    env.sessions.bump_config().unwrap();
    assert_eq!(
        env.fault_code(&sync_req(&c3.cookie, &[], &[])),
        ErrorCode::ConfigChanged
    );
    // GetCookie with a stale LastChange
    let auth = auth_cookie(&env, Uuid::from_u128(12), None);
    let mut stale = get_cookie_req(&env, auth, None);
    stale.last_change = xs("2001-01-01T00:00:00Z");
    assert_eq!(env.fault_code(&stale), ErrorCode::ConfigChanged);
    // A session cookie is not an authorization cookie.
    let sess = handshake(&env, Uuid::from_u128(12), None).cookie;
    let as_auth = wsus_protocol::common::AuthorizationCookie {
        plug_in_id: Presence::Value("SimpleTargeting".into()),
        cookie_data: sess.encrypted_data.clone(),
    };
    assert_eq!(
        env.fault_code(&get_cookie_req(&env, as_auth, None)),
        ErrorCode::InvalidAuthorizationCookie
    );
}

#[test]
fn get_cookie_requires_exactly_one_authorization_cookie_and_a_known_plugin() {
    let env = setup();
    let auth = auth_cookie(&env, Uuid::from_u128(13), None);
    let mut none = get_cookie_req(&env, auth.clone(), None);
    none.auth_cookies = Presence::Value(vec![]);
    assert_eq!(env.fault_code(&none), ErrorCode::InvalidParameters);
    let mut two = get_cookie_req(&env, auth.clone(), None);
    two.auth_cookies = Presence::Value(vec![auth.clone(), auth.clone()]);
    assert_eq!(env.fault_code(&two), ErrorCode::InvalidParameters);
    let mut other = auth;
    other.plug_in_id = Presence::Value("Other".into());
    assert_eq!(
        env.fault_code(&get_cookie_req(&env, other, None)),
        ErrorCode::InvalidAuthorizationCookie
    );
}

#[test]
fn old_cookie_state_is_copied_into_the_new_cookie() {
    let env = setup();
    env.publish(&[frag(1), frag(2)]);
    env.approve(1);
    env.approve(2);
    let mut c = registered(&env, 14);
    let info = sync(&env, &mut c, &[], &[]);
    assert_eq!(new_ids(&info).len(), 2);
    // Re-handshake passing the old cookie: still the same computer, not rejected.
    let auth = auth_cookie(&env, Uuid::from_u128(14), None);
    let fresh = env
        .call(&get_cookie_req(&env, auth, Some(c.cookie.clone())))
        .unwrap()
        .result
        .into_value()
        .unwrap();
    assert!(env.call(&sync_req(&fresh, &[], &[])).is_ok());
}
