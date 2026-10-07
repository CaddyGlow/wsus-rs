//! Client, SimpleAuth operations.
use std::collections::BTreeSet;

use uuid::Uuid;
use wsus_protocol::common::{AuthorizationCookie, Cookie};
use wsus_protocol::identity::{ComputerId, DigestAlgorithm, UpdateRevision};
use wsus_protocol::soap::{ErrorCode, Presence};
use wsus_protocol::wusp::*;

use super::fault::{ApiError, invalid};
use super::scope::{self, Scope, ScopedUpdate};
use super::time::{format_date, format_xs, parse_xs};
use super::{AUTH_PLUGIN_ID, AUTH_SERVICE_URL, Ctx, DeliveryScope, SyncDelivery};
use crate::catalog::{FileDescriptor, GenerationId, Snapshot};
use crate::computers::ComputerDetails;
use crate::content::ContentDescriptor;
use crate::fragments::{self, PrefixMap, WuspFragments, select_language};
use crate::policy::{self, VisibleUpdate};
use crate::session::{CookieClaims, CookieError, CookieKind};

/// Namespace for deriving a computer id from a `clientId` that is not a GUID.
const CLIENT_ID_NAMESPACE: Uuid = Uuid::from_u128(0x7c1d_9a52_3b0e_4f6a_8d21_5e90_a4c7_b3f8);
const MAX_TEXT: usize = 256;

fn text(p: &Presence<String>) -> Option<&str> {
    p.value()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn session(cx: &Ctx<'_>, cookie: &Presence<Cookie>) -> Result<CookieClaims, ApiError> {
    Ok(cx
        .inner
        .svc
        .sessions
        .validate(cookie.value(), CookieKind::Session)?)
}

fn renew(cx: &Ctx<'_>, claims: &CookieClaims) -> Cookie {
    cx.inner.svc.sessions.issue(claims)
}

// ---- GetConfig ---------------------------------------------------------------------

pub(crate) fn get_config(cx: &Ctx<'_>, req: GetConfig) -> Result<GetConfigResponse, ApiError> {
    if let Some(v) = text(&req.protocol_version) {
        let ok = v.split_once('.').is_some_and(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit())
        });
        if !ok {
            return Err(invalid("protocolVersion must be major.minor"));
        }
    }
    let c = &cx.inner.config;
    let prop = |n: &str, v: String| ConfigurationProperty {
        name: Presence::Value(n.into()),
        value: Presence::Value(v),
    };
    Ok(GetConfigResponse {
        result: Presence::Value(Config {
            last_change: cx.inner.svc.sessions.config_last_change(),
            is_registration_required: true,
            auth_info: Presence::Value(vec![AuthPlugInInfo {
                plug_in_id: Presence::Value(AUTH_PLUGIN_ID.into()),
                service_url: Presence::Value(AUTH_SERVICE_URL.into()),
                parameter: Presence::Absent,
            }]),
            allowed_event_ids: if c.allowed_event_ids.is_empty() {
                Presence::Absent
            } else {
                Presence::Value(c.allowed_event_ids.clone())
            },
            properties: Presence::Value(vec![
                prop(
                    "MaxExtendedUpdatesPerRequest",
                    c.max_extended_updates_per_request.to_string(),
                ),
                prop("ProtocolVersion", c.effective_protocol_version().into()),
                prop("IsInventoryRequired", "0".into()),
                prop("ClientReportingLevel", "2".into()),
            ]),
        }),
    })
}

// ---- GetAuthorizationCookie --------------------------------------------------------

fn computer_id(client_id: &str) -> ComputerId {
    match Uuid::parse_str(client_id) {
        Ok(u) => ComputerId(u),
        Err(_) => ComputerId(Uuid::new_v5(&CLIENT_ID_NAMESPACE, client_id.as_bytes())),
    }
}

pub(crate) fn authorization_cookie(
    cx: &Ctx<'_>,
    req: GetAuthorizationCookie,
) -> Result<GetAuthorizationCookieResponse, ApiError> {
    let client_id = text(&req.client_id).ok_or(invalid("clientId is required"))?;
    let dns = text(&req.dns_name).ok_or(invalid("dnsName is required"))?;
    if client_id.len() > MAX_TEXT || dns.len() > MAX_TEXT {
        return Err(invalid("clientId or dnsName too long"));
    }
    let mut claims = CookieClaims::new(CookieKind::Authorization, computer_id(client_id));
    claims.target_group = text(&req.target_group_name)
        .filter(|g| g.len() <= MAX_TEXT)
        .map(str::to_owned);
    claims.dns_name = Some(dns.to_owned());
    let cookie = cx.inner.svc.sessions.issue(&claims);
    Ok(GetAuthorizationCookieResponse {
        result: Presence::Value(AuthorizationCookie {
            plug_in_id: Presence::Value(AUTH_PLUGIN_ID.into()),
            cookie_data: Presence::Value(cookie.encrypted_data.into_value().unwrap_or_default()),
        }),
    })
}

// ---- GetCookie ---------------------------------------------------------------------

pub(crate) fn get_cookie(cx: &Ctx<'_>, req: GetCookie) -> Result<GetCookieResponse, ApiError> {
    let sessions = &cx.inner.svc.sessions;
    let auths = req
        .auth_cookies
        .value()
        .filter(|a| a.len() == 1)
        .ok_or(invalid("exactly one authorization cookie is required"))?;
    let auth = &auths[0];
    if auth.plug_in_id.value().map(String::as_str) != Some(AUTH_PLUGIN_ID) {
        return Err(ApiError::Code(
            ErrorCode::InvalidAuthorizationCookie,
            "unknown authorization plug-in",
        ));
    }
    let claims = sessions
        .validate_bytes(
            auth.cookie_data.value().map(Vec::as_slice),
            CookieKind::Authorization,
        )
        .map_err(|e| match e {
            CookieError::Invalid => ApiError::Code(
                ErrorCode::InvalidAuthorizationCookie,
                "invalid authorization cookie",
            ),
            other => other.into(),
        })?;
    let last_change = parse_xs(req.last_change.as_str()).ok_or(invalid("bad lastChange"))?;
    if last_change != sessions.state().config_last_change {
        return Err(CookieError::ConfigChanged.into());
    }
    let mut session = CookieClaims::new(CookieKind::Session, claims.computer);
    session.target_group = claims.target_group;
    session.dns_name = claims.dns_name;
    // Copy synchronization state from a still-valid old cookie of the same computer
    // ("SHOULD copy state"); an unusable old cookie is ignored ("MAY ignore").
    if let Ok(old) = sessions.validate(req.old_cookie.value(), CookieKind::Session)
        && old.computer == session.computer
    {
        session.catalog_generation = old.catalog_generation;
        session.policy_generation = old.policy_generation;
    }
    Ok(GetCookieResponse {
        result: Presence::Value(sessions.issue(&session)),
    })
}

// ---- RegisterComputer --------------------------------------------------------------

pub(crate) fn register_computer(
    cx: &Ctx<'_>,
    req: RegisterComputer,
) -> Result<RegisterComputerResponse, ApiError> {
    let claims = session(cx, &req.cookie)?;
    let info = req
        .computer_info
        .value()
        .ok_or(invalid("computerInfo is required"))?;
    let dns = text(&info.dns_name);
    if let (Some(a), Some(b)) = (dns, claims.dns_name.as_deref())
        && !a.eq_ignore_ascii_case(b)
    {
        return Err(invalid("DnsName differs from the authorization request"));
    }
    let mut details = ComputerDetails {
        dns_name: dns.map(str::to_owned),
        os_version: Some(format!(
            "{}.{}.{}",
            info.os_major_version, info.os_minor_version, info.os_build_number
        )),
        ip_address: None,
        client_version: Some(format!(
            "{}.{}.{}.{}",
            info.client_version_major_number,
            info.client_version_minor_number,
            info.client_version_build_number,
            info.client_version_qfe_number
        )),
        extra: Default::default(),
    };
    for (k, v) in [
        ("manufacturer", &info.computer_manufacturer),
        ("model", &info.computer_model),
        ("bios_version", &info.bios_version),
        ("bios_name", &info.bios_name),
        ("os_locale", &info.os_locale),
        ("processor_architecture", &info.processor_architecture),
        ("os_description", &info.os_description),
    ] {
        if let Some(v) = text(v) {
            details
                .extra
                .insert(k.into(), v.chars().take(MAX_TEXT).collect());
        }
    }
    cx.inner
        .svc
        .computers
        .register(claims.computer, &details, claims.target_group.as_deref())?;
    Ok(RegisterComputerResponse {})
}

// ---- catalog access ----------------------------------------------------------------

/// Snapshot to serve. `pinned` continues an in-progress synchronization on the generation
/// it started on; otherwise the source's active generation is used. `None` means there is
/// no active catalog yet.
pub(super) fn snapshot(cx: &Ctx<'_>, pinned: i64) -> Result<Option<Snapshot>, ApiError> {
    let cat = &cx.inner.svc.catalog;
    if pinned != 0
        && let Ok(s) = cat.snapshot_of(GenerationId(pinned))
    {
        return Ok(Some(s));
    }
    let Some(source) = cat.source_by_name(&cx.inner.config.source_name)? else {
        return Ok(None);
    };
    Ok(cat.snapshot(source.id)?)
}

fn registered(cx: &Ctx<'_>, computer: ComputerId) -> Result<(), ApiError> {
    match cx.inner.svc.computers.get(computer)? {
        Some(_) => Ok(()),
        None => Err(ApiError::Code(
            ErrorCode::RegistrationRequired,
            "registration required",
        )),
    }
}

/// Wire deployment id: a stable positive 31-bit value taken from the approval GUID.
fn deployment_id(v: &VisibleUpdate) -> i32 {
    let b = v
        .approvals
        .first()
        .map(|d| *d.0.as_bytes())
        .unwrap_or([0; 16]);
    let n = i32::from_be_bytes([b[0] & 0x7f, b[1], b[2], b[3]]);
    n.max(1)
}

fn deployment(cx: &Ctx<'_>, v: &VisibleUpdate) -> Result<Deployment, ApiError> {
    let mut changed = 0;
    for id in &v.approvals {
        if let Some(a) = cx.inner.svc.policy.approval(*id)? {
            changed = changed.max(a.created_at);
        }
    }
    Ok(Deployment {
        id: deployment_id(v),
        action: match v.action {
            policy::DeploymentAction::Install => DeploymentAction::Install,
            policy::DeploymentAction::Uninstall => DeploymentAction::Uninstall,
        },
        deadline: v
            .deadline
            .map_or(Presence::Absent, |d| Presence::Value(format_xs(d))),
        // Observed (real WSUS, 2026-10-04): an approval with no deadline is still
        // `IsAssigned=true`, `LastChangeTime` is date-only, and `AutoSelect`,
        // `AutoDownload` and `SupersedenceBehavior` are present with value 0.
        is_assigned: true,
        last_change_time: format_date(changed),
        download_priority: Presence::Absent,
        hardware_ids: Presence::Absent,
        auto_select: Presence::Value("0".into()),
        auto_download: Presence::Value("0".into()),
        supersedence_behavior: Presence::Value("0".into()),
        flag_bitmask: Presence::Absent,
        client_behaviors: Presence::Absent,
    })
}

/// Deployment for an update that is in scope only as metadata (a prerequisite, category or
/// bundle member). Observed on a real WSUS (2026-10-04): every one of 159 `UpdateInfo`
/// elements carries a `Deployment`, with `Action` `Evaluate` (69), `Bundle` (86) or
/// `PreDeploymentCheck` (3, not reproduced here: the rule that selects it is unknown). A
/// native Windows Update Agent fails `PopulateDataStore` with `E_INVALIDARG` (from its time
/// conversion) when a revision has no deployment, so the element must never be omitted. The
/// id is the local revision id; `LastChangeTime` is the date of the last configuration change.
fn evaluate_deployment(cx: &Ctx<'_>, u: &ScopedUpdate) -> Deployment {
    Deployment {
        id: u.record.local.id,
        action: if u.bundled {
            DeploymentAction::Bundle
        } else if u.software {
            // `all_non_declined` only (the approved scope never marks `software`): an
            // unapproved software update that is not a bundle member. Observed on a real WSUS
            // for unapproved bundle parents (441 of 441); for other unapproved software the
            // same action is INFERRED (no such update exists in the real catalogs).
            DeploymentAction::PreDeploymentCheck
        } else {
            DeploymentAction::Evaluate
        },
        deadline: Presence::Absent,
        is_assigned: true,
        last_change_time: cx
            .inner
            .svc
            .sessions
            .config_last_change()
            .as_str()
            .get(..10)
            .unwrap_or("1970-01-01")
            .to_string(),
        download_priority: Presence::Absent,
        hardware_ids: Presence::Absent,
        auto_select: Presence::Value("0".into()),
        auto_download: Presence::Value("0".into()),
        supersedence_behavior: Presence::Value("0".into()),
        flag_bitmask: Presence::Absent,
        client_behaviors: Presence::Absent,
    }
}

fn xml_of(bytes: &[u8]) -> Result<String, ApiError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| ApiError::Internal)
}

/// WUSP fragments of a catalog record: stored fragments as they are, whole update
/// documents (what the downstream importer stores) derived on read. See
/// [`crate::fragments`]. A document that cannot be transformed is an internal error, not a
/// guess.
fn wusp_fragments(snap: &Snapshot, u: &ScopedUpdate) -> Result<WuspFragments, ApiError> {
    let record = u.full(snap)?;
    fragments::wusp_fragments(
        &record,
        &PrefixMap::specified(),
        &wsus_protocol::soap::Limits::stored_documents(),
    )
    .map_err(|_| ApiError::Internal)
}

/// The scope of `computer` under the configured delivery rule.
fn scope_of(cx: &Ctx<'_>, snap: &Snapshot, computer: ComputerId) -> Result<Scope, ApiError> {
    Ok(match cx.inner.config.delivery_scope {
        DeliveryScope::Approved => scope::compute(snap, &cx.inner.svc.policy, computer)?,
        DeliveryScope::AllNonDeclined => {
            scope::compute_all(snap, &cx.inner.svc.policy, computer, &cx.inner.all_index)?
        }
    })
}

// ---- SyncUpdates -------------------------------------------------------------------

/// `DriverSyncNotNeeded` of a software pass. Observed (2026-10-04, WS2025 10.0.26100): the
/// software-pass responses of the unfiltered `flow` capture said `false` (a driver pass
/// follows) and those of the category-filtered OOBE `scan` capture said `true`. The only
/// request difference we can name is `FilterCategoryIds`, so a filtered scan answers `true`
/// (Implementation decision; the real rule is unknown).
fn software_pass_driver_sync_not_needed(p: &SyncUpdateParameters) -> bool {
    p.filter_category_ids.value().is_some_and(|f| !f.is_empty())
}

pub(crate) fn sync_updates(
    cx: &Ctx<'_>,
    req: SyncUpdates,
) -> Result<SyncUpdatesResponse, ApiError> {
    let mut claims = session(cx, &req.cookie)?;
    registered(cx, claims.computer)?;
    let p = req
        .parameters
        .value()
        .ok_or(invalid("parameters are required"))?;
    if p.express_query {
        return Err(invalid("ExpressQuery is not supported"));
    }
    if p.system_spec.value().is_some_and(|d| !d.is_empty()) && !p.skip_software_sync {
        return Err(invalid("SystemSpec requires SkipSoftwareSync"));
    }
    let installed: Vec<i32> = p
        .installed_non_leaf_update_ids
        .value()
        .cloned()
        .unwrap_or_default();
    let other: Vec<i32> = p
        .other_cached_update_ids
        .value()
        .cloned()
        .unwrap_or_default();
    let cfg = &cx.inner.config;
    let staged_mode = cfg.sync_delivery == SyncDelivery::Staged;
    // Observed on the real WSUS: 400 ids accepted, 401 rejected with InvalidParameters
    // naming `parameters.InstalledNonLeafUpdateIDs`.
    if staged_mode
        && cfg.max_installed_non_leaf_ids != 0
        && installed.len() > cfg.max_installed_non_leaf_ids
    {
        return Err(invalid("parameters.InstalledNonLeafUpdateIDs"));
    }
    let first_call = installed.is_empty() && other.is_empty();
    let policy_gen = cx.inner.svc.policy.generation()?;
    cx.inner.svc.computers.record_sync(claims.computer)?;

    let pinned = if first_call {
        0
    } else {
        claims.catalog_generation
    };
    let snap = snapshot(cx, pinned)?;
    let mut info = SyncInfo {
        new_updates: Presence::Value(Vec::new()),
        out_of_scope_revision_ids: Presence::Absent,
        changed_updates: Presence::Absent,
        truncated: false,
        new_cookie: Presence::Absent,
        deployed_out_of_scope_revision_ids: Presence::Absent,
        driver_sync_not_needed: Presence::Absent,
    };
    let mut next_generation = 0;
    if p.skip_software_sync {
        // Driver pass (Observed, flow 000014 and scan 000009): no `NewUpdates` element and
        // `DriverSyncNotNeeded` true; this server has no driver catalog.
        info.new_updates = Presence::Absent;
        info.driver_sync_not_needed = Presence::Value("true".into());
    } else {
        info.driver_sync_not_needed = Presence::Value(
            if software_pass_driver_sync_not_needed(p) {
                "true"
            } else {
                "false"
            }
            .into(),
        );
    }
    if let (Some(snap), false) = (&snap, p.skip_software_sync) {
        let scope = scope_of(cx, snap, claims.computer)?;
        let cached: BTreeSet<i32> = installed.iter().chain(other.iter()).copied().collect();
        let (out, holdable, fresh): (Vec<i32>, BTreeSet<i32>, Vec<&ScopedUpdate>) = if staged_mode {
            let st = scope::staged(
                &cx.inner.clauses,
                snap,
                &scope,
                &installed,
                &other,
                cfg.out_of_scope_unsatisfied,
            )?;
            let fresh = st.deliverable.iter().map(|&i| &scope.updates[i]).collect();
            (st.out_of_scope, st.held, fresh)
        } else {
            let in_scope = scope.local_ids();
            (
                cached.difference(&in_scope).copied().collect(),
                cached.clone(),
                scope
                    .updates
                    .iter()
                    .filter(|u| !cached.contains(&u.record.local.id))
                    .collect(),
            )
        };
        if !out.is_empty() {
            info.out_of_scope_revision_ids = Presence::Value(out);
        }
        // Deployment changes since the cookie's policy generation, for revisions the client
        // already holds.
        if claims.policy_generation != policy_gen && !first_call {
            let mut changed = Vec::new();
            for u in scope
                .updates
                .iter()
                .filter(|u| holdable.contains(&u.record.local.id))
            {
                if let Some(d) = &u.deployment {
                    changed.push(update_info(cx, snap, u, Some(d), false)?);
                }
            }
            if !changed.is_empty() {
                info.changed_updates = Presence::Value(changed);
            }
        }
        let limit = cfg.max_sync_new_updates.max(1);
        info.truncated = fresh.len() > limit;
        let mut new = Vec::new();
        let mut delivered_non_leaf = false;
        for u in fresh.into_iter().take(limit) {
            delivered_non_leaf |= !u.is_leaf;
            new.push(update_info(cx, snap, u, u.deployment.as_ref(), true)?);
        }
        info.new_updates = Presence::Value(new);
        // The pin only lives while a sequence is in progress; the final page releases it so
        // the next scan reads the then-active generation. In staged mode a sequence also
        // continues after a complete response that delivered a non-leaf update, because the
        // client must call again (MS-WUSP 3.1.5.7) and the answer depends on the same catalog.
        if info.truncated || (staged_mode && delivered_non_leaf) {
            next_generation = snap.generation().0;
        }
    }
    claims.catalog_generation = next_generation;
    claims.policy_generation = policy_gen;
    info.new_cookie = Presence::Value(renew(cx, &claims));
    Ok(SyncUpdatesResponse {
        result: Presence::Value(info),
    })
}

// ---- StartCategoryScan -------------------------------------------------------------

/// Most categories a request may name; the specification records that WSUS 3.0 SP2 rejects
/// 200 or more (inventory 5.2).
const MAX_SCAN_CATEGORIES: usize = 200;

/// `StartCategoryScan`. Observed (scan 000005): the request carries no cookie, and the real
/// server echoed the requested category in `preferredCategoryIds` with no
/// `requestedCategoryIdsInError`. Implementation decision for what "preferred" means: a
/// requested category that exists in the catalog this server serves (any revision, any update
/// type, `Present`) is preferred, in order of first appearance and without duplicates; one
/// that does not exist is reported in `requestedCategoryIdsInError`. The DNF structure
/// (`IndexOfAndGroup`) is validated but does not change the answer, because the server does
/// not narrow `SyncUpdates` by category (the filter is accepted and ignored).
pub(crate) fn start_category_scan(
    cx: &Ctx<'_>,
    req: StartCategoryScan,
) -> Result<StartCategoryScanResponse, ApiError> {
    let wanted = req
        .requested_categories
        .value()
        .filter(|c| !c.is_empty())
        .ok_or(invalid("requestedCategories is required"))?;
    if wanted.len() >= MAX_SCAN_CATEGORIES || wanted.iter().any(|c| c.index_of_and_group < 0) {
        return Err(invalid("requestedCategories"));
    }
    let snap = snapshot(cx, 0)?;
    let (mut preferred, mut in_error) = (Vec::new(), Vec::new());
    for c in wanted {
        let id = wsus_protocol::identity::UpdateId(c.category_id);
        let exists = match &snap {
            Some(s) => s.has_present_update(id)?,
            None => false,
        };
        let list = if exists {
            &mut preferred
        } else {
            &mut in_error
        };
        if !list.contains(&c.category_id) {
            list.push(c.category_id);
        }
    }
    Ok(StartCategoryScanResponse {
        preferred_category_ids: opt(preferred),
        requested_category_ids_in_error: opt(in_error),
    })
}

fn update_info(
    cx: &Ctx<'_>,
    snap: &Snapshot,
    u: &ScopedUpdate,
    dep: Option<&VisibleUpdate>,
    with_xml: bool,
) -> Result<UpdateInfo, ApiError> {
    Ok(UpdateInfo {
        id: u.record.local.id,
        deployment: Presence::Value(match dep {
            Some(d) => deployment(cx, d)?,
            None => evaluate_deployment(cx, u),
        }),
        is_leaf: u.is_leaf,
        xml: if with_xml {
            Presence::Value(xml_of(&wusp_fragments(snap, u)?.core)?)
        } else {
            Presence::Absent
        },
    })
}

// ---- RefreshCache ------------------------------------------------------------------

pub(crate) fn refresh_cache(
    cx: &Ctx<'_>,
    req: RefreshCache,
) -> Result<RefreshCacheResponse, ApiError> {
    let claims = session(cx, &req.cookie)?;
    registered(cx, claims.computer)?;
    let ids: Vec<UpdateRevision> = req.global_ids.value().cloned().unwrap_or_default();
    let mut out = Vec::new();
    if let Some(snap) = snapshot(cx, 0)? {
        let scope = scope_of(cx, &snap, claims.computer)?;
        for id in ids {
            if let Some(u) = scope.updates.iter().find(|u| u.record.identity == id) {
                out.push(RefreshCacheResult {
                    revision_id: u.record.local.id,
                    global_id: Presence::Value(id),
                    is_leaf: u.is_leaf,
                    deployment: Presence::Value(match &u.deployment {
                        Some(d) => deployment(cx, d)?,
                        None => evaluate_deployment(cx, u),
                    }),
                });
            }
        }
    }
    Ok(RefreshCacheResponse {
        result: Presence::Value(out),
    })
}

// ---- file locations ----------------------------------------------------------------

fn sha1_of(f: &FileDescriptor) -> Option<&[u8]> {
    f.digests
        .iter()
        .find(|d| d.algorithm == DigestAlgorithm::Sha1)
        .map(|d| d.bytes.as_slice())
}

fn file_url(base: &str, sha1: &[u8], file_name: &str) -> String {
    let hex = crate::storage::hex_encode(sha1).to_ascii_uppercase();
    let ext: String = file_name
        .rsplit_once('.')
        .map(|(_, e)| e)
        .filter(|e| !e.is_empty() && e.len() <= 8 && e.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(|e| format!(".{}", e.to_ascii_lowercase()))
        .unwrap_or_default();
    format!(
        "{}/Content/{}/{hex}{ext}",
        base.trim_end_matches('/'),
        &hex[hex.len() - 2..]
    )
}

/// Location for a file, only if its content is verified-available in the store. Metadata
/// publication and content availability are independent: a file that is described but not
/// downloaded yields `None`.
fn location(cx: &Ctx<'_>, f: &FileDescriptor, v2: bool) -> Result<Option<FileLocation>, ApiError> {
    let Some(sha1) = sha1_of(f) else {
        return Ok(None);
    };
    let desc = ContentDescriptor {
        file_name: f.file_name.clone(),
        size: f.size,
        digests: f.digests.clone(),
    };
    // `all_non_declined` answers like the real WSUS, which returned a location for a file of an
    // update it had never downloaded (Observed, inventory 12.17: the URL then answered 404).
    // The default scope keeps the earlier rule: only content verified-available is announced.
    if cx.inner.config.delivery_scope == DeliveryScope::Approved
        && cx.inner.svc.content.find_available(&desc)?.is_none()
    {
        return Ok(None);
    }
    let base = cx.base_url.as_deref().ok_or(ApiError::Internal)?;
    Ok(Some(FileLocation {
        file_digest: Presence::Value(sha1.to_vec()),
        url: Presence::Value(file_url(base, sha1, &f.file_name)),
        pieces_hash_url: Presence::Absent,
        block_map_url: Presence::Absent,
        decryption_information: Presence::Absent,
        file_digest_algorithm: if v2 {
            Presence::Value("SHA1".into())
        } else {
            Presence::Absent
        },
        encrypted_file_digest: Presence::Absent,
        encrypted_file_digest_algorithm: Presence::Absent,
    }))
}

pub(crate) fn file_locations(
    cx: &Ctx<'_>,
    req: GetFileLocations,
) -> Result<GetFileLocationsResponse, ApiError> {
    let claims = session(cx, &req.cookie)?;
    let digests: Vec<Vec<u8>> = req.file_digests.value().cloned().unwrap_or_default();
    if digests.len() > cx.inner.config.max_file_digests_per_request
        || digests.iter().any(|d| d.len() != 20)
    {
        return Err(invalid(
            "fileDigests must be 20-byte SHA-1 values within the limit",
        ));
    }
    registered(cx, claims.computer)?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(snap) = snapshot(cx, 0)? {
        let scope = scope_of(cx, &snap, claims.computer)?;
        for d in digests {
            if !seen.insert(d.clone()) {
                continue;
            }
            if let Some(f) = scope.file_by_sha1(&snap, &d)? {
                out.extend(location(cx, &f, false)?);
            }
        }
    }
    Ok(GetFileLocationsResponse {
        result: Presence::Value(GetFileLocationsResults {
            file_locations: Presence::Value(out),
            new_cookie: Presence::Value(renew(cx, &claims)),
        }),
    })
}

// ---- extended update info ----------------------------------------------------------

fn check_types(
    cx: &Ctx<'_>,
    types: &Presence<Vec<XmlUpdateFragmentType>>,
    locales: &Presence<Vec<String>>,
    count: usize,
) -> Result<Vec<XmlUpdateFragmentType>, ApiError> {
    let types = types.value().cloned().unwrap_or_default();
    if types.is_empty() {
        return Err(invalid("infoTypes is required"));
    }
    if count > cx.inner.config.max_extended_updates_per_request {
        return Err(invalid("too many updates requested"));
    }
    let needs_locale = types.iter().any(|t| {
        matches!(
            t,
            XmlUpdateFragmentType::Eula | XmlUpdateFragmentType::LocalizedProperties
        )
    });
    if needs_locale && locales.value().is_none_or(|l| l.is_empty()) {
        return Err(invalid(
            "locales are required for Eula and LocalizedProperties",
        ));
    }
    Ok(types)
}

/// `Updates` entries for one in-scope update. Core and Extended come from the stored or
/// derived fragments; LocalizedProperties and Eula exist only for records that were derived
/// from a whole update document (stored WUSP-form records have no slot for them) and are
/// selected by the requested locales.
fn fragments(
    snap: &Snapshot,
    u: &ScopedUpdate,
    types: &[XmlUpdateFragmentType],
    locales: &[String],
) -> Result<Vec<UpdateData>, ApiError> {
    let f = wusp_fragments(snap, u)?;
    let entry = |xml: &[u8]| -> Result<UpdateData, ApiError> {
        Ok(UpdateData {
            id: u.record.local.id,
            xml: Presence::Value(xml_of(xml)?),
        })
    };
    let mut out = Vec::new();
    if types.contains(&XmlUpdateFragmentType::Core) {
        out.push(entry(&f.core)?);
    }
    if types.contains(&XmlUpdateFragmentType::Extended)
        && let Some(x) = &f.extended
    {
        out.push(entry(x)?);
    }
    if types.contains(&XmlUpdateFragmentType::LocalizedProperties) {
        for l in select_language(&f.localized, locales, f.default_language.as_deref()) {
            out.push(entry(&l.xml)?);
        }
    }
    if types.contains(&XmlUpdateFragmentType::Eula) {
        for l in select_language(&f.eula, locales, f.default_language.as_deref()) {
            out.push(entry(&l.xml)?);
        }
    }
    Ok(out)
}

fn wants_files(types: &[XmlUpdateFragmentType]) -> bool {
    types.iter().any(|t| {
        matches!(
            t,
            XmlUpdateFragmentType::Extended | XmlUpdateFragmentType::FileUrl
        )
    })
}

fn locations_for(
    cx: &Ctx<'_>,
    snap: &Snapshot,
    u: &ScopedUpdate,
    v2: bool,
    seen: &mut BTreeSet<Vec<u8>>,
) -> Result<Vec<FileLocation>, ApiError> {
    let mut out = Vec::new();
    for f in snap.files(u.record.local)? {
        if let Some(d) = sha1_of(&f)
            && !seen.insert(d.to_vec())
        {
            continue;
        }
        out.extend(location(cx, &f, v2)?);
    }
    Ok(out)
}

pub(crate) fn extended_info(
    cx: &Ctx<'_>,
    req: GetExtendedUpdateInfo,
) -> Result<GetExtendedUpdateInfoResponse, ApiError> {
    let claims = session(cx, &req.cookie)?;
    let ids: Vec<i32> = req.revision_ids.value().cloned().unwrap_or_default();
    let types = check_types(cx, &req.info_types, &req.locales, ids.len())?;
    let locales: Vec<String> = req.locales.value().cloned().unwrap_or_default();
    registered(cx, claims.computer)?;
    let (mut updates, mut files, mut out_of_scope) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen = BTreeSet::new();
    let snap = snapshot(cx, claims.catalog_generation)?;
    let scope = match &snap {
        Some(s) => scope_of(cx, s, claims.computer)?,
        None => Scope::default(),
    };
    for id in ids {
        match (&snap, scope.by_local(id)) {
            (Some(snap), Some(u)) => {
                updates.extend(fragments(snap, u, &types, &locales)?);
                if wants_files(&types) {
                    files.extend(locations_for(cx, snap, u, false, &mut seen)?);
                }
            }
            _ => out_of_scope.push(id),
        }
    }
    Ok(GetExtendedUpdateInfoResponse {
        result: Presence::Value(ExtendedUpdateInfo {
            updates: opt(updates),
            file_locations: opt(files),
            out_of_scope_revision_ids: opt(out_of_scope),
        }),
    })
}

pub(crate) fn extended_info2(
    cx: &Ctx<'_>,
    req: GetExtendedUpdateInfo2,
) -> Result<GetExtendedUpdateInfo2Response, ApiError> {
    let claims = session(cx, &req.cookie)?;
    let ids: Vec<UpdateRevision> = req.update_ids.value().cloned().unwrap_or_default();
    let types = check_types(cx, &req.info_types, &req.locales, ids.len())?;
    let locales: Vec<String> = req.locales.value().cloned().unwrap_or_default();
    registered(cx, claims.computer)?;
    let (mut updates, mut files, mut details) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen = BTreeSet::new();
    if let Some(snap) = snapshot(cx, claims.catalog_generation)? {
        let scope = scope_of(cx, &snap, claims.computer)?;
        for id in ids {
            let Some(u) = scope.updates.iter().find(|u| u.record.identity == id) else {
                continue;
            };
            updates.extend(fragments(&snap, u, &types, &locales)?);
            if wants_files(&types) {
                files.extend(locations_for(cx, &snap, u, true, &mut seen)?);
            }
            details.push(UpdateEncryptionDetail {
                update_identity: id,
                has_encrypted_files: false,
            });
        }
    }
    Ok(GetExtendedUpdateInfo2Response {
        result: Presence::Value(ExtendedUpdateInfo2 {
            updates: opt(updates),
            file_locations: opt(files),
            file_decryption_data: Presence::Absent,
            file_decryption_data2: Presence::Absent,
            update_encryption_details: opt(details),
        }),
    })
}

fn opt<T>(v: Vec<T>) -> Presence<Vec<T>> {
    if v.is_empty() {
        Presence::Absent
    } else {
        Presence::Value(v)
    }
}
