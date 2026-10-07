//! MS-WSUSSS operations.
use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rusqlite::params;
use uuid::Uuid;
use wsus_protocol::identity::{ComputerId, DigestAlgorithm, UpdateRevision};
use wsus_protocol::soap::{ErrorCode, Presence, XsDateTime};
use wsus_protocol::wsusss::*;

use super::anchors::{Resolved, stamp, well_formed_stamp};
use super::summary::{Cache, Summary, delta, looks_like_update_document};
use super::{
    AUTH_PLUGIN_ID, AUTH_SERVICE_URL, AccountState, Ctx, DownstreamAccess, Inner,
    MAX_DOWNLOAD_FILES_DIGESTS, UpstreamServerConfig, UssError, source_id,
};
use crate::catalog::{FragmentRecord, FragmentState, GenerationId, GenerationState, SourceId};
use crate::endpoints::content::find_by_sha1;
use crate::endpoints::time::format_xs;
use crate::session::{CookieClaims, CookieKind};
use crate::storage::{self, hex_encode};

type R<T> = Result<T, UssError>;

const MAX_NAME: usize = 256;
/// Superseded generations searched for a revision a downstream server was told about
/// earlier (catalog refresh in the middle of its synchronization).
const SUPERSEDED_LOOKBACK: i64 = 8;

fn bad(reason: &'static str) -> UssError {
    UssError::code(ErrorCode::InvalidParameters, reason)
}

fn xs(unix: i64) -> XsDateTime {
    XsDateTime::new(&format_xs(unix)).expect("format_xs yields a valid xs:dateTime")
}

fn text(p: &Presence<String>) -> Option<&str> {
    p.value()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Active generation of the served source.
pub(crate) fn active(inner: &Inner) -> Result<Option<(SourceId, GenerationId)>, storage::Error> {
    let Some(source) = source_id(inner)? else {
        return Ok(None);
    };
    Ok(inner
        .svc
        .catalog
        .active_generation(source)?
        .map(|g| (source, g)))
}

/// Advertised `MaxNumberOfUpdatesPerRequest`: the configured count limit, reduced so that
/// `count * largest blob` fits the response limit.
pub(crate) fn batch_limit(config: &UpstreamServerConfig, max_blob: u64) -> usize {
    let by_size = (config.max_update_response_bytes as u64)
        .checked_div(max_blob)
        .map_or(usize::MAX, |n| n.max(1) as usize);
    config
        .max_updates_per_request
        .max(1)
        .min(by_size)
        .min(i32::MAX as usize)
}

fn summary_of(
    inner: &Inner,
    generation: GenerationId,
) -> Result<std::sync::Arc<Summary>, UssError> {
    Ok(Cache::get_or_load(
        &inner.summaries,
        inner.svc.catalog.database(),
        generation,
    )?)
}

/// Validate a downstream session cookie. Every cookie problem is `InvalidCookie`, the
/// specified reaction being "restart from authorization": expiry, a changed configuration
/// generation and a different server identity all mean the same to the downstream server.
fn session(cx: &Ctx<'_>, cookie: &Presence<Cookie>) -> R<CookieClaims> {
    cx.inner
        .svc
        .sessions
        .validate(cookie.value(), CookieKind::DownstreamSession)
        .map_err(|_| UssError::code(ErrorCode::InvalidCookie, "invalid or expired cookie"))
}

// ---- GetAuthConfig ---------------------------------------------------------------

pub(crate) fn get_auth_config(cx: &Ctx<'_>, _: GetAuthConfig) -> R<GetAuthConfigResponse> {
    let last = cx
        .inner
        .config_state
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .last_change;
    Ok(GetAuthConfigResponse {
        result: Presence::Value(ServerAuthConfig {
            last_change: xs(last),
            auth_info: Presence::Value(vec![AuthPlugInInfo {
                plug_in_id: Presence::Value(AUTH_PLUGIN_ID.into()),
                service_url: Presence::Value(AUTH_SERVICE_URL.into()),
                parameter: Presence::Absent,
            }]),
            allowed_event_ids: Presence::Absent,
        }),
    })
}

// ---- GetAuthorizationCookie ------------------------------------------------------

fn valid_account_name(name: &str) -> bool {
    // The specification asks for an FQDN-valid name; Windows accounts also look like
    // `DOMAIN\HOST$`, so the backslash, `$` and `@` are accepted too.
    name.len() <= MAX_NAME
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'\\' | b'$' | b'@')
        })
}

pub(crate) fn authorization_cookie(
    cx: &Ctx<'_>,
    req: GetAuthorizationCookie,
) -> R<GetAuthorizationCookieResponse> {
    let name = text(&req.account_name)
        .filter(|n| valid_account_name(n))
        .ok_or(bad("accountName is missing or not a valid account name"))?;
    let guid = text(&req.account_guid)
        .and_then(|g| Uuid::parse_str(g).ok())
        .ok_or(bad("accountGuid is missing or not a GUID"))?;
    match cx.inner.config.access {
        DownstreamAccess::Open => {
            cx.inner.downstreams.enroll(guid, name)?;
        }
        DownstreamAccess::Allowlist => {
            cx.inner.downstreams.touch(guid)?;
        }
    }
    let mut claims = CookieClaims::new(CookieKind::DownstreamAuthorization, ComputerId(guid));
    claims.dns_name = Some(name.to_owned());
    let cookie = cx.inner.svc.sessions.issue(&claims);
    Ok(GetAuthorizationCookieResponse {
        result: Presence::Value(AuthorizationCookie {
            plug_in_id: Presence::Value(AUTH_PLUGIN_ID.into()),
            cookie_data: Presence::Value(cookie.encrypted_data.into_value().unwrap_or_default()),
        }),
    })
}

// ---- GetCookie -------------------------------------------------------------------

fn check_protocol_version(v: Option<&str>) -> R<()> {
    let v = v.ok_or(bad("protocolVersion is required"))?;
    let (major, minor) = v
        .split_once('.')
        .filter(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit())
        })
        .ok_or(bad("protocolVersion must be major.minor"))?;
    let _ = minor;
    if major.parse::<u32>().ok() != Some(1) {
        return Err(UssError::code(
            ErrorCode::IncompatibleProtocolVersion,
            "only protocol major version 1 is supported",
        ));
    }
    Ok(())
}

pub(crate) fn get_cookie(cx: &Ctx<'_>, req: GetCookie) -> R<GetCookieResponse> {
    let auths = req
        .auth_cookies
        .value()
        .filter(|a| a.len() == 1)
        .ok_or(bad("exactly one authorization cookie is required"))?;
    check_protocol_version(text(&req.protocol_version))?;
    let auth = &auths[0];
    let refused = |reason| UssError::code(ErrorCode::InvalidAuthorizationCookie, reason);
    if auth.plug_in_id.value().map(String::as_str) != Some(AUTH_PLUGIN_ID) {
        return Err(refused("unknown authorization plug-in"));
    }
    let sessions = &cx.inner.svc.sessions;
    let claims = sessions
        .validate_bytes(
            auth.cookie_data.value().map(Vec::as_slice),
            CookieKind::DownstreamAuthorization,
        )
        .map_err(|_| refused("invalid or expired authorization cookie"))?;
    let guid = claims.computer.0;
    match cx.inner.downstreams.get(guid)? {
        Some(a) if a.state == AccountState::Enabled => {}
        _ => return Err(refused("downstream account is not enabled")),
    }
    cx.inner.downstreams.touch(guid)?;
    let mut session = CookieClaims::new(CookieKind::DownstreamSession, claims.computer);
    session.dns_name = claims.dns_name;
    // The previous cookie (`oldCookie`) carries nothing this server needs; it is ignored,
    // which the specification permits.
    Ok(GetCookieResponse {
        result: Presence::Value(sessions.issue_until(&session, claims.expires_at)),
    })
}

// ---- GetConfigData ---------------------------------------------------------------

fn config_anchor(generation: i64, last_change: i64) -> String {
    format!("{generation},{}", stamp(last_change.saturating_mul(1000)))
}

pub(crate) fn get_config_data(cx: &Ctx<'_>, req: GetConfigData) -> R<GetConfigDataResponse> {
    session(cx, &req.cookie)?;
    let inner = cx.inner;
    let state = *inner.config_state.read().unwrap_or_else(|e| e.into_inner());
    if let Some(a) = text(&req.config_anchor) {
        let (g, rest) = a.split_once(',').ok_or(bad("configAnchor is malformed"))?;
        let g = g
            .parse::<i64>()
            .ok()
            .filter(|g| *g >= 1 && g.to_string() == a.split_once(',').map_or("", |x| x.0))
            .ok_or(bad("configAnchor is malformed"))?;
        if !well_formed_stamp(rest) {
            return Err(bad("configAnchor is malformed"));
        }
        if g > state.generation {
            return Err(UssError::code(
                ErrorCode::ServerChanged,
                "configAnchor was not issued by this server",
            ));
        }
    }
    let max_blob = match active(inner)? {
        Some((_, g)) => summary_of(inner, g)?.max_blob,
        None => 0,
    };
    let c = &inner.config;
    Ok(GetConfigDataResponse {
        result: Presence::Value(ServerSyncConfigData {
            catalog_only_sync: c.catalog_only_sync,
            lazy_sync: false,
            server_hosts_psf_files: false,
            // Driver operations are not implemented; the limits are advertised as 1.
            max_number_of_computer_ids_in_request: 1,
            max_number_of_driver_sets_per_request: 1,
            max_number_of_pnp_hardware_ids_in_request: 1,
            max_number_of_updates_per_request: batch_limit(c, max_blob) as i32,
            new_config_anchor: Presence::Value(config_anchor(state.generation, state.last_change)),
            protocol_version: Presence::Value(c.protocol_version.clone()),
            language_update_list: Presence::Value(vec![ServerSyncLanguageData {
                language_id: 0,
                short_language: Presence::Value("all".into()),
                long_language: Presence::Value("All Languages".into()),
                enabled: true,
            }]),
            max_updates_per_request_in_get_update_decryption_data: 1,
        }),
    })
}

// ---- GetRevisionIdList -----------------------------------------------------------

fn server_changed(reason: &'static str) -> UssError {
    UssError::code(ErrorCode::ServerChanged, reason)
}

pub(crate) fn get_revision_id_list(
    cx: &Ctx<'_>,
    req: GetRevisionIdList,
) -> R<GetRevisionIdListResponse> {
    session(cx, &req.cookie)?;
    let inner = cx.inner;
    let filter = req.filter.value().ok_or(bad("filter is required"))?;
    // Category, classification and language filters (and `Delta`) have no processing rules
    // in the pinned specification text (inventory section 8 item 10) and are ignored: every
    // revision of the requested class is enumerated and the downstream server filters.
    let Some((source, generation)) = active(inner)? else {
        return Ok(GetRevisionIdListResponse {
            result: Presence::Value(RevisionIdList {
                anchor: Presence::Absent,
                new_revisions: Presence::Value(Vec::new()),
            }),
        });
    };
    let current = inner
        .anchors
        .for_generation(source, generation, inner.svc.sessions.now())?;
    let new = summary_of(inner, generation)?;
    let old = match text(&filter.anchor) {
        None => None,
        Some(a) => match inner.anchors.resolve(a)? {
            Resolved::Malformed => return Err(bad("anchor is malformed")),
            Resolved::Unknown => {
                return Err(server_changed("anchor was not issued by this server"));
            }
            Resolved::Found(a) if a.source != source || a.generation > generation => {
                return Err(server_changed("anchor belongs to another catalog"));
            }
            Resolved::Found(a) if a.generation == generation => None.or(Some(new.clone())),
            Resolved::Found(a) => {
                match inner.svc.catalog.generation(a.generation) {
                    Ok(info)
                        if matches!(
                            info.state,
                            GenerationState::Active | GenerationState::Superseded
                        ) => {}
                    Ok(_) | Err(storage::Error::NotFound(_)) => {
                        return Err(server_changed("anchor generation is no longer available"));
                    }
                    Err(e) => return Err(e.into()),
                }
                Some(summary_of(inner, a.generation)?)
            }
        },
    };
    Ok(GetRevisionIdListResponse {
        result: Presence::Value(RevisionIdList {
            anchor: Presence::Value(current.text()),
            new_revisions: Presence::Value(delta(old.as_deref(), &new, filter.get_config)),
        }),
    })
}

// ---- GetUpdateData ---------------------------------------------------------------

/// Active generation followed by the most recent superseded ones, newest first.
fn generations(
    inner: &Inner,
    source: SourceId,
    active: GenerationId,
) -> Result<Vec<GenerationId>, storage::Error> {
    let mut out = vec![active];
    let older: Vec<GenerationId> = inner.svc.catalog.database().with_conn(|c| {
        let mut st = c.prepare(
            "SELECT id FROM generations WHERE source_id=?1 AND state='superseded' AND id<?2 \
             ORDER BY id DESC LIMIT ?3",
        )?;
        let rows = st.query_map(params![source.0, active.0, SUPERSEDED_LOOKBACK], |r| {
            r.get::<_, i64>(0).map(GenerationId)
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })?;
    out.extend(older);
    Ok(out)
}

/// Record and the generation it was found in. Withdrawn revisions are served; a tombstone
/// in a newer generation hides the revision from older ones.
fn find_record(
    inner: &Inner,
    gens: &[GenerationId],
    id: UpdateRevision,
) -> Result<Option<(FragmentRecord, GenerationId)>, storage::Error> {
    for g in gens {
        let snap = inner.svc.catalog.snapshot_of(*g)?;
        if let Some(rec) = snap.get(id)? {
            let head = &rec.core_xml[..rec.core_xml.len().min(512)];
            let servable = rec.state != FragmentState::Deleted && looks_like_update_document(head);
            return Ok(servable.then_some((rec, *g)));
        }
    }
    Ok(None)
}

fn content_base(cx: &Ctx<'_>) -> Result<String, UssError> {
    let c = &cx.inner.config;
    if let Some(b) = &c.content_base_url {
        return Ok(b.trim_end_matches('/').to_owned());
    }
    let host = cx
        .host
        .as_deref()
        .ok_or(UssError::Api(super::ApiError::Internal))?;
    Ok(match c.content_port {
        Some(80) | None => format!("http://{host}"),
        Some(p) => format!("http://{host}:{p}"),
    })
}

/// `Content/<folder>/<file>`: last two lower-case hex digits of the SHA-1 as the folder and
/// the 40 lower-case hex digits as the file name. Unverified (inventory section 8 item 1).
fn uss_url(base: &str, sha1: &[u8]) -> String {
    let hex = hex_encode(sha1);
    format!("{base}/Content/{}/{hex}", &hex[hex.len() - 2..])
}

fn sha1_of(f: &crate::catalog::FileDescriptor) -> Option<&[u8]> {
    f.digests
        .iter()
        .find(|d| d.algorithm == DigestAlgorithm::Sha1)
        .map(|d| d.bytes.as_slice())
}

pub(crate) fn get_update_data(cx: &Ctx<'_>, req: GetUpdateData) -> R<GetUpdateDataResponse> {
    session(cx, &req.cookie)?;
    let inner = cx.inner;
    let ids = req.update_ids.value().cloned().unwrap_or_default();
    if ids.is_empty() {
        return Err(bad("updateIds is required"));
    }
    let Some((source, generation)) = active(inner)? else {
        return Err(bad("unknown update revision"));
    };
    let limit = batch_limit(&inner.config, summary_of(inner, generation)?.max_blob);
    if ids.len() > limit {
        return Err(bad("more updateIds than MaxNumberOfUpdatesPerRequest"));
    }
    let gens = generations(inner, source, generation)?;
    let base = content_base(cx)?;
    let mut seen = BTreeSet::new();
    let mut updates = Vec::new();
    let mut urls = Vec::new();
    let mut digests_seen = BTreeSet::new();
    let mut total = 0usize;
    for id in ids {
        if !seen.insert(id) {
            continue;
        }
        let (rec, g) = find_record(inner, &gens, id)?.ok_or(bad("unknown update revision"))?;
        let blob = String::from_utf8(rec.core_xml.clone())
            .map_err(|_| UssError::Api(super::ApiError::Internal))?;
        total += blob.len();
        let files = inner.svc.catalog.snapshot_of(g)?.files(rec.local)?;
        let sha1s: Vec<Vec<u8>> = files
            .iter()
            .filter_map(|f| sha1_of(f))
            .map(<[u8]>::to_vec)
            .collect();
        for d in &sha1s {
            if digests_seen.insert(d.clone()) {
                urls.push(ServerSyncUrlData {
                    file_digest: Presence::Value(d.clone()),
                    mu_url: Presence::Absent,
                    uss_url: Presence::Value(uss_url(&base, d)),
                    decryption_key: Presence::Absent,
                });
            }
        }
        updates.push(ServerSyncUpdateData {
            id: Presence::Value(rec.identity),
            xml_update_blob: Presence::Value(blob),
            file_digest_list: if sha1s.is_empty() {
                Presence::Absent
            } else {
                Presence::Value(sha1s)
            },
            xml_update_blob_compressed: Presence::Absent,
        });
    }
    // A single update larger than the limit cannot be split and is served alone; any other
    // over-limit batch (the catalog changed after `GetConfigData`) is refused.
    if total > inner.config.max_update_response_bytes && updates.len() > 1 {
        return Err(bad("the requested updates exceed the response size limit"));
    }
    Ok(GetUpdateDataResponse {
        result: Presence::Value(ServerUpdateData {
            updates: Presence::Value(updates),
            file_urls: Presence::Value(urls),
        }),
    })
}

// ---- DownloadFiles ---------------------------------------------------------------

pub(crate) fn download_files(cx: &Ctx<'_>, req: DownloadFiles) -> R<DownloadFilesResponse> {
    session(cx, &req.cookie)?;
    let inner = cx.inner;
    let digests = req.file_digest_list.value().cloned().unwrap_or_default();
    if digests.len() > MAX_DOWNLOAD_FILES_DIGESTS {
        return Err(bad("more than 100 file digests"));
    }
    if digests.iter().any(|d| d.len() != 20) {
        return Err(bad("file digests must be SHA-1 values"));
    }
    if digests.is_empty() {
        return Ok(DownloadFilesResponse {});
    }
    let known: BTreeSet<Vec<u8>> = match active(inner)? {
        Some((source, generation)) => {
            let gens = generations(inner, source, generation)?;
            known_digests(inner, &gens, &digests)?
        }
        None => BTreeSet::new(),
    };
    let missing: Vec<String> = digests
        .iter()
        .filter(|d| !known.contains(*d))
        .map(|d| STANDARD.encode(d))
        .collect();
    if !missing.is_empty() {
        return Err(UssError::Message(
            ErrorCode::FileDigestsMissing,
            "unknown file digests",
            missing.join("|"),
        ));
    }
    // Known digests whose content is not here are queued for content acquisition. The
    // specification has the USS fetch them from its own parent and silently ignore
    // failures; fetching is the caller's job (see `drain_download_requests`).
    let db = inner.svc.catalog.database();
    let mut queue = inner
        .requested_downloads
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for d in &digests {
        let arr: [u8; 20] = d.as_slice().try_into().expect("length checked");
        if find_by_sha1(db, &arr)?.is_none() {
            queue.insert(d.clone());
        }
    }
    Ok(DownloadFilesResponse {})
}

fn known_digests(
    inner: &Inner,
    gens: &[GenerationId],
    digests: &[Vec<u8>],
) -> Result<BTreeSet<Vec<u8>>, storage::Error> {
    inner.svc.catalog.database().with_conn(|c| {
        let mut st = c.prepare(
            "SELECT 1 FROM file_digests WHERE algorithm='sha1' AND digest=?1 \
             AND generation_id=?2 LIMIT 1",
        )?;
        let mut out = BTreeSet::new();
        for d in digests {
            for g in gens {
                if st.exists(params![d, g.0])? {
                    out.insert(d.clone());
                    break;
                }
            }
        }
        Ok(out)
    })
}
