//! Bounded, deterministic harnesses for `wsus-protocol`.
//!
//! Every input is `[flags, payload...]`. Bit 0 of `flags` toggles
//! `Limits::strict_sequence_order`; bits 1.. select a message type or SOAP
//! version where a target has several. The remaining bytes are the document.
//! This module is included by path from each binary, the replay tool and the
//! smoke test, so it must not depend on the rest of this crate.
use wsus_protocol::soap::{
    self, Body, Envelope, Limits, SoapFault, SoapMessage, SoapRequest, SoapVersion, xml,
};
use wsus_protocol::{
    applicability::{
        ApplicabilityRules, Expr, FakeFacts, NoFacts, RecordedFacts, SectionKind, evaluate,
        required_queries,
    },
    metadata::index::FragmentIndex,
    metadata::index::UpdateIndex,
    wsusss, wusp,
};

/// Inputs above this size are skipped, well above any seed fixture.
pub const INPUT_LIMIT: usize = 64 * 1024;

/// Small limits keep every iteration fast; all are enforced by the crate.
pub fn limits(flags: u8) -> Limits {
    Limits {
        max_body_bytes: INPUT_LIMIT,
        max_depth: 16,
        max_array_len: 64,
        max_elements: 2048,
        strict_sequence_order: flags & 1 == 0,
    }
}

fn split(data: &[u8]) -> Option<(u8, &[u8])> {
    let (&flags, rest) = data.split_first()?;
    (rest.len() <= INPUT_LIMIT).then_some((flags, rest))
}

fn version(selector: u8) -> SoapVersion {
    if selector & 1 == 0 {
        SoapVersion::V11
    } else {
        SoapVersion::V12
    }
}

/// SOAP envelope decode for both versions, plus the header/action helpers.
pub fn envelope(data: &[u8]) {
    let Some((flags, body)) = split(data) else {
        return;
    };
    let limits = limits(flags);
    if let Ok(env) = Envelope::decode(body, &limits) {
        let _ = env.payload_name();
        let _ = env.must_understand_headers();
        if let (Some(name), true) = (env.payload_name(), flags & 2 != 0) {
            let _ = soap::validate_action(std::str::from_utf8(body).ok(), name);
        }
    }
    if let Ok(text) = std::str::from_utf8(body) {
        let _ = soap::action_from_content_type(text);
    }
}

/// Fault parsing from an arbitrary element, both versions, and whole envelopes.
pub fn fault(data: &[u8]) {
    let Some((flags, body)) = split(data) else {
        return;
    };
    let limits = limits(flags);
    if let Ok(el) = xml::parse(body, &limits) {
        for v in [SoapVersion::V11, SoapVersion::V12] {
            let fault = SoapFault::from_element(&el, v);
            let _ = fault.to_element().to_bytes();
            let _ = fault.code_local();
            let _ = fault.to_string();
            if let Some(w) = &fault.wsus {
                let _ = w.error_code.wusp_recovery();
            }
            let _ = soap::encode_fault(&fault);
        }
    }
    if let Ok(Envelope {
        body: Body::Fault(f),
        ..
    }) = Envelope::decode(body, &limits)
    {
        let _ = soap::encode_fault(&f);
    }
}

/// `xml::parse` and `xml::parse_fragments`.
pub fn xml_parse(data: &[u8]) {
    let Some((flags, body)) = split(data) else {
        return;
    };
    let limits = limits(flags);
    if let Ok(el) = xml::parse(body, &limits) {
        let _ = el.to_bytes();
        let _ = el.text();
        let _ = el.is_nil();
    }
    if let Ok(els) = xml::parse_fragments(body, &limits) {
        for el in &els {
            let _ = el.to_bytes();
        }
    }
}

macro_rules! message_target {
    ($name:ident, $module:ident, [$($req:ident),+ $(,)?]) => {
        pub fn $name(data: &[u8]) {
            let Some((flags, body)) = split(data) else { return };
            let limits = limits(flags);
            let sel = flags >> 1;
            let v_count = [$(stringify!($req)),+].len() as u8;
            let pick = sel % v_count;
            let mut i = 0u8;
            $(
                if pick == i {
                    let action = <$module::$req as SoapRequest>::action();
                    let _ = soap::decode_request::<$module::$req>(Some(&action), body, &limits);
                    let _ = soap::decode_request::<$module::$req>(None, body, &limits);
                    let _ = soap::decode_response::<<$module::$req as SoapRequest>::Response>(
                        body, &limits,
                    );
                }
                i += 1;
            )+
            let _ = i;
        }
    };
}

message_target!(
    wusp_messages,
    wusp,
    [
        GetConfig,
        GetAuthorizationCookie,
        GetCookie,
        RegisterComputer,
        SyncUpdates,
        RefreshCache,
        GetExtendedUpdateInfo,
        GetExtendedUpdateInfo2,
        GetFileLocations,
        ReportEventBatch,
    ]
);

message_target!(
    wsusss_messages,
    wsusss,
    [
        GetAuthConfig,
        GetAuthorizationCookie,
        GetCookie,
        GetConfigData,
        GetRevisionIdList,
        GetUpdateData,
        GetUpdateDecryptionData,
        DownloadFiles,
        GetDeployments,
        GetRelatedRevisionsForUpdates,
    ]
);

/// `UpdateIndex::parse` and `FragmentIndex::parse`.
pub fn metadata(data: &[u8]) {
    let Some((flags, body)) = split(data) else {
        return;
    };
    let limits = limits(flags);
    let _ = UpdateIndex::parse(body, &limits);
    if let Ok(fragments) = FragmentIndex::parse(body, &limits) {
        let _ = fragments.clone().into_update_index();
        let _ = fragments.clone().merge(fragments);
    }
}

/// Applicability rules: parse whatever the lenient fragment parser (bit 1 set)
/// or the strict one accepts as an `ApplicabilityRules` section or a bare
/// expression, evaluate it against no facts, a fake machine and (bit 2) a
/// recorded snapshot built from the same bytes, and list its queries. The
/// invariant is "never panic, and an Unknown carries a blocker".
pub fn applicability(data: &[u8]) {
    use wsus_protocol::applicability::Tri;
    let Some((flags, body)) = split(data) else {
        return;
    };
    let limits = limits(flags);
    let mut world = FakeFacts::windows11_x64();
    world.set_dword("SOFTWARE\\Acme", "Level", 5);
    let snapshot = (flags & 4 != 0)
        .then(|| std::str::from_utf8(body).ok())
        .flatten()
        .and_then(|t| RecordedFacts::from_json(t).ok());
    let check = |expr: &Expr| {
        let _ = required_queries(expr);
        let _ = expr.unsupported();
        let mut providers: Vec<&dyn wsus_protocol::applicability::FactProvider> =
            vec![&NoFacts, &world];
        if let Some(s) = &snapshot {
            providers.push(s);
        }
        for p in providers {
            let o = evaluate(expr, p);
            assert!(
                o.value != Tri::Unknown || !o.blockers.is_empty(),
                "Unknown without a blocker"
            );
            assert!(
                o.value == Tri::Unknown || o.blockers.is_empty(),
                "definite answer with blockers"
            );
        }
    };
    let elements = if flags & 2 == 0 {
        xml::parse_fragments(body, &limits).ok()
    } else {
        xml::parse(body, &limits).ok().map(|e| vec![e])
    };
    for el in elements.iter().flatten() {
        let rules = ApplicabilityRules::from_element(el);
        for kind in [
            SectionKind::IsInstalled,
            SectionKind::IsInstallable,
            SectionKind::IsSuperseded,
        ] {
            if let Some(s) = rules.section(kind) {
                check(&s.expr);
            }
            let _ = rules.evaluate(kind, &world);
        }
        check(&Expr::parse(el));
    }
    if let Ok(idx) = FragmentIndex::parse(body, &limits)
        && let Some(rules) = ApplicabilityRules::from_fragment(&idx)
    {
        let _ = rules.is_fully_supported();
        let _ = rules.evaluate(SectionKind::IsInstalled, &world);
    }
}

fn roundtrip_message<M>(body: &[u8], limits: &Limits, v: SoapVersion)
where
    M: SoapMessage + PartialEq + std::fmt::Debug,
{
    if let Ok(m) = soap::decode_response::<M>(body, limits) {
        let enc = soap::encode_response(v, &m);
        let again = soap::decode_response::<M>(&enc.body, limits)
            .unwrap_or_else(|e| panic!("re-decode of encoded {} failed: {e}", M::NAME));
        assert_eq!(m, again, "{} changed across encode/decode", M::NAME);
    }
}

fn roundtrip_request<R>(body: &[u8], limits: &Limits, v: SoapVersion)
where
    R: SoapRequest + PartialEq + std::fmt::Debug,
{
    if let Ok((_, m)) = soap::decode_request::<R>(None, body, limits) {
        let enc = soap::encode_request(v, &m);
        let (_, again) = soap::decode_request::<R>(Some(&R::action()), &enc.body, limits)
            .unwrap_or_else(|e| panic!("re-decode of encoded {} failed: {e}", R::NAME));
        assert_eq!(m, again, "{} changed across encode/decode", R::NAME);
    }
}

macro_rules! roundtrip_messages {
    ($pick:expr, $body:expr, $limits:expr, $v:expr, $module:ident, [$($req:ident),+ $(,)?]) => {{
        let count = [$(stringify!($req)),+].len() as u8;
        let mut i = 0u8;
        $(
            if $pick % count == i {
                roundtrip_request::<$module::$req>($body, $limits, $v);
                roundtrip_message::<<$module::$req as SoapRequest>::Response>($body, $limits, $v);
            }
            i += 1;
        )+
        let _ = i;
    }};
}

/// `encode(decode(x))` must re-decode equal wherever `decode(x)` succeeds.
///
/// Flags bits 1..2 pick the area (XML tree, envelope, WUSP, WSUSSS), bit 3 the
/// SOAP version used to encode, bits 4.. the message type.
pub fn roundtrip(data: &[u8]) {
    let Some((flags, body)) = split(data) else {
        return;
    };
    let limits = limits(flags);
    let v = version(flags >> 3);
    let pick = flags >> 4;
    match (flags >> 1) & 3 {
        0 => {
            if let Ok(el) = xml::parse(body, &limits) {
                let again = xml::parse(&el.to_bytes(), &limits)
                    .unwrap_or_else(|e| panic!("re-parse of serialized XML failed: {e}"));
                assert_eq!(el, again, "XML tree changed across serialize/parse");
            }
        }
        1 => {
            if let Ok(env) = Envelope::decode(body, &limits) {
                let again = Envelope::decode(&env.encode(), &limits)
                    .unwrap_or_else(|e| panic!("re-decode of encoded envelope failed: {e}"));
                match (&env.body, &again.body) {
                    (Body::Fault(f), Body::Fault(g)) => {
                        // KNOWN normalisation: SoapFault::to_element prefixes an
                        // unqualified code with `soap:` and rebuilds `detail`
                        // from the parsed WSUS fields when present, dropping any
                        // other detail content. Every parsed field must survive,
                        // and a second round must be a fixed point.
                        assert_eq!(env.version, again.version);
                        assert_eq!(env.headers, again.headers);
                        assert_eq!(f.version, g.version);
                        assert_eq!(f.subcodes, g.subcodes);
                        assert_eq!(f.reason, g.reason);
                        assert_eq!(f.actor, g.actor);
                        assert_eq!(f.wsus, g.wsus);
                        let third = Envelope::decode(&again.encode(), &limits)
                            .unwrap_or_else(|e| panic!("third decode failed: {e}"));
                        assert_eq!(again, third, "fault encoding is not a fixed point");
                    }
                    _ => assert_eq!(env, again, "envelope changed across encode/decode"),
                }
            }
        }
        2 => roundtrip_messages!(
            pick,
            body,
            &limits,
            v,
            wusp,
            [
                GetConfig,
                GetAuthorizationCookie,
                GetCookie,
                RegisterComputer,
                SyncUpdates,
                RefreshCache,
                GetExtendedUpdateInfo,
                GetExtendedUpdateInfo2,
                GetFileLocations,
                ReportEventBatch,
            ]
        ),
        _ => roundtrip_messages!(
            pick,
            body,
            &limits,
            v,
            wsusss,
            [
                GetAuthConfig,
                GetAuthorizationCookie,
                GetCookie,
                GetConfigData,
                GetRevisionIdList,
                GetUpdateData,
                GetUpdateDecryptionData,
                DownloadFiles,
                GetDeployments,
                GetRelatedRevisionsForUpdates,
            ]
        ),
    }
}

/// Xpress body framing: decode arbitrary bytes under tight limits (flag bit 0
/// picks a small block and total cap, bit 1 the default block size), and round
/// trip: whatever decodes must re-encode to something that decodes to the same
/// bytes, and the payload itself must round trip.
pub fn xpress(data: &[u8]) {
    use wsus_protocol::xpress::{self, Limits};
    let Some((flags, payload)) = split(data) else {
        return;
    };
    let limits = Limits {
        max_block_bytes: if flags & 1 == 0 { 65535 } else { 700 },
        max_total_bytes: if flags & 2 == 0 { 256 * 1024 } else { 2048 },
    };
    if let Ok(decoded) = xpress::decode(payload, &limits) {
        assert!(decoded.len() <= limits.max_total_bytes);
        let wire = xpress::encode(&decoded).expect("encode");
        let again = xpress::decode(&wire, &Limits::with_max_total(decoded.len().max(1)))
            .expect("decode of our own encoding");
        assert_eq!(again, decoded);
    }
    let wire = xpress::encode(payload).expect("encode");
    assert_eq!(
        xpress::decode(&wire, &Limits::with_max_total(payload.len().max(1))).expect("roundtrip"),
        payload
    );
}

/// Run a named harness, used by standalone reproduction and tests.
pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "wsus_envelope" => envelope(data),
        "wsus_fault" => fault(data),
        "wsus_xml" => xml_parse(data),
        "wsus_wusp" => wusp_messages(data),
        "wsus_wsusss" => wsusss_messages(data),
        "wsus_metadata" => metadata(data),
        "wsus_applicability" => applicability(data),
        "wsus_roundtrip" => roundtrip(data),
        "wsus_xpress" => xpress(data),
        _ => {
            return Err(
                "target must be wsus_envelope, wsus_fault, wsus_xml, wsus_wusp, wsus_wsusss, wsus_metadata, wsus_applicability, wsus_roundtrip or wsus_xpress",
            );
        }
    }
    Ok(())
}
