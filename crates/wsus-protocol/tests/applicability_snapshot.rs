//! Snapshot format of `scripts/wsus/collect-facts.ps1` and `RecordedFacts`.
use wsus_protocol::applicability::expr::RegValueType;
use wsus_protocol::applicability::facts::{FileInfo, FileLocation, MsiProduct, RegValue};
use wsus_protocol::applicability::recorded::{
    FactEntry, FactQuery, FactResult, SNAPSHOT_SCHEMA, Snapshot, SnapshotOs, reg_value_to_json,
};
use wsus_protocol::applicability::value::Version;
use wsus_protocol::applicability::{
    ApplicabilityRules, Expr, Fact, FactProvider, RecordedFacts, RegView, SectionKind, Tri,
    evaluate,
};
use wsus_protocol::soap::Limits;
use wsus_protocol::soap::xml::parse_fragments;

const SAMPLE: &str = include_str!("fixtures/applicability_facts_sample.json");

fn rules(xml: &str) -> ApplicabilityRules {
    let els = parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
    ApplicabilityRules::from_element(&els[0])
}

#[test]
fn collector_shaped_sample_loads_and_answers_every_kind() {
    let r = RecordedFacts::from_json(SAMPLE).expect("sample loads");
    assert_eq!(r.collected_at(), "2026-10-04T12:00:00Z");
    assert_eq!(r.len(), 26);
    // registry, case-insensitive on names
    assert_eq!(
        r.reg_key_exists(RegView::Native, "software\\MICROSOFT\\windows defender"),
        Fact::Known(())
    );
    assert_eq!(
        r.reg_key_exists(RegView::Wow32, "SOFTWARE\\Nope"),
        Fact::Absent
    );
    // the same key was only recorded for the native view
    assert!(matches!(
        r.reg_key_exists(RegView::Wow32, "SOFTWARE\\Microsoft\\Windows Defender"),
        Fact::Unavailable(_)
    ));
    assert_eq!(
        r.reg_value(
            RegView::Native,
            "SYSTEM\\CurrentControlSet\\Services\\WinDefend",
            "start"
        ),
        Fact::Known(RegValue::Dword(2))
    );
    assert_eq!(
        r.reg_value(RegView::Native, "SOFTWARE\\Big", "Q"),
        Fact::Known(RegValue::Qword(u64::MAX))
    );
    assert_eq!(
        r.reg_value(RegView::Native, "SOFTWARE\\Big", "Bin"),
        Fact::Known(RegValue::Binary(vec![0x0a, 0xff]))
    );
    assert_eq!(
        r.reg_value(RegView::Native, "SOFTWARE\\Big", "Multi"),
        Fact::Known(RegValue::MultiSz(vec!["a".into(), "b".into()]))
    );
    assert_eq!(
        r.reg_value(RegView::Native, "SOFTWARE\\Big", "Exp"),
        Fact::Known(RegValue::ExpandSz("%SystemRoot%\\x".into()))
    );
    assert_eq!(
        r.reg_value(RegView::Native, "SOFTWARE\\Big", "None"),
        Fact::Known(RegValue::Other("REG_NONE".into()))
    );
    assert_eq!(
        r.reg_value(RegView::Wow32, "SOFTWARE\\Gone", "X"),
        Fact::Absent
    );
    assert!(
        matches!(r.reg_value(RegView::Native, "SOFTWARE\\Denied", "x"), Fact::Unavailable(m) if m == "Access denied")
    );
    assert_eq!(
        r.reg_subkeys(RegView::Native, "SOFTWARE\\Microsoft\\Microsoft SQL Server"),
        Fact::Absent
    );
    assert_eq!(
        r.reg_subkeys(RegView::Native, "software\\two"),
        Fact::Known(vec!["A".into(), "B".into()])
    );
    // files
    let Fact::Known(i) = r.file(&FileLocation::Csidl { csidl: 37 }, "\\NTOSKRNL.exe") else {
        panic!()
    };
    assert_eq!(i.size, Some(12345));
    assert_eq!(i.version, Version::parse("10.0.26100.1"));
    assert_eq!(
        i.modified.unwrap().to_rfc3339(),
        "2026-01-02T03:04:05.1234567Z"
    );
    assert_eq!(
        r.file(&FileLocation::Csidl { csidl: 38 }, "gone\\x.exe"),
        Fact::Absent
    );
    let loc = FileLocation::RegSz {
        view: RegView::Native,
        subkey: "software\\microsoft\\windows defender".into(),
        value: "installlocation".into(),
    };
    assert!(matches!(
        r.file(&loc, "mpclient.dll"),
        Fact::Known(FileInfo { size: Some(5), .. })
    ));
    assert!(matches!(
        r.file(&FileLocation::Absolute, "C:\\x.txt"),
        Fact::Unavailable(_)
    ));
    // others
    assert_eq!(r.system_metric(87), Fact::Known(0));
    assert_eq!(r.license_dword("kernel-productinfo"), Fact::Known(101));
    assert_eq!(
        r.wmi_query("ROOT/CIMV2", "SELECT * FROM Win32_BIOS"),
        Fact::Known(true)
    );
    assert_eq!(
        r.msi_product("{e49ca583-2ec0-4510-862a-c2befd036330}"),
        Fact::Known(MsiProduct {
            version: "10.22.130".into(),
            language: Some(1033)
        })
    );
    assert_eq!(
        r.msi_product("{00000000-0000-0000-0000-000000000000}"),
        Fact::Absent
    );
    assert_eq!(
        r.msi_feature("{E49CA583-2EC0-4510-862A-C2BEFD036330}", "admin"),
        Fact::Known(true)
    );
    assert_eq!(
        r.msi_component(
            "{E49CA583-2EC0-4510-862A-C2BEFD036330}",
            "{38b098dd-cf55-49e3-9cba-8604e2b1d59a}"
        ),
        Fact::Known(false)
    );
    assert!(matches!(
        r.msi_patch(
            "{E49CA583-2EC0-4510-862A-C2BEFD036330}",
            "{E1D63391-7DA5-442C-BEAB-CEE5B046A22D}"
        ),
        Fact::Unavailable(_)
    ));
    assert_eq!(
        r.cbs_package("package_for_kb1~31BF3856AD364E35~amd64~~10.0.1.0"),
        Fact::Known(112)
    );
    // OS section
    let Fact::Known(os) = r.os() else { panic!() };
    assert_eq!(
        (os.major, os.build, os.product_type, os.suite_mask),
        (10, 26200, 1, 256)
    );
    assert_eq!(r.processor_architecture(), Fact::Known(9));
    assert_eq!(r.windows_language(), Fact::Known("en-US".into()));
    assert_eq!(r.mui_installed(), Fact::Known(false));
    // Not recorded means Unavailable, never Absent.
    assert!(
        matches!(r.reg_key_exists(RegView::Native, "SOFTWARE\\Never Asked"), Fact::Unavailable(m) if m.contains("not in snapshot"))
    );
}

#[test]
fn rules_evaluate_against_the_recorded_sample() {
    let r = RecordedFacts::from_json(SAMPLE).unwrap();
    let rules = rules(
        r#"<ApplicabilityRules><IsInstalled><And><b.WindowsVersion Comparison="GreaterThanOrEqualTo" MajorVersion="10" MinorVersion="0" BuildNumber="22000"/><b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SYSTEM\CurrentControlSet\Services\WinDefend" Value="Start" Comparison="EqualTo" Data="2"/><b.FileVersion Csidl="37" Path="ntoskrnl.exe" Comparison="GreaterThanOrEqualTo" Version="10.0.26100.0"/><b.FileVersionPrependRegSz Path="MpClient.dll" Comparison="GreaterThan" Version="4.18.0.0" Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Microsoft\Windows Defender" Value="InstallLocation"/></And></IsInstalled></ApplicabilityRules>"#,
    );
    assert_eq!(
        rules.evaluate(SectionKind::IsInstalled, &r).value,
        Tri::True
    );
    // A query that was never collected yields Unknown with the fact named.
    let rules2 = self::rules(
        r#"<ApplicabilityRules><IsInstalled><b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Unlisted"/></IsInstalled></ApplicabilityRules>"#,
    );
    let o = rules2.evaluate(SectionKind::IsInstalled, &r);
    assert_eq!(o.value, Tri::Unknown);
    assert!(o.blockers[0].to_string().contains("not in snapshot"));
}

fn every_kind() -> Snapshot {
    let mut s = Snapshot::new("2026-10-04T00:00:00Z");
    s.machine.insert("computer".into(), "X".into());
    s.os = Some(SnapshotOs {
        major: 10,
        minor: 0,
        build: 26200,
        product_type: 1,
        suite_mask: 256,
        architecture: Some(9),
        language: Some("en-US".into()),
        mui_installed: Some(false),
        ..SnapshotOs::default()
    });
    let q = |query: FactQuery, result: FactResult| FactEntry { query, result };
    let v = RegView::Native;
    s.facts = vec![
        q(
            FactQuery::RegKey {
                view: v,
                subkey: "A".into(),
            },
            FactResult::known_unit(),
        ),
        q(
            FactQuery::RegKey {
                view: RegView::Wow32,
                subkey: "B".into(),
            },
            FactResult::absent(),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "d".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::Dword(7))),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "q".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::Qword(1 << 40))),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "s".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::Sz("x".into()))),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "b".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::Binary(vec![1, 2, 255]))),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "m".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::MultiSz(vec!["p".into()]))),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "e".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::ExpandSz("%x%".into()))),
        ),
        q(
            FactQuery::RegValue {
                view: v,
                subkey: "A".into(),
                value: "o".into(),
            },
            FactResult::known(reg_value_to_json(&RegValue::Other("REG_NONE".into()))),
        ),
        q(
            FactQuery::RegSubkeys {
                view: v,
                subkey: "A".into(),
            },
            FactResult::known(serde_json::json!(["c1", "c2"])),
        ),
        q(
            FactQuery::File {
                location: FileLocation::Csidl { csidl: 37 },
                path: "a.dll".into(),
            },
            FactResult::known(
                serde_json::to_value(FileInfo {
                    size: Some(9),
                    version: Version::parse("1.2.3.4"),
                    modified: wsus_protocol::applicability::value::FileTime::parse(
                        "2020-02-29T23:59:59.9999999Z",
                    ),
                    created: None,
                    resolved_path: Some("C:\\Windows\\System32\\a.dll".into()),
                })
                .unwrap(),
            ),
        ),
        q(
            FactQuery::File {
                location: FileLocation::Absolute,
                path: "C:\\z".into(),
            },
            FactResult::unavailable("because"),
        ),
        q(
            FactQuery::File {
                location: FileLocation::RegSz {
                    view: v,
                    subkey: "A".into(),
                    value: "s".into(),
                },
                path: "q.exe".into(),
            },
            FactResult::absent(),
        ),
        q(
            FactQuery::SystemMetric { index: 86 },
            FactResult::known(serde_json::json!(1)),
        ),
        q(
            FactQuery::LicenseDword { name: "L".into() },
            FactResult::known(serde_json::json!(4294967295u32)),
        ),
        q(
            FactQuery::WmiQuery {
                namespace: "root\\cimv2".into(),
                query: "select 1".into(),
            },
            FactResult::known(serde_json::json!(false)),
        ),
        q(
            FactQuery::MsiProduct {
                product: "{E49CA583-2EC0-4510-862A-C2BEFD036330}".into(),
            },
            FactResult::known(serde_json::json!({"version": "1.2.3", "language": 1033})),
        ),
        q(
            FactQuery::MsiFeature {
                product: "{E49CA583-2EC0-4510-862A-C2BEFD036330}".into(),
                feature: "F".into(),
            },
            FactResult::known(serde_json::json!(true)),
        ),
        q(
            FactQuery::MsiComponent {
                product: "{E49CA583-2EC0-4510-862A-C2BEFD036330}".into(),
                component: "{C}".into(),
            },
            FactResult::known(serde_json::json!(false)),
        ),
        q(
            FactQuery::MsiPatch {
                product: "{E49CA583-2EC0-4510-862A-C2BEFD036330}".into(),
                patch: "{P}".into(),
            },
            FactResult::unavailable("n/a"),
        ),
        q(
            FactQuery::CbsPackage {
                identity: "Pkg~1".into(),
            },
            FactResult::known(serde_json::json!(112)),
        ),
    ];
    s
}

#[test]
fn snapshot_json_roundtrips_exactly() {
    let s = every_kind();
    let text = s.to_json();
    let back = Snapshot::from_json(&text).expect("parse what we wrote");
    assert_eq!(back, s);
    // A second round is byte identical.
    assert_eq!(back.to_json(), text);
    assert_eq!(s.schema, SNAPSHOT_SCHEMA);
    // It also loads as RecordedFacts and every entry is answerable.
    let r = RecordedFacts::from_snapshot(back).expect("index");
    assert_eq!(r.len(), 21);
    assert_eq!(
        r.reg_value(RegView::Native, "a", "Q"),
        Fact::Known(RegValue::Qword(1 << 40))
    );
    assert!(RegValue::Sz("x".into()).is_type(&RegValueType::Sz));
    assert_eq!(r.license_dword("l"), Fact::Known(u32::MAX));
}

#[test]
fn snapshot_loading_rejects_bad_input() {
    assert!(RecordedFacts::from_json("not json").is_err());
    assert!(
        RecordedFacts::from_json(r#"{"schema":"other/1","collected_at":"x","facts":[]}"#).is_err()
    );
    let bad_state = r#"{"schema":"wsus-applicability-facts/1","collected_at":"x","facts":[{"kind":"reg_key","view":"native","subkey":"a","result":{"state":"maybe"}}]}"#;
    assert!(RecordedFacts::from_json(bad_state).is_err());
    let bad_value = r#"{"schema":"wsus-applicability-facts/1","collected_at":"x","facts":[{"kind":"reg_value","view":"native","subkey":"a","value":"v","result":{"state":"known","value":{"type":"REG_DWORD","data":"x"}}}]}"#;
    assert!(RecordedFacts::from_json(bad_value).is_err());
    let no_value = r#"{"schema":"wsus-applicability-facts/1","collected_at":"x","facts":[{"kind":"license_dword","name":"n","result":{"state":"known"}}]}"#;
    assert!(RecordedFacts::from_json(no_value).is_err());
    let dup = r#"{"schema":"wsus-applicability-facts/1","collected_at":"x","facts":[{"kind":"reg_key","view":"native","subkey":"A","result":{"state":"absent"}},{"kind":"reg_key","view":"native","subkey":"a\\","result":{"state":"known"}}]}"#;
    assert!(
        RecordedFacts::from_json(dup).is_err(),
        "conflicting duplicates"
    );
    let same = r#"{"schema":"wsus-applicability-facts/1","collected_at":"x","facts":[{"kind":"reg_key","view":"native","subkey":"A","result":{"state":"absent"}},{"kind":"reg_key","view":"native","subkey":"a\\","result":{"state":"absent"}}]}"#;
    assert_eq!(RecordedFacts::from_json(same).unwrap().len(), 1);
}

#[test]
fn recorded_and_fake_facts_agree_on_the_same_world() {
    use wsus_protocol::applicability::FakeFacts;
    let mut fake = FakeFacts::windows11_x64();
    fake.set_dword("SOFTWARE\\Acme", "Level", 5);
    let mut snap = Snapshot::new("t");
    snap.os = Some(SnapshotOs {
        major: 10,
        minor: 0,
        build: 26200,
        product_type: 1,
        suite_mask: 0x100,
        architecture: Some(9),
        language: Some("en-US".into()),
        mui_installed: Some(false),
        ..SnapshotOs::default()
    });
    for view in [RegView::Native, RegView::Wow32] {
        snap.facts.push(FactEntry {
            query: FactQuery::RegValue {
                view,
                subkey: "SOFTWARE\\Acme".into(),
                value: "Level".into(),
            },
            result: FactResult::known(reg_value_to_json(&RegValue::Dword(5))),
        });
    }
    let rec = RecordedFacts::from_snapshot(snap).unwrap();
    let rules = [
        r#"<And><b.WindowsVersion Comparison="GreaterThanOrEqualTo" MajorVersion="10" MinorVersion="0"/><b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="software\acme" Value="level" Comparison="EqualTo" Data="5"/></And>"#,
        r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" Value="Level" Comparison="EqualTo" Data="6" RegType32="true"/>"#,
        r#"<b.Processor Architecture="9"/>"#,
    ];
    for r in rules {
        let els = parse_fragments(r.as_bytes(), &Limits::default()).unwrap();
        let e = Expr::parse(&els[0]);
        assert_eq!(evaluate(&e, &fake), evaluate(&e, &rec), "{r}");
    }
}
