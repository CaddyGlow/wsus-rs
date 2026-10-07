//! Operator semantics, Kleene logic, parsing, and robustness of the
//! applicability evaluator. Synthetic rules and a [`FakeFacts`] machine only;
//! see `applicability_real.rs` for the stored real catalog.
use wsus_protocol::applicability::FactProvider;
use wsus_protocol::applicability::expr::{Expr, Operator};
use wsus_protocol::applicability::facts::{FileInfo, RegValue};
use wsus_protocol::applicability::value::{FileTime, Version};
use wsus_protocol::applicability::{
    ApplicabilityRules, Blocker, FakeFacts, NoFacts, OsInfo, Outcome, RegView, SectionKind, Tri,
    evaluate,
};
use wsus_protocol::soap::Limits;
use wsus_protocol::soap::xml::parse_fragments;

fn expr(xml: &str) -> Expr {
    let els = parse_fragments(xml.as_bytes(), &Limits::default()).expect("fragment");
    assert_eq!(els.len(), 1, "one expression");
    Expr::parse(&els[0])
}

fn ev(xml: &str, f: &dyn FactProvider) -> Outcome {
    evaluate(&expr(xml), f)
}

fn t(xml: &str, f: &dyn FactProvider) -> Tri {
    ev(xml, f).value
}

const HK: &str = r#"Key="HKEY_LOCAL_MACHINE""#;

fn machine() -> FakeFacts {
    let mut m = FakeFacts::windows11_x64();
    m.set_dword("SOFTWARE\\Acme", "Level", 5)
        .set_sz("SOFTWARE\\Acme", "Name", "Acme Widget 2")
        .set_sz("SOFTWARE\\Acme", "Version", "4.5.0.7")
        .set_sz("SOFTWARE\\Acme", "", "default text")
        .add_key_both("SOFTWARE\\Acme\\Empty");
    m.set_value_both("SOFTWARE\\Acme", "Blob", RegValue::Binary(vec![1, 2]));
    m
}

#[test]
fn constants_and_kleene_connectives() {
    let f = NoFacts;
    assert_eq!(t("<True/>", &f), Tri::True);
    assert_eq!(t("<False/>", &f), Tri::False);
    assert_eq!(t("<Not><True/></Not>", &f), Tri::False);
    // An unavailable fact is Unknown.
    let u = r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="X"/>"#;
    assert_eq!(t(u, &f), Tri::Unknown);
    assert_eq!(t(&format!("<And>{u}<True/></And>"), &f), Tri::Unknown);
    assert_eq!(t(&format!("<And>{u}<False/></And>"), &f), Tri::False);
    assert_eq!(t(&format!("<Or>{u}<True/></Or>"), &f), Tri::True);
    assert_eq!(t(&format!("<Or>{u}<False/></Or>"), &f), Tri::Unknown);
    assert_eq!(t(&format!("<Not>{u}</Not>"), &f), Tri::Unknown);
    // Short-circuited definite answers carry no blockers.
    assert!(
        ev(&format!("<And>{u}<False/></And>"), &f)
            .blockers
            .is_empty()
    );
    assert_eq!(ev(&format!("<Or>{u}<False/></Or>"), &f).blockers.len(), 1);
}

#[test]
fn tri_tables_are_kleene() {
    use Tri::*;
    let all = [True, False, Unknown];
    for a in all {
        assert_eq!(!!a, a);
        for b in all {
            assert_eq!(a.and(b), b.and(a));
            assert_eq!(a.or(b), b.or(a));
            // De Morgan.
            assert_eq!(!a.and(b), (!a).or(!b));
            // Unknown never becomes True through And, never False through Or.
            if a == Unknown || b == Unknown {
                assert_ne!(a.and(b), True);
                assert_ne!(a.or(b), False);
            }
        }
    }
}

#[test]
fn unsupported_operator_is_unknown_visible_and_short_circuited_away() {
    let f = machine();
    let o = ev("<And><True/><Frobnicate A=\"1\"/></And>", &f);
    assert_eq!(o.value, Tri::Unknown);
    assert_eq!(o.unsupported_names(), vec!["Frobnicate"]);
    assert_eq!(t("<And><False/><Frobnicate/></And>", &f), Tri::False);
    assert_eq!(t("<Or><True/><Frobnicate/></Or>", &f), Tri::True);
    assert_eq!(t("<Or><False/><Frobnicate/></Or>", &f), Tri::Unknown);
    let o = ev(
        r#"<ProductReleaseVersion Name="n" Version="0.0.0.0" Comparison="greaterthan"/>"#,
        &f,
    );
    // implemented since inventory 12.17: a product name without a fact source is Unknown through an
    // unavailable fact, not an unsupported operator
    assert_eq!(o.value, Tri::Unknown);
    assert!(o.unsupported_names().is_empty());
}

#[test]
fn registry_key_and_value_existence() {
    let f = machine();
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyExists {HK} Subkey="software\ACME"/>"#),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyExists {HK} Subkey="SOFTWARE\Nope"/>"#),
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Acme" Value="LEVEL"/>"#),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(
                r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Acme" Value="Level" Type="REG_DWORD"/>"#
            ),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(
                r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Acme" Value="Level" Type="REG_SZ"/>"#
            ),
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(
                r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Acme" Value="Blob" Type="REG_BINARY"/>"#
            ),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Acme" Type="REG_SZ"/>"#),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Acme\Empty"/>"#),
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegValueExists {HK} Subkey="SOFTWARE\Nope" Value="x"/>"#),
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyExists {HK} Subkey="SOFTWARE\Acme"/>"#),
            &NoFacts
        ),
        Tri::Unknown
    );
}

#[test]
fn registry_views_are_distinct() {
    let mut f = FakeFacts::new();
    f.add_key(RegView::Wow32, "SOFTWARE\\Only32");
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyExists {HK} Subkey="SOFTWARE\Only32" RegType32="true"/>"#),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyExists {HK} Subkey="SOFTWARE\Only32" RegType32="false"/>"#),
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyExists {HK} Subkey="SOFTWARE\Only32"/>"#),
            &f
        ),
        Tri::False
    );
}

#[test]
fn reg_dword_comparisons_and_absence() {
    let f = machine();
    let q = |c: &str, d: u32| {
        t(
            &format!(
                r#"<b.RegDword {HK} Subkey="SOFTWARE\Acme" Value="Level" Comparison="{c}" Data="{d}"/>"#
            ),
            &f,
        )
    };
    assert_eq!(q("EqualTo", 5), Tri::True);
    assert_eq!(q("EqualTo", 4), Tri::False);
    assert_eq!(q("GreaterThan", 4), Tri::True);
    assert_eq!(q("GreaterThan", 5), Tri::False);
    assert_eq!(q("GreaterThanOrEqualTo", 5), Tri::True);
    assert_eq!(q("LessThan", 6), Tri::True);
    assert_eq!(q("LessThanOrEqualTo", 4), Tri::False);
    // Absent value is false, so Not(...) is true.
    let missing = format!(
        r#"<b.RegDword {HK} Subkey="SOFTWARE\Acme" Value="Missing" Comparison="GreaterThan" Data="0"/>"#
    );
    assert_eq!(t(&missing, &f), Tri::False);
    assert_eq!(t(&format!("<Not>{missing}</Not>"), &f), Tri::True);
    // Wrong registry type: Unknown, not false.
    let wrong = format!(
        r#"<b.RegDword {HK} Subkey="SOFTWARE\Acme" Value="Name" Comparison="EqualTo" Data="1"/>"#
    );
    assert_eq!(t(&wrong, &f), Tri::Unknown);
    // Unavailable.
    assert_eq!(t(&missing, &NoFacts), Tri::Unknown);
    // Unsigned 32-bit data.
    let mut g = FakeFacts::new();
    g.set_dword("K", "V", 0xFFFF_FFFF);
    assert_eq!(
        t(
            &format!(
                r#"<b.RegDword {HK} Subkey="K" Value="V" Comparison="EqualTo" Data="4294967295"/>"#
            ),
            &g
        ),
        Tri::True
    );
    assert!(matches!(
        expr(&format!(
            r#"<b.RegDword {HK} Subkey="K" Value="V" Comparison="EqualTo" Data="4294967296"/>"#
        )),
        Expr::Unsupported(_)
    ));
}

#[test]
fn reg_sz_comparisons_case_rule_and_types() {
    let f = machine();
    let q = |c: &str, d: &str| {
        t(
            &format!(
                r#"<b.RegSz {HK} Subkey="SOFTWARE\Acme" Value="Name" Comparison="{c}" Data="{d}"/>"#
            ),
            &f,
        )
    };
    assert_eq!(q("EqualTo", "Acme Widget 2"), Tri::True);
    assert_eq!(q("EqualTo", "Other"), Tri::False);
    assert_eq!(q("BeginsWith", "Acme"), Tri::True);
    assert_eq!(q("Contains", "Widget"), Tri::True);
    assert_eq!(q("EndsWith", "2"), Tri::True);
    // Differs only by case: the case rule is unverified, so Unknown.
    assert_eq!(q("EqualTo", "acme widget 2"), Tri::Unknown);
    assert_eq!(q("EqualTo", "ACME WIDGET 3"), Tri::False);
    // Wrong type.
    assert_eq!(
        t(
            &format!(
                r#"<b.RegSz {HK} Subkey="SOFTWARE\Acme" Value="Level" Comparison="EqualTo" Data="5"/>"#
            ),
            &f
        ),
        Tri::Unknown
    );
    assert_eq!(
        t(
            &format!(
                r#"<b.RegSz {HK} Subkey="SOFTWARE\Acme" Value="Nope" Comparison="EqualTo" Data="5"/>"#
            ),
            &f
        ),
        Tri::False
    );
}

#[test]
fn reg_expand_sz_with_environment_references_is_unknown() {
    let mut f = FakeFacts::new();
    f.set_value_both("K", "Plain", RegValue::ExpandSz("True".into()));
    f.set_value_both("K", "Path", RegValue::ExpandSz("%ProgramFiles%\\X".into()));
    let q = |v: &str| {
        t(
            &format!(
                r#"<b.RegExpandSz {HK} Subkey="K" Value="{v}" Comparison="EqualTo" Data="True"/>"#
            ),
            &f,
        )
    };
    assert_eq!(q("Plain"), Tri::True);
    assert_eq!(q("Path"), Tri::Unknown);
    assert_eq!(q("Missing"), Tri::False);
}

#[test]
fn reg_sz_to_version() {
    let f = machine();
    let q = |c: &str, d: &str| {
        t(
            &format!(
                r#"<b.RegSzToVersion {HK} Subkey="SOFTWARE\Acme" Value="Version" Comparison="{c}" Data="{d}"/>"#
            ),
            &f,
        )
    };
    assert_eq!(q("GreaterThanOrEqualTo", "4.5.0.0"), Tri::True);
    assert_eq!(q("LessThan", "4.5.0.7"), Tri::False);
    assert_eq!(q("EqualTo", "4.5.0.7"), Tri::True);
    assert_eq!(q("GreaterThan", "4.10.0.0"), Tri::False);
    let mut g = FakeFacts::new();
    g.set_sz("SOFTWARE\\Win", "CurrentVersion", "6.3");
    let w = |c: &str, d: &str| {
        t(
            &format!(
                r#"<b.RegSzToVersion {HK} Subkey="SOFTWARE\Win" Value="CurrentVersion" Comparison="{c}" Data="{d}"/>"#
            ),
            &g,
        )
    };
    assert_eq!(
        w("GreaterThan", "6.1.0.0"),
        Tri::True,
        "a two-part string is padded"
    );
    assert_eq!(w("EqualTo", "6.3.0.0"), Tri::True);
    // Not a four-part version.
    assert_eq!(
        t(
            &format!(
                r#"<b.RegSzToVersion {HK} Subkey="SOFTWARE\Acme" Value="Name" Comparison="EqualTo" Data="1.0.0.0"/>"#
            ),
            &f
        ),
        Tri::Unknown
    );
    assert_eq!(
        t(
            &format!(
                r#"<b.RegSzToVersion {HK} Subkey="SOFTWARE\Acme" Value="Gone" Comparison="EqualTo" Data="1.0.0.0"/>"#
            ),
            &f
        ),
        Tri::False
    );
}

#[test]
fn reg_key_loop_any_none_all_and_loop_target() {
    let mut f = FakeFacts::new();
    f.set_dword("SOFTWARE\\SQL\\A\\Setup", "Cluster", 1);
    f.set_dword("SOFTWARE\\SQL\\B\\Setup", "Cluster", 0);
    let body = r#"<b.RegDword Key="HKEY_LOOP_TARGET" Subkey="Setup" Value="Cluster" Comparison="EqualTo" Data="1"/>"#;
    let lp = |logic: &str, key: &str| {
        t(
            &format!(
                r#"<b.RegKeyLoop {HK} Subkey="{key}" TrueIf="{logic}"><And>{body}</And></b.RegKeyLoop>"#
            ),
            &f,
        )
    };
    assert_eq!(lp("Any", "SOFTWARE\\SQL"), Tri::True);
    assert_eq!(lp("None", "SOFTWARE\\SQL"), Tri::False);
    assert_eq!(lp("All", "SOFTWARE\\SQL"), Tri::False);
    // Missing loop key: no iterations.
    assert_eq!(lp("Any", "SOFTWARE\\Nope"), Tri::False);
    assert_eq!(lp("None", "SOFTWARE\\Nope"), Tri::True);
    assert_eq!(lp("All", "SOFTWARE\\Nope"), Tri::Unknown);
    // Unavailable registry.
    assert_eq!(
        t(
            &format!(r#"<b.RegKeyLoop {HK} Subkey="x" TrueIf="Any">{body}</b.RegKeyLoop>"#),
            &NoFacts
        ),
        Tri::Unknown
    );
    // HKEY_LOOP_TARGET outside a loop.
    assert_eq!(t(body, &f), Tri::Unknown);
}

fn files() -> FakeFacts {
    let mut f = FakeFacts::windows11_x64();
    f.add_file(
        Some(37),
        "ntoskrnl.exe",
        FileInfo {
            size: Some(1000),
            version: Version::parse("10.0.26100.1"),
            modified: FileTime::parse("2024-05-01T10:00:00Z"),
            created: FileTime::parse("2024-04-01T10:00:00Z"),
            resolved_path: None,
        },
    );
    f.add_file(
        Some(37),
        "novers.dll",
        FileInfo {
            size: Some(5),
            ..FileInfo::default()
        },
    );
    f.set_sz(
        "SOFTWARE\\Acme",
        "InstallLocation",
        "C:\\Program Files\\Acme\\",
    );
    f.add_file(
        None,
        "C:\\Program Files\\Acme\\tool.exe",
        FileInfo {
            version: Version::parse("1.2.3.4"),
            ..FileInfo::default()
        },
    );
    f
}

#[test]
fn file_operators() {
    let f = files();
    assert_eq!(
        t(r#"<b.FileExists Csidl="37" Path="NTOSKRNL.EXE"/>"#, &f),
        Tri::True
    );
    assert_eq!(
        t(r#"<b.FileExists Csidl="37" Path="\ntoskrnl.exe"/>"#, &f),
        Tri::True
    );
    assert_eq!(
        t(r#"<b.FileExists Csidl="38" Path="ntoskrnl.exe"/>"#, &f),
        Tri::False
    );
    assert_eq!(
        t(
            r#"<b.FileExists Csidl="37" Path="ntoskrnl.exe" Size="1000"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            r#"<b.FileExists Csidl="37" Path="ntoskrnl.exe" Size="999"/>"#,
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            r#"<b.FileExists Csidl="37" Path="novers.dll" Size="5"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            r#"<b.FileVersion Csidl="37" Path="ntoskrnl.exe" Comparison="GreaterThanOrEqualTo" Version="10.0.26100.0"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            r#"<b.FileVersion Csidl="37" Path="ntoskrnl.exe" Comparison="LessThan" Version="10.0.26100.1"/>"#,
            &f
        ),
        Tri::False
    );
    // Missing file: false (the version check implies existence).
    assert_eq!(
        t(
            r#"<b.FileVersion Csidl="37" Path="gone.dll" Comparison="GreaterThanOrEqualTo" Version="1.0.0.0"/>"#,
            &f
        ),
        Tri::False
    );
    // Existing file with no recorded version: Unknown.
    assert_eq!(
        t(
            r#"<b.FileVersion Csidl="37" Path="novers.dll" Comparison="GreaterThanOrEqualTo" Version="1.0.0.0"/>"#,
            &f
        ),
        Tri::Unknown
    );
    assert_eq!(
        t(
            r#"<b.FileModified Csidl="37" Path="ntoskrnl.exe" Comparison="GreaterThanOrEqualTo" Modified="2024-05-01T10:00:00.0000000Z"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            r#"<b.FileModified Csidl="37" Path="ntoskrnl.exe" Comparison="LessThan" Modified="2024-05-01T10:00:00.0000000Z"/>"#,
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            r#"<b.FileModified Csidl="37" Path="novers.dll" Comparison="LessThan" Modified="2024-05-01T10:00:00Z"/>"#,
            &f
        ),
        Tri::Unknown
    );
    assert_eq!(
        t(
            r#"<b.FileModified Csidl="37" Path="gone.dll" Comparison="LessThan" Modified="2024-05-01T10:00:00Z"/>"#,
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            r#"<b.FileSize Csidl="37" Path="ntoskrnl.exe" Comparison="GreaterThan" Size="999"/>"#,
            &f
        ),
        Tri::True
    );
    // Absolute paths with an environment variable are not expanded.
    assert_eq!(
        t(r#"<b.FileExists Path="%windir%\x.dll"/>"#, &f),
        Tri::Unknown
    );
    assert_eq!(
        t(
            r#"<b.FileExists Csidl="37" Path="ntoskrnl.exe"/>"#,
            &NoFacts
        ),
        Tri::Unknown
    );
    // Attributes the evaluator does not model make the operator unsupported.
    assert!(matches!(
        expr(r#"<b.FileExists Csidl="37" Path="a" Language="1033"/>"#),
        Expr::Unsupported(_)
    ));
}

#[test]
fn prepend_reg_sz_file_operators() {
    let f = files();
    let base = format!(r#"{HK} Subkey="SOFTWARE\Acme" Value="InstallLocation""#);
    assert_eq!(
        t(
            &format!(r#"<b.FileExistsPrependRegSz Path="tool.exe" {base}/>"#),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(r#"<b.FileExistsPrependRegSz Path="other.exe" {base}/>"#),
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(
                r#"<b.FileVersionPrependRegSz Path="tool.exe" Comparison="EqualTo" Version="1.2.3.4" {base}/>"#
            ),
            &f
        ),
        Tri::True
    );
    // Missing base value: false.
    assert_eq!(
        t(
            &format!(
                r#"<b.FileVersionPrependRegSz Path="tool.exe" Comparison="EqualTo" Version="1.2.3.4" {HK} Subkey="SOFTWARE\Acme" Value="Missing"/>"#
            ),
            &f
        ),
        Tri::False
    );
}

#[test]
fn windows_version_semantics() {
    let mut f = FakeFacts::new();
    f.set_os(OsInfo {
        major: 10,
        minor: 0,
        build: 26200,
        sp_major: 0,
        sp_minor: 0,
        product_type: 1,
        suite_mask: 0x100,
        ..OsInfo::default()
    });
    let q = |a: &str| t(&format!("<b.WindowsVersion {a}/>"), &f);
    assert_eq!(
        q(r#"Comparison="EqualTo" MajorVersion="10" MinorVersion="0""#),
        Tri::True
    );
    assert_eq!(
        q(r#"MajorVersion="10" MinorVersion="0""#),
        Tri::True,
        "EqualTo is the default"
    );
    assert_eq!(
        q(r#"Comparison="GreaterThanOrEqualTo" MajorVersion="6" MinorVersion="3""#),
        Tri::True
    );
    // Hierarchical: major greater makes minor irrelevant.
    assert_eq!(
        q(r#"Comparison="GreaterThan" MajorVersion="6" MinorVersion="9""#),
        Tri::True
    );
    assert_eq!(
        q(r#"Comparison="LessThan" MajorVersion="6" MinorVersion="9""#),
        Tri::False
    );
    assert_eq!(
        q(r#"Comparison="LessThan" MajorVersion="10" MinorVersion="1""#),
        Tri::True
    );
    assert_eq!(
        q(
            r#"Comparison="LessThanOrEqualTo" MajorVersion="10" MinorVersion="0" BuildNumber="26100""#
        ),
        Tri::False
    );
    assert_eq!(
        q(
            r#"Comparison="GreaterThanOrEqualTo" MajorVersion="10" MinorVersion="0" BuildNumber="26100""#
        ),
        Tri::True
    );
    assert_eq!(
        q(r#"Comparison="LessThan" BuildNumber="17763""#),
        Tri::False
    );
    assert_eq!(q(r#"Comparison="EqualTo" MajorVersion="10""#), Tri::True);
    assert_eq!(
        q(r#"Comparison="EqualTo" MajorVersion="6" MinorVersion="1" ProductType="1""#),
        Tri::False
    );
    assert_eq!(q(r#"Comparison="EqualTo" ProductType="1""#), Tri::True);
    assert_eq!(q(r#"Comparison="EqualTo" ProductType="3""#), Tri::False);
    assert_eq!(q(r#"ProductType="1""#), Tri::True);
    // ProductType compares for equality whatever the Comparison is.
    assert_eq!(
        q(r#"Comparison="GreaterThan" MajorVersion="6" MinorVersion="3" ProductType="1""#),
        Tri::True
    );
    assert_eq!(
        q(r#"Comparison="EqualTo" ServicePackMajor="0" MajorVersion="10" MinorVersion="0""#),
        Tri::True
    );
    // Suites: 0x100 = personal.
    assert_eq!(q(r#"SuiteMask="256""#), Tri::True);
    assert_eq!(q(r#"SuiteMask="2""#), Tri::False);
    assert_eq!(q(r#"SuiteMask="258""#), Tri::True, "any of the suites");
    assert_eq!(
        q(r#"SuiteMask="258" AllSuitesMustBePresent="true""#),
        Tri::False
    );
    assert_eq!(
        q(r#"SuiteMask="256" AllSuitesMustBePresent="true""#),
        Tri::True
    );
    assert_eq!(
        t(r#"<b.WindowsVersion MajorVersion="10"/>"#, &NoFacts),
        Tri::Unknown
    );
}

#[test]
fn processor_metric_language_mui_wmi_license() {
    let mut f = FakeFacts::windows11_x64();
    f.set_metric(87, 10)
        .set_wmi("root\\cimv2", "select * from Win32_BIOS", true)
        .set_license_dword("Kernel-ProductInfo", 101);
    assert_eq!(t(r#"<b.Processor Architecture="9"/>"#, &f), Tri::True);
    assert_eq!(t(r#"<b.Processor Architecture="12"/>"#, &f), Tri::False);
    assert!(matches!(
        expr(r#"<b.Processor Architecture="9" Level="6"/>"#),
        Expr::Unsupported(_)
    ));
    assert_eq!(
        t(
            r#"<b.SystemMetric Comparison="EqualTo" Index="87" Value="10"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            r#"<b.SystemMetric Comparison="EqualTo" Index="86" Value="0"/>"#,
            &f
        ),
        Tri::Unknown
    );
    assert_eq!(t(r#"<b.WindowsLanguage Language="en-us"/>"#, &f), Tri::True);
    assert_eq!(t(r#"<b.WindowsLanguage Language="de"/>"#, &f), Tri::False);
    assert_eq!(
        t(r#"<b.WindowsLanguage Language="fr-ca"/>"#, &f),
        Tri::False
    );
    assert_eq!(
        t(r#"<b.WindowsLanguage Language="en"/>"#, &f),
        Tri::Unknown,
        "neutral vs specific"
    );
    assert_eq!(t("<b.MuiInstalled/>", &f), Tri::False);
    f.set_mui_installed(true);
    assert_eq!(t("<b.MuiInstalled/>", &f), Tri::True);
    assert_eq!(
        t(r#"<b.WindowsLanguage Language="en-us"/>"#, &f),
        Tri::False,
        "false when MUI is installed"
    );
    assert_eq!(
        t(
            r#"<b.WmiQuery Namespace="root/cimv2" WqlQuery="select * from Win32_BIOS"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(r#"<b.WmiQuery WqlQuery="select * from Win32_BIOS"/>"#, &f),
        Tri::True,
        "default namespace"
    );
    assert_eq!(t(r#"<b.WmiQuery WqlQuery="select 1"/>"#, &f), Tri::Unknown);
    assert_eq!(
        t(
            r#"<b.LicenseDword Value="kernel-productinfo" Comparison="EqualTo" Data="101"/>"#,
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            r#"<b.LicenseDword Value="Other" Comparison="EqualTo" Data="1"/>"#,
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            r#"<b.LicenseDword Value="Other" Comparison="EqualTo" Data="1"/>"#,
            &NoFacts
        ),
        Tri::Unknown
    );
}

#[test]
fn msi_operators() {
    let p = "{E49CA583-2EC0-4510-862A-C2BEFD036330}";
    let mut f = FakeFacts::new();
    f.add_msi_product(p, "10.22.130", Some(1033))
        .add_msi_feature(p, "Admin")
        .add_msi_component(p, "{38B098DD-CF55-49E3-9CBA-8604E2B1D59A}")
        .add_msi_patch(p, "{E1D63391-7DA5-442C-BEAB-CEE5B046A22D}");
    let q = |a: &str| {
        t(
            &format!(r#"<m.MsiProductInstalled ProductCode="{p}" {a}/>"#),
            &f,
        )
    };
    assert_eq!(q(""), Tri::True);
    assert_eq!(
        q(r#"VersionMin="10.22.123.0" VersionMax="10.22.136.0""#),
        Tri::True
    );
    assert_eq!(
        q(r#"VersionMin="10.22.130.0""#),
        Tri::True,
        "inclusive, zero padded"
    );
    assert_eq!(
        q(r#"VersionMin="10.22.130.0" ExcludeVersionMin="true""#),
        Tri::False
    );
    assert_eq!(
        q(r#"VersionMax="10.22.130" ExcludeVersionMax="true""#),
        Tri::False
    );
    assert_eq!(q(r#"VersionMax="10.22.129""#), Tri::False);
    assert_eq!(
        q(r#"ExcludeVersionMax="true" ExcludeVersionMin="true""#),
        Tri::True,
        "exclusion without a bound is ignored"
    );
    assert_eq!(q(r#"Language="1033""#), Tri::True);
    assert_eq!(q(r#"Language="1041""#), Tri::False);
    assert_eq!(
        t(
            r#"<m.MsiProductInstalled ProductCode="{00000000-0000-0000-0000-000000000000}"/>"#,
            &f
        ),
        Tri::False
    );
    assert_eq!(
        t(
            &format!(
                r#"<m.MsiProductInstalled ProductCode="{}"/>"#,
                p.to_lowercase()
            ),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(r#"<m.MsiProductInstalled ProductCode="{p}"/>"#),
            &NoFacts
        ),
        Tri::Unknown
    );
    // Feature / component / patch.
    let feat = |all_f: &str, feats: &[&str]| {
        let kids: String = feats
            .iter()
            .map(|x| format!("<m.Feature>{x}</m.Feature>"))
            .collect();
        t(
            &format!(
                r#"<m.MsiFeatureInstalledForProduct AllFeaturesRequired="{all_f}">{kids}<m.Product>{p}</m.Product></m.MsiFeatureInstalledForProduct>"#
            ),
            &f,
        )
    };
    assert_eq!(feat("false", &["Admin", "Other"]), Tri::True);
    assert_eq!(feat("true", &["Admin", "Other"]), Tri::False);
    assert_eq!(feat("true", &["Admin"]), Tri::True);
    assert_eq!(
        t(
            &format!(
                r#"<m.MsiComponentInstalledForProduct AllComponentsRequired="true" AllProductsRequired="true"><m.Component>{{38b098dd-cf55-49e3-9cba-8604e2b1d59a}}</m.Component><m.Product>{p}</m.Product></m.MsiComponentInstalledForProduct>"#
            ),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(
                r#"<m.MsiPatchInstalledForProduct PatchCode="{{e1d63391-7da5-442c-beab-cee5b046a22d}}" ProductCode="{p}"/>"#
            ),
            &f
        ),
        Tri::True
    );
    assert_eq!(
        t(
            &format!(
                r#"<m.MsiPatchInstalledForProduct PatchCode="{{00000000-0000-0000-0000-000000000001}}" ProductCode="{p}"/>"#
            ),
            &f
        ),
        Tri::False
    );
}

#[test]
fn cbs_package_state() {
    let id = "Package_for_KB1~31bf3856ad364e35~amd64~~10.0.1.0";
    let mut f = FakeFacts::new();
    f.set_cbs_package(id, 112).set_cbs_package("Other~1", 80);
    let q = |i: &str| {
        t(
            &format!(r#"<CbsPackageInstalledByIdentity PackageIdentity="{i}"/>"#),
            &f,
        )
    };
    assert_eq!(q(id), Tri::True);
    assert_eq!(q("Other~1"), Tri::Unknown);
    assert_eq!(q("Missing~1"), Tri::False);
}

#[test]
fn sections_parse_and_evaluate() {
    let xml = r#"<ApplicabilityRules><IsInstalled><True/></IsInstalled><IsInstallable><b.Processor Architecture="9"/><b.Processor Architecture="9"/></IsInstallable><Metadata><x/></Metadata><Odd/></ApplicabilityRules>"#;
    let els = parse_fragments(xml.as_bytes(), &Limits::default()).unwrap();
    let r = ApplicabilityRules::from_element(&els[0]);
    assert_eq!(r.metadata.len(), 1);
    assert_eq!(r.other.len(), 1, "unknown section kept");
    assert!(!r.is_fully_supported());
    let f = FakeFacts::windows11_x64();
    assert_eq!(r.evaluate(SectionKind::IsInstalled, &f).value, Tri::True);
    assert_eq!(
        r.evaluate(SectionKind::IsInstallable, &f).value,
        Tri::True,
        "implicit And"
    );
    let o = r.evaluate(SectionKind::IsSuperseded, &f);
    assert_eq!(o.value, Tri::Unknown);
    assert!(matches!(o.blockers[0], Blocker::Undecidable { .. }));
    let empty = ApplicabilityRules::from_element(
        &parse_fragments(
            b"<ApplicabilityRules><IsInstalled/></ApplicabilityRules>",
            &Limits::default(),
        )
        .unwrap()[0],
    );
    assert_eq!(
        empty.evaluate(SectionKind::IsInstalled, &f).value,
        Tri::Unknown
    );
}

#[test]
fn strict_prefixed_documents_evaluate_like_fragments() {
    let xml = r#"<Update xmlns="http://schemas.microsoft.com/msus/2002/12/Update" xmlns:lar="http://schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules" xmlns:bar="http://schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules"><UpdateIdentity UpdateID="11111111-1111-4111-8111-111111111111" RevisionNumber="1"/><ApplicabilityRules><IsInstalled><lar:And><bar:Processor Architecture="9"/><lar:Not><bar:RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="X"/></lar:Not></lar:And></IsInstalled></ApplicabilityRules></Update>"#;
    let idx =
        wsus_protocol::metadata::UpdateIndex::parse(xml.as_bytes(), &Limits::default()).unwrap();
    let rules = ApplicabilityRules::from_element(idx.applicability_rules.as_ref().unwrap());
    assert!(rules.is_fully_supported(), "{rules:?}");
    assert_eq!(
        rules
            .evaluate(SectionKind::IsInstalled, &FakeFacts::windows11_x64())
            .value,
        Tri::True
    );
}

#[test]
fn parsed_operators_expose_typed_fields() {
    let Expr::Op(Operator::RegDword { value, data, .. }) = expr(
        r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="S" Value="V" Comparison="LessThan" Data="7" RegType32="true"/>"#,
    ) else {
        panic!()
    };
    assert_eq!(data, 7);
    assert_eq!(value.key.view, RegView::Wow32);
}

// ---- property-style and robustness tests ------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn random_expr(r: &mut Rng, depth: u32) -> String {
    let leaves = [
        "<True/>",
        "<False/>",
        "<Frobnicate/>",
        r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme"/>"#,
        r#"<b.RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Missing"/>"#,
        r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" Value="Level" Comparison="EqualTo" Data="5"/>"#,
        r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" Value="Name" Comparison="EqualTo" Data="5"/>"#,
        r#"<b.WmiQuery WqlQuery="select 1"/>"#,
        r#"<b.Processor Architecture="9"/>"#,
        r#"<ProductReleaseVersion Name="n" Version="1.0.0.0" Comparison="greaterthan"/>"#,
    ];
    if depth == 0 || r.pick(4) == 0 {
        return leaves[r.pick(leaves.len())].to_owned();
    }
    let n = 1 + r.pick(3);
    let kids: String = (0..n).map(|_| random_expr(r, depth - 1)).collect();
    match r.pick(3) {
        0 => format!("<And>{kids}</And>"),
        1 => format!("<Or>{kids}</Or>"),
        _ => format!("<Not>{}</Not>", random_expr(r, depth - 1)),
    }
}

/// Reference: replace every Unknown leaf by True and by False. A definite
/// answer for the real tree must equal the answer of both substitutions
/// (Kleene monotonicity), so Unknown can never turn into True or False.
#[test]
fn unknown_never_becomes_definite_against_any_completion() {
    let f = machine();
    let mut r = Rng(0x1234_5678_9abc_def1);
    let mut definite = 0;
    let mut unknown = 0;
    for _ in 0..600 {
        let xml = random_expr(&mut r, 4);
        let e = expr(&xml);
        let o = evaluate(&e, &f);
        // Substitute unknown leaves (Frobnicate, WmiQuery select 1, type
        // mismatch RegDword, ProductReleaseVersion) with constants.
        for fill in ["<True/>", "<False/>"] {
            let mut sub = xml.clone();
            for u in [
                "<Frobnicate/>",
                r#"<b.WmiQuery WqlQuery="select 1"/>"#,
                r#"<b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" Value="Name" Comparison="EqualTo" Data="5"/>"#,
                r#"<ProductReleaseVersion Name="n" Version="1.0.0.0" Comparison="greaterthan"/>"#,
            ] {
                sub = sub.replace(u, fill);
            }
            let s = evaluate(&expr(&sub), &f).value;
            assert_ne!(s, Tri::Unknown, "{sub}");
            match o.value {
                Tri::True => assert_eq!(s, Tri::True, "{xml} with {fill}"),
                Tri::False => assert_eq!(s, Tri::False, "{xml} with {fill}"),
                Tri::Unknown => {}
            }
        }
        match o.value {
            Tri::Unknown => {
                unknown += 1;
                assert!(!o.blockers.is_empty(), "{xml}");
            }
            _ => {
                definite += 1;
                assert!(o.blockers.is_empty(), "{xml}");
            }
        }
    }
    assert!(definite > 50 && unknown > 50, "{definite} {unknown}");
}

#[test]
fn mutated_rule_xml_never_panics() {
    let seeds = [
        r#"<ApplicabilityRules><IsInstalled><And><b.RegDword Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" Value="Level" Comparison="GreaterThanOrEqualTo" Data="1"/><Not><b.WindowsVersion Comparison="EqualTo" MajorVersion="6" MinorVersion="1" BuildNumber="7601" ProductType="1"/></Not><m.MsiProductInstalled ProductCode="{E49CA583-2EC0-4510-862A-C2BEFD036330}" VersionMin="1.0.0.0" ExcludeVersionMin="true"/><b.RegKeyLoop Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" TrueIf="Any"><b.RegKeyExists Key="HKEY_LOOP_TARGET" Subkey="Empty"/></b.RegKeyLoop><b.FileVersionPrependRegSz Path="x.dll" Comparison="LessThan" Version="1.2.3.4" Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Acme" Value="InstallLocation"/><b.FileModified Path="a" Csidl="37" Comparison="LessThan" Modified="2013-11-30T14:50:16.0000000Z"/></And></IsInstalled><IsInstallable><True/></IsInstallable></ApplicabilityRules>"#,
        r#"<lar:And xmlns:lar="http://schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules"><lar:True/></lar:And>"#,
    ];
    let f = machine();
    let mut r = Rng(0xdead_beef_cafe_f00d);
    let mut parsed = 0;
    for seed in seeds {
        for _ in 0..2000 {
            let mut b = seed.as_bytes().to_vec();
            for _ in 0..1 + r.pick(4) {
                let i = r.pick(b.len());
                match r.pick(4) {
                    0 => b[i] = (r.next() & 0xff) as u8,
                    1 => {
                        b.remove(i);
                    }
                    2 => b.insert(i, b"<>/=\"' a"[r.pick(8)]),
                    _ => {
                        let j = r.pick(b.len());
                        b.swap(i, j);
                    }
                }
            }
            let limits = Limits::default();
            if let Ok(els) = parse_fragments(&b, &limits) {
                for el in &els {
                    parsed += 1;
                    let rules = ApplicabilityRules::from_element(el);
                    let _ = rules.evaluate(SectionKind::IsInstalled, &f);
                    let _ = rules.evaluate(SectionKind::IsInstallable, &NoFacts);
                    let e = Expr::parse(el);
                    let o = evaluate(&e, &f);
                    // Whatever the input, an unknown carries a reason.
                    assert!(o.value != Tri::Unknown || !o.blockers.is_empty());
                    let _ = wsus_protocol::applicability::required_queries(&e);
                }
            }
        }
    }
    assert!(
        parsed > 500,
        "mutations should often still parse, got {parsed}"
    );
}

/// The deepest expression the parser accepts (nesting 63 of `MAX_DEPTH` 64) parses, evaluates
/// and drops on a thread with a small stack; one level deeper is kept as an unsupported node.
#[test]
fn maximum_nesting_fits_a_small_stack() {
    let depth = wsus_protocol::applicability::expr::MAX_DEPTH;
    let handle = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || {
            let nest = |n: usize| {
                let mut x = String::from("<b.RegKeyLoop Key=\"HKEY_LOCAL_MACHINE\" Subkey=\"K\" TrueIf=\"Any\"><And><Or>");
                for _ in 0..n {
                    x.push_str("<Not><And>");
                }
                x.push_str("<True/>");
                for _ in 0..n {
                    x.push_str("</And></Not>");
                }
                x.push_str("</Or></And></b.RegKeyLoop>");
                x
            };
            let limits = Limits { max_depth: 1000, ..Limits::default() };
            let ok = parse_fragments(nest((depth - 4) / 2).as_bytes(), &limits).unwrap();
            let e = Expr::parse(&ok[0]);
            assert!(e.is_fully_supported());
            let mut f = FakeFacts::new();
            f.add_key_both("K\\child");
            let _ = evaluate(&e, &f);
            let deep = parse_fragments(nest(depth).as_bytes(), &limits).unwrap();
            let e = Expr::parse(&deep[0]);
            assert!(!e.is_fully_supported());
            let _ = evaluate(&e, &f);
        })
        .unwrap();
    handle.join().unwrap();
}
