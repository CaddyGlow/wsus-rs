//! Scalar value types shared by the expression parser, the fact providers and
//! the evaluator: comparison operators, four-part versions, MSI versions and
//! file times.
//!
//! Evidence labels follow the module documentation of [`super`].
use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};

/// `bt:ScalarComparison` (Specified: BaseTypes schema). The operand order is
/// always `observed value <op> value in the rule`; the schema page does not
/// state the direction, the `FileVersion` example in "Version Detection
/// Logic" ("file version GreaterThanOrEqualTo 9.0.0.3344" means "the file has
/// the fix") fixes it for the file operators and this crate uses it for all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Comparison {
    LessThan,
    LessThanOrEqualTo,
    EqualTo,
    GreaterThanOrEqualTo,
    GreaterThan,
}

impl Comparison {
    /// Parse a `ScalarComparison` token. The schema enumeration is
    /// case-sensitive; one real operator (`ProductReleaseVersion`) writes
    /// `greaterthan`, so matching here ignores ASCII case (Implementation
    /// decision; every other real occurrence is exactly cased).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "lessthan" => Self::LessThan,
            "lessthanorequalto" => Self::LessThanOrEqualTo,
            "equalto" => Self::EqualTo,
            "greaterthanorequalto" => Self::GreaterThanOrEqualTo,
            "greaterthan" => Self::GreaterThan,
            _ => return None,
        })
    }

    /// Schema spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LessThan => "LessThan",
            Self::LessThanOrEqualTo => "LessThanOrEqualTo",
            Self::EqualTo => "EqualTo",
            Self::GreaterThanOrEqualTo => "GreaterThanOrEqualTo",
            Self::GreaterThan => "GreaterThan",
        }
    }

    /// Does `have.cmp(want)` satisfy the comparison.
    pub fn test(self, have_vs_want: Ordering) -> bool {
        match self {
            Self::LessThan => have_vs_want == Ordering::Less,
            Self::LessThanOrEqualTo => have_vs_want != Ordering::Greater,
            Self::EqualTo => have_vs_want == Ordering::Equal,
            Self::GreaterThanOrEqualTo => have_vs_want != Ordering::Less,
            Self::GreaterThan => have_vs_want == Ordering::Greater,
        }
    }

    /// Compare two ordered values, `have` against `want`.
    pub fn apply<T: Ord>(self, have: T, want: T) -> bool {
        self.test(have.cmp(&want))
    }
}

/// `bt:StringComparison` (Specified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringComparison {
    EqualTo,
    BeginsWith,
    Contains,
    EndsWith,
}

impl StringComparison {
    /// Parse the schema token (ASCII case-insensitive, see [`Comparison::parse`]).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "equalto" => Self::EqualTo,
            "beginswith" => Self::BeginsWith,
            "contains" => Self::Contains,
            "endswith" => Self::EndsWith,
            _ => return None,
        })
    }

    /// Schema spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EqualTo => "EqualTo",
            Self::BeginsWith => "BeginsWith",
            Self::Contains => "Contains",
            Self::EndsWith => "EndsWith",
        }
    }

    /// Ordinal (case-sensitive) test of `have <op> want`.
    pub fn test(self, have: &str, want: &str) -> bool {
        match self {
            Self::EqualTo => have == want,
            Self::BeginsWith => have.starts_with(want),
            Self::Contains => have.contains(want),
            Self::EndsWith => have.ends_with(want),
        }
    }
}

/// `bt:LoopLogic` (Specified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoopLogic {
    Any,
    All,
    None,
}

impl LoopLogic {
    /// Parse the schema token (ASCII case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "any" => Self::Any,
            "all" => Self::All,
            "none" => Self::None,
            _ => return None,
        })
    }
}

/// Four-part numeric version (`bt:Version`, Specified: `\d{1,5}(\.\d{1,5}){3}`).
/// Ordering is numeric per part, left to right, so `1.38.02612.1523` has the
/// third part 2612.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub [u32; 4]);

impl Version {
    /// Strict four-part parse. Parts must be decimal digits; more than five
    /// digits per part is accepted as long as it fits `u32` (the schema limit
    /// is not enforced, an Implementation decision that only widens input).
    pub fn parse(s: &str) -> Option<Self> {
        let parts = parse_parts(s)?;
        <[u32; 4]>::try_from(parts).ok().map(Self)
    }
}

impl Version {
    /// One to four numeric parts, missing parts zero (`6.3` is `6.3.0.0`). Used for
    /// registry strings read as versions: the real `CurrentVersion` value is `6.3`.
    pub fn parse_padded(s: &str) -> Option<Self> {
        let mut parts = parse_parts(s)?;
        if parts.len() > 4 {
            return None;
        }
        parts.resize(4, 0);
        <[u32; 4]>::try_from(parts).ok().map(Self)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl Serialize for Version {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Version::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("bad version `{s}`")))
    }
}

fn parse_parts(s: &str) -> Option<Vec<u32>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    s.split('.')
        .map(|p| {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                p.parse::<u32>().ok()
            }
        })
        .collect()
}

/// Windows Installer version (`mspblob:Version` in the rules, `VersionString`
/// of the product): one to four numeric parts. Missing parts compare as zero
/// (Implementation decision: the pinned pages do not say how `1.2.3` orders
/// against `1.2.3.0`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MsiVersion(Vec<u32>);

impl MsiVersion {
    /// Parse one to four numeric parts; anything else is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        let parts = parse_parts(s)?;
        (parts.len() <= 4).then_some(Self(parts))
    }

    /// Ordering with zero padding.
    pub fn cmp_padded(&self, other: &Self) -> Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let a = self.0.get(i).copied().unwrap_or(0);
            let b = other.0.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        Ordering::Equal
    }
}

/// A UTC instant with 100 ns resolution (the NTFS FILETIME granularity),
/// counted from 0001-01-01T00:00:00Z. Parsed from `xs:dateTime`; a value with
/// no time zone is rejected rather than assumed to be UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileTime(pub i64);

const TICKS_PER_SEC: i64 = 10_000_000;
const SECS_PER_DAY: i64 = 86_400;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    // Howard Hinnant's algorithm; day 0 is 0000-03-01.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

impl FileTime {
    /// Parse `YYYY-MM-DDThh:mm:ss[.f{1,9}](Z|+hh:mm|-hh:mm)`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let b = s.as_bytes();
        let num = |from: usize, len: usize| -> Option<i64> {
            let t = b.get(from..from + len)?;
            if !t.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(t).ok()?.parse().ok()
        };
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
            return None;
        }
        if b[16] != b':' {
            return None;
        }
        let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
        let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
        if !(1..=9999).contains(&y)
            || !(1..=12).contains(&mo)
            || d < 1
            || d > days_in_month(y, mo)
            || h > 23
            || mi > 59
            || sec > 59
        {
            return None;
        }
        let mut i = 19;
        let mut frac = 0i64;
        if b.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            let digits = &s[start..i];
            if digits.is_empty() || digits.len() > 9 {
                return None;
            }
            let mut padded = digits.to_owned();
            while padded.len() < 7 {
                padded.push('0');
            }
            frac = padded[..7].parse().ok()?;
        }
        let offset_secs = match b.get(i..)? {
            b"Z" => 0,
            rest if rest.len() == 6 && (rest[0] == b'+' || rest[0] == b'-') && rest[3] == b':' => {
                let oh = num(i + 1, 2)?;
                let om = num(i + 4, 2)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                let v = oh * 3600 + om * 60;
                if rest[0] == b'+' { v } else { -v }
            }
            _ => return None,
        };
        // Days since 0001-01-01: civil day 0 is 1970-01-01.
        let days = days_from_civil(y, mo, d) - days_from_civil(1, 1, 1);
        let secs = days * SECS_PER_DAY + h * 3600 + mi * 60 + sec - offset_secs;
        if secs < 0 {
            return None;
        }
        secs.checked_mul(TICKS_PER_SEC)?.checked_add(frac).map(Self)
    }

    /// `YYYY-MM-DDThh:mm:ss.fffffffZ`.
    pub fn to_rfc3339(self) -> String {
        let secs = self.0.div_euclid(TICKS_PER_SEC);
        let frac = self.0.rem_euclid(TICKS_PER_SEC);
        let days = secs.div_euclid(SECS_PER_DAY) + days_from_civil(1, 1, 1);
        let rem = secs.rem_euclid(SECS_PER_DAY);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:07}Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }
}

impl Serialize for FileTime {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for FileTime {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        FileTime::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("bad time `{s}`")))
    }
}

/// Canonical form of a registry sub-key path for comparison: forward slashes
/// become backslashes, duplicate and edge backslashes are removed, ASCII and
/// Unicode case are folded (registry key and value names are case-insensitive,
/// Specified by the Windows registry; the rule pages do not restate it).
pub fn canon_key(s: &str) -> String {
    canon_path(s)
}

/// Canonical form of a file path fragment for comparison: as [`canon_key`]
/// (NTFS names are case-insensitive for lookup; duplicate backslashes are
/// removed, Specified for the client by the `FileExists` text "canonicalize the
/// path to remove duplicate backslashes (among other things)").
pub fn canon_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_sep = true;
    for c in s.chars() {
        let c = if c == '/' { '\\' } else { c };
        if c == '\\' {
            if !last_sep {
                out.push('\\');
            }
            last_sep = true;
        } else {
            out.extend(c.to_lowercase());
            last_sep = false;
        }
    }
    while out.ends_with('\\') {
        out.pop();
    }
    out
}

/// Normalize a registry value name for comparison (case-insensitive).
pub fn canon_value_name(s: &str) -> String {
    s.to_lowercase()
}

/// Normalize a GUID string to `{UPPER-CASE}` form; non-GUID text is only
/// upper-cased and brace-wrapped.
pub fn canon_guid(s: &str) -> String {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    format!("{{{}}}", t.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_numerically_per_part() {
        let a = Version::parse("1.38.02612.1523").unwrap();
        assert_eq!(a.0, [1, 38, 2612, 1523]);
        assert!(Version::parse("1.9.0.0").unwrap() < Version::parse("1.10.0.0").unwrap());
        assert!(Version::parse("1.2.3").is_none());
        assert!(Version::parse("1.2.3.x").is_none());
        assert!(Version::parse("1.2.3.4.5").is_none());
        assert!(Version::parse("").is_none());
    }

    #[test]
    fn msi_versions_pad_with_zero() {
        let a = MsiVersion::parse("1.2.3").unwrap();
        let b = MsiVersion::parse("1.2.3.0").unwrap();
        assert_eq!(a.cmp_padded(&b), Ordering::Equal);
        assert!(MsiVersion::parse("1.2.3.4.5").is_none());
    }

    #[test]
    fn file_times_parse_compare_and_roundtrip() {
        let a = FileTime::parse("2013-11-30T14:50:16.0000000Z").unwrap();
        let b = FileTime::parse("2013-11-30T14:50:17Z").unwrap();
        assert!(a < b);
        assert_eq!(b.0 - a.0, TICKS_PER_SEC);
        assert_eq!(a.to_rfc3339(), "2013-11-30T14:50:16.0000000Z");
        let off = FileTime::parse("2013-11-30T16:50:16+02:00").unwrap();
        assert_eq!(off, a);
        assert!(FileTime::parse("2013-11-30T14:50:16").is_none());
        assert!(FileTime::parse("2013-02-30T14:50:16Z").is_none());
        assert!(FileTime::parse("garbage").is_none());
        // FILETIME epoch 1601-01-01 is 504911232000000000 ticks after 0001-01-01.
        assert_eq!(
            FileTime::parse("1601-01-01T00:00:00Z").unwrap().0,
            504_911_232_000_000_000
        );
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(
            canon_key("\\Software\\\\Microsoft/Windows\\"),
            "software\\microsoft\\windows"
        );
        assert_eq!(
            canon_path("\\Internet Explorer\\IEXPLORE.exe"),
            "internet explorer\\iexplore.exe"
        );
        assert_eq!(
            canon_guid("e49ca583-2ec0-4510-862a-c2befd036330"),
            "{E49CA583-2EC0-4510-862A-C2BEFD036330}"
        );
    }

    #[test]
    fn comparisons_have_the_value_first() {
        assert!(Comparison::GreaterThanOrEqualTo.apply(5, 5));
        assert!(Comparison::LessThan.apply(4, 5));
        assert!(!Comparison::GreaterThan.apply(5, 5));
        assert_eq!(
            Comparison::parse("greaterthan"),
            Some(Comparison::GreaterThan)
        );
        assert!(Comparison::parse("Near").is_none());
    }
}
