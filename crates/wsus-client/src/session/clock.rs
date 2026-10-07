//! Time source and conversion between Unix seconds and `xs:dateTime`.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use wsus_protocol::soap::XsDateTime;

/// Source of the current time as Unix seconds.
pub trait Clock: Sync {
    /// Current time.
    fn now_unix(&self) -> i64;
}

/// Wall-clock time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }
}

/// Manually advanced clock; clones share the same time. Useful for tests.
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    /// Clock starting at `now_unix`.
    pub fn new(now_unix: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_unix)))
    }

    /// Sets the time.
    pub fn set(&self, now_unix: i64) {
        self.0.store(now_unix, Ordering::SeqCst);
    }

    /// Advances the time.
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl<C: Clock + Send> Clock for Arc<C> {
    fn now_unix(&self) -> i64 {
        self.as_ref().now_unix()
    }
}

// Howard Hinnant's civil-date algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
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

/// Formats Unix seconds as a UTC `xs:dateTime` (`YYYY-MM-DDTHH:MM:SSZ`).
/// Years outside 1..=9999 are clamped to the representable range.
pub fn unix_to_xs(unix: i64) -> XsDateTime {
    let unix = unix.clamp(-62_135_596_800, 253_402_300_799);
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let text = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    );
    XsDateTime::new(&text).expect("formatted dateTime is valid")
}

/// Parses an `xs:dateTime` to Unix seconds. A value without a zone is taken as
/// UTC; fractional seconds are truncated; years before 0001 are rejected.
pub fn xs_to_unix(value: &XsDateTime) -> Option<i64> {
    let t = value.as_str().trim();
    if t.starts_with('-') || t.len() < 19 {
        return None;
    }
    let b = t.as_bytes();
    let num = |a: usize, z: usize| t.get(a..z)?.parse::<i64>().ok();
    // Year may have more than four digits; locate the first '-' after it.
    let ydash = t.find('-')?;
    let y: i64 = t[..ydash].parse().ok()?;
    let rest = &t[ydash..];
    let off = ydash;
    if rest.len() < 15 || b[off + 3] != b'-' || b[off + 6] != b'T' {
        return None;
    }
    let (mo, d) = (num(off + 1, off + 3)?, num(off + 4, off + 6)?);
    let (h, mi, s) = (
        num(off + 7, off + 9)?,
        num(off + 10, off + 12)?,
        num(off + 13, off + 15)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 24 || mi > 59 || s > 60 {
        return None;
    }
    let mut tail = &t[off + 15..];
    if let Some(frac) = tail.strip_prefix('.') {
        let n = frac.chars().take_while(char::is_ascii_digit).count();
        tail = &frac[n..];
    }
    let zone = match tail {
        "" | "Z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let hh: i64 = z.get(1..3)?.parse().ok()?;
            let mm: i64 = z.get(4..6)?.parse().ok()?;
            sign * (hh * 3600 + mm * 60)
        }
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - zone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_parses_zones() {
        for unix in [0, 1_700_000_000, 4_102_444_800, -86_400] {
            assert_eq!(xs_to_unix(&unix_to_xs(unix)), Some(unix));
        }
        let with_zone = XsDateTime::new("2024-01-01T01:00:00.250+01:00").unwrap();
        assert_eq!(xs_to_unix(&with_zone), Some(1_704_067_200));
        assert_eq!(unix_to_xs(0).as_str(), "1970-01-01T00:00:00Z");
    }
}
