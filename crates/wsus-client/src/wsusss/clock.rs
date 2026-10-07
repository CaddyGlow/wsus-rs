//! Time source and lexical `xs:dateTime` conversion.
use std::time::{SystemTime, UNIX_EPOCH};

use wsus_protocol::soap::XsDateTime;

/// Source of the current time, injectable for tests.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// Wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Convert `YYYY-MM-DDThh:mm:ss[.f+][Z|+hh:mm|-hh:mm]` to Unix seconds
/// (fractions are dropped). A value without a designator is read as UTC, which
/// is an Implementation decision: peers send both forms. `None` when the text
/// does not have that shape.
pub fn parse_unix(value: &XsDateTime) -> Option<i64> {
    let t = value.as_str().trim();
    if t.starts_with('-') {
        return None;
    }
    let (date, rest) = t.split_once('T')?;
    let mut dp = date.split('-');
    let (y, m, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let split_at = rest.find(['Z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(split_at);
    let clock = clock.split('.').next()?;
    let mut tp = clock.split(':');
    let (hh, mm, ss) = (num(tp.next()?)?, num(tp.next()?)?, num(tp.next()?)?);
    if tp.next().is_some() || hh > 24 || mm > 59 || ss > 60 {
        return None;
    }
    let offset = match zone {
        "" | "Z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let (oh, om) = z[1..].split_once(':')?;
            sign * (num(oh)? * 3600 + num(om)? * 60)
        }
    };
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<i64> {
        parse_unix(&XsDateTime::new(s)?)
    }

    #[test]
    fn parses_known_instants() {
        assert_eq!(p("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(p("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(p("2000-03-01T01:00:00+01:00"), Some(951_868_800));
        assert_eq!(p("2000-03-01T00:00:00.1234567"), Some(951_868_800));
        assert_eq!(p("9999-12-31T23:59:59.9999999"), Some(253_402_300_799));
    }
}
