//! Unix-time conversions for `xs:dateTime` values (proleptic Gregorian, UTC).

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
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

/// `2026-10-04T12:00:00.000Z`.
pub fn format_xs(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `2026-10-04T12:00:00.0000000Z`: seven fractional digits, the form a real WSUS uses for
/// cookie `Expiration` (Observed 2026-10-04: 34 of 35 samples; the other had no fraction). Our
/// earlier three-digit form is accepted by the handshake but is not what the real server emits.
pub fn format_xs7(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.0000000Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `2026-10-04`: the date-only form a real WSUS uses for `Deployment/LastChangeTime`
/// (Observed 2026-10-04, WSUS on Windows Server 2025 10.0.26100: 189 of 189 deployments in the
/// captures). A native Windows Update Agent rejects the full `xs:dateTime` form there with
/// `E_INVALIDARG` from its time parser right after `SyncUpdates`.
pub fn format_date(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parse an `xs:dateTime` to unix seconds. Fractions are dropped; a missing zone means UTC.
pub fn parse_xs(text: &str) -> Option<i64> {
    let t = text.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let (date, time) = t.split_once('T')?;
    let mut dp = date.splitn(3, '-');
    let y: i64 = dp.next()?.parse().ok()?;
    let m: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (clock, offset) = match time.find(['Z', '+', '-']) {
        Some(i) if &time[i..] == "Z" => (&time[..i], 0),
        Some(i) => {
            let sign = if time.as_bytes()[i] == b'-' { -1 } else { 1 };
            let (h, mi) = time[i + 1..].split_once(':')?;
            (
                &time[..i],
                sign * (h.parse::<i64>().ok()? * 3600 + mi.parse::<i64>().ok()? * 60),
            )
        }
        None => (time, 0),
    };
    let clock = clock.split('.').next()?;
    let mut tp = clock.splitn(3, ':');
    let hh: i64 = tp.next()?.parse().ok()?;
    let mm: i64 = tp.next()?.parse().ok()?;
    let ss: i64 = tp.next()?.parse().ok()?;
    if hh > 24 || mm > 59 || ss > 60 {
        return None;
    }
    let y = if neg { -y } else { y };
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_handles_offsets() {
        assert_eq!(format_xs(0), "1970-01-01T00:00:00.000Z");
        for t in [0, 951_782_400, 1_790_000_000, 4_102_444_799] {
            assert_eq!(parse_xs(&format_xs(t)), Some(t));
        }
        assert_eq!(parse_xs("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_xs("2000-02-29T00:00:00"), Some(951_782_400));
        assert_eq!(parse_xs("nonsense"), None);
    }
}
