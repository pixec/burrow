pub mod auth;
pub mod edge;
pub mod tags;
pub mod telemetry;

use serde::{Deserialize, Serialize};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

macro_rules! id_type {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn generate() -> Self {
                Self(format!("{}_{}", $prefix, uuid::Uuid::new_v4().simple()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(NodeId, "node");
id_type!(SandboxId, "sbx");
id_type!(SnapshotId, "snap");
// One VM boot inside a sandbox's life. Minted by the node that started the VM,
// unlike sandbox and snapshot ids: a session is never named by a caller and
// never has to be reserved before it exists.
id_type!(SessionId, "ses");

/// RFC 3339 UTC timestamp `days` in the past, for retention cutoffs.
pub fn rfc3339_days_ago(days: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_from_unix(now.saturating_sub(days * 86_400))
}

/// RFC 3339 UTC timestamp for the current instant, without sub-second noise.
pub fn now_rfc3339() -> String {
    // Avoid a chrono/time dependency for one format: seconds since epoch is
    // converted manually to a civil date (valid for 1970-9999).
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    rfc3339_from_unix(secs)
}

/// Seconds since the epoch for a timestamp this crate produced.
///
/// Handles the shape [`now_rfc3339`] emits (`T` separator, `Z` suffix, no
/// offset, no fractional seconds) and rejects anything structurally different.
/// Zero-padding is not policed: the only timestamps fed to it are ones burrow
/// wrote.
pub fn unix_from_rfc3339(text: &str) -> Option<i64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let (year, month, day): (i64, i64, i64) = (
        date.next()?.parse().ok()?,
        date.next()?.parse().ok()?,
        date.next()?.parse().ok()?,
    );
    let mut time = time.split(':');
    let (hour, minute, second): (i64, i64, i64) = (
        time.next()?.parse().ok()?,
        time.next()?.parse().ok()?,
        time.next()?.parse().ok()?,
    );

    // Days since 1970-01-01, by the civil-from-days algorithm (Howard Hinnant).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// RFC 3339 UTC timestamp for an instant given in seconds since the epoch.
///
/// The inverse of [`unix_from_rfc3339`], for the timestamps burrow stores as
/// numbers and reports as text.
pub fn rfc3339_from_unix_secs(secs: i64) -> String {
    rfc3339_from_unix(secs.max(0) as u64)
}

/// Seconds since the epoch, now.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn rfc3339_from_unix(secs: u64) -> String {
    let days = secs / 86_400;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_prefixes() {
        assert!(NodeId::generate().as_str().starts_with("node_"));
        assert!(SandboxId::generate().as_str().starts_with("sbx_"));
        assert!(SnapshotId::generate().as_str().starts_with("snap_"));
    }

    #[test]
    fn civil_conversion_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn a_timestamp_survives_a_round_trip() {
        for secs in [0u64, 1, 86_399, 86_400, 1_700_000_000, 4_102_444_800] {
            let text = rfc3339_from_unix(secs);
            assert_eq!(
                unix_from_rfc3339(&text),
                Some(secs as i64),
                "round trip failed for {text}"
            );
        }
    }

    #[test]
    fn a_known_timestamp_parses_to_the_right_instant() {
        assert_eq!(
            unix_from_rfc3339("2026-08-27T04:31:14Z"),
            Some(1_787_805_074)
        );
    }

    #[test]
    fn a_leap_day_is_handled() {
        let text = "2024-02-29T12:00:00Z";
        let secs = unix_from_rfc3339(text).expect("leap day should parse");
        assert_eq!(rfc3339_from_unix(secs as u64), text);
    }

    #[test]
    fn anything_that_is_not_our_format_is_rejected() {
        for bad in [
            "",
            "not a date",
            "2026-08-27",
            "2026-08-27T04:31:14+01:00",
            "2026-08-27 04:31:14Z",
            "2026-08-27T04:31Z",
        ] {
            assert_eq!(unix_from_rfc3339(bad), None, "{bad:?} should not parse");
        }
    }
}
