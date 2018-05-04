//! Epoch time interface.

use super::error::{Error, Result};
use chrono::{DateTime, TimeZone, Utc};

/// The number of intervals (epochs) since a fixed instant in time (epoch date).
pub type EpochTime = u64;

/// The epoch base time, as the number of seconds since the UNIX epoch (time_t).
pub const EKIDEN_EPOCH: u64 = 1514764800; // 2018-01-01T00:00:00+00:00

/// The epoch interval in seconds.
pub const EPOCH_INTERVAL: u64 = 86400; // 1 day

/// A time source that provides epoch time.
pub trait TimeSource: Send + Sync {
    /// Returns a tuple consisting of the current epoch, and the number of
    /// seconds since the begining of the current epoch.
    fn get_epoch(&self) -> Result<(EpochTime, u64)>;

    /// Returns a tuple consisting of the epoch corresponding to an arbitrary
    /// civil time, and the number of seconds since the begining of that epoch.
    fn get_epoch_at(&self, at: &DateTime<Utc>) -> Result<(EpochTime, u64)>;
}

/// A system time based TimeSource.
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn get_epoch(&self) -> Result<(EpochTime, u64)> {
        let now = Utc::now();
        self.get_epoch_at(&now)
    }

    fn get_epoch_at(&self, at: &DateTime<Utc>) -> Result<(EpochTime, u64)> {
        let epoch_base = Utc.timestamp(EKIDEN_EPOCH as i64, 0);
        let at = at.signed_duration_since(epoch_base).num_seconds();
        if at < 0 {
            return Err(Error::new("Current system time predates EKIDEN_EPOCH"));
        }
        let epoch = (at as u64) / EPOCH_INTERVAL;
        let since = (at as u64) % EPOCH_INTERVAL;
        Ok((epoch, since))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_ekiden_epoch() {
        let dt = DateTime::parse_from_rfc3339("2018-01-01T00:00:00+00:00").unwrap();
        let dt = dt.with_timezone(&Utc);

        // Ensure that EKIDEN_EPOCH is sensible, and in fact, represents the
        // instant in time that it should, relative to the UNIX epoch.
        let ekiden_epoch = Utc.timestamp(EKIDEN_EPOCH as i64, 0);
        assert!(dt == ekiden_epoch);

        // EpochTime for the epoch should be 0.
        let ts = SystemTimeSource {};
        let (epoch, since) = ts.get_epoch_at(&dt).unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(since, 0);

        // Ensure the epoch transitions when expected, and increments.
        let dt = DateTime::parse_from_rfc3339("2018-01-01T23:59:59+00:00").unwrap();
        let dt = dt.with_timezone(&Utc);
        let (epoch, since) = ts.get_epoch_at(&dt).unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(since, EPOCH_INTERVAL - 1);

        let dt = DateTime::parse_from_rfc3339("2018-01-02T00:00:00+00:00").unwrap();
        let dt = dt.with_timezone(&Utc);
        let (epoch, since) = ts.get_epoch_at(&dt).unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(since, 0);

        // Forbid epochs that pre-date the base.
        let dt = DateTime::parse_from_rfc3339("1997-08-29T02:14:00-04:00").unwrap();
        let dt = dt.with_timezone(&Utc);
        assert!(ts.get_epoch_at(&dt).is_err());
    }

    #[test]
    fn test_get_epoch() {
        let ts = SystemTimeSource {};

        // Might race, unlikely.
        let now = Utc::now();
        let now_get_epoch = ts.get_epoch().unwrap();
        let now_epoch_at = ts.get_epoch_at(&now).unwrap();
        assert!(now_get_epoch == now_epoch_at);
    }
}
