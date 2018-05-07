//! Epoch time interface.
use std::sync::{Arc, Mutex};

use super::error::{Error, Result};
use super::futures::BoxStream;
use chrono::{DateTime, TimeZone, Utc};
use subscribers::StreamSubscribers;

/// The number of intervals (epochs) since a fixed instant in time (epoch date).
pub type EpochTime = u64;

/// The epoch base time, as the number of seconds since the UNIX epoch (time_t).
pub const EKIDEN_EPOCH: u64 = 1514764800; // 2018-01-01T00:00:00+00:00

/// The epoch interval in seconds.
pub const EPOCH_INTERVAL: u64 = 86400; // 1 day

/// The placeholder invalid epoch.
pub const EKIDEN_EPOCH_INVALID: u64 = 0xffffffffffffffff; // ~50 quadrillion years away.

/// A time source that provides epoch time.
pub trait TimeSource: Send + Sync {
    /// Returns a tuple consisting of the current epoch, and the number of
    /// seconds since the begining of the current epoch.
    fn get_epoch(&self) -> Result<(EpochTime, u64)>;

    /// Returns a tuple consisting of the epoch corresponding to an arbitrary
    /// civil time, and the number of seconds since the begining of that epoch.
    fn get_epoch_at(&self, at: &DateTime<Utc>) -> Result<(EpochTime, u64)>;
}

fn get_epoch_at_generic(at: &DateTime<Utc>) -> Result<(EpochTime, u64)> {
    let epoch_base = Utc.timestamp(EKIDEN_EPOCH as i64, 0);
    let at = at.signed_duration_since(epoch_base).num_seconds();
    if at < 0 {
        return Err(Error::new("Current system time predates EKIDEN_EPOCH"));
    }
    let epoch = (at as u64) / EPOCH_INTERVAL;
    let since = (at as u64) % EPOCH_INTERVAL;
    Ok((epoch, since))
}

/// A system time based TimeSource.
#[derive(Clone, Debug)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn get_epoch(&self) -> Result<(EpochTime, u64)> {
        let now = Utc::now();
        self.get_epoch_at(&now)
    }

    fn get_epoch_at(&self, at: &DateTime<Utc>) -> Result<(EpochTime, u64)> {
        get_epoch_at_generic(at)
    }
}

/// A mock TimeSource.
pub struct MockTimeSource {
    inner: Arc<Mutex<MockTimeSourceInner>>,
}

impl MockTimeSource {
    /// Create a new MockTimeSource at the start of epoch 0.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockTimeSourceInner { epoch: 0, till: 0 })),
        }
    }

    /// Set the mock epoch, and offset based off a UTC DateTime.
    pub fn set_mock_time_utc(&self, at: &DateTime<Utc>) -> Result<()> {
        let (epoch, till) = get_epoch_at_generic(at)?;
        let mut inner = self.inner.lock()?;
        inner.set_mock_time_impl(epoch, till)
    }

    /// Set the mock epoch and offset.
    pub fn set_mock_time(&self, epoch: EpochTime, till: u64) -> Result<()> {
        let mut inner = self.inner.lock()?;
        inner.set_mock_time_impl(epoch, till)
    }
}

impl TimeSource for MockTimeSource {
    fn get_epoch(&self) -> Result<(EpochTime, u64)> {
        let inner = self.inner.lock()?;
        Ok((inner.epoch, inner.till))
    }

    fn get_epoch_at(&self, at: &DateTime<Utc>) -> Result<(EpochTime, u64)> {
        get_epoch_at_generic(at)
    }
}

struct MockTimeSourceInner {
    epoch: EpochTime,
    till: u64,
}

impl MockTimeSourceInner {
    pub fn set_mock_time_impl(&mut self, epoch: EpochTime, till: u64) -> Result<()> {
        if till > EPOCH_INTERVAL {
            return Err(Error::new("Till value out of range"));
        }
        self.epoch = epoch;
        self.till = till;
        Ok(())
    }
}

/// A TimeSource based epoch transition event source.
pub struct TimeSourceNotifier {
    inner: Arc<Mutex<TimeSourceNotifierInner>>,
    subscribers: StreamSubscribers<EpochTime>,
    time_source: Arc<TimeSource>,
}

impl TimeSourceNotifier {
    /// Create a new TimeSourceNotifier.
    pub fn new(time_source: Arc<TimeSource>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TimeSourceNotifierInner {
                last_notify: EKIDEN_EPOCH_INVALID,
            })),
            subscribers: StreamSubscribers::new(),
            time_source: time_source,
        }
    }

    /// Return a reference to the underlying time source.
    pub fn time_source(&self) -> Arc<TimeSource> {
        self.time_source.clone()
    }

    /// Subscribe to updates of epoch transitions.  Upon subscription, the
    /// current epoch will be sent immediately.
    pub fn watch_epochs(&self) -> BoxStream<EpochTime> {
        let inner = self.inner.lock().unwrap();
        let (send, recv) = self.subscribers.subscribe();

        // Iff the notifications for the current epoch went out already,
        // send the current epoch to the subscriber.
        let now = self.time_source.get_epoch().unwrap().1;
        if now == inner.last_notify {
            send.unbounded_send(now).unwrap();
        }

        recv
    }

    /// Notify subscribers of an epoch transition.  The owner of the object
    /// is responsible for driving notifications, perhaps by calling this
    /// routine from a timer or something.
    pub fn notify_subscribers(&self) -> Result<()> {
        const NOTIFY_SLACK: u64 = 5; // 5 seconds of slack.

        // Update the state, release the lock, then notify.
        let now: Result<EpochTime> = {
            let mut inner = self.inner.lock()?;

            let (now, till) = self.time_source.get_epoch()?;

            // Ensure that the epoch is increasing.
            if inner.last_notify != EKIDEN_EPOCH_INVALID && inner.last_notify >= now {
                return Err(Error::new("Epoch did not advance between notify calls"));
            }

            // Ensure that it is approximately the start of the epoch.
            if till < EPOCH_INTERVAL - NOTIFY_SLACK {
                return Err(Error::new("Not called at approximate start of epoch"));
            }

            inner.last_notify = now;
            Ok(now)
        };
        self.subscribers.notify(&(now?));
        Ok(())
    }
}

struct TimeSourceNotifierInner {
    last_notify: EpochTime,
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
