use std::sync::{Arc, Mutex};

use super::*;
use super::super::error::{Error, Result};
use super::super::futures::{future, BoxFuture, BoxStream};
use super::super::subscribers::StreamSubscribers;

use chrono::{DateTime, TimeZone, Utc};

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
pub struct LocalTimeSourceNotifier {
    inner: Arc<Mutex<TimeSourceNotifierInner>>,
    subscribers: StreamSubscribers<EpochTime>,
    time_source: Arc<TimeSource>,
}

impl LocalTimeSourceNotifier {
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

    /// Notify subscribers of an epoch transition.  The owner of the object
    /// is responsible for driving notifications, perhaps by calling this
    /// routine from a timer or something.
    pub fn notify_subscribers(&self) -> Result<()> {
        // Update the state, release the lock, then notify.
        let now: Result<EpochTime> = {
            let mut inner = self.inner.lock()?;

            let (now, _) = self.time_source.get_epoch()?;

            // Iff at least one notification has been sent, do some sanity
            // checking to ensure a linear passage of time.  The first
            // notification is exempt so this can play nice with the "send
            // current epoch on subscribe" semantics.
            if inner.last_notify != EKIDEN_EPOCH_INVALID {
                // Ensure that the epoch is increasing.
                if inner.last_notify >= now {
                    return Err(Error::new("Epoch did not advance between notify calls"));
                }

                // This used to assert that the notify call happened around
                // the epoch transition based on the "till" value, but
                // the "correct" value here is dependent on the epoch
                // duration, which is not guaranteed to be EPOCH_INTERVAL.
            }

            inner.last_notify = now;
            Ok(now)
        };
        self.subscribers.notify(&(now?));
        Ok(())
    }
}

impl TimeSourceNotifier for LocalTimeSourceNotifier {
    fn get_epoch(&self) -> BoxFuture<EpochTime> {
        match self.time_source.get_epoch() {
            Ok((epoch, _)) => Box::new(future::ok(epoch)),
            Err(e) => Box::new(future::err(e)),
        }
    }

    /// Subscribe to updates of epoch transitions.  Upon subscription, the
    /// current epoch will be sent immediately.
    fn watch_epochs(&self) -> BoxStream<EpochTime> {
        let inner = self.inner.lock().unwrap();
        let (send, recv) = self.subscribers.subscribe();

        // Iff the notifications for the current epoch went out already,
        // send the current epoch to the subscriber.
        let now = self.time_source.get_epoch().unwrap().1;
        if now == inner.last_notify {
            trace!("watch_epochs(): Catch up: Epoch: {}", now);
            send.unbounded_send(now).unwrap();
        }

        recv
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
