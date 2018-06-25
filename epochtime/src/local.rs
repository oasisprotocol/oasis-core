//! Local epoch time implementation
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
#[allow(unused_imports)]
use ekiden_common::futures::{future, BoxFuture, BoxStream, Future, Stream};
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_di;
use interface::*;
use std::mem;
use std::sync::{Arc, Mutex};
use std::sync::{Once, ONCE_INIT};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};
use futures_timer::{Interval, TimerHandle};

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
#[derive(Clone, Debug, Default)]
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
            inner: Arc::new(Mutex::new(MockTimeSourceInner {
                waiting: false,
                epoch: 0,
                till: 0,
            })),
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

    /// Set the mock epoch.
    pub fn set_mock_epoch(&self, epoch: EpochTime) -> Result<()> {
        let mut inner = self.inner.lock()?;
        let till = inner.till;
        inner.set_mock_time_impl(epoch, till)
    }

    /// Check-And-Set for initially-paused mock time sources.
    pub fn was_waiting(&self) -> Result<(bool, u64)> {
        let mut inner = self.inner.lock()?;
        if inner.waiting {
            inner.waiting = false;
            Ok((true, inner.till))
        } else {
            Ok((false, inner.till))
        }
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
    waiting: bool,
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
        let now = self.time_source.get_epoch().unwrap().0;
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

/// LocalTime is an explict path for the controller to recover
/// specifc type information of DI injected variants of the time source.
#[derive(Clone)]
pub struct LocalTime {
    pub mock: Arc<Mutex<Arc<MockTimeSource>>>,
    pub notifier: Arc<Mutex<Arc<LocalTimeSourceNotifier>>>,
}

/// Get the system-used local time instance.
// Follows the singleton pattern from
// https://stackoverflow.com/questions/27791532/how-do-i-create-a-global-mutable-singleton
pub fn get_local_time() -> LocalTime {
    static mut LOCALTIME: *const LocalTime = 0 as *const LocalTime;
    static ONCE: Once = ONCE_INIT;
    unsafe {
        ONCE.call_once(|| {
            let mock = Arc::new(MockTimeSource::new());
            let notifier = Arc::new(LocalTimeSourceNotifier::new(mock.clone()));
            let singleton = LocalTime {
                mock: Arc::new(Mutex::new(mock)),
                notifier: Arc::new(Mutex::new(notifier)),
            };
            LOCALTIME = mem::transmute(Box::new(singleton));
        });
        (*LOCALTIME).clone()
    }
}

// Register for dependency injection.
create_component!(
    system,
    "time-source-notifier",
    LocalTimeSourceNotifier,
    TimeSourceNotifier,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        let source = Arc::new(SystemTimeSource::default());
        let notifier = Arc::new(LocalTimeSourceNotifier::new(source.clone()));
        let instance: Arc<TimeSourceNotifier> = notifier.clone();

        {
            let localtime = get_local_time();
            let mut globalnotifier = localtime.notifier.lock().unwrap();
            *globalnotifier = notifier.clone();
        }

        // drive instance.
        let (now, till) = source.get_epoch().unwrap();
        trace!("SystemTime: Epoch: {} Till: {}", now, till);

        // Note: This assumes that the underlying futures_timer
        // crate has relatively accurate time keeping, that the
        // host's idea of civil time is correct at startup, and
        // that timers are never early.
        //
        // This could be made more resilient to various
        // failures/misbehavior by periodically polling the
        // epoch (eg: once every 60s or so).

        let at = Instant::now() + Duration::from_secs(till);
        let dur = Duration::from_secs(EPOCH_INTERVAL);
        let timer = Interval::new_handle(at, dur, TimerHandle::default());

        environment.spawn({
            let source = source.clone();
            let notifier = notifier.clone();

            Box::new(
                timer
                    .map_err(|error| Error::from(error))
                    .for_each(move |_| {
                        let (now, till) = source.get_epoch().unwrap();
                        trace!("SystemTime: Epoch: {} Till: {}", now, till);
                        notifier.notify_subscribers()
                    })
                    .then(|_| future::ok(())),
            )
        });

        Ok(Box::new(instance))
    }),
    []
);

pub struct MockTimeRpcNotifier {}
create_component!(
    mockrpc,
    "time-source-notifier",
    MockTimeRpcNotifier,
    TimeSourceNotifier,
    (|container: &mut Container| -> Result<Box<Any>> {
        let source = Arc::new(MockTimeSource::new());

        let args = container.get_arguments().unwrap();

        let notifier = Arc::new(LocalTimeSourceNotifier::new(source.clone()));
        let instance: Arc<TimeSourceNotifier> = notifier.clone();

        {
            let localtime = get_local_time();
            let mut globalsource = localtime.mock.lock().unwrap();
            let mut globalnotifier = localtime.notifier.lock().unwrap();
            *globalsource = source.clone();
            *globalnotifier = notifier.clone();
        }

        // drive instance.
        source
            .set_mock_time(0, value_t_or_exit!(args, "mock-rpc-epoch-interval", u64))
            .map_err(|e| ekiden_di::error::Error::from(format!("{:?}", e)))?;
        let (now, till) = source.get_epoch().unwrap();
        trace!("MockTimeRPC: Epoch: {} Till: {}", now, till);

        // No timer, the entire operation is RPC dependent.

        Ok(Box::new(instance))
    }),
    [Arg::with_name("mock-rpc-epoch-interval")
        .long("mock-rpc-epoch-interval")
        .help("Mock time epoch interval in seconds.")
        .default_value("600")
        .takes_value(true)]
);

pub struct MockTimeNotifier {}
create_component!(
    mock,
    "time-source-notifier",
    MockTimeNotifier,
    TimeSourceNotifier,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;
        let source = Arc::new(MockTimeSource::new());

        let args = container.get_arguments().unwrap();
        let should_wait = args.is_present("time-rpc-wait");
        let epoch_interval = value_t_or_exit!(args, "mock-epoch-interval", u64);

        let notifier = Arc::new(LocalTimeSourceNotifier::new(source.clone()));
        let instance: Arc<TimeSourceNotifier> = notifier.clone();

        {
            let localtime = get_local_time();
            let mut globalsource = localtime.mock.lock().unwrap();
            let mut globalnotifier = localtime.notifier.lock().unwrap();
            *globalsource = source.clone();
            *globalnotifier = notifier.clone();
        }

        // drive instance.
        source
            .set_mock_time(0, epoch_interval)
            .map_err(|e| ekiden_di::error::Error::from(format!("{:?}", e)))?;
        let (now, till) = source.get_epoch().unwrap();
        trace!("MockTimeRPC: Epoch: {} Till: {}", now, till);

        if should_wait {
            trace!("MockTime: Epoch: {} Till: {} (-> Wait)", now, till);
            source.inner.lock().unwrap().waiting = true;
        } else {
            trace!("MockTime: Epoch: {} Till: {}", now, till);
            let dur = Duration::from_secs(epoch_interval);
            environment.spawn({
                let time_source = source.clone();
                let time_notifier = notifier.clone();

                Box::new(
                    Interval::new(dur)
                        .map_err(|error| Error::from(error))
                        .for_each(move |_| {
                            let (now, till) = time_source.get_epoch().unwrap();
                            trace!("MockTime: Epoch: {} Till: {}", now + 1, till);
                            time_source.set_mock_time(now + 1, till)?;
                            time_notifier.notify_subscribers()
                        })
                        .then(|_| future::ok(())),
                )
            });
        }

        Ok(Box::new(instance))
    }),
    [
        Arg::with_name("mock-epoch-interval")
            .long("mock-epoch-interval")
            .help("Mock time epoch interval in seconds.")
            .default_value("600")
            .takes_value(true),
        Arg::with_name("time-rpc-wait")
            .long("time-rpc-wait")
            .help("Wait on an RPC call before starting MockTime timer.")
    ]
);
