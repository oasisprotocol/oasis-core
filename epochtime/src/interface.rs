//! Epoch time interface.

use chrono::{DateTime, Utc};
use ekiden_common::error::Result;
use ekiden_common::futures::{BoxFuture, BoxStream};

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

/// A subscription for learning of new epochs.
pub trait TimeSourceNotifier: Send + Sync {
    /// Return the current epoch.
    fn get_epoch(&self) -> BoxFuture<EpochTime>;

    /// Receive a stream of messages alerting the transition to new epochs as they occur.
    fn watch_epochs(&self) -> BoxStream<EpochTime>;
}
