//! Runtime time source.
use std::{
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lazy_static::lazy_static;
use slog::error;

use crate::common::logger::get_logger;

const INITIAL_MINIMUM_TIME: i64 = 1659312000; // Mon, 01 Aug 2022 00:00:00 UTC

struct TimeSource {
    inner: Mutex<Inner>,
}

struct Inner {
    timestamp: i64,
}

/// Returns the number of seconds since the UNIX epoch.  The time returned
/// is guaranteed to never decrease within each enclave instance (though it
/// may decrease iff the enclave is re-launched).
///
/// The returned timestamp MUST NOT be trusted on in any way, as the underlying
/// time source is reliant on the host operating system.
pub fn insecure_posix_time() -> i64 {
    let mut inner = TIME_SOURCE.inner.lock().unwrap();

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let now = now.as_secs() as i64;

    if now < inner.timestamp {
        error!(
            get_logger("runtime/time"),
            "clock appeared to have ran backwards"
        );
        panic!("time: clock appeared to have ran backwards")
    }
    inner.timestamp = now;

    inner.timestamp
}

// Returns `insecure_posix_time` as SystemTime.
pub fn insecure_posix_system_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(insecure_posix_time() as u64)
}

/// Force update the minimum timestamp from a semi-trusted source (eg: the AVR
/// timestamp), under the assumption that the semi-trusted source is more trust
/// worthy than the host operating system.
pub(crate) fn update_insecure_posix_time(timestamp: i64) {
    let mut inner = TIME_SOURCE.inner.lock().unwrap();

    if timestamp > inner.timestamp {
        inner.timestamp = timestamp;
    }

    // The IAS clock and local clock should be closely synced, and minor
    // differences in NTP implementations (eg: smear vs no smear), should
    // be masked by the fact that the AVR timestamp will be a minimum of
    // 1 RTT in the past.
}

lazy_static! {
    static ref TIME_SOURCE: TimeSource = TimeSource {
        inner: Mutex::new(Inner {
            timestamp: INITIAL_MINIMUM_TIME,
        })
    };
}
