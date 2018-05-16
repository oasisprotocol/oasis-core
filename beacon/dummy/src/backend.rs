use std::sync::{Arc, Mutex};

use byteorder::{LittleEndian, WriteBytesExt};
use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::B256;
use ekiden_common::epochtime::{EpochTime, TimeSourceNotifier, EKIDEN_EPOCH_INVALID};
use ekiden_common::futures::{future, BoxFuture, BoxStream, Executor, Future, Stream};
use ekiden_common::ring::digest;
use ekiden_common::subscribers::StreamSubscribers;

const DUMMY_BEACON_CONTEXT: &'static [u8] = b"EkB-Dumm";

/// Dummy RandomBeacon implementation.
///
/// WARNING: As the name suggests, this implementation is intended for testing
/// purposes and is INSECURE due to the returned values being entirely
/// deterministic.
pub struct InsecureDummyRandomBeacon {
    inner: Arc<Mutex<InsecureDummyRandomBeaconInner>>,
}

impl InsecureDummyRandomBeacon {
    /// Create a new dummy random beacon.
    pub fn new(time_notifier: Arc<TimeSourceNotifier>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InsecureDummyRandomBeaconInner {
                subscribers: StreamSubscribers::new(),
                time_notifier: time_notifier,
                last_notify: EKIDEN_EPOCH_INVALID,
                cached_beacon: B256::zero(),
            })),
        }
    }
}

impl RandomBeacon for InsecureDummyRandomBeacon {
    fn start(&self, executor: &mut Executor) {
        // Subscribe to the time source.
        executor.spawn({
            let shared_inner = self.inner.clone();
            let inner = self.inner.lock().unwrap();

            Box::new(
                inner
                    .time_notifier
                    .watch_epochs()
                    .for_each(move |now| {
                        let mut inner = shared_inner.lock().unwrap();

                        // Acquire the beacon value for the new epoch.
                        let beacon = inner.get_beacon_impl(now);

                        // Cache the epoch/beacon that was last batch notified.
                        inner.last_notify = now;
                        inner.cached_beacon = beacon;

                        // Batch notify to all current subscribers.
                        let to_send = (now, beacon);
                        inner.subscribers.notify(&to_send);

                        Ok(())
                    })
                    .then(|_| future::ok(())),
            )
        });
    }

    fn get_beacon(&self, epoch: EpochTime) -> BoxFuture<B256> {
        let inner = self.inner.lock().unwrap();
        Box::new(future::ok(inner.get_beacon_impl(epoch)))
    }

    fn watch_beacons(&self) -> BoxStream<(EpochTime, B256)> {
        let (streamrecv, initialpoll) = {
            let locked_inner = self.inner.lock().unwrap();
            let (send, recv) = locked_inner.subscribers.subscribe();

            // explicit fetch of current epoch to catch up the new subscriber.
            let inner = self.inner.clone();
            let pre_notify_time = locked_inner.last_notify;

            (
                recv,
                locked_inner
                    .time_notifier
                    .get_epoch()
                    .and_then(move |epoch| {
                        let inner = inner.lock().unwrap();
                        if epoch == pre_notify_time {
                            send.unbounded_send((epoch, inner.cached_beacon)).unwrap();
                        }
                        future::ok(())
                    }),
            )
        };
        // TODO: should this be given to an executor?
        let _r = initialpoll.wait();

        streamrecv
    }
}

struct InsecureDummyRandomBeaconInner {
    subscribers: StreamSubscribers<(EpochTime, B256)>,
    time_notifier: Arc<TimeSourceNotifier>,
    last_notify: EpochTime,
    cached_beacon: B256,
}

impl InsecureDummyRandomBeaconInner {
    fn get_beacon_impl(&self, epoch: EpochTime) -> B256 {
        // Simulate a per-epoch shared random beacon value with
        // `SHA512_256("EkB-Dumm" | to_le_64(epoch))` as it is a reasonable
        // approximation of a well behaved random beacon, just without the
        // randomness.
        let mut seed = Vec::with_capacity(DUMMY_BEACON_CONTEXT.len() + 8);
        seed.extend_from_slice(DUMMY_BEACON_CONTEXT);
        seed.write_u64::<LittleEndian>(epoch).unwrap();

        B256::from(digest::digest(&digest::SHA512_256, &seed).as_ref())
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_hex;

    use self::rustc_hex::ToHex;
    use super::*;
    use ekiden_common::epochtime::EPOCH_INTERVAL;
    use ekiden_common::epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
    use ekiden_common::futures::{cpupool, Future};

    #[test]
    fn test_insecure_dummy_random_beacon() {
        // Known values generated with a Go implementation.
        const BEACON_0: &str = "0c2d4edf3c57c2071f8856d1f74cb126455c2df949a2e3638509b20f8bd5e85d";
        const BEACON_FAR_FUTURE: &str =
            "36ae91d1c4c40e52bcaa86f5cbb8fe514f36e5165c721b18f5feabc25fb0aa84";
        const FAR_FUTURE: u64 = 0xcafebabedeadbeef;

        let time_source = Arc::new(MockTimeSource::new());
        let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));
        let beacon = InsecureDummyRandomBeacon::new(time_notifier.clone());

        // Trivial known answer tests, generated with a Go implementation of
        // the same algorithm.
        let v = &(beacon.get_beacon(0).wait()).unwrap();
        assert_eq!((*v).to_hex(), BEACON_0);

        let v = &(beacon.get_beacon(FAR_FUTURE).wait()).unwrap();
        assert_eq!((*v).to_hex(), BEACON_FAR_FUTURE);

        // Test the async event source.
        let mut pool = cpupool::CpuPool::new(1);
        beacon.start(&mut pool);

        // Subscribe to the beacon.
        let get_beacons = beacon
            .watch_beacons()
            .take(2)
            .for_each(move |(epoch, value)| {
                println!("epoch: {}", epoch);
                match epoch {
                    0 => assert_eq!(value.to_hex(), BEACON_0),
                    FAR_FUTURE => assert_eq!(value.to_hex(), BEACON_FAR_FUTURE),
                    _ => panic!("incorrect epoch: {}", epoch),
                }
                Ok(())
            });

        // Manually force progression of time.
        time_source.set_mock_time(0, EPOCH_INTERVAL).unwrap();
        time_notifier.notify_subscribers().unwrap();
        time_source
            .set_mock_time(FAR_FUTURE, EPOCH_INTERVAL)
            .unwrap();
        time_notifier.notify_subscribers().unwrap();

        // Consume all the notifications.
        get_beacons.wait().unwrap();
    }
}
