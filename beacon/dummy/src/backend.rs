use std::sync::{Arc, Mutex};

use byteorder::{LittleEndian, WriteBytesExt};
use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::sync::mpsc;
use ekiden_common::futures::{future, BoxFuture, BoxStream, Executor, Future, Stream, StreamExt};
use ekiden_common::ring::digest;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_epochtime::interface::{EpochTime, TimeSourceNotifier, EKIDEN_EPOCH_INVALID};

const DUMMY_BEACON_CONTEXT: &'static [u8] = b"EkB-Dumm";

/// Commands for communicating synchronization requests to the beacon
enum Command {
    /// Notify a sender of an initial epoch if needed.
    Catchup((mpsc::UnboundedSender<(EpochTime, B256)>, EpochTime)),
}

/// Dummy RandomBeacon implementation.
///
/// WARNING: As the name suggests, this implementation is intended for testing
/// purposes and is INSECURE due to the returned values being entirely
/// deterministic.
pub struct InsecureDummyRandomBeacon {
    inner: Arc<InsecureDummyRandomBeaconInner>,
}

impl InsecureDummyRandomBeacon {
    /// Create a new dummy random beacon.
    pub fn new(time_notifier: Arc<TimeSourceNotifier>) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();

        Self {
            inner: Arc::new(InsecureDummyRandomBeaconInner {
                subscribers: StreamSubscribers::new(),
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                time_notifier: time_notifier,
                last_notify: Mutex::new((EKIDEN_EPOCH_INVALID, B256::zero())),
            }),
        }
    }
}

impl RandomBeacon for InsecureDummyRandomBeacon {
    fn start(&self, executor: &mut Executor) {
        // Subscribe to the time source.
        executor.spawn({
            let shared_inner = self.inner.clone();

            Box::new(
                self.inner
                    .time_notifier
                    .watch_epochs()
                    .for_each(move |now| {
                        let mut notification = shared_inner.last_notify.lock().unwrap();

                        // Acquire the beacon value for the new epoch.
                        let beacon = shared_inner.get_beacon_impl(now);

                        // Cache the epoch/beacon that was last batch notified.
                        notification.0 = now;
                        notification.1 = beacon;

                        trace!("Epoch: {} Beacon: {:?}", now, beacon);

                        // Batch notify to all current subscribers.
                        let to_send = (now, beacon);
                        shared_inner.subscribers.notify(&to_send);

                        Ok(())
                    })
                    .then(|_| future::ok(())),
            )
        });
        let inner = self.inner.clone();

        executor.spawn({
            let command_receiver = inner
                .command_receiver
                .lock()
                .unwrap()
                .take()
                .expect("start already called");
            let notifier = inner.time_notifier.clone();

            command_receiver
                .map_err(|_| Error::new("command channel closed"))
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error catching up beacon subscriber",
                    move |command| match command {
                        Command::Catchup((sender, pre_notify_time)) => {
                            let inner = inner.clone();
                            notifier.get_epoch().and_then(move |epoch| {
                                let notification = inner.last_notify.lock().unwrap();
                                if epoch == pre_notify_time {
                                    trace!(
                                        "Command::Catchup(): Catch up: Epoch: {} Beacon: {:?}",
                                        epoch,
                                        notification.1
                                    );
                                    sender.unbounded_send((epoch, notification.1)).unwrap();
                                }
                                future::ok(())
                            })
                        }
                    },
                )
        });
    }

    fn get_beacon(&self, epoch: EpochTime) -> BoxFuture<B256> {
        Box::new(future::ok(self.inner.get_beacon_impl(epoch)))
    }

    fn watch_beacons(&self) -> BoxStream<(EpochTime, B256)> {
        let (send, recv) = self.inner.subscribers.subscribe();

        // add the task for maybe catching up the new subscriber to the queue.
        let inner = self.inner.clone();
        let notify = inner.last_notify.lock().unwrap();
        let pre_notify_time = notify.0;
        self.inner
            .command_sender
            .unbounded_send(Command::Catchup((send, pre_notify_time)))
            .unwrap();

        recv
    }
}

struct InsecureDummyRandomBeaconInner {
    subscribers: StreamSubscribers<(EpochTime, B256)>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    time_notifier: Arc<TimeSourceNotifier>,
    last_notify: Mutex<(EpochTime, B256)>,
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

// Register for dependency injection.
create_component!(
    dummy,
    "random-beacon-backend",
    InsecureDummyRandomBeacon,
    RandomBeacon,
    [TimeSourceNotifier]
);

#[cfg(test)]
mod tests {
    extern crate rustc_hex;

    use self::rustc_hex::ToHex;
    use super::*;
    use ekiden_common::epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
    use ekiden_common::epochtime::EPOCH_INTERVAL;
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
