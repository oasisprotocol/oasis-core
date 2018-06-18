//! Random beacon interface.

use ekiden_common::bytes::B256;
use ekiden_common::futures::{BoxFuture, BoxStream, Executor};
use ekiden_epochtime::interface::EpochTime;

/// Random Beacon backend implementing the Ekiden random beacon interface.
pub trait RandomBeacon: Send + Sync {
    /// Start the async event source associated with the beacon.
    fn start(&self, executor: &mut Executor);

    /// Queries the random beacon implementation for the specified epoch's
    /// value.  Output will not be returned for epochs in the future.
    fn get_beacon(&self, epoch: EpochTime) -> BoxFuture<B256>;

    /// Subscribe to updates of random beacon generation.  Upon subscription
    /// the beacon value for the current epoch will be sent immediately if
    /// available.
    fn watch_beacons(&self) -> BoxStream<(EpochTime, B256)>;

    /// Provide the ethereum block at which an epoch occured.
    /// This will fail if an ethereum-backed beacon is not in use.
    fn get_block_for_epoch(&self, _epoch: EpochTime) -> Option<u64> {
        unimplemented!();
    }
}
