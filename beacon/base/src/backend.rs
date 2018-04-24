//! Random beacon interface.

use ekiden_common::bytes::B256;
use ekiden_common::epochtime::EpochTime;
use ekiden_common::futures::BoxFuture;

/// Random Beacon backend implementing the Ekiden random beacon interface.
pub trait RandomBeacon {
    /// Queries the random beacon implementation for the specified epoch's
    /// value.  Output will not be returned for epochs in the future.
    fn get_beacon(&self, epoch: EpochTime) -> BoxFuture<B256>;
}
