//! Scheduler interface.
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::epochtime::EpochTime;
use ekiden_common::futures::BoxFuture;

/// The role a given Node plays in a committee.
pub enum Role {
    Worker,
    Leader,
}

/// A node participating in a committee.
pub struct CommitteeNode {
    pub role: Role,
    pub public_key: B256,
}

/// The functionality a committee exists to provide.
pub enum CommitteeType {
    Compute,
    Storage,
}

/// A per-contract (per-contract instance) committee instance.
pub struct Committee {
    pub kind: CommitteeType,
    pub members: Vec<CommitteeNode>,
    pub contract: Arc<Contract>,
    pub valid_for: EpochTime,
}

/// Scheduler backend implementing the Ekiden scheduler interface.
pub trait Scheduler {
    /// Return a vector of the committees for a given contract invocation,
    /// for the current epoch.
    fn get_committees(&self, contract: Arc<Contract>) -> BoxFuture<Vec<Committee>>;
}
