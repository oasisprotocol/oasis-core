//! Scheduler interface.
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::epochtime::EpochTime;
use ekiden_common::futures::{BoxFuture, BoxStream, Executor};

/// The role a given Node plays in a committee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Worker node.
    Worker,
    /// Group leader.
    Leader,
}

/// A node participating in a committee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeNode {
    /// Node role.
    pub role: Role,
    /// Node public key.
    pub public_key: B256,
}

/// The functionality a committee exists to provide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitteeType {
    Compute,
    Storage,
}

/// A per-contract (per-contract instance) committee instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committee {
    pub kind: CommitteeType,
    pub members: Vec<CommitteeNode>,
    pub contract: Arc<Contract>,
    pub valid_for: EpochTime,
}

/// Scheduler backend implementing the Ekiden scheduler interface.
pub trait Scheduler: Send + Sync {
    /// Start the async event source associated with the scheduler.
    fn start(&self, executor: &mut Executor);

    /// Return a vector of the committees for a given contract invocation,
    /// for the current epoch.
    fn get_committees(&self, contract: Arc<Contract>) -> BoxFuture<Vec<Committee>>;

    /// Subscribe to all comittee generation updates.  Upon subscription
    /// all committees for the current epoch will be send immediately.
    fn watch_committees(&self) -> BoxStream<Committee>;
}
