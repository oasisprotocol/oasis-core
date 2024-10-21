//! Scheduler structures.
use anyhow::{anyhow, Result};

use crate::{
    common::{crypto::signature::PublicKey, namespace::Namespace},
    consensus::beacon::EpochTime,
};

/// The role a given node plays in a committee.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode,
)]
#[repr(u8)]
pub enum Role {
    /// An invalid role (should never appear on the wire).
    #[default]
    Invalid = 0,
    /// Indicates the node is a worker.
    Worker = 1,
    /// Indicates the node is a backup worker.
    BackupWorker = 2,
}

/// A node participating in a committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct CommitteeNode {
    /// The node's role in a committee.
    pub role: Role,

    /// The node's public key.
    pub public_key: PublicKey,
}

/// The functionality a committee exists to provide.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode,
)]
#[repr(u8)]
pub enum CommitteeKind {
    /// An invalid committee (should never appear on the wire).
    #[default]
    Invalid = 0,
    /// A compute executor committee.
    ComputeExecutor = 1,
}

/// A per-runtime (instance) committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct Committee {
    /// The functionality a committee exists to provide.
    pub kind: CommitteeKind,

    /// The committee members.
    pub members: Vec<CommitteeNode>,

    /// The runtime ID that this committee is for.
    pub runtime_id: Namespace,

    /// The epoch for which the committee is valid.
    pub valid_for: EpochTime,
}

impl Committee {
    /// Returns committee nodes with Worker role.
    pub fn workers(&self) -> Vec<&CommitteeNode> {
        self.members
            .iter()
            .filter(|&member| member.role == Role::Worker)
            .collect()
    }

    /// Returns the transaction scheduler of the provided committee based on the provided round.
    pub fn transaction_scheduler(&self, round: u64) -> Result<&CommitteeNode> {
        let workers = self.workers();
        if workers.is_empty() {
            return Err(anyhow!("GetTransactionScheduler: no workers in committee"));
        }
        let scheduler_idx = round as usize % workers.len();
        let scheduler = workers[scheduler_idx];

        Ok(scheduler)
    }
}
