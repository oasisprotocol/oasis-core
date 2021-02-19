//! Scheduler structures.
use serde_repr::{Deserialize_repr, Serialize_repr};

/// The role a given node plays in a committee.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Role {
    /// An invalid role (should never appear on the wire).
    #[serde(rename = "invalid")]
    Invalid = 0,
    /// Indicates the node is a worker.
    #[serde(rename = "worker")]
    Worker = 1,
    /// Indicates the node is a backup worker.
    #[serde(rename = "backup-worker")]
    BackupWorker = 2,
}

impl Default for Role {
    fn default() -> Self {
        Role::Invalid
    }
}

/// The functionality a committee exists to provide.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CommitteeKind {
    /// An invalid committee (should never appear on the wire).
    #[serde(rename = "invalid")]
    Invalid = 0,
    /// A compute executor committee.
    #[serde(rename = "executor")]
    ComputeExecutor = 1,
    /// A storage committee.
    #[serde(rename = "storage")]
    Storage = 2,
}

impl Default for CommitteeKind {
    fn default() -> Self {
        CommitteeKind::Invalid
    }
}
