//! Scheduler structures.

/// The role a given node plays in a committee.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum Role {
    /// An invalid role (should never appear on the wire).
    Invalid = 0,
    /// Indicates the node is a worker.
    Worker = 1,
    /// Indicates the node is a backup worker.
    BackupWorker = 2,
}

impl Default for Role {
    fn default() -> Self {
        Role::Invalid
    }
}

/// The functionality a committee exists to provide.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum CommitteeKind {
    /// An invalid committee (should never appear on the wire).
    Invalid = 0,
    /// A compute executor committee.
    ComputeExecutor = 1,
}

impl Default for CommitteeKind {
    fn default() -> Self {
        CommitteeKind::Invalid
    }
}
