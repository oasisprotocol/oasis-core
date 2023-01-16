//! Scheduler structures.

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
