//! Reduced set of roothash structures.
use serde_derive::{Deserialize, Serialize};

use super::crypto::hash::Hash;

/// Block.
///
/// # Note
///
/// This is a reduced roothash block as used within the runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    /// Header.
    pub header: Header,
}

/// Block header.
///
/// # Note
///
/// This is a reduced roothash block header as used within the runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Header {
    /// Round number.
    pub round: u64,
    /// Timestamp (POSIX time).
    pub timestamp: u64,
    /// State root hash.
    pub state_root: Hash,
}
