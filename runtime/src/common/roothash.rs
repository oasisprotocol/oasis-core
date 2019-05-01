//! Roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/block.
//!
use serde_derive::{Deserialize, Serialize};

use super::crypto::{hash::Hash, signature::SignatureBundle};

/// Block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    /// Header.
    pub header: Header,
}

impl_bytes!(Namespace, 32, "Chain namespace.");

/// Block header.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Header {
    /// Protocol version number.
    pub version: u16,
    /// Chain namespace.
    pub namespace: Namespace,
    /// Round number.
    pub round: u64,
    /// Timestamp (POSIX time).
    pub timestamp: u64,
    /// Header type.
    pub header_type: u8,
    /// Previous block hash.
    pub previous_hash: Hash,
    /// Computation group hash.
    pub group_hash: Hash,
    /// Input hash.
    pub input_hash: Hash,
    /// Output hash.
    pub output_hash: Hash,
    /// Tag hash.
    pub tag_hash: Hash,
    /// State root hash.
    pub state_root: Hash,
    /// Commitments hash.
    pub commitments_hash: Hash,
    /// Storage receipt.
    pub storage_receipt: SignatureBundle,
}
