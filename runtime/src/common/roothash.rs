//! Roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/block.
//!
use serde_derive::{Deserialize, Serialize};

use super::crypto::{hash::Hash, signature::SignatureBundle};

/// The key holding inputs in the I/O tree.
pub const IO_KEY_INPUTS: &'static [u8] = b"i";
/// The key holding outputs in the I/O tree.
pub const IO_KEY_OUTPUTS: &'static [u8] = b"o";
/// The key holding tags in the I/O tree.
pub const IO_KEY_TAGS: &'static [u8] = b"t";

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
    /// I/O merkle root.
    pub io_root: Hash,
    /// State merkle root.
    pub state_root: Hash,
    /// Commitments hash.
    pub commitments_hash: Hash,
    /// Storage receipt.
    pub storage_receipt: SignatureBundle,
}
