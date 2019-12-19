//! Roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/block.
//!
use serde_derive::{Deserialize, Serialize};

use super::{
    cbor,
    crypto::{hash::Hash, signature::SignatureBundle},
};

/// Runtime block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    /// Header.
    pub header: Header,
}

/// Runtime block annotated with consensus information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnnotatedBlock {
    /// Consensus height at which this runtime block was produced.
    pub consensus_height: i64,
    /// Runtime block.
    pub block: Block,
}

impl_bytes!(Namespace, 32, "Chain namespace.");

/// Roothash message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Message {}

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
    /// I/O merkle root.
    pub io_root: Hash,
    /// State merkle root.
    pub state_root: Hash,
    /// Messages sent this round.
    pub messages: Option<Vec<Message>>,
    /// Storage receipt signatures.
    pub storage_signatures: Option<Vec<SignatureBundle>>,
}

impl Header {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(&self))
    }
}

/// Compute results header signature context.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
pub const COMPUTE_RESULTS_HEADER_CONTEXT: &'static [u8] =
    b"oasis-core/roothash: compute results header";

/// The header of a computed batch output by a runtime. This header is a
/// compressed representation (e.g., hashes instead of full content) of
/// the actual results.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComputeResultsHeader {
    /// Hash of the previous block header this batch was computed against.
    pub previous_hash: Hash,
    /// The I/O merkle root.
    pub io_root: Hash,
    /// The root hash of the state after computing this batch.
    pub state_root: Hash,
    /// Messages sent from this batch.
    pub messages: Vec<Message>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_hash() {
        // NOTE: These hashes MUST be synced with go/roothash/api/block/header_test.go.
        let empty = Header::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("727b8c92cd436abc597df9ccbe3a02eeba8d7409cc68fcdf0ce3b577450631ac")
        );

        let populated = Header {
            version: 42,
            namespace: Namespace::from(Hash::empty_hash().as_ref()),
            round: 1000,
            timestamp: 1560257841,
            header_type: 1,
            previous_hash: empty.encoded_hash(),
            io_root: Hash::empty_hash(),
            state_root: Hash::empty_hash(),
            messages: None,
            ..Default::default()
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("e42c423b85e6ac261712f65b50ddbdef4758ed214c316c1f61ee76db28d1d8a5")
        );
    }
}
