//! Roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/block.
//!
use serde::{Deserialize, Serialize};
use serde_repr::*;

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

/// Header type.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/block/header.go.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum HeaderType {
    Invalid = 0,
    Normal = 1,
    RoundFailed = 2,
    EpochTransition = 3,
    Suspended = 4,
}

impl Default for HeaderType {
    fn default() -> Self {
        HeaderType::Invalid
    }
}

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
    pub header_type: HeaderType,
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
    /// Round number.
    pub round: u64,
    /// Hash of the previous block header this batch was computed against.
    pub previous_hash: Hash,
    /// The I/O merkle root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_root: Option<Hash>,
    /// The root hash of the state after computing this batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
    /// Messages sent from this batch.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<Message>,
}

impl ComputeResultsHeader {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(&self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_hash_header() {
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
            header_type: HeaderType::RoundFailed,
            previous_hash: empty.encoded_hash(),
            io_root: Hash::empty_hash(),
            state_root: Hash::empty_hash(),
            ..Default::default()
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("c39e8aefea5a1f794fb57f294a4ea8599381cd8739e67a8a9acb7763b54a630a")
        );
    }

    #[test]
    fn test_consistent_hash_compute_results_header() {
        // NOTE: These hashes MUST be synced with go/roothash/api/commitment/executor_test.go.
        let empty = ComputeResultsHeader::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")
        );

        let populated = ComputeResultsHeader {
            round: 42,
            previous_hash: empty.encoded_hash(),
            io_root: Some(Hash::empty_hash()),
            state_root: Some(Hash::empty_hash()),
            messages: Vec::new(),
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("374021bcba44f1014d0d9919e876a1ecd7fe5ec1a92ecf9c8b313cd4976fbc01")
        );
    }
}
