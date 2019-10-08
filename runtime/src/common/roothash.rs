//! Roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/block.
//!
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::{
    cbor,
    crypto::{
        hash::Hash,
        signature::{PublicKey, SignatureBundle},
    },
};

/// Block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    /// Header.
    pub header: Header,
}

impl_bytes!(Namespace, 32, "Chain namespace.");

/// Operation used in `StakingGeneralAdjustmentRoothashMessage`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum AdjustmentOp {
    INCREASE = 1,
    DECREASE = 2,
}

/// Roothash message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RoothashMessage {
    StakingGeneralAdjustmentRoothashMessage {
        account: PublicKey,
        op: AdjustmentOp,
        #[serde(with = "serde_bytes")]
        amount: Vec<u8>,
    },
}

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
    /// Roothash messages sent this round.
    pub roothash_messages: Option<Vec<RoothashMessage>>,
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
pub const COMPUTE_RESULTS_HEADER_CONTEXT: [u8; 8] = *b"EkComRHd";

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
    /// Roothash messages sent from this batch.
    pub roothash_messages: Vec<RoothashMessage>,
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
            Hash::from("96227abf446627117cd990023d9201f79ee2e3cc5119eded59259b913a1d79f5")
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
            roothash_messages: Some(vec![
                RoothashMessage::StakingGeneralAdjustmentRoothashMessage {
                    account: PublicKey(*b"UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"),
                    op: AdjustmentOp::INCREASE,
                    amount: vec![0x01, 0x0f, 0x00],
                },
            ]),
            ..Default::default()
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("480a773c029e57cc9f4c520ae659de28eba69bde92371a0dd0f076725382515e")
        );
    }
}
