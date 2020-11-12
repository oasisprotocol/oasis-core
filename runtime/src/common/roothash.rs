//! Consensus roothash structures.
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
    staking,
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

/// A message that can be emitted by the runtime to be processed by the consensus layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Message {
    #[serde(rename = "noop")]
    Noop {},

    #[serde(rename = "staking")]
    Staking {
        v: u16,
        #[serde(flatten)]
        msg: StakingMessage,
    },
}

impl Message {
    /// Returns a hash of provided runtime messages.
    pub fn messages_hash(msgs: &[Message]) -> Hash {
        if msgs.is_empty() {
            // Special case if there are no messages.
            return Hash::empty_hash();
        }
        Hash::digest_bytes(&cbor::to_vec(&msgs))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StakingMessage {
    #[serde(rename = "transfer")]
    Transfer(staking::Transfer),
    #[serde(rename = "withdraw")]
    Withdraw(staking::Withdraw),
}

/// Result of a message being processed by the consensus layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageEvent {
    #[serde(default)]
    pub module: String,
    #[serde(default)]
    pub code: u32,
    #[serde(default)]
    pub index: u32,
}

impl MessageEvent {
    /// Returns true if the event indicates that the message was successfully processed.
    pub fn is_success(&self) -> bool {
        return self.code == 0;
    }
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
    pub header_type: HeaderType,
    /// Previous block hash.
    pub previous_hash: Hash,
    /// I/O merkle root.
    pub io_root: Hash,
    /// State merkle root.
    pub state_root: Hash,
    /// Messages hash.
    pub messages_hash: Hash,
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
    /// Hash of messages sent from this batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages_hash: Option<Hash>,
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
            Hash::from("f7f340550630426b4962c3054cb7f21cf3662bd916642daff4efc9a00b4aab3f")
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
            messages_hash: Hash::empty_hash(),
            ..Default::default()
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("e5f8d6958fdedf15e705cb8fc8e2515d870c79d80dd2fa17f35c9e307ca4215a")
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
            messages_hash: Some(Hash::empty_hash()),
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("430ff02fafc53fc0e5eb432ad3e8b09167842a3948e09a7ee4bdd88e83e01d5a")
        );
    }

    #[test]
    fn test_consistent_messages_hash() {
        // NOTE: These hashes MUST be synced with go/roothash/api/block/messages_test.go.
        let tcs = vec![
            (
                vec![],
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            ),
            (
                vec![Message::Noop {}],
                "c8b55f87109e30fe2ba57507ffc0e96e40df7c0d24dfef82a858632f5f8420f1",
            ),
            (
                vec![Message::Staking {
                    v: 0,
                    msg: StakingMessage::Transfer(staking::Transfer::default()),
                }],
                "a6b91f974b34a9192efd12025659a768520d2f04e1dae9839677456412cdb2be",
            ),
            (
                vec![Message::Staking {
                    v: 0,
                    msg: StakingMessage::Withdraw(staking::Withdraw::default()),
                }],
                "069b0fda76d804e3fd65d4bbd875c646f15798fb573ac613100df67f5ba4c3fd",
            ),
        ];
        for (msgs, expected_hash) in tcs {
            assert_eq!(Message::messages_hash(&msgs), Hash::from(expected_hash));
        }
    }
}
