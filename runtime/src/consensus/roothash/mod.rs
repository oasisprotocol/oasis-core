//! Consensus roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api.
//!
use thiserror::Error;

use crate::{
    common::{
        crypto::{hash::Hash, signature::PublicKey},
        namespace::Namespace,
    },
    consensus::state::StateError,
};

// Modules.
mod block;
mod commitment;
mod message;

// Re-exports.
pub use block::*;
pub use commitment::*;
pub use message::*;

/// Errors emitted by the roothash module.
#[derive(Debug, Error)]
pub enum Error {
    #[error("roothash: invalid runtime {0}")]
    InvalidRuntime(Namespace),

    #[error(transparent)]
    State(#[from] StateError),

    #[error("roothash/commitment: no runtime configured")]
    NoRuntime,

    #[error("roothash/commitment: no committee configured")]
    NoCommittee,

    #[error("roothash/commitment: invalid committee kind")]
    InvalidCommitteeKind,

    #[error("roothash/commitment: batch RAK signature invalid")]
    RakSigInvalid,

    #[error("roothash/commitment: node not part of committee")]
    NotInCommittee,

    #[error("roothash/commitment: node already sent commitment")]
    AlreadyCommitted,

    #[error("roothash/commitment: submitted commitment is not based on correct block")]
    NotBasedOnCorrectBlock,

    #[error("roothash/commitment: discrepancy detected")]
    DiscrepancyDetected,

    #[error("roothash/commitment: still waiting for commits")]
    StillWaiting,

    #[error("roothash/commitment: insufficient votes to finalize discrepancy resolution round")]
    InsufficientVotes,

    #[error("roothash/commitment: bad executor commitment")]
    BadExecutorCommitment,

    #[error("roothash/commitment: invalid messages")]
    InvalidMessages,

    #[error("roothash/commitment: invalid round")]
    InvalidRound,

    #[error("roothash/commitment: no proposer commitment")]
    NoProposerCommitment,

    #[error("roothash/commitment: bad proposer commitment")]
    BadProposerCommitment,
}

/// Runtime block annotated with consensus information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct AnnotatedBlock {
    /// Consensus height at which this runtime block was produced.
    pub consensus_height: i64,
    /// Runtime block.
    pub block: Block,
}

/// Result of a message being processed by the consensus layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct MessageEvent {
    #[cbor(optional)]
    pub module: String,

    #[cbor(optional)]
    pub code: u32,

    #[cbor(optional)]
    pub index: u32,

    #[cbor(optional)]
    pub result: Option<cbor::Value>,
}

impl MessageEvent {
    /// Returns true if the event indicates that the message was successfully processed.
    pub fn is_success(&self) -> bool {
        self.code == 0
    }
}

/// Information about how a particular round was executed by the consensus layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct RoundResults {
    /// Results of executing emitted runtime messages.
    #[cbor(optional)]
    pub messages: Vec<MessageEvent>,

    /// Public keys of compute nodes' controlling entities that positively contributed to the round
    /// by replicating the computation correctly.
    #[cbor(optional)]
    pub good_compute_entities: Vec<PublicKey>,
    /// Public keys of compute nodes' controlling entities that negatively contributed to the round
    /// by causing discrepancies.
    #[cbor(optional)]
    pub bad_compute_entities: Vec<PublicKey>,
}

/// Per-round state and I/O roots that are stored in consensus state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, cbor::Encode, cbor::Decode)]
#[cbor(as_array)]
pub struct RoundRoots {
    pub state_root: Hash,
    pub io_root: Hash,
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use super::*;

    #[test]
    fn test_consistent_round_results() {
        let tcs = vec![
            ("oA==", RoundResults::default()),
            ("oWhtZXNzYWdlc4GiZGNvZGUBZm1vZHVsZWR0ZXN0", RoundResults {
                messages: vec![MessageEvent{module: "test".to_owned(), code: 1, index: 0, result: None}],
                ..Default::default()
            }),
            ("omhtZXNzYWdlc4GkZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3RmcmVzdWx0a3Rlc3QtcmVzdWx0dWdvb2RfY29tcHV0ZV9lbnRpdGllc4NYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=",
                RoundResults {
                    messages: vec![MessageEvent{module: "test".to_owned(), code: 42, index: 1, result: Some(cbor::Value::TextString("test-result".to_string()))}],
                    good_compute_entities: vec![
                        "0000000000000000000000000000000000000000000000000000000000000000".into(),
                        "0000000000000000000000000000000000000000000000000000000000000001".into(),
                        "0000000000000000000000000000000000000000000000000000000000000002".into(),
                    ],
                    ..Default::default()
                }),
            ("o2htZXNzYWdlc4GkZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3RmcmVzdWx0a3Rlc3QtcmVzdWx0dGJhZF9jb21wdXRlX2VudGl0aWVzgVggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF1Z29vZF9jb21wdXRlX2VudGl0aWVzglggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC",
                RoundResults {
                    messages: vec![MessageEvent{module: "test".to_owned(), code: 42, index: 1, result: Some(cbor::Value::TextString("test-result".to_string()))}],
                    good_compute_entities: vec![
                        "0000000000000000000000000000000000000000000000000000000000000000".into(),
                        "0000000000000000000000000000000000000000000000000000000000000002".into(),
                    ],
                    bad_compute_entities: vec![
                        "0000000000000000000000000000000000000000000000000000000000000001".into(),
                    ],
                }),
        ];
        for (encoded_base64, rr) in tcs {
            let dec: RoundResults =
                cbor::from_slice(&BASE64_STANDARD.decode(encoded_base64).unwrap())
                    .expect("round results should deserialize correctly");
            assert_eq!(dec, rr, "decoded results should match the expected value");
        }
    }

    #[test]
    fn test_consistent_round_roots() {
        let tcs = vec![
            ("glggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RoundRoots::default()),
            ("glggPTf+WENeDYcyPe5KLBsznvlU3mNxbuefV0f5TZdPkT9YIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RoundRoots {
                state_root: Hash::digest_bytes(b"test"),
                ..Default::default()
            }),
            ("glggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYID03/lhDXg2HMj3uSiwbM575VN5jcW7nn1dH+U2XT5E/", RoundRoots {
                io_root: Hash::digest_bytes(b"test"),
                ..Default::default()
            }),
            ("glggPTf+WENeDYcyPe5KLBsznvlU3mNxbuefV0f5TZdPkT9YID03/lhDXg2HMj3uSiwbM575VN5jcW7nn1dH+U2XT5E/",
                RoundRoots {
                    state_root: Hash::digest_bytes(b"test"),
                    io_root: Hash::digest_bytes(b"test"),
                }),
            ("glggC4+lzfqNgLxCHLxwDp+Bf5PLLb0DILrUZWwF+lp6Z/NYIJ3seczGUDFDvmAEdVCeep6Xsn8XRosTKWpu9wZ3mQRq",
                RoundRoots {
                    state_root: Hash::digest_bytes(b"test1"),
                    io_root: Hash::digest_bytes(b"test2"),
                }),
            ("glggnex5zMZQMUO+YAR1UJ56npeyfxdGixMpam73BneZBGpYIAuPpc36jYC8Qhy8cA6fgX+Tyy29AyC61GVsBfpaemfz",
                RoundRoots {
                    state_root: Hash::digest_bytes(b"test2"),
                    io_root: Hash::digest_bytes(b"test1"),
                }),
        ];

        for (encoded_base64, rr) in tcs {
            let dec: RoundRoots =
                cbor::from_slice(&BASE64_STANDARD.decode(encoded_base64).unwrap())
                    .expect("round roots should deserialize correctly");
            assert_eq!(
                dec, rr,
                "decoded round roots should match the expected value"
            );
        }
    }
}
