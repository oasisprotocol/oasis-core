//! Consensus roothash structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api.
//!
use thiserror::Error;

use crate::{
    common::{crypto::signature::PublicKey, namespace::Namespace},
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

#[cfg(test)]
mod tests {
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
            let dec: RoundResults = cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                .expect("round results should deserialize correctly");
            assert_eq!(dec, rr, "decoded results should match the expected value");
        }
    }
}
