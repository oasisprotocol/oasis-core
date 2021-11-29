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
        versioned::Versioned,
    },
    consensus::{registry, staking, state::StateError},
};

/// Errors emitted by the roothash module.
#[derive(Debug, Error)]
pub enum Error {
    #[error("roothash: invalid runtime {0}")]
    InvalidRuntime(Namespace),

    #[error(transparent)]
    State(#[from] StateError),
}

/// Runtime block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Block {
    /// Header.
    pub header: Header,
}

/// Runtime block annotated with consensus information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct AnnotatedBlock {
    /// Consensus height at which this runtime block was produced.
    pub consensus_height: i64,
    /// Runtime block.
    pub block: Block,
}

/// Header type.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/block/header.go.
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub enum Message {
    #[cbor(rename = "staking")]
    Staking(Versioned<StakingMessage>),

    #[cbor(rename = "registry")]
    Registry(Versioned<RegistryMessage>),
}

impl Message {
    /// Returns a hash of provided runtime messages.
    pub fn messages_hash(msgs: &[Message]) -> Hash {
        if msgs.is_empty() {
            // Special case if there are no messages.
            return Hash::empty_hash();
        }
        Hash::digest_bytes(&cbor::to_vec(msgs.to_vec()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub enum StakingMessage {
    #[cbor(rename = "transfer")]
    Transfer(staking::Transfer),

    #[cbor(rename = "withdraw")]
    Withdraw(staking::Withdraw),

    #[cbor(rename = "add_escrow")]
    AddEscrow(staking::Escrow),

    #[cbor(rename = "reclaim_escrow")]
    ReclaimEscrow(staking::ReclaimEscrow),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub enum RegistryMessage {
    #[cbor(rename = "update_runtime")]
    UpdateRuntime(registry::Runtime),
}

/// Result of a message being processed by the consensus layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct MessageEvent {
    #[cbor(optional)]
    #[cbor(default)]
    pub module: String,

    #[cbor(optional)]
    #[cbor(default)]
    pub code: u32,

    #[cbor(optional)]
    #[cbor(default)]
    pub index: u32,
}

impl MessageEvent {
    /// Returns true if the event indicates that the message was successfully processed.
    pub fn is_success(&self) -> bool {
        return self.code == 0;
    }
}

/// Information about how a particular round was executed by the consensus layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct RoundResults {
    /// Results of executing emitted runtime messages.
    #[cbor(optional)]
    #[cbor(default)]
    pub messages: Vec<MessageEvent>,

    /// Public keys of compute nodes' controlling entities that positively contributed to the round
    /// by replicating the computation correctly.
    #[cbor(optional)]
    #[cbor(default)]
    pub good_compute_entities: Vec<PublicKey>,
    /// Public keys of compute nodes' controlling entities that negatively contributed to the round
    /// by causing discrepancies.
    #[cbor(optional)]
    #[cbor(default)]
    pub bad_compute_entities: Vec<PublicKey>,
}

/// Block header.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
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
}

impl Header {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(self.clone()))
    }
}

/// Compute results header signature context.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
pub const COMPUTE_RESULTS_HEADER_CONTEXT: &'static [u8] =
    b"oasis-core/roothash: compute results header";

/// The header of a computed batch output by a runtime. This header is a
/// compressed representation (e.g., hashes instead of full content) of
/// the actual results.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ComputeResultsHeader {
    /// Round number.
    pub round: u64,
    /// Hash of the previous block header this batch was computed against.
    pub previous_hash: Hash,

    /// The I/O merkle root.
    #[cbor(optional)]
    pub io_root: Option<Hash>,
    /// The root hash of the state after computing this batch.
    #[cbor(optional)]
    pub state_root: Option<Hash>,
    /// Hash of messages sent from this batch.
    #[cbor(optional)]
    pub messages_hash: Option<Hash>,
}

impl ComputeResultsHeader {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{common::quantity, consensus::scheduler};

    #[test]
    fn test_consistent_hash_header() {
        // NOTE: These hashes MUST be synced with go/roothash/api/block/header_test.go.
        let empty = Header::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("4a7526c9ce073f69f9bbc3f88170aaee91c63c4cf929b2ef2f758fc26d23d78b")
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
            Hash::from("cf1971df10ea8202fbdfaf567179ace4dea9987199ff3e6ccef1be1ab43e757a")
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
        // NOTE: This runtime structure must be synced with go/roothash/api/block/messages_test.go.
        let test_ent_id =
            PublicKey::from("4ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35");

        let q = quantity::Quantity::from(1000u32);

        let mut st = BTreeMap::new();
        st.insert(staking::ThresholdKind::KindNodeCompute, q.clone());

        let mut wlc = BTreeMap::new();
        wlc.insert(registry::RolesMask::RoleComputeWorker, 2);

        let mut wl = BTreeMap::new();
        wl.insert(
            test_ent_id,
            registry::EntityWhitelistConfig {
                max_nodes: Some(wlc),
            },
        );

        let rt = registry::Runtime {
            v: registry::LATEST_RUNTIME_DESCRIPTOR_VERSION,
            id: Namespace::default(),
            entity_id: test_ent_id,
            genesis: registry::RuntimeGenesis {
                state_root: Hash::empty_hash(),
                round: 0,
            },
            kind: registry::RuntimeKind::KindCompute,
            tee_hardware: registry::TEEHardware::TEEHardwareInvalid,
            versions: registry::VersionInfo::default(),
            key_manager: None,
            executor: registry::ExecutorParameters {
                group_size: 3,
                group_backup_size: 5,
                allowed_stragglers: 1,
                round_timeout: 10,
                max_messages: 32,
            },
            txn_scheduler: registry::TxnSchedulerParameters {
                algorithm: "simple".to_string(),
                batch_flush_timeout: 20000000000, // 20 seconds.
                max_batch_size: 1,
                max_batch_size_bytes: 1024,
                propose_batch_timeout: 5,
            },
            storage: registry::StorageParameters {
                checkpoint_interval: 0,
                checkpoint_num_kept: 0,
                checkpoint_chunk_size: 0,
            },
            admission_policy: registry::RuntimeAdmissionPolicy::EntityWhitelist(
                registry::EntityWhitelistRuntimeAdmissionPolicy { entities: Some(wl) },
            ),
            constraints: {
                let mut cs = BTreeMap::new();
                cs.insert(scheduler::CommitteeKind::ComputeExecutor, {
                    let mut ce = BTreeMap::new();
                    ce.insert(
                        scheduler::Role::Worker,
                        registry::SchedulingConstraints {
                            min_pool_size: Some(registry::MinPoolSizeConstraint { limit: 1 }),
                            validator_set: Some(registry::ValidatorSetConstraint {}),
                            ..Default::default()
                        },
                    );
                    ce.insert(
                        scheduler::Role::BackupWorker,
                        registry::SchedulingConstraints {
                            min_pool_size: Some(registry::MinPoolSizeConstraint { limit: 2 }),
                            ..Default::default()
                        },
                    );
                    ce
                });

                Some(cs)
            },
            staking: registry::RuntimeStakingParameters {
                thresholds: Some(st),
            },
            governance_model: registry::RuntimeGovernanceModel::GovernanceEntity,
        };

        // NOTE: These hashes MUST be synced with go/roothash/api/message/message_test.go.
        let tcs = vec![
            (
                vec![],
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::Transfer(staking::Transfer::default()),
                ))],
                "a6b91f974b34a9192efd12025659a768520d2f04e1dae9839677456412cdb2be",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::Withdraw(staking::Withdraw::default()),
                ))],
                "069b0fda76d804e3fd65d4bbd875c646f15798fb573ac613100df67f5ba4c3fd",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::AddEscrow(staking::Escrow::default()),
                ))],
                "65049870b9dae657390e44065df0c78176816876e67b96dac7791ee6a1aa42e2",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::ReclaimEscrow(staking::ReclaimEscrow::default()),
                ))],
                "c78547eae2f104268e49827cbe624cf2b350ee59e8d693dec0673a70a4664a2e",
            ),
            (
                vec![Message::Registry(Versioned::new(
                    0,
                    RegistryMessage::UpdateRuntime(registry::Runtime::default()),
                ))],
                "24f5e1502f9cfaa64404cc4fea4a4b6f799baefad6f18c9c805b82b727e15d25",
            ),
            (
                vec![Message::Registry(Versioned::new(
                    0,
                    RegistryMessage::UpdateRuntime(rt),
                ))],
                "ba161c59194e6991af9ba2ae2efe77e3dd245956185bcb82ff2db226fed63cdb",
            ),
        ];
        for (msgs, expected_hash) in tcs {
            assert_eq!(Message::messages_hash(&msgs), Hash::from(expected_hash));
        }
    }

    #[test]
    fn test_consistent_round_results() {
        let tcs = vec![
            ("oA==", RoundResults::default()),
            ("oWhtZXNzYWdlc4GiZGNvZGUBZm1vZHVsZWR0ZXN0", RoundResults {
                messages: vec![MessageEvent{module: "test".to_owned(), code: 1, index: 0}],
                ..Default::default()
            }),
            ("omhtZXNzYWdlc4GjZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3R1Z29vZF9jb21wdXRlX2VudGl0aWVzg1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg==",
                RoundResults {
                    messages: vec![MessageEvent{module: "test".to_owned(), code: 42, index: 1}],
                    good_compute_entities: vec![
                        "0000000000000000000000000000000000000000000000000000000000000000".into(),
                        "0000000000000000000000000000000000000000000000000000000000000001".into(),
                        "0000000000000000000000000000000000000000000000000000000000000002".into(),
                    ],
                    ..Default::default()
                }),
            ("o2htZXNzYWdlc4GjZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3R0YmFkX2NvbXB1dGVfZW50aXRpZXOBWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXVnb29kX2NvbXB1dGVfZW50aXRpZXOCWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=",
                RoundResults {
                    messages: vec![MessageEvent{module: "test".to_owned(), code: 42, index: 1}],
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
