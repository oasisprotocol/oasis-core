//! Registry structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/registry/api.
//!
use std::collections::BTreeMap;

use num_traits::Zero;

use crate::{
    common::{
        crypto::{hash::Hash, signature::PublicKey},
        namespace::Namespace,
        quantity,
        version::Version,
    },
    consensus::{scheduler, staking},
};

/// Runtime kind.
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
#[repr(u32)]
pub enum RuntimeKind {
    /// Invalid runtime that should never be explicitly set.
    KindInvalid = 0,
    /// Generic compute runtime.
    KindCompute = 1,
    /// Key manager runtime.
    KindKeyManager = 2,
}

impl Default for RuntimeKind {
    fn default() -> Self {
        RuntimeKind::KindInvalid
    }
}

/// Parameters for the executor committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ExecutorParameters {
    /// Size of the committee.
    pub group_size: u16,
    /// Size of the discrepancy resolution group.
    pub group_backup_size: u16,
    /// Number of allowed stragglers.
    pub allowed_stragglers: u16,
    /// Round timeout in consensus blocks.
    pub round_timeout: i64,
    /// Maximum number of messages that can be emitted by the runtime
    /// in a single round.
    pub max_messages: u32,
    /// Minimum percentage of rounds in an epoch that a node must participate in positively in order
    /// to be considered live. Nodes not satisfying this may be penalized.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub min_live_rounds_percent: u8,
    /// Minimum number of live rounds in an epoch for the liveness calculations to be considered for
    /// evaluation.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub min_live_rounds_eval: u64,
    /// Maximum number of liveness failures that are tolerated before suspending and/or slashing the
    /// node. Zero means unlimited.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub max_liveness_fails: u8,
}

/// Parameters for the runtime transaction scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct TxnSchedulerParameters {
    /// How long to wait for a scheduled batch in nanoseconds (when using the
    /// "simple" scheduling algorithm).
    pub batch_flush_timeout: i64,
    /// Maximum size of a scheduled batch.
    pub max_batch_size: u64,
    /// Maximum size of a scheduled batch in bytes.
    pub max_batch_size_bytes: u64,
    /// Maximum size of the incoming message queue.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub max_in_messages: u32,
    /// Timeout (in consensus blocks) for the scheduler to propose a batch.
    pub propose_batch_timeout: i64,
}

/// Storage parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct StorageParameters {
    /// Expected runtime state checkpoint interval (in rounds).
    pub checkpoint_interval: u64,
    /// Expected minimum number of checkpoints to keep.
    pub checkpoint_num_kept: u64,
    /// Chunk size parameter for checkpoint creation.
    pub checkpoint_chunk_size: u64,
}

/// The node scheduling constraints.
///
/// Multiple fields may be set in which case the ALL the constraints must be satisfied.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct SchedulingConstraints {
    #[cbor(optional)]
    pub validator_set: Option<ValidatorSetConstraint>,

    #[cbor(optional)]
    pub max_nodes: Option<MaxNodesConstraint>,

    #[cbor(optional)]
    pub min_pool_size: Option<MinPoolSizeConstraint>,
}

/// A constraint which specifies that the entity must have a node that is part of the validator set.
/// No other options can currently be specified.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ValidatorSetConstraint {}

/// A constraint which specifies that only the given number of nodes may be eligible per entity.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct MaxNodesConstraint {
    pub limit: u16,
}

/// A constraint which specifies the minimum required candidate pool size.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct MinPoolSizeConstraint {
    pub limit: u16,
}

/// Stake-related parameters for a runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct RuntimeStakingParameters {
    /// Minimum stake thresholds for a runtime. These per-runtime thresholds are
    /// in addition to the global thresholds. May be left unspecified.
    ///
    /// In case a node is registered for multiple runtimes, it will need to
    /// satisfy the maximum threshold of all the runtimes.
    #[cbor(optional)]
    pub thresholds: Option<BTreeMap<staking::ThresholdKind, quantity::Quantity>>,

    /// Per-runtime misbehavior slashing parameters.
    #[cbor(optional)]
    pub slashing: Option<BTreeMap<staking::SlashReason, staking::Slash>>,

    /// The percentage of the reward obtained when slashing for equivocation that is transferred to
    /// the runtime's account.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub reward_equivocation: u8,

    /// The percentage of the reward obtained when slashing for incorrect results that is
    /// transferred to the runtime's account.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub reward_bad_results: u8,

    /// Specifies the minimum fee that the incoming message must include for the
    /// message to be queued.
    #[cbor(optional, default, skip_serializing_if = "num_traits::Zero::is_zero")]
    pub min_in_message_fee: quantity::Quantity,
}

/// Oasis node roles bitmask.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode)]
#[repr(u32)]
pub enum RolesMask {
    /// Compute worker role.
    RoleComputeWorker = 1 << 0,
    /// Key manager role.
    RoleKeyManager = 1 << 2,
    /// Validator role.
    RoleValidator = 1 << 3,
    /// Public consensus RPC services worker role.
    RoleConsensusRPC = 1 << 4,
    /// Public storage RPC services worker role.
    RoleStorageRPC = 1 << 5,
}

/// Policy that allows only whitelisted entities' nodes to register.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct EntityWhitelistRuntimeAdmissionPolicy {
    /// Entity whitelist configuration for each whitelisted entity.
    #[cbor(optional)]
    pub entities: Option<BTreeMap<PublicKey, EntityWhitelistConfig>>,
}

/// Entity whitelist configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct EntityWhitelistConfig {
    /// Maximum number of nodes that an entity can register under the given
    /// runtime for a specific role. If the map is empty or absent, the number
    /// of nodes is unlimited. If the map is present and non-empty, the number
    /// of nodes is restricted to the specified maximum (where zero
    /// means no nodes allowed), any missing roles imply zero nodes.
    #[cbor(optional)]
    pub max_nodes: Option<BTreeMap<RolesMask, u16>>,
}

/// Specification of which nodes are allowed to register for a runtime.
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub enum RuntimeAdmissionPolicy {
    /// Allow any node to register.
    #[cbor(rename = "any_node")]
    AnyNode {},
    /// Allow only the whitelisted entities' nodes to register.
    #[cbor(rename = "entity_whitelist")]
    EntityWhitelist(EntityWhitelistRuntimeAdmissionPolicy),
}

impl Default for RuntimeAdmissionPolicy {
    fn default() -> Self {
        RuntimeAdmissionPolicy::AnyNode {}
    }
}

/// Runtime governance model.
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum RuntimeGovernanceModel {
    /// Invalid model that should never be explicitly set.
    GovernanceInvalid = 0,
    /// Entity governance model.
    GovernanceEntity = 1,
    /// Runtime governance model.
    GovernanceRuntime = 2,
    /// Consensus governance model.
    GovernanceConsensus = 3,
}

impl Default for RuntimeGovernanceModel {
    fn default() -> Self {
        RuntimeGovernanceModel::GovernanceInvalid
    }
}

/// Per-runtime version information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct VersionInfo {
    /// Version of the runtime.
    pub version: Version,
    /// Enclave version information, in an enclave provided specific format (if any).
    #[cbor(optional)]
    pub tee: Option<Vec<u8>>,
}

/// TEE hardware implementation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum TEEHardware {
    /// Non-TEE implementation.
    TEEHardwareInvalid = 0,
    /// Intel SGX TEE implementation.
    TEEHardwareIntelSGX = 1,
}

impl Default for TEEHardware {
    fn default() -> Self {
        TEEHardware::TEEHardwareInvalid
    }
}

/// The latest entity descriptor version that should be used for all new descriptors. Using earlier
/// versions may be rejected.
pub const LATEST_RUNTIME_DESCRIPTOR_VERSION: u16 = 3;

/// Runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Runtime {
    /// Structure version.
    pub v: u16,
    /// Globally unique long term identifier of the runtime.
    pub id: Namespace,
    /// Public key identifying the Entity controlling the runtime.
    pub entity_id: PublicKey,
    /// Runtime genesis information.
    pub genesis: RuntimeGenesis,
    /// Type of runtime.
    pub kind: RuntimeKind,
    /// Runtime's TEE hardware requirements.
    pub tee_hardware: TEEHardware,
    /// Runtime version information.
    pub versions: VersionInfo,
    /// Key manager runtime ID for this runtime.
    #[cbor(optional)]
    pub key_manager: Option<Namespace>,
    /// Parameters of the executor committee.
    #[cbor(optional, default)]
    pub executor: ExecutorParameters,
    /// Transaction scheduling parameters of the executor committee.
    #[cbor(optional, default)]
    pub txn_scheduler: TxnSchedulerParameters,
    /// Parameters of the storage committee.
    #[cbor(optional, default)]
    pub storage: StorageParameters,
    /// Which nodes are allowed to register for this runtime.
    pub admission_policy: RuntimeAdmissionPolicy,
    /// Node scheduling constraints.
    #[cbor(optional)]
    pub constraints: Option<
        BTreeMap<scheduler::CommitteeKind, BTreeMap<scheduler::Role, SchedulingConstraints>>,
    >,
    /// Runtime's staking-related parameters.
    #[cbor(optional, default, skip_serializing_if = "staking_params_are_empty")]
    pub staking: RuntimeStakingParameters,
    /// Runtime governance model.
    pub governance_model: RuntimeGovernanceModel,
}

fn staking_params_are_empty(p: &RuntimeStakingParameters) -> bool {
    p.thresholds.is_none()
        && p.slashing.is_none()
        && p.reward_equivocation == 0
        && p.reward_bad_results == 0
        && p.min_in_message_fee.is_zero()
}

/// Runtime genesis information that is used to initialize runtime state in the first block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct RuntimeGenesis {
    /// State root that should be used at genesis time. If the runtime should start with empty state,
    /// this must be set to the empty hash.
    pub state_root: Hash,

    /// Runtime round in the genesis.
    pub round: u64,
}
#[cfg(test)]
mod tests {
    use crate::common::quantity::Quantity;

    use super::*;

    /// Constructs a BTreeMap using a `btreemap! { key => value, ... }` syntax.
    macro_rules! btreemap {
    // allow trailing comma
    ( $($key:expr => $value:expr,)+ ) => (btreemap!($($key => $value),+));
    ( $($key:expr => $value:expr),* ) => {
        {
            let mut m = BTreeMap::new();
            $( m.insert($key.into(), $value); )*
            m
        }
    };
}

    #[test]
    fn test_consistent_runtime() {
        // NOTE: These tests MUST be synced with go/registry/api/runtime.go.
        let tcs = vec![
            ("rGF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBodmVyc2lvbnOhZ3ZlcnNpb26gaWVudGl0eV9pZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsdGVlX2hhcmR3YXJlAG10eG5fc2NoZWR1bGVypG5tYXhfYmF0Y2hfc2l6ZQBzYmF0Y2hfZmx1c2hfdGltZW91dAB0bWF4X2JhdGNoX3NpemVfYnl0ZXMAdXByb3Bvc2VfYmF0Y2hfdGltZW91dABwYWRtaXNzaW9uX3BvbGljeaFoYW55X25vZGWgcGdvdmVybmFuY2VfbW9kZWwA", Runtime::default()),
            ("rGF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBodmVyc2lvbnOhZ3ZlcnNpb26gaWVudGl0eV9pZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsdGVlX2hhcmR3YXJlAG10eG5fc2NoZWR1bGVypG5tYXhfYmF0Y2hfc2l6ZQBzYmF0Y2hfZmx1c2hfdGltZW91dAB0bWF4X2JhdGNoX3NpemVfYnl0ZXMAdXByb3Bvc2VfYmF0Y2hfdGltZW91dABwYWRtaXNzaW9uX3BvbGljeaFoYW55X25vZGWgcGdvdmVybmFuY2VfbW9kZWwA",
                Runtime {
                    staking: RuntimeStakingParameters {
                        thresholds:          None,
                        slashing:            None,
                        reward_equivocation: 0,
                        reward_bad_results:  0,
                        min_in_message_fee:  Quantity::from(0u32),
                    },
                    ..Default::default()
                }),
            ("rWF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0YWtpbmehcnJld2FyZF9iYWRfcmVzdWx0cwpnc3RvcmFnZaNzY2hlY2twb2ludF9pbnRlcnZhbABzY2hlY2twb2ludF9udW1fa2VwdAB1Y2hlY2twb2ludF9jaHVua19zaXplAGhleGVjdXRvcqVqZ3JvdXBfc2l6ZQBsbWF4X21lc3NhZ2VzAG1yb3VuZF90aW1lb3V0AHFncm91cF9iYWNrdXBfc2l6ZQByYWxsb3dlZF9zdHJhZ2dsZXJzAGh2ZXJzaW9uc6FndmVyc2lvbqBpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGx0ZWVfaGFyZHdhcmUAbXR4bl9zY2hlZHVsZXKkbm1heF9iYXRjaF9zaXplAHNiYXRjaF9mbHVzaF90aW1lb3V0AHRtYXhfYmF0Y2hfc2l6ZV9ieXRlcwB1cHJvcG9zZV9iYXRjaF90aW1lb3V0AHBhZG1pc3Npb25fcG9saWN5oWhhbnlfbm9kZaBwZ292ZXJuYW5jZV9tb2RlbAA=",
                Runtime {
                    staking: RuntimeStakingParameters {
                        thresholds:          None,
                        slashing:            None,
                        reward_equivocation: 0,
                        reward_bad_results:  10,
                        min_in_message_fee:  Quantity::from(0u32),
                    },
                    ..Default::default()
                }),
		    ("r2F2GCpiaWRYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGtpbmQCZ2dlbmVzaXOiZXJvdW5kGCtqc3RhdGVfcm9vdFggseUhAZ+3vd413IH+55BlYQy937jvXCXihJg2aBkqbQ1nc3Rha2luZ6FycmV3YXJkX2JhZF9yZXN1bHRzCmdzdG9yYWdlo3NjaGVja3BvaW50X2ludGVydmFsGCFzY2hlY2twb2ludF9udW1fa2VwdAZ1Y2hlY2twb2ludF9jaHVua19zaXplGGVoZXhlY3V0b3Koamdyb3VwX3NpemUJbG1heF9tZXNzYWdlcwVtcm91bmRfdGltZW91dAZxZ3JvdXBfYmFja3VwX3NpemUIcmFsbG93ZWRfc3RyYWdnbGVycwdybWF4X2xpdmVuZXNzX2ZhaWxzAnRtaW5fbGl2ZV9yb3VuZHNfZXZhbAN3bWluX2xpdmVfcm91bmRzX3BlcmNlbnQEaHZlcnNpb25zomN0ZWVLdmVyc2lvbiB0ZWVndmVyc2lvbqJlbWFqb3IYLGVwYXRjaAFpZW50aXR5X2lkWCASNFZ4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGtjb25zdHJhaW50c6EBoQGjaW1heF9ub2Rlc6FlbGltaXQKbW1pbl9wb29sX3NpemWhZWxpbWl0BW12YWxpZGF0b3Jfc2V0oGtrZXlfbWFuYWdlclgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFsdGVlX2hhcmR3YXJlAW10eG5fc2NoZWR1bGVypW5tYXhfYmF0Y2hfc2l6ZRknEG9tYXhfaW5fbWVzc2FnZXMYIHNiYXRjaF9mbHVzaF90aW1lb3V0GjuaygB0bWF4X2JhdGNoX3NpemVfYnl0ZXMaAJiWgHVwcm9wb3NlX2JhdGNoX3RpbWVvdXQBcGFkbWlzc2lvbl9wb2xpY3mhcGVudGl0eV93aGl0ZWxpc3ShaGVudGl0aWVzoVggEjRWeJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAChaW1heF9ub2Rlc6IBAwQBcGdvdmVybmFuY2VfbW9kZWwD",
                Runtime {
                    v: 42,
                    id: Namespace::from("8000000000000000000000000000000000000000000000000000000000000000"),
                    entity_id: PublicKey::from("1234567890000000000000000000000000000000000000000000000000000000"),
                    genesis: RuntimeGenesis{
                        round: 43,
                        state_root: Hash::digest_bytes(b"stateroot hash"),
                    },
                    kind: RuntimeKind::KindKeyManager,
                    tee_hardware: TEEHardware::TEEHardwareIntelSGX,
                    versions: VersionInfo{
                        version: Version { major: 44, minor: 0, patch: 1 },
                        tee: Some(b"version tee".to_vec()),
                    },
                    key_manager: Some(
                        Namespace::from("8000000000000000000000000000000000000000000000000000000000000001")
                    ),
                    executor: ExecutorParameters{
                        group_size: 9,
                        group_backup_size: 8,
                        allowed_stragglers: 7,
                        round_timeout: 6,
                        max_messages: 5,
                        min_live_rounds_percent: 4,
                        min_live_rounds_eval: 3,
                        max_liveness_fails: 2,
                    },
                    txn_scheduler: TxnSchedulerParameters{
                        batch_flush_timeout: 1_000_000_000,
                        max_batch_size: 10_000,
                        max_batch_size_bytes: 10_000_000,
                        max_in_messages: 32,
                        propose_batch_timeout: 1,
                    },
                    storage: StorageParameters {
                        checkpoint_interval: 33,
                        checkpoint_num_kept: 6,
                        checkpoint_chunk_size: 101,
                    },
                    admission_policy: RuntimeAdmissionPolicy::EntityWhitelist(EntityWhitelistRuntimeAdmissionPolicy{
                        entities: Some(
                            btreemap! {
                                PublicKey::from("1234567890000000000000000000000000000000000000000000000000000000") => EntityWhitelistConfig {
                                     max_nodes: Some(btreemap! {
                                         RolesMask::RoleComputeWorker => 3,
                                         RolesMask::RoleKeyManager => 1,
                                    })
                                }
                            }
                        )
                    }),
                    constraints: Some(
                        btreemap! {
                            scheduler::CommitteeKind::ComputeExecutor => btreemap! {
                                scheduler::Role::Worker => SchedulingConstraints{
                                    max_nodes: Some(
                                        MaxNodesConstraint{
                                            limit: 10,
                                        }
                                    ),
                                    min_pool_size: Some(
                                        MinPoolSizeConstraint {
                                            limit: 5,
                                        }
                                    ),
                                    validator_set: Some(ValidatorSetConstraint{}),
                                },
                            }
                        }
                    ),
                    staking: RuntimeStakingParameters {
                        thresholds:          None,
                        slashing:            None,
                        reward_equivocation: 0,
                        reward_bad_results:  10,
                        min_in_message_fee:  Quantity::from(0u32),
                    },
                    governance_model: RuntimeGovernanceModel::GovernanceConsensus,
                }),
        ];
        for (encoded_base64, rr) in tcs {
            let dec: Runtime = cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                .expect("runtime should deserialize correctly");
            assert_eq!(dec, rr, "decoded runtime should match the expected value");
            let ser = base64::encode(cbor::to_vec(dec));
            assert_eq!(ser, encoded_base64, "runtime should serialize correctly");
        }
    }
}
