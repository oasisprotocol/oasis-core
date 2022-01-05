//! Registry structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/registry/api.
//!
use std::collections::BTreeMap;

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
    /// rRound timeout in consensus blocks.
    pub round_timeout: i64,
    /// Maximum number of messages that can be emitted by the runtime
    /// in a single round.
    pub max_messages: u32,
}

/// Parameters for the runtime transaction scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct TxnSchedulerParameters {
    /// Transaction scheduling algorithm.
    pub algorithm: String,
    /// How long to wait for a scheduled batch in nanoseconds (when using the
    /// "simple" scheduling algorithm).
    pub batch_flush_timeout: i64,
    /// Maximum size of a scheduled batch.
    pub max_batch_size: u64,
    /// Maximum size of a scheduled batch in bytes.
    pub max_batch_size_bytes: u64,
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
    return Option::is_none(&p.thresholds);
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
