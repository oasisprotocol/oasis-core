//! Registry structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/registry/api.
//!
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_repr::*;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, SignatureBundle},
        },
        namespace::Namespace,
        quantity,
        version::Version,
    },
    consensus::staking,
    storage::mkvs::WriteLog,
};

/// Runtime functionality.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum RuntimeKind {
    /// Invalid runtime that should never be explicitly set.
    #[serde(rename = "invalid")]
    KindInvalid = 0,
    /// Generic compute runtime.
    #[serde(rename = "compute")]
    KindCompute = 1,
    /// Key manager runtime.
    #[serde(rename = "keymanager")]
    KindKeyManager = 2,
}

impl Default for RuntimeKind {
    fn default() -> Self {
        RuntimeKind::KindInvalid
    }
}

/// Parameters for the executor committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutorParameters {
    /// Size of the committee.
    #[serde(default)]
    pub group_size: u64,
    /// Size of the discrepancy resolution group.
    #[serde(default)]
    pub group_backup_size: u64,
    /// Number of allowed stragglers.
    #[serde(default)]
    pub allowed_stragglers: u64,
    /// rRound timeout in consensus blocks.
    #[serde(default)]
    pub round_timeout: i64,
    /// Maximum number of messages that can be emitted by the runtime
    /// in a single round.
    #[serde(default)]
    pub max_messages: u32,
    /// Minimum required candidate compute node pool size.
    #[serde(default)]
    pub min_pool_size: u64,
}

/// Parameters for the runtime transaction scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxnSchedulerParameters {
    /// Transaction scheduling algorithm.
    #[serde(default)]
    pub algorithm: String,
    /// How long to wait for a scheduled batch in nanoseconds (when using the
    /// "simple" scheduling algorithm).
    #[serde(default)]
    pub batch_flush_timeout: i64,
    /// Maximum size of a scheduled batch.
    #[serde(default)]
    pub max_batch_size: u64,
    /// Maximum size of a scheduled batch in bytes.
    #[serde(default)]
    pub max_batch_size_bytes: u64,
    /// Timeout (in consensus blocks) for the scheduler to propose a batch.
    #[serde(default)]
    pub propose_batch_timeout: i64,
}

/// Parameters for the storage committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StorageParameters {
    /// Size of the storage group.
    #[serde(default)]
    pub group_size: u64,
    /// Number of nodes to which any writes must be replicated before being
    /// assumed to be committed. It must be less than or equal to group_size.
    #[serde(default)]
    pub min_write_replication: u64,
    /// Maximum number of write log entries when performing an Apply operation.
    #[serde(default)]
    pub max_apply_write_log_entries: u64,
    /// Maximum number of Apply operations in a batch.
    #[serde(default)]
    pub max_apply_ops: u64,
    /// Expected runtime state checkpoint interval (in rounds).
    #[serde(default)]
    pub checkpoint_interval: u64,
    /// Expected minimum number of checkpoints to keep.
    #[serde(default)]
    pub checkpoint_num_kept: u64,
    /// Chunk size parameter for checkpoint creation.
    #[serde(default)]
    pub checkpoint_chunk_size: u64,
    /// Minimum required candidate storage node pool size.
    #[serde(default)]
    pub min_pool_size: u64,
}

/// Stake-related parameters for a runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuntimeStakingParameters {
    /// Minimum stake thresholds for a runtime. These per-runtime thresholds are
    /// in addition to the global thresholds. May be left unspecified.
    ///
    /// In case a node is registered for multiple runtimes, it will need to
    /// satisfy the maximum threshold of all the runtimes.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub thresholds: Option<BTreeMap<staking::ThresholdKind, quantity::Quantity>>,
}

/// Oasis node roles bitmask.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum RolesMask {
    /// Compute worker role.
    #[serde(rename = "compute")]
    RoleComputeWorker = 1 << 0,
    /// Storage worker role.
    #[serde(rename = "storage")]
    RoleStorageWorker = 1 << 1,
    /// Key manager role.
    #[serde(rename = "key-manager")]
    RoleKeyManager = 1 << 2,
    /// Validator role.
    #[serde(rename = "validator")]
    RoleValidator = 1 << 3,
    /// Public consensus RPC services worker role.
    #[serde(rename = "consensus-rpc")]
    RoleConsensusRPC = 1 << 4,
    /// Public storage RPC services worker role.
    #[serde(rename = "storage-rpc")]
    RoleStorageRPC = 1 << 5,
}

/// Policy that allows only whitelisted entities' nodes to register.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityWhitelistRuntimeAdmissionPolicy {
    /// Entity whitelist configuration for each whitelisted entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "entities")]
    #[serde(default)]
    pub entities: Option<BTreeMap<PublicKey, EntityWhitelistConfig>>,
}

/// Entity whitelist configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityWhitelistConfig {
    /// Maximum number of nodes that an entity can register under the given
    /// runtime for a specific role. If the map is empty or absent, the number
    /// of nodes is unlimited. If the map is present and non-empty, the number
    /// of nodes is restricted to the specified maximum (where zero
    /// means no nodes allowed), any missing roles imply zero nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "max_nodes")]
    #[serde(default)]
    pub max_nodes: Option<BTreeMap<RolesMask, u16>>,
}

/// Specification of which nodes are allowed to register for a runtime.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeAdmissionPolicy {
    /// Allow any node to register.
    #[serde(rename = "any_node")]
    AnyNode {},
    /// Allow only the whitelisted entities' nodes to register.
    #[serde(rename = "entity_whitelist")]
    EntityWhitelist {
        #[serde(flatten)]
        policy: EntityWhitelistRuntimeAdmissionPolicy,
    },
}

impl Default for RuntimeAdmissionPolicy {
    fn default() -> Self {
        RuntimeAdmissionPolicy::AnyNode {}
    }
}

/// Runtime governance model.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum RuntimeGovernanceModel {
    /// Invalid model that should never be explicitly set.
    #[serde(rename = "invalid")]
    GovernanceInvalid = 0,
    /// Entity governance model.
    #[serde(rename = "entity")]
    GovernanceEntity = 1,
    /// Runtime governance model.
    #[serde(rename = "runtime")]
    GovernanceRuntime = 2,
    /// Consensus governance model.
    #[serde(rename = "consensus")]
    GovernanceConsensus = 3,
}

impl Default for RuntimeGovernanceModel {
    fn default() -> Self {
        RuntimeGovernanceModel::GovernanceInvalid
    }
}

/// Per-runtime version information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Version of the runtime.
    #[serde(default)]
    pub version: Version,
    /// Enclave version information, in an enclave provided specific format (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub tee: Option<Vec<u8>>,
}

/// TEE hardware implementation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum TEEHardware {
    /// Non-TEE implementation.
    #[serde(rename = "invalid")]
    TEEHardwareInvalid = 0,
    /// Intel SGX TEE implementation.
    #[serde(rename = "intel-sgx")]
    TEEHardwareIntelSGX = 1,
}

impl Default for TEEHardware {
    fn default() -> Self {
        TEEHardware::TEEHardwareInvalid
    }
}

/// Runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Runtime {
    /// Structure version.
    #[serde(default)]
    pub v: u16,
    /// Globally unique long term identifier of the runtime.
    #[serde(default)]
    pub id: Namespace,
    /// Public key identifying the Entity controlling the runtime.
    #[serde(default)]
    pub entity_id: PublicKey,
    /// Runtime genesis information.
    #[serde(default)]
    pub genesis: RuntimeGenesis,
    /// Type of runtime.
    #[serde(default)]
    pub kind: RuntimeKind,
    /// Runtime's TEE hardware requirements.
    #[serde(default)]
    pub tee_hardware: TEEHardware,
    /// Runtime version information.
    #[serde(default)]
    pub versions: VersionInfo,
    /// Key manager runtime ID for this runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub key_manager: Option<Namespace>,
    /// Parameters of the executor committee.
    #[serde(default)]
    pub executor: ExecutorParameters,
    /// Transaction scheduling parameters of the executor committee.
    #[serde(default)]
    pub txn_scheduler: TxnSchedulerParameters,
    /// Parameters of the storage committee.
    #[serde(default)]
    pub storage: StorageParameters,
    /// Which nodes are allowed to register for this runtime.
    #[serde(default)]
    pub admission_policy: RuntimeAdmissionPolicy,
    /// Runtime's staking-related parameters.
    #[serde(skip_serializing_if = "staking_params_are_empty")]
    #[serde(default)]
    pub staking: RuntimeStakingParameters,
    /// Runtime governance model.
    #[serde(default)]
    pub governance_model: RuntimeGovernanceModel,
}

fn staking_params_are_empty(p: &RuntimeStakingParameters) -> bool {
    return Option::is_none(&p.thresholds);
}

/// Runtime genesis information that is used to initialize runtime state in the first block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuntimeGenesis {
    /// State root that should be used at genesis time. If the runtime should start with empty state,
    /// this must be set to the empty hash.
    pub state_root: Hash,

    /// State identified by the state_root. It may be empty iff all storage_receipts are valid or
    /// state_root is an empty hash or if used in network genesis (e.g. during consensus chain init).
    pub state: Option<WriteLog>,

    /// Storage receipts for the state root. The list may be empty or a signature in the list
    /// invalid iff the state is non-empty or state_root is an empty hash or if used in network
    /// genesis (e.g. during consensus chain init).
    pub storage_receipts: Option<Vec<SignatureBundle>>,

    /// Runtime round in the genesis.
    pub round: u64,
}
