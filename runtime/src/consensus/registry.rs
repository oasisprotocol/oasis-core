//! Registry structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/registry/api.
//!
use std::collections::BTreeMap;

use num_traits::Zero;
use tiny_keccak::{Hasher, TupleHash};

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signature},
        },
        namespace::Namespace,
        quantity, sgx,
        version::Version,
    },
    consensus::{beacon::EpochTime, scheduler, staking},
    rak::RAK,
};

/// Attestation signature context.
pub const ATTESTATION_SIGNATURE_CONTEXT: &[u8] = b"oasis-core/node: TEE attestation signature";

/// Represents the address of a TCP endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct TCPAddress {
    #[cbor(rename = "IP")]
    pub ip: Vec<u8>,
    #[cbor(rename = "Port")]
    pub port: i64,
    #[cbor(rename = "Zone")]
    pub zone: String,
}

/// Represents an Oasis committee address that includes a TLS public key and a TCP address.
///
/// NOTE: The address TLS public key can be different from the actual node TLS public key to allow
/// using a sentry node's addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct TLSAddress {
    /// Public key used for establishing TLS connections.
    pub pub_key: PublicKey,

    /// Address at which the node can be reached.
    pub address: TCPAddress,
}

/// Node's TLS information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct TLSInfo {
    /// Public key used for establishing TLS connections.
    pub pub_key: PublicKey,

    /// Public key that will be used for establishing connections after certificate rotation (if enabled).
    pub next_pub_key: PublicKey,

    /// List of addresses at which the node can be reached.
    pub addresses: Option<Vec<TLSAddress>>,
}

/// Node's P2P information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct P2PInfo {
    /// Unique identifier of the node on the P2P transport.
    pub id: PublicKey,

    /// List of addresses at which the node can be reached.
    pub addresses: Option<Vec<TCPAddress>>,
}

/// Represents a consensus address that includes an ID and a TCP address.
///
/// NOTE: The consensus address ID could be different from the consensus ID
/// to allow using a sentry node's ID and address instead of the validator's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ConsensusAddress {
    /// Public key identifying the node.
    pub id: PublicKey,

    /// Address at which the node can be reached.
    pub address: TCPAddress,
}

/// Node's consensus member information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ConsensusInfo {
    /// Unique identifier of the node as a consensus member.
    pub id: PublicKey,

    /// List of addresses at which the node can be reached.
    pub addresses: Option<Vec<ConsensusAddress>>,
}

/// Contains information for this node's participation in VRF based elections.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct VRFInfo {
    /// Unique identifier of the node used to generate VRF proofs.
    pub id: PublicKey,
}

/// Represents the node's TEE capability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct CapabilityTEE {
    /// Hardware type.
    pub hardware: TEEHardware,

    /// Runtime attestation key.
    pub rak: PublicKey,

    /// Runtime encryption key.
    #[cbor(optional)]
    pub rek: Option<[u8; 32]>,

    /// Attestation.
    pub attestation: Vec<u8>,
}

impl CapabilityTEE {
    /// Tries to decode the TEE-specific attestation.
    pub fn try_decode_attestation<T>(&self) -> Result<T, cbor::DecodeError>
    where
        T: cbor::Decode,
    {
        cbor::from_slice_non_strict(&self.attestation)
    }

    /// Checks whether the TEE capability matches the given TEE identity.
    pub fn matches(&self, rak: &RAK) -> bool {
        match self.hardware {
            TEEHardware::TEEHardwareInvalid => false,
            TEEHardware::TEEHardwareIntelSGX => {
                // Decode SGX attestation and check quote equality.
                let attestation: SGXAttestation = self.try_decode_attestation().unwrap();
                rak.matches(&self.rak, &attestation.quote())
            }
        }
    }
}

/// Represents a node's capabilities.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Capabilities {
    /// Is the capability of a node executing batches in a TEE.
    #[cbor(optional)]
    pub tee: Option<CapabilityTEE>,
}

/// Represents the runtimes supported by a given Oasis node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct NodeRuntime {
    /// Public key identifying the runtime.
    pub id: Namespace,

    /// Version of the runtime.
    pub version: Version,

    /// Node's capabilities for a given runtime.
    pub capabilities: Capabilities,

    /// Extra per node + per runtime opaque data associated with the current instance.
    pub extra_info: Option<Vec<u8>>,
}

/// TEE hardware implementation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
#[cbor(transparent)]
pub struct RolesMask(pub u32);

// XXX: Would be nicer to use bitflags crate for this, but there is no way to add
// custom derives to the enum at the moment.
// Should be possible in v2.0 (https://github.com/bitflags/bitflags/issues/262).
impl RolesMask {
    /// Empty roles mask.
    pub const ROLE_EMPTY: RolesMask = RolesMask(0);
    /// Compute worker role.
    pub const ROLE_COMPUTE_WORKER: RolesMask = RolesMask(1 << 0);
    /// Reserved role (storage role in v1 descriptors).
    pub const ROLE_RESERVED_2: RolesMask = RolesMask(1 << 1);
    /// Key manager role.
    pub const ROLE_KEY_MANAGER: RolesMask = RolesMask(1 << 2);
    /// Validator role.
    pub const ROLE_VALIDATOR: RolesMask = RolesMask(1 << 3);
    /// Public consensus RPC services worker role.
    pub const ROLE_CONSENSUS_RPC: RolesMask = RolesMask(1 << 4);
    /// Public storage RPC services worker role.
    pub const ROLE_STORAGE_RPC: RolesMask = RolesMask(1 << 5);

    // Bits of the Oasis node roles bitmask that are reserved and must not be used.
    pub const ROLES_RESERVED: RolesMask =
        RolesMask(u32::MAX & !((Self::ROLE_STORAGE_RPC.0 << 1) - 1) | Self::ROLE_RESERVED_2.0);
}

impl PartialOrd for RolesMask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for RolesMask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Default for RolesMask {
    fn default() -> Self {
        Self::ROLE_EMPTY
    }
}

/// Node registry descriptor.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct Node {
    /// Structure version.
    pub v: u16,

    /// Public key identifying the node.
    pub id: PublicKey,

    /// Public key identifying the Entity controlling the node.
    pub entity_id: PublicKey,

    /// Epoch in which the node's commitment expires.
    pub expiration: u64,

    /// Information for connecting to this node via TLS.
    pub tls: TLSInfo,

    /// Information for connecting to this node via P2P.
    pub p2p: P2PInfo,

    /// Information for connecting to this node as a consensus member.
    pub consensus: ConsensusInfo,

    /// Information for this node's participation in VRF based elections.
    #[cbor(optional)]
    pub vrf: Option<VRFInfo>,

    /// Information for this node's participation in the old PVSS based random beacon protocol.
    /// Deprecated.
    #[cbor(optional)]
    pub beacon: Option<cbor::Value>,

    /// Node's runtimes.
    pub runtimes: Option<Vec<NodeRuntime>>,

    /// Bitmask representing the node roles.
    pub roles: RolesMask,

    /// Node's oasis-node software version.
    #[cbor(optional)]
    pub software_version: Option<String>,
}

impl Node {
    /// Checks whether the node has the provided TEE identity configured.
    pub fn has_tee(&self, rak: &RAK, runtime_id: &Namespace, version: &Version) -> bool {
        if let Some(rts) = &self.runtimes {
            for rt in rts {
                if runtime_id != &rt.id {
                    continue;
                }
                if version != &rt.version {
                    continue;
                }
                if let Some(tee) = &rt.capabilities.tee {
                    if tee.matches(rak) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

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
    #[cbor(optional)]
    pub min_live_rounds_percent: u8,
    /// Minimum number of live rounds in an epoch for the liveness calculations to be considered for
    /// evaluation.
    #[cbor(optional)]
    pub min_live_rounds_eval: u64,
    /// Maximum number of liveness failures that are tolerated before suspending and/or slashing the
    /// node. Zero means unlimited.
    #[cbor(optional)]
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
    #[cbor(optional)]
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
    pub thresholds: BTreeMap<staking::ThresholdKind, quantity::Quantity>,

    /// Per-runtime misbehavior slashing parameters.
    #[cbor(optional)]
    pub slashing: BTreeMap<staking::SlashReason, staking::Slash>,

    /// The percentage of the reward obtained when slashing for equivocation that is transferred to
    /// the runtime's account.
    #[cbor(optional)]
    pub reward_equivocation: u8,

    /// The percentage of the reward obtained when slashing for incorrect results that is
    /// transferred to the runtime's account.
    #[cbor(optional)]
    pub reward_bad_results: u8,

    /// Specifies the minimum fee that the incoming message must include for the
    /// message to be queued.
    #[cbor(optional)]
    pub min_in_message_fee: quantity::Quantity,
}

/// Policy that allows only whitelisted entities' nodes to register.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct EntityWhitelistRuntimeAdmissionPolicy {
    /// Entity whitelist configuration for each whitelisted entity.
    #[cbor(optional)]
    pub entities: BTreeMap<PublicKey, EntityWhitelistConfig>,
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
    pub max_nodes: BTreeMap<RolesMask, u16>,
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
    /// The epoch at which this version is valid.
    pub valid_from: EpochTime,
    /// Enclave version information, in an enclave provided specific format (if any).
    #[cbor(optional)]
    pub tee: Vec<u8>,
}

impl VersionInfo {
    /// Tries to decode the TEE-specific version information.
    pub fn try_decode_tee<T>(&self) -> Result<T, cbor::DecodeError>
    where
        T: cbor::Decode,
    {
        cbor::from_slice_non_strict(&self.tee)
    }
}

/// Intel SGX TEE constraints.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[cbor(tag = "v")]
pub enum SGXConstraints {
    /// Old V0 format that only supported IAS policies.
    #[cbor(rename = 0, missing)]
    V0 {
        /// The allowed MRENCLAVE/MRSIGNER pairs.
        #[cbor(optional)]
        enclaves: Vec<sgx::EnclaveIdentity>,

        /// A set of allowed quote statuses.
        #[cbor(optional)]
        allowed_quote_statuses: Vec<i64>,
    },

    /// New V1 format that supports both IAS and PCS policies.
    #[cbor(rename = 1)]
    V1 {
        /// The allowed MRENCLAVE/MRSIGNER pairs.
        #[cbor(optional)]
        enclaves: Vec<sgx::EnclaveIdentity>,

        /// The quote policy.
        #[cbor(optional)]
        policy: sgx::QuotePolicy,

        /// The maximum attestation age (in blocks).
        #[cbor(optional)]
        max_attestation_age: u64,
    },
}

impl SGXConstraints {
    /// Checks whether the given enclave identity is whitelisted.
    pub fn contains_enclave(&self, eid: &sgx::EnclaveIdentity) -> bool {
        let enclaves = match self {
            Self::V0 { ref enclaves, .. } => enclaves,
            Self::V1 { ref enclaves, .. } => enclaves,
        };
        enclaves.contains(eid)
    }

    /// SGX quote policy.
    pub fn policy(&self) -> sgx::QuotePolicy {
        match self {
            Self::V0 {
                ref allowed_quote_statuses,
                ..
            } => sgx::QuotePolicy {
                ias: Some(sgx::ias::QuotePolicy {
                    disabled: false,
                    allowed_quote_statuses: allowed_quote_statuses.clone(),
                }),
                ..Default::default()
            },
            Self::V1 { ref policy, .. } => policy.clone(),
        }
    }
}

/// Intel SGX remote attestation.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[cbor(tag = "v")]
pub enum SGXAttestation {
    /// Old V0 format that only supported IAS quotes.
    #[cbor(rename = 0, missing)]
    V0(sgx::ias::AVR),

    /// New V1 format that supports both IAS and PCS policies.
    #[cbor(rename = 1)]
    V1 {
        /// An Intel SGX quote.
        quote: sgx::Quote,
        /// The runtime's view of the consensus layer height at the time of attestation.
        height: u64,
        /// The signature of the attestation by the enclave (RAK).
        signature: Signature,
    },
}

impl SGXAttestation {
    /// SGX attestation quote.
    pub fn quote(&self) -> sgx::Quote {
        match self {
            Self::V0(avr) => sgx::Quote::Ias(avr.clone()),
            Self::V1 { quote, .. } => quote.clone(),
        }
    }

    /// Hashes the required data that needs to be signed by RAK producing the attestation signature.
    pub fn hash(report_data: &[u8], node_id: PublicKey, height: u64) -> [u8; 32] {
        let mut h = TupleHash::v256(ATTESTATION_SIGNATURE_CONTEXT);
        h.update(report_data);
        h.update(node_id.as_ref());
        h.update(&height.to_le_bytes());
        let mut result = [0u8; 32];
        h.finalize(&mut result);
        result
    }
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
    /// Runtime deployment information.
    #[cbor(optional)]
    pub deployments: Vec<VersionInfo>,
    /// Key manager runtime ID for this runtime.
    #[cbor(optional)]
    pub key_manager: Option<Namespace>,
    /// Parameters of the executor committee.
    #[cbor(optional)]
    pub executor: ExecutorParameters,
    /// Transaction scheduling parameters of the executor committee.
    #[cbor(optional)]
    pub txn_scheduler: TxnSchedulerParameters,
    /// Parameters of the storage committee.
    #[cbor(optional)]
    pub storage: StorageParameters,
    /// Which nodes are allowed to register for this runtime.
    pub admission_policy: RuntimeAdmissionPolicy,
    /// Node scheduling constraints.
    #[cbor(optional)]
    pub constraints:
        BTreeMap<scheduler::CommitteeKind, BTreeMap<scheduler::Role, SchedulingConstraints>>,
    /// Runtime's staking-related parameters.
    #[cbor(optional, skip_serializing_if = "staking_params_are_empty")]
    pub staking: RuntimeStakingParameters,
    /// Runtime governance model.
    pub governance_model: RuntimeGovernanceModel,
}

fn staking_params_are_empty(p: &RuntimeStakingParameters) -> bool {
    p.thresholds.is_empty()
        && p.slashing.is_empty()
        && p.reward_equivocation == 0
        && p.reward_bad_results == 0
        && p.min_in_message_fee.is_zero()
}

impl Runtime {
    /// The currently active deployment for the specified epoch if it exists.
    pub fn active_deployment(&self, now: EpochTime) -> Option<VersionInfo> {
        self.deployments
            .iter()
            .filter(|vi| vi.valid_from <= now) // Ignore versions that are not valid yet.
            .fold(None, |acc, vi| match acc {
                None => Some(vi.clone()),
                Some(ad) if ad.valid_from < vi.valid_from => Some(vi.clone()),
                _ => acc,
            })
    }

    /// Deployment corresponding to the specified version if it exists.
    pub fn deployment_for_version(&self, version: Version) -> Option<VersionInfo> {
        self.deployments
            .iter()
            .find(|vi| vi.version == version)
            .cloned()
    }
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
    use std::net::Ipv4Addr;

    use rustc_hex::ToHex;

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
            ("q2F2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGx0ZWVfaGFyZHdhcmUAbXR4bl9zY2hlZHVsZXKkbm1heF9iYXRjaF9zaXplAHNiYXRjaF9mbHVzaF90aW1lb3V0AHRtYXhfYmF0Y2hfc2l6ZV9ieXRlcwB1cHJvcG9zZV9iYXRjaF90aW1lb3V0AHBhZG1pc3Npb25fcG9saWN5oWhhbnlfbm9kZaBwZ292ZXJuYW5jZV9tb2RlbAA=", Runtime::default()),
            ("q2F2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGx0ZWVfaGFyZHdhcmUAbXR4bl9zY2hlZHVsZXKkbm1heF9iYXRjaF9zaXplAHNiYXRjaF9mbHVzaF90aW1lb3V0AHRtYXhfYmF0Y2hfc2l6ZV9ieXRlcwB1cHJvcG9zZV9iYXRjaF90aW1lb3V0AHBhZG1pc3Npb25fcG9saWN5oWhhbnlfbm9kZaBwZ292ZXJuYW5jZV9tb2RlbAA=",
                Runtime {
                    staking: RuntimeStakingParameters {
                        thresholds:          BTreeMap::new(),
                        slashing:            BTreeMap::new(),
                        reward_equivocation: 0,
                        reward_bad_results:  0,
                        min_in_message_fee:  Quantity::from(0u32),
                    },
                    ..Default::default()
                }),
            ("rGF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0YWtpbmehcnJld2FyZF9iYWRfcmVzdWx0cwpnc3RvcmFnZaNzY2hlY2twb2ludF9pbnRlcnZhbABzY2hlY2twb2ludF9udW1fa2VwdAB1Y2hlY2twb2ludF9jaHVua19zaXplAGhleGVjdXRvcqVqZ3JvdXBfc2l6ZQBsbWF4X21lc3NhZ2VzAG1yb3VuZF90aW1lb3V0AHFncm91cF9iYWNrdXBfc2l6ZQByYWxsb3dlZF9zdHJhZ2dsZXJzAGllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbHRlZV9oYXJkd2FyZQBtdHhuX3NjaGVkdWxlcqRubWF4X2JhdGNoX3NpemUAc2JhdGNoX2ZsdXNoX3RpbWVvdXQAdG1heF9iYXRjaF9zaXplX2J5dGVzAHVwcm9wb3NlX2JhdGNoX3RpbWVvdXQAcGFkbWlzc2lvbl9wb2xpY3mhaGFueV9ub2RloHBnb3Zlcm5hbmNlX21vZGVsAA==",
                Runtime {
                    staking: RuntimeStakingParameters {
                        thresholds:          BTreeMap::new(),
                        slashing:            BTreeMap::new(),
                        reward_equivocation: 0,
                        reward_bad_results:  10,
                        min_in_message_fee:  Quantity::from(0u32),
                    },
                    ..Default::default()
                }),
		    ("r2F2GCpiaWRYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGtpbmQCZ2dlbmVzaXOiZXJvdW5kGCtqc3RhdGVfcm9vdFggseUhAZ+3vd413IH+55BlYQy937jvXCXihJg2aBkqbQ1nc3Rha2luZ6FycmV3YXJkX2JhZF9yZXN1bHRzCmdzdG9yYWdlo3NjaGVja3BvaW50X2ludGVydmFsGCFzY2hlY2twb2ludF9udW1fa2VwdAZ1Y2hlY2twb2ludF9jaHVua19zaXplGGVoZXhlY3V0b3Koamdyb3VwX3NpemUJbG1heF9tZXNzYWdlcwVtcm91bmRfdGltZW91dAZxZ3JvdXBfYmFja3VwX3NpemUIcmFsbG93ZWRfc3RyYWdnbGVycwdybWF4X2xpdmVuZXNzX2ZhaWxzAnRtaW5fbGl2ZV9yb3VuZHNfZXZhbAN3bWluX2xpdmVfcm91bmRzX3BlcmNlbnQEaWVudGl0eV9pZFggEjRWeJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABrY29uc3RyYWludHOhAaEBo2ltYXhfbm9kZXOhZWxpbWl0Cm1taW5fcG9vbF9zaXploWVsaW1pdAVtdmFsaWRhdG9yX3NldKBrZGVwbG95bWVudHOBo2N0ZWVLdmVyc2lvbiB0ZWVndmVyc2lvbqJlbWFqb3IYLGVwYXRjaAFqdmFsaWRfZnJvbQBra2V5X21hbmFnZXJYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABbHRlZV9oYXJkd2FyZQFtdHhuX3NjaGVkdWxlcqVubWF4X2JhdGNoX3NpemUZJxBvbWF4X2luX21lc3NhZ2VzGCBzYmF0Y2hfZmx1c2hfdGltZW91dBo7msoAdG1heF9iYXRjaF9zaXplX2J5dGVzGgCYloB1cHJvcG9zZV9iYXRjaF90aW1lb3V0AXBhZG1pc3Npb25fcG9saWN5oXBlbnRpdHlfd2hpdGVsaXN0oWhlbnRpdGllc6FYIBI0VniQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoWltYXhfbm9kZXOiAQMEAXBnb3Zlcm5hbmNlX21vZGVsAw==",
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
                    deployments: vec![
                        VersionInfo{
                            version: Version { major: 44, minor: 0, patch: 1 },
                            valid_from: 0,
                            tee: b"version tee".to_vec(),
                        },
                    ],
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
                        entities:
                            btreemap! {
                                PublicKey::from("1234567890000000000000000000000000000000000000000000000000000000") => EntityWhitelistConfig {
                                     max_nodes: btreemap! {
                                         RolesMask::ROLE_COMPUTE_WORKER => 3,
                                         RolesMask::ROLE_KEY_MANAGER => 1,
                                    }
                                }
                            }
                    }),
                    constraints:
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
                        },
                    staking: RuntimeStakingParameters {
                        thresholds:          BTreeMap::new(),
                        slashing:            BTreeMap::new(),
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

    #[test]
    fn test_consistent_node() {
        // NOTE: These tests MUST be synced with go/common/node/node_test.go.
        let tcs = vec![
            (
                "qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAA==",
                Node{v: 2, ..Default::default()},
                true,
            ),
			(
                "qmF2AmJpZFgg//////////////////////////////////////////BjcDJwomJpZFgg//////////////////////////////////////////VpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIP/////////////////////////////////////////yaWFkZHJlc3Nlc4GiZ2FkZHJlc3OjYklQUAAAAAAAAAAAAAD//38AAAFkUG9ydBkEV2Rab25lYGdwdWJfa2V5WCD/////////////////////////////////////////9GxuZXh0X3B1Yl9rZXlYIP/////////////////////////////////////////zY3ZyZqFiaWRYIP/////////////////////////////////////////3ZXJvbGVzAGhydW50aW1lc4KkYmlkWCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGd2ZXJzaW9uoWVwYXRjaBkBQWpleHRyYV9pbmZv9mxjYXBhYmlsaXRpZXOgpGJpZFgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFndmVyc2lvbqFlcGF0Y2gYe2pleHRyYV9pbmZvRAUDAgFsY2FwYWJpbGl0aWVzoWN0ZWWjY3Jha1gg//////////////////////////////////////////hoaGFyZHdhcmUBa2F0dGVzdGF0aW9uRgABAgMEBWljb25zZW5zdXOiYmlkWCD/////////////////////////////////////////9mlhZGRyZXNzZXOAaWVudGl0eV9pZFgg//////////////////////////////////////////FqZXhwaXJhdGlvbhgg",
                Node{
                    v: 2,
                    id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
                    entity_id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
                    expiration: 32,
                    tls: TLSInfo{
                        pub_key: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
                        next_pub_key: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
                        addresses: Some(vec![
                            TLSAddress{
                                pub_key: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
                                address: TCPAddress{
                                    ip: Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped().octets().to_vec(),
                                    port: 1111,
                                    ..Default::default()
                                },
                            },
                        ]),
                    },
                    p2p: P2PInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5"),
                        ..Default::default()
                    },
                    consensus: ConsensusInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6"),
                        addresses: Some(Vec::new()),
                    },
                    vrf: Some(VRFInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7"),
                    }),
                    runtimes: Some(vec![
                        NodeRuntime{
                            id: Namespace::from("8000000000000000000000000000000000000000000000000000000000000010"),
                            version: Version::from(321u64),
                            ..Default::default()
                        },
                        NodeRuntime{
                            id: Namespace::from("8000000000000000000000000000000000000000000000000000000000000011"),
                            version: Version::from(123),
                            capabilities: Capabilities{
                               tee: Some(CapabilityTEE{
                                   hardware: TEEHardware::TEEHardwareIntelSGX,
                                    rak: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8"),
                                    attestation: vec![0, 1,2,3,4,5],
                                    ..Default::default()
                               }),
                            },
                            extra_info: Some(vec![5,3,2,1]),
                        },
                    ]),
                    ..Default::default()
                },
                true,
            ),
            (
                "qmF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAHBzb2Z0d2FyZV92ZXJzaW9u9g==",
                Node{v: 2, ..Default::default()},
                false,
            ),
            (
                "qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXOBomJpZFgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBndmVyc2lvbvZpY29uc2Vuc3VzomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamV4cGlyYXRpb24A",
                Node{
                    v: 2,
                    runtimes: Some(vec![
                        NodeRuntime{
                            id: Namespace::from("8000000000000000000000000000000000000000000000000000000000000010"),
                            version: Version::from(0u64),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                },
                false,
            ),
        ];
        for (encoded_base64, node, round_trip) in tcs {
            println!("{:?}", node);
            let dec: Node = cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                .expect("node should deserialize correctly");
            assert_eq!(dec, node, "decoded node should match the expected value");

            if round_trip {
                let ser = base64::encode(cbor::to_vec(dec));
                assert_eq!(ser, encoded_base64, "node should serialize correctly");
            }
        }
    }

    #[test]
    fn test_runtime_deployments() {
        let rt = Runtime::default();
        assert_eq!(rt.active_deployment(0), None);

        let rt = Runtime {
            deployments: vec![
                VersionInfo {
                    version: Version {
                        major: 0,
                        minor: 1,
                        patch: 0,
                    },
                    valid_from: 0,
                    ..Default::default()
                },
                VersionInfo {
                    version: Version {
                        major: 0,
                        minor: 2,
                        patch: 0,
                    },
                    valid_from: 10,
                    ..Default::default()
                },
                VersionInfo {
                    version: Version {
                        major: 0,
                        minor: 3,
                        patch: 0,
                    },
                    valid_from: 20,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let ad = rt.active_deployment(0).unwrap();
        assert_eq!(ad.version.minor, 1);
        let ad = rt.active_deployment(1).unwrap();
        assert_eq!(ad.version.minor, 1);
        let ad = rt.active_deployment(9).unwrap();
        assert_eq!(ad.version.minor, 1);
        let ad = rt.active_deployment(10).unwrap();
        assert_eq!(ad.version.minor, 2);
        let ad = rt.active_deployment(20).unwrap();
        assert_eq!(ad.version.minor, 3);
        let ad = rt.active_deployment(50).unwrap();
        assert_eq!(ad.version.minor, 3);
        let ad = rt.active_deployment(100).unwrap();
        assert_eq!(ad.version.minor, 3);
        let ad = rt.active_deployment(1000).unwrap();
        assert_eq!(ad.version.minor, 3);

        let ad = rt
            .deployment_for_version(Version {
                major: 0,
                minor: 1,
                patch: 0,
            })
            .unwrap();
        assert_eq!(ad.valid_from, 0);
        let ad = rt
            .deployment_for_version(Version {
                major: 0,
                minor: 2,
                patch: 0,
            })
            .unwrap();
        assert_eq!(ad.valid_from, 10);
        let ad = rt
            .deployment_for_version(Version {
                major: 0,
                minor: 3,
                patch: 0,
            })
            .unwrap();
        assert_eq!(ad.valid_from, 20);
        let ad = rt.deployment_for_version(Version {
            major: 0,
            minor: 99,
            patch: 0,
        });
        assert_eq!(ad, None);
    }

    #[test]
    fn test_hash_attestation() {
        let h = SGXAttestation::hash(
            b"foo bar",
            PublicKey::from("47aadd91516ac548decdb436fde957992610facc09ba2f850da0fe1b2be96119"),
            42,
        );
        assert_eq!(
            h.to_hex::<String>(),
            "0f01a5084bbf432427873cbce5f8c3bff76bc22b9d1e0674b852e43698abb195"
        );
    }
}
