use oasis_core_runtime::{
    common::{crypto::signature::Signature, namespace::Namespace},
    consensus::beacon::EpochTime,
};

use crate::crypto::{KeyPairId, MasterSecret};

/// Key manager initialization request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct InitRequest {
    /// Checksum for validating replication.
    pub checksum: Vec<u8>,
    /// Policy for queries/replication.
    pub policy: Vec<u8>,
    /// True iff the enclave may generate a new master secret.
    pub may_generate: bool,
}

/// Key manager initialization response.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct InitResponse {
    /// True iff the key manager thinks it's running in a secure mode.
    pub is_secure: bool,
    /// Checksum for validating replication.
    pub checksum: Vec<u8>,
    /// Checksum for identifying policy.
    pub policy_checksum: Vec<u8>,
}

/// Signed InitResponse.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct SignedInitResponse {
    /// InitResponse.
    pub init_response: InitResponse,
    /// Sign(init_response).
    pub signature: Signature,
}

/// Key manager replication request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct ReplicateRequest {
    /// Latest trust root height.
    #[cbor(optional)]
    pub height: Option<u64>,
}

impl ReplicateRequest {
    pub fn new(height: Option<u64>) -> Self {
        Self { height }
    }
}

/// Key manager replication response.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct ReplicateResponse {
    pub master_secret: MasterSecret,
}

/// Long-term key request for private/public key generation and retrieval.
///
/// Long-term keys are runtime-scoped long-lived keys derived by the key manager
/// from the master secret. They can be generated at any time.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct LongTermKeyRequest {
    /// Latest trust root height.
    pub height: Option<u64>,
    /// Runtime ID.
    pub runtime_id: Namespace,
    /// Key pair ID.
    pub key_pair_id: KeyPairId,
}

impl LongTermKeyRequest {
    pub fn new(height: Option<u64>, runtime_id: Namespace, key_pair_id: KeyPairId) -> Self {
        Self {
            height,
            runtime_id,
            key_pair_id,
        }
    }
}

/// Ephemeral key request for private/public key generation and retrieval.
///
/// Ephemeral keys are runtime-scoped short-lived keys derived by
/// the key manager from the master secret. They can only be generated
/// for the past few epochs relative to the consensus layer state.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct EphemeralKeyRequest {
    /// Latest trust root height.
    pub height: Option<u64>,
    /// Runtime ID.
    pub runtime_id: Namespace,
    /// Key pair ID.
    pub key_pair_id: KeyPairId,
    /// Epoch time.
    pub epoch: EpochTime,
}

impl EphemeralKeyRequest {
    pub fn new(
        height: Option<u64>,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Self {
        Self {
            height,
            runtime_id,
            key_pair_id,
            epoch,
        }
    }
}
