use std::{
    collections::{HashMap, HashSet},
    default::Default,
};

use base64;
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek;

use oasis_core_runtime::{
    common::{
        crypto::signature::{PublicKey as OasisPublicKey, Signature, SignatureBundle},
        namespace::Namespace,
        sgx::avr::EnclaveIdentity,
    },
    impl_bytes, runtime_api,
};

impl_bytes!(KeyPairId, 32, "A 256-bit key pair identifier.");
impl_bytes!(PrivateKey, 32, "A private key.");
impl_bytes!(PublicKey, 32, "A public key.");
impl_bytes!(StateKey, 32, "A state key.");
impl_bytes!(MasterSecret, 32, "A 256 bit master secret.");

/// Key manager initialization request.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitRequest {
    /// Checksum for validating replication.
    #[serde(with = "serde_bytes")]
    pub checksum: Vec<u8>,
    /// Policy for queries/replication.
    #[serde(with = "serde_bytes")]
    pub policy: Vec<u8>,
    /// True iff the enclave may generate a new master secret.
    pub may_generate: bool,
}

/// Key manager initialization response.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitResponse {
    /// True iff the key manager thinks it's running in a secure mode.
    pub is_secure: bool,
    /// Checksum for validating replication.
    #[serde(with = "serde_bytes")]
    pub checksum: Vec<u8>,
    /// Checksum for identifying policy.
    #[serde(with = "serde_bytes")]
    pub policy_checksum: Vec<u8>,
}

/// Context used for the init response signature.
pub const INIT_RESPONSE_CONTEXT: &'static [u8] = b"oasis-core/keymanager: init response";

/// Signed InitResponse.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedInitResponse {
    /// InitResponse.
    pub init_response: InitResponse,
    /// Sign(init_response).
    pub signature: Signature,
}

/// Key manager replication request.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplicateRequest {
    // Empty.
}

/// Key manager replication response.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplicateResponse {
    pub master_secret: MasterSecret,
}

/// Request runtime/key pair id tuple.
#[derive(Clone, Serialize, Deserialize)]
pub struct RequestIds {
    /// Runtime ID.
    pub runtime_id: Namespace,
    /// Key pair ID.
    pub key_pair_id: KeyPairId,
}

impl RequestIds {
    pub fn new(runtime_id: Namespace, key_pair_id: KeyPairId) -> Self {
        Self {
            runtime_id,
            key_pair_id,
        }
    }

    pub fn to_cache_key(&self) -> Vec<u8> {
        let mut k = self.runtime_id.as_ref().to_vec();
        k.extend_from_slice(self.key_pair_id.as_ref());
        k
    }
}

/// A key pair managed by the key manager.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Input key pair (pk, sk)
    pub input_keypair: InputKeyPair,
    /// State encryption key
    pub state_key: StateKey,
    /// Checksum of the key manager state.
    #[serde(with = "serde_bytes")]
    pub checksum: Vec<u8>,
}

impl KeyPair {
    /// Generate a new random key (for testing).
    pub fn generate_mock() -> Self {
        let mut rng = OsRng {};
        let sk = x25519_dalek::StaticSecret::new(&mut rng);
        let pk = x25519_dalek::PublicKey::from(&sk);

        let mut state_key = StateKey::default();
        rng.fill(&mut state_key.0);

        KeyPair::new(
            PublicKey(*pk.as_bytes()),
            PrivateKey(sk.to_bytes()),
            state_key,
            vec![],
        )
    }

    /// Create a `KeyPair`.
    pub fn new(pk: PublicKey, sk: PrivateKey, k: StateKey, sum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair::new(pk, sk),
            state_key: k,
            checksum: sum,
        }
    }

    /// Create a `KeyPair` with only the public key.
    pub fn from_public_key(k: PublicKey, sum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair::new(k, PrivateKey::default()),
            state_key: StateKey::default(),
            checksum: sum,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InputKeyPair {
    /// Pk
    pk: PublicKey,
    /// sk
    sk: PrivateKey,
}

impl InputKeyPair {
    pub fn new(pk: PublicKey, sk: PrivateKey) -> Self {
        Self { pk, sk }
    }

    pub fn get_pk(&self) -> PublicKey {
        self.pk
    }

    pub fn get_sk(&self) -> PrivateKey {
        self.sk
    }
}

/// Context used for the public key signature.
pub const PUBLIC_KEY_CONTEXT: [u8; 8] = *b"EkKmPubK";

/// Signed public key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPublicKey {
    /// Public key.
    pub key: PublicKey,
    /// Checksum of the key manager state.
    #[serde(with = "serde_bytes")]
    pub checksum: Vec<u8>,
    /// Sign(sk, (key || checksum)) from the key manager.
    pub signature: Signature,
}

/// Key manager error.
#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("client session is not authenticated")]
    NotAuthenticated,
    #[error("client session authentication is invalid")]
    InvalidAuthentication,
    #[error("key manager is not initialized")]
    NotInitialized,
    #[error("key manager state corrupted")]
    StateCorrupted,
    #[error("key manager replication required")]
    ReplicationRequired,
    #[error("policy rollback")]
    PolicyRollback,
    #[error("policy alteration, without serial increment")]
    PolicyChanged,
    #[error("policy is malformed or invalid")]
    PolicyInvalid,
    #[error("policy failed signature verification")]
    PolicyInvalidSignature,
    #[error("policy has insufficient signatures")]
    PolicyInsufficientSignatures,
}

/// Key manager access control policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySGX {
    pub serial: u32,
    pub id: Namespace,
    pub enclaves: HashMap<EnclaveIdentity, EnclavePolicySGX>,
}

/// Per enclave key manager access control policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnclavePolicySGX {
    pub may_query: HashMap<Namespace, Vec<EnclaveIdentity>>,
    pub may_replicate: Vec<EnclaveIdentity>,
}

/// Signed key manager access control policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPolicySGX {
    pub policy: PolicySGX,
    pub signatures: Vec<SignatureBundle>,
}

/// Set of trusted key manager policy signing keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedPolicySigners {
    /// Set of trusted signers.
    pub signers: HashSet<OasisPublicKey>,
    /// Threshold for determining if enough valid signatures are present.
    pub threshold: usize,
}

impl Default for TrustedPolicySigners {
    fn default() -> Self {
        Self {
            signers: HashSet::new(),
            threshold: 9001,
        }
    }
}

runtime_api! {
    pub fn get_or_create_keys(RequestIds) -> KeyPair;

    pub fn get_public_key(RequestIds) -> Option<SignedPublicKey>;

    pub fn replicate_master_secret(ReplicateRequest) -> ReplicateResponse;
}
