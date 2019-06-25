use std::collections::HashMap;

use failure::Fail;
use rand::{rngs::OsRng, Rng};
use serde_derive::{Deserialize, Serialize};
use x25519_dalek;

use ekiden_runtime::{
    common::{
        crypto::signature::{Signature, SignatureBundle},
        runtime::RuntimeId,
        sgx::avr::{EnclaveIdentity, MrEnclave, MrSigner},
    },
    impl_bytes, runtime_api,
};

impl_bytes!(ContractId, 32, "A 256-bit contract identifier.");
impl_bytes!(PrivateKey, 32, "A private key.");
impl_bytes!(PublicKey, 32, "A public key.");
impl_bytes!(StateKey, 32, "A state key.");
impl_bytes!(MasterSecret, 32, "A 256 bit master secret.");
impl_bytes!(RawEnclaveId, 64, "MRSIGNER | MRENCLAVE.");

impl Into<EnclaveIdentity> for RawEnclaveId {
    fn into(self) -> EnclaveIdentity {
        let raw = self.as_ref();
        EnclaveIdentity {
            mr_signer: MrSigner::from(&raw[0..32]),
            mr_enclave: MrEnclave::from(&raw[32..64]),
        }
    }
}

impl From<EnclaveIdentity> for RawEnclaveId {
    fn from(id: EnclaveIdentity) -> Self {
        let mut tmp = vec![];
        tmp.extend_from_slice(id.mr_signer.as_ref());
        tmp.extend_from_slice(id.mr_enclave.as_ref());
        RawEnclaveId::from(tmp)
    }
}

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

/// Context used for th einit response signature.
pub const INIT_RESPONSE_CONTEXT: [u8; 8] = *b"EkKmIniR";

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

/// Request runtime/contract id tuple.
#[derive(Clone, Serialize, Deserialize)]
pub struct RequestIds {
    /// Runtime ID.
    pub runtime_id: RuntimeId,
    /// Contract ID.
    pub contract_id: ContractId,
}

impl RequestIds {
    pub fn new(runtime_id: RuntimeId, contract_id: ContractId) -> Self {
        Self {
            runtime_id,
            contract_id,
        }
    }

    pub fn to_cache_key(&self) -> Vec<u8> {
        let mut k = self.runtime_id.as_ref().to_vec();
        k.extend_from_slice(self.contract_id.as_ref());
        k
    }
}

/// Keys for a contract.
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractKey {
    /// Input key pair (pk, sk)
    pub input_keypair: InputKeyPair,
    /// State encryption key
    pub state_key: StateKey,
    /// Checksum of the key manager state.
    #[serde(with = "serde_bytes")]
    pub checksum: Vec<u8>,
}

impl ContractKey {
    /// Generate a new random key (for testing).
    pub fn generate_mock() -> Self {
        let mut rng = OsRng::new().unwrap();
        let sk = x25519_dalek::StaticSecret::new(&mut rng);
        let pk = x25519_dalek::PublicKey::from(&sk);

        let mut state_key = StateKey::default();
        rng.fill(&mut state_key.0);

        ContractKey::new(
            PublicKey(*pk.as_bytes()),
            PrivateKey(sk.to_bytes()),
            state_key,
            vec![],
        )
    }

    /// Create a set of `ContractKey`.
    pub fn new(pk: PublicKey, sk: PrivateKey, k: StateKey, sum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair { pk, sk },
            state_key: k,
            checksum: sum,
        }
    }

    /// Create a set of `ContractKey` with only the public key.
    pub fn from_public_key(k: PublicKey, sum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair {
                pk: k,
                sk: PrivateKey::default(),
            },
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[derive(Debug, Fail)]
pub enum KeyManagerError {
    #[fail(display = "client session is not authenticated")]
    NotAuthenticated,
    #[fail(display = "client session authentication is invalid")]
    InvalidAuthentication,
    #[fail(display = "key manager is not initialized")]
    NotInitialized,
    #[fail(display = "key manager state corrupted")]
    StateCorrupted,
    #[fail(display = "key manager replication required")]
    ReplicationRequired,
    #[fail(display = "policy rollback")]
    PolicyRollback,
    #[fail(display = "policy alteration, without serial increment")]
    PolicyChanged,
    #[fail(display = "policy is malformed or invalid")]
    PolicyInvalid,
    #[fail(display = "policy failed signature verification")]
    PolicyInvalidSignature,
    #[fail(display = "policy has insufficient signatures")]
    PolicyInsufficientSignatures,
}

/// Key manager access control policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySGX {
    pub serial: u32,
    pub id: RuntimeId,
    pub enclaves: HashMap<RawEnclaveId, EnclavePolicySGX>,
}

/// Per enclave key manager access control policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnclavePolicySGX {
    pub may_query: HashMap<RuntimeId, Vec<RawEnclaveId>>,
    pub may_replicate: Vec<RawEnclaveId>,
}

/// Signed key manager access control policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPolicySGX {
    pub policy: PolicySGX,
    pub signatures: Vec<SignatureBundle>,
}

runtime_api! {
    pub fn get_or_create_keys(RequestIds) -> ContractKey;

    pub fn get_public_key(RequestIds) -> Option<SignedPublicKey>;

    pub fn replicate_master_secret(ReplicateRequest) -> ReplicateResponse;
}
