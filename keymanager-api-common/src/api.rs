use std::{collections::HashSet, default::Default, vec};

use rand::{rngs::OsRng, Rng};
use thiserror::Error;
use x25519_dalek;
use zeroize::Zeroize;

use oasis_core_runtime::{
    common::{
        crypto::signature::{PublicKey as OasisPublicKey, Signature},
        namespace::Namespace,
    },
    consensus::{
        beacon::EpochTime,
        keymanager::{PolicySGX, SignedPolicySGX},
    },
    impl_bytes,
};

impl_bytes!(KeyPairId, 32, "A 256-bit key pair identifier.");
impl_bytes!(PublicKey, 32, "A public key.");

/// A private key.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
#[cbor(transparent)]
#[zeroize(drop)]
pub struct PrivateKey(pub [u8; 32]);

/// A state encryption key.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
#[cbor(transparent)]
#[zeroize(drop)]
pub struct StateKey(pub [u8; 32]);

impl AsRef<[u8]> for StateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A 256-bit master secret.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
#[cbor(transparent)]
#[zeroize(drop)]
pub struct MasterSecret(pub [u8; 32]);

impl AsRef<[u8]> for MasterSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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

/// Context used for the init response signature.
pub const INIT_RESPONSE_CONTEXT: &[u8] = b"oasis-core/keymanager: init response";

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

/// A key pair managed by the key manager.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct KeyPair {
    /// Input key pair (pk, sk)
    pub input_keypair: InputKeyPair,
    /// State encryption key
    pub state_key: StateKey,
    /// Checksum of the key manager state.
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
            input_keypair: InputKeyPair { pk, sk },
            state_key: k,
            checksum: sum,
        }
    }

    /// Create a `KeyPair` with only the public key.
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

#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct InputKeyPair {
    /// Public key.
    pub pk: PublicKey,
    /// Private key.
    pub sk: PrivateKey,
}

/// Context used for the public key signature.
pub const PUBLIC_KEY_CONTEXT: [u8; 8] = *b"EkKmPubK";

/// Signed public key.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedPublicKey {
    /// Public key.
    pub key: PublicKey,
    /// Checksum of the key manager state.
    pub checksum: Vec<u8>,
    /// Sign(sk, (key || checksum)) from the key manager.
    pub signature: Signature,
}

/// Key manager error.
#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("client session is not authenticated")]
    NotAuthenticated,
    #[error("client is not authorized")]
    NotAuthorized,
    #[error("invalid epoch")]
    InvalidEpoch,
    #[error("height is not fresh")]
    HeightNotFresh,
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
    #[error("policy has invalid runtime")]
    PolicyInvalidRuntime,
    #[error("policy is malformed or invalid: {0}")]
    PolicyInvalid(#[from] anyhow::Error),
    #[error("policy has insufficient signatures")]
    PolicyInsufficientSignatures,
    #[error("policy hasn't been published")]
    PolicyNotPublished,
    #[error(transparent)]
    Other(anyhow::Error),
}

/// Set of trusted key manager policy signing keys.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct TrustedPolicySigners {
    /// Set of trusted signers.
    pub signers: HashSet<OasisPublicKey>,
    /// Threshold for determining if enough valid signatures are present.
    pub threshold: u64,
}

impl Default for TrustedPolicySigners {
    fn default() -> Self {
        Self {
            signers: HashSet::new(),
            threshold: 9001,
        }
    }
}

impl TrustedPolicySigners {
    /// Verify that policy has valid signatures and that enough of them are from trusted signers.
    pub fn verify<'a>(
        &self,
        signed_policy: &'a SignedPolicySGX,
    ) -> Result<&'a PolicySGX, KeyManagerError> {
        let policy = signed_policy
            .verify()
            .map_err(|err| KeyManagerError::PolicyInvalid(err.into()))?;

        self.verify_trusted_signers(signed_policy)?;

        Ok(policy)
    }

    /// Verify that policy has enough signatures from trusted signers.
    fn verify_trusted_signers(
        &self,
        signed_policy: &SignedPolicySGX,
    ) -> Result<(), KeyManagerError> {
        // Use set to remove duplicates.
        let all: HashSet<_> = signed_policy
            .signatures
            .iter()
            .map(|s| s.public_key)
            .collect();
        let trusted: HashSet<_> = self.signers.intersection(&all).collect();
        if trusted.len() < self.threshold as usize {
            return Err(KeyManagerError::PolicyInsufficientSignatures);
        }
        Ok(())
    }
}

/// Name of the `get_or_create_keys` method.
pub const METHOD_GET_OR_CREATE_KEYS: &str = "get_or_create_keys";
/// Name of the `get_public_key` method.
pub const METHOD_GET_PUBLIC_KEY: &str = "get_public_key";
/// Name of the `get_or_create_ephemeral_keys` method.
pub const METHOD_GET_OR_CREATE_EPHEMERAL_KEYS: &str = "get_or_create_ephemeral_keys";
/// Name of the `get_public_ephemeral_key` method.
pub const METHOD_GET_PUBLIC_EPHEMERAL_KEY: &str = "get_public_ephemeral_key";
/// Name of the `replicate_master_secret` method.
pub const METHOD_REPLICATE_MASTER_SECRET: &str = "replicate_master_secret";

/// Name of the `init` local method.
pub const LOCAL_METHOD_INIT: &str = "init";

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::FromIterator};

    use crypto::signature::{PublicKey as OasisPublicKey, SignatureBundle};
    use oasis_core_runtime::{common::crypto, consensus::keymanager::SignedPolicySGX};

    use crate::TrustedPolicySigners;

    #[test]
    fn test_trusted_policy_signers() {
        // Prepare data for tests.
        let public_keys = vec![
            OasisPublicKey::from(
                "af2c61c73142d1718fb51a7e151680ab4fea5ed0a95108e4e9d6719a6ef6186e",
            ), // trusted
            OasisPublicKey::from(
                "2b87e78e941cccca2222dd30fca04dee45d7e652da907d607b0971422c1bde1f",
            ), // trusted
            OasisPublicKey::from(
                "2c1378defc5a1d932c18c87008e6d33e6fcfed33312fa3224de4e3d7fcc3251c",
            ), // trusted
            OasisPublicKey::from(
                "235ca1d91ed078a3568018bef563edfb3503afa6434dbdee8310ab6fe2df50a7",
            ),
            OasisPublicKey::from(
                "17504048e11cbc8bc164785379f993f1a6934c3a9f10a78b178b59e85cd7c4c4",
            ),
        ];
        let signatures = vec![
            SignatureBundle {
                public_key: public_keys[1], // trusted
                ..Default::default()
            },
            SignatureBundle {
                public_key: public_keys[2], // trusted
                ..Default::default()
            },
            SignatureBundle {
                public_key: public_keys[3],
                ..Default::default()
            },
            SignatureBundle {
                public_key: public_keys[4],
                ..Default::default()
            },
        ];
        let trusted_signers = TrustedPolicySigners {
            signers: HashSet::from_iter(vec![public_keys[0], public_keys[1], public_keys[2]]),
            threshold: 2,
        };

        // Happy path, enough trust (2/3).
        let policy = SignedPolicySGX {
            signatures: signatures[..].to_vec(),
            ..Default::default()
        };
        trusted_signers
            .verify_trusted_signers(&policy)
            .expect("policy should be trusted");

        // Not enough trust (1/3).
        let policy = SignedPolicySGX {
            signatures: signatures[1..].to_vec(),
            ..Default::default()
        };
        trusted_signers
            .verify_trusted_signers(&policy)
            .expect_err("policy should not be trusted");

        // Multiple signatures from the same signer.
        let policy = SignedPolicySGX {
            signatures: vec![
                signatures[0].clone(),
                signatures[0].clone(),
                signatures[0].clone(),
            ],
            ..Default::default()
        };
        trusted_signers
            .verify_trusted_signers(&policy)
            .expect_err("policy should not be trusted");
    }
}
