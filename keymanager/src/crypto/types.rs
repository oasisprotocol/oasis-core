use std::sync::Arc;

use anyhow::Result;
use rand::{rngs::OsRng, Rng};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use oasis_core_runtime::{
    common::{
        crypto::{
            signature::{self, Signature, Signer},
            x25519,
        },
        namespace::Namespace,
    },
    consensus::beacon::EpochTime,
    impl_bytes,
};

impl_bytes!(KeyPairId, 32, "A 256-bit key pair identifier.");

/// Context used for the public key signature.
const PUBLIC_KEY_SIGNATURE_CONTEXT: &[u8] = b"oasis-core/keymanager: pk signature";

/// Maximum age of a signed ephemeral public key in the number of epochs.
const MAX_SIGNED_EPHEMERAL_PUBLIC_KEY_AGE: EpochTime = 10;

/// The size of the key manager state checksum.
const CHECKSUM_SIZE: usize = 32;

/// The size of the key manager state encryption key.
pub const STATE_KEY_SIZE: usize = 32;

/// The size of the key manager master and ephemeral secrets.
pub const SECRET_SIZE: usize = 32;

/// A state encryption key.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize, ZeroizeOnDrop)]
#[cbor(transparent)]
pub struct StateKey(pub [u8; STATE_KEY_SIZE]);

impl AsRef<[u8]> for StateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A 256-bit secret.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize, ZeroizeOnDrop)]
#[cbor(transparent)]
pub struct Secret(pub [u8; SECRET_SIZE]);

impl Secret {
    pub fn generate() -> Self {
        let mut rng = OsRng {};
        let mut secret = Secret::default();
        rng.fill(&mut secret.0);

        secret
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A secret with a checksum of the preceding secret.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct VerifiableSecret {
    /// Secret.
    pub secret: Secret,
    /// Checksum of the preceding secret.
    pub checksum: Vec<u8>,
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
        let sk = x25519::PrivateKey::generate();
        let pk = x25519::PublicKey::from(&sk);

        let mut rng = OsRng {};
        let mut state_key = StateKey::default();
        rng.fill(&mut state_key.0);

        KeyPair::new(pk, sk, state_key, vec![])
    }

    /// Create a `KeyPair`.
    pub fn new(
        pk: x25519::PublicKey,
        sk: x25519::PrivateKey,
        state_key: StateKey,
        checksum: Vec<u8>,
    ) -> Self {
        Self {
            input_keypair: InputKeyPair { pk, sk },
            state_key,
            checksum,
        }
    }

    /// Create a `KeyPair` with only the public key.
    pub fn from_public_key(pk: x25519::PublicKey, checksum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair {
                pk,
                ..Default::default()
            },
            checksum,
            ..Default::default()
        }
    }
}

#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct InputKeyPair {
    /// Public key.
    pub pk: x25519::PublicKey,
    /// Private key.
    pub sk: x25519::PrivateKey,
}

/// Signed public key error.
#[derive(Error, Debug)]
enum SignedPublicKeyError {
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("current epoch required")]
    CurrentEpochRequired,
    #[error("signature from the future")]
    SignatureFromFuture,
    #[error("signature expired")]
    SignatureExpired,
}

/// Signed public key.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedPublicKey {
    /// Public key.
    pub key: x25519::PublicKey,
    /// Checksum of the key manager state.
    pub checksum: Vec<u8>,
    /// Sign(sk, (key || checksum || runtime id || key pair id || epoch || expiration epoch)) from
    /// the key manager.
    pub signature: Signature,
    /// Expiration epoch.
    #[cbor(optional)]
    pub expiration: Option<EpochTime>,
}

impl SignedPublicKey {
    /// Create a new signed public key.
    pub fn new(
        key: x25519::PublicKey,
        checksum: Vec<u8>,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
        signer: &Arc<dyn Signer>,
    ) -> Result<Self> {
        if checksum.len() != CHECKSUM_SIZE {
            return Err(SignedPublicKeyError::InvalidChecksum.into());
        }

        let expiration = epoch.map(|epoch| epoch + MAX_SIGNED_EPHEMERAL_PUBLIC_KEY_AGE);
        let body = Self::body(key, &checksum, runtime_id, key_pair_id, epoch, expiration);
        let signature = signer.sign(PUBLIC_KEY_SIGNATURE_CONTEXT, &body)?;

        Ok(SignedPublicKey {
            key,
            checksum,
            signature,
            expiration,
        })
    }

    /// Verify the signature.
    pub fn verify(
        &self,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
        now: Option<EpochTime>,
        pk: &signature::PublicKey,
    ) -> Result<()> {
        // Checksum validation.
        if self.checksum.len() != CHECKSUM_SIZE {
            return Err(SignedPublicKeyError::InvalidChecksum.into());
        }

        // Cache validation for ephemeral keys.
        if let Some(epoch) = epoch {
            let now = now.ok_or(SignedPublicKeyError::CurrentEpochRequired)?;
            if now < epoch {
                return Err(SignedPublicKeyError::SignatureFromFuture.into());
            }
        }
        if let Some(expiration) = self.expiration {
            let now = now.ok_or(SignedPublicKeyError::CurrentEpochRequired)?;
            if now > expiration {
                return Err(SignedPublicKeyError::SignatureExpired.into());
            }
        }

        let body = Self::body(
            self.key,
            &self.checksum,
            runtime_id,
            key_pair_id,
            epoch,
            self.expiration,
        );

        self.signature
            .verify(pk, PUBLIC_KEY_SIGNATURE_CONTEXT, &body)
    }

    fn body(
        key: x25519::PublicKey,
        checksum: &[u8],
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
        expiration: Option<EpochTime>,
    ) -> Vec<u8> {
        let mut body = key.0.as_bytes().to_vec();
        body.extend_from_slice(checksum);
        body.extend_from_slice(runtime_id.as_ref());
        body.extend_from_slice(key_pair_id.as_ref());
        if let Some(epoch) = epoch {
            body.extend_from_slice(&epoch.to_be_bytes());
        }
        if let Some(expiration) = expiration {
            body.extend_from_slice(&expiration.to_be_bytes());
        }
        body
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use oasis_core_runtime::{
        common::{
            crypto::{
                signature::{self, Signer},
                x25519,
            },
            namespace::Namespace,
        },
        consensus::beacon::EpochTime,
    };

    use crate::crypto::{
        types::MAX_SIGNED_EPHEMERAL_PUBLIC_KEY_AGE, KeyPairId, Secret, SignedPublicKey, StateKey,
        SECRET_SIZE, STATE_KEY_SIZE,
    };

    #[test]
    fn test_signed_public_key_with_epoch() {
        test_signed_public_key(Some(10), Some(15))
    }

    #[test]
    fn test_signed_public_key_without_epoch() {
        test_signed_public_key(None, None)
    }

    fn test_signed_public_key(epoch: Option<EpochTime>, now: Option<EpochTime>) {
        let sk = Arc::new(signature::PrivateKey::from_test_seed("seed".to_string()));
        let pk = sk.public_key();

        let key = x25519::PublicKey::from([1u8; 32]);
        let checksum = [1u8; 32].to_vec();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![1u8; 32]);
        let signer: Arc<dyn Signer> = sk;

        // Create a signature with invalid checksum.
        let result = SignedPublicKey::new(
            key,
            [2u8; 30].to_vec(),
            runtime_id,
            key_pair_id,
            epoch,
            &signer,
        );
        assert!(
            result.is_err(),
            "signing public key with invalid checksum should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid checksum");

        // Create a signature.
        let result = SignedPublicKey::new(key, checksum, runtime_id, key_pair_id, epoch, &signer);
        assert!(result.is_ok(), "signing public key should work");
        let signed_pk = result.unwrap();

        // Verify the signature.
        let result = signed_pk.verify(runtime_id, key_pair_id, epoch, now, &pk);
        assert!(result.is_ok(), "verification should succeed");

        // Verify the signature with different runtime id.
        let result = signed_pk.verify(Namespace::from(vec![2u8; 32]), key_pair_id, epoch, now, &pk);
        assert!(
            result.is_err(),
            "verification with different runtime id should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid signature");

        // Verify the signature with different key pair id.
        let result = signed_pk.verify(runtime_id, KeyPairId::from(vec![2u8; 32]), epoch, now, &pk);
        assert!(
            result.is_err(),
            "verification with different key pair id should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid signature");

        // Verify the signature with different values of epoch.
        match epoch {
            Some(epoch) => {
                // Verify the signature with different epoch.
                let result = signed_pk.verify(runtime_id, key_pair_id, Some(epoch + 1), now, &pk);
                assert!(
                    result.is_err(),
                    "verification with different epoch should fail"
                );
                assert_eq!(result.unwrap_err().to_string(), "invalid signature");

                // Verify the signature after it expires.
                let result = signed_pk.verify(
                    runtime_id,
                    key_pair_id,
                    Some(epoch),
                    Some(epoch + MAX_SIGNED_EPHEMERAL_PUBLIC_KEY_AGE + 1),
                    &pk,
                );
                assert!(
                    result.is_err(),
                    "verification of expired signature should fail"
                );
                assert_eq!(result.unwrap_err().to_string(), "signature expired");

                // Verify the signature with epoch from the future.
                let result =
                    signed_pk.verify(runtime_id, key_pair_id, Some(epoch), Some(epoch - 1), &pk);
                assert!(
                    result.is_err(),
                    "verification with epoch from the future should fail"
                );
                assert_eq!(result.unwrap_err().to_string(), "signature from the future");

                // Verify the signature without epoch.
                let result = signed_pk.verify(runtime_id, key_pair_id, None, now, &pk);
                assert!(result.is_err(), "verification without epoch should fail");
                assert_eq!(result.unwrap_err().to_string(), "invalid signature");

                // Verify the signature without current epoch.
                let result = signed_pk.verify(runtime_id, key_pair_id, Some(epoch), None, &pk);
                assert!(
                    result.is_err(),
                    "verification without current epoch should fail"
                );
                assert_eq!(result.unwrap_err().to_string(), "current epoch required");
            }
            None => {
                // Verify the signature with epoch.
                let result = signed_pk.verify(runtime_id, key_pair_id, Some(1), Some(1), &pk);
                assert!(result.is_err(), "verification with an epoch should fail");
                assert_eq!(result.unwrap_err().to_string(), "invalid signature");
            }
        };

        // Verify the signature with different key.
        let invalid_signed_pk = SignedPublicKey {
            key: x25519::PublicKey::from([2u8; 32]),
            checksum: signed_pk.checksum.clone(),
            signature: signed_pk.signature.clone(),
            expiration: signed_pk.expiration,
        };
        let result = invalid_signed_pk.verify(runtime_id, key_pair_id, epoch, now, &pk);
        assert!(
            result.is_err(),
            "verification with different key should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid signature");

        // Verify the signature with different checksum.
        let invalid_signed_pk = SignedPublicKey {
            key: signed_pk.key.clone(),
            checksum: [2u8; 32].to_vec(),
            signature: signed_pk.signature.clone(),
            expiration: signed_pk.expiration,
        };
        let result = invalid_signed_pk.verify(runtime_id, key_pair_id, epoch, now, &pk);
        assert!(
            result.is_err(),
            "verification with different checksum should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid signature");

        // Verify the signature with invalid checksum.
        let invalid_signed_pk = SignedPublicKey {
            key: signed_pk.key.clone(),
            checksum: [1u8; 30].to_vec(),
            signature: signed_pk.signature.clone(),
            expiration: signed_pk.expiration,
        };
        let result = invalid_signed_pk.verify(runtime_id, key_pair_id, epoch, now, &pk);
        assert!(
            result.is_err(),
            "verification with invalid checksum should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid checksum");

        // Verify the signature with different expiration epoch.
        let invalid_signed_pk = SignedPublicKey {
            key: signed_pk.key.clone(),
            checksum: signed_pk.checksum.clone(),
            signature: signed_pk.signature.clone(),
            expiration: Some(100),
        };
        let result = invalid_signed_pk.verify(runtime_id, key_pair_id, epoch, Some(15), &pk);
        assert!(
            result.is_err(),
            "verification with different expiration epoch should fail"
        );
        assert_eq!(result.unwrap_err().to_string(), "invalid signature");
    }

    #[test]
    fn test_zeroize_on_drop() {
        // Prepare secret and state key.
        let secret_ptr;
        let state_key_ptr;
        {
            let secret = Secret([10; SECRET_SIZE]);
            secret_ptr = secret.0.as_ptr();

            let state_key = StateKey([20; STATE_KEY_SIZE]);
            state_key_ptr = state_key.0.as_ptr();
        }

        // Access the elements of the secret and the state key using pointer
        // arithmetic and verify that they are all zero.
        unsafe {
            for i in 0..SECRET_SIZE {
                assert_eq!(*secret_ptr.add(i), 0);
            }
            for i in 0..STATE_KEY_SIZE {
                assert_eq!(*state_key_ptr.add(i), 0);
            }
        }
    }
}
