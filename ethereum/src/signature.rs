//! Ethereum signatures.
use std::result::Result as StdResult;
use std::sync::Arc;

use constant_time_eq::constant_time_eq;
use ekiden_common::bytes::{B256, B520, H160, H256};
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::Future;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Error as SecpError, Message, RecoverableSignature, RecoveryId, SECP256K1};
use tiny_keccak::{keccak256, Keccak};
use web3;
use web3::api::Web3;
use web3::Transport;

const ETH_SIGNATURE_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";
const ETH_V_ADJ: u8 = 27;

/// Ethereum signature size in bytes.
pub const SIGNATURE_SIZE: usize = 520 / 8;

// Ethereum web3 delegated signature signer.
pub struct Web3Signer<T: Transport + Sync + Send> {
    client: Arc<Web3<T>>,
    identity: web3::types::H160,
}

impl<T: 'static + Transport + Sync + Send> Web3Signer<T>
where
    <T as web3::Transport>::Out: Send,
{
    /// Create a new Signer from a web3 client and address.
    pub fn new(client: Arc<Web3<T>>, address: &H160) -> Self {
        Self {
            client,
            identity: web3::types::H160(address.0),
        }
    }

    /// Sign given 256-bit digest, and return a web3/geth compatible signature.
    pub fn sign(&self, data: &H256) -> B520 {
        let data = web3::types::Bytes(data.to_vec());
        let f = self.client.eth().sign(self.identity, data);

        B520(f.wait().unwrap().0) // Should be near instant, API disconnect.
    }
}

// Ethereum signature signer.
pub struct Signer {
    secret_key: SecretKey,
    identity: H160,
}

impl Signer {
    /// Create a new Signer from a Ethereum private key.
    pub fn new(private_key: &B256) -> Result<Self> {
        // De-serialize the private key.
        let secret_key = match SecretKey::from_slice(&SECP256K1, &private_key.0) {
            Ok(secret_key) => secret_key,
            Err(e) => return Err(secperror_to_error(e)),
        };

        // Derive the Ethereum identity.
        let public_key = match PublicKey::from_secret_key(&SECP256K1, &secret_key) {
            Ok(public_key) => public_key,
            Err(e) => return Err(secperror_to_error(e)),
        };
        let identity = public_key_to_identity(&public_key)?;

        Ok(Self {
            secret_key,
            identity,
        })
    }

    /// Sign given 256-bit digest, and return a web3/geth compatible signature.
    pub fn sign(&self, data: &H256) -> B520 {
        // Sign.
        let message = to_geth_digest(&data).unwrap();
        let sig = (&SECP256K1)
            .sign_recoverable(&message, &self.secret_key)
            .unwrap();
        let (v, r_s) = sig.serialize_compact(&SECP256K1);
        let v: u8 = v.to_i32() as u8 + ETH_V_ADJ;
        assert!(v == ETH_V_ADJ || v == ETH_V_ADJ + 1, "Invalid recovery ID");

        // Serialize in a format that matches the web3 API.
        let mut r_s_v = [0; 65];
        r_s_v[0..64].copy_from_slice(&r_s);
        r_s_v[64] = v;

        B520::from(r_s_v)
    }

    /// Get the Ethereum identity (address).
    pub fn get_identity(&self) -> H160 {
        self.identity.clone()
    }
}

// Ethereum signature verifier.
pub struct Verifier {
    identity: H160,
}

impl Verifier {
    /// Create a new Verifier from an Ethereum public key.
    pub fn new(public_key: B520) -> Result<Self> {
        let public_key = match PublicKey::from_slice(&SECP256K1, &public_key.0) {
            Ok(public_key) => public_key,
            Err(e) => return Err(secperror_to_error(e)),
        };
        let identity = public_key_to_identity(&public_key)?;

        Ok(Self { identity })
    }

    /// Create a new Verifier from an Ethereum identity (address).
    pub fn new_from_address(address: &H160) -> Self {
        Self {
            identity: address.clone(),
        }
    }

    /// Verify signature and optional attestation.
    pub fn verify(&self, data: &H256, signature: &B520, attestation: Option<&Vec<u8>>) -> bool {
        if attestation.is_some() {
            return false;
        }

        let identity = match Verifier::recover(data, signature) {
            Ok(identity) => identity,
            Err(_) => return false,
        };
        constant_time_eq(&identity.0, &self.identity.0)
    }

    /// Recover the Ethereum identity (address) from a signature.
    pub fn recover(data: &H256, signature: &B520) -> Result<H160> {
        let public_key = match Verifier::_recover(&data, &signature) {
            Ok(public_key) => public_key,
            Err(e) => return Err(secperror_to_error(e)),
        };
        public_key_to_identity(&public_key)
    }

    fn _recover(data: &H256, signature: &B520) -> StdResult<PublicKey, SecpError> {
        let message = to_geth_digest(&data)?;
        let recovery_id = from_geth_v(signature[64])?;
        let signature =
            RecoverableSignature::from_compact(&SECP256K1, &signature[0..64], recovery_id)?;
        (&SECP256K1).recover(&message, &signature)
    }
}

fn public_key_to_identity(public_key: &PublicKey) -> Result<H160> {
    let public_key = public_key.serialize_vec(&SECP256K1, false);
    if public_key[0] != 0x04 {
        return Err(secperror_to_error(SecpError::InvalidPublicKey));
    }

    let digest = keccak256(&public_key[1..]);
    Ok(H160::from(&digest[12..]))
}

fn to_geth_digest(digest: &H256) -> StdResult<Message, SecpError> {
    // Hash with the web3/geth prefix.
    let mut h = Keccak::new_keccak256();
    h.update(ETH_SIGNATURE_PREFIX);
    h.update(digest);
    let mut message = [0; 32];
    h.finalize(&mut message);
    Message::from_slice(&message)
}

fn from_geth_v(v: u8) -> StdResult<RecoveryId, SecpError> {
    let v = match v {
        0 | ETH_V_ADJ => 0,
        1 | 28 => 1, // ETH_V_ADJ + 1, compiler complains.
        _ => return Err(SecpError::InvalidRecoveryId),
    };
    RecoveryId::from_i32(v)
}

fn secperror_to_error(err: SecpError) -> Error {
    match err {
        SecpError::IncapableContext => Error::new("Incapable context"),
        SecpError::IncorrectSignature => Error::new("Incorrect signature"),
        SecpError::InvalidMessage => Error::new("Invalid message"),
        SecpError::InvalidPublicKey => Error::new("Invalid public key"),
        SecpError::InvalidSignature => Error::new("Invalid signature"),
        SecpError::InvalidSecretKey => Error::new("invalid secret key"),
        SecpError::InvalidRecoveryId => Error::new("Invalid recovery ID"),
    }
}
