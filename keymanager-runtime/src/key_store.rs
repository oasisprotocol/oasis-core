use byteorder::{BigEndian, WriteBytesExt};
use failure::Fallible;
use lazy_static::lazy_static;
use serde_cbor;

use ekiden_keymanager_api::{ContractId, ContractKey, PublicKey, SignedPublicKey, StateKey};
use ekiden_runtime::{
    common::crypto::signature,
    storage::{mkvs::with_encryption_key, StorageContext},
};

lazy_static! {
    // Global key store object.
    static ref KEY_STORE: KeyStore = KeyStore::new();
}

/// A dummy key for use in tests where confidentiality is not needed.
const UNSECRET_ENCRYPTION_KEY: StateKey = StateKey([
    119, 206, 190, 82, 117, 21, 62, 84, 119, 212, 117, 60, 32, 158, 183, 32, 68, 55, 131, 112, 38,
    169, 217, 219, 58, 109, 194, 211, 89, 39, 198, 204, 254, 104, 202, 114, 203, 213, 89, 44, 192,
    168, 42, 136, 220, 230, 66, 74, 197, 220, 22, 146, 84, 121, 175, 216, 144, 182, 40, 179, 6, 73,
    177, 9,
]);

/// A dummy key for use in tests where integrity is not needed.
/// Public Key: 0x9d41a874b80e39a40c9644e964f0e4f967100c91654bfd7666435fe906af060f
const UNSECRET_SIGNING_KEY_PKCS8: [u8; 85] = [
    48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 109, 124, 181, 54, 35, 91, 34, 238,
    29, 127, 17, 115, 64, 41, 135, 165, 19, 211, 246, 106, 37, 136, 149, 157, 187, 145, 157, 192,
    170, 25, 201, 141, 161, 35, 3, 33, 0, 157, 65, 168, 116, 184, 14, 57, 164, 12, 150, 68, 233,
    100, 240, 228, 249, 103, 16, 12, 145, 101, 75, 253, 118, 102, 67, 95, 233, 6, 175, 6, 15,
];

// TODO: Signing key should be bound to RAK.

/// Key store, which actually stores the key manager keys.
pub struct KeyStore {
    /// Encryption key.
    encryption_key: StateKey,
    /// Signing key.
    signing_key: signature::PrivateKey,
}

impl KeyStore {
    fn new() -> Self {
        Self {
            encryption_key: UNSECRET_ENCRYPTION_KEY,
            signing_key: signature::PrivateKey::from_pkcs8(&UNSECRET_SIGNING_KEY_PKCS8).unwrap(),
        }
    }

    /// Global key store instance.
    pub fn global<'a>() -> &'a KeyStore {
        &KEY_STORE
    }

    /// Get or create keys.
    pub fn get_or_create_keys(&self, contract_id: &ContractId) -> Fallible<ContractKey> {
        StorageContext::with_current(|_cas, mkvs| {
            with_encryption_key(mkvs, self.encryption_key.as_ref(), |mkvs| {
                match mkvs.get(contract_id.as_ref()) {
                    Some(raw_key) => {
                        Ok(serde_cbor::from_slice(&raw_key).expect("state corruption"))
                    }
                    None => {
                        let key = ContractKey::generate();
                        mkvs.insert(contract_id.as_ref(), &serde_cbor::to_vec(&key).unwrap());

                        Ok(key)
                    }
                }
            })
        })
    }

    /// Get the public part of the key.
    pub fn get_public_key(&self, contract_id: &ContractId) -> Fallible<Option<PublicKey>> {
        StorageContext::with_current(|_cas, mkvs| {
            with_encryption_key(mkvs, self.encryption_key.as_ref(), |mkvs| {
                Ok(mkvs
                    .get(contract_id.as_ref())
                    .map(|raw_key| serde_cbor::from_slice(&raw_key).expect("state corruption"))
                    .map(|key: ContractKey| key.input_keypair.get_pk()))
            })
        })
    }

    /// Signs the public key using the key manager key.
    pub fn sign_public_key(
        &self,
        key: PublicKey,
        timestamp: Option<u64>,
    ) -> Fallible<SignedPublicKey> {
        let mut body = key.as_ref().to_vec();
        if let Some(ts) = timestamp {
            body.write_u64::<BigEndian>(ts).unwrap();
        }

        Ok(SignedPublicKey {
            key,
            timestamp,
            // XXX: PUBLIC_KEY_CONTEXT not used for backward compatibility.
            signature: self.signing_key.sign(&[], &body)?,
        })
    }
}
