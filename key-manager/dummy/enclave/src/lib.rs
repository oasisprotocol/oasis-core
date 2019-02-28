extern crate bincode;
extern crate byteorder;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde_cbor;
extern crate sodalite;
#[cfg(not(target_env = "sgx"))]
use std::sync::Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;

extern crate ekiden_core;
extern crate ekiden_keymanager_api;
extern crate ekiden_keymanager_common;
extern crate ekiden_trusted;

extern crate ring;
extern crate untrusted;

use byteorder::{BigEndian, WriteBytesExt};

use ekiden_core::{
    bytes::{B512, H256},
    error::Result,
    hash,
    signature::{InMemorySigner, Signer},
};
use ekiden_keymanager_api::{with_api, GetOrCreateKeyRequest, GetOrCreateKeyResponse};
use ekiden_keymanager_common::PublicKeyType;
use ekiden_trusted::{
    enclave::enclave_init,
    rpc::{create_enclave_rpc, request::Request},
};

mod key_store;
use key_store::KeyStore;

use ring::signature;

enclave_init!();

// Create enclave RPC handlers.
with_api! {
    create_enclave_rpc!(api);
}

// We have not implemented key-expiry yet. So give all keys the maximum expiry of 2^53-1
// because (as a convenience) that is the maximum safe number to use in JavaScript and its
// more than enough to account for enough time.
static MAX_KEY_TIMESTAMP: u64 = (1 << 53) - 1;

pub fn get_or_create_keys(
    request: &Request<GetOrCreateKeyRequest>,
) -> Result<GetOrCreateKeyResponse> {
    let mut response = GetOrCreateKeyResponse::new();
    // Query the key store.
    {
        let mut key_store = KeyStore::get();
        // TODO: verify MR_ENCLAVE in a meaningful way. See #694.
        let _mr_enclave = request.get_client_mr_enclave();

        let keys = key_store.get_or_create_keys(H256::try_from(request.get_contract_id())?)?;
        response.set_key(serde_cbor::to_vec(&keys)?);
    }

    Ok(response)
}

pub fn get_public_key(
    request: &Request<GetOrCreateKeyRequest>,
) -> Result<Option<GetOrCreateKeyResponse>> {
    let mut response = GetOrCreateKeyResponse::new();
    // Query the key store.
    {
        let key_store = KeyStore::get();
        let key = match key_store.get_public_key(H256::try_from(request.get_contract_id())?)? {
            Some(key) => key,
            None => return Ok(None),
        };
        // Expired keys are not implemented yet, so allow this key to be valid as long as possible.
        let timestamp = MAX_KEY_TIMESTAMP;
        let signature = sign_public_key(key, Some(timestamp))?;

        response.set_key(serde_cbor::to_vec(&key)?);
        response.set_timestamp(timestamp);
        response.set_signature(serde_cbor::to_vec(&signature)?);
    }

    Ok(Some(response))
}

pub fn long_term_public_key(
    request: &Request<GetOrCreateKeyRequest>,
) -> Result<Option<GetOrCreateKeyResponse>> {
    let mut response = GetOrCreateKeyResponse::new();
    {
        let key_store = KeyStore::get();
        let key = match key_store.get_public_key(H256::try_from(request.get_contract_id())?)? {
            Some(key) => key,
            None => return Ok(None),
        };
        let signature = sign_public_key(key, None)?;

        response.set_key(serde_cbor::to_vec(&key)?);
        response.set_signature(serde_cbor::to_vec(&signature)?);
    }
    Ok(Some(response))
}

/// ECALL, see edl
#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn set_internal_keys(internal_keys: *const u8, internal_keys_length: usize) {
    let internal_keys_buf =
        unsafe { std::slice::from_raw_parts(internal_keys, internal_keys_length) };
    let internal_keys: ekiden_keymanager_common::DummyInternalKeys =
        serde_cbor::from_slice(internal_keys_buf).unwrap();

    key_store::KeyStore::get().set_encryption_key(internal_keys.keystore_encryption_key);

    *(SIGNER_KEY_PKCS8.lock().unwrap()) = internal_keys.signing_key;
}

fn sign_public_key(public_key: PublicKeyType, timestamp: Option<u64>) -> Result<B512> {
    let signer = dummy_signer()?;
    let digest = public_key_digest(public_key, timestamp);
    Ok(signer.sign(&digest))
}

fn public_key_digest(public_key: PublicKeyType, timestamp: Option<u64>) -> H256 {
    let mut hash_data = public_key.to_vec();
    if timestamp.is_some() {
        hash_data
            .write_u64::<BigEndian>(timestamp.unwrap())
            .unwrap();
    }
    hash::from_bytes(hash_data.as_slice())
}

/// A dummy key for use in tests where integrity is not needed.
/// Public Key: 0x9d41a874b80e39a40c9644e964f0e4f967100c91654bfd7666435fe906af060f
const UNSECRET_SIGNING_KEY_PKCS8: [u8; 85] = [
    48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 109, 124, 181, 54, 35, 91, 34, 238,
    29, 127, 17, 115, 64, 41, 135, 165, 19, 211, 246, 106, 37, 136, 149, 157, 187, 145, 157, 192,
    170, 25, 201, 141, 161, 35, 3, 33, 0, 157, 65, 168, 116, 184, 14, 57, 164, 12, 150, 68, 233,
    100, 240, 228, 249, 103, 16, 12, 145, 101, 75, 253, 118, 102, 67, 95, 233, 6, 175, 6, 15,
];

lazy_static! {
    // Global key store object.
    static ref SIGNER_KEY_PKCS8: Mutex<Vec<u8>> = Mutex::new(UNSECRET_SIGNING_KEY_PKCS8.to_vec());
}

/// Returns a dummy signer used by the KeyManager to sign public keys.
///
/// This should be replaced as part of the following issue:
/// https://github.com/oasislabs/ekiden/issues/1291
fn dummy_signer() -> Result<InMemorySigner> {
    let guard = SIGNER_KEY_PKCS8.lock().unwrap();
    let pkcs8_input = untrusted::Input::from(guard.as_slice());
    let keypair = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8_input)
        .expect("Should always derive a keypair from the given pkc8s");

    Ok(InMemorySigner::new(keypair))
}

#[cfg(test)]
mod tests {

    use super::*;
    use ekiden_core::signature::{PublicKeyVerifier, Verifier};

    // Public key the tests that will be signed by the tests (i.e., an example of
    // what would be returned by the KeyStore::get_public_key).
    static TEST_PUBLIC_KEY: PublicKeyType = [
        213, 175, 12, 152, 110, 106, 156, 206, 82, 208, 88, 3, 233, 98, 212, 177, 159, 145, 89, 5,
        222, 188, 180, 31, 53, 182, 142, 235, 201, 84, 250, 73,
    ];

    #[test]
    fn test_sign_public_key_zero_timestamp() {
        test_sign_public_key(TEST_PUBLIC_KEY, Some(0), true, |_signature: &mut B512| {});
    }

    #[test]
    fn test_sign_public_key_one_timestamp() {
        test_sign_public_key(TEST_PUBLIC_KEY, Some(1), true, |_signature: &mut B512| {});
    }

    #[test]
    fn test_sign_public_key_no_timestamp() {
        test_sign_public_key(TEST_PUBLIC_KEY, None, true, |_signature: &mut B512| {});
    }

    #[test]
    fn test_sign_public_key_max_timestamp() {
        test_sign_public_key(
            TEST_PUBLIC_KEY,
            Some(MAX_KEY_TIMESTAMP),
            true,
            |_signature: &mut B512| {},
        );
    }

    #[test]
    fn test_sign_public_key_failure() {
        test_sign_public_key(
            TEST_PUBLIC_KEY,
            Some(MAX_KEY_TIMESTAMP),
            false,
            |signature: &mut B512| {
                // Change a byte of the signature so that the verification fails.
                signature[0] = 9;
            },
        );
    }

    /// Tests that we can sign a given public key with a given timestamp and then verify
    /// the signature.
    ///
    /// `expected_result` is true if we expect the signature verification to be true.
    /// `signature_fn` is a closure taking in a mutable signature. This is used if we
    /// want to purposefully change the signature to force a failure.
    fn test_sign_public_key(
        public_key: PublicKeyType,
        timestamp: Option<u64>,
        expected_result: bool,
        signature_fn: impl Fn(&mut B512),
    ) {
        let mut signature = sign_public_key(public_key, timestamp).unwrap();
        signature_fn(&mut signature);

        let signer = dummy_signer().unwrap();
        let pk = signer.get_public_key();

        let digest = public_key_digest(public_key, timestamp);

        let verifier = PublicKeyVerifier::new(&pk);

        let result = verifier.verify(&digest, &signature, None);
        assert_eq!(result, expected_result);
    }

}
