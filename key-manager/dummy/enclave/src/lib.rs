extern crate bincode;
extern crate byteorder;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde_cbor;
extern crate sodalite;

extern crate ekiden_core;
extern crate ekiden_keymanager_api;
extern crate ekiden_keymanager_common;
extern crate ekiden_trusted;

extern crate ring;
extern crate untrusted;

use byteorder::{BigEndian, WriteBytesExt};

use ekiden_core::{bytes::{B512, H256},
                  error::{Error, Result},
                  hash,
                  signature::{InMemorySigner, Signer}};
use ekiden_keymanager_api::{with_api, GetOrCreateKeyRequest, GetOrCreateKeyResponse};
use ekiden_keymanager_common::PublicKeyType;
use ekiden_trusted::enclave::enclave_init;
use ekiden_trusted::rpc::create_enclave_rpc;
use ekiden_trusted::rpc::request::Request;

mod key_store;
use key_store::KeyStore;

use ring::signature;

enclave_init!();

// Create enclave RPC handlers.
with_api! {
    create_enclave_rpc!(api);
}

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

pub fn get_public_key(request: &Request<GetOrCreateKeyRequest>) -> Result<GetOrCreateKeyResponse> {
    let mut response = GetOrCreateKeyResponse::new();
    // Query the key store.
    {
        let key_store = KeyStore::get();
        let key = key_store.get_public_key(H256::try_from(request.get_contract_id())?)?;
        // Expired keys are not implemented yet, so allow this key to be valid as long as possible.
        let timestamp = std::u64::MAX;
        let signature = sign_public_key(key, timestamp)?;

        response.set_key(serde_cbor::to_vec(&key)?);
        response.set_timestamp(timestamp);
        response.set_signature(serde_cbor::to_vec(&signature)?);
    }

    Ok(response)
}

fn sign_public_key(public_key: PublicKeyType, timestamp: u64) -> Result<B512> {
    let signer = dummy_signer()?;
    let digest = public_key_digest(public_key, timestamp);
    Ok(signer.sign(&digest))
}

fn public_key_digest(public_key: PublicKeyType, timestamp: u64) -> H256 {
    let mut hash_data = public_key.to_vec();
    hash_data.write_u64::<BigEndian>(timestamp).unwrap();
    hash::from_bytes(hash_data.as_slice())
}

/// Returns a dummy signer used by the KeyManager to sign public keys.
/// Public Key: 0x51d5e24342ae2c4a951e24a2ba45a68106bcb7986198817331889264fd10f1bf
///
/// This should be replaced as part of the following issue:
/// https://github.com/oasislabs/ekiden/issues/1291
fn dummy_signer() -> Result<InMemorySigner> {
    let pkc8s = [
        48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 255, 135, 103, 97, 49, 33, 200,
        139, 130, 186, 54, 177, 83, 2, 162, 146, 160, 234, 231, 218, 124, 160, 72, 113, 26, 177,
        100, 40, 135, 129, 195, 50, 161, 35, 3, 33, 0, 81, 213, 226, 67, 66, 174, 44, 74, 149, 30,
        36, 162, 186, 69, 166, 129, 6, 188, 183, 152, 97, 152, 129, 115, 49, 136, 146, 100, 253,
        16, 241, 191,
    ];
    let pkc8s_input = untrusted::Input::from(&pkc8s);
    let keypair = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkc8s_input)
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
        test_sign_public_key(TEST_PUBLIC_KEY, 0, true, |_signature: &mut B512| {});
    }

    #[test]
    fn test_sign_public_key_one_timestamp() {
        test_sign_public_key(TEST_PUBLIC_KEY, 1, true, |_signature: &mut B512| {});
    }

    #[test]
    fn test_sign_public_key_max_timestamp() {
        test_sign_public_key(
            TEST_PUBLIC_KEY,
            std::u64::MAX,
            true,
            |_signature: &mut B512| {},
        );
    }

    #[test]
    fn test_sign_public_key_failure() {
        test_sign_public_key(
            TEST_PUBLIC_KEY,
            std::u64::MAX,
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
        timestamp: u64,
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
