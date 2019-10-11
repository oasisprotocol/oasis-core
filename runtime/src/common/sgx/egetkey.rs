//! SGX per-CPU package sealing key accessor.

use sgx_isa::Keypolicy;
use sp800_185::KMac;

#[cfg(target_env = "sgx")]
use sgx_isa::{Keyname, Keyrequest};
#[cfg(target_env = "sgx")]
use tiny_keccak::sha3_256;

// This crate is not portable due to dependencies, even when using the mock
// key derivation:
//
//  * sp800_185 relies on tiny_keccak, which as of 1.4.2, will produce
//    incorrect results on big endian targets, and will crash on any
//    architecture that requires aligned 64 bit loads and stores.
#[cfg(not(target_arch = "x86_64"))]
error!("Only x86_64 is supported");

#[cfg(not(target_env = "sgx"))]
const MOCK_MRENCLAVE_KEY: &[u8] = b"Ekiden Test MRENCLAVE KEY";
#[cfg(not(target_env = "sgx"))]
const MOCK_MRSIGNER_KEY: &[u8] = b"Ekiden Test MRSIGNER KEY";
#[cfg(not(target_env = "sgx"))]
const MOCK_KDF_CUSTOM: &[u8] = b"Ekiden Extract Test SGX Seal Key";

const SEAL_KDF_CUSTOM: &[u8] = b"Ekiden Expand SGX Seal Key";

#[cfg(target_env = "sgx")]
fn egetkey_impl(key_policy: Keypolicy, context: &[u8]) -> [u8; 16] {
    let mut req = Keyrequest::default();

    req.keyname = Keyname::Seal as u16;
    req.keypolicy = key_policy;
    req.keyid = sha3_256(context);
    // Fucking sgx_isa::Attributes doesn't have a -> [u64;2].
    req.attributemask[0] = 1 | 2 | 4; // SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT
    req.attributemask[1] = 3; // SGX_XFRM_LEGACY

    match req.egetkey() {
        Err(e) => panic!("EGETKEY failed: {:?}", e),
        Ok(k) => k,
    }
}

#[cfg(not(target_env = "sgx"))]
fn egetkey_impl(key_policy: Keypolicy, context: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];

    // Deterministically generate a test master key from the context.
    let mut kdf = match key_policy {
        Keypolicy::MRENCLAVE => KMac::new_kmac256(MOCK_MRENCLAVE_KEY, MOCK_KDF_CUSTOM),
        Keypolicy::MRSIGNER => KMac::new_kmac256(MOCK_MRSIGNER_KEY, MOCK_KDF_CUSTOM),
        _ => panic!("Invalid key_policy"),
    };
    kdf.update(&context);
    kdf.finalize(&mut k);

    k
}

/// egetkey returns a 256 bit key suitable for sealing secrets to the
/// enclave in cold storage, derived from the results of the `EGETKEY`
/// instruction.  The `context` field a domain separation tag.
///
/// Note: The key can also be used for other things (eg: as an X25519
/// private key).
pub fn egetkey(key_policy: Keypolicy, context: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];

    // Obtain the per-CPU package SGX sealing key, with the requested
    // policy.
    let master_secret = egetkey_impl(key_policy, context);

    // Expand the 128 bit EGETKEY result into a 256 bit key, suitable
    // for use with our MRAE primitives.
    let mut kdf = KMac::new_kmac256(&master_secret, SEAL_KDF_CUSTOM);
    kdf.update(&context);
    kdf.finalize(&mut k);

    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_egetkey() {
        // Ensure key policies works.
        let mr_signer_key = egetkey(Keypolicy::MRSIGNER, b"MRSIGNER");
        assert!(mr_signer_key != [0u8; 32]);
        let mr_enclave_key = egetkey(Keypolicy::MRENCLAVE, b"MRENCLAVE");
        assert!(mr_enclave_key != [0u8; 32]);
        assert!(mr_signer_key != mr_enclave_key);

        // Ensure the context does something.
        let a_key = egetkey(Keypolicy::MRENCLAVE, b"Context A");
        let b_key = egetkey(Keypolicy::MRENCLAVE, b"Context B");
        assert!(a_key != b_key);

        // Ensure determinism.
        let aa_key = egetkey(Keypolicy::MRENCLAVE, b"Context A");
        assert!(a_key == aa_key);
    }
}
