//! Wrappers for sealing secrets to the enclave in cold storage.
use anyhow::{format_err, Error};
use rand::{rngs::OsRng, Rng};
use sgx_isa::Keypolicy;
use zeroize::Zeroize;

use crate::common::{
    crypto::mrae::deoxysii::{DeoxysII, NONCE_SIZE, TAG_SIZE},
    sgx::egetkey::egetkey,
};

/// Seal a secret to the enclave.
///
/// The `context` field is a domain separation tag.
pub fn seal(key_policy: Keypolicy, context: &[u8], data: &[u8]) -> Vec<u8> {
    let mut rng = OsRng {};

    // Encrypt the raw policy.
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill(&mut nonce);
    let d2 = new_deoxysii(key_policy, context);
    let mut ciphertext = d2.seal(&nonce, data, vec![]);
    ciphertext.extend_from_slice(&nonce);

    ciphertext
}

/// Unseal a previously sealed secret to the enclave.
///
/// The `context` field is a domain separation tag.
pub fn unseal(
    key_policy: Keypolicy,
    context: &[u8],
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    let ct_len = ciphertext.len();
    if ct_len == 0 {
        return Ok(None);
    }
    if ct_len < TAG_SIZE + NONCE_SIZE {
        return Err(format_err!("ciphertext is corrupted: invalid size"));
    }
    let ct_len = ct_len - NONCE_SIZE;

    // Split the ciphertext || tag || nonce.
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&ciphertext[ct_len..]);
    let ciphertext = &ciphertext[..ct_len];

    let d2 = new_deoxysii(key_policy, context);

    match d2.open(&nonce, ciphertext.to_vec(), vec![]) {
        Ok(plaintext) => Ok(Some(plaintext)),
        Err(_) => Err(format_err!("ciphertext is corrupted")),
    }
}

/// Creates a new Deoxys-II instance initialized with an SGX sealing key derived
/// from the results of the `EGETKEY`instruction.
///
/// The `context` field is a domain separation tag.
pub fn new_deoxysii(key_policy: Keypolicy, context: &[u8]) -> DeoxysII {
    let mut seal_key = egetkey(key_policy, context);
    let d2 = DeoxysII::new(&seal_key);
    seal_key.zeroize();

    d2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal() {
        // Test different policies.
        let sealed_a = seal(Keypolicy::MRSIGNER, b"MRSIGNER", b"Mr. Signer");
        let unsealed_a = unseal(Keypolicy::MRSIGNER, b"MRSIGNER", &sealed_a);
        assert_eq!(unsealed_a.unwrap(), Some(b"Mr. Signer".to_vec()));

        let sealed_b = seal(Keypolicy::MRENCLAVE, b"MRENCLAVE", b"Mr. Enclave");
        let unsealed_b = unseal(Keypolicy::MRENCLAVE, b"MRENCLAVE", &sealed_b);
        assert_eq!(unsealed_b.unwrap(), Some(b"Mr. Enclave".to_vec()));

        // Test zero-length ciphertext.
        let unsealed_c = unseal(Keypolicy::MRENCLAVE, b"MRENCLAVE", b"");
        assert_eq!(unsealed_c.unwrap(), None);
    }

    #[test]
    fn test_incorrect_context() {
        // Test incorrect context.
        let sealed_b = seal(Keypolicy::MRENCLAVE, b"MRENCLAVE1", b"Mr. Enclave");
        let unsealed_b = unseal(Keypolicy::MRENCLAVE, b"MRENCLAVE2", &sealed_b);
        assert_eq!(unsealed_b.is_err(), true);
    }

    #[test]
    fn test_incorrect_ciphertext_a() {
        let sealed_b = seal(Keypolicy::MRENCLAVE, b"MRENCLAVE", b"Mr. Enclave");
        let unsealed_b = unseal(Keypolicy::MRENCLAVE, b"MRENCLAVE", &sealed_b[..2]);
        assert_eq!(unsealed_b.is_err(), true);
    }

    #[test]
    fn test_incorrect_ciphertext_b() {
        let mut sealed_b = seal(Keypolicy::MRENCLAVE, b"MRENCLAVE", b"Mr. Enclave");
        sealed_b[0] = sealed_b[0].wrapping_add(1);
        let unsealed_b = unseal(Keypolicy::MRENCLAVE, b"MRENCLAVE", &sealed_b);
        assert_eq!(unsealed_b.is_err(), true);
    }
}
