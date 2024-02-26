//! CHURP storage handler.
pub use std::{convert::TryInto, sync::Arc};

use anyhow::Result;
use p384::elliptic_curve::PrimeField;
use secret_sharing::vss::polynomial::BivariatePolynomial;
use sgx_isa::Keypolicy;

use oasis_core_runtime::{
    common::{
        crypto::mrae::nonce::{Nonce, NONCE_SIZE},
        sgx::seal::new_deoxysii,
    },
    storage::KeyValue,
};

use super::Error;

/// Domain separation tag for encrypting bivariate polynomials.
const BIVARIATE_POLYNOMIAL_SEAL_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: bivariate polynomial";

/// Prefix for storage keys used to store bivariate polynomials.
const BIVARIATE_POLYNOMIAL_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_churp_bivariate_polynomial";

// CHURP storage handler.
pub struct Storage {
    // Untrusted local_storage.
    storage: Arc<dyn KeyValue>,
}

impl Storage {
    /// Creates a new CHURP storage handlers.
    pub fn new(storage: Arc<dyn KeyValue>) -> Self {
        Storage { storage }
    }

    // Loads and decrypts a bivariate polynomial.
    pub fn load_bivariate_polynomial<Fp>(
        &self,
        churp_id: u8,
        round: u64,
    ) -> Result<Option<BivariatePolynomial<Fp>>>
    where
        Fp: PrimeField,
    {
        let key = Self::create_bivariate_polynomial_key(churp_id);
        let mut ciphertext = self.storage.get(key)?;
        if ciphertext.is_empty() {
            return Ok(None);
        }

        let polynomial = Self::decrypt_bivariate_polynomial(&mut ciphertext, churp_id, round)?;
        Ok(Some(polynomial))
    }

    // Encrypts and stores the given bivariate polynomial.
    pub fn store_bivariate_polynomial<Fp>(
        &self,
        polynomial: &BivariatePolynomial<Fp>,
        churp_id: u8,
        round: u64,
    ) -> Result<()>
    where
        Fp: PrimeField,
    {
        let key = Self::create_bivariate_polynomial_key(churp_id);
        let ciphertext = Self::encrypt_bivariate_polynomial(polynomial, churp_id, round);
        self.storage.insert(key, ciphertext)?;

        Ok(())
    }

    // Encrypts and authenticates the given bivariate polynomial using
    // the provided ID and round as additional data.
    fn encrypt_bivariate_polynomial<Fp>(
        polynomial: &BivariatePolynomial<Fp>,
        churp_id: u8,
        round: u64,
    ) -> Vec<u8>
    where
        Fp: PrimeField,
    {
        let nonce = Nonce::generate();
        let plaintext = polynomial.to_bytes();
        let additional_data = Self::pack_churp_id_round(churp_id, round);
        let d2 = new_deoxysii(Keypolicy::MRENCLAVE, BIVARIATE_POLYNOMIAL_SEAL_CONTEXT);
        let mut ciphertext = d2.seal(&nonce, plaintext, additional_data);
        ciphertext.extend_from_slice(&nonce.to_vec());
        ciphertext
    }

    // Decrypts and authenticates encrypted bivariate polynomial using
    // the provided ID and round as additional data.
    fn decrypt_bivariate_polynomial<Fp>(
        ciphertext: &mut Vec<u8>,
        churp_id: u8,
        round: u64,
    ) -> Result<BivariatePolynomial<Fp>>
    where
        Fp: PrimeField,
    {
        let (ciphertext, nonce) = Self::unpack_ciphertext_with_nonce(ciphertext)?;
        let additional_data = Self::pack_churp_id_round(churp_id, round);
        let d2 = new_deoxysii(Keypolicy::MRENCLAVE, BIVARIATE_POLYNOMIAL_SEAL_CONTEXT);
        let plaintext = d2
            .open(nonce, ciphertext, additional_data)
            .map_err(|_| Error::InvalidBivariatePolynomial)?;

        BivariatePolynomial::from_bytes(plaintext).ok_or(Error::InvalidBivariatePolynomial.into())
    }

    /// Concatenates churp ID and round.
    fn create_bivariate_polynomial_key(churp_id: u8) -> Vec<u8> {
        let mut key = BIVARIATE_POLYNOMIAL_STORAGE_KEY_PREFIX.to_vec();
        key.extend(vec![churp_id]);
        key
    }

    /// Concatenates churp ID and round.
    fn pack_churp_id_round(churp_id: u8, round: u64) -> Vec<u8> {
        let mut data = vec![churp_id];
        data.extend(round.to_le_bytes());
        data
    }

    /// Unpack the concatenation of ciphertext and nonce (ciphertext || nonce).
    fn unpack_ciphertext_with_nonce(data: &mut [u8]) -> Result<(&mut [u8], &[u8; NONCE_SIZE])> {
        let mid = data
            .len()
            .checked_sub(NONCE_SIZE)
            .ok_or(Error::InvalidData)?;
        let (ciphertext, nonce) = data.split_at_mut(mid);
        let nonce: &[u8; NONCE_SIZE] = (&*nonce)
            .try_into()
            .expect("nonce should have correct length");
        Ok((ciphertext, nonce))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rand::rngs::OsRng;

    use oasis_core_runtime::storage::{KeyValue, UntrustedInMemoryStorage};

    use secret_sharing::vss::polynomial::BivariatePolynomial;

    use super::Storage;

    #[test]
    fn test_store_load_polynomial() {
        let untrusted = Arc::new(UntrustedInMemoryStorage::new());
        let storage = Storage::new(untrusted.clone());
        let polynomial = BivariatePolynomial::<p384::Scalar>::random(2, 4, &mut OsRng);
        let churp_id = 1;
        let round = 10;

        // Happy path.
        storage
            .store_bivariate_polynomial(&polynomial, churp_id, round)
            .expect("bivariate polynomial should be stored");
        let restored = storage
            .load_bivariate_polynomial::<p384::Scalar>(churp_id, round)
            .expect("bivariate polynomial should be loaded")
            .expect("bivariate polynomial should exist");
        assert_eq!(polynomial, restored);

        // Non-existing ID.
        let restored = storage
            .load_bivariate_polynomial::<p384::Scalar>(churp_id + 1, round)
            .expect("bivariate polynomial should be loaded");
        assert_eq!(None, restored);

        // Invalid round, decryption should fail.
        storage
            .load_bivariate_polynomial::<p384::Scalar>(churp_id, round + 1)
            .expect_err("decryption of bivariate polynomial should fail");

        // Manipulate local storage.
        let right_key = Storage::create_bivariate_polynomial_key(churp_id);
        let mut encrypted_polynomial = untrusted
            .get(right_key.clone())
            .expect("bivariate polynomial should be loaded");

        let wrong_key = Storage::create_bivariate_polynomial_key(churp_id + 1);
        untrusted
            .insert(wrong_key, encrypted_polynomial.clone())
            .expect("bivariate polynomial should be stored");

        encrypted_polynomial[0] += 1;
        untrusted
            .insert(right_key, encrypted_polynomial.clone())
            .expect("bivariate polynomial should be stored");

        // Invalid ID, decryption should fail.
        storage
            .load_bivariate_polynomial::<p384::Scalar>(churp_id + 1, round)
            .expect_err("decryption of bivariate polynomial should fail");

        // Corrupted ciphertext, decryption should fail.
        storage
            .load_bivariate_polynomial::<p384::Scalar>(churp_id, round)
            .expect_err("decryption of bivariate polynomial should fail");
    }

    #[test]
    fn test_encrypt_decrypt_polynomial() {
        let polynomial = BivariatePolynomial::<p384::Scalar>::random(2, 4, &mut OsRng);
        let churp_id = 1;
        let round = 10;

        // Happy path.
        let mut ciphertext = Storage::encrypt_bivariate_polynomial(&polynomial, churp_id, round);
        Storage::decrypt_bivariate_polynomial::<p384::Scalar>(&mut ciphertext, churp_id, round)
            .expect("decryption of bivariate polynomial should succeed");

        // Invalid ID, decryption should fail.
        let mut ciphertext = Storage::encrypt_bivariate_polynomial(&polynomial, churp_id, round);
        Storage::decrypt_bivariate_polynomial::<p384::Scalar>(&mut ciphertext, churp_id + 1, round)
            .expect_err("decryption of bivariate polynomial should fail");

        // Invalid round, decryption should fail.
        let mut ciphertext = Storage::encrypt_bivariate_polynomial(&polynomial, churp_id, round);
        Storage::decrypt_bivariate_polynomial::<p384::Scalar>(&mut ciphertext, churp_id, round + 1)
            .expect_err("decryption of bivariate polynomial should fail");

        // Corrupted ciphertext, decryption should fail.
        let mut ciphertext = Storage::encrypt_bivariate_polynomial(&polynomial, churp_id, round);
        ciphertext[0] += 1;
        Storage::decrypt_bivariate_polynomial::<p384::Scalar>(&mut ciphertext, churp_id, round)
            .expect_err("decryption of bivariate polynomial should fail");
    }
}
