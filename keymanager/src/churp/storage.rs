//! CHURP storage handler.
pub use std::{convert::TryInto, sync::Arc};

use anyhow::Result;
use group::{ff::PrimeField, Group, GroupEncoding};
use secret_sharing::{churp::VerifiableSecretShare, poly::BivariatePolynomial};
use sgx_isa::Keypolicy;

use oasis_core_runtime::{
    common::{
        crypto::mrae::nonce::{Nonce, NONCE_SIZE},
        sgx::seal::new_deoxysii,
    },
    consensus::beacon::EpochTime,
    storage::KeyValue,
};

use super::{EncodedVerifiableSecretShare, Error};

/// Domain separation tag for encrypting bivariate polynomials for proactivization.
const BIVARIATE_POLYNOMIAL_SEAL_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: bivariate polynomial";
/// Domain separation tag for encrypting secret shares.
const SECRET_SHARE_SEAL_CONTEXT: &[u8] = b"oasis-core/keymanager/churp: secret share";

/// Prefix for storage keys used to store bivariate polynomials for proactivization.
const BIVARIATE_POLYNOMIAL_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_churp_bivariate_polynomial";
/// Prefix for storage keys used to store secret share.
const SECRET_SHARE_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_churp_secret_share";
/// Prefix for storage keys used to store secret share for the next handoff.
const NEXT_SECRET_SHARE_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_churp_next_secret_share";

/// CHURP storage handler.
pub struct Storage {
    /// Untrusted local_storage.
    storage: Arc<dyn KeyValue>,
}

impl Storage {
    /// Creates a new CHURP storage handlers.
    pub fn new(storage: Arc<dyn KeyValue>) -> Self {
        Storage { storage }
    }

    /// Loads and decrypts a bivariate polynomial.
    pub fn load_bivariate_polynomial<F: PrimeField>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<Option<BivariatePolynomial<F>>> {
        let key = Self::create_bivariate_polynomial_storage_key(churp_id);
        let mut ciphertext = self.storage.get(key)?;
        if ciphertext.is_empty() {
            return Ok(None);
        }

        let polynomial = Self::decrypt_bivariate_polynomial(&mut ciphertext, churp_id, epoch)?;
        Ok(Some(polynomial))
    }

    /// Encrypts and stores the given bivariate polynomial.
    pub fn store_bivariate_polynomial<F: PrimeField>(
        &self,
        polynomial: &BivariatePolynomial<F>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<()> {
        let key = Self::create_bivariate_polynomial_storage_key(churp_id);
        let ciphertext = Self::encrypt_bivariate_polynomial(polynomial, churp_id, epoch);
        self.storage.insert(key, ciphertext)?;

        Ok(())
    }

    /// Loads and decrypts a secret share, consisting of a polynomial
    /// and its associated verification matrix.
    pub fn load_secret_share<G: Group + GroupEncoding>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<Option<VerifiableSecretShare<G>>> {
        let key = Self::create_secret_share_storage_key(churp_id);
        let mut ciphertext = self.storage.get(key)?;
        if ciphertext.is_empty() {
            return Ok(None);
        }

        let share = Self::decrypt_secret_share(&mut ciphertext, churp_id, epoch)?;
        Ok(Some(share))
    }

    /// Encrypts and stores the provided secret share, consisting of
    /// a polynomial and its associated verification matrix.
    pub fn store_secret_share<G: Group + GroupEncoding>(
        &self,
        share: &VerifiableSecretShare<G>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<()> {
        let key = Self::create_secret_share_storage_key(churp_id);
        let ciphertext = Self::encrypt_secret_share(share, churp_id, epoch);
        self.storage.insert(key, ciphertext)?;

        Ok(())
    }

    /// Loads and decrypts the next secret share, consisting of a polynomial
    /// and its associated verification matrix.
    pub fn load_next_secret_share<G: Group + GroupEncoding>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<Option<VerifiableSecretShare<G>>> {
        let key = Self::create_next_secret_share_storage_key(churp_id);
        let mut ciphertext = self.storage.get(key)?;
        if ciphertext.is_empty() {
            return Ok(None);
        }

        let share = Self::decrypt_secret_share(&mut ciphertext, churp_id, epoch)?;
        Ok(Some(share))
    }

    /// Encrypts and stores the provided next secret share, consisting of
    /// a polynomial and its associated verification matrix.
    pub fn store_next_secret_share<G: Group + GroupEncoding>(
        &self,
        share: &VerifiableSecretShare<G>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<()> {
        let key = Self::create_next_secret_share_storage_key(churp_id);
        let ciphertext = Self::encrypt_secret_share(share, churp_id, epoch);
        self.storage.insert(key, ciphertext)?;

        Ok(())
    }

    /// Encrypts and authenticates the given bivariate polynomial
    /// using the provided ID and handoff epoch as additional data.
    fn encrypt_bivariate_polynomial<F: PrimeField>(
        polynomial: &BivariatePolynomial<F>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Vec<u8> {
        let nonce = Nonce::generate();
        let plaintext = polynomial.to_bytes();
        let additional_data = Self::pack_churp_id_epoch(churp_id, epoch);
        let d2 = new_deoxysii(Keypolicy::MRENCLAVE, BIVARIATE_POLYNOMIAL_SEAL_CONTEXT);
        let mut ciphertext = d2.seal(&nonce, plaintext, additional_data);
        ciphertext.extend_from_slice(&nonce.to_vec());
        ciphertext
    }

    /// Decrypts and authenticates encrypted bivariate polynomial
    /// using the provided ID and handoff epoch as additional data.
    fn decrypt_bivariate_polynomial<F: PrimeField>(
        ciphertext: &mut Vec<u8>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<BivariatePolynomial<F>> {
        let (ciphertext, nonce) = Self::unpack_ciphertext_with_nonce(ciphertext)?;
        let additional_data = Self::pack_churp_id_epoch(churp_id, epoch);
        let d2 = new_deoxysii(Keypolicy::MRENCLAVE, BIVARIATE_POLYNOMIAL_SEAL_CONTEXT);
        let plaintext = d2
            .open(nonce, ciphertext, additional_data)
            .map_err(|_| Error::InvalidBivariatePolynomial)?;

        BivariatePolynomial::from_bytes(plaintext)
            .ok_or(Error::BivariatePolynomialDecodingFailed.into())
    }

    /// Encrypts and authenticates the given polynomial and verification matrix
    /// using the provided ID and handoff as additional data.
    fn encrypt_secret_share<G: Group + GroupEncoding>(
        verifiable_share: &VerifiableSecretShare<G>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Vec<u8> {
        let share: EncodedVerifiableSecretShare = verifiable_share.into();
        let nonce: Nonce = Nonce::generate();
        let plaintext = cbor::to_vec(share);
        let additional_data = Self::pack_churp_id_epoch(churp_id, epoch);
        let d2 = new_deoxysii(Keypolicy::MRENCLAVE, SECRET_SHARE_SEAL_CONTEXT);
        let mut ciphertext = d2.seal(&nonce, plaintext, additional_data);
        ciphertext.extend_from_slice(&nonce.to_vec());
        ciphertext
    }

    /// Decrypts and authenticates encrypted polynomial and verification matrix
    /// using the provided ID and handoff as additional data.
    fn decrypt_secret_share<G: Group + GroupEncoding>(
        ciphertext: &mut Vec<u8>,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<VerifiableSecretShare<G>> {
        let (ciphertext, nonce) = Self::unpack_ciphertext_with_nonce(ciphertext)?;
        let additional_data = Self::pack_churp_id_epoch(churp_id, epoch);
        let d2 = new_deoxysii(Keypolicy::MRENCLAVE, SECRET_SHARE_SEAL_CONTEXT);
        let plaintext = d2
            .open(nonce, ciphertext, additional_data)
            .map_err(|_| Error::InvalidSecretShare)?;

        let encoded: EncodedVerifiableSecretShare =
            cbor::from_slice(&plaintext).map_err(|_| Error::InvalidSecretShare)?;
        let verifiable_share = encoded.try_into()?;

        Ok(verifiable_share)
    }

    /// Creates storage key for the bivariate polynomial.
    fn create_bivariate_polynomial_storage_key(churp_id: u8) -> Vec<u8> {
        let mut key = BIVARIATE_POLYNOMIAL_STORAGE_KEY_PREFIX.to_vec();
        key.extend(vec![churp_id]);
        key
    }

    /// Creates storage key for the secret share.
    fn create_secret_share_storage_key(churp_id: u8) -> Vec<u8> {
        let mut key = SECRET_SHARE_STORAGE_KEY_PREFIX.to_vec();
        key.extend(&[churp_id]);
        key
    }

    /// Creates storage key for the next secret share.
    fn create_next_secret_share_storage_key(churp_id: u8) -> Vec<u8> {
        let mut key = NEXT_SECRET_SHARE_STORAGE_KEY_PREFIX.to_vec();
        key.extend(&[churp_id]);
        key
    }

    /// Concatenates churp ID and handoff epoch.
    fn pack_churp_id_epoch(churp_id: u8, epoch: EpochTime) -> Vec<u8> {
        let mut data = vec![churp_id];
        data.extend(epoch.to_le_bytes());
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
    use std::{collections::HashSet, sync::Arc};

    use rand::{rngs::StdRng, SeedableRng};

    use oasis_core_runtime::storage::{KeyValue, UntrustedInMemoryStorage};

    use secret_sharing::{
        churp::{SecretShare, VerifiableSecretShare},
        poly, vss,
    };

    use crate::churp::storage::{
        BIVARIATE_POLYNOMIAL_SEAL_CONTEXT, BIVARIATE_POLYNOMIAL_STORAGE_KEY_PREFIX,
        NEXT_SECRET_SHARE_STORAGE_KEY_PREFIX, SECRET_SHARE_SEAL_CONTEXT,
        SECRET_SHARE_STORAGE_KEY_PREFIX,
    };

    use super::Storage;

    type PrimeField = p384::Scalar;
    type Group = p384::ProjectivePoint;
    type BivariatePolynomial = poly::BivariatePolynomial<PrimeField>;
    type VerificationMatrix = vss::VerificationMatrix<Group>;

    #[test]
    fn test_unique_seal_contexts() {
        let mut ctxs = HashSet::new();
        ctxs.insert(BIVARIATE_POLYNOMIAL_SEAL_CONTEXT);
        ctxs.insert(SECRET_SHARE_SEAL_CONTEXT);
        assert_eq!(ctxs.len(), 2);
    }

    #[test]
    fn test_unique_storage_key_prefixes() {
        let mut prefixes = HashSet::new();
        prefixes.insert(BIVARIATE_POLYNOMIAL_STORAGE_KEY_PREFIX);
        prefixes.insert(SECRET_SHARE_STORAGE_KEY_PREFIX);
        prefixes.insert(NEXT_SECRET_SHARE_STORAGE_KEY_PREFIX);
        assert_eq!(prefixes.len(), 3);
    }

    #[test]
    fn test_unique_storage_keys() {
        let churp_id = 10;
        let mut prefixes = HashSet::new();
        prefixes.insert(Storage::create_bivariate_polynomial_storage_key(churp_id));
        prefixes.insert(Storage::create_secret_share_storage_key(churp_id));
        prefixes.insert(Storage::create_next_secret_share_storage_key(churp_id));
        assert_eq!(prefixes.len(), 3);
    }

    #[test]
    fn test_store_load_bivariate_polynomial() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let untrusted = Arc::new(UntrustedInMemoryStorage::new());
        let storage = Storage::new(untrusted.clone());
        let polynomial = BivariatePolynomial::random(2, 4, &mut rng);
        let churp_id = 1;
        let epoch = 10;

        // Happy path.
        storage
            .store_bivariate_polynomial(&polynomial, churp_id, epoch)
            .expect("bivariate polynomial should be stored");
        let restored = storage
            .load_bivariate_polynomial::<PrimeField>(churp_id, epoch)
            .expect("bivariate polynomial should be loaded")
            .expect("bivariate polynomial should exist");
        assert!(polynomial == restored);

        // Non-existing ID.
        let restored = storage
            .load_bivariate_polynomial::<PrimeField>(churp_id + 1, epoch)
            .expect("bivariate polynomial should be loaded");
        assert!(None == restored);

        // Invalid epoch, decryption should fail.
        let res = storage.load_bivariate_polynomial::<PrimeField>(churp_id, epoch + 1);
        assert!(
            res.is_err(),
            "decryption of bivariate polynomial should fail"
        );

        // Manipulate local storage.
        let right_key = Storage::create_bivariate_polynomial_storage_key(churp_id);
        let mut encrypted_polynomial = untrusted
            .get(right_key.clone())
            .expect("bivariate polynomial should be loaded");

        let wrong_key = Storage::create_bivariate_polynomial_storage_key(churp_id + 1);
        untrusted
            .insert(wrong_key, encrypted_polynomial.clone())
            .expect("bivariate polynomial should be stored");

        (encrypted_polynomial[0], _) = encrypted_polynomial[0].overflowing_add(1);
        untrusted
            .insert(right_key, encrypted_polynomial.clone())
            .expect("bivariate polynomial should be stored");

        // Invalid ID, decryption should fail.
        let res = storage.load_bivariate_polynomial::<PrimeField>(churp_id + 1, epoch);
        assert!(
            res.is_err(),
            "decryption of bivariate polynomial should fail"
        );

        // Corrupted ciphertext, decryption should fail.
        let res = storage.load_bivariate_polynomial::<PrimeField>(churp_id, epoch);
        assert!(
            res.is_err(),
            "decryption of bivariate polynomial should fail"
        );
    }

    #[test]
    fn test_store_load_secret_share() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let untrusted = Arc::new(UntrustedInMemoryStorage::new());
        let storage = Storage::new(untrusted.clone());
        let x = PrimeField::from_u64(2);
        let bp = BivariatePolynomial::random(2, 4, &mut rng);
        let vm = VerificationMatrix::from(&bp);
        let p = bp.eval_x(&x);
        let share = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        let churp_id = 1;
        let epoch = 10;

        // Happy path.
        storage
            .store_secret_share(&verifiable_share, churp_id, epoch)
            .expect("secret share should be stored");
        let restored = storage
            .load_secret_share::<Group>(churp_id, epoch)
            .expect("secret share should be loaded")
            .expect("secret share should exist");
        assert!(
            verifiable_share.secret_share().polynomial() == restored.secret_share().polynomial()
        );
        assert!(verifiable_share.verification_matrix() == restored.verification_matrix());

        // Non-existing ID.
        let restored = storage
            .load_secret_share::<Group>(churp_id + 1, epoch)
            .expect("secret share should be loaded");
        assert!(restored.is_none());

        // Invalid epoch, decryption should fail.
        let res = storage.load_secret_share::<Group>(churp_id, epoch + 1);
        assert!(res.is_err(), "decryption of secret share should fail");

        // Manipulate local storage.
        let right_key = Storage::create_secret_share_storage_key(churp_id);
        let mut encrypted_share = untrusted
            .get(right_key.clone())
            .expect("secret share should be loaded");

        let wrong_key = Storage::create_secret_share_storage_key(churp_id + 1);
        untrusted
            .insert(wrong_key, encrypted_share.clone())
            .expect("secret share should be stored");

        (encrypted_share[0], _) = encrypted_share[0].overflowing_add(1);
        untrusted
            .insert(right_key, encrypted_share.clone())
            .expect("secret share should be stored");

        // Invalid ID, decryption should fail.
        let res = storage.load_secret_share::<Group>(churp_id + 1, epoch);
        assert!(res.is_err(), "decryption of secret share should fail");

        // Corrupted ciphertext, decryption should fail.
        let res = storage.load_secret_share::<Group>(churp_id, epoch);
        assert!(res.is_err(), "decryption of secret share should fail");
    }

    #[test]
    fn test_store_load_next_secret_share() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let untrusted = Arc::new(UntrustedInMemoryStorage::new());
        let storage = Storage::new(untrusted.clone());
        let x = PrimeField::from_u64(2);
        let bp = BivariatePolynomial::random(2, 4, &mut rng);
        let vm = VerificationMatrix::from(&bp);
        let p = bp.eval_x(&x);
        let share = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        let churp_id = 1;
        let epoch = 10;

        // Happy path.
        storage
            .store_next_secret_share(&verifiable_share, churp_id, epoch)
            .expect("next secret share should be stored");
        let restored = storage
            .load_next_secret_share::<Group>(churp_id, epoch)
            .expect("next secret share should be loaded")
            .expect("next secret share should exist");
        assert!(
            verifiable_share.secret_share().polynomial() == restored.secret_share().polynomial()
        );
        assert!(verifiable_share.verification_matrix() == restored.verification_matrix());

        // Non-existing ID.
        let restored = storage
            .load_next_secret_share::<Group>(churp_id + 1, epoch)
            .expect("next secret share should be loaded");
        assert!(restored.is_none());

        // Invalid epoch, decryption should fail.
        let res = storage.load_next_secret_share::<Group>(churp_id, epoch + 1);
        assert!(res.is_err(), "decryption of next secret share should fail");

        // Manipulate local storage.
        let right_key = Storage::create_next_secret_share_storage_key(churp_id);
        let mut encrypted_share = untrusted
            .get(right_key.clone())
            .expect("next secret share should be loaded");

        let wrong_key = Storage::create_next_secret_share_storage_key(churp_id + 1);
        untrusted
            .insert(wrong_key, encrypted_share.clone())
            .expect("next secret share should be stored");

        (encrypted_share[0], _) = encrypted_share[0].overflowing_add(1);
        untrusted
            .insert(right_key, encrypted_share.clone())
            .expect("next secret share should be stored");

        // Invalid ID, decryption should fail.
        let res = storage.load_next_secret_share::<Group>(churp_id + 1, epoch);
        assert!(res.is_err(), "decryption of next secret share should fail");

        // Corrupted ciphertext, decryption should fail.
        let res = storage.load_next_secret_share::<Group>(churp_id, epoch);
        assert!(res.is_err(), "decryption of next secret share should fail");
    }

    #[test]
    fn test_encrypt_decrypt_bivariate_polynomial() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let polynomial = BivariatePolynomial::random(2, 4, &mut rng);
        let churp_id = 1;
        let epoch = 10;

        // Happy path.
        let mut ciphertext = Storage::encrypt_bivariate_polynomial(&polynomial, churp_id, epoch);
        Storage::decrypt_bivariate_polynomial::<PrimeField>(&mut ciphertext, churp_id, epoch)
            .expect("decryption of bivariate polynomial should succeed");

        // Invalid ID, decryption should fail.
        let res = Storage::decrypt_bivariate_polynomial::<PrimeField>(
            &mut ciphertext,
            churp_id + 1,
            epoch,
        );
        assert!(
            res.is_err(),
            "decryption of bivariate polynomial should fail"
        );

        // Invalid handoff, decryption should fail.
        let res = Storage::decrypt_bivariate_polynomial::<PrimeField>(
            &mut ciphertext,
            churp_id,
            epoch + 1,
        );
        assert!(
            res.is_err(),
            "decryption of bivariate polynomial should fail"
        );

        // Corrupted ciphertext, decryption should fail.
        (ciphertext[0], _) = ciphertext[0].overflowing_add(1);
        let res =
            Storage::decrypt_bivariate_polynomial::<PrimeField>(&mut ciphertext, churp_id, epoch);
        assert!(
            res.is_err(),
            "decryption of bivariate polynomial should fail"
        );
    }

    #[test]
    fn test_encrypt_decrypt_secret_share() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let x = PrimeField::from_u64(2);
        let bp = BivariatePolynomial::random(2, 4, &mut rng);
        let vm = VerificationMatrix::from(&bp);
        let p = bp.eval_x(&x);
        let share = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        let churp_id = 1;
        let epoch = 10;

        // Happy path.
        let mut ciphertext = Storage::encrypt_secret_share(&verifiable_share, churp_id, epoch);
        Storage::decrypt_secret_share::<Group>(&mut ciphertext, churp_id, epoch)
            .expect("decryption of secret share should succeed");

        // Invalid ID, decryption should fail.
        let res = Storage::decrypt_secret_share::<Group>(&mut ciphertext, churp_id + 1, epoch);
        assert!(res.is_err(), "decryption of secret share should fail");

        // Invalid epoch, decryption should fail.
        let res = Storage::decrypt_secret_share::<Group>(&mut ciphertext, churp_id, epoch + 1);
        assert!(res.is_err(), "decryption of secret share should fail");

        // Corrupted ciphertext, decryption should fail.
        (ciphertext[0], _) = ciphertext[0].overflowing_add(1);
        let res = Storage::decrypt_secret_share::<Group>(&mut ciphertext, churp_id, epoch);
        assert!(res.is_err(), "decryption of secret share should fail");
    }
}
