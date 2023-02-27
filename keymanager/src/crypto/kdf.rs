//! Key Derivation Function.
use std::{
    collections::HashMap,
    convert::TryInto,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use lazy_static::lazy_static;
use lru::LruCache;
use sgx_isa::Keypolicy;
use sp800_185::{CShake, KMac};
use zeroize::Zeroize;

use oasis_core_runtime::{
    common::{
        crypto::{
            mrae::{deoxysii::DeoxysII, nonce::Nonce},
            signature::{self, PublicKey},
            x25519,
        },
        namespace::Namespace,
        sgx::egetkey::egetkey,
    },
    consensus::beacon::EpochTime,
    storage::KeyValue,
    BUILD_INFO,
};

use crate::{
    api::KeyManagerError,
    crypto::{
        pack_runtime_id_generation, unpack_encrypted_generation_nonce,
        unpack_encrypted_secret_nonce, KeyPair, KeyPairId, Secret, SignedPublicKey, StateKey,
    },
};

lazy_static! {
    // Global KDF object.
    static ref KDF: Kdf = Kdf::new();

    static ref CHECKSUM_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-validate-master-secret",
            false => b"ekiden-validate-master-secret-insecure",
        }
    };

    static ref RUNTIME_KDF_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-runtime-secret",
            false => b"ekiden-derive-runtime-secret-insecure",
        }
    };

    static ref RUNTIME_XOF_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-contract-keys",
            false => b"ekiden-derive-contract-keys-insecure",
        }
    };

    static ref EPHEMERAL_KDF_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-ephemeral-secret",
            false => b"ekiden-derive-ephemeral-secret-insecure",
        }
    };

    static ref EPHEMERAL_XOF_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-ephemeral-keys",
            false => b"ekiden-derive-ephemeral-keys-insecure",
        }
    };

    static ref CHECKSUM_MASTER_SECRET_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-checksum-master-secret",
            false => b"ekiden-checksum-master-secret-insecure",
        }
    };

    static ref CHECKSUM_EPHEMERAL_SECRET_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-checksum-ephemeral-secret",
            false => b"ekiden-checksum-ephemeral-secret-insecure",
        }
    };

    static ref RUNTIME_SIGNING_KEY_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-signing-key",
            false => b"ekiden-derive-signing-key-insecure",
        }
    };
}

const LATEST_GENERATION_STORAGE_KEY: &[u8] = b"keymanager_master_secret_generation";
const MASTER_SECRET_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_master_secret";
const MASTER_SECRET_SEAL_CONTEXT: &[u8] = b"Ekiden Keymanager Seal master secret v0";

const MASTER_SECRET_CACHE_SIZE: usize = 20;
const EPHEMERAL_SECRET_CACHE_SIZE: usize = 20;

/// Kdf, which derives key manager keys from a master secret.
pub struct Kdf {
    inner: RwLock<Inner>,
}

struct Inner {
    /// Generation of the last master secret.
    generation: Option<u64>,
    /// Master secrets used to derive long-term runtime keys, RSK keys, etc.
    master_secrets: LruCache<u64, Secret>,
    // Ephemeral secrets used to derive ephemeral runtime keys.
    ephemeral_secrets: HashMap<EpochTime, Secret>,
    /// Checksum of the master secret and the key manager runtime ID.
    checksum: Option<Vec<u8>>,
    /// Key manager runtime ID.
    runtime_id: Option<Namespace>,
    /// Key manager committee runtime signer derived from
    /// the latest master secret and the key manager runtime ID.
    ///
    /// Used to sign derived long-term and ephemeral public runtime keys.
    signer: Option<Arc<dyn signature::Signer>>,
    /// Key manager committee public runtime signing key derived from
    /// the latest master secret and the key manager runtime ID.
    ///
    /// Used to verify derived long-term and ephemeral public runtime keys.
    signing_key: Option<signature::PublicKey>,
    /// Local cache for the long-term private keys.
    longterm_keys: LruCache<(Vec<u8>, u64), KeyPair>,
    /// Local cache for the ephemeral private keys.
    ephemeral_keys: LruCache<(Vec<u8>, EpochTime), KeyPair>,
}

impl Inner {
    fn reset(&mut self) {
        self.generation = None;
        self.master_secrets.clear();
        self.ephemeral_secrets.clear();
        self.checksum = None;
        self.runtime_id = None;
        self.signer = None;
        self.signing_key = None;
        self.longterm_keys.clear();
        self.ephemeral_keys.clear();
    }

    // Derive ephemeral or long-term keys from the given secret.
    fn derive_keys(&self, secret: Secret, xof_custom: &[u8]) -> Result<KeyPair> {
        let checksum = self.get_checksum()?;

        // Note: The `name` parameter for cSHAKE is reserved for use by NIST.
        let mut xof = CShake::new_cshake256(&[], xof_custom);
        xof.update(secret.as_ref());
        let mut xof = xof.xof();

        // State (storage) key.
        let mut k = [0u8; 32];
        xof.squeeze(&mut k);
        let state_key = StateKey(k);

        // Public/private keypair.
        xof.squeeze(&mut k);
        let sk = x25519::PrivateKey::from(k);
        k.zeroize();
        let pk = x25519::PublicKey::from(&sk);

        Ok(KeyPair::new(pk, sk, state_key, checksum))
    }

    /// Derive ephemeral secret from the key manager's ephemeral secret.
    fn derive_ephemeral_secret(
        &self,
        kdf_custom: &[u8],
        seed: &[u8],
        epoch: EpochTime,
    ) -> Result<Secret> {
        let secret = match self.ephemeral_secrets.get(&epoch) {
            Some(secret) => secret,
            None => return Err(KeyManagerError::EphemeralSecretNotFound(epoch).into()),
        };

        Self::derive_secret(secret, kdf_custom, seed)
    }

    /// Derive long-term secret from the key manager's master secret.
    fn derive_longterm_secret(
        &mut self,
        kdf_custom: &[u8],
        seed: &[u8],
        generation: u64,
    ) -> Result<Secret> {
        let secret = match self.master_secrets.get(&generation) {
            Some(secret) => secret,
            None => return Err(KeyManagerError::MasterSecretNotFound(generation).into()),
        };

        Self::derive_secret(secret, kdf_custom, seed)
    }

    fn derive_secret(secret: &Secret, kdf_custom: &[u8], seed: &[u8]) -> Result<Secret> {
        let mut k = Secret::default();

        // KMAC256(secret, seed, 32, kdf_custom)
        let mut f = KMac::new_kmac256(secret.as_ref(), kdf_custom);
        f.update(seed);
        f.finalize(&mut k.0);

        Ok(k)
    }

    fn get_checksum(&self) -> Result<Vec<u8>> {
        match self.checksum.as_ref() {
            Some(checksum) => Ok(checksum.clone()),
            None => Err(KeyManagerError::NotInitialized.into()),
        }
    }

    fn get_generation(&self) -> Result<u64> {
        match self.generation {
            Some(generation) => Ok(generation),
            None => Err(KeyManagerError::NotInitialized.into()),
        }
    }

    fn get_signing_key(&self) -> Result<signature::PublicKey> {
        match self.signing_key {
            Some(signing_key) => Ok(signing_key),
            None => Err(KeyManagerError::NotInitialized.into()),
        }
    }

    fn get_next_generation(&self) -> u64 {
        self.generation.map(|g| g + 1).unwrap_or_default()
    }

    fn get_runtime_id(&self) -> Result<Namespace> {
        match self.runtime_id {
            Some(runtime_id) => Ok(runtime_id),
            None => Err(KeyManagerError::NotInitialized.into()),
        }
    }

    fn verify_runtime_id(&self, runtime_id: &Namespace) -> Result<()> {
        let id = self
            .runtime_id
            .as_ref()
            .ok_or(KeyManagerError::NotInitialized)?;
        if runtime_id != id {
            return Err(KeyManagerError::RuntimeMismatch.into());
        }
        Ok(())
    }

    pub fn set_runtime_id(&mut self, runtime_id: Namespace) -> Result<()> {
        match self.runtime_id {
            Some(id) if id == runtime_id => (),
            Some(_) => return Err(KeyManagerError::RuntimeMismatch.into()),
            None => self.runtime_id = Some(runtime_id),
        }
        Ok(())
    }
}

impl Kdf {
    fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                generation: None,
                master_secrets: LruCache::new(NonZeroUsize::new(MASTER_SECRET_CACHE_SIZE).unwrap()),
                ephemeral_secrets: HashMap::new(),
                checksum: None,
                runtime_id: None,
                signer: None,
                signing_key: None,
                longterm_keys: LruCache::new(NonZeroUsize::new(1024).unwrap()),
                ephemeral_keys: LruCache::new(NonZeroUsize::new(128).unwrap()),
            }),
        }
    }

    /// Global KDF instance.
    pub fn global<'a>() -> &'a Kdf {
        &KDF
    }

    /// Set the runtime ID if it is not already set.
    ///
    /// If the runtime ID changes, the internal state is reset and an error is returned.
    pub fn set_runtime_id(&self, runtime_id: Namespace) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.set_runtime_id(runtime_id).map_err(|_| {
            // Whowa, the caller's idea of our runtime ID has changed,
            // something really screwed up is going on.
            inner.reset();
            KeyManagerError::StateCorrupted.into()
        })
    }

    /// Key manager runtime ID.
    pub fn runtime_id(&self) -> Option<Namespace> {
        let inner = self.inner.read().unwrap();
        inner.runtime_id
    }

    /// Next generation of the key manager master secret.
    pub fn next_generation(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.get_next_generation()
    }

    /// Status of the internal state, i.e. checksum and runtime signing key.
    ///
    /// If given checksum and generation don't match internal state,
    /// the state is reset and an error is returned.
    pub fn status(
        &self,
        runtime_id: &Namespace,
        checksum: Vec<u8>,
        generation: u64,
    ) -> Result<(Vec<u8>, PublicKey)> {
        let mut inner = self.inner.write().unwrap();
        inner.verify_runtime_id(runtime_id)?;

        let local_checksum = inner.get_checksum()?;
        if !checksum.is_empty() && local_checksum != checksum {
            // The caller provided a checksum and there was a mismatch.
            // The global key manager state disagrees with the enclave state.
            inner.reset();
            return Err(KeyManagerError::StateCorrupted.into());
        }

        let last_generation = inner.get_generation()?;
        if generation != last_generation {
            return Err(KeyManagerError::InvalidGeneration(last_generation, generation).into());
        }

        let rsk = inner.get_signing_key()?;

        Ok((local_checksum, rsk))
    }

    /// Get or create long-term keys.
    pub fn get_or_create_longterm_keys(
        &self,
        storage: &dyn KeyValue,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> Result<KeyPair> {
        // Construct a seed that must be unique for every key request.
        // Long-term keys: seed = runtime_id || key_pair_id
        let mut seed = runtime_id.as_ref().to_vec();
        seed.extend_from_slice(key_pair_id.as_ref());

        // Check to see if the cached value exists.
        let id = (seed, generation);
        let mut inner = self.inner.write().unwrap();
        if let Some(keys) = inner.longterm_keys.get(&id) {
            return Ok(keys.clone());
        };

        // Make sure the secret is loaded.
        if !inner.master_secrets.contains(&generation) {
            let secret = match Self::load_master_secret(storage, &runtime_id, generation) {
                Some(secret) => secret,
                None => {
                    inner.reset();
                    return Err(KeyManagerError::StateCorrupted.into());
                }
            };
            inner.master_secrets.push(generation, secret);
        }

        // Generate keys.
        let secret = inner.derive_longterm_secret(&RUNTIME_KDF_CUSTOM, &id.0, id.1)?;
        // FIXME: Replace KDF custom with XOF custom when possible.
        let keys = inner.derive_keys(secret, &RUNTIME_KDF_CUSTOM)?;

        // Insert into the cache.
        inner.longterm_keys.put(id, keys.clone());

        Ok(keys)
    }

    /// Get or create ephemeral keys.
    pub fn get_or_create_ephemeral_keys(
        &self,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Result<KeyPair> {
        // Construct a seed that must be unique for every key request.
        // Ephemeral keys: seed = runtime_id || key_pair_id || epoch
        let mut seed = runtime_id.as_ref().to_vec();
        seed.extend_from_slice(key_pair_id.as_ref());
        seed.extend_from_slice(epoch.to_be_bytes().as_ref()); // TODO: Remove once we transition to ephemeral secrets (how?)

        // Check to see if the cached value exists.
        let mut inner = self.inner.write().unwrap();
        let id = (seed, epoch);
        if let Some(keys) = inner.ephemeral_keys.get(&id) {
            return Ok(keys.clone());
        };

        // Generate keys.
        let secret = inner.derive_ephemeral_secret(&EPHEMERAL_KDF_CUSTOM, &id.0, id.1)?;
        let keys = inner.derive_keys(secret, &EPHEMERAL_XOF_CUSTOM)?;

        // Insert into the cache.
        inner.ephemeral_keys.put(id, keys.clone());

        Ok(keys)
    }

    /// Get the public part of the long-term key.
    pub fn get_public_longterm_key(
        &self,
        storage: &dyn KeyValue,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> Result<x25519::PublicKey> {
        let keys =
            self.get_or_create_longterm_keys(storage, runtime_id, key_pair_id, generation)?;
        Ok(keys.input_keypair.pk)
    }

    /// Get the public part of the ephemeral key.
    pub fn get_public_ephemeral_key(
        &self,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Result<x25519::PublicKey> {
        let keys = self.get_or_create_ephemeral_keys(runtime_id, key_pair_id, epoch)?;
        Ok(keys.input_keypair.pk)
    }

    /// Signs the public key using the key manager key.
    pub fn sign_public_key(
        &self,
        key: x25519::PublicKey,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
    ) -> Result<SignedPublicKey> {
        let inner = self.inner.read().unwrap();
        let checksum = inner.get_checksum()?;
        let signer = inner
            .signer
            .as_ref()
            .ok_or(KeyManagerError::NotInitialized)?;

        SignedPublicKey::new(key, checksum, runtime_id, key_pair_id, epoch, signer)
    }

    /// Replicate master secret.
    pub fn replicate_master_secret(
        &self,
        storage: &dyn KeyValue,
        generation: u64,
    ) -> Result<Secret> {
        let mut inner = self.inner.write().unwrap();

        // Replicate only generations we know.
        let last_generation = inner.get_generation()?;
        if generation > last_generation {
            return Err(KeyManagerError::GenerationFromFuture(last_generation, generation).into());
        }

        // First check the cache.
        if let Some(secret) = inner.master_secrets.get(&generation).cloned() {
            return Ok(secret);
        }

        // Then try to load it from the storage.
        // Don't update the cache as someone could be replicating old secrets.
        let runtime_id = inner.get_runtime_id()?;
        let secret = match Self::load_master_secret(storage, &runtime_id, generation) {
            Some(secret) => secret,
            None => {
                inner.reset();
                return Err(KeyManagerError::StateCorrupted.into());
            }
        };

        Ok(secret)
    }

    /// Replicate ephemeral secret.
    pub fn replicate_ephemeral_secret(&self, epoch: EpochTime) -> Result<Secret> {
        let inner = self.inner.read().unwrap();

        let secret = inner
            .ephemeral_secrets
            .get(&epoch)
            .ok_or(KeyManagerError::EphemeralSecretNotFound(epoch))?
            .clone();
        Ok(secret)
    }

    /// Save master secret to the local cache.
    fn save_master_secret(
        &self,
        runtime_id: &Namespace,
        secret: Secret,
        generation: u64,
    ) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.verify_runtime_id(runtime_id)?;

        // Master secrets need to be added in sequential order.
        let next_generation = inner.get_next_generation();
        if generation != next_generation {
            return Err(KeyManagerError::InvalidGeneration(next_generation, generation).into());
        }

        // Compute next checksum.
        let last_checksum = inner.get_checksum().unwrap_or(runtime_id.as_ref().to_vec());
        let checksum = Self::checksum_master_secret(&secret, &last_checksum);

        // Derive signing key from the latest secret.
        let rsk_secret =
            Inner::derive_secret(&secret, &RUNTIME_SIGNING_KEY_CUSTOM, runtime_id.as_ref())?;
        let sk = signature::PrivateKey::from_bytes(rsk_secret.0.to_vec());
        let pk = sk.public_key();

        // Update state.
        inner.generation = Some(generation);
        inner.checksum = Some(checksum);
        inner.signing_key = Some(pk);
        inner.signer = Some(Arc::new(sk));
        inner.master_secrets.push(generation, secret);

        Ok(())
    }

    /// Add master secret to the local cache and store it encrypted to untrusted local storage.
    pub fn add_master_secret(
        &self,
        storage: &dyn KeyValue,
        runtime_id: &Namespace,
        secret: Secret,
        generation: u64,
    ) -> Result<()> {
        // Add to the cache before storing locally to make sure that secrets are added
        // in sequential order.
        self.save_master_secret(runtime_id, secret.clone(), generation)?;

        // Update the last generation after the secret is stored to avoid problems
        // if we panic in between.
        Self::store_master_secret(storage, runtime_id, &secret, generation);
        Self::store_last_generation(storage, runtime_id, generation);

        Ok(())
    }

    /// Add ephemeral secret to the local cache.
    pub fn add_ephemeral_secret(&self, secret: Secret, epoch: EpochTime) {
        let mut inner = self.inner.write().unwrap();
        inner.ephemeral_secrets.insert(epoch, Secret(secret.0));

        // Drop the oldest secret, if we exceed the capacity.
        if inner.ephemeral_secrets.len() > EPHEMERAL_SECRET_CACHE_SIZE {
            let min = *inner
                .ephemeral_secrets
                .keys()
                .min()
                .expect("map should not be empty");
            inner.ephemeral_secrets.remove(&min);
        }
    }

    /// Load master secrets from untrusted local storage, if not loaded already.
    pub fn load_master_secrets(
        &self,
        storage: &dyn KeyValue,
        runtime_id: &Namespace,
    ) -> Result<()> {
        if self.next_generation() != 0 {
            return Ok(());
        }

        // Fetch the last generation number.
        let last_generation = match Self::load_last_generation(storage, runtime_id) {
            Some(generation) => generation,
            None => {
                // Empty storage, nothing to load.
                return Ok(());
            }
        };

        // Fetch secrets and add them to the cache.
        for generation in 0..=last_generation {
            let secret = match Kdf::load_master_secret(storage, runtime_id, generation) {
                Some(secret) => secret,
                None => {
                    // We could stop here and let the caller replicate other secrets,
                    // but we won't as this looks like a state corruption.
                    let mut inner = self.inner.write().unwrap();
                    inner.reset();
                    return Err(KeyManagerError::StateCorrupted.into());
                }
            };

            self.save_master_secret(runtime_id, secret, generation)?;
        }

        Ok(())
    }

    /// Load master secret from untrusted local storage.
    ///
    /// Loaded secrets are authenticated so there is no need to calculate and verify the checksum
    /// again. The Deoxys-II AEAD algorithm ensures that the secrets belong to the correct runtime
    /// and generation, while the consensus layer guarantees uniqueness, i.e. only one generation
    /// of the master secret can be published per key manager runtime.
    fn load_master_secret(
        untrusted_local: &dyn KeyValue,
        runtime_id: &Namespace,
        generation: u64,
    ) -> Option<Secret> {
        // Fetch the encrypted master secret if it exists.
        let mut key = MASTER_SECRET_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        let ciphertext = untrusted_local.get(key).unwrap();
        if ciphertext.is_empty() {
            return None;
        }

        let (ciphertext, nonce) = unpack_encrypted_secret_nonce(&ciphertext)
            .expect("persisted state is corrupted, invalid size");
        let additional_data = pack_runtime_id_generation(runtime_id, generation);

        // Decrypt the persisted master secret.
        let d2 = Self::new_d2();
        let plaintext = d2
            .open(&nonce, ciphertext.to_vec(), additional_data)
            .expect("persisted state is corrupted");

        Some(Secret(plaintext.try_into().unwrap()))
    }

    /// Encrypt and store the master secret to untrusted local storage.
    ///
    /// WARNING: To ensure uniqueness always verify that the master secret has been published
    /// in the consensus layer!!!
    fn store_master_secret(
        storage: &dyn KeyValue,
        runtime_id: &Namespace,
        secret: &Secret,
        generation: u64,
    ) {
        // Every secret is stored under its own key.
        let mut key = MASTER_SECRET_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        // Encrypt the master secret.
        let nonce = Nonce::generate();
        let additional_data = pack_runtime_id_generation(runtime_id, generation);
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(&nonce, secret.as_ref(), additional_data);
        ciphertext.extend_from_slice(&nonce.to_vec());

        // Persist the encrypted master secret.
        storage
            .insert(key, ciphertext)
            .expect("failed to persist master secret");
    }

    /// Load the generation of the last stored master secret from untrusted local storage.
    fn load_last_generation(untrusted_local: &dyn KeyValue, runtime_id: &Namespace) -> Option<u64> {
        // Fetch the encrypted generation if it exists.
        let key = LATEST_GENERATION_STORAGE_KEY.to_vec();
        let ciphertext = untrusted_local.get(key).unwrap();
        if ciphertext.is_empty() {
            return None;
        }

        let (ciphertext, nonce) = unpack_encrypted_generation_nonce(&ciphertext)
            .expect("persisted state is corrupted, invalid size");

        // Decrypt the persisted generation.
        let d2 = Self::new_d2();
        let plaintext = d2
            .open(&nonce, ciphertext.to_vec(), runtime_id)
            .expect("persisted state is corrupted");

        Some(u64::from_le_bytes(plaintext.try_into().unwrap()))
    }

    /// Store the generation of the last master secret to untrusted local storage.
    fn store_last_generation(
        untrusted_local: &dyn KeyValue,
        runtime_id: &Namespace,
        generation: u64,
    ) {
        // We only store the latest generation.
        let key = LATEST_GENERATION_STORAGE_KEY.to_vec();

        // Encrypt the generation.
        let nonce = Nonce::generate();
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(&nonce, generation.to_le_bytes(), runtime_id);
        ciphertext.extend_from_slice(&nonce.to_vec());

        // Persist the encrypted generation.
        untrusted_local
            .insert(key, ciphertext)
            .expect("failed to persist master secret generation");
    }

    /// Compute the checksum of the master secret.
    ///
    /// The master secret checksum is computed by successively applying the KMAC algorithm
    /// to the key manager's runtime ID, using master secret generations as the KMAC keys
    /// at each step. The checksum calculation for the n-th generation can be expressed by
    /// the formula: KMAC(gen_n, ... KMAC(gen_2, KMAC(gen_1, KMAC(gen_0, runtime_id)))).
    fn checksum_master_secret(master_secret: &Secret, last_checksum: &Vec<u8>) -> Vec<u8> {
        let mut k = [0u8; 32];

        // KMAC256(master_secret, last_checksum, 32, "ekiden-checksum-master-secret")
        let mut f = KMac::new_kmac256(master_secret.as_ref(), &CHECKSUM_MASTER_SECRET_CUSTOM);
        f.update(last_checksum);
        f.finalize(&mut k);

        k.to_vec()
    }

    /// Compute the checksum of the ephemeral secret.
    ///
    /// The ephemeral secret checksum is computed by applying the KMAC algorithm to the
    /// concatenation of the key manager's runtime ID and the epoch, using ephemeral secret
    /// as the KMAC key.
    pub fn checksum_ephemeral_secret(
        ephemeral_secret: &Secret,
        runtime_id: &Namespace,
        epoch: EpochTime,
    ) -> Vec<u8> {
        let mut k = [0u8; 32];

        // KMAC256(ephemeral_secret, kmRuntimeID, epoch, 32, "ekiden-checksum-ephemeral-secret")
        let mut f = KMac::new_kmac256(ephemeral_secret.as_ref(), &CHECKSUM_EPHEMERAL_SECRET_CUSTOM);
        f.update(runtime_id.as_ref());
        f.update(epoch.to_le_bytes().as_ref());
        f.finalize(&mut k);

        k.to_vec()
    }

    fn new_d2() -> DeoxysII {
        let mut seal_key = egetkey(Keypolicy::MRENCLAVE, MASTER_SECRET_SEAL_CONTEXT);
        let d2 = DeoxysII::new(&seal_key);
        seal_key.zeroize();

        d2
    }
}

#[cfg(test)]
mod tests {

    use std::{
        collections::{HashMap, HashSet},
        convert::TryInto,
        num::NonZeroUsize,
        panic,
        sync::{Arc, Mutex, RwLock},
    };

    use lru::LruCache;
    use rustc_hex::{FromHex, ToHex};

    use oasis_core_runtime::{
        common::{
            crypto::{signature::PrivateKey, x25519},
            namespace::{Namespace, NAMESPACE_SIZE},
        },
        consensus::beacon::EpochTime,
        storage::KeyValue,
        types::Error,
    };

    use crate::crypto::{
        kdf::{
            CHECKSUM_CUSTOM, CHECKSUM_EPHEMERAL_SECRET_CUSTOM, CHECKSUM_MASTER_SECRET_CUSTOM,
            EPHEMERAL_SECRET_CACHE_SIZE, RUNTIME_SIGNING_KEY_CUSTOM,
        },
        KeyPairId, Secret, SECRET_SIZE,
    };

    use super::{
        Inner, Kdf, EPHEMERAL_KDF_CUSTOM, EPHEMERAL_XOF_CUSTOM, RUNTIME_KDF_CUSTOM,
        RUNTIME_XOF_CUSTOM,
    };

    impl Kdf {
        fn clear_cache(&self) {
            let mut inner = self.inner.write().unwrap();
            inner.longterm_keys.clear();
            inner.ephemeral_keys.clear();
        }
    }

    impl Default for Kdf {
        fn default() -> Self {
            let mut master_secrets = LruCache::new(NonZeroUsize::new(10).unwrap());
            master_secrets.push(0, Secret([1u8; SECRET_SIZE]));
            master_secrets.push(1, Secret([2u8; SECRET_SIZE]));

            let ephemeral_secrets = HashMap::from([
                (1, Secret([1u8; SECRET_SIZE])),
                (2, Secret([2u8; SECRET_SIZE])),
            ]);

            Self {
                inner: RwLock::new(Inner {
                    generation: Some(1),
                    master_secrets,
                    ephemeral_secrets,
                    checksum: Some(vec![2u8; 32]),
                    runtime_id: Some(Namespace([3u8; 32])),
                    signer: Some(Arc::new(PrivateKey::from_bytes(vec![4u8; 32]))),
                    signing_key: Some(PrivateKey::from_bytes(vec![4u8; 32]).public_key()),
                    longterm_keys: LruCache::new(NonZeroUsize::new(1).unwrap()),
                    ephemeral_keys: LruCache::new(NonZeroUsize::new(1).unwrap()),
                }),
            }
        }
    }

    /// Untrusted key/value store which stores arbitrary binary key/value pairs in memory.
    pub struct InMemoryKeyValue {
        store: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl InMemoryKeyValue {
        pub fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    impl KeyValue for InMemoryKeyValue {
        fn get(&self, key: Vec<u8>) -> Result<Vec<u8>, Error> {
            // To mock the untrusted local key value store, we must return
            // an empty vector if the key is not found.
            let cache = self.store.lock().unwrap();
            let value = cache.get(&key).cloned().unwrap_or_default();
            Ok(value)
        }

        fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
            let mut cache = self.store.lock().unwrap();
            cache.insert(key, value);
            Ok(())
        }
    }

    #[test]
    fn key_generation_is_deterministic() {
        let kdf = Kdf::default();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![2u8; 32]);
        let generation = 0;
        let epoch = 1;

        // Long-term keys.
        kdf.clear_cache();
        let sk1 = kdf
            .get_or_create_longterm_keys(&storage, runtime_id, key_pair_id, generation)
            .expect("private key should be created");

        kdf.clear_cache();
        let sk2 = kdf
            .get_or_create_longterm_keys(&storage, runtime_id, key_pair_id, generation)
            .expect("private key should be created");

        assert_eq!(
            sk1.input_keypair.sk.0.to_bytes(),
            sk2.input_keypair.sk.0.to_bytes()
        );
        assert_eq!(sk1.input_keypair.pk.0, sk2.input_keypair.pk.0);

        // Ephemeral keys.
        kdf.clear_cache();
        let sk1 = kdf
            .get_or_create_ephemeral_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");

        kdf.clear_cache();
        let sk2 = kdf
            .get_or_create_ephemeral_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");

        assert_eq!(
            sk1.input_keypair.sk.0.to_bytes(),
            sk2.input_keypair.sk.0.to_bytes()
        );
        assert_eq!(sk1.input_keypair.pk.0, sk2.input_keypair.pk.0);
    }

    #[test]
    fn private_keys_are_unique() {
        // Default values.
        let kdf = Kdf::default();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![1u8; 32]);
        let generation = 0;
        let epoch = 1;

        // Long-terms keys should depend on runtime_id and key_pair_id.
        let sk1 = kdf
            .get_or_create_longterm_keys(&storage, runtime_id, key_pair_id, generation)
            .expect("private key should be created");
        let sk2 = kdf
            .get_or_create_longterm_keys(&storage, vec![2u8; 32].into(), key_pair_id, generation)
            .expect("private key should be created");
        let sk3 = kdf
            .get_or_create_longterm_keys(&storage, runtime_id, vec![3u8; 32].into(), generation)
            .expect("private key should be created");

        // Ephemeral keys should depend on runtime_id, key_pair_id and epoch.
        let sk4 = kdf
            .get_or_create_ephemeral_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");
        let sk5 = kdf
            .get_or_create_ephemeral_keys(vec![2u8; 32].into(), key_pair_id, epoch)
            .expect("private key should be created");
        let sk6 = kdf
            .get_or_create_ephemeral_keys(runtime_id, vec![3u8; 32].into(), epoch)
            .expect("private key should be created");
        let sk7 = kdf
            .get_or_create_ephemeral_keys(runtime_id, key_pair_id, epoch + 1)
            .expect("private key should be created");

        let keys = HashSet::from(
            [sk1, sk2, sk3, sk4, sk5, sk6, sk7].map(|sk| sk.input_keypair.sk.0.to_bytes()),
        );
        assert_eq!(7, keys.len());
    }

    #[test]
    fn private_and_public_key_match() {
        let kdf = Kdf::default();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![2u8; 32]);
        let generation = 0;
        let epoch = 1;

        // Long-term keys.
        let sk = kdf
            .get_or_create_longterm_keys(&storage, runtime_id, key_pair_id, generation)
            .expect("private key should be created");
        let pk = kdf
            .get_public_longterm_key(&storage, runtime_id, key_pair_id, generation)
            .unwrap();

        assert_eq!(sk.input_keypair.pk, pk);

        // Ephemeral keys.
        let sk = kdf
            .get_or_create_ephemeral_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");
        let pk = kdf
            .get_public_ephemeral_key(runtime_id, key_pair_id, epoch)
            .unwrap();

        assert_eq!(sk.input_keypair.pk, pk);
    }

    #[test]
    fn public_key_signature_is_valid() {
        let kdf = Kdf::default();

        let pk = x25519::PublicKey::from([1u8; 32]);
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![1u8; 32]);
        let epoch = Some(10);
        let now = Some(15);

        let sig = kdf
            .sign_public_key(pk, runtime_id, key_pair_id, epoch)
            .expect("public key should be signed");

        let mut body = pk.0.to_bytes().to_vec();
        let checksum = kdf.inner.into_inner().unwrap().checksum.unwrap();
        body.extend_from_slice(&checksum);

        let pk = PrivateKey::from_bytes(vec![4u8; 32]).public_key();
        sig.verify(runtime_id, key_pair_id, epoch, now, &pk)
            .expect("signature should be valid");
    }

    #[test]
    fn master_secret_can_be_replicated() {
        let kdf = Kdf::default();
        let storage = InMemoryKeyValue::new();

        // Happy path.
        let generation = 1;
        let secret = kdf
            .replicate_master_secret(&storage, generation)
            .expect("master secret should be replicated");
        {
            let mut inner = kdf.inner.write().unwrap();
            assert_eq!(secret.0, inner.master_secrets.get(&generation).unwrap().0);
        }

        // Generation in the future.
        let generation = 2;
        let result = kdf
            .replicate_master_secret(&storage, generation)
            .map(|s| s.0);
        assert_eq!(
            result.unwrap_err().to_string(),
            "generation is in the future: expected max 1, got 2"
        );

        // Secret loaded from the storage.
        let generation = kdf.next_generation();
        let new_secret = Secret([3u8; SECRET_SIZE]);
        {
            let mut inner = kdf.inner.write().unwrap();
            inner.generation = Some(generation);
            assert!(inner.master_secrets.get(&generation).is_none());
        }
        Kdf::store_master_secret(
            &storage,
            &kdf.runtime_id().unwrap(),
            &new_secret,
            generation,
        );

        let secret = kdf
            .replicate_master_secret(&storage, generation)
            .expect("master secret should be replicated");
        assert_eq!(secret.0, new_secret.0);
    }

    #[test]
    fn ephemeral_secret_can_be_replicated() {
        let kdf = Kdf::default();

        // Non-existing secret.
        let error = kdf
            .replicate_ephemeral_secret(100)
            .map(|_| ())
            .expect_err("ephemeral secret should not be replicated");
        assert_eq!(
            error.to_string(),
            "ephemeral secret for epoch 100 not found"
        );

        // Existing secret.
        let secret = kdf
            .replicate_ephemeral_secret(1)
            .expect("ephemeral secret should be replicated");
        let inner = kdf.inner.into_inner().unwrap();
        assert_eq!(secret.0, inner.ephemeral_secrets.get(&1).unwrap().0);
    }

    #[test]
    fn ephemeral_secret_can_be_loaded() {
        let kdf = Kdf::default();

        // Secret for epoch 1 should exist.
        kdf.inner
            .read()
            .unwrap()
            .ephemeral_secrets
            .get(&1)
            .expect("ephemeral secret for epoch 1 should exist");

        // Secret for epoch 2 should also exist.
        {
            let inner = kdf.inner.read().unwrap();
            let secret = inner
                .ephemeral_secrets
                .get(&2)
                .expect("ephemeral secret for epoch 2 should exist");
            assert_eq!(secret.0, [2; SECRET_SIZE]);
        }

        // Secret for epoch 3 should not exist.
        kdf.inner
            .read()
            .unwrap()
            .ephemeral_secrets
            .get(&3)
            .map(|_| panic!("ephemeral secret for epoch 3 should not exist"));

        // Insert enough secrets so that the oldest one is removed.
        for epoch in 1..EPHEMERAL_SECRET_CACHE_SIZE + 2 {
            kdf.add_ephemeral_secret(Secret([100; SECRET_SIZE]), epoch.try_into().unwrap());
        }

        // Secret for epoch 1 should be removed.
        kdf.inner
            .read()
            .unwrap()
            .ephemeral_secrets
            .get(&1)
            .map(|_| panic!("ephemeral secret for epoch 1 should not exist"));

        // Secret for epoch 2 should change.
        {
            let inner = kdf.inner.read().unwrap();
            let secret = inner
                .ephemeral_secrets
                .get(&2)
                .expect("ephemeral secret for epoch 2 should exist");
            assert_eq!(secret.0, [100; SECRET_SIZE]);
        }

        // Secret for epoch 3 should be inserted.
        kdf.inner
            .read()
            .unwrap()
            .ephemeral_secrets
            .get(&3)
            .expect("ephemeral secret for epoch 3 should exist");
    }

    #[test]
    fn unique_customs() {
        // All key requests must have unique customs otherwise they can
        // derivate keys from the same KMac and/or CShake!!!
        let customs: Vec<&[u8]> = vec![
            &CHECKSUM_CUSTOM,
            &RUNTIME_KDF_CUSTOM,
            &RUNTIME_XOF_CUSTOM,
            &EPHEMERAL_KDF_CUSTOM,
            &EPHEMERAL_XOF_CUSTOM,
            &CHECKSUM_MASTER_SECRET_CUSTOM,
            &CHECKSUM_EPHEMERAL_SECRET_CUSTOM,
            &RUNTIME_SIGNING_KEY_CUSTOM,
        ];
        let total = customs.len();
        let set: HashSet<&[u8]> = customs.into_iter().collect();
        assert_eq!(total, set.len());
    }

    #[test]
    fn vector_test() {
        #[derive(Default)]
        struct TestVector<'a> {
            master_secret: &'a str,
            ephemeral_secret: &'a str,
            runtime_id: &'a str,
            key_pair_id: &'a str,
            generation: u64,
            epoch: EpochTime,
            lk_sk: &'a str,
            lk_pk: &'a str,
            ek_sk: &'a str,
            ek_pk: &'a str,
        }

        let vectors = vec![
            // A random vector.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                ephemeral_secret:
                    "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                generation: 0,
                epoch: 8935419451,
                // FIXME: Replace the values when the long-term key derivation is fixed (see FIXME above).
                lk_sk: "702c5a25ff1149591cf7bca763fbe647a43939f43330a8fd331305d73e489b7c",
                lk_pk: "66013b5ad263b4fa504e8682371fbfa102d18cc1e1b811bc125603b1abc9487b",
                // lk_sk: "a009036a2a796c3bf1ae498e7055b481bc5965f9ff013c25270b1a61c8da125d",
                // lk_pk: "14dc0e45265d8bb23479b742b39528eb10bec264c5c9f74b8c2f51638f3a7239",
                ek_sk: "70b65768679884c84dc0cd406a852a15e9ab40291f23c35215d0ea402dbf5955",
                ek_pk: "0b7f41d8b1896fee21e294e1e03078ad6efd5136d1ecf8a029d83ac5e87eca38",
            },
            // Different master and ephemeral secret.
            TestVector {
                master_secret: "54083e90f05860653161bc1575765b3311f6a55d1cab84919cb1e2b02c8351ec",
                ephemeral_secret:
                    "b8092ab767ddc47cb56807d4d1fd0e66eae0b02e289d1e38d4dfa900619edc47",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                generation: 0,
                epoch: 8935419451,
                // FIXME: Replace the values when the long-term key derivation is fixed (see FIXME above).
                lk_sk: "5045ff4735a1fc7cbdb729d7cfb9349a11e664bf3198e78b9b714bf7dffe984e",
                lk_pk: "ba3de0b2d206d7c8c46c3cf82bdf7ea6a6db1c768207ed54f54d08a72c65101e",
                // lk_sk: "885c1651dc64af6965ef2ed5d690d2110cfce0353f4d263cb6e894db847d4468",
                // lk_pk: "4260efb7dcc4e5655139477e991e5a124243740644e7f937680cd015e8645d1a",
                ek_sk: "6877eab1ce46ca610a2ca3c7d5fa560049ac55ccc6e95cad3aa2ac108c3f8659",
                ek_pk: "2b11099802017aaf256631ad309c01f35647433ace0f9eb30e0059dfb1d8773d",
            },
            // Different runtime ID.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                ephemeral_secret:
                    "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                runtime_id: "1aa3e6d86c0779afde8a367dbbb025538fb77e410624ece8b25a6be9e1a5170d",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                generation: 0,
                epoch: 8935419451,
                // FIXME: Replace the values when the long-term key derivation is fixed (see FIXME above).
                lk_sk: "e03a8c8e86024934e84d61d789ae7b292a0124bd7cedb1ac740e750391936150",
                lk_pk: "09761afffa3ef10c7a62390e81bca3c217c7cde216c9660c0f69d3709439587b",
                // lk_sk: "e8c587d47625d6d7b213fcc4db3ddda295cf5bf6458165aedd293afea89f7a49",
                // lk_pk: "1733d7cd352941d2fad73d73e4bcc88ee9d94a6872a2c0ce0431ba20616eed75",
                ek_sk: "10dc53440e825f2ed1a9d584223deae2d07a0440f9dec306e7ebc81568fb6070",
                ek_pk: "f1cf258fc81c72b6bf8ce552e1f9823b0def9d0892d54083adad56a09acada61",
            },
            // Different key pair ID.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                ephemeral_secret:
                    "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "18789f16d8a8fbd75f529f0a1de3e95469eb537c283dc66eb296a6681a46c066",
                generation: 0,
                epoch: 8935419451,
                // FIXME: Replace the values when the long-term key derivation is fixed (see FIXME above).
                lk_sk: "a82089503a2b9f2804ee61dcc8ddc3c52f49be9aa6545d235ede885597d12d7a",
                lk_pk: "a0d546af1faf39e45171830d8779b1744f1b2407b3dcad5d454d1cdcfe7b7276",
                // lk_sk: "7034c6b9054b726286732bf6e8f0e8075e1d0ee3610a7fe9a188afba4fe97b6a",
                // lk_pk: "d03ff12b41e83913433c4b57d919d05c18661ef1c6ac014568ad2efc67e48f40",
                ek_sk: "905bc45eb9d1b0e543f0fe37a9d9827dd21bc02e70a538ee9a95cbb18a769f68",
                ek_pk: "ec6dc8616acfedaf9ba2a2853a4eb286befab6e7e3beda3f5bce68a344ddaa13",
            },
            // Different epoch.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                ephemeral_secret:
                    "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                generation: 0,
                epoch: 943032087,
                // FIXME: Replace the values when the long-term key derivation is fixed (see FIXME above).
                lk_sk: "702c5a25ff1149591cf7bca763fbe647a43939f43330a8fd331305d73e489b7c",
                lk_pk: "66013b5ad263b4fa504e8682371fbfa102d18cc1e1b811bc125603b1abc9487b",
                // lk_sk: "a009036a2a796c3bf1ae498e7055b481bc5965f9ff013c25270b1a61c8da125d",
                // lk_pk: "14dc0e45265d8bb23479b742b39528eb10bec264c5c9f74b8c2f51638f3a7239",
                ek_sk: "a05eaa02f85225b5618dd3bdf15984601d80558947a9a51b9c3a141f16979f6e",
                ek_pk: "026d01541e41af210cbb482de8b0a7ea772757e53bf3dbe5008e43f95db49d64",
            },
        ];

        // Values that don't effect key derivation.
        let checksum = "100246b37912e916e71ff79982b2f62be892ddf1025cde84804f67e7f5713b75";
        let runtime_id = "8000000000000000000000000000000000000000000000000000000000000000";
        let signer = "08e35ef2b23fc2d27281117f8ad3fa0cb4d52e803a070ebb20e7ac9aa8d1f84a";

        // Test all vectors.
        for v in vectors {
            let mut master_secrets = LruCache::new(NonZeroUsize::new(10).unwrap());
            master_secrets.push(
                v.generation,
                Secret(
                    v.master_secret
                        .from_hex::<Vec<u8>>()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            );

            let ephemeral_secrets = HashMap::from([(
                v.epoch,
                Secret(
                    v.ephemeral_secret
                        .from_hex::<Vec<u8>>()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            )]);

            let kdf = Kdf {
                inner: RwLock::new(Inner {
                    generation: Some(v.generation),
                    master_secrets,
                    ephemeral_secrets,
                    checksum: Some(checksum.from_hex().unwrap()),
                    runtime_id: Some(Namespace::from(runtime_id)),
                    signer: Some(Arc::new(PrivateKey::from_bytes(signer.from_hex().unwrap()))),
                    signing_key: Some(
                        PrivateKey::from_bytes(signer.from_hex().unwrap()).public_key(),
                    ),
                    longterm_keys: LruCache::new(NonZeroUsize::new(1).unwrap()),
                    ephemeral_keys: LruCache::new(NonZeroUsize::new(1).unwrap()),
                }),
            };
            let storage = InMemoryKeyValue::new();
            let runtime_id = Namespace::from(v.runtime_id);
            let key_pair_id = KeyPairId::from(v.key_pair_id);

            let lk = kdf
                .get_or_create_longterm_keys(&storage, runtime_id, key_pair_id, v.generation)
                .expect("private key should be created");

            let ek = kdf
                .get_or_create_ephemeral_keys(runtime_id, key_pair_id, v.epoch)
                .expect("private key should be created");

            assert_eq!(lk.input_keypair.sk.0.to_bytes().to_hex::<String>(), v.lk_sk);
            assert_eq!(lk.input_keypair.pk.0.to_bytes().to_hex::<String>(), v.lk_pk);
            assert_eq!(ek.input_keypair.sk.0.to_bytes().to_hex::<String>(), v.ek_sk);
            assert_eq!(ek.input_keypair.pk.0.to_bytes().to_hex::<String>(), v.ek_pk);
        }
    }

    #[test]
    fn generation_save_load() {
        let storage = InMemoryKeyValue::new();
        let generation = 1;
        let runtime_id = Namespace([2; NAMESPACE_SIZE]);

        // Empty storage.
        let result = Kdf::load_last_generation(&storage, &runtime_id);
        assert!(result.is_none());

        // Happy path.
        Kdf::store_last_generation(&storage, &runtime_id, generation);
        let loaded =
            Kdf::load_last_generation(&storage, &runtime_id).expect("generation should be loaded");
        assert_eq!(generation, loaded);

        // Decryption panics (invalid runtime ID).
        let invalid_runtime_id = Namespace([3; NAMESPACE_SIZE]);
        let result =
            panic::catch_unwind(|| Kdf::load_last_generation(&storage, &invalid_runtime_id));
        assert!(result.is_err());
    }

    #[test]
    fn master_secret_save_load() {
        let storage = InMemoryKeyValue::new();
        let secret = Secret([1; SECRET_SIZE]);
        let runtime_id = Namespace([2; NAMESPACE_SIZE]);
        let generation = 3;

        // Empty storage.
        let result = Kdf::load_master_secret(&storage, &runtime_id, generation);
        assert!(result.is_none());

        // Happy path.
        Kdf::store_master_secret(&storage, &runtime_id, &secret, generation);
        let loaded = Kdf::load_master_secret(&storage, &runtime_id, generation)
            .expect("master secret should be loaded");
        assert_eq!(secret.0, loaded.0);

        // Decryption panics (invalid runtime ID).
        let invalid_runtime_id = Namespace([3; NAMESPACE_SIZE]);
        let result = panic::catch_unwind(|| {
            Kdf::load_master_secret(&storage, &invalid_runtime_id, generation)
        });
        assert!(result.is_err());
    }

    #[test]
    fn load_master_secrets() {
        let runtime_id = Namespace([1; NAMESPACE_SIZE]);
        let master_secrets = vec![
            Secret([0; SECRET_SIZE]),
            Secret([1; SECRET_SIZE]),
            Secret([2; SECRET_SIZE]),
        ];

        let empty_storage = InMemoryKeyValue::new();
        let full_storage = InMemoryKeyValue::new();

        Kdf::store_last_generation(&full_storage, &runtime_id, 2);
        for (generation, secret) in master_secrets.iter().enumerate() {
            Kdf::store_master_secret(&full_storage, &runtime_id, secret, generation as u64);
        }

        // Happy path.
        let kdf = Kdf::new();
        kdf.set_runtime_id(runtime_id)
            .expect("runtime id should not be set");

        let result = kdf.load_master_secrets(&full_storage, &runtime_id);
        assert!(result.is_ok());

        let mut inner = kdf.inner.write().unwrap();
        assert_eq!(inner.generation.unwrap(), 2);
        assert_eq!(
            inner.checksum.clone().unwrap().to_hex::<String>(),
            "ca9b0c294056ef674c4266e267e8972df8c6b8b0b5a3a86e081ed24daf306abf"
        );
        assert_eq!(inner.master_secrets.len(), 3);
        for (generation, secret) in master_secrets.iter().enumerate() {
            let generation = generation as u64;
            let loaded = inner.master_secrets.get(&generation).cloned();
            assert_eq!(loaded.unwrap().0, secret.0);
        }

        // One master secret is missing.
        Kdf::store_last_generation(&full_storage, &runtime_id, 3);

        let kdf = Kdf::new();
        kdf.set_runtime_id(runtime_id)
            .expect("runtime id should not be set");

        let result = kdf.load_master_secrets(&full_storage, &runtime_id);
        assert_eq!(
            result.unwrap_err().to_string(),
            "key manager state corrupted"
        );

        // Empty store.
        let kdf = Kdf::new();
        let result = kdf.load_master_secrets(&empty_storage, &runtime_id);
        assert!(result.is_ok());
    }
}
