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
            signature, x25519,
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
        pack_runtime_id_generation, unpack_encrypted_secret_nonce, KeyPair, KeyPairId, Secret,
        SignedPublicKey, StateKey, VerifiableSecret,
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

const MASTER_SECRET_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_master_secret";
const MASTER_SECRET_CHECKSUM_STORAGE_KEY_PREFIX: &[u8] = b"keymanager_master_secret_checksum";
const MASTER_SECRET_PROPOSAL_STORAGE_KEY: &[u8] = b"keymanager_master_secret_proposal";
const MASTER_SECRET_SEAL_CONTEXT: &[u8] = b"Ekiden Keymanager Seal master secret v0";

const MASTER_SECRET_CACHE_SIZE: usize = 20;
const EPHEMERAL_SECRET_CACHE_SIZE: usize = 20;

/// KDF state.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct State {
    /// Checksum of the master secret.
    ///
    /// Empty if KDF is not initialized.
    pub checksum: Vec<u8>,
    /// Checksum of the next master secret.
    ///
    /// Empty if the proposal for the next master secret is not set.
    pub next_checksum: Vec<u8>,
    /// Key manager committee public runtime signing key.
    ///
    /// None if KDF is not initialized.
    pub signing_key: Option<signature::PublicKey>,
    /// Next key manager committee public runtime signing key.
    ///
    /// Empty if the proposal for the next master secret is not set.
    pub next_signing_key: Option<signature::PublicKey>,
}

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
    /// Checksum of the master secret.
    checksum: Option<Vec<u8>>,
    /// Checksum of the proposal for the next master secret.
    next_checksum: Option<Vec<u8>>,
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
    /// Key manager committee public runtime signing key derived from
    /// the proposal for the next master secret.
    next_signing_key: Option<signature::PublicKey>,
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

        Ok(Self::derive_secret(secret, kdf_custom, seed))
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

        Ok(Self::derive_secret(secret, kdf_custom, seed))
    }

    fn derive_secret(secret: &Secret, kdf_custom: &[u8], seed: &[u8]) -> Secret {
        let mut k = Secret::default();

        // KMAC256(secret, seed, 32, kdf_custom)
        let mut f = KMac::new_kmac256(secret.as_ref(), kdf_custom);
        f.update(seed);
        f.finalize(&mut k.0);

        k
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

    fn get_next_generation(&self) -> u64 {
        self.generation.map(|g| g + 1).unwrap_or_default()
    }

    fn verify_next_generation(&self, generation: u64) -> Result<()> {
        let next_generation = self.get_next_generation();
        if next_generation != generation {
            return Err(KeyManagerError::InvalidGeneration(next_generation, generation).into());
        }
        Ok(())
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
                next_checksum: None,
                runtime_id: None,
                signer: None,
                signing_key: None,
                next_signing_key: None,
                longterm_keys: LruCache::new(NonZeroUsize::new(1024).unwrap()),
                ephemeral_keys: LruCache::new(NonZeroUsize::new(128).unwrap()),
            }),
        }
    }

    /// Global KDF instance.
    pub fn global<'a>() -> &'a Kdf {
        &KDF
    }

    /// Initialize the KDF to ensure that its internal state is up-to-date.
    ///
    /// The state is considered up-to-date if all generations of the master secret are encrypted
    /// and stored locally, and the checksum of the last generation matches the given checksum.
    /// If this condition is not met, the internal state is reset and the KDF needs to be
    /// initialized again.
    ///
    /// WARNINGS:
    /// - Once master secrets have been persisted to disk, it is intended that manual
    /// intervention by the operator is required to remove/alter them.
    /// - The first initialization can take a very long time, especially if all generations
    /// of the master secret must be replicated from other enclaves.
    pub fn init<M>(
        &self,
        storage: &dyn KeyValue,
        runtime_id: Namespace,
        generation: u64,
        checksum: Vec<u8>,
        master_secret_fetcher: M,
    ) -> Result<State>
    where
        M: Fn(u64) -> Result<VerifiableSecret>,
    {
        // If the key manager has no secrets, nothing needs to be replicated.
        if checksum.is_empty() {
            let mut inner = self.inner.write().unwrap();
            inner.set_runtime_id(runtime_id)?;

            if inner.checksum.is_some() {
                inner.reset();
                return Err(KeyManagerError::StateCorrupted.into());
            }

            return Ok(State {
                checksum,
                next_checksum: inner.next_checksum.clone().unwrap_or_default(),
                signing_key: inner.signing_key,
                next_signing_key: inner.next_signing_key,
            });
        }

        // Fetch internal state.
        let (mut next_generation, mut curr_checksum) = {
            let mut inner = self.inner.write().unwrap();
            inner.set_runtime_id(runtime_id)?;

            let next_generation = inner.get_next_generation();
            let curr_checksum = inner.checksum.clone().unwrap_or(runtime_id.0.to_vec());
            (next_generation, curr_checksum)
        };

        // On startup load all master secrets.
        if next_generation == 0 {
            loop {
                let secret = match Self::load_master_secret(storage, &runtime_id, next_generation) {
                    Some(secret) => secret,
                    None => break,
                };

                let prev_checksum = Self::load_checksum(storage, next_generation);
                if prev_checksum != curr_checksum {
                    let mut inner = self.inner.write().unwrap();
                    inner.reset();
                    return Err(KeyManagerError::StorageCorrupted.into());
                }

                curr_checksum = Self::checksum_master_secret(&secret, &curr_checksum);
                next_generation += 1;
            }
        }

        // If only one master secret is missing, try using stored proposal.
        if next_generation == generation {
            if let Some(secret) = Self::load_master_secret_proposal(storage) {
                // Proposed secret is untrusted and needs to be verified.
                let next_checksum = Self::checksum_master_secret(&secret, &curr_checksum);

                if next_checksum == checksum {
                    Self::store_master_secret(storage, &runtime_id, &secret, generation);
                    Self::store_checksum(storage, curr_checksum, generation);

                    curr_checksum = next_checksum;
                    next_generation += 1;
                }
            }
        }

        // Load and replicate the missing master secrets in reverse order so that every secret
        // is verified against the consensus checksum before being saved.
        let mut last_checksum = checksum.clone();
        for generation in (next_generation..=generation).rev() {
            // Check the local storage first.
            let secret = Self::load_master_secret(storage, &runtime_id, generation);
            if let Some(secret) = secret {
                // Previous checksum is untrusted and needs to be verified.
                let prev_checksum = Self::load_checksum(storage, generation);
                let next_checksum = Self::checksum_master_secret(&secret, &prev_checksum);

                if next_checksum != last_checksum {
                    let mut inner = self.inner.write().unwrap();
                    inner.reset();
                    return Err(KeyManagerError::StorageCorrupted.into());
                }

                last_checksum = prev_checksum;
                continue;
            }

            // Master secret wasn't found and needs to be fetched from another enclave.
            // Fetched values are untrusted and need to be verified.
            let vs = master_secret_fetcher(generation)?;
            let (secret, prev_checksum) = match vs.checksum.is_empty() {
                true => (vs.secret, runtime_id.0.to_vec()),
                false => (vs.secret, vs.checksum),
            };
            let next_checksum = Self::checksum_master_secret(&secret, &prev_checksum);

            if next_checksum != last_checksum {
                return Err(KeyManagerError::MasterSecretChecksumMismatch.into());
            }

            Self::store_master_secret(storage, &runtime_id, &secret, generation);
            Self::store_checksum(storage, prev_checksum.clone(), generation);

            last_checksum = prev_checksum;
        }

        // Replication finished, verify the final state.
        if next_generation > generation + 1 || curr_checksum != last_checksum {
            // The caller provided a checksum and a generation and replication produced a mismatch.
            // The global key manager state disagrees with the enclave state.
            let mut inner = self.inner.write().unwrap();
            inner.reset();
            return Err(KeyManagerError::StateCorrupted.into());
        }

        // Update internal state.
        let mut inner = self.inner.write().unwrap();
        inner.set_runtime_id(runtime_id)?;

        if inner.generation != Some(generation) {
            // Derive signing key from the latest secret.
            let secret = Self::load_master_secret(storage, &runtime_id, generation)
                .ok_or(anyhow::anyhow!(KeyManagerError::StateCorrupted))?;

            let sk = Self::derive_signing_key(&runtime_id, &secret);
            let pk = sk.public_key();

            inner.generation = Some(generation);
            inner.checksum = Some(checksum);
            inner.signing_key = Some(pk);
            inner.signer = Some(Arc::new(sk));
            inner.next_checksum = None;
            inner.next_signing_key = None;
            inner.master_secrets.push(generation, secret);
        }

        Ok(State {
            checksum: inner.checksum.clone().unwrap_or_default(),
            next_checksum: inner.next_checksum.clone().unwrap_or_default(),
            signing_key: inner.signing_key,
            next_signing_key: inner.next_signing_key,
        })
    }

    /// Key manager runtime ID.
    pub fn runtime_id(&self) -> Result<Namespace> {
        let inner = self.inner.read().unwrap();
        inner.get_runtime_id()
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

        let mut inner = self.inner.write().unwrap();

        // Return only generations we know.
        let last_generation = inner.get_generation()?;
        if generation > last_generation {
            return Err(KeyManagerError::GenerationFromFuture(last_generation, generation).into());
        }

        // Check to see if the cached value exists.
        let id = (seed, generation);
        if let Some(keys) = inner.longterm_keys.get(&id) {
            return Ok(keys.clone());
        };

        // Make sure the secret is loaded.
        if !inner.master_secrets.contains(&generation) {
            let runtime_id = inner.get_runtime_id()?;
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

        let mut inner = self.inner.write().unwrap();

        // Check to see if the cached value exists.
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
        // Don't update the cache as the caller could be replicating old secrets.
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

    /// Verify the proposal for the next master secret and store it encrypted in untrusted
    /// local storage.
    pub fn add_master_secret_proposal(
        &self,
        storage: &dyn KeyValue,
        runtime_id: &Namespace,
        secret: Secret,
        generation: u64,
        checksum: &Vec<u8>,
    ) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.verify_runtime_id(runtime_id)?;
        inner.verify_next_generation(generation)?;

        let last_checksum = inner.get_checksum().unwrap_or(runtime_id.0.to_vec());
        let next_checksum = Self::checksum_master_secret(&secret, &last_checksum);
        if &next_checksum != checksum {
            return Err(KeyManagerError::MasterSecretChecksumMismatch.into());
        }

        Self::store_master_secret_proposal(storage, &secret);
        inner.next_checksum = Some(next_checksum);

        let next_signing_key = Self::derive_signing_key(runtime_id, &secret).public_key();
        inner.next_signing_key = Some(next_signing_key);

        Ok(())
    }

    /// Add ephemeral secret to the local cache.
    pub fn add_ephemeral_secret(
        &self,
        runtime_id: &Namespace,
        secret: Secret,
        epoch: EpochTime,
        checksum: &Vec<u8>,
    ) -> Result<()> {
        let expected_checksum = Self::checksum_ephemeral_secret(runtime_id, &secret, epoch);
        if &expected_checksum != checksum {
            return Err(KeyManagerError::EphemeralSecretChecksumMismatch.into());
        }

        let mut inner = self.inner.write().unwrap();
        inner.verify_runtime_id(runtime_id)?;

        // Add to the cache.
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

        Ok(())
    }

    /// Load master secret from untrusted local storage.
    ///
    /// Loaded secrets are authenticated so there is no need to calculate and verify the checksum
    /// again. The Deoxys-II AEAD algorithm ensures that the secrets belong to the correct runtime
    /// and generation, while the consensus layer guarantees uniqueness, i.e. only one generation
    /// of the master secret can be published per key manager runtime.
    fn load_master_secret(
        storage: &dyn KeyValue,
        runtime_id: &Namespace,
        generation: u64,
    ) -> Option<Secret> {
        // Fetch the encrypted master secret if it exists.
        let mut key = MASTER_SECRET_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        let ciphertext = storage.get(key).unwrap();
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
    /// WARNING: Always verify that the master secret has been published in the consensus layer!!!
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
        let mut ciphertext = d2.seal(&nonce, secret, additional_data);
        ciphertext.extend_from_slice(&nonce.to_vec());

        // Persist the encrypted master secret.
        storage
            .insert(key, ciphertext)
            .expect("failed to persist master secret");
    }

    /// Load the proposal for the next master secret from untrusted local storage.
    ///
    /// Since master secret proposals can be overwritten if not accepted by the end of the rotation
    /// period, it is impossible to know whether the loaded proposal is the latest one. Therefore,
    /// it is crucial to ALWAYS verify that the checksum of the proposal matches the one published
    /// in the consensus before accepting it.
    fn load_master_secret_proposal(storage: &dyn KeyValue) -> Option<Secret> {
        // Fetch the encrypted master secret proposal if it exists.
        let key = MASTER_SECRET_PROPOSAL_STORAGE_KEY.to_vec();

        let ciphertext = storage.get(key).unwrap();
        if ciphertext.is_empty() {
            return None;
        }

        let (ciphertext, nonce) = unpack_encrypted_secret_nonce(&ciphertext)
            .expect("persisted state is corrupted, invalid size");

        // Decrypt the persisted master secret proposal.
        let d2 = Self::new_d2();
        let plaintext = match d2.open(&nonce, ciphertext.to_vec(), vec![]) {
            Ok(plaintext) => plaintext,
            Err(_) => return None,
        };

        Some(Secret(plaintext.try_into().unwrap()))
    }

    /// Encrypt and store the next master secret proposal in untrusted local storage.
    ///
    /// If a proposal already exists, it will be overwritten.
    fn store_master_secret_proposal(storage: &dyn KeyValue, secret: &Secret) {
        // Using the same key for all proposals will override the previous one.
        let key = MASTER_SECRET_PROPOSAL_STORAGE_KEY.to_vec();

        // Encrypt the master secret.
        // Additional data has to be different from the one used when storing verified master
        // secrets so that the attacker cannot replace secrets with rejected proposals.
        // Since proposals are always verified before being accepted, confidentiality will suffice.
        let nonce = Nonce::generate();
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(&nonce, secret, vec![]);
        ciphertext.extend_from_slice(&nonce.to_vec());

        // Persist the encrypted master secret.
        storage
            .insert(key, ciphertext)
            .expect("failed to persist master secret proposal");
    }

    /// Load the master secret checksum from untrusted local storage.
    pub fn load_checksum(storage: &dyn KeyValue, generation: u64) -> Vec<u8> {
        // Fetch the checksum if it exists.
        let mut key = MASTER_SECRET_CHECKSUM_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        storage.get(key).expect("failed to fetch checksum")
    }

    /// Store the previous master secret checksum to untrusted local storage.
    fn store_checksum(storage: &dyn KeyValue, checksum: Vec<u8>, generation: u64) {
        // Every checksum is stored under its own key.
        let mut key = MASTER_SECRET_CHECKSUM_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        // Persist the checksum.
        storage
            .insert(key, checksum)
            .expect("failed to persist checksum");
    }

    /// Compute the checksum of the master secret that should follow the last know generation.
    pub fn checksum_master_secret_proposal(
        &self,
        runtime_id: Namespace,
        secret: &Secret,
        generation: u64,
    ) -> Result<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner.verify_runtime_id(&runtime_id)?;
        inner.verify_next_generation(generation)?;

        let last_checksum = inner.get_checksum().unwrap_or(runtime_id.0.to_vec());
        let next_checksum = Self::checksum_master_secret(secret, &last_checksum);

        Ok(next_checksum)
    }

    /// Compute the checksum of the master secret.
    ///
    /// The master secret checksum is computed by successively applying the KMAC algorithm
    /// to the key manager's runtime ID, using master secret generations as the KMAC keys
    /// at each step. The checksum calculation for the n-th generation can be expressed by
    /// the formula: KMAC(gen_n, ... KMAC(gen_2, KMAC(gen_1, KMAC(gen_0, runtime_id)))).
    fn checksum_master_secret(secret: &Secret, last_checksum: &Vec<u8>) -> Vec<u8> {
        let mut k = [0u8; 32];

        // KMAC256(master_secret, last_checksum, 32, "ekiden-checksum-master-secret")
        let mut f = KMac::new_kmac256(secret.as_ref(), &CHECKSUM_MASTER_SECRET_CUSTOM);
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
        runtime_id: &Namespace,
        secret: &Secret,
        epoch: EpochTime,
    ) -> Vec<u8> {
        let mut k = [0u8; 32];

        // KMAC256(ephemeral_secret, kmRuntimeID, epoch, 32, "ekiden-checksum-ephemeral-secret")
        let mut f = KMac::new_kmac256(secret.as_ref(), &CHECKSUM_EPHEMERAL_SECRET_CUSTOM);
        f.update(runtime_id.as_ref());
        f.update(epoch.to_le_bytes().as_ref());
        f.finalize(&mut k);

        k.to_vec()
    }

    fn derive_signing_key(runtime_id: &Namespace, secret: &Secret) -> signature::PrivateKey {
        let sec = Inner::derive_secret(secret, &RUNTIME_SIGNING_KEY_CUSTOM, runtime_id.as_ref());
        signature::PrivateKey::from_bytes(sec.0.to_vec())
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
        vec,
    };

    use anyhow::Result;
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

    use crate::{
        api::KeyManagerError,
        crypto::{
            kdf::{
                State, CHECKSUM_CUSTOM, CHECKSUM_EPHEMERAL_SECRET_CUSTOM,
                CHECKSUM_MASTER_SECRET_CUSTOM, EPHEMERAL_SECRET_CACHE_SIZE,
                MASTER_SECRET_CHECKSUM_STORAGE_KEY_PREFIX, MASTER_SECRET_STORAGE_KEY_PREFIX,
                RUNTIME_SIGNING_KEY_CUSTOM,
            },
            KeyPairId, Secret, VerifiableSecret, SECRET_SIZE,
        },
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
                    next_checksum: None,
                    runtime_id: Some(Namespace([3u8; 32])),
                    signer: Some(Arc::new(PrivateKey::from_bytes(vec![4u8; 32]))),
                    signing_key: Some(PrivateKey::from_bytes(vec![4u8; 32]).public_key()),
                    next_signing_key: None,
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

    /// Master secret and checksum provider.
    pub struct MasterSecretProvider {
        runtime_id: Namespace,
    }

    impl MasterSecretProvider {
        fn new(runtime_id: Namespace) -> Self {
            return Self { runtime_id };
        }

        fn fetch(&self, generation: u64) -> Result<VerifiableSecret> {
            let mut secret = Default::default();
            let mut prev_checksum = Default::default();
            let mut next_checksum = self.runtime_id.0.to_vec();

            for generation in 0..=generation {
                secret = Secret([generation as u8; SECRET_SIZE]);

                prev_checksum = next_checksum;
                next_checksum = Kdf::checksum_master_secret(&secret, &prev_checksum);
            }

            Ok(VerifiableSecret {
                secret,
                checksum: prev_checksum,
            })
        }

        fn checksum(&self, generation: u64) -> Vec<u8> {
            self.fetch(generation + 1).unwrap().checksum
        }
    }

    #[test]
    fn init_replication() {
        let kdf = Kdf::new();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let provider = MasterSecretProvider::new(runtime_id);
        let master_secret_fetcher = |generation| provider.fetch(generation);

        // No secrets.
        let result = kdf.init(&storage, runtime_id, 0, vec![], master_secret_fetcher);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state, State::default());

        // Secrets replicated from other enclaves.
        for generation in [0, 0, 1, 1, 2, 2, 5, 5] {
            let checksum = provider.checksum(generation);

            let result = kdf.init(
                &storage,
                runtime_id,
                generation,
                checksum.clone(),
                master_secret_fetcher,
            );
            assert!(result.is_ok());

            let state = result.unwrap();
            assert_eq!(state.checksum, checksum);
            assert!(state.signing_key.is_some());
            assert!(state.next_checksum.is_empty());
            assert!(state.next_signing_key.is_none());
        }

        // Secrets loaded from local storage or replicated from other enclaves.
        for generation in [5, 5, 6, 6, 10, 10] {
            let kdf = Kdf::new();
            let checksum = provider.checksum(generation);

            let result = kdf.init(
                &storage,
                runtime_id,
                generation,
                checksum.clone(),
                master_secret_fetcher,
            );
            assert!(result.is_ok());

            let state = result.unwrap();
            assert_eq!(state.checksum, checksum);
            assert!(state.signing_key.is_some());
            assert!(state.next_checksum.is_empty());
            assert!(state.next_signing_key.is_none());
        }
    }

    #[test]
    fn init_rotation() {
        let kdf = Kdf::new();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let provider = MasterSecretProvider::new(runtime_id);
        let master_secret_fetcher =
            |generation| Err(KeyManagerError::MasterSecretNotFound(generation).into());

        // KDF needs to be initialized.
        let result = kdf.init(&storage, runtime_id, 0, vec![], master_secret_fetcher);
        assert!(result.is_ok());

        // Rotate master secrets.
        for generation in 0..5 {
            let secret = provider.fetch(generation).unwrap().secret;
            let checksum = provider.checksum(generation);
            let result = kdf.add_master_secret_proposal(
                &storage,
                &runtime_id,
                secret,
                generation,
                &checksum,
            );
            assert!(result.is_ok());

            let result = kdf.init(
                &storage,
                runtime_id,
                generation,
                checksum.clone(),
                master_secret_fetcher,
            );
            assert!(result.is_ok());

            let state = result.unwrap();
            assert_eq!(state.checksum, checksum);
        }

        // Invalid proposal.
        let generation = 5;
        let secret = Secret([0; SECRET_SIZE]);
        let checksum = kdf
            .checksum_master_secret_proposal(runtime_id, &secret, generation)
            .unwrap();
        let result =
            kdf.add_master_secret_proposal(&storage, &runtime_id, secret, generation, &checksum);
        assert!(result.is_ok());

        let checksum = provider.checksum(generation);
        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum,
            master_secret_fetcher,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            KeyManagerError::MasterSecretNotFound(generation).to_string()
        );

        // Valid proposal.
        let secret = provider.fetch(generation).unwrap().secret;
        let checksum = provider.checksum(generation);
        let result =
            kdf.add_master_secret_proposal(&storage, &runtime_id, secret, generation, &checksum);
        assert!(result.is_ok());

        // Rotate master secret after restart.
        let kdf = Kdf::new();
        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.checksum, checksum);
    }

    #[test]
    fn init_corrupted_checksum() {
        let kdf = Kdf::new();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let provider = MasterSecretProvider::new(runtime_id);
        let master_secret_fetcher = |generation| provider.fetch(generation);

        // Init.
        let generation = 5;
        let checksum = provider.checksum(generation);

        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_ok());

        // Corrupt checksum.
        let mut key = MASTER_SECRET_CHECKSUM_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        storage
            .insert(key, vec![1, 2, 3])
            .expect("checksum should be inserted");

        // Init.
        let kdf = Kdf::new();
        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            KeyManagerError::StorageCorrupted.to_string()
        );
    }

    #[test]
    fn init_corrupted_secret() {
        let kdf = Kdf::new();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let provider = MasterSecretProvider::new(runtime_id);
        let master_secret_fetcher = |generation| provider.fetch(generation);

        // Init.
        let generation = 5;
        let checksum = provider.checksum(generation);

        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_ok());

        // Corrupt master secret.
        let mut key = MASTER_SECRET_STORAGE_KEY_PREFIX.to_vec();
        key.extend(generation.to_le_bytes());

        storage
            .insert(key, vec![1, 2, 3])
            .expect("secret should be inserted");

        // Init.
        let kdf = Kdf::new();
        let result = panic::catch_unwind(|| {
            kdf.init(
                &storage,
                runtime_id,
                generation,
                checksum.clone(),
                master_secret_fetcher,
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn init_invalid_generation() {
        let kdf = Kdf::new();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let provider = MasterSecretProvider::new(runtime_id);
        let master_secret_fetcher = |generation| provider.fetch(generation);

        // Init.
        let generation = 10;
        let checksum = provider.checksum(generation);

        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_ok());

        // Init with outdated generation.
        let generation = 5;
        let checksum = provider.checksum(generation);

        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            KeyManagerError::StateCorrupted.to_string()
        );
    }

    #[test]
    fn init_invalid_runtime_id() {
        let kdf = Kdf::new();
        let storage = InMemoryKeyValue::new();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let invalid_runtime_id = Namespace::from(vec![2u8; 32]);
        let provider = MasterSecretProvider::new(runtime_id);
        let master_secret_fetcher = |generation| provider.fetch(generation);

        // No secrets.
        let result = kdf.init(&storage, runtime_id, 0, vec![], master_secret_fetcher);
        assert!(result.is_ok());

        let result = kdf.init(
            &storage,
            invalid_runtime_id,
            0,
            vec![],
            master_secret_fetcher,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            KeyManagerError::RuntimeMismatch.to_string()
        );

        // Few secrets.
        let generation = 5;
        let checksum = provider.checksum(generation);

        let result = kdf.init(
            &storage,
            runtime_id,
            generation,
            checksum.clone(),
            master_secret_fetcher,
        );
        assert!(result.is_ok());

        let result = kdf.init(
            &storage,
            invalid_runtime_id,
            generation,
            checksum,
            master_secret_fetcher,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            KeyManagerError::RuntimeMismatch.to_string()
        );
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
        let generation = 2;
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
        let runtime_id = kdf.runtime_id().expect("runtime id should be set");

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
        for epoch in 1..(EPHEMERAL_SECRET_CACHE_SIZE + 2) as EpochTime {
            let secret = Secret([100; SECRET_SIZE]);
            let checksum = Kdf::checksum_ephemeral_secret(&runtime_id, &secret, epoch);
            let result = kdf.add_ephemeral_secret(&runtime_id, secret, epoch, &checksum);
            assert!(result.is_ok())
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
                    next_checksum: None,
                    runtime_id: Some(Namespace::from(runtime_id)),
                    signer: Some(Arc::new(PrivateKey::from_bytes(signer.from_hex().unwrap()))),
                    signing_key: Some(
                        PrivateKey::from_bytes(signer.from_hex().unwrap()).public_key(),
                    ),
                    next_signing_key: None,
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
    fn checksum_save_load() {
        let storage = InMemoryKeyValue::new();
        let generation = 0;
        let checksum = vec![1, 2, 3];

        // Empty storage.
        let result = Kdf::load_checksum(&storage, generation);
        assert!(result.is_empty());

        // Happy path.
        Kdf::store_checksum(&storage, checksum.clone(), generation);
        let loaded = Kdf::load_checksum(&storage, generation);
        assert_eq!(checksum, loaded);
    }

    #[test]
    fn master_secret_proposal_save_load() {
        let storage = InMemoryKeyValue::new();
        let secret = Secret([0; SECRET_SIZE]);
        let new_secret = Secret([1; SECRET_SIZE]);

        // Empty storage.
        let result = Kdf::load_master_secret_proposal(&storage);
        assert!(result.is_none());

        // Happy path.
        Kdf::store_master_secret_proposal(&storage, &secret);
        let loaded =
            Kdf::load_master_secret_proposal(&storage).expect("master secret should be loaded");
        assert_eq!(secret.0, loaded.0);

        // Overwrite the proposal and check if the last secret is kept.
        Kdf::store_master_secret_proposal(&storage, &new_secret);
        let loaded =
            Kdf::load_master_secret_proposal(&storage).expect("master secret should be loaded");
        assert_eq!(new_secret.0, loaded.0);
    }
}
