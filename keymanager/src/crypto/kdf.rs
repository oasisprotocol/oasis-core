//! Key Derivation Function.
use std::{
    convert::TryInto,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    vec,
};

use anyhow::Result;
use io_context::Context as IoContext;
use lazy_static::lazy_static;
use lru::LruCache;
use rand::{rngs::OsRng, Rng};
use sgx_isa::Keypolicy;
use sp800_185::{CShake, KMac};
use zeroize::Zeroize;

use oasis_core_runtime::{
    common::{
        crypto::{
            mrae::deoxysii::{DeoxysII, NONCE_SIZE, TAG_SIZE},
            signature::{self, Signer},
            x25519,
        },
        namespace::Namespace,
        sgx::egetkey::egetkey,
    },
    consensus::beacon::EpochTime,
    enclave_rpc::Context as RpcContext,
    runtime_context,
    storage::KeyValue,
    BUILD_INFO,
};

use crate::{
    api::{InitRequest, InitResponse, KeyManagerError, SignedInitResponse},
    client::{KeyManagerClient, RemoteClient},
    crypto::{KeyPair, Secret, SignedPublicKey, StateKey},
    policy::Policy,
    runtime::context::Context as KmContext,
};

use super::KeyPairId;

/// Context used for the init response signature.
const INIT_RESPONSE_CONTEXT: &[u8] = b"oasis-core/keymanager: init response";

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

    static ref RUNTIME_CHECKSUM_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-checksum-master-secret",
            false => b"ekiden-checksum-master-secret-insecure",
        }
    };

    static ref RUNTIME_SIGNING_KEY_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-signing-key",
            false => b"ekiden-derive-signing-key-insecure",
        }
    };
}

const MASTER_SECRET_STORAGE_KEY: &[u8] = b"keymanager_master_secret";
const MASTER_SECRET_STORAGE_SIZE: usize = 32 + TAG_SIZE + NONCE_SIZE;
const MASTER_SECRET_SEAL_CONTEXT: &[u8] = b"Ekiden Keymanager Seal master secret v0";

/// Kdf, which derives key manager keys from a master secret.
pub struct Kdf {
    inner: RwLock<Inner>,
}

struct Inner {
    /// Master secret.
    master_secret: Option<Secret>,
    /// Checksum of the master secret and the key manager runtime ID.
    checksum: Option<Vec<u8>>,
    /// Key manager runtime ID.
    runtime_id: Option<Namespace>,
    /// Key manager committee signer derived from the master secret and
    /// the key manager runtime ID.
    ///
    /// Used to sign derived long-term and ephemeral public runtime keys.
    signer: Option<Arc<dyn signature::Signer>>,
    /// Cache for storing derived key pairs.
    cache: LruCache<Vec<u8>, KeyPair>,
}

impl Inner {
    fn reset(&mut self) {
        self.master_secret = None;
        self.checksum = None;
        self.runtime_id = None;
        self.signer = None;
        self.cache.clear();
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

    /// Derive ephemeral secret from the master secret.
    fn derive_ephemeral_secret(&self, kdf_custom: &[u8], seed: &[u8]) -> Result<Secret> {
        let secret = match self.master_secret.as_ref() {
            Some(secret) => secret,
            None => return Err(KeyManagerError::NotInitialized.into()),
        };

        Self::derive_secret(secret, kdf_custom, seed)
    }

    /// Derive long-term secret from the master secret.
    fn derive_static_secret(&self, kdf_custom: &[u8], seed: &[u8]) -> Result<Secret> {
        let secret = match self.master_secret.as_ref() {
            Some(secret) => secret,
            None => return Err(KeyManagerError::NotInitialized.into()),
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
}

impl Kdf {
    fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                master_secret: None,
                checksum: None,
                runtime_id: None,
                signer: None,
                cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
            }),
        }
    }

    /// Global KDF instance.
    pub fn global<'a>() -> &'a Kdf {
        &KDF
    }

    /// Initialize the KDF internal state.
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    pub fn init(
        &self,
        req: &InitRequest,
        ctx: &mut RpcContext,
        policy_checksum: Vec<u8>,
    ) -> Result<SignedInitResponse> {
        let mut inner = self.inner.write().unwrap();

        let rctx = runtime_context!(ctx, KmContext);
        if inner.runtime_id.is_some() {
            // Whowa, the caller's idea of our runtime ID has changed,
            // something really screwed up is going on.
            if rctx.runtime_id != inner.runtime_id.unwrap() {
                inner.reset();
                return Err(KeyManagerError::StateCorrupted.into());
            }
        } else {
            inner.runtime_id = Some(rctx.runtime_id);
        }

        let km_runtime_id = inner.runtime_id.unwrap();

        // How initialization proceeds depends on the state and the request.
        //
        // WARNING: Once a master secret has been persisted to disk, it is
        // intended that manual intervention by the operator is required to
        // remove/alter it.
        if inner.master_secret.is_some() {
            // A master secret is set.  This enclave has initialized successfully
            // at least once.

            let checksum = inner.get_checksum()?;
            if !req.checksum.is_empty() && req.checksum != checksum {
                // The init request provided a checksum and there was a mismatch.
                // The global key manager state disagrees with the enclave state.
                inner.reset();
                return Err(KeyManagerError::StateCorrupted.into());
            }
        } else if !req.checksum.is_empty() {
            // A master secret is not set, and there is a checksum in the
            // request.  An enclave somewhere, has initialized at least
            // once.

            // Attempt to load the master secret.
            let (master_secret, did_replicate) =
                match Self::load_master_secret(ctx.untrusted_local_storage, &km_runtime_id) {
                    Some(master_secret) => (master_secret, false),
                    None => {
                        // Couldn't load, fetch the master secret from another
                        // enclave instance.

                        let rctx = runtime_context!(ctx, KmContext);

                        let km_client = RemoteClient::new_runtime_with_enclaves_and_policy(
                            rctx.runtime_id,
                            Some(rctx.runtime_id),
                            Policy::global().may_replicate_from(),
                            ctx.identity.quote_policy(),
                            rctx.protocol.clone(),
                            ctx.consensus_verifier.clone(),
                            ctx.identity.clone(),
                            1, // Not used, doesn't matter.
                            vec![],
                        );

                        let result =
                            km_client.replicate_master_secret(IoContext::create_child(&ctx.io_ctx));
                        let master_secret = tokio::runtime::Handle::current().block_on(result)?;
                        (master_secret, true)
                    }
                };

            let checksum = Self::checksum_master_secret(&master_secret, &km_runtime_id);
            if req.checksum != checksum {
                // We either loaded or replicated something that does
                // not match the rest of the world.
                inner.reset();
                return Err(KeyManagerError::StateCorrupted.into());
            }

            // The loaded/replicated master secret is consistent with the rest
            // of the world.   Ok to proceed.
            if did_replicate {
                Self::save_master_secret(
                    ctx.untrusted_local_storage,
                    &master_secret,
                    &km_runtime_id,
                );
            }
            inner.master_secret = Some(master_secret);
            inner.checksum = Some(checksum);
        } else {
            // A master secret is not set, and there is no checksum in the
            // request. Either this key manager instance has never been
            // initialized, or our view of the external state is not current.

            // Attempt to load the master secret, the caller may just be
            // behind the rest of the world.
            let master_secret =
                match Self::load_master_secret(ctx.untrusted_local_storage, &km_runtime_id) {
                    Some(master_secret) => master_secret,
                    None => {
                        // Unable to load, perhaps we can generate?
                        if !req.may_generate {
                            return Err(KeyManagerError::ReplicationRequired.into());
                        }

                        // TODO: Support static keying for debugging.
                        let master_secret = Secret::generate();

                        Self::save_master_secret(
                            ctx.untrusted_local_storage,
                            &master_secret,
                            &km_runtime_id,
                        );

                        master_secret
                    }
                };

            // Loaded or generated a master secret.  There is no checksum to
            // compare against, but that is expected when bootstrapping or
            // lagging.
            inner.checksum = Some(Self::checksum_master_secret(&master_secret, &km_runtime_id));
            inner.master_secret = Some(master_secret);
        }

        // If we make it this far, we have a master secret and checksum
        // that either matches the global state, will become the global
        // state, or should become the global state (rare).
        //
        // It is ok to derive the signing key and generate a response.

        // Derive signing key from the master secret.
        let secret =
            inner.derive_static_secret(&RUNTIME_SIGNING_KEY_CUSTOM, km_runtime_id.as_ref())?;
        let sk = signature::PrivateKey::from_bytes(secret.0.to_vec());
        let pk = sk.public_key();
        inner.signer = Some(Arc::new(sk));

        // Build the response and sign it with the RAK.
        let init_response = InitResponse {
            is_secure: BUILD_INFO.is_secure && !Policy::unsafe_skip(),
            checksum: inner.checksum.as_ref().unwrap().clone(),
            policy_checksum,
            rsk: pk,
        };

        let body = cbor::to_vec(init_response.clone());
        let signature = ctx.identity.sign(INIT_RESPONSE_CONTEXT, &body)?;

        Ok(SignedInitResponse {
            init_response,
            signature,
        })
    }

    /// Get or create long-term or ephemeral keys.
    pub fn get_or_create_keys(
        &self,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
    ) -> Result<KeyPair> {
        // Construct a seed that must be unique for every key request.
        // Long-term keys: seed = runtime_id || key_pair_id
        // Ephemeral keys: seed = runtime_id || key_pair_id || epoch
        let mut seed = runtime_id.as_ref().to_vec();
        seed.extend_from_slice(key_pair_id.as_ref());
        if let Some(epoch) = epoch {
            seed.extend_from_slice(epoch.to_be_bytes().as_ref());
        }

        // Check to see if the cached value exists.
        let mut inner = self.inner.write().unwrap();
        if let Some(keys) = inner.cache.get(&seed) {
            return Ok(keys.clone());
        };

        // Generate keys.
        let keys = match epoch {
            Some(_) => {
                let secret = inner.derive_ephemeral_secret(&EPHEMERAL_KDF_CUSTOM, &seed)?;
                inner.derive_keys(secret, &EPHEMERAL_XOF_CUSTOM)?
            }
            None => {
                let secret = inner.derive_static_secret(&RUNTIME_KDF_CUSTOM, &seed)?;
                // FIXME: Replace KDF custom with XOF custom when possible.
                inner.derive_keys(secret, &RUNTIME_KDF_CUSTOM)?
            }
        };

        // Insert into the cache.
        inner.cache.put(seed, keys.clone());

        Ok(keys)
    }

    /// Get the public part of the key.
    pub fn get_public_key(
        &self,
        runtime_id: Namespace,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
    ) -> Result<x25519::PublicKey> {
        let keys = self.get_or_create_keys(runtime_id, key_pair_id, epoch)?;
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
    pub fn replicate_master_secret(&self) -> Result<Secret> {
        let inner = self.inner.read().unwrap();

        let secret = inner
            .master_secret
            .as_ref()
            .cloned()
            .ok_or(KeyManagerError::NotInitialized)?;
        Ok(secret)
    }

    fn load_master_secret(
        untrusted_local: &dyn KeyValue,
        runtime_id: &Namespace,
    ) -> Option<Secret> {
        let ciphertext = untrusted_local
            .get(MASTER_SECRET_STORAGE_KEY.to_vec())
            .unwrap();

        match ciphertext.len() {
            0 => return None,
            MASTER_SECRET_STORAGE_SIZE => (),
            _ => {
                panic!("persisted state is corrupted, invalid size");
            }
        }

        // Split the ciphertext || tag || nonce.
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&ciphertext[32 + TAG_SIZE..]);
        let ciphertext = &ciphertext[..32 + TAG_SIZE];

        // Decrypt the persisted master secret.
        let d2 = Self::new_d2();
        let plaintext = d2
            .open(&nonce, ciphertext.to_vec(), runtime_id.as_ref())
            .expect("persisted state is corrupted");

        Some(Secret(plaintext.try_into().unwrap()))
    }

    fn save_master_secret(
        untrusted_local: &dyn KeyValue,
        master_secret: &Secret,
        runtime_id: &Namespace,
    ) {
        let mut rng = OsRng {};

        // Encrypt the master secret.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(&nonce, master_secret.as_ref(), runtime_id.as_ref());
        ciphertext.extend_from_slice(&nonce);

        // Persist the encrypted master secret.
        untrusted_local
            .insert(MASTER_SECRET_STORAGE_KEY.to_vec(), ciphertext)
            .expect("failed to persist master secret");
    }

    fn checksum_master_secret(master_secret: &Secret, runtime_id: &Namespace) -> Vec<u8> {
        let mut k = [0u8; 32];

        // KMAC256(master_secret, kmRuntimeID, 32, "ekiden-checksum-master-secret")
        let mut f = KMac::new_kmac256(master_secret.as_ref(), &RUNTIME_CHECKSUM_CUSTOM);
        f.update(runtime_id.as_ref());
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
        collections::HashSet,
        convert::TryInto,
        num::NonZeroUsize,
        sync::{Arc, RwLock},
    };

    use lru::LruCache;
    use rustc_hex::{FromHex, ToHex};

    use oasis_core_runtime::{
        common::{
            crypto::{signature::PrivateKey, x25519},
            namespace::Namespace,
        },
        consensus::beacon::EpochTime,
    };

    use crate::crypto::{
        kdf::{CHECKSUM_CUSTOM, RUNTIME_CHECKSUM_CUSTOM, RUNTIME_SIGNING_KEY_CUSTOM},
        KeyPairId, Secret,
    };

    use super::{
        Inner, Kdf, EPHEMERAL_KDF_CUSTOM, EPHEMERAL_XOF_CUSTOM, RUNTIME_KDF_CUSTOM,
        RUNTIME_XOF_CUSTOM,
    };

    impl Kdf {
        fn clear_cache(&self) {
            self.inner.write().unwrap().cache.clear();
        }
    }

    impl Default for Kdf {
        fn default() -> Self {
            Self {
                inner: RwLock::new(Inner {
                    master_secret: Some(Secret([1u8; 32])),
                    checksum: Some(vec![2u8; 32]),
                    runtime_id: Some(Namespace([3u8; 32])),
                    signer: Some(Arc::new(PrivateKey::from_bytes(vec![4u8; 32]))),
                    cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
                }),
            }
        }
    }

    #[test]
    fn key_generation_is_deterministic() {
        let kdf = Kdf::default();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![2u8; 32]);
        let epoch = Some(1);

        // Long-term keys.
        kdf.clear_cache();
        let sk1 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, None)
            .expect("private key should be created");

        kdf.clear_cache();
        let sk2 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, None)
            .expect("private key should be created");

        assert_eq!(
            sk1.input_keypair.sk.0.to_bytes(),
            sk2.input_keypair.sk.0.to_bytes()
        );
        assert_eq!(sk1.input_keypair.pk.0, sk2.input_keypair.pk.0);

        // Ephemeral keys.
        kdf.clear_cache();
        let sk1 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");

        kdf.clear_cache();
        let sk2 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, epoch)
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
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![1u8; 32]);
        let epoch = Some(1);

        // Long-terms keys should depend on runtime_id and key_pair_id.
        let sk1 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, None)
            .expect("private key should be created");
        let sk2 = kdf
            .get_or_create_keys(vec![2u8; 32].into(), key_pair_id, None)
            .expect("private key should be created");
        let sk3 = kdf
            .get_or_create_keys(runtime_id, vec![3u8; 32].into(), None)
            .expect("private key should be created");

        // Ephemeral keys should depend on runtime_id, key_pair_id and epoch.
        let sk4 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");
        let sk5 = kdf
            .get_or_create_keys(vec![2u8; 32].into(), key_pair_id, epoch)
            .expect("private key should be created");
        let sk6 = kdf
            .get_or_create_keys(runtime_id, vec![3u8; 32].into(), epoch)
            .expect("private key should be created");
        let sk7 = kdf
            .get_or_create_keys(runtime_id, key_pair_id, Some(2))
            .expect("private key should be created");

        let keys = HashSet::from(
            [sk1, sk2, sk3, sk4, sk5, sk6, sk7].map(|sk| sk.input_keypair.sk.0.to_bytes()),
        );
        assert_eq!(7, keys.len());
    }

    #[test]
    fn private_and_public_key_match() {
        let kdf = Kdf::default();
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![2u8; 32]);
        let epoch = Some(1);

        // Long-term keys.
        let sk = kdf
            .get_or_create_keys(runtime_id, key_pair_id, None)
            .expect("private key should be created");
        let pk = kdf.get_public_key(runtime_id, key_pair_id, None).unwrap();

        assert_eq!(sk.input_keypair.pk, pk);

        // Ephemeral keys.
        let sk = kdf
            .get_or_create_keys(runtime_id, key_pair_id, epoch)
            .expect("private key should be created");
        let pk = kdf.get_public_key(runtime_id, key_pair_id, epoch).unwrap();

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
        let secret = kdf
            .replicate_master_secret()
            .expect("master secret should be replicated");
        let inner = kdf.inner.into_inner().unwrap();

        assert_eq!(secret.0, inner.master_secret.unwrap().0);
    }

    #[test]
    fn unique_customs() {
        // All key requests must have unique customs otherwise they can
        // derivate keys from the same KMac and/or CShake!!!
        let mut customs: HashSet<&[u8]> = HashSet::new();
        customs.insert(&CHECKSUM_CUSTOM);
        customs.insert(&RUNTIME_KDF_CUSTOM);
        customs.insert(&RUNTIME_XOF_CUSTOM);
        customs.insert(&EPHEMERAL_KDF_CUSTOM);
        customs.insert(&EPHEMERAL_XOF_CUSTOM);
        customs.insert(&RUNTIME_CHECKSUM_CUSTOM);
        customs.insert(&RUNTIME_SIGNING_KEY_CUSTOM);
        assert_eq!(7, customs.len());
    }

    #[test]
    fn vector_test() {
        #[derive(Default)]
        struct TestVector<'a> {
            master_secret: &'a str,
            runtime_id: &'a str,
            key_pair_id: &'a str,
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
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                epoch: 8935419451,
                lk_sk: "702c5a25ff1149591cf7bca763fbe647a43939f43330a8fd331305d73e489b7c",
                lk_pk: "66013b5ad263b4fa504e8682371fbfa102d18cc1e1b811bc125603b1abc9487b",
                // lk_sk: "a009036a2a796c3bf1ae498e7055b481bc5965f9ff013c25270b1a61c8da125d",
                // lk_pk: "14dc0e45265d8bb23479b742b39528eb10bec264c5c9f74b8c2f51638f3a7239",
                ek_sk: "780899b45db36117c26d68991bed2820afe8fa9822d3ad5e7bb3a1b7280bf575",
                ek_pk: "e60c69b71ab3323d94b0739639a3196ffc1e18a090a3ca5074291387849c2e0a",
            },
            // Different master secret.
            TestVector {
                master_secret: "54083e90f05860653161bc1575765b3311f6a55d1cab84919cb1e2b02c8351ec",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                epoch: 8935419451,
                lk_sk: "5045ff4735a1fc7cbdb729d7cfb9349a11e664bf3198e78b9b714bf7dffe984e",
                lk_pk: "ba3de0b2d206d7c8c46c3cf82bdf7ea6a6db1c768207ed54f54d08a72c65101e",
                // lk_sk: "885c1651dc64af6965ef2ed5d690d2110cfce0353f4d263cb6e894db847d4468",
                // lk_pk: "4260efb7dcc4e5655139477e991e5a124243740644e7f937680cd015e8645d1a",
                ek_sk: "486a42ca2b133bda56acf0b10856475d33d5d65bdd8a19f758e66f477bf1e84c",
                ek_pk: "e9ce9a2ea28044a2ce9bf407079f1afc00e263faf187af84ef3ac33451a83e12",
            },
            // Different runtime ID.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                runtime_id: "1aa3e6d86c0779afde8a367dbbb025538fb77e410624ece8b25a6be9e1a5170d",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                epoch: 8935419451,
                lk_sk: "e03a8c8e86024934e84d61d789ae7b292a0124bd7cedb1ac740e750391936150",
                lk_pk: "09761afffa3ef10c7a62390e81bca3c217c7cde216c9660c0f69d3709439587b",
                // lk_sk: "e8c587d47625d6d7b213fcc4db3ddda295cf5bf6458165aedd293afea89f7a49",
                // lk_pk: "1733d7cd352941d2fad73d73e4bcc88ee9d94a6872a2c0ce0431ba20616eed75",
                ek_sk: "e01cbc199d1c4ce1e1cf079dd109957801f0861491cdc7bcfefc45ced487ae69",
                ek_pk: "1a070e1ba69d6ece36e80731331f2b0414f2db05657aa5b32637dbbee278e95f",
            },
            // Different key pair ID.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "18789f16d8a8fbd75f529f0a1de3e95469eb537c283dc66eb296a6681a46c066",
                epoch: 8935419451,
                lk_sk: "a82089503a2b9f2804ee61dcc8ddc3c52f49be9aa6545d235ede885597d12d7a",
                lk_pk: "a0d546af1faf39e45171830d8779b1744f1b2407b3dcad5d454d1cdcfe7b7276",
                // lk_sk: "7034c6b9054b726286732bf6e8f0e8075e1d0ee3610a7fe9a188afba4fe97b6a",
                // lk_pk: "d03ff12b41e83913433c4b57d919d05c18661ef1c6ac014568ad2efc67e48f40",
                ek_sk: "b09515d7ea6cc46eb0bfcc5228112185c83f7f151b62f6c2932a35bb277b127f",
                ek_pk: "45bff1009b9ea4a712c127dd29a38df8b74825d381a280b1730202a4a66b6041",
            },
            // Different epoch.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                runtime_id: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                key_pair_id: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
                epoch: 943032087,
                lk_sk: "702c5a25ff1149591cf7bca763fbe647a43939f43330a8fd331305d73e489b7c",
                lk_pk: "66013b5ad263b4fa504e8682371fbfa102d18cc1e1b811bc125603b1abc9487b",
                // lk_sk: "a009036a2a796c3bf1ae498e7055b481bc5965f9ff013c25270b1a61c8da125d",
                // lk_pk: "14dc0e45265d8bb23479b742b39528eb10bec264c5c9f74b8c2f51638f3a7239",
                ek_sk: "70c67e2b4e8899b043fbd2e5d8ab78afb3f87f141724494d5c45f03f085d5a59",
                ek_pk: "5cf09d76408b397312c664696416b9e6e2a9dbe6aa08b01d81f80a2bd7666218",
            },
        ];

        // Values that don't effect key derivation.
        let checksum = "100246b37912e916e71ff79982b2f62be892ddf1025cde84804f67e7f5713b75";
        let runtime_id = "8000000000000000000000000000000000000000000000000000000000000000";
        let signer = "08e35ef2b23fc2d27281117f8ad3fa0cb4d52e803a070ebb20e7ac9aa8d1f84a";

        // Test all vectors.
        for v in vectors {
            let kdf = Kdf {
                inner: RwLock::new(Inner {
                    master_secret: Some(Secret(
                        v.master_secret
                            .from_hex::<Vec<u8>>()
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    )),
                    checksum: Some(checksum.from_hex().unwrap()),
                    runtime_id: Some(Namespace::from(runtime_id)),
                    signer: Some(Arc::new(PrivateKey::from_bytes(signer.from_hex().unwrap()))),
                    cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
                }),
            };

            let runtime_id = Namespace::from(v.runtime_id);
            let key_pair_id = KeyPairId::from(v.key_pair_id);

            let lk = kdf
                .get_or_create_keys(runtime_id, key_pair_id, None)
                .expect("private key should be created");

            let ek = kdf
                .get_or_create_keys(runtime_id, key_pair_id, Some(v.epoch))
                .expect("private key should be created");

            assert_eq!(lk.input_keypair.sk.0.to_bytes().to_hex::<String>(), v.lk_sk);
            assert_eq!(lk.input_keypair.pk.0.to_bytes().to_hex::<String>(), v.lk_pk);
            assert_eq!(ek.input_keypair.sk.0.to_bytes().to_hex::<String>(), v.ek_sk);
            assert_eq!(ek.input_keypair.pk.0.to_bytes().to_hex::<String>(), v.ek_pk);
        }
    }
}
