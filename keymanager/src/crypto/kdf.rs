//! Key Derivation Function.
use std::{
    convert::TryInto,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use io_context::Context as IoContext;
use lazy_static::lazy_static;
use lru::LruCache;
use rand::{rngs::OsRng, Rng};
use sgx_isa::Keypolicy;
use sp800_185::{CShake, KMac};
use x25519_dalek;
use zeroize::Zeroize;

use oasis_core_runtime::{
    common::{
        crypto::{
            mrae::deoxysii::{DeoxysII, NONCE_SIZE, TAG_SIZE},
            signature,
        },
        namespace::Namespace,
        sgx::egetkey::egetkey,
    },
    enclave_rpc::Context as RpcContext,
    runtime_context,
    storage::KeyValue,
    BUILD_INFO,
};

use crate::{
    api::{
        EphemeralKeyRequest, InitRequest, InitResponse, KeyManagerError, LongTermKeyRequest,
        ReplicateResponse, SignedInitResponse,
    },
    client::{KeyManagerClient, RemoteClient},
    crypto::{KeyPair, MasterSecret, PrivateKey, PublicKey, SignedPublicKey, StateKey},
    policy::Policy,
    runtime::context::Context as KmContext,
};

/// Context used for the init response signature.
const INIT_RESPONSE_CONTEXT: &[u8] = b"oasis-core/keymanager: init response";

/// Context used for the public key signature.
const PUBLIC_KEY_CONTEXT: [u8; 8] = *b"EkKmPubK";

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
}

/// A dummy key for use in non-SGX tests where integrity is not needed.
#[cfg(not(target_env = "sgx"))]
const INSECURE_SIGNING_KEY_SEED: &str = "ekiden test key manager RAK seed";

const MASTER_SECRET_STORAGE_KEY: &[u8] = b"keymanager_master_secret";
const MASTER_SECRET_STORAGE_SIZE: usize = 32 + TAG_SIZE + NONCE_SIZE;
const MASTER_SECRET_SEAL_CONTEXT: &[u8] = b"Ekiden Keymanager Seal master secret v0";

/// Key request interface for key derivation.
pub trait KeyRequest {
    /// A unique seed for secret derivation.
    fn seed(&self) -> Vec<u8>;

    /// Custom kdf parameter for secret derivation.
    fn kdf_custom(&self) -> &[u8];

    /// Custom xof parameter for private key derivation.
    fn xof_custom(&self) -> &[u8];
}

impl KeyRequest for LongTermKeyRequest {
    fn seed(&self) -> Vec<u8> {
        // seed = runtimeID || keypairID
        let mut s = self.runtime_id.as_ref().to_vec();
        s.extend_from_slice(self.key_pair_id.as_ref());
        s
    }

    fn kdf_custom(&self) -> &[u8] {
        &RUNTIME_KDF_CUSTOM
    }

    fn xof_custom(&self) -> &[u8] {
        &RUNTIME_KDF_CUSTOM
    }
}

impl KeyRequest for EphemeralKeyRequest {
    fn seed(&self) -> Vec<u8> {
        // seed = runtimeID || keypairID || epoch
        let mut s = self.runtime_id.as_ref().to_vec();
        s.extend_from_slice(self.key_pair_id.as_ref());
        s.extend_from_slice(&self.epoch.to_be_bytes());
        s
    }

    fn kdf_custom(&self) -> &[u8] {
        &EPHEMERAL_KDF_CUSTOM
    }

    fn xof_custom(&self) -> &[u8] {
        &EPHEMERAL_XOF_CUSTOM
    }
}

/// Kdf, which derives key manager keys from a master secret.
pub struct Kdf {
    inner: RwLock<Inner>,
}

struct Inner {
    /// Master secret.
    master_secret: Option<MasterSecret>,
    checksum: Option<Vec<u8>>,
    runtime_id: Option<Namespace>,
    signer: Option<Arc<dyn signature::Signer>>,
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

    fn derive_key(&self, req: &impl KeyRequest) -> Result<KeyPair> {
        let checksum = self.get_checksum()?;
        let mut secret = self.derive_secret(req)?;

        // Note: The `name` parameter for cSHAKE is reserved for use by NIST.
        let mut xof = CShake::new_cshake256(&[], req.xof_custom());
        xof.update(&secret);
        secret.zeroize();
        let mut xof = xof.xof();

        // State (storage) key.
        let mut k = [0u8; 32];
        xof.squeeze(&mut k);
        let state_key = StateKey(k);

        // Public/private keypair.
        xof.squeeze(&mut k);
        let sk = x25519_dalek::StaticSecret::from(k);
        k.zeroize();
        let pk = x25519_dalek::PublicKey::from(&sk);

        Ok(KeyPair::new(
            PublicKey(*pk.as_bytes()),
            PrivateKey(sk.to_bytes()),
            state_key,
            checksum,
        ))
    }

    fn derive_secret(&self, req: &impl KeyRequest) -> Result<Vec<u8>> {
        let master_secret = match self.master_secret.as_ref() {
            Some(master_secret) => master_secret,
            None => return Err(KeyManagerError::NotInitialized.into()),
        };

        let mut k = [0u8; 32];

        // KMAC256(master_secret, seed, 32, kdf_custom)
        let mut f = KMac::new_kmac256(master_secret.as_ref(), req.kdf_custom());
        f.update(&req.seed()[..]);
        f.finalize(&mut k);

        Ok(k.to_vec())
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

                        let km_client = RemoteClient::new_runtime_with_enclave_identities(
                            rctx.runtime_id,
                            Policy::global().may_replicate_from(),
                            rctx.protocol.clone(),
                            ctx.consensus_verifier.clone(),
                            ctx.rak.clone(),
                            1, // Not used, doesn't matter.
                        );

                        let result =
                            km_client.replicate_master_secret(IoContext::create_child(&ctx.io_ctx));
                        let master_secret = tokio::runtime::Handle::current().block_on(result)?;
                        (master_secret.unwrap(), true)
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

                        Self::generate_master_secret(ctx.untrusted_local_storage, &km_runtime_id)
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
        // It is ok to generate a response.

        // The RAK (signing key) may have changed since the last init call.
        #[cfg(target_env = "sgx")]
        {
            let signer: Arc<dyn signature::Signer> = ctx.rak.clone();
            inner.signer = Some(signer);
        }
        #[cfg(not(target_env = "sgx"))]
        {
            let priv_key = Arc::new(signature::PrivateKey::from_test_seed(
                INSECURE_SIGNING_KEY_SEED.to_string(),
            ));

            let signer: Arc<dyn signature::Signer> = priv_key;
            inner.signer = Some(signer);
        }

        // Build the response and sign it with the RAK.
        let init_response = InitResponse {
            is_secure: BUILD_INFO.is_secure && !Policy::unsafe_skip(),
            checksum: inner.checksum.as_ref().unwrap().clone(),
            policy_checksum,
        };

        let body = cbor::to_vec(init_response.clone());
        let signature = inner
            .signer
            .as_ref()
            .unwrap()
            .sign(INIT_RESPONSE_CONTEXT, &body)?;

        Ok(SignedInitResponse {
            init_response,
            signature,
        })
    }

    /// Get or create keys.
    pub fn get_or_create_keys(&self, req: &impl KeyRequest) -> Result<KeyPair> {
        let cache_key = req.seed();

        // Check to see if the cached value exists.
        let mut inner = self.inner.write().unwrap();
        if let Some(keys) = inner.cache.get(&cache_key) {
            return Ok(keys.clone());
        };

        let key = inner.derive_key(req)?;
        inner.cache.put(cache_key, key.clone());

        Ok(key)
    }

    /// Get the public part of the key.
    pub fn get_public_key(&self, req: &impl KeyRequest) -> Result<Option<PublicKey>> {
        let keys = self.get_or_create_keys(req)?;
        Ok(Some(keys.input_keypair.pk))
    }

    /// Signs the public key using the key manager key.
    pub fn sign_public_key(&self, key: PublicKey) -> Result<SignedPublicKey> {
        let mut body = key.as_ref().to_vec();

        let inner = self.inner.read().unwrap();
        let checksum = inner.get_checksum()?;
        body.extend_from_slice(&checksum);

        let signer = inner
            .signer
            .as_ref()
            .ok_or(KeyManagerError::NotInitialized)?;
        let signature = signer.sign(&PUBLIC_KEY_CONTEXT, &body)?;

        Ok(SignedPublicKey {
            key,
            checksum,
            signature,
        })
    }

    // Replicate master secret.
    pub fn replicate_master_secret(&self) -> Result<ReplicateResponse> {
        let inner = self.inner.read().unwrap();

        let master_secret = inner
            .master_secret
            .as_ref()
            .cloned()
            .ok_or(KeyManagerError::NotInitialized)?;
        Ok(ReplicateResponse { master_secret })
    }

    fn load_master_secret(
        untrusted_local: &dyn KeyValue,
        runtime_id: &Namespace,
    ) -> Option<MasterSecret> {
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

        Some(MasterSecret(plaintext.try_into().unwrap()))
    }

    fn save_master_secret(
        untrusted_local: &dyn KeyValue,
        master_secret: &MasterSecret,
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

    fn generate_master_secret(
        untrusted_local: &dyn KeyValue,
        runtime_id: &Namespace,
    ) -> MasterSecret {
        let mut rng = OsRng {};

        // TODO: Support static keying for debugging.
        let mut master_secret = [0u8; 32];
        rng.fill(&mut master_secret);
        let master_secret = MasterSecret(master_secret);

        Self::save_master_secret(untrusted_local, &master_secret, runtime_id);

        master_secret
    }

    fn checksum_master_secret(master_secret: &MasterSecret, runtime_id: &Namespace) -> Vec<u8> {
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

    use oasis_core_runtime::common::{crypto::signature::PrivateKey, namespace::Namespace};

    use crate::{
        api::{EphemeralKeyRequest, LongTermKeyRequest},
        crypto::{KeyPairId, MasterSecret, PublicKey},
    };

    use super::{
        Inner, Kdf, KeyRequest, EPHEMERAL_KDF_CUSTOM, EPHEMERAL_XOF_CUSTOM, PUBLIC_KEY_CONTEXT,
        RUNTIME_KDF_CUSTOM, RUNTIME_XOF_CUSTOM,
    };

    struct SimpleKeyRequest<'a> {
        seed: &'a str,
        kdf_custom: &'a [u8],
        xof_custom: &'a [u8],
    }

    impl Default for SimpleKeyRequest<'_> {
        fn default() -> Self {
            Self {
                seed: "8842befd88ea1952decf60f5c7430ee479b84a9b2472b2cc1fc796d35d5d71c3",
                kdf_custom: b"kdf_custom",
                xof_custom: b"xof_custom",
            }
        }
    }

    impl KeyRequest for SimpleKeyRequest<'_> {
        fn seed(&self) -> Vec<u8> {
            self.seed.from_hex().unwrap()
        }

        fn kdf_custom(&self) -> &[u8] {
            self.kdf_custom
        }

        fn xof_custom(&self) -> &[u8] {
            self.xof_custom
        }
    }

    impl Default for Kdf {
        fn default() -> Self {
            Self {
                inner: RwLock::new(Inner {
                    master_secret: Some(MasterSecret([1u8; 32])),
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
        let req = SimpleKeyRequest::default();

        let sk1 = kdf
            .get_or_create_keys(&req)
            .expect("private key should be created");

        let sk2 = kdf
            .get_or_create_keys(&req)
            .expect("private key should be created");

        assert_eq!(sk1.input_keypair.sk.0, sk2.input_keypair.sk.0);
        assert_eq!(sk1.input_keypair.pk.0, sk2.input_keypair.pk.0);
    }

    #[test]
    fn private_keys_are_unique() {
        let kdf = Kdf::default();
        let mut req = SimpleKeyRequest::default();

        let sk1 = kdf
            .get_or_create_keys(&req)
            .expect("private key should be created");

        req.seed = "eeffe4ab608f4adad8b5168163ab95fab43a818321ad49fba897fcb435097099";
        let sk2 = kdf
            .get_or_create_keys(&req)
            .expect("private key should be created");

        assert_ne!(sk1.input_keypair.sk.0, sk2.input_keypair.sk.0);
        assert_ne!(sk1.input_keypair.pk.0, sk2.input_keypair.pk.0);
    }

    #[test]
    fn private_and_public_key_match() {
        let kdf = Kdf::default();
        let req = SimpleKeyRequest::default();

        let sk = kdf
            .get_or_create_keys(&req)
            .expect("private key should be created");

        let pk = kdf
            .get_public_key(&req)
            .unwrap()
            .expect("public key should be fetched");

        assert_eq!(sk.input_keypair.pk, pk);
    }

    #[test]
    fn public_key_signature_is_valid() {
        let kdf = Kdf::default();

        let pk = PublicKey::from(vec![1u8; 32]);
        let sig = kdf
            .sign_public_key(pk)
            .expect("public key should be signed");

        let mut body = pk.as_ref().to_vec();
        let checksum = kdf.inner.into_inner().unwrap().checksum.unwrap();
        body.extend_from_slice(&checksum);

        let pk = PrivateKey::from_bytes(vec![4u8; 32]).public_key();
        sig.signature
            .verify(&pk, &PUBLIC_KEY_CONTEXT, &body)
            .expect("signature should be valid");
    }

    #[test]
    fn master_secret_can_be_replicated() {
        let kdf = Kdf::default();
        let ms = kdf
            .replicate_master_secret()
            .expect("master secret should be replicated");

        assert_eq!(
            ms.master_secret.0,
            kdf.inner.into_inner().unwrap().master_secret.unwrap().0
        );
    }

    #[test]
    fn requests_have_unique_customs() {
        // All key requests must have unique customs otherwise they can
        // derivate keys from the same KMac and/or CShake!!!
        let runtime_req = LongTermKeyRequest::default();
        let ephemeral_req = EphemeralKeyRequest::default();

        assert_ne!(runtime_req.xof_custom(), ephemeral_req.xof_custom());
        assert_ne!(runtime_req.kdf_custom(), ephemeral_req.kdf_custom());
    }

    #[test]
    fn requests_generate_unique_seeds() {
        // Default values.
        let runtime_id = Namespace::from(vec![1u8; 32]);
        let key_pair_id = KeyPairId::from(vec![1u8; 32]);
        let epoch = 1;
        let height = None;

        // LongTermKeyRequest's seed should depend on runtime_id and
        // key_pair_id.
        let req1 = LongTermKeyRequest {
            height,
            runtime_id,
            key_pair_id,
        };
        let mut req2 = req1.clone();
        let mut req3 = req1.clone();
        req2.runtime_id = Namespace::from(vec![2u8; 32]);
        req3.key_pair_id = KeyPairId::from(vec![3u8; 32]);

        let mut seeds = HashSet::new();
        seeds.insert(req1.seed());
        seeds.insert(req2.seed());
        seeds.insert(req3.seed());

        assert_eq!(seeds.len(), 3);

        // EphemeralKeyRequest's seed should depend on runtime_id, key_pair_id
        // and epoch.
        let req1 = EphemeralKeyRequest {
            height,
            epoch,
            runtime_id,
            key_pair_id,
        };
        let mut req2 = req1.clone();
        let mut req3 = req1.clone();
        let mut req4 = req1.clone();
        req2.runtime_id = Namespace::from(vec![2u8; 32]);
        req3.key_pair_id = KeyPairId::from(vec![3u8; 32]);
        req4.epoch = 2;

        let mut seeds = HashSet::new();
        seeds.insert(req1.seed());
        seeds.insert(req2.seed());
        seeds.insert(req3.seed());
        seeds.insert(req4.seed());

        assert_eq!(seeds.len(), 4);
    }

    #[test]
    fn vector_test() {
        struct TestVector<'a> {
            master_secret: &'a str,
            seed: &'a str,
            kdf_custom: &'a [u8],
            xof_custom: &'a [u8],
            sk: &'a str,
            pk: &'a str,
        }

        let kdf_custom = b"54761365b5a007c2bd13cf880a8a58263f56bb7057f7548b7467e871f6f4bb1f";
        let xof_custom = b"a0caee5ecac1a287f06ff8748cf37e809f049cf6866d668ecdbed3ce05b40f2c";

        let vectors = vec![
            // A random vector.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                seed: "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                kdf_custom: &RUNTIME_KDF_CUSTOM,
                xof_custom: &RUNTIME_XOF_CUSTOM,
                sk: "c818f97228a53b201e2afa383b64199c732c7ba1a67ac55ea2cb3b8fba367740",
                pk: "fb99076f6a5a8c52bcf562cae5152d0410f47a615fc7bc4966dc9a4f477bd217",
            },
            // Different master secret.
            TestVector {
                master_secret: "54083e90f05860653161bc1575765b3311f6a55d1cab84919cb1e2b02c8351ec",
                seed: "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                kdf_custom: &RUNTIME_KDF_CUSTOM,
                xof_custom: &RUNTIME_XOF_CUSTOM,
                sk: "b8092ab767ddc47cb56807d4d1fd0e66eae0b02e289d1e38d4dfa900619edc47",
                pk: "6782329a12e821697f1d7cc44ba5644a2d81bd827fe09208549296be51da8b66",
            },
            // Different seed.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                seed: "6cc9f7dfe776c7e531331eaf5fd8717d638cae65a4ebb0d6f128b1873f0f9c22",
                kdf_custom: &RUNTIME_KDF_CUSTOM,
                xof_custom: &RUNTIME_XOF_CUSTOM,
                sk: "f0d5bf36b424f7b168fa37e1a1407f191a260dda149d78676d4ca077b1e8614c",
                pk: "9099b1e19c482927eb2785c77b34ef2c4b95f812e089e3b2cd6f2a0a743b7561",
            },
            // Different kdf custom.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                seed: "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                kdf_custom: &EPHEMERAL_KDF_CUSTOM,
                xof_custom: &RUNTIME_XOF_CUSTOM,
                sk: "18789f16d8a8fbd75f529f0a1de3e95469eb537c283dc66eb296a6681a46c066",
                pk: "1aa3e6d86c0779afde8a367dbbb025538fb77e410624ece8b25a6be9e1a5170d",
            },
            // Different xof custom.
            TestVector {
                master_secret: "3fa39161fe106fb770503558dad41bea3221888c09477d864507e615094f5d38",
                seed: "2a9d51ed0380d11b26255ecc894dfc3aa48196c9b0da463a3073ea820a65a090",
                kdf_custom: &RUNTIME_KDF_CUSTOM,
                xof_custom: &EPHEMERAL_XOF_CUSTOM,
                sk: "e0e6faa3172634c8fdc47554f0541c7141f7ddfe07333b0dab1801bb5dcd755e",
                pk: "455f877b6c977c51580e947a5a2ae57b4b1ec0a379cf6509be07f10aa88df735",
            },
            // Another random vector.
            TestVector {
                master_secret: "b573fa13ec26d21a7a2b5117eb124dcab5883eb63ec0a5a9cc0b1d1948bcfc71",
                seed: "774cbb9c1e8c634e7e136357d9994f65d72fc0e7d72c1e9ad766db1a74e0bb8c",
                kdf_custom,
                xof_custom,
                sk: "70c077d8bd0c5c2be66d08fbacac4f1a996001883baaf62bd933e2f7de390e5f",
                pk: "2d62567e9061a7cc64df3793fbee65c863862b8f0acc992e2a39e32757f2c743",
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
                    master_secret: Some(MasterSecret(
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

            let req = SimpleKeyRequest {
                seed: v.seed,
                kdf_custom: v.kdf_custom,
                xof_custom: v.xof_custom,
            };

            let sk = kdf
                .get_or_create_keys(&req)
                .expect("private key should be created");

            assert_eq!(sk.input_keypair.sk.0.to_hex::<String>(), v.sk);
            assert_eq!(sk.input_keypair.pk.0.to_hex::<String>(), v.pk);
        }
    }
}
