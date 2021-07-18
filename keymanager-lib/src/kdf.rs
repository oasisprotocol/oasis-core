///! Key Derivation Function.
use std::sync::{Arc, RwLock};

use anyhow::Result;
use io_context::Context as IoContext;
use lazy_static::lazy_static;
use lru::LruCache;
use rand::{rngs::OsRng, Rng};
use sgx_isa::Keypolicy;
use sp800_185::{CShake, KMac};
use x25519_dalek;
use zeroize::Zeroize;

use oasis_core_keymanager_api_common::{
    InitRequest, InitResponse, KeyManagerError, KeyPair, MasterSecret, PrivateKey, PublicKey,
    ReplicateResponse, RequestIds, SignedInitResponse, SignedPublicKey, StateKey,
    INIT_RESPONSE_CONTEXT, PUBLIC_KEY_CONTEXT,
};
use oasis_core_keymanager_client::{KeyManagerClient, RemoteClient};
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
    storage::StorageContext,
    BUILD_INFO,
};

use crate::{context::Context as KmContext, policy::Policy};

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

const MASTER_SECRET_STORAGE_KEY: &'static [u8] = b"keymanager_master_secret";
const MASTER_SECRET_STORAGE_SIZE: usize = 32 + TAG_SIZE + NONCE_SIZE;
const MASTER_SECRET_SEAL_CONTEXT: &'static [u8] = b"Ekiden Keymanager Seal master secret v0";

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

    fn derive_contract_key(&self, req: &RequestIds) -> Result<KeyPair> {
        let checksum = self.get_checksum()?;
        let mut contract_secret = self.derive_contract_secret(req)?;

        // Note: The `name` parameter for cSHAKE is reserved for use by NIST.
        let mut xof = CShake::new_cshake256(&vec![], &RUNTIME_XOF_CUSTOM);
        xof.update(&contract_secret);
        contract_secret.zeroize();
        let mut xof = xof.xof();

        // State (storage) key.
        let mut k = [0u8; 32];
        xof.squeeze(&mut k);
        let state_key = StateKey::from(k.to_vec());

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

    fn derive_contract_secret(&self, req: &RequestIds) -> Result<Vec<u8>> {
        let master_secret = match self.master_secret.as_ref() {
            Some(master_secret) => master_secret,
            None => return Err(KeyManagerError::NotInitialized.into()),
        };

        let mut k = [0u8; 32];

        // KMAC256(master_secret, runtimeID || contractID, 32, "ekiden-derive-runtime-secret")
        let mut f = KMac::new_kmac256(master_secret.as_ref(), &RUNTIME_KDF_CUSTOM);
        f.update(req.runtime_id.as_ref());
        f.update(req.key_pair_id.as_ref());
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
                cache: LruCache::new(1024),
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
            if req.checksum.len() > 0 && req.checksum != checksum {
                // The init request provided a checksum and there was a mismatch.
                // The global key manager state disagrees with the enclave state.
                inner.reset();
                return Err(KeyManagerError::StateCorrupted.into());
            }
        } else if req.checksum.len() > 0 {
            // A master secret is not set, and there is a checksum in the
            // request.  An enclave somewhere, has initialized at least
            // once.

            // Attempt to load the master secret.
            let (master_secret, did_replicate) = match Self::load_master_secret(&km_runtime_id) {
                Some(master_secret) => (master_secret, false),
                None => {
                    // Couldn't load, fetch the master secret from another
                    // enclave instance.

                    let rctx = runtime_context!(ctx, KmContext);

                    let km_client = RemoteClient::new_runtime_with_enclave_identities(
                        rctx.runtime_id,
                        Policy::global().may_replicate_from(),
                        rctx.protocol.clone(),
                        ctx.rak.clone(),
                        1, // Not used, doesn't matter.
                    );

                    let result =
                        km_client.replicate_master_secret(IoContext::create_child(&ctx.io_ctx));
                    let master_secret = ctx.tokio.block_on(result)?;
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
                Self::save_master_secret(&master_secret, &km_runtime_id);
            }
            inner.master_secret = Some(master_secret);
            inner.checksum = Some(checksum);
        } else {
            // A master secret is not set, and there is no checksum in the
            // request. Either this key manager instance has never been
            // initialized, or our view of the external state is not current.

            // Attempt to load the master secret, the caller may just be
            // behind the rest of the world.
            let master_secret = match Self::load_master_secret(&km_runtime_id) {
                Some(master_secret) => master_secret,
                None => {
                    // Unable to load, perhaps we can generate?
                    if !req.may_generate {
                        return Err(KeyManagerError::ReplicationRequired.into());
                    }

                    Self::generate_master_secret(&km_runtime_id)
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
            .sign(&INIT_RESPONSE_CONTEXT, &body)?;

        Ok(SignedInitResponse {
            init_response,
            signature,
        })
    }

    // Get or create keys.
    pub fn get_or_create_keys(&self, req: &RequestIds) -> Result<KeyPair> {
        let cache_key = req.to_cache_key();

        // Check to see if the cached value exists.
        let mut inner = self.inner.write().unwrap();
        match inner.cache.get(&cache_key) {
            Some(keys) => return Ok(keys.clone()),
            None => {}
        };

        let contract_key = inner.derive_contract_key(req)?;
        inner.cache.put(cache_key, contract_key.clone());

        Ok(contract_key)
    }

    /// Get the public part of the key.
    pub fn get_public_key(&self, req: &RequestIds) -> Result<Option<PublicKey>> {
        let contract_keys = self.get_or_create_keys(req)?;
        Ok(Some(contract_keys.input_keypair.get_pk()))
    }

    /// Signs the public key using the key manager key.
    pub fn sign_public_key(&self, key: PublicKey) -> Result<SignedPublicKey> {
        let mut body = key.as_ref().to_vec();

        let inner = self.inner.read().unwrap();
        let checksum = inner.get_checksum()?;
        body.extend_from_slice(&checksum);

        let signer = match inner.signer.as_ref() {
            Some(rak) => rak,
            None => return Err(KeyManagerError::NotInitialized.into()),
        };
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

        match inner.master_secret {
            Some(master_secret) => Ok(ReplicateResponse { master_secret }),
            None => Err(KeyManagerError::NotInitialized.into()),
        }
    }

    fn load_master_secret(runtime_id: &Namespace) -> Option<MasterSecret> {
        let ciphertext = StorageContext::with_current(|_mkvs, untrusted_local| {
            untrusted_local.get(MASTER_SECRET_STORAGE_KEY.to_vec())
        })
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
            .open(&nonce, ciphertext.to_vec(), runtime_id.as_ref().to_vec())
            .expect("persisted state is corrupted");

        Some(MasterSecret::from(plaintext))
    }

    fn save_master_secret(master_secret: &MasterSecret, runtime_id: &Namespace) {
        let mut rng = OsRng {};

        // Encrypt the master secret.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(
            &nonce,
            master_secret.as_ref().to_vec(),
            runtime_id.as_ref().to_vec(),
        );
        ciphertext.extend_from_slice(&nonce);

        // Persist the encrypted master secret.
        StorageContext::with_current(|_mkvs, untrusted_local| {
            untrusted_local.insert(MASTER_SECRET_STORAGE_KEY.to_vec(), ciphertext)
        })
        .expect("failed to persist master secret");
    }

    fn generate_master_secret(runtime_id: &Namespace) -> MasterSecret {
        let mut rng = OsRng {};

        // TODO: Support static keying for debugging.
        let mut master_secret = [0u8; 32];
        rng.fill(&mut master_secret);
        let master_secret = MasterSecret::from(master_secret.to_vec());

        Self::save_master_secret(&master_secret, runtime_id);

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
        let mut seal_key = egetkey(Keypolicy::MRENCLAVE, &MASTER_SECRET_SEAL_CONTEXT);
        let d2 = DeoxysII::new(&seal_key);
        seal_key.zeroize();

        d2
    }
}
