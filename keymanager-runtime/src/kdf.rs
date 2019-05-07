///! Key Derivation Function
use std::sync::{Arc, RwLock};

use byteorder::{BigEndian, WriteBytesExt};
use failure::Fallible;
use lazy_static::lazy_static;
use lru::LruCache;
use rand::{rngs::OsRng, Rng};
use sgx_isa::Keypolicy;
use sp800_185::{CShake, KMac};
use x25519_dalek;
use zeroize::Zeroize;

use ekiden_keymanager_api::{
    ContractKey, KeyManagerError, MasterSecret, PrivateKey, PublicKey, RequestIds, SignedPublicKey,
    StateKey, PUBLIC_KEY_CONTEXT,
};
use ekiden_runtime::{
    common::{
        crypto::{
            mrae::deoxysii::{DeoxysII, NONCE_SIZE, TAG_SIZE},
            signature,
        },
        sgx::egetkey::egetkey,
    },
    rpc::Context as RpcContext,
    storage::StorageContext,
    BUILD_INFO,
};

lazy_static! {
    // Global KDF object.
    static ref KDF: Kdf = Kdf::new();

    static ref RUNTIME_KDF_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true =>  b"ekiden-derive-runtime-secret",
            false => b"ekiden-derive-runtime-secret-insecure",
        }
    };

    static ref RUNTIME_XOF_CUSTOM: &'static [u8] = {
        match BUILD_INFO.is_secure {
            true => b"ekiden-derive-contract-keys",
            false => b"ekiden-derive-contract-keys-insecure",
        }
    };
}

/// A dummy key for use in tests where integrity is not needed.
/// Public Key: 0x9d41a874b80e39a40c9644e964f0e4f967100c91654bfd7666435fe906af060f
#[cfg(not(target_env = "sgx"))]
const SIGNING_KEY_PKCS8: &'static [u8] = &[
    48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 109, 124, 181, 54, 35, 91, 34, 238,
    29, 127, 17, 115, 64, 41, 135, 165, 19, 211, 246, 106, 37, 136, 149, 157, 187, 145, 157, 192,
    170, 25, 201, 141, 161, 35, 3, 33, 0, 157, 65, 168, 116, 184, 14, 57, 164, 12, 150, 68, 233,
    100, 240, 228, 249, 103, 16, 12, 145, 101, 75, 253, 118, 102, 67, 95, 233, 6, 175, 6, 15,
];

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
    signer: Option<Arc<signature::Signer>>,
    cache: LruCache<Vec<u8>, ContractKey>,
}

impl Inner {
    fn derive_contract_key(&self, req: &RequestIds) -> Fallible<ContractKey> {
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

        Ok(ContractKey::new(
            PublicKey(*pk.as_bytes()),
            PrivateKey(sk.to_bytes()),
            state_key,
        ))
    }

    fn derive_contract_secret(&self, req: &RequestIds) -> Fallible<Vec<u8>> {
        let master_secret = match self.master_secret.as_ref() {
            Some(master_secret) => master_secret,
            None => return Err(KeyManagerError::NotInitialized.into()),
        };

        let mut k = [0u8; 32];

        // KMAC256(master_secret, MRENCLAVE_km || runtimeID || contractID, 32, "ekiden-derive-runtime-secret")
        // XXX: We don't pass in the MRENCLAVE yet.
        let mut f = KMac::new_kmac256(master_secret.as_ref(), &RUNTIME_KDF_CUSTOM);
        f.update(req.runtime_id.as_ref());
        f.update(req.contract_id.as_ref());
        f.finalize(&mut k);

        Ok(k.to_vec())
    }
}

impl Kdf {
    fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                master_secret: None,
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
    pub fn init(&self, ctx: &RpcContext) -> Fallible<()> {
        // TODO: This is where replication cleverness should probably happen, if not
        // in the caller.
        let mut inner = self.inner.write().unwrap();

        if inner.master_secret.is_some() {
            return Ok(()); // HACK HACK HACK.
                           //return Err(KeyManagerError::AlreadyInitialized.into());
        }

        // Failures past this point indicate a messed up worker host, and
        // are fatal.

        let master_secret = match Self::load_master_secret() {
            Some(master_secret) => master_secret,
            None => Self::generate_master_secret(),
        };
        inner.master_secret = Some(MasterSecret::from(master_secret));

        #[cfg(not(target_env = "sgx"))]
        let signer: Arc<signature::Signer> =
            Arc::new(signature::PrivateKey::from_pkcs8(SIGNING_KEY_PKCS8).unwrap());
        #[cfg(target_env = "sgx")]
        let signer: Arc<signature::Signer> = ctx.rak.clone();

        inner.signer = Some(signer);

        return Ok(());
    }

    // Get or create keys.
    pub fn get_or_create_keys(&self, req: &RequestIds) -> Fallible<ContractKey> {
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
    pub fn get_public_key(&self, req: &RequestIds) -> Fallible<Option<PublicKey>> {
        let contract_keys = self.get_or_create_keys(req)?;
        Ok(Some(contract_keys.input_keypair.get_pk()))
    }

    /// Signs the public key using the key manager key.
    pub fn sign_public_key(
        &self,
        key: PublicKey,
        timestamp: Option<u64>,
    ) -> Fallible<SignedPublicKey> {
        let mut body = key.as_ref().to_vec();
        if let Some(ts) = timestamp {
            body.write_u64::<BigEndian>(ts).unwrap();
        }

        let inner = self.inner.read().unwrap();
        let signer = match inner.signer.as_ref() {
            Some(rak) => rak,
            None => return Err(KeyManagerError::NotInitialized.into()),
        };
        let signature = signer.sign(&PUBLIC_KEY_CONTEXT, &body)?;

        Ok(SignedPublicKey {
            key,
            timestamp,
            signature,
        })
    }

    fn load_master_secret() -> Option<Vec<u8>> {
        let ciphertext = StorageContext::with_current(|_cas, _mkvs, untrusted_local| {
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
            .open(&nonce, ciphertext.to_vec(), vec![])
            .expect("persisted state is corrupted");

        Some(plaintext)
    }

    fn generate_master_secret() -> Vec<u8> {
        let mut rng = OsRng::new().unwrap();

        // TODO: Support static keying for debugging.
        let mut master_secret = [0u8; 32];
        rng.fill(&mut master_secret);

        // Encrypt the master secret.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(&nonce, master_secret.to_vec(), vec![]);
        ciphertext.extend_from_slice(&nonce);

        // Persist the encrypted master secret.
        StorageContext::with_current(|_cas, _mkvs, untrusted_local| {
            untrusted_local.insert(MASTER_SECRET_STORAGE_KEY.to_vec(), ciphertext)
        })
        .expect("failed to persist master secret");

        master_secret.to_vec()
    }

    fn new_d2() -> DeoxysII {
        let mut seal_key = egetkey(Keypolicy::MRENCLAVE, &MASTER_SECRET_SEAL_CONTEXT);
        let d2 = DeoxysII::new(&seal_key);
        seal_key.zeroize();

        d2
    }
}
