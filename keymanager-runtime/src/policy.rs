//! Policy support.
use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
};

use failure::Fallible;
use lazy_static::lazy_static;
use rand::{rngs::OsRng, Rng};
use serde_cbor;
use sgx_isa::Keypolicy;
use tiny_keccak::sha3_256;
use zeroize::Zeroize;

use ekiden_keymanager_api::*;
use ekiden_runtime::{
    common::{
        crypto::{
            mrae::deoxysii::{DeoxysII, NONCE_SIZE, TAG_SIZE},
            signature::{PrivateKey, PublicKey},
        },
        runtime::RuntimeId,
        sgx::{
            avr::{get_enclave_identity, EnclaveIdentity},
            egetkey::egetkey,
        },
    },
    rpc::Context as RpcContext,
    runtime_context,
    storage::StorageContext,
};

use crate::context::Context as KmContext;

lazy_static! {
    static ref POLICY: Policy = Policy::new();
    static ref MULTISIG_KEYS: HashSet<PublicKey> = {
        let mut set = HashSet::new();
        if option_env!("EKIDNE_UNSAFE_KM_POLICY_KEYS").is_some() {
            for seed in [
                "ekiden key manager test multisig key 0",
                "ekiden key manager test multisig key 1",
                "ekiden key manager test multisig key 2",
            ].iter() {
                let private_key = PrivateKey::from_test_seed(
                    seed.to_string(),
                );
                set.insert(private_key.public_key());
            }
        }

        // TODO: Populate with the production keys as well.
        set
    };
}
const MULTISIG_THRESHOLD: usize = 0; // TODO: Set this to a real value.

const POLICY_STORAGE_KEY: &'static [u8] = b"keymanager_policy";
const POLICY_SEAL_CONTEXT: &'static [u8] = b"Ekiden Keymanager Seal policy v0";
const POLICY_SIGN_CONTEXT: [u8; 8] = *b"EkKmPolS";

/// Policy, which manages the key manager policy.
pub struct Policy {
    inner: RwLock<Inner>,
}

struct Inner {
    policy: Option<CachedPolicy>,
}

impl Policy {
    fn new() -> Self {
        Self {
            inner: RwLock::new(Inner { policy: None }),
        }
    }

    pub fn unsafe_skip() -> bool {
        option_env!("EKIDEN_UNSAFE_SKIP_KM_POLICY").is_some()
    }

    /// Global Policy instance.
    pub fn global<'a>() -> &'a Policy {
        &POLICY
    }

    /// Initialize (or update) the policy state.
    pub fn init(&self, ctx: &mut RpcContext, raw_policy: &Vec<u8>) -> Fallible<Vec<u8>> {
        // If this is an insecure build, don't bother trying to apply any policy.
        if Self::unsafe_skip() {
            return Ok(vec![]);
        }

        let mut inner = self.inner.write().unwrap();

        // If there is no existing policy, attempt to load from local storage.
        let old_policy = match inner.policy.as_ref() {
            Some(old_policy) => old_policy.clone(),
            None => match Self::load_policy() {
                Some(old_policy) => old_policy,
                None => CachedPolicy::default(),
            },
        };

        // De-serialize the new policy, verify signatures.
        let new_policy = CachedPolicy::parse(raw_policy)?;

        // Ensure the new policy's runtime ID matches the current enclave's.
        let rctx = runtime_context!(ctx, KmContext);
        if rctx.runtime_id != new_policy.runtime_id {
            return Err(KeyManagerError::PolicyInvalid.into());
        }

        // Compare the new serial number with the old serial number, ensure
        // it is greater.
        if old_policy.serial > new_policy.serial {
            return Err(KeyManagerError::PolicyRollback.into());
        } else if old_policy.serial == new_policy.serial {
            // Policy should be identical, ensure nothing has changed
            // and just return.
            if old_policy.checksum != new_policy.checksum {
                return Err(KeyManagerError::PolicyChanged.into());
            }
            return Ok(old_policy.checksum.clone());
        }

        // Persist then apply the new policy.
        Self::save_raw_policy(raw_policy);
        let new_checksum = new_policy.checksum.clone();
        inner.policy = Some(new_policy);

        // Return the checksum of the newly applied policy.
        Ok(new_checksum)
    }

    /// Check if the MRSIGNER/MRENCLAVE may query keys for the given
    /// runtime ID/contract ID.
    pub fn may_get_or_create_keys(
        &self,
        remote_enclave: &EnclaveIdentity,
        req: &RequestIds,
    ) -> Fallible<()> {
        let inner = self.inner.read().unwrap();
        let policy = match inner.policy.as_ref() {
            Some(policy) => policy,
            None => return Err(KeyManagerError::InvalidAuthentication.into()),
        };
        match policy.may_get_or_create_keys(remote_enclave, req) {
            true => Ok(()),
            false => Err(KeyManagerError::InvalidAuthentication.into()),
        }
    }

    /// Check if the MRSIGNER/MRENCLAVE may replicate.
    pub fn may_replicate_master_secret(&self, remote_enclave: &EnclaveIdentity) -> Fallible<()> {
        // Always allow replication to ourselves, if it is possible to do so in
        // an authenticated manner.
        #[cfg(target_env = "sgx")]
        {
            let our_id = get_enclave_identity().expect("failed to query MRSIGNER/MRENCLAVE");
            if our_id == *remote_enclave {
                return Ok(());
            }
        }

        let inner = self.inner.read().unwrap();
        let policy = match inner.policy.as_ref() {
            Some(policy) => policy,
            None => return Err(KeyManagerError::InvalidAuthentication.into()),
        };
        match policy.may_replicate_master_secret(remote_enclave) {
            true => Ok(()),
            false => Err(KeyManagerError::InvalidAuthentication.into()),
        }
    }

    fn load_policy() -> Option<CachedPolicy> {
        let ciphertext = StorageContext::with_current(|_mkvs, untrusted_local| {
            untrusted_local.get(POLICY_STORAGE_KEY.to_vec())
        })
        .unwrap();

        let ct_len = ciphertext.len();
        if ct_len == 0 {
            return None;
        } else if ct_len < TAG_SIZE + NONCE_SIZE {
            panic!("persisted state is corrupted, invalid size");
        }
        let ct_len = ct_len - NONCE_SIZE;

        // Split the ciphertext || tag || nonce.
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&ciphertext[ct_len..]);
        let ciphertext = &ciphertext[..ct_len];

        let d2 = Self::new_d2();
        let plaintext = d2
            .open(&nonce, ciphertext.to_vec(), vec![])
            .expect("persisted state is corrupted");

        // Deserialization failures are fatal, because it is state corruption.
        Some(CachedPolicy::parse(&plaintext).expect("failed to deserialize persisted policy"))
    }

    fn save_raw_policy(raw_policy: &Vec<u8>) {
        let mut rng = OsRng::new().unwrap();

        // Encrypt the raw policy.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let d2 = Self::new_d2();
        let mut ciphertext = d2.seal(&nonce, raw_policy.to_vec(), vec![]);
        ciphertext.extend_from_slice(&nonce);

        // Persist the encrypted master secret.
        StorageContext::with_current(|_mkvs, untrusted_local| {
            untrusted_local.insert(POLICY_STORAGE_KEY.to_vec(), ciphertext)
        })
        .expect("failed to persist master secret");
    }

    fn new_d2() -> DeoxysII {
        let mut seal_key = egetkey(Keypolicy::MRENCLAVE, &POLICY_SEAL_CONTEXT);
        let d2 = DeoxysII::new(&seal_key);
        seal_key.zeroize();

        d2
    }
}

#[derive(Clone)]
struct CachedPolicy {
    pub checksum: Vec<u8>,
    pub serial: u32,
    pub runtime_id: RuntimeId,
    pub may_query: HashMap<RuntimeId, HashSet<EnclaveIdentity>>,
    pub may_replicate: HashSet<EnclaveIdentity>,
    pub may_replicate_from: HashSet<EnclaveIdentity>,
}

impl CachedPolicy {
    fn parse(raw: &Vec<u8>) -> Fallible<Self> {
        // Parse out the signed policy.
        let untrusted_policy: SignedPolicySGX = serde_cbor::from_slice(&raw)?;

        // Verify the signatures.
        let untrusted_policy_raw = serde_cbor::to_vec(&untrusted_policy.policy)?;
        let mut signers: HashSet<PublicKey> = HashSet::new();
        for sig in untrusted_policy.signatures {
            let public_key = match sig.public_key {
                Some(public_key) => public_key,
                None => return Err(KeyManagerError::PolicyInvalid.into()),
            };

            if !sig
                .signature
                .verify(&public_key, &POLICY_SIGN_CONTEXT, &untrusted_policy_raw)
                .is_ok()
            {
                return Err(KeyManagerError::PolicyInvalidSignature.into());
            }
            signers.insert(public_key);
        }

        // Ensure that enough valid signatures from trusted signers are present.
        let signers: HashSet<_> = MULTISIG_KEYS.intersection(&signers).collect();
        let multisig_threshold = match option_env!("EKIDNE_UNSAFE_KM_POLICY_KEYS") {
            Some(_) => 2,
            None => MULTISIG_THRESHOLD,
        };
        if signers.len() < multisig_threshold {
            return Err(KeyManagerError::PolicyInsufficientSignatures.into());
        }

        let policy = untrusted_policy.policy;
        let mut cached_policy = Self::default();
        cached_policy.checksum = sha3_256(&raw).to_vec();
        cached_policy.serial = policy.serial;
        cached_policy.runtime_id = policy.id;

        // Convert the policy into a cached one.
        //
        // TODO: Need a mock enclave identity for non-sgx builds if we want to
        // ever test policies with such a build.
        let enclave_identity = match get_enclave_identity() {
            Some(enclave_identity) => RawEnclaveId::from(enclave_identity),
            None => return Ok(cached_policy),
        };
        let enclave_policy = match policy.enclaves.get(&enclave_identity) {
            Some(enclave_policy) => enclave_policy,
            None => return Ok(cached_policy), // No policy for the current enclave.
        };
        for (rt_id, ids) in &enclave_policy.may_query {
            let mut query_ids = HashSet::new();
            for raw_id in ids {
                query_ids.insert((*raw_id).into());
            }
            cached_policy.may_query.insert(*rt_id, query_ids);
        }
        for raw_id in &enclave_policy.may_replicate {
            cached_policy.may_replicate.insert((*raw_id).into());
        }
        for (raw_id, other_policy) in &policy.enclaves {
            if other_policy.may_replicate.contains(&enclave_identity) {
                cached_policy.may_replicate_from.insert((*raw_id).into());
            }
        }

        Ok(cached_policy)
    }

    fn default() -> Self {
        CachedPolicy {
            checksum: vec![],
            serial: 0,
            runtime_id: RuntimeId::default(),
            may_query: HashMap::new(),
            may_replicate: HashSet::new(),
            may_replicate_from: HashSet::new(),
        }
    }

    fn may_get_or_create_keys(&self, remote_enclave: &EnclaveIdentity, req: &RequestIds) -> bool {
        let may_query = match self.may_query.get(&req.runtime_id) {
            Some(may_query) => may_query,
            None => return false,
        };
        may_query.contains(remote_enclave)
    }

    fn may_replicate_master_secret(&self, remote_enclave: &EnclaveIdentity) -> bool {
        self.may_replicate.contains(remote_enclave)
    }
}
