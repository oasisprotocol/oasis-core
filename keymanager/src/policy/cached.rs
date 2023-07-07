//! Policy support.
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::RwLock,
};

use anyhow::Result;
use lazy_static::lazy_static;
use sgx_isa::Keypolicy;
use tiny_keccak::{Hasher, Sha3};

use oasis_core_runtime::{
    common::{
        namespace::Namespace,
        sgx::{
            seal::{seal, unseal},
            EnclaveIdentity,
        },
    },
    consensus::{beacon::EpochTime, keymanager::SignedPolicySGX},
    storage::KeyValue,
};

use crate::api::KeyManagerError;

use super::verify_policy_and_trusted_signers;

lazy_static! {
    static ref POLICY: Policy = Policy::new();
}

const POLICY_STORAGE_KEY: &[u8] = b"keymanager_policy";
const POLICY_SEAL_CONTEXT: &[u8] = b"oasis-core/keymanager: policy seal";

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
        option_env!("OASIS_UNSAFE_SKIP_KM_POLICY").is_some()
    }

    /// Global Policy instance.
    pub fn global<'a>() -> &'a Policy {
        &POLICY
    }

    /// Initialize (or update) the policy state.
    ///
    /// The policy is presumed trustworthy, so it's up to the caller to verify it against
    /// the consensus layer state. Empty polices are allowed only in unsafe builds.
    pub fn init(&self, storage: &dyn KeyValue, policy: Option<SignedPolicySGX>) -> Result<Vec<u8>> {
        // If this is an insecure build, don't bother trying to apply any policy.
        if policy.is_none() && Self::unsafe_skip() {
            return Ok(vec![]);
        }

        // Cache the new policy.
        let policy = policy.ok_or(KeyManagerError::PolicyRequired)?;
        let raw_policy = cbor::to_vec(policy.clone());
        let new_policy = CachedPolicy::parse(policy, &raw_policy)?;

        // Lock as late as possible.
        let mut inner = self.inner.write().unwrap();

        // If there is no existing policy, attempt to load from local storage.
        let old_policy = inner
            .policy
            .as_ref()
            .cloned()
            .unwrap_or_else(|| Self::load_policy(storage).unwrap_or_default());

        // Compare the new serial number with the old serial number, ensure
        // it is greater.
        match old_policy.serial.cmp(&new_policy.serial) {
            Ordering::Greater => Err(KeyManagerError::PolicyRollback.into()),
            Ordering::Equal if old_policy.checksum != new_policy.checksum => {
                // Policy should be identical.
                Err(KeyManagerError::PolicyChanged.into())
            }
            Ordering::Equal => {
                inner.policy = Some(old_policy.clone());
                Ok(old_policy.checksum)
            }
            Ordering::Less => {
                // Persist then apply the new policy.
                Self::save_raw_policy(storage, &raw_policy);
                let new_checksum = new_policy.checksum.clone();
                inner.policy = Some(new_policy);

                // Return the checksum of the newly applied policy.
                Ok(new_checksum)
            }
        }
    }

    /// Check if the MRSIGNER/MRENCLAVE may query keys for the given
    /// runtime ID/contract ID.
    pub fn may_get_or_create_keys(
        &self,
        remote_enclave: &EnclaveIdentity,
        runtime_id: &Namespace,
    ) -> Result<()> {
        let inner = self.inner.read().unwrap();
        let policy = inner
            .policy
            .as_ref()
            .ok_or(KeyManagerError::NotAuthorized)?;

        match policy.may_get_or_create_keys(remote_enclave, runtime_id) {
            true => Ok(()),
            false => Err(KeyManagerError::NotAuthorized.into()),
        }
    }

    /// Check if the MRENCLAVE/MRSIGNER may replicate.
    pub fn may_replicate_secret(&self, remote_enclave: &EnclaveIdentity) -> Result<()> {
        // Always allow replication to ourselves, if it is possible to do so in
        // an authenticated manner.
        #[cfg(target_env = "sgx")]
        {
            let our_id = EnclaveIdentity::current().expect("failed to query MRENCLAVE/MRSIGNER");
            if our_id == *remote_enclave {
                return Ok(());
            }
        }

        let inner = self.inner.read().unwrap();
        let policy = inner
            .policy
            .as_ref()
            .ok_or(KeyManagerError::NotAuthorized)?;

        match policy.may_replicate_secret(remote_enclave) {
            true => Ok(()),
            false => Err(KeyManagerError::NotAuthorized.into()),
        }
    }

    /// Return the set of enclave identities we are allowed to replicate from.
    pub fn may_replicate_from(&self) -> Option<HashSet<EnclaveIdentity>> {
        let inner = self.inner.read().unwrap();
        let mut src_set = inner
            .policy
            .as_ref()
            .map(|policy| policy.may_replicate_from.clone())
            .unwrap_or_default();

        if let Some(id) = EnclaveIdentity::current() {
            src_set.insert(id);
        };

        match src_set.is_empty() {
            true => None,
            false => Some(src_set),
        }
    }

    fn load_policy(storage: &dyn KeyValue) -> Option<CachedPolicy> {
        let ciphertext = storage.get(POLICY_STORAGE_KEY.to_vec()).unwrap();

        unseal(Keypolicy::MRENCLAVE, POLICY_SEAL_CONTEXT, &ciphertext).map(|plaintext| {
            // Deserialization failures are fatal, because it is state corruption.
            CachedPolicy::parse_raw(&plaintext).expect("failed to deserialize persisted policy")
        })
    }

    fn save_raw_policy(storage: &dyn KeyValue, raw_policy: &[u8]) {
        let ciphertext = seal(Keypolicy::MRENCLAVE, POLICY_SEAL_CONTEXT, raw_policy);

        // Persist the encrypted policy.
        storage
            .insert(POLICY_STORAGE_KEY.to_vec(), ciphertext)
            .expect("failed to persist policy");
    }
}

#[derive(Clone, Default, Debug)]
struct CachedPolicy {
    pub checksum: Vec<u8>,
    pub serial: u32,
    pub runtime_id: Namespace,
    pub may_query: HashMap<Namespace, HashSet<EnclaveIdentity>>,
    pub may_replicate: HashSet<EnclaveIdentity>,
    pub may_replicate_from: HashSet<EnclaveIdentity>,
    pub master_secret_rotation_interval: EpochTime,
    pub max_ephemeral_secret_age: EpochTime,
}

impl CachedPolicy {
    fn parse_raw(raw: &[u8]) -> Result<Self> {
        let untrusted_policy: SignedPolicySGX = cbor::from_slice(raw)?;
        Self::parse(untrusted_policy, raw)
    }

    fn parse(untrusted_policy: SignedPolicySGX, raw: &[u8]) -> Result<Self> {
        let policy = verify_policy_and_trusted_signers(&untrusted_policy)?;
        let checksum = Self::checksum_policy(raw);

        let mut cached_policy = Self::default();
        cached_policy.serial = policy.serial;
        cached_policy.runtime_id = policy.id;
        cached_policy.checksum = checksum;

        // Convert the policy into a cached one.
        //
        // TODO: Need a mock enclave identity for non-sgx builds if we want to
        // ever test policies with such a build.
        let enclave_identity = match EnclaveIdentity::current() {
            Some(enclave_identity) => enclave_identity,
            None => return Ok(cached_policy),
        };
        let enclave_policy = match policy.enclaves.get(&enclave_identity) {
            Some(enclave_policy) => enclave_policy,
            None => return Ok(cached_policy), // No policy for the current enclave.
        };
        for (rt_id, ids) in &enclave_policy.may_query {
            let mut query_ids = HashSet::new();
            for e_id in ids {
                query_ids.insert(e_id.clone());
            }
            cached_policy.may_query.insert(*rt_id, query_ids);
        }
        for e_id in &enclave_policy.may_replicate {
            cached_policy.may_replicate.insert(e_id.clone());
        }
        for (e_id, other_policy) in &policy.enclaves {
            if other_policy.may_replicate.contains(&enclave_identity) {
                cached_policy.may_replicate_from.insert(e_id.clone());
            }
        }

        cached_policy.master_secret_rotation_interval = policy.master_secret_rotation_interval;
        cached_policy.max_ephemeral_secret_age = policy.max_ephemeral_secret_age;

        Ok(cached_policy)
    }

    fn may_get_or_create_keys(
        &self,
        remote_enclave: &EnclaveIdentity,
        runtime_id: &Namespace,
    ) -> bool {
        let may_query = match self.may_query.get(runtime_id) {
            Some(may_query) => may_query,
            None => return false,
        };
        may_query.contains(remote_enclave)
    }

    fn may_replicate_secret(&self, remote_enclave: &EnclaveIdentity) -> bool {
        self.may_replicate.contains(remote_enclave)
    }

    fn checksum_policy(raw: &[u8]) -> Vec<u8> {
        let mut sha3 = Sha3::v256();
        sha3.update(raw);
        let mut k = [0; 32];
        sha3.finalize(&mut k);
        k.to_vec()
    }
}
