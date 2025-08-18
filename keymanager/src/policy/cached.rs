//! Policy support.
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::RwLock,
};

use anyhow::Result;
use lazy_static::lazy_static;
use tiny_keccak::{Hasher, Sha3};

use oasis_core_runtime::{
    common::{namespace::Namespace, sgx::EnclaveIdentity},
    consensus::keymanager::SignedPolicySGX,
};

use crate::api::KeyManagerError;

use super::verify_data_and_trusted_signers;

lazy_static! {
    static ref POLICY: Policy = Policy::new();
}

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
        // Skip policy checks iff both OASIS_UNSAFE_SKIP_KM_POLICY and
        // OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES are set. The latter is there to ensure that this is a
        // debug build that is inherently incompatible with non-debug builds.
        option_env!("OASIS_UNSAFE_SKIP_KM_POLICY").is_some()
            && option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_some()
    }

    /// Global Policy instance.
    pub fn global<'a>() -> &'a Policy {
        &POLICY
    }

    /// Initialize (or update) the policy state.
    ///
    /// The policy is presumed trustworthy, so it's up to the caller to verify it against
    /// the consensus layer state. Empty polices are allowed only in unsafe builds.
    pub fn init(&self, policy: Option<SignedPolicySGX>) -> Result<Vec<u8>> {
        // If this is an insecure build, don't bother trying to apply any policy.
        if policy.is_none() && Self::unsafe_skip() {
            return Ok(vec![]);
        }

        // Cache the new policy.
        let policy = policy.ok_or(KeyManagerError::PolicyRequired)?;
        let new_policy = CachedPolicy::parse(policy)?;

        // Lock as late as possible.
        let mut inner = self.inner.write().unwrap();

        // Compare the new serial number with the old serial number, ensure
        // it is greater.
        if let Some(old_policy) = inner.policy.as_ref() {
            match old_policy.serial.cmp(&new_policy.serial) {
                Ordering::Greater => return Err(KeyManagerError::PolicyRollback.into()),
                Ordering::Equal => {
                    if old_policy.checksum != new_policy.checksum {
                        // Policy should be identical.
                        return Err(KeyManagerError::PolicyChanged.into());
                    }
                    return Ok(new_policy.checksum);
                }
                Ordering::Less => {}
            }
        };

        // Return the checksum of the newly applied policy.
        let new_checksum = new_policy.checksum.clone();
        inner.policy = Some(new_policy);

        Ok(new_checksum)
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
        #[cfg(any(target_env = "sgx", feature = "debug-mock-sgx"))]
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
}

#[derive(Clone, Default, Debug)]
struct CachedPolicy {
    pub checksum: Vec<u8>,
    pub serial: u32,
    pub may_query: HashMap<Namespace, HashSet<EnclaveIdentity>>,
    pub may_replicate: HashSet<EnclaveIdentity>,
    pub may_replicate_from: HashSet<EnclaveIdentity>,
}

impl CachedPolicy {
    fn parse(untrusted_policy: SignedPolicySGX) -> Result<Self> {
        let policy = verify_data_and_trusted_signers(&untrusted_policy)?;

        // Convert the policy into a cached one.
        let mut cached_policy = CachedPolicy {
            serial: policy.serial,
            ..Default::default()
        };

        if let Some(enclave_identity) = EnclaveIdentity::current() {
            if let Some(enclave_policy) = policy.enclaves.get(&enclave_identity) {
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
            }
        }

        let raw = cbor::to_vec(untrusted_policy);
        cached_policy.checksum = Self::checksum_policy(&raw);

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
