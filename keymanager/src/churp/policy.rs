//! Policy support.
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use anyhow::Result;

use oasis_core_runtime::{
    common::sgx::EnclaveIdentity,
    consensus::keymanager::churp::{PolicySGX, SignedPolicySGX},
};

use crate::policy::verify_data_and_trusted_signers;

use super::Error;

/// A collection of cached key manager policies.
pub struct VerifiedPolicies {
    policies: Mutex<HashMap<u8, Arc<VerifiedPolicy>>>,
}

impl VerifiedPolicies {
    /// Creates a new collection of cached verified policies.
    pub fn new() -> Self {
        Self {
            policies: Mutex::new(HashMap::new()),
        }
    }

    /// Verifies and caches the given policy.
    pub fn verify(&self, policy: &SignedPolicySGX) -> Result<Arc<VerifiedPolicy>> {
        let mut policies = self.policies.lock().unwrap();

        let churp_id = policy.policy.id;
        let verified_policy = policies.get(&churp_id);
        if let Some(verified_policy) = verified_policy {
            match verified_policy.serial.cmp(&policy.policy.serial) {
                Ordering::Less => (),
                Ordering::Equal => return Ok(verified_policy.clone()),
                Ordering::Greater => return Err(Error::PolicyRollback.into()),
            }
        }

        let verified_policy = verify_data_and_trusted_signers(policy)?;
        let verified_policy = VerifiedPolicy::new(verified_policy)?;
        let verified_policy = Arc::new(verified_policy);
        policies.insert(churp_id, verified_policy.clone());

        Ok(verified_policy)
    }
}

impl Default for VerifiedPolicies {
    fn default() -> Self {
        Self::new()
    }
}

/// A policy verified to be signed by trusted signers and published
/// in the consensus layer.
#[derive(Clone, Default, Debug)]
pub struct VerifiedPolicy {
    /// A monotonically increasing policy serial number.
    pub serial: u32,

    /// A set of enclave identities from which a share can be obtained
    /// during handouts.
    pub may_share: HashSet<EnclaveIdentity>,

    /// A hash of enclave identities that may form the new committee
    /// in the next handoffs.
    pub may_join: HashSet<EnclaveIdentity>,
}

impl VerifiedPolicy {
    /// Creates a new policy from the given SGX policy.
    ///
    /// The provided policy should be valid, signed by trusted signers,
    /// and published in the consensus layer state.
    fn new(verified_policy: &PolicySGX) -> Result<Self> {
        let mut may_share = HashSet::new();
        for enclave_identity in &verified_policy.may_share {
            may_share.insert(enclave_identity.clone());
        }

        let mut may_join = HashSet::new();
        for enclave_identity in &verified_policy.may_join {
            may_join.insert(enclave_identity.clone());
        }

        Ok(Self {
            serial: verified_policy.serial,
            may_share,
            may_join,
        })
    }

    /// Returns true iff shares can be obtained from the remote enclave
    /// during handouts.
    pub fn may_share(&self, remote_enclave: &EnclaveIdentity) -> bool {
        self.may_share.contains(remote_enclave)
    }

    /// Returns true iff the remote enclave is allowed to form the new
    /// committee in the next handoffs.
    pub fn may_join(&self, remote_enclave: &EnclaveIdentity) -> bool {
        self.may_join.contains(remote_enclave)
    }
}
