//! Policy support.
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::RwLock,
};

use anyhow::Result;
use io_context::Context;
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
    consensus::{
        keymanager::SignedPolicySGX, state::keymanager::ImmutableState as KeyManagerState,
    },
    enclave_rpc::Context as RpcContext,
    runtime_context,
    storage::KeyValue,
};

use crate::{api::KeyManagerError, runtime::context::Context as KmContext};

use super::verify_policy_and_trusted_signers;

lazy_static! {
    static ref POLICY: Policy = Policy::new();
}

const POLICY_STORAGE_KEY: &[u8] = b"keymanager_policy";
const POLICY_SEAL_CONTEXT: &[u8] = b"Ekiden Keymanager Seal policy v0";

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
    pub fn init(&self, ctx: &mut RpcContext, raw_policy: &[u8]) -> Result<Vec<u8>> {
        // If this is an insecure build, don't bother trying to apply any policy.
        if Self::unsafe_skip() {
            return Ok(vec![]);
        }

        // De-serialize the new policy, verify signatures.
        let new_policy = CachedPolicy::parse(raw_policy)?;

        // Ensure the new policy's runtime ID matches the current enclave's.
        let rctx = runtime_context!(ctx, KmContext);
        if rctx.runtime_id != new_policy.runtime_id {
            return Err(KeyManagerError::PolicyInvalidRuntime.into());
        }

        // Ensure the new policy was published in the consensus layer.
        let state = ctx.consensus_verifier.latest_state()?;
        let km_state = KeyManagerState::new(&state);
        let published_policy = km_state
            .status(Context::create_child(&ctx.io_ctx), new_policy.runtime_id)?
            .ok_or(KeyManagerError::PolicyNotPublished)?
            .policy
            .ok_or(KeyManagerError::PolicyNotPublished)?;
        let untrusted_policy: SignedPolicySGX = cbor::from_slice(raw_policy)?;
        if untrusted_policy != published_policy {
            return Err(KeyManagerError::PolicyNotPublished.into());
        }

        // Lock as late as possible.
        let mut inner = self.inner.write().unwrap();

        // If there is no existing policy, attempt to load from local storage.
        let old_policy =
            inner.policy.as_ref().cloned().unwrap_or_else(|| {
                Self::load_policy(ctx.untrusted_local_storage).unwrap_or_default()
            });

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
                Self::save_raw_policy(ctx.untrusted_local_storage, raw_policy);
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
    pub fn may_replicate_master_secret(&self, remote_enclave: &EnclaveIdentity) -> Result<()> {
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

        match policy.may_replicate_master_secret(remote_enclave) {
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

    fn load_policy(untrusted_local: &dyn KeyValue) -> Option<CachedPolicy> {
        let ciphertext = untrusted_local.get(POLICY_STORAGE_KEY.to_vec()).unwrap();

        unseal(Keypolicy::MRENCLAVE, POLICY_SEAL_CONTEXT, &ciphertext).map(|plaintext| {
            // Deserialization failures are fatal, because it is state corruption.
            CachedPolicy::parse(&plaintext).expect("failed to deserialize persisted policy")
        })
    }

    fn save_raw_policy(untrusted_local: &dyn KeyValue, raw_policy: &[u8]) {
        let ciphertext = seal(Keypolicy::MRENCLAVE, POLICY_SEAL_CONTEXT, raw_policy);

        // Persist the encrypted master secret.
        untrusted_local
            .insert(POLICY_STORAGE_KEY.to_vec(), ciphertext)
            .expect("failed to persist master secret");
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
}

impl CachedPolicy {
    fn parse(raw: &[u8]) -> Result<Self> {
        // Parse out the signed policy.
        let untrusted_policy: SignedPolicySGX = cbor::from_slice(raw)?;
        let policy = verify_policy_and_trusted_signers(&untrusted_policy)?;

        let mut cached_policy = Self::default();
        cached_policy.serial = policy.serial;
        cached_policy.runtime_id = policy.id;

        let mut sha3 = Sha3::v256();
        sha3.update(raw);
        let mut k = [0; 32];
        sha3.finalize(&mut k);
        cached_policy.checksum = k.to_vec();

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

    fn may_replicate_master_secret(&self, remote_enclave: &EnclaveIdentity) -> bool {
        self.may_replicate.contains(remote_enclave)
    }
}
