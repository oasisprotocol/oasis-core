//! Key manager client which talks to a remote key manager enclave.
#[cfg(target_env = "sgx")]
use std::iter::FromIterator;
use std::{
    collections::HashSet,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use lru::LruCache;

use oasis_core_runtime::{
    common::{
        crypto::signature::{self, PublicKey},
        namespace::Namespace,
        sgx::{EnclaveIdentity, QuotePolicy},
    },
    consensus::{
        beacon::EpochTime,
        state::{beacon::ImmutableState as BeaconState, keymanager::Status as KeyManagerStatus},
        verifier::Verifier,
    },
    enclave_rpc::{client::RpcClient, session},
    identity::Identity,
    protocol::Protocol,
};

use crate::{
    api::{
        EphemeralKeyRequest, KeyManagerError, LongTermKeyRequest, ReplicateEphemeralSecretRequest,
        ReplicateEphemeralSecretResponse, ReplicateMasterSecretRequest,
        ReplicateMasterSecretResponse, METHOD_GET_OR_CREATE_EPHEMERAL_KEYS,
        METHOD_GET_OR_CREATE_KEYS, METHOD_GET_PUBLIC_EPHEMERAL_KEY, METHOD_GET_PUBLIC_KEY,
        METHOD_REPLICATE_EPHEMERAL_SECRET, METHOD_REPLICATE_MASTER_SECRET,
    },
    crypto::{KeyPair, KeyPairId, Secret, SignedPublicKey},
    policy::{set_trusted_policy_signers, verify_policy_and_trusted_signers, TrustedPolicySigners},
};

use super::KeyManagerClient;

/// Key manager RPC endpoint.
const KEY_MANAGER_ENDPOINT: &str = "key-manager";

struct Inner {
    /// Runtime identifier for which we are going to request keys.
    runtime_id: Namespace,
    /// RPC client.
    rpc_client: RpcClient,
    /// Consensus verifier.
    consensus_verifier: Arc<dyn Verifier>,
    /// Local cache for the long-term private keys.
    longterm_private_keys: RwLock<LruCache<(KeyPairId, u64), KeyPair>>,
    /// Local cache for the long-term public keys.
    longterm_public_keys: RwLock<LruCache<(KeyPairId, u64), SignedPublicKey>>,
    /// Local cache for the ephemeral private keys.
    ephemeral_private_keys: RwLock<LruCache<(KeyPairId, EpochTime), KeyPair>>,
    /// Local cache for the ephemeral public keys.
    ephemeral_public_keys: RwLock<LruCache<(KeyPairId, EpochTime), SignedPublicKey>>,
    /// Key manager's runtime signing key.
    rsk: RwLock<Option<PublicKey>>,
}

/// A key manager client which talks to a remote key manager enclave.
pub struct RemoteClient {
    inner: Arc<Inner>,
}

impl RemoteClient {
    fn new(
        runtime_id: Namespace,
        rpc_client: RpcClient,
        consensus_verifier: Arc<dyn Verifier>,
        keys_cache_sizes: usize,
    ) -> Self {
        let cap = NonZeroUsize::new(keys_cache_sizes).unwrap();

        Self {
            inner: Arc::new(Inner {
                runtime_id,
                rpc_client,
                consensus_verifier,
                longterm_private_keys: RwLock::new(LruCache::new(cap)),
                longterm_public_keys: RwLock::new(LruCache::new(cap)),
                ephemeral_private_keys: RwLock::new(LruCache::new(cap)),
                ephemeral_public_keys: RwLock::new(LruCache::new(cap)),
                rsk: RwLock::new(None),
            }),
        }
    }

    /// Create a new key manager client with runtime-internal transport and explicit key manager
    /// enclave identities and quote policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new_runtime_with_enclaves_and_policy(
        runtime_id: Namespace,
        km_runtime_id: Option<Namespace>,
        enclaves: Option<HashSet<EnclaveIdentity>>,
        policy: Option<Arc<QuotePolicy>>,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
        identity: Arc<Identity>,
        keys_cache_sizes: usize,
        nodes: Vec<signature::PublicKey>,
    ) -> Self {
        Self::new(
            runtime_id,
            RpcClient::new_runtime(
                session::Builder::default()
                    .remote_enclaves(enclaves)
                    .quote_policy(policy)
                    .local_identity(identity)
                    .consensus_verifier(Some(consensus_verifier.clone()))
                    .remote_runtime_id(km_runtime_id),
                protocol,
                KEY_MANAGER_ENDPOINT,
                nodes,
            ),
            consensus_verifier,
            keys_cache_sizes,
        )
    }

    /// Create a new key manager client with runtime-internal transport.
    ///
    /// Using this method valid enclave identities, quote policy and key manager runtime ID won't
    /// be preset and should be obtained via the runtime-host protocol and updated with the
    /// `set_status` and `set_quote_policy` methods. In case the signer set is non-empty, session
    /// establishment will fail until the initial policies will be updated.
    pub fn new_runtime(
        runtime_id: Namespace,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
        identity: Arc<Identity>,
        keys_cache_sizes: usize,
        signers: TrustedPolicySigners,
        nodes: Vec<signature::PublicKey>,
    ) -> Self {
        // Skip policy checks iff both OASIS_UNSAFE_SKIP_KM_POLICY and
        // OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES are set. The latter is there to ensure that this is a
        // debug build that is inherently incompatible with non-debug builds.
        let unsafe_skip_policy_checks = option_env!("OASIS_UNSAFE_SKIP_KM_POLICY").is_some()
            && option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_some();

        // When using a non-empty policy signer set we set enclaves to an empty set so until we get
        // a policy we will not accept any enclave identities (as we don't know what they should
        // be). When the policy signer set is empty or unsafe policy skip is enabled we allow any
        // enclave.
        let enclaves = if !signers.signers.is_empty() && !unsafe_skip_policy_checks {
            Some(HashSet::new())
        } else {
            None
        };

        // Key manager's quote policy and runtime ID should be obtained via the runtime-host
        // protocol. Until then, all quote verifications will fail with a missing quote policy
        // error and all remote node identity verifications will fail with a missing runtime ID
        // error.
        let policy = None;
        let km_runtime_id = None;

        // Configure trusted policy signers.
        set_trusted_policy_signers(signers);

        Self::new_runtime_with_enclaves_and_policy(
            runtime_id,
            km_runtime_id,
            enclaves,
            policy,
            protocol,
            consensus_verifier,
            identity,
            keys_cache_sizes,
            nodes,
        )
    }

    /// Set allowed enclaves and runtime signing key from key manager status.
    pub fn set_status(&self, status: KeyManagerStatus) -> Result<(), KeyManagerError> {
        // Set runtime signing key.
        if let Some(rsk) = status.rsk {
            self.inner.rsk.write().unwrap().replace(rsk);
        }

        // Set key manager runtime ID.
        self.inner.rpc_client.update_runtime_id(Some(status.id));

        // Verify and apply the policy, if set.
        let untrusted_policy = match status.policy {
            Some(policy) => policy,
            None => return Ok(()),
        };

        #[cfg_attr(not(target_env = "sgx"), allow(unused))]
        let policy = verify_policy_and_trusted_signers(&untrusted_policy)?;

        // Set client allowed enclaves from key manager policy.
        #[cfg(target_env = "sgx")]
        {
            let enclaves: HashSet<EnclaveIdentity> =
                HashSet::from_iter(policy.enclaves.keys().cloned());
            self.inner.rpc_client.update_enclaves(Some(enclaves));
        }

        Ok(())
    }

    /// Set key manager's quote policy.
    pub fn set_quote_policy(&self, policy: QuotePolicy) {
        self.inner.rpc_client.update_quote_policy(policy);
    }

    /// Set allowed key manager nodes.
    pub fn set_nodes(&self, nodes: Vec<signature::PublicKey>) {
        self.inner.rpc_client.update_nodes(nodes);
    }

    fn verify_public_key(
        &self,
        key: &SignedPublicKey,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
        now: Option<EpochTime>,
    ) -> Result<(), KeyManagerError> {
        let pk = self.inner.rsk.read().unwrap();
        let pk = pk.as_ref().ok_or(KeyManagerError::RSKMissing)?;

        key.verify(self.inner.runtime_id, key_pair_id, epoch, now, pk)
            .map_err(KeyManagerError::InvalidSignature)
    }
}

#[async_trait]
impl KeyManagerClient for RemoteClient {
    fn clear_cache(&self) {
        // We explicitly only take one lock at a time.

        let mut cache = self.inner.longterm_private_keys.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.inner.longterm_public_keys.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.inner.ephemeral_private_keys.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.inner.ephemeral_public_keys.write().unwrap();
        cache.clear();
        drop(cache);
    }

    async fn get_or_create_keys(
        &self,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> Result<KeyPair, KeyManagerError> {
        let id = (key_pair_id, generation);

        // First try to fetch from cache.
        {
            let mut cache = self.inner.longterm_private_keys.write().unwrap();
            if let Some(keys) = cache.get(&id) {
                return Ok(keys.clone());
            }
        }

        // No entry in cache, fetch from key manager.
        let height = self
            .inner
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let keys: KeyPair = self
            .inner
            .rpc_client
            .secure_call(
                METHOD_GET_OR_CREATE_KEYS,
                LongTermKeyRequest {
                    height: Some(height),
                    runtime_id: self.inner.runtime_id,
                    key_pair_id,
                    generation,
                },
            )
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Cache key.
        let mut cache = self.inner.longterm_private_keys.write().unwrap();
        cache.put(id, keys.clone());

        Ok(keys)
    }

    async fn get_public_key(
        &self,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> Result<SignedPublicKey, KeyManagerError> {
        let id = (key_pair_id, generation);

        // First fetch from cache.
        {
            let mut cache = self.inner.longterm_public_keys.write().unwrap();
            if let Some(key) = cache.get(&id) {
                match self.verify_public_key(key, key_pair_id, None, None) {
                    Ok(()) => return Ok(key.clone()),
                    Err(_) => {
                        cache.pop(&id);
                    }
                }
            }
        }

        // No entry in cache, fetch from key manager.
        let height = self
            .inner
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let key: SignedPublicKey = self
            .inner
            .rpc_client
            .insecure_call(
                METHOD_GET_PUBLIC_KEY,
                LongTermKeyRequest {
                    height: Some(height),
                    runtime_id: self.inner.runtime_id,
                    key_pair_id,
                    generation,
                },
            )
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Verify the signature.
        self.verify_public_key(&key, key_pair_id, None, None)?;

        // Cache key.
        let mut cache = self.inner.longterm_public_keys.write().unwrap();
        cache.put(id, key.clone());

        Ok(key)
    }

    async fn get_or_create_ephemeral_keys(
        &self,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Result<KeyPair, KeyManagerError> {
        let id = (key_pair_id, epoch);

        // First try to fetch from cache.
        {
            let mut cache = self.inner.ephemeral_private_keys.write().unwrap();
            if let Some(keys) = cache.get(&id) {
                return Ok(keys.clone());
            }
        }

        // No entry in cache, fetch from key manager.
        let height = self
            .inner
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let keys: KeyPair = self
            .inner
            .rpc_client
            .secure_call(
                METHOD_GET_OR_CREATE_EPHEMERAL_KEYS,
                EphemeralKeyRequest {
                    height: Some(height),
                    runtime_id: self.inner.runtime_id,
                    key_pair_id,
                    epoch,
                },
            )
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Cache key.
        let mut cache = self.inner.ephemeral_private_keys.write().unwrap();
        cache.put(id, keys.clone());

        Ok(keys)
    }

    async fn get_public_ephemeral_key(
        &self,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Result<SignedPublicKey, KeyManagerError> {
        let id = (key_pair_id, epoch);

        // Fetch current epoch.
        let consensus_state = self.inner.consensus_verifier.latest_state().await?;
        let consensus_epoch = tokio::task::block_in_place(move || {
            let beacon_state = BeaconState::new(&consensus_state);
            beacon_state.epoch()
        })?;

        // First try to fetch from cache.
        {
            let mut cache = self.inner.ephemeral_public_keys.write().unwrap();
            if let Some(key) = cache.get(&id) {
                match self.verify_public_key(key, key_pair_id, Some(epoch), Some(consensus_epoch)) {
                    Ok(()) => return Ok(key.clone()),
                    Err(_) => {
                        cache.pop(&id);
                    }
                }
            }
        }

        // No entry in cache, fetch from key manager.
        let height = self
            .inner
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let key: SignedPublicKey = self
            .inner
            .rpc_client
            .insecure_call(
                METHOD_GET_PUBLIC_EPHEMERAL_KEY,
                EphemeralKeyRequest {
                    height: Some(height),
                    runtime_id: self.inner.runtime_id,
                    key_pair_id,
                    epoch,
                },
            )
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Verify the signature.
        self.verify_public_key(&key, key_pair_id, Some(epoch), Some(consensus_epoch))?;

        // Cache key.
        let mut cache = self.inner.ephemeral_public_keys.write().unwrap();
        cache.put(id, key.clone());

        Ok(key)
    }

    async fn replicate_master_secret(&self, generation: u64) -> Result<Secret, KeyManagerError> {
        let height = self
            .inner
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        self.inner
            .rpc_client
            .secure_call(
                METHOD_REPLICATE_MASTER_SECRET,
                ReplicateMasterSecretRequest {
                    height: Some(height),
                    generation,
                },
            )
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
            .map(|rsp: ReplicateMasterSecretResponse| rsp.master_secret)
    }

    async fn replicate_ephemeral_secret(
        &self,
        epoch: EpochTime,
    ) -> Result<Secret, KeyManagerError> {
        let height = self
            .inner
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        self.inner
            .rpc_client
            .secure_call(
                METHOD_REPLICATE_EPHEMERAL_SECRET,
                ReplicateEphemeralSecretRequest {
                    height: Some(height),
                    epoch,
                },
            )
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
            .map(|rsp: ReplicateEphemeralSecretResponse| rsp.ephemeral_secret)
    }
}
