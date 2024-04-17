//! Key manager client which talks to a remote key manager enclave.
use std::{
    collections::HashSet,
    iter::FromIterator,
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
    churp::{
        EncodedSecretShare, QueryRequest, METHOD_BIVARIATE_SHARE, METHOD_SHARE_DISTRIBUTION_POINT,
        METHOD_SHARE_REDUCTION_POINT, METHOD_VERIFICATION_MATRIX,
    },
    crypto::{KeyPair, KeyPairId, Secret, SignedPublicKey, VerifiableSecret},
    policy::{set_trusted_signers, verify_data_and_trusted_signers, Policy, TrustedSigners},
};

use super::KeyManagerClient;

/// Key manager RPC endpoint.
const KEY_MANAGER_ENDPOINT: &str = "key-manager";

/// A key manager client which talks to a remote key manager enclave.
pub struct RemoteClient {
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

impl RemoteClient {
    fn new(
        runtime_id: Namespace,
        rpc_client: RpcClient,
        consensus_verifier: Arc<dyn Verifier>,
        keys_cache_sizes: usize,
    ) -> Self {
        let cap = NonZeroUsize::new(keys_cache_sizes).unwrap();

        Self {
            runtime_id,
            rpc_client,
            consensus_verifier,
            longterm_private_keys: RwLock::new(LruCache::new(cap)),
            longterm_public_keys: RwLock::new(LruCache::new(cap)),
            ephemeral_private_keys: RwLock::new(LruCache::new(cap)),
            ephemeral_public_keys: RwLock::new(LruCache::new(cap)),
            rsk: RwLock::new(None),
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
        signers: TrustedSigners,
        nodes: Vec<signature::PublicKey>,
    ) -> Self {
        // When using a non-empty policy signer set we set enclaves to an empty set so until we get
        // a policy we will not accept any enclave identities (as we don't know what they should
        // be). When the policy signer set is empty or unsafe policy skip is enabled we allow any
        // enclave.
        let enclaves = if !signers.signers.is_empty() && !Policy::unsafe_skip() {
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

        // Configure trusted signers.
        set_trusted_signers(signers);

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
            self.rsk.write().unwrap().replace(rsk);
        }

        // Set key manager runtime ID.
        self.rpc_client.update_runtime_id(Some(status.id));

        // Verify and apply the policy, if set.
        let untrusted_policy = match status.policy {
            Some(policy) => policy,
            None => return Ok(()),
        };

        let policy = verify_data_and_trusted_signers(&untrusted_policy)?;

        // Set client allowed enclaves from key manager policy.
        if !Policy::unsafe_skip() {
            let enclaves: HashSet<EnclaveIdentity> =
                HashSet::from_iter(policy.enclaves.keys().cloned());
            self.rpc_client.update_enclaves(Some(enclaves));
        }

        Ok(())
    }

    /// Set key manager's quote policy.
    pub fn set_quote_policy(&self, policy: QuotePolicy) {
        self.rpc_client.update_quote_policy(policy);
    }

    /// Set allowed key manager nodes.
    pub fn set_nodes(&self, nodes: Vec<signature::PublicKey>) {
        self.rpc_client.update_nodes(nodes);
    }

    fn verify_public_key(
        &self,
        key: &SignedPublicKey,
        key_pair_id: KeyPairId,
        epoch: Option<EpochTime>,
        now: Option<EpochTime>,
    ) -> Result<(), KeyManagerError> {
        let pk = self.rsk.read().unwrap();
        let pk = pk.as_ref().ok_or(KeyManagerError::RSKMissing)?;

        key.verify(self.runtime_id, key_pair_id, epoch, now, pk)
            .map_err(KeyManagerError::InvalidSignature)
    }
}

#[async_trait]
impl KeyManagerClient for RemoteClient {
    fn clear_cache(&self) {
        // We explicitly only take one lock at a time.

        let mut cache = self.longterm_private_keys.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.longterm_public_keys.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.ephemeral_private_keys.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.ephemeral_public_keys.write().unwrap();
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
            let mut cache = self.longterm_private_keys.write().unwrap();
            if let Some(keys) = cache.get(&id) {
                return Ok(keys.clone());
            }
        }

        // No entry in cache, fetch from key manager.
        let height = self
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let keys: KeyPair = self
            .rpc_client
            .secure_call(
                METHOD_GET_OR_CREATE_KEYS,
                LongTermKeyRequest {
                    height: Some(height),
                    runtime_id: self.runtime_id,
                    key_pair_id,
                    generation,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Cache key.
        let mut cache = self.longterm_private_keys.write().unwrap();
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
            let mut cache = self.longterm_public_keys.write().unwrap();
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
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let key: SignedPublicKey = self
            .rpc_client
            .insecure_call(
                METHOD_GET_PUBLIC_KEY,
                LongTermKeyRequest {
                    height: Some(height),
                    runtime_id: self.runtime_id,
                    key_pair_id,
                    generation,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Verify the signature.
        self.verify_public_key(&key, key_pair_id, None, None)?;

        // Cache key.
        let mut cache = self.longterm_public_keys.write().unwrap();
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
            let mut cache = self.ephemeral_private_keys.write().unwrap();
            if let Some(keys) = cache.get(&id) {
                return Ok(keys.clone());
            }
        }

        // No entry in cache, fetch from key manager.
        let height = self
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let keys: KeyPair = self
            .rpc_client
            .secure_call(
                METHOD_GET_OR_CREATE_EPHEMERAL_KEYS,
                EphemeralKeyRequest {
                    height: Some(height),
                    runtime_id: self.runtime_id,
                    key_pair_id,
                    epoch,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Cache key.
        let mut cache = self.ephemeral_private_keys.write().unwrap();
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
        let consensus_state = self.consensus_verifier.latest_state().await?;
        let consensus_epoch = tokio::task::block_in_place(move || {
            let beacon_state = BeaconState::new(&consensus_state);
            beacon_state.epoch()
        })?;

        // First try to fetch from cache.
        {
            let mut cache = self.ephemeral_public_keys.write().unwrap();
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
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        let key: SignedPublicKey = self
            .rpc_client
            .insecure_call(
                METHOD_GET_PUBLIC_EPHEMERAL_KEY,
                EphemeralKeyRequest {
                    height: Some(height),
                    runtime_id: self.runtime_id,
                    key_pair_id,
                    epoch,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        // Verify the signature.
        self.verify_public_key(&key, key_pair_id, Some(epoch), Some(consensus_epoch))?;

        // Cache key.
        let mut cache = self.ephemeral_public_keys.write().unwrap();
        cache.put(id, key.clone());

        Ok(key)
    }

    async fn replicate_master_secret(
        &self,
        generation: u64,
    ) -> Result<VerifiableSecret, KeyManagerError> {
        let height = self
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        self.rpc_client
            .secure_call(
                METHOD_REPLICATE_MASTER_SECRET,
                ReplicateMasterSecretRequest {
                    height: Some(height),
                    generation,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
            .map(|rsp: ReplicateMasterSecretResponse| VerifiableSecret {
                secret: rsp.master_secret,
                checksum: rsp.checksum,
            })
    }

    async fn replicate_ephemeral_secret(
        &self,
        epoch: EpochTime,
    ) -> Result<Secret, KeyManagerError> {
        let height = self
            .consensus_verifier
            .latest_height()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))?;

        self.rpc_client
            .secure_call(
                METHOD_REPLICATE_EPHEMERAL_SECRET,
                ReplicateEphemeralSecretRequest {
                    height: Some(height),
                    epoch,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
            .map(|rsp: ReplicateEphemeralSecretResponse| rsp.ephemeral_secret)
    }

    async fn verification_matrix(
        &self,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Result<Vec<u8>, KeyManagerError> {
        self.rpc_client
            .insecure_call(
                METHOD_VERIFICATION_MATRIX,
                QueryRequest {
                    id: churp_id,
                    runtime_id: self.runtime_id,
                    epoch,
                    node_id: None,
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn share_reduction_point(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        node_id: PublicKey,
    ) -> Result<Vec<u8>, KeyManagerError> {
        self.rpc_client
            .secure_call(
                METHOD_SHARE_REDUCTION_POINT,
                QueryRequest {
                    id: churp_id,
                    runtime_id: self.runtime_id,
                    epoch,
                    node_id: Some(node_id),
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn share_distribution_point(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        node_id: PublicKey,
    ) -> Result<Vec<u8>, KeyManagerError> {
        self.rpc_client
            .secure_call(
                METHOD_SHARE_DISTRIBUTION_POINT,
                QueryRequest {
                    id: churp_id,
                    runtime_id: self.runtime_id,
                    epoch,
                    node_id: Some(node_id),
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn bivariate_share(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        node_id: PublicKey,
    ) -> Result<EncodedSecretShare, KeyManagerError> {
        self.rpc_client
            .secure_call(
                METHOD_BIVARIATE_SHARE,
                QueryRequest {
                    id: churp_id,
                    runtime_id: self.runtime_id,
                    epoch,
                    node_id: Some(node_id),
                },
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }
}
