//! Key manager client which talks to a remote key manager enclave.
use std::{
    collections::HashSet,
    convert::TryInto,
    iter::FromIterator,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use anyhow::anyhow;
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use group::GroupEncoding;
use lru::LruCache;
use rand::{prelude::SliceRandom, rngs::OsRng};

use oasis_core_runtime::{
    common::{
        crypto::signature::PublicKey,
        namespace::{Namespace, NAMESPACE_SIZE},
        sgx::{EnclaveIdentity, QuotePolicy},
    },
    consensus::{
        beacon::EpochTime,
        keymanager::churp::{self, Status as ChurpStatus, SuiteId},
        state::{
            beacon::ImmutableState as BeaconState,
            keymanager::{churp::ImmutableState as ChurpState, Status as KeyManagerStatus},
            registry::ImmutableState as RegistryState,
        },
        verifier::Verifier,
    },
    enclave_rpc::{client::RpcClient, session},
    identity::Identity,
    protocol::Protocol,
};
use secret_sharing::{
    churp::{HandoffKind, Player},
    kdc::KeyRecoverer,
    poly::EncryptedPoint,
    suites::{p384, Suite},
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
        EncodedEncryptedPoint, EncodedVerifiableSecretShare, Kdf, KeyShareRequest, QueryRequest,
        METHOD_BIVARIATE_SHARE, METHOD_SGX_POLICY_KEY_SHARE, METHOD_SHARE_DISTRIBUTION_POINT,
        METHOD_SHARE_REDUCTION_POINT, METHOD_VERIFICATION_MATRIX,
    },
    crypto::{
        KeyPair, KeyPairId, Secret, SignedPublicKey, StateKey, VerifiableSecret, KEY_PAIR_ID_SIZE,
    },
    policy::{set_trusted_signers, verify_data_and_trusted_signers, Policy, TrustedSigners},
};

use super::KeyManagerClient;

/// Key manager RPC endpoint.
const KEY_MANAGER_ENDPOINT: &str = "key-manager";
/// Maximum total number of EnclaveRPC sessions.
const RPC_MAX_SESSIONS: usize = 32;
/// Maximum concurrent EnclaveRPC sessions per peer. In case more sessions are open, old sessions
/// will be closed to make room for new sessions.
const RPC_MAX_SESSIONS_PER_PEER: usize = 2;
/// EnclaveRPC sessions without any processed frame for more than RPC_STALE_SESSION_TIMEOUT_SECS
/// seconds can be closed to make room for new sessions.
const RPC_STALE_SESSION_TIMEOUT_SECS: i64 = 10;

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
    /// Local cache for the state keys.
    state_keys: RwLock<LruCache<(KeyPairId, u8), StateKey>>,
    /// Key manager runtime ID.
    key_manager_id: RwLock<Option<Namespace>>,
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
            state_keys: RwLock::new(LruCache::new(cap)),
            key_manager_id: RwLock::new(None),
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
    ) -> Self {
        let builder = session::Builder::default()
            .remote_enclaves(enclaves)
            .quote_policy(policy)
            .local_identity(identity)
            .consensus_verifier(Some(consensus_verifier.clone()))
            .remote_runtime_id(km_runtime_id);

        Self::new(
            runtime_id,
            RpcClient::new_runtime(
                protocol,
                KEY_MANAGER_ENDPOINT,
                builder,
                RPC_MAX_SESSIONS,
                RPC_MAX_SESSIONS_PER_PEER,
                RPC_STALE_SESSION_TIMEOUT_SECS,
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
        )
    }

    /// Set allowed enclaves and runtime signing key from key manager status.
    pub fn set_status(&self, status: KeyManagerStatus) -> Result<(), KeyManagerError> {
        // Set runtime signing key.
        if let Some(rsk) = status.rsk {
            self.rsk.write().unwrap().replace(rsk);
        }

        // Set key manager runtime ID.
        *self.key_manager_id.write().unwrap() = Some(status.id);
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

    async fn churp_recover_state_key<S: Suite>(
        &self,
        key_id: KeyPairId,
        status: churp::Status,
    ) -> Result<StateKey, KeyManagerError> {
        // Fault detection and blame assignment are not supported,
        // so the minimal number of key shares will suffice.
        let kind = HandoffKind::CommitteeUnchanged;
        let player = Player::new(status.threshold, kind);
        let min_shares = player.min_shares();
        let mut shares = Vec::with_capacity(min_shares);

        // Fetch key shares in random order.
        let mut committee = status.committee;
        committee.shuffle(&mut OsRng);

        // Fetch key shares concurrently.
        let mut futures = FuturesUnordered::new();

        loop {
            // Continuously add new key share requests until the required
            // number of key shares is received, ensuring the future queue
            // remains filled even if some requests fail.
            while shares.len() + futures.len() < min_shares {
                let node_id = match committee.pop() {
                    Some(node_id) => node_id,
                    None => return Err(KeyManagerError::InsufficientKeyShares),
                };

                let future = self.rpc_client.secure_call(
                    METHOD_SGX_POLICY_KEY_SHARE,
                    KeyShareRequest {
                        id: status.id,
                        runtime_id: status.runtime_id,
                        epoch: status.handoff,
                        key_runtime_id: self.runtime_id,
                        key_id,
                    },
                    vec![node_id],
                );

                futures.push(future);
            }

            // Wait for the next future to finish.
            let response = match futures.next().await {
                Some(response) => response,
                None => break,
            };

            // Send back peer feedback.
            let response = response.into_result_with_feedback().await;

            // Decode the response.
            let encoded_share: EncodedEncryptedPoint = match response {
                Ok(encoded_share) => encoded_share,
                Err(_) => continue, // Ignore error and skip this share.
            };
            let share: EncryptedPoint<S::Group> = match encoded_share.try_into() {
                Ok(share) => share,
                Err(_) => continue, // Ignore error and skip this share.
            };

            shares.push(share);
        }

        // Abort if we don't have enough shares.
        if shares.len() != min_shares {
            return Err(KeyManagerError::InsufficientKeyShares);
        }

        // Prepare salt for key derivation (runtime id || churp id || key id).
        let mut salt = [0; NAMESPACE_SIZE + 1 + KEY_PAIR_ID_SIZE];
        salt[..NAMESPACE_SIZE].copy_from_slice(&status.runtime_id.0);
        salt[NAMESPACE_SIZE] = status.id;
        salt[NAMESPACE_SIZE + 1..].copy_from_slice(&key_id.0);

        // Recover the secret and derive the state key from it.
        // NOTE: Elliptic curve points in projective form are first converted
        // to affine form, and then encoded to bytes using point compression.
        let key = player.recover_key(&shares)?;
        let secret = key.to_bytes();
        let state_key = Kdf::state_key(secret.as_ref(), &salt);

        Ok(state_key)
    }
}

#[async_trait]
impl KeyManagerClient for RemoteClient {
    fn runtime_id(&self) -> Option<Namespace> {
        *self.key_manager_id.read().unwrap()
    }

    fn runtime_signing_key(&self) -> Option<PublicKey> {
        *self.rsk.read().unwrap()
    }

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
                vec![],
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
                vec![],
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
                vec![],
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
                vec![],
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
        nodes: Vec<PublicKey>,
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
                nodes,
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
        nodes: Vec<PublicKey>,
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
                nodes,
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
            .map(|rsp: ReplicateEphemeralSecretResponse| rsp.ephemeral_secret)
    }

    async fn churp_verification_matrix(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        nodes: Vec<PublicKey>,
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
                nodes,
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn churp_share_reduction_point(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        node_id: PublicKey,
        nodes: Vec<PublicKey>,
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
                nodes,
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn churp_share_distribution_point(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        node_id: PublicKey,
        nodes: Vec<PublicKey>,
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
                nodes,
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn churp_bivariate_share(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        node_id: PublicKey,
        nodes: Vec<PublicKey>,
    ) -> Result<EncodedVerifiableSecretShare, KeyManagerError> {
        self.rpc_client
            .secure_call(
                METHOD_BIVARIATE_SHARE,
                QueryRequest {
                    id: churp_id,
                    runtime_id: self.runtime_id,
                    epoch,
                    node_id: Some(node_id),
                },
                nodes,
            )
            .await
            .into_result_with_feedback()
            .await
            .map_err(|err| KeyManagerError::Other(err.into()))
    }

    async fn churp_state_key(
        &self,
        churp_id: u8,
        key_id: KeyPairId,
    ) -> Result<StateKey, KeyManagerError> {
        let id = (key_id, churp_id);

        // First try to fetch from cache.
        {
            let mut cache = self.state_keys.write().unwrap();
            if let Some(key) = cache.get(&id) {
                return Ok(key.clone());
            }
        }

        // No entry in cache, fetch from key manager.
        let consensus_state = self.consensus_verifier.latest_state().await?;
        let registry_state = RegistryState::new(&consensus_state);
        let churp_state = ChurpState::new(&consensus_state);

        let status = tokio::task::block_in_place(move || -> Result<ChurpStatus, anyhow::Error> {
            let runtime = registry_state
                .runtime(&self.runtime_id)?
                .ok_or(anyhow!("missing runtime descriptor"))?;
            let key_manager_id = runtime
                .key_manager
                .ok_or(anyhow!("runtime doesn't use key manager"))?;
            let status = churp_state
                .status(key_manager_id, churp_id)?
                .ok_or(anyhow!("churp status not found"))?;
            Ok(status)
        })?;

        let state_key = match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.churp_recover_state_key::<p384::Sha3_384>(key_id, status)
                    .await?
            }
        };

        // Cache key.
        let mut cache = self.state_keys.write().unwrap();
        cache.put(id, state_key.clone());

        Ok(state_key)
    }
}
