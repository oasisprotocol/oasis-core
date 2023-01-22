//! Key manager client which talks to a remote key manager enclave.
use std::{
    collections::HashSet,
    iter::FromIterator,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use futures::future::{self, BoxFuture};
use io_context::Context;
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
        EphemeralKeyRequest, KeyManagerError, LongTermKeyRequest, ReplicateMasterSecretRequest,
        ReplicateMasterSecretResponse, METHOD_GET_OR_CREATE_EPHEMERAL_KEYS,
        METHOD_GET_OR_CREATE_KEYS, METHOD_GET_PUBLIC_EPHEMERAL_KEY, METHOD_GET_PUBLIC_KEY,
        METHOD_REPLICATE_MASTER_SECRET,
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
    /// Local cache for the long-term and ephemeral private keys fetched from
    /// get_or_create_keys and get_or_create_ephemeral_keys KeyManager endpoints.
    private_key_cache: RwLock<LruCache<(KeyPairId, Option<EpochTime>), KeyPair>>,
    /// Local cache for the long-term and ephemeral public keys fetched from
    /// get_public_key and get_public_ephemeral_key KeyManager endpoints.
    public_key_cache: RwLock<LruCache<(KeyPairId, Option<EpochTime>), SignedPublicKey>>,
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
        Self {
            inner: Arc::new(Inner {
                runtime_id,
                rpc_client,
                consensus_verifier,
                private_key_cache: RwLock::new(LruCache::new(
                    NonZeroUsize::new(keys_cache_sizes).unwrap(),
                )),
                public_key_cache: RwLock::new(LruCache::new(
                    NonZeroUsize::new(keys_cache_sizes).unwrap(),
                )),
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

        // Set client allowed enclaves from key manager policy.
        if let Some(untrusted_policy) = status.policy {
            let policy = verify_policy_and_trusted_signers(&untrusted_policy)?;

            let policies: HashSet<EnclaveIdentity> =
                HashSet::from_iter(policy.enclaves.keys().cloned());
            self.inner.rpc_client.update_enclaves(Some(policies));
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

impl KeyManagerClient for RemoteClient {
    fn clear_cache(&self) {
        // We explicitly only take one lock at a time.

        let mut cache = self.inner.private_key_cache.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.inner.public_key_cache.write().unwrap();
        cache.clear();
        drop(cache);
    }

    fn get_or_create_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        // Fetch from cache.
        let mut cache = self.inner.private_key_cache.write().unwrap();
        let id = &(key_pair_id, None);
        if let Some(keys) = cache.get(id) {
            return Box::pin(future::ok(keys.clone()));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let keys: KeyPair = inner
                .rpc_client
                .secure_call(
                    ctx,
                    METHOD_GET_OR_CREATE_KEYS,
                    LongTermKeyRequest::new(Some(height), inner.runtime_id, key_pair_id),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            // Cache key.
            let mut cache = inner.private_key_cache.write().unwrap();
            cache.put((key_pair_id, None), keys.clone());

            Ok(keys)
        })
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>> {
        // Fetch from cache.
        let mut cache = self.inner.public_key_cache.write().unwrap();
        let id = &(key_pair_id, None);
        if let Some(key) = cache.get(id) {
            match self.verify_public_key(key, key_pair_id, None, None) {
                Ok(()) => return Box::pin(future::ok(key.clone())),
                Err(_) => {
                    cache.pop(id);
                }
            }
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let key: SignedPublicKey = inner
                .rpc_client
                .insecure_call(
                    ctx,
                    METHOD_GET_PUBLIC_KEY,
                    LongTermKeyRequest::new(Some(height), inner.runtime_id, key_pair_id),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            // Verify the signature.
            self.verify_public_key(&key, key_pair_id, None, None)?;

            // Cache key.
            let mut cache = inner.public_key_cache.write().unwrap();
            cache.put((key_pair_id, None), key.clone());

            Ok(key)
        })
    }

    fn get_or_create_ephemeral_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        // Fetch from cache.
        let mut cache = self.inner.private_key_cache.write().unwrap();
        let id = &(key_pair_id, Some(epoch));
        if let Some(keys) = cache.get(id) {
            return Box::pin(future::ok(keys.clone()));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let keys: KeyPair = inner
                .rpc_client
                .secure_call(
                    ctx,
                    METHOD_GET_OR_CREATE_EPHEMERAL_KEYS,
                    EphemeralKeyRequest::new(Some(height), inner.runtime_id, key_pair_id, epoch),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            // Cache key.
            let mut cache = inner.private_key_cache.write().unwrap();
            cache.put((key_pair_id, Some(epoch)), keys.clone());

            Ok(keys)
        })
    }

    fn get_public_ephemeral_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>> {
        let ctx = ctx.freeze();

        // Fetch current epoch.
        let get_consensus_epoch = || -> Result<EpochTime, anyhow::Error> {
            let consensus_state = self.inner.consensus_verifier.latest_state()?;
            let beacon_state = BeaconState::new(&consensus_state);
            let consensus_epoch = beacon_state.epoch(Context::create_child(&ctx))?;
            Ok(consensus_epoch)
        };
        let consensus_epoch = match get_consensus_epoch() {
            Ok(epoch) => epoch,
            Err(err) => return Box::pin(future::err(KeyManagerError::Other(err))),
        };

        // Fetch from cache.
        let mut cache = self.inner.public_key_cache.write().unwrap();
        let id = &(key_pair_id, Some(epoch));
        if let Some(key) = cache.get(id) {
            match self.verify_public_key(key, key_pair_id, Some(epoch), Some(consensus_epoch)) {
                Ok(()) => return Box::pin(future::ok(key.clone())),
                Err(_) => {
                    cache.pop(id);
                }
            }
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let key: SignedPublicKey = inner
                .rpc_client
                .insecure_call(
                    Context::create_child(&ctx),
                    METHOD_GET_PUBLIC_EPHEMERAL_KEY,
                    EphemeralKeyRequest::new(Some(height), inner.runtime_id, key_pair_id, epoch),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            // Verify the signature.
            self.verify_public_key(&key, key_pair_id, Some(epoch), Some(consensus_epoch))?;

            // Cache key.
            let mut cache = inner.public_key_cache.write().unwrap();
            cache.put((key_pair_id, Some(epoch)), key.clone());

            Ok(key)
        })
    }

    fn replicate_master_secret(&self, ctx: Context) -> BoxFuture<Result<Secret, KeyManagerError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let rsp: ReplicateMasterSecretResponse = inner
                .rpc_client
                .secure_call(
                    ctx,
                    METHOD_REPLICATE_MASTER_SECRET,
                    ReplicateMasterSecretRequest::new(Some(height)),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;
            Ok(rsp.master_secret)
        })
    }
}
