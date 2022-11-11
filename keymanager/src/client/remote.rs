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
    common::{namespace::Namespace, sgx::EnclaveIdentity},
    consensus::{beacon::EpochTime, keymanager::SignedPolicySGX, verifier::Verifier},
    enclave_rpc::{client::RpcClient, session},
    protocol::Protocol,
    rak::RAK,
};

use crate::{
    api::{
        EphemeralKeyRequest, KeyManagerError, LongTermKeyRequest, ReplicateRequest,
        ReplicateResponse, METHOD_GET_OR_CREATE_EPHEMERAL_KEYS, METHOD_GET_OR_CREATE_KEYS,
        METHOD_GET_PUBLIC_EPHEMERAL_KEY, METHOD_GET_PUBLIC_KEY, METHOD_REPLICATE_MASTER_SECRET,
    },
    crypto::{KeyPair, KeyPairId, MasterSecret, SignedPublicKey},
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
            }),
        }
    }

    /// Create a new key manager client with runtime-internal transport and explicit key manager
    /// enclave identities.
    pub fn new_runtime_with_enclave_identities(
        runtime_id: Namespace,
        enclaves: Option<HashSet<EnclaveIdentity>>,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
        rak: Arc<RAK>,
        keys_cache_sizes: usize,
    ) -> Self {
        Self::new(
            runtime_id,
            RpcClient::new_runtime(
                session::Builder::default()
                    .remote_enclaves(enclaves)
                    .local_rak(rak),
                protocol,
                KEY_MANAGER_ENDPOINT,
            ),
            consensus_verifier,
            keys_cache_sizes,
        )
    }

    /// Create a new key manager client with runtime-internal transport.
    ///
    /// Using this method valid enclave identities won't be preset and should be obtained via the
    /// worker-host protocol and updated with the set_policy method. In case the signer set is
    /// non-empty, session establishment will fail until the initial policies will be updated.
    pub fn new_runtime(
        runtime_id: Namespace,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
        rak: Arc<RAK>,
        keys_cache_sizes: usize,
        signers: TrustedPolicySigners,
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

        // Configure trusted policy signers.
        set_trusted_policy_signers(signers);

        Self::new_runtime_with_enclave_identities(
            runtime_id,
            enclaves,
            protocol,
            consensus_verifier,
            rak,
            keys_cache_sizes,
        )
    }

    /// Set client allowed enclaves from key manager policy.
    pub fn set_policy(&self, signed_policy_raw: Vec<u8>) -> Result<(), KeyManagerError> {
        let untrusted_policy: SignedPolicySGX = cbor::from_slice(&signed_policy_raw)
            .map_err(|err| KeyManagerError::PolicyInvalid(err.into()))?;
        let policy = verify_policy_and_trusted_signers(&untrusted_policy)?;

        let policies: HashSet<EnclaveIdentity> =
            HashSet::from_iter(policy.enclaves.keys().cloned());
        self.inner.rpc_client.update_enclaves(Some(policies));

        Ok(())
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
        let mut cache = self.inner.private_key_cache.write().unwrap();
        if let Some(keys) = cache.get(&(key_pair_id, None)) {
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
                .call(
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
    ) -> BoxFuture<Result<Option<SignedPublicKey>, KeyManagerError>> {
        let mut cache = self.inner.public_key_cache.write().unwrap();
        if let Some(key) = cache.get(&(key_pair_id, None)) {
            return Box::pin(future::ok(Some(key.clone())));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let key: Option<SignedPublicKey> = inner
                .rpc_client
                .call(
                    ctx,
                    METHOD_GET_PUBLIC_KEY,
                    LongTermKeyRequest::new(Some(height), inner.runtime_id, key_pair_id),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            match key {
                Some(key) => {
                    // Cache key.
                    let mut cache = inner.public_key_cache.write().unwrap();
                    cache.put((key_pair_id, None), key.clone());

                    Ok(Some(key))
                }
                None => Ok(None),
            }
        })
    }

    fn get_or_create_ephemeral_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        let mut cache = self.inner.private_key_cache.write().unwrap();
        if let Some(keys) = cache.get(&(key_pair_id, Some(epoch))) {
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
                .call(
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
    ) -> BoxFuture<Result<Option<SignedPublicKey>, KeyManagerError>> {
        let mut cache = self.inner.public_key_cache.write().unwrap();
        if let Some(key) = cache.get(&(key_pair_id, Some(epoch))) {
            return Box::pin(future::ok(Some(key.clone())));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let key: Option<SignedPublicKey> = inner
                .rpc_client
                .call(
                    ctx,
                    METHOD_GET_PUBLIC_EPHEMERAL_KEY,
                    EphemeralKeyRequest::new(Some(height), inner.runtime_id, key_pair_id, epoch),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            match key {
                Some(key) => {
                    // Cache key.
                    let mut cache = inner.public_key_cache.write().unwrap();
                    cache.put((key_pair_id, Some(epoch)), key.clone());

                    Ok(Some(key))
                }
                None => Ok(None),
            }
        })
    }

    fn replicate_master_secret(
        &self,
        ctx: Context,
    ) -> BoxFuture<Result<Option<MasterSecret>, KeyManagerError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let _height = inner
                .consensus_verifier
                .latest_height()
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            let rsp: ReplicateResponse = inner
                .rpc_client
                .call(
                    ctx,
                    METHOD_REPLICATE_MASTER_SECRET,
                    ReplicateRequest::new(None), // XXX: Add this back once everything is upgraded.
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;
            Ok(Some(rsp.master_secret))
        })
    }
}
