//! Key manager client which talks to a remote key manager enclave.
use std::{
    collections::HashSet,
    iter::FromIterator,
    sync::{Arc, RwLock},
};

use futures::future::{self, BoxFuture};
use io_context::Context;
use lru::LruCache;

use oasis_core_client::RpcClient;
use oasis_core_keymanager_api_common::*;
use oasis_core_runtime::{
    common::{namespace::Namespace, sgx::avr::EnclaveIdentity},
    enclave_rpc::session,
    protocol::Protocol,
    rak::RAK,
};

use super::KeyManagerClient;

/// Key manager RPC endpoint.
const KEY_MANAGER_ENDPOINT: &'static str = "key-manager";

struct Inner {
    /// Runtime identifier for which we are going to request keys.
    runtime_id: Namespace,
    /// RPC client.
    rpc_client: RpcClient,
    /// Local cache for the get_or_create_keys KeyManager endpoint.
    get_or_create_secret_keys_cache: RwLock<LruCache<KeyPairId, KeyPair>>,
    /// Local cache for the get_public_key KeyManager endpoint.
    get_public_key_cache: RwLock<LruCache<KeyPairId, SignedPublicKey>>,
}

/// A key manager client which talks to a remote key manager enclave.
pub struct RemoteClient {
    inner: Arc<Inner>,
}

impl RemoteClient {
    fn new(runtime_id: Namespace, rpc_client: RpcClient, keys_cache_sizes: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                runtime_id,
                rpc_client,
                get_or_create_secret_keys_cache: RwLock::new(LruCache::new(keys_cache_sizes)),
                get_public_key_cache: RwLock::new(LruCache::new(keys_cache_sizes)),
            }),
        }
    }

    /// Create a new key manager client with runtime-internal transport and explicit key manager
    /// enclave identities.
    pub fn new_runtime_with_enclave_identities(
        runtime_id: Namespace,
        enclaves: Option<HashSet<EnclaveIdentity>>,
        protocol: Arc<Protocol>,
        rak: Arc<RAK>,
        keys_cache_sizes: usize,
    ) -> Self {
        Self::new(
            runtime_id,
            RpcClient::new_runtime(
                session::Builder::new()
                    .remote_enclaves(enclaves)
                    .local_rak(rak),
                protocol,
                KEY_MANAGER_ENDPOINT,
            ),
            keys_cache_sizes,
        )
    }

    /// Create a new key manager client with runtime-internal transport.
    ///
    /// Using this method valid enclave identities won't be preset and should
    /// be obtained via the worker-host protocol and updated with the set_policy
    /// method. In case of sgx, the session establishment will fail until the
    /// initial policies will be updated.
    pub fn new_runtime(
        runtime_id: Namespace,
        protocol: Arc<Protocol>,
        rak: Arc<RAK>,
        keys_cache_sizes: usize,
        signers: TrustedPolicySigners,
    ) -> Self {
        #[cfg(target_env = "sgx")]
        set_trusted_policy_signers(signers);

        #[cfg(not(target_env = "sgx"))]
        let _ = signers;

        #[cfg(target_env = "sgx")]
        let enclaves = Some(HashSet::new());
        #[cfg(not(target_env = "sgx"))]
        let enclaves = None;

        Self::new_runtime_with_enclave_identities(
            runtime_id,
            enclaves,
            protocol,
            rak,
            keys_cache_sizes,
        )
    }

    /// Set client allowed enclaves from key manager policy.
    pub fn set_policy(&self, signed_policy_raw: Vec<u8>) -> Result<(), KeyManagerError> {
        let untrusted_policy: SignedPolicySGX =
            cbor::from_slice(&signed_policy_raw).map_err(|_| KeyManagerError::PolicyInvalid)?;
        let policy = untrusted_policy.verify()?;
        let policies: HashSet<EnclaveIdentity> =
            HashSet::from_iter(policy.enclaves.keys().cloned());
        self.inner.rpc_client.update_enclaves(Some(policies));
        Ok(())
    }
}

impl KeyManagerClient for RemoteClient {
    fn clear_cache(&self) {
        // We explicitly only take one lock at a time.

        let mut cache = self.inner.get_or_create_secret_keys_cache.write().unwrap();
        cache.clear();
        drop(cache);

        let mut cache = self.inner.get_public_key_cache.write().unwrap();
        cache.clear();
        drop(cache);
    }

    fn get_or_create_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        let mut cache = self.inner.get_or_create_secret_keys_cache.write().unwrap();
        if let Some(keys) = cache.get(&key_pair_id) {
            return Box::pin(future::ok(keys.clone()));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let keys: KeyPair = inner
                .rpc_client
                .call(
                    ctx,
                    METHOD_GET_OR_CREATE_KEYS,
                    RequestIds::new(inner.runtime_id, key_pair_id),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            // Cache key.
            let mut cache = inner.get_or_create_secret_keys_cache.write().unwrap();
            cache.put(key_pair_id, keys.clone());

            Ok(keys)
        })
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Result<Option<SignedPublicKey>, KeyManagerError>> {
        let mut cache = self.inner.get_public_key_cache.write().unwrap();
        if let Some(key) = cache.get(&key_pair_id) {
            return Box::pin(future::ok(Some(key.clone())));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::pin(async move {
            let key: Option<SignedPublicKey> = inner
                .rpc_client
                .call(
                    ctx,
                    METHOD_GET_PUBLIC_KEY,
                    RequestIds::new(inner.runtime_id, key_pair_id),
                )
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;

            match key {
                Some(key) => {
                    // Cache key.
                    let mut cache = inner.get_public_key_cache.write().unwrap();
                    cache.put(key_pair_id, key.clone());

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
            let rsp: ReplicateResponse = inner
                .rpc_client
                .call(ctx, METHOD_REPLICATE_MASTER_SECRET, ReplicateRequest {})
                .await
                .map_err(|err| KeyManagerError::Other(err.into()))?;
            Ok(Some(rsp.master_secret))
        })
    }
}
