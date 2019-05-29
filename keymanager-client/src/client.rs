//! Key manager client which talks to a remote key manager enclave.
use std::sync::{Arc, RwLock};

use futures::{future, prelude::*};
#[cfg(not(target_env = "sgx"))]
use grpcio::Channel;
use io_context::Context;
use lru::LruCache;

use ekiden_client::{create_rpc_api_client, BoxFuture, RpcClient};
use ekiden_keymanager_api::*;
use ekiden_runtime::{
    common::{runtime::RuntimeId, sgx::avr::MrEnclave},
    protocol::Protocol,
    rak::RAK,
    rpc::session,
};

use super::KeyManagerClient;

with_api! {
    create_rpc_api_client!(Client, api);
}

/// Key manager RPC endpoint.
const KEY_MANAGER_ENDPOINT: &'static str = "key-manager";

struct Inner {
    /// Runtime Id for which we are going to request keys.
    runtime_id: RuntimeId,
    /// RPC client.
    rpc_client: Client,
    /// Local cache for the get_or_create_keys KeyManager endpoint.
    get_or_create_secret_keys_cache: RwLock<LruCache<ContractId, ContractKey>>,
    /// Local cache for the get_public_key KeyManager endpoint.
    get_public_key_cache: RwLock<LruCache<ContractId, SignedPublicKey>>,
    /// Local cache for the get_long_term_public_key KeyManager endpoint.
    get_long_term_public_key_cache: RwLock<LruCache<ContractId, SignedPublicKey>>,
}

/// A key manager client which talks to a remote key manager enclave.
pub struct RemoteClient {
    inner: Arc<Inner>,
}

impl RemoteClient {
    fn new(runtime_id: RuntimeId, client: RpcClient, keys_cache_sizes: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                runtime_id,
                rpc_client: Client::new(client),
                get_or_create_secret_keys_cache: RwLock::new(LruCache::new(keys_cache_sizes)),
                get_public_key_cache: RwLock::new(LruCache::new(keys_cache_sizes)),
                get_long_term_public_key_cache: RwLock::new(LruCache::new(keys_cache_sizes)),
            }),
        }
    }

    /// Create a new key manager client with runtime-internal transport.
    pub fn new_runtime(
        runtime_id: RuntimeId,
        mrenclave: Option<MrEnclave>,
        protocol: Arc<Protocol>,
        rak: Arc<RAK>,
        keys_cache_sizes: usize,
    ) -> Self {
        Self::new(
            runtime_id,
            RpcClient::new_runtime(
                session::Builder::new()
                    .remote_mrenclave(mrenclave)
                    .local_rak(rak),
                protocol,
                KEY_MANAGER_ENDPOINT,
            ),
            keys_cache_sizes,
        )
    }

    /// Create a new key manager client with gRPC transport.
    #[cfg(not(target_env = "sgx"))]
    pub fn new_grpc(
        runtime_id: RuntimeId,
        mrenclave: Option<MrEnclave>,
        channel: Channel,
        keys_cache_sizes: usize,
    ) -> Self {
        Self::new(
            runtime_id,
            RpcClient::new_grpc(
                session::Builder::new().remote_mrenclave(mrenclave),
                channel,
                &format!("{}://{:?}", KEY_MANAGER_ENDPOINT, runtime_id),
            ),
            keys_cache_sizes,
        )
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

        let mut cache = self.inner.get_long_term_public_key_cache.write().unwrap();
        cache.clear();
        drop(cache);
    }

    fn get_or_create_keys(&self, ctx: Context, contract_id: ContractId) -> BoxFuture<ContractKey> {
        let mut cache = self.inner.get_or_create_secret_keys_cache.write().unwrap();
        if let Some(keys) = cache.get(&contract_id) {
            return Box::new(future::ok(keys.clone()));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::new(
            self.inner
                .rpc_client
                .get_or_create_keys(ctx, RequestIds::new(inner.runtime_id, contract_id))
                .and_then(move |keys| {
                    let mut cache = inner.get_or_create_secret_keys_cache.write().unwrap();
                    cache.put(contract_id, keys.clone());

                    Ok(keys)
                }),
        )
    }

    fn get_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        let mut cache = self.inner.get_public_key_cache.write().unwrap();
        if let Some(key) = cache.get(&contract_id) {
            return Box::new(future::ok(Some(key.clone())));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::new(
            self.inner
                .rpc_client
                .get_public_key(ctx, RequestIds::new(inner.runtime_id, contract_id))
                .and_then(move |key| match key {
                    Some(key) => {
                        let mut cache = inner.get_public_key_cache.write().unwrap();
                        cache.put(contract_id, key.clone());

                        Ok(Some(key))
                    }
                    None => Ok(None),
                }),
        )
    }

    fn get_long_term_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        let mut cache = self.inner.get_long_term_public_key_cache.write().unwrap();
        if let Some(key) = cache.get(&contract_id) {
            return Box::new(future::ok(Some(key.clone())));
        }

        // No entry in cache, fetch from key manager.
        let inner = self.inner.clone();
        Box::new(
            self.inner
                .rpc_client
                .get_long_term_public_key(ctx, RequestIds::new(inner.runtime_id, contract_id))
                .and_then(move |key| match key {
                    Some(key) => {
                        let mut cache = inner.get_long_term_public_key_cache.write().unwrap();
                        cache.put(contract_id, key.clone());

                        Ok(Some(key))
                    }
                    None => Ok(None),
                }),
        )

    fn replicate_master_secret(&self, ctx: Context) -> BoxFuture<Option<MasterSecret>> {
        Box::new(
            self.inner
                .rpc_client
                .replicate_master_secret(ctx, ReplicateRequest {})
                .and_then(move |rsp| Ok(Some(rsp.master_secret))),
        )
    }
}
