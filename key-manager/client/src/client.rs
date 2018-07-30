use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

#[cfg(not(target_env = "sgx"))]
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::x509::Certificate;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_keymanager_api::with_api;
#[cfg(not(target_env = "sgx"))]
use ekiden_rpc_client::backend::network::NetworkRpcClientBackend;
use ekiden_rpc_client::create_client_rpc;
#[cfg(target_env = "sgx")]
use ekiden_rpc_common::client::ClientEndpoint;
#[cfg(target_env = "sgx")]
use ekiden_rpc_trusted::client::OcallRpcClientBackend;

use ekiden_keymanager_common::{ContractId, ContractKey, PrivateKeyType, PublicKeyType,
                               StateKeyType};
use serde_cbor;

// Create API client for the key manager.
with_api! {
    create_client_rpc!(key_manager, ekiden_keymanager_api, api);
}

/// Key manager client interface.
pub struct KeyManager {
    /// Key manager contract MRENCLAVE.
    mr_enclave: Option<MrEnclave>,
    /// Internal API client.
    #[cfg(target_env = "sgx")]
    client: Option<key_manager::Client<OcallRpcClientBackend>>,
    #[cfg(not(target_env = "sgx"))]
    client: Option<key_manager::Client<NetworkRpcClientBackend>>,
    #[cfg(not(target_env = "sgx"))]
    backend_config: Option<NetworkRpcClientBackendConfig>,
    /// Local key cache.
    cache: HashMap<ContractId, ContractKey>,
}

/// gRPC client backend configuration
#[cfg(not(target_env = "sgx"))]
#[derive(Clone)]
pub struct NetworkRpcClientBackendConfig {
    /// environment
    pub environment: Arc<Environment>,
    /// gRPC timeout
    pub timeout: Option<Duration>,
    /// host
    pub host: String,
    /// port
    pub port: u16,
    /// certificate of the key manager node
    pub certificate: Certificate,
}

lazy_static! {
    // Global key store object.
    static ref KEY_MANAGER: Mutex<KeyManager> = Mutex::new(KeyManager::new());
}

impl KeyManager {
    /// Construct new key manager interface.
    fn new() -> Self {
        KeyManager {
            mr_enclave: None,
            client: None,
            #[cfg(not(target_env = "sgx"))]
            backend_config: None,
            cache: HashMap::new(),
        }
    }

    /// Set the backend
    #[cfg(not(target_env = "sgx"))]
    pub fn configure_backend(&mut self, config: NetworkRpcClientBackendConfig) {
        self.backend_config.get_or_insert(config);
    }

    /// Establish a connection with the key manager contract.
    ///
    /// This will establish a mutually authenticated secure channel with the key manager
    /// contract, so this operation may fail due to the key manager being unavailable or
    /// issues with establishing a mutually authenticated secure channel.
    fn connect(&mut self) -> Result<()> {
        let mr_enclave = match self.mr_enclave {
            Some(ref mr_enclave) => mr_enclave.clone(),
            None => {
                return Err(Error::new(
                    "Tried to call key manager without known manager identity",
                ))
            }
        };

        if self.client.is_some() {
            return Ok(());
        }

        #[cfg(target_env = "sgx")]
        let backend = {
            match OcallRpcClientBackend::new(ClientEndpoint::KeyManager) {
                Ok(backend) => backend,
                _ => return Err(Error::new("Failed to create key manager client backend")),
            }
        };

        #[cfg(not(target_env = "sgx"))]
        let backend = {
            match self.backend_config {
                None => return Err(Error::new("Backend not configured yet")),
                Some(ref config) => {
                    let backend = match NetworkRpcClientBackend::new(
                        config.environment.clone(),
                        config.timeout.clone(),
                        &config.host.clone(),
                        config.port.clone(),
                        config.certificate.clone(),
                    ) {
                        Ok(backend) => backend,
                        _ => return Err(Error::new("Failed to create key manager client backend")),
                    };
                    backend
                }
            }
        };

        let client = key_manager::Client::new(Arc::new(backend), mr_enclave, Some(false));
        self.client.get_or_insert(client);

        Ok(())
    }

    /// Configures identity of key manager contract.
    ///
    /// **This method must be called before the key manager client can be used.**
    pub fn set_contract(&mut self, mr_enclave: MrEnclave) {
        self.mr_enclave.get_or_insert(mr_enclave);
    }

    /// Get global key manager client instance.
    ///
    /// Calling this method will take a lock on the global instance, which will
    /// be released once the value goes out of scope.
    pub fn get<'a>() -> Result<MutexGuard<'a, KeyManager>> {
        Ok(KEY_MANAGER.lock().unwrap())
    }

    /// Clear local key cache.
    ///
    /// This will make the client re-fetch the keys from the key manager.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get or create named key.
    ///
    /// If the key does not yet exist, the key manager will generate one. If
    /// the key has already been cached locally, it will be retrieved from
    /// cache.
    pub fn get_or_create_secret_keys(
        &mut self,
        contract_id: ContractId,
    ) -> Result<(PrivateKeyType, StateKeyType)> {
        // Ensure manager is connected.
        self.connect()?;

        // Check cache first.
        match self.cache.entry(contract_id) {
            Entry::Occupied(entry) => {
                let keys = entry.get().clone();
                Ok((keys.input_keypair.get_sk(), keys.state_key))
            }
            Entry::Vacant(entry) => {
                // No entry in cache, fetch from key manager.
                let mut request = key_manager::GetOrCreateKeyRequest::new();
                request.set_contract_id(contract_id.to_vec());
                // make a RPC
                let mut response = match self.client
                    .as_mut()
                    .unwrap()
                    .get_or_create_keys(request)
                    .wait()
                {
                    Ok(response) => response,
                    Err(error) => {
                        return Err(Error::new(error.description()));
                    }
                };
                let keys: ContractKey = serde_cbor::from_slice(&response.take_key())?;
                // Cache all keys locally
                entry.insert(keys.clone());
                Ok((keys.input_keypair.get_sk(), keys.state_key))
            }
        }
    }

    pub fn get_public_key(&mut self, contract_id: ContractId) -> Result<PublicKeyType> {
        self.connect()?;

        match self.cache.entry(contract_id) {
            Entry::Occupied(entry) => Ok(entry.get().clone().input_keypair.get_pk()),
            Entry::Vacant(entry) => {
                let mut request = key_manager::GetOrCreateKeyRequest::new();
                request.set_contract_id(contract_id.to_vec());
                // make a RPC
                let mut response =
                    match self.client.as_mut().unwrap().get_public_key(request).wait() {
                        Ok(r) => r,
                        Err(e) => return Err(Error::new(e.description())),
                    };

                let public_key: PublicKeyType = serde_cbor::from_slice(&response.take_key())?;
                entry.insert(ContractKey::from_public_key(public_key));
                Ok(public_key)
            }
        }
    }
}
