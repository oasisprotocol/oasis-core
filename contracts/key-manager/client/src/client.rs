use std::collections::HashMap;
use std::collections::hash_map::Entry;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;

use ekiden_common::error::{Error, Result};
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_key_manager_api::with_api;
use ekiden_rpc_client::{create_client_rpc, FutureExtra};
use ekiden_rpc_common::client::ClientEndpoint;
use ekiden_rpc_trusted::client::OcallContractClientBackend;

// Create API client for the key manager.
with_api! {
    create_client_rpc!(key_manager, ekiden_key_manager_api, api);
}

/// Key manager client interface.
pub struct KeyManager {
    /// Key manager contract MRENCLAVE.
    mr_enclave: Option<MrEnclave>,
    /// Internal API client.
    client: Option<key_manager::Client<OcallContractClientBackend>>,
    /// Local key cache.
    cache: HashMap<String, Vec<u8>>,
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
            cache: HashMap::new(),
        }
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

        let backend = match OcallContractClientBackend::new(ClientEndpoint::KeyManager) {
            Ok(backend) => backend,
            _ => return Err(Error::new("Failed to create key manager client backend")),
        };

        let client = key_manager::Client::new(backend, mr_enclave);
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
    pub fn get_or_create_key(&mut self, name: &str, size: usize) -> Result<Vec<u8>> {
        // Ensure manager is connected.
        self.connect()?;

        // Check cache first.
        match self.cache.entry(name.to_string()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                // No entry in cache, fetch from key manager.
                let mut request = key_manager::GetOrCreateKeyRequest::new();
                request.set_name(name.to_string());
                request.set_size(size as u32);

                let mut response = match self.client
                    .as_mut()
                    .unwrap()
                    .get_or_create_key(request)
                    .wait()
                {
                    Ok(response) => response,
                    Err(error) => {
                        return Err(Error::new(format!(
                            "Failed to call key manager: {}",
                            error.message
                        )))
                    }
                };

                Ok(entry.insert(response.take_key()).clone())
            }
        }
    }
}
