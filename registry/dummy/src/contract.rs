//! Ekiden dummy contract registry backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, BoxStream};
use ekiden_common::signature::Signed;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_registry_base::*;

struct DummyContractRegistryBackendInner {
    /// state.
    contracts: Mutex<HashMap<B256, Contract>>,
    /// Event subscribers.
    subscribers: StreamSubscribers<Contract>,
}

/// A dummy contract registry backend.
///
/// **This backend should only be used for tests. it is centralized and unsafe.***
pub struct DummyContractRegistryBackend {
    inner: Arc<DummyContractRegistryBackendInner>,
}

impl DummyContractRegistryBackend {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DummyContractRegistryBackendInner {
                contracts: Mutex::new(HashMap::new()),
                subscribers: StreamSubscribers::new(),
            }),
        }
    }
}

impl ContractRegistryBackend for DummyContractRegistryBackend {
    fn register_contract(&self, contract: Signed<Contract>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let contract = contract.open(&REGISTER_CONTRACT_SIGNATURE_CONTEXT)?;
            {
                let mut contracts = inner.contracts.lock().unwrap();
                contracts.insert(contract.id, contract.clone());
            }

            inner.subscribers.notify(&contract);

            Ok(())
        }))
    }

    fn get_contract(&self, id: B256) -> BoxFuture<Contract> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let contracts = inner.contracts.lock().unwrap();
            match contracts.get(&id) {
                Some(contract) => Ok(contract.clone()),
                None => Err(Error::new("No contract found")),
            }
        }))
    }

    fn get_contracts(&self) -> BoxStream<Contract> {
        // Feed every single currently valid contract, to catch up the
        // subscriber to current time.
        let inner = self.inner.clone();
        let contracts = inner.contracts.lock().unwrap();

        // Subscribe with the lock held to avoid sending duplicate
        // notifications due a concurrent registration.
        let (send, recv) = self.inner.subscribers.subscribe();
        for contract in contracts.values() {
            send.unbounded_send(contract.clone()).unwrap();
        }

        recv
    }
}
