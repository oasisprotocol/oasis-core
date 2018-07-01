//! Storage frontend - a router to be used to access storage.
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_scheduler_base::{Committee, CommitteeType, Scheduler};
use ekiden_storage_base::StorageBackend;

use client::StorageClient;

struct Inner {
    /// Contract context for storage operations.
    contract_id: B256,
    /// Notification of committee changes.
    scheduler: Arc<Scheduler>,
    /// Registry of nodes.
    registry: Arc<EntityRegistryBackend>,
    /// Environment for scheduling execution.
    environment: Arc<Environment>,
    /// Node identity.
    identity: Arc<NodeIdentity>,
    /// How agressively to retry connections to backends before erroring.
    retries: usize,
}

/// StorageFrontend provides a storage interface routed to active storage backends for a given
/// `Contract`, as directed by the Ekiden `Scheduler`.
pub struct StorageFrontend {
    /// Active connections to storage backends.
    clients: Arc<Mutex<Vec<Arc<StorageClient>>>>,
    /// Shared state associated with the storage frontend.
    inner: Arc<Inner>,
}

impl StorageFrontend {
    /// Create a new frontend that uses clients based on pointers from the scheduler.
    pub fn new(
        contract_id: B256,
        scheduler: Arc<Scheduler>,
        registry: Arc<EntityRegistryBackend>,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
        retries: usize,
    ) -> Self {
        Self {
            clients: Arc::new(Mutex::new(vec![])),
            inner: Arc::new(Inner {
                contract_id,
                scheduler,
                registry,
                environment,
                identity,
                retries,
            }),
        }
    }

    /// Refreshes the list of active storage connections by polling the scheduler for the active
    /// storage committee for a given contract.
    fn refresh(inner: Arc<Inner>) -> BoxFuture<Vec<Arc<StorageClient>>> {
        let shared_inner = inner.clone();

        Box::new(
            inner
                .scheduler
                .get_committees(inner.contract_id)
                .and_then(move |committee: Vec<Committee>| -> BoxFuture<Node> {
                    let committee = committee
                        .iter()
                        .filter(|c| c.kind == CommitteeType::Storage)
                        .next();
                    if committee.is_none() {
                        return Box::new(future::err(Error::new("No storage committee")));
                    }
                    let storers = &committee.unwrap().members;

                    // TODO: rather than just looking up one committee member, registry should be queried for each.
                    let storer = &storers[0];
                    // Now look up the storer's ID in the registry.
                    inner.registry.get_node(storer.public_key)
                })
                .and_then(move |node| -> BoxFuture<Vec<Arc<StorageClient>>> {
                    Box::new(future::ok(vec![Arc::new(StorageClient::from_node(
                        &node,
                        shared_inner.environment.clone(),
                        shared_inner.identity.clone(),
                    ))]))
                }),
        )
    }

    /// Get an active and connected StorageClient that storage requests can be routed to.
    fn get_storage(&self, max_retries: usize) -> BoxFuture<Arc<StorageClient>> {
        let shared_storage = self.clients.clone();
        let shared_inner = self.inner.clone();

        let attempts = future::loop_fn(
            max_retries,
            move |retries| -> BoxFuture<future::Loop<Arc<StorageClient>, usize>> {
                let known_storage = shared_storage.clone();
                let this_inner = shared_inner.clone();
                let nodes = known_storage.lock().unwrap();

                match nodes.first() {
                    None => {
                        let known_storage = shared_storage.clone();
                        return Box::new(StorageFrontend::refresh(this_inner).then(
                            move |response| match response {
                                Ok(mut clients) => {
                                    let mut nodes = known_storage.lock().unwrap();
                                    nodes.append(&mut clients);
                                    Ok(future::Loop::Continue(retries - 1))
                                }
                                Err(e) => Err(e),
                            },
                        ));
                    }
                    Some(client) => {
                        let out_client = client.clone();
                        Box::new(future::ok(future::Loop::Break(out_client)))
                    }
                }
            },
        );

        Box::new(attempts)
    }
}

impl StorageBackend for StorageFrontend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        Box::new(
            self.get_storage(self.inner.retries)
                .and_then(move |s| s.get(key)),
        )
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        Box::new(
            self.get_storage(self.inner.retries)
                .and_then(move |s| s.insert(value, expiry)),
        )
    }
}
