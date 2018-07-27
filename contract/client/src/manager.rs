//! Manager for contract clients.
use std;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::streamfollow;
use ekiden_common::futures::sync::oneshot;
use ekiden_common::node::Node;
use ekiden_compute_api;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_roothash_base::backend::RootHashBackend;
use ekiden_scheduler_base::{CommitteeType, Role, Scheduler};
use ekiden_storage_base::backend::StorageBackend;

use super::client::ContractClient;

/// Computation group leader.
struct Leader {
    /// Node descriptor.
    node: Node,
    /// Contract client.
    client: ContractClient,
}

struct Inner {
    /// Contract identifier.
    contract_id: B256,
    /// Optional call timeout.
    timeout: Option<Duration>,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Entity registry.
    entity_registry: Arc<EntityRegistryBackend>,
    /// Environment.
    environment: Arc<Environment>,
    /// Shared service for waiting for contract calls.
    call_wait_manager: Arc<super::callwait::Manager>,
    /// Current computation group leader.
    leader: RwLock<Option<Arc<Leader>>>,
    /// Future for waiting for the leader in case there is no leader yet.
    future_leader: future::Shared<oneshot::Receiver<Arc<Leader>>>,
    /// Leader notification channel.
    leader_notify: Mutex<Option<oneshot::Sender<Arc<Leader>>>>,
}

/// Manager for a contract client.
///
/// The manager handles things like leader discovery and epoch transitions.
pub struct ContractClientManager {
    inner: Arc<Inner>,
}

impl ContractClientManager {
    pub fn new(
        contract_id: B256,
        _mr_enclave: MrEnclave,
        timeout: Option<Duration>,
        environment: Arc<Environment>,
        scheduler: Arc<Scheduler>,
        entity_registry: Arc<EntityRegistryBackend>,
        roothash: Arc<RootHashBackend>,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let call_wait_manager = Arc::new(super::callwait::Manager::new(
            environment.clone(),
            contract_id,
            roothash,
            storage,
        ));
        let (leader_notify, future_leader) = oneshot::channel();

        let manager = Self {
            inner: Arc::new(Inner {
                contract_id,
                timeout,
                environment,
                scheduler,
                entity_registry,
                call_wait_manager,
                leader: RwLock::new(None),
                future_leader: future_leader.shared(),
                leader_notify: Mutex::new(Some(leader_notify)),
            }),
        };
        manager.start();

        manager
    }

    /// Start contract client manager.
    fn start(&self) {
        self.inner.environment.spawn({
            let inner_init = self.inner.clone();
            let inner = self.inner.clone();
            let contract_id = self.inner.contract_id;

            streamfollow::follow_skip(
                move || {
                    inner_init
                        .scheduler
                        .watch_committees()
                        .filter(move |committee| committee.contract.id == contract_id)
                        .filter(|committee| committee.kind == CommitteeType::Compute)
                },
                |com| com.valid_for,
                |_| false,
            ).for_each(move |committee| {
                // Committee has been updated, check if we need to update the leader.
                let new_leader = match committee
                    .members
                    .iter()
                    .filter(|member| member.role == Role::Leader)
                    .map(|member| member.public_key)
                    .next()
                {
                    Some(leader) => leader,
                    None => return future::err(Error::new("missing committee leader")).into_box(),
                };
                let previous_leader = inner.leader.read().unwrap();

                if let Some(ref previous_leader) = *previous_leader {
                    if previous_leader.node.id == new_leader {
                        return future::ok(()).into_box();
                    }
                }

                info!(
                    "Compute committee has changed, new leader is: {:?}",
                    new_leader
                );

                // Need to change the leader.
                let inner = inner.clone();

                inner
                    .entity_registry
                    .get_node(new_leader)
                    .and_then(move |node| {
                        // Create new client to the leader node.
                        let rpc = ekiden_compute_api::ContractClient::new(
                            node.connect_without_identity(inner.environment.clone()),
                        );
                        let client = ContractClient::new(
                            rpc,
                            inner.call_wait_manager.clone(),
                            inner.timeout.clone(),
                        );

                        // Change the leader.
                        let mut previous_leader = inner.leader.write().unwrap();
                        let new_leader = Arc::new(Leader { node, client });
                        if previous_leader.is_none() {
                            // Notify tasks waiting for the leader. Unwrap is safe as this is only
                            // needed the first time when there is no leader yet.
                            let mut leader_notify = inner.leader_notify.lock().unwrap();
                            let leader_notify = leader_notify.take().unwrap();
                            drop(leader_notify.send(new_leader.clone()));
                        }

                        if let Some(previous_leader) = previous_leader.take() {
                            previous_leader.client.shutdown();
                        }
                        *previous_leader = Some(new_leader);

                        Ok(())
                    })
                    .into_box()
            })
                .then(|r| -> Result<(), ()> {
                    match r {
                        // Committee stream ended.
                        Ok(()) => {
                            // The scheduler has ended the blockchain.
                            // For now, exit, because no more progress can be made.
                            error!("Unexpected end of stream while watching scheduler committees");
                            std::process::exit(1);
                        }
                        // Committee stream errored.
                        Err(e) => {
                            // Propagate error to service manager (high-velocity implementation).
                            error!(
                                "Unexpected error while watching scheduler committees: {:?}",
                                e
                            );
                            std::process::exit(1);
                        }
                    };
                })
                .into_box()
        });
    }

    /// Queue a contract call.
    pub fn call<C, O>(&self, method: &str, arguments: C) -> BoxFuture<O>
    where
        C: Serialize + Send + 'static,
        O: DeserializeOwned + Send + 'static,
    {
        let leader = self.inner.leader.read().unwrap();

        match *leader {
            Some(ref leader) => leader.client.call(method, arguments),
            None => {
                // No leader yet, we need to wait for the leader and then make the call.
                let method = method.to_owned();

                self.inner
                    .future_leader
                    .clone()
                    .map_err(|error| error.into())
                    .and_then(move |leader| leader.client.call(&method, arguments))
                    .into_box()
            }
        }
    }
}
