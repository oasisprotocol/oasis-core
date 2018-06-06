//! Manager for contract clients.
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::sync::oneshot;
use ekiden_common::futures::{future, BoxFuture, Future, FutureExt, Stream, StreamExt};
use ekiden_common::node::Node;
use ekiden_common::signature::Signer;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_rpc_client::backend::Web3RpcClientBackend;
use ekiden_scheduler_base::{CommitteeType, Role, Scheduler};

use super::client::ContractClient;

/// Computation group leader.
struct Leader {
    /// Node descriptor.
    node: Node,
    /// Contract client.
    client: ContractClient<Web3RpcClientBackend>,
}

struct Inner {
    /// Contract identifier.
    contract_id: B256,
    /// Enclave identifier.
    mr_enclave: MrEnclave,
    /// Optional call timeout.
    timeout: Option<Duration>,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Entity registry.
    entity_registry: Arc<EntityRegistryBackend>,
    /// Environment.
    environment: Arc<Environment>,
    /// Signer.
    signer: Arc<Signer>,
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
        mr_enclave: MrEnclave,
        timeout: Option<Duration>,
        environment: Arc<Environment>,
        scheduler: Arc<Scheduler>,
        entity_registry: Arc<EntityRegistryBackend>,
        signer: Arc<Signer>,
    ) -> Self {
        let (leader_notify, future_leader) = oneshot::channel();

        let manager = Self {
            inner: Arc::new(Inner {
                contract_id,
                mr_enclave,
                timeout,
                environment,
                scheduler,
                entity_registry,
                signer,
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
            let inner = self.inner.clone();
            let contract_id = self.inner.contract_id;

            self.inner
                .scheduler
                .watch_committees()
                .filter(move |committee| committee.contract.id == contract_id)
                .filter(|committee| committee.kind == CommitteeType::Compute)
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error while watching scheduler committees",
                    move |committee| -> BoxFuture<()> {
                        // Committee has been updated, check if we need to update the leader.
                        let new_leader = match committee
                            .members
                            .iter()
                            .filter(|member| member.role == Role::Leader)
                            .map(|member| member.public_key)
                            .next()
                        {
                            Some(leader) => leader,
                            None => {
                                return future::err(Error::new("missing committee leader"))
                                    .into_box()
                            }
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
                                let address = node.addresses[0];
                                let backend = Web3RpcClientBackend::new(
                                    inner.environment.grpc(),
                                    inner.timeout,
                                    &format!("{}", address.ip()),
                                    address.port(),
                                )?;
                                let client = ContractClient::new(
                                    Arc::new(backend),
                                    inner.mr_enclave,
                                    inner.signer.clone(),
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
                                *previous_leader = Some(new_leader);

                                Ok(())
                            })
                            .into_box()
                    },
                )
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
