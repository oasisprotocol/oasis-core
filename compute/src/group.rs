//! Computation group structures.
use std::sync::{Arc, Mutex};

use grpcio;

use ekiden_compute_api::{ComputationGroupClient, SubmitBatchRequest};
use ekiden_core::bytes::{B256, B64, H256};
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::sync::mpsc;
use ekiden_core::node::Node;
use ekiden_core::node_group::NodeGroup;
use ekiden_core::signature::{Signed, Signer};
use ekiden_core::subscribers::StreamSubscribers;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_scheduler_base::{CommitteeNode, CommitteeType, Role, Scheduler};

/// Signature context used for batch submission.
const SUBMIT_BATCH_SIGNATURE_CONTEXT: B64 = B64(*b"EkCgBaSu");

/// Commands for communicating with the computation group from other tasks.
enum Command {
    /// Submit batch to workers.
    Submit(H256),
    /// Update committee.
    UpdateCommittee(Vec<CommitteeNode>),
}

struct Inner {
    /// Contract identifier the computation group is for.
    contract_id: B256,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Entity registry.
    entity_registry: Arc<EntityRegistryBackend>,
    /// Computation node group.
    node_group: NodeGroup<ComputationGroupClient>,
    /// Computation committee metadata.
    committee: Mutex<Vec<CommitteeNode>>,
    /// Signer for the compute node.
    signer: Arc<Signer>,
    /// gRPC environment.
    environment: Arc<grpcio::Environment>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Role subscribers.
    role_subscribers: StreamSubscribers<Option<Role>>,
}

impl Inner {
    /// Get local node's role in the committee.
    ///
    /// May be `None` in case the local node is not part of the computation group.
    fn get_role(&self) -> Option<Role> {
        let committee = self.committee.lock().unwrap();
        committee
            .iter()
            .filter(|node| node.public_key == self.signer.get_public_key())
            .map(|node| node.role.clone())
            .next()
    }
}

/// Structure that maintains connections to the current compute committee.
pub struct ComputationGroup {
    inner: Arc<Inner>,
}

impl ComputationGroup {
    /// Create new computation group.
    pub fn new(
        contract_id: B256,
        scheduler: Arc<Scheduler>,
        entity_registry: Arc<EntityRegistryBackend>,
        signer: Arc<Signer>,
        environment: Arc<grpcio::Environment>,
    ) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();

        Self {
            inner: Arc::new(Inner {
                contract_id,
                scheduler,
                entity_registry,
                node_group: NodeGroup::new(),
                committee: Mutex::new(vec![]),
                signer,
                environment,
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                role_subscribers: StreamSubscribers::new(),
            }),
        }
    }

    /// Start computation group tasks.
    pub fn start(&self, executor: &mut Executor) {
        info!("Starting computation group services");

        let mut event_sources = stream::SelectAll::new();

        // Subscribe to computation group formations for given contract and update nodes.
        let contract_id = self.inner.contract_id;
        event_sources.push(
            self.inner
                .scheduler
                .watch_committees()
                .filter(|committee| committee.kind == CommitteeType::Compute)
                .filter(move |committee| committee.contract.id == contract_id)
                .map(|committee| Command::UpdateCommittee(committee.members))
                .into_box(),
        );

        // Receive commands.
        let command_receiver = self.inner
            .command_receiver
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        event_sources.push(
            command_receiver
                .map_err(|_| Error::new("command channel closed"))
                .into_box(),
        );

        // Process commands.
        executor.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing group commands",
                move |command| match command {
                    Command::Submit(batch_hash) => Self::handle_submit(inner.clone(), batch_hash),
                    Command::UpdateCommittee(members) => {
                        measure_counter_inc!("committee_updates_count");

                        Self::handle_update_committee(inner.clone(), members)
                    }
                },
            )
        });
    }

    /// Handle committee update.
    fn handle_update_committee(inner: Arc<Inner>, members: Vec<CommitteeNode>) -> BoxFuture<()> {
        info!("Starting update of computation group committee");

        // Clear previous group.
        {
            let mut committee = inner.committee.lock().unwrap();
            committee.clear();
        }
        inner.node_group.clear();

        // Check if we are still part of the committee. If we are not, do not populate the node
        // group with any nodes as it is not needed.
        if !members
            .iter()
            .any(|node| node.public_key == inner.signer.get_public_key())
        {
            info!("No longer a member of the computation group");
            inner.role_subscribers.notify(&None);
            return Box::new(future::ok(()));
        }

        // Resolve nodes via the entity registry.
        // TODO: Support group fetch to avoid multiple requests to registry or make scheduler return nodes.
        let nodes: Vec<BoxFuture<Node>> = members
            .iter()
            .filter(|node| node.public_key != inner.signer.get_public_key())
            .filter(|node| node.role == Role::Worker)
            .map(|node| inner.entity_registry.get_node(node.public_key))
            .collect();

        Box::new(
            future::join_all(nodes)
                .and_then(move |nodes| {
                    // Update group.
                    for node in nodes {
                        let channel = node.connect(inner.environment.clone());
                        let client = ComputationGroupClient::new(channel);
                        inner.node_group.add_node(client);
                    }

                    trace!("New committee: {:?}", members);

                    // Update current committee.
                    {
                        let mut committee = inner.committee.lock().unwrap();
                        *committee = members;
                    }

                    let new_role = inner.get_role().unwrap();
                    info!("Our new role is: {:?}", new_role);
                    inner.role_subscribers.notify(&Some(new_role));

                    info!("Update of computation group committee finished");

                    Ok(())
                })
                .or_else(|error| {
                    error!(
                        "Failed to resolve computation group from registry: {}",
                        error.message
                    );
                    Ok(())
                }),
        )
    }

    /// Handle batch submission.
    fn handle_submit(inner: Arc<Inner>, batch_hash: H256) -> BoxFuture<()> {
        trace!("Submitting batch to workers");

        // Sign batch.
        let signed_batch = Signed::sign(&inner.signer, &SUBMIT_BATCH_SIGNATURE_CONTEXT, batch_hash);

        // Submit batch.
        let mut request = SubmitBatchRequest::new();
        request.set_batch_hash(batch_hash.to_vec());
        request.set_signature(signed_batch.signature.into());

        inner
            .node_group
            .call_all(move |client| client.submit_batch_async(&request))
            .and_then(|results| {
                for result in results {
                    if let Err(error) = result {
                        error!("Failed to submit batch to node: {}", error.message);
                    }
                }

                Ok(())
            })
            .into_box()
    }

    /// Submit batch to workers in the computation group.
    pub fn submit(&self, batch_hash: H256) -> Vec<CommitteeNode> {
        self.inner
            .command_sender
            .unbounded_send(Command::Submit(batch_hash))
            .unwrap();

        let committee = self.inner.committee.lock().unwrap();
        committee.clone()
    }

    /// Verify that given batch has been signed by the current leader.
    ///
    /// Returns the call batch and the current compute committee.
    pub fn open_remote_batch(
        &self,
        batch_hash: Signed<H256>,
    ) -> Result<(H256, Vec<CommitteeNode>)> {
        // Check if batch was signed by leader, drop otherwise.
        let committee = {
            let committee = self.inner.committee.lock().unwrap();
            if !committee.iter().any(|node| {
                node.role == Role::Leader && node.public_key == batch_hash.signature.public_key
            }) {
                warn!("Dropping call batch not signed by compute committee leader");
                return Err(Error::new("not signed by compute committee leader"));
            }

            committee.clone()
        };

        Ok((batch_hash.open(&SUBMIT_BATCH_SIGNATURE_CONTEXT)?, committee))
    }

    /// Subscribe to notifications on our current role in the computation committee.
    pub fn watch_role(&self) -> BoxStream<Option<Role>> {
        self.inner.role_subscribers.subscribe().1
    }

    /// Get current committee.
    pub fn get_committee(&self) -> Vec<CommitteeNode> {
        self.inner.committee.lock().unwrap().clone()
    }

    /// Get local node's role in the committee.
    ///
    /// May be `None` in case the local node is not part of the computation group.
    pub fn get_role(&self) -> Option<Role> {
        self.inner.get_role()
    }

    /// Check if the local node is a leader of the computation group.
    pub fn is_leader(&self) -> bool {
        self.get_role() == Some(Role::Leader)
    }
}
