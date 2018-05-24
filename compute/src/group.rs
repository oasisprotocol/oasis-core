//! Computation group structures.
use std::sync::{Arc, Mutex};

use grpcio;
use protobuf::RepeatedField;

use ekiden_compute_api::{ComputationGroupClient, SubmitBatchRequest};
use ekiden_core::bytes::{B256, B64};
use ekiden_core::contract::batch::CallBatch;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::sync::mpsc;
use ekiden_core::futures::{future, BoxFuture, Executor, Future, IntoFuture, Stream, StreamExt};
use ekiden_core::node::Node;
use ekiden_core::node_group::NodeGroup;
use ekiden_core::signature::{Signed, Signer};
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_scheduler_base::{CommitteeNode, CommitteeType, Role, Scheduler};

/// Signature context used for batch submission.
const SUBMIT_BATCH_SIGNATURE_CONTEXT: B64 = B64(*b"EkCgBaSu");

/// Commands for communicating with the computation group from other tasks.
enum Command {
    /// Submit batch to workers.
    Submit(CallBatch),
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
    signer: Arc<Signer + Send + Sync>,
    /// gRPC environment.
    environment: Arc<grpcio::Environment>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
}

/// Structure that maintains connections to the current compute committee.
pub struct ComputationGroup {
    inner: Arc<Inner>,
}

impl ComputationGroup {
    pub fn new(
        contract_id: B256,
        scheduler: Arc<Scheduler>,
        entity_registry: Arc<EntityRegistryBackend>,
        signer: Arc<Signer + Send + Sync>,
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
            }),
        }
    }

    /// Start computation group tasks.
    pub fn start(&self, executor: &mut Executor) {
        info!("Starting computation group services");

        // Subscribe to computation group formations for given contract and update nodes.
        executor.spawn({
            let inner = self.inner.clone();
            let contract_id = self.inner.contract_id;

            self.inner
                .scheduler
                .watch_committees()
                .filter(|committee| committee.kind == CommitteeType::Compute)
                .filter(move |committee| committee.contract.id == contract_id)
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error while processing committee updates",
                    move |committees| {
                        // Update node group with new nodes.
                        inner
                            .command_sender
                            .unbounded_send(Command::UpdateCommittee(committees.members))
                            .map_err(|error| Error::from(error))
                            .into_future()
                    },
                )
        });

        // Receive commands.
        let command_receiver = self.inner
            .command_receiver
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        executor.spawn({
            let inner = self.inner.clone();

            command_receiver
                .map_err(|_| Error::new("command channel closed"))
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error while processing group commands",
                    move |command| match command {
                        Command::Submit(calls) => Self::handle_submit(inner.clone(), calls),
                        Command::UpdateCommittee(members) => {
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
            return Box::new(future::ok(()));
        }

        // Check if we are the leader.
        if members.iter().any(|node| {
            node.public_key == inner.signer.get_public_key() && node.role == Role::Leader
        }) {
            info!("We are now the computation group leader");
        }

        // Resolve nodes via the entity registry.
        // TODO: Support group fetch to avoid multiple requests to registry or make scheduler return nodes.
        let nodes: Vec<BoxFuture<Node>> = members
            .iter()
            .filter(|node| node.public_key != inner.signer.get_public_key())
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
    fn handle_submit(inner: Arc<Inner>, calls: CallBatch) -> BoxFuture<()> {
        trace!("Submitting batch to workers");

        // Sign batch.
        let signed_calls = Signed::sign(&inner.signer, &SUBMIT_BATCH_SIGNATURE_CONTEXT, calls);

        // Submit batch.
        let mut request = SubmitBatchRequest::new();
        request.set_batch(RepeatedField::from_vec(
            signed_calls.get_value_unsafe().to_vec(),
        ));
        request.set_signature(signed_calls.signature.into());

        Box::new(
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
                }),
        )
    }

    /// Submit batch to workers in the computation group.
    pub fn submit(&self, calls: CallBatch) -> Vec<CommitteeNode> {
        self.inner
            .command_sender
            .unbounded_send(Command::Submit(calls))
            .unwrap();

        let committee = self.inner.committee.lock().unwrap();
        committee.clone()
    }

    /// Verify that given batch has been signed by the current leader.
    ///
    /// Returns the call batch and the current compute committee.
    pub fn open_remote_batch(
        &self,
        calls: Signed<CallBatch>,
    ) -> Result<(CallBatch, Vec<CommitteeNode>)> {
        // Check if batch was signed by leader, drop otherwise.
        let committee = {
            let committee = self.inner.committee.lock().unwrap();
            if !committee.iter().any(|node| {
                node.role == Role::Leader && node.public_key == calls.signature.public_key
            }) {
                warn!("Dropping call batch not signed by compute committee leader");
                return Err(Error::new("not signed by compute committee leader"));
            }

            committee.clone()
        };

        Ok((calls.open(&SUBMIT_BATCH_SIGNATURE_CONTEXT)?, committee))
    }

    /// Check if the local node is a leader of the computation group.
    pub fn is_leader(&self) -> bool {
        let committee = self.inner.committee.lock().unwrap();
        committee.iter().any(|node| {
            node.public_key == self.inner.signer.get_public_key() && node.role == Role::Leader
        })
    }
}
