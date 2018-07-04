//! Computation group structures.
use std::sync::{Arc, Mutex};

use ekiden_compute_api as api;
use ekiden_consensus_base::network::{ConsensusNetwork, Content, Message, Recipient};
use ekiden_consensus_base::{Commitment, Reveal};
use ekiden_core::bytes::{B256, H256};
use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::sync::mpsc;
use ekiden_core::identity::NodeIdentity;
use ekiden_core::node::Node;
use ekiden_core::node_group::NodeGroup;
use ekiden_core::subscribers::StreamSubscribers;
use ekiden_epochtime::interface::EpochTime;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_scheduler_base::{CommitteeNode, CommitteeType, Role, Scheduler};
use ekiden_storage_base::StorageBackend;
use ekiden_storage_frontend::StorageClient;

/// Commands for communicating with the computation group from other tasks.
enum Command {
    /// Submit batch to workers.
    Submit(H256),
    /// Update committee.
    UpdateCommittee(EpochTime, Vec<CommitteeNode>),
    /// Submit a commit to the leader for aggregation.
    SubmitAggCommit(Commitment),
    /// Submit a reveal to the leader for aggregation.
    SubmitAggReveal(Reveal),
    /// Submit consensus gossip.
    SubmitConsensusGossip(Recipient, Content),
}

struct Inner {
    /// Contract identifier the computation group is for.
    contract_id: B256,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Entity registry.
    entity_registry: Arc<EntityRegistryBackend>,
    /// Computation node group.
    node_group: NodeGroup<api::ComputationGroupClient, CommitteeNode>,
    /// Computation committee metadata.
    committee: Mutex<Vec<CommitteeNode>>,
    /// Compute node's public key.
    public_key: B256,
    /// Current leader of the computation committee.
    leader: Arc<Mutex<Option<CommitteeNode>>>,
    /// Environment.
    environment: Arc<Environment>,
    /// Node identity,
    identity: Arc<NodeIdentity>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Role subscribers.
    role_subscribers: StreamSubscribers<Option<Role>>,
    /// Message subscribers.
    message_subscribers: StreamSubscribers<Message>,
}

impl Inner {
    /// Get local node's role in the committee.
    /// May be `None` in case the local node is not part of the computation group.
    fn get_role(&self) -> Option<Role> {
        let committee = self.committee.lock().unwrap();
        committee
            .iter()
            .filter(|node| node.public_key == self.public_key)
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
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();

        let instance = Self {
            inner: Arc::new(Inner {
                contract_id,
                scheduler,
                entity_registry,
                node_group: NodeGroup::new(),
                committee: Mutex::new(vec![]),
                public_key: identity.get_public_key(),
                leader: Arc::new(Mutex::new(None)),
                environment,
                identity,
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                role_subscribers: StreamSubscribers::new(),
                message_subscribers: StreamSubscribers::new(),
            }),
        };
        instance.start();

        instance
    }

    /// Start computation group tasks.
    pub fn start(&self) {
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
                .map(|committee| Command::UpdateCommittee(committee.valid_for, committee.members))
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
        self.inner.environment.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing group commands",
                move |command| match command {
                    Command::Submit(batch_hash) => Self::handle_submit(inner.clone(), batch_hash),
                    Command::UpdateCommittee(epoch, members) => {
                        measure_counter_inc!("committee_updates_count");

                        Self::handle_update_committee(inner.clone(), epoch, members)
                    }
                    Command::SubmitAggCommit(commit) => {
                        Self::handle_submit_agg_commit(inner.clone(), commit)
                    }
                    Command::SubmitAggReveal(reveal) => {
                        Self::handle_submit_agg_reveal(inner.clone(), reveal)
                    }
                    Command::SubmitConsensusGossip(recipient, content) => {
                        Self::handle_submit_consensus_gossip(inner.clone(), recipient, content)
                    }
                },
            )
        });
    }

    /// Handle committee update.
    fn handle_update_committee(
        inner: Arc<Inner>,
        epoch: EpochTime,
        members: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        info!("Starting update of computation group committee");

        // Clear previous group.
        {
            let mut committee = inner.committee.lock().unwrap();
            if *committee == members {
                info!("Not updating committee as membership has not changed");
                return future::ok(()).into_box();
            }

            committee.clear();
        }
        inner.node_group.clear();

        // Clear the current leader as well.
        *inner.leader.lock().unwrap() = None;

        // Check if we are still part of the committee. If we are not, do not populate the node
        // group with any nodes as it is not needed.
        if !members
            .iter()
            .any(|node| node.public_key == inner.public_key)
        {
            info!("No longer a member of the computation group");
            inner.role_subscribers.notify(&None);
            return Box::new(future::ok(()));
        }

        // Find new leader.
        *inner.leader.lock().unwrap() = members
            .iter()
            .find(|node| node.role == Role::Leader)
            .cloned();

        // Resolve nodes via the entity registry.
        // TODO: Support group fetch to avoid multiple requests to registry or make scheduler return nodes.
        let nodes: Vec<BoxFuture<(Node, CommitteeNode)>> = members
            .iter()
            .filter(|node| node.public_key != inner.public_key)
            .filter(|node| node.role == Role::Worker || node.role == Role::Leader)
            .map(|node| {
                let node = node.clone();

                inner
                    .entity_registry
                    .get_node(node.public_key)
                    .and_then(move |reg_node| Ok((reg_node, node.clone())))
                    .into_box()
            })
            .collect();

        let cur_epoch = epoch;
        trace!("Current epoch is {}", cur_epoch);

        let _cur_nodes = inner.entity_registry.get_nodes(cur_epoch);
        //      trace!("Current get_nodes list is {:?}", cur_nodes.wait().unwrap());

        let pre_nodes_handle: BoxFuture<Vec<Node>>;
        let mut pre_epoch = 1;
        if epoch > 1 {
            pre_epoch = epoch - 1;
        }
        trace!("Previous epoch is {}", pre_epoch);

        pre_nodes_handle = inner.entity_registry.get_nodes(pre_epoch);

        Box::new(
            future::join_all(nodes)
                .join(pre_nodes_handle)
                .and_then(move |(nodes, pre_nodes_handle)| {
                    // Update group.
                    for (node, committee_node) in nodes {
                        let channel =
                            node.connect(inner.environment.clone(), inner.identity.clone());
                        let client = api::ComputationGroupClient::new(channel);
                        inner.node_group.add_node(client, committee_node);
                    }

                    trace!("New committee: {:?}", members);

                    let old_role = inner.get_role();

                    // Update current committee.
                    {
                        let mut committee = inner.committee.lock().unwrap();
                        *committee = members;
                    }

                    let new_role = inner.get_role();
                    if new_role != old_role {
                        info!("Our new role is: {:?}", &new_role.unwrap());
                        inner.role_subscribers.notify(&new_role);
                    }

                    info!("Update of computation group committee finished");

                    if epoch > 1 {
                        let pre_nodes_unwrap = pre_nodes_handle;
                        let _client = StorageClient::from_node(
                            &pre_nodes_unwrap[0].clone(),
                            inner.environment.clone(),
                            inner.identity.clone(),
                        );
                    }

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

        // Submit batch.
        let mut request = api::SubmitBatchRequest::new();
        request.set_batch_hash(batch_hash.to_vec());

        inner
            .node_group
            .call_filtered(
                |_, node| node.role == Role::Worker,
                move |client, _| client.submit_batch_async(&request),
            )
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

    /// Handle submission of a single commit to the leader for aggregation.
    fn handle_submit_agg_commit(inner: Arc<Inner>, commit: Commitment) -> BoxFuture<()> {
        trace!("Submitting aggregate commit to leader");

        // Submit commit.
        let mut request = api::SubmitAggCommitRequest::new();
        request.set_commit(commit.into());

        inner
            .node_group
            .call_filtered(
                |_, node| node.role == Role::Leader,
                move |client, _| client.submit_agg_commit_async(&request),
            )
            .and_then(|results| {
                trace!("Aggregate commit submitted successfully!");

                for result in results {
                    if let Err(error) = result {
                        error!(
                            "Failed to submit aggregate commit to node: {}",
                            error.message
                        );
                    }
                }

                Ok(())
            })
            .into_box()
    }

    /// Handle submission of a single reveal to the leader for aggregation.
    fn handle_submit_agg_reveal(inner: Arc<Inner>, reveal: Reveal) -> BoxFuture<()> {
        trace!("Submitting aggregate reveal to leader");

        // Submit reveal.
        let mut request = api::SubmitAggRevealRequest::new();
        request.set_reveal(reveal.into());

        inner
            .node_group
            .call_filtered(
                |_, node| node.role == Role::Leader,
                move |client, _| client.submit_agg_reveal_async(&request),
            )
            .and_then(|results| {
                trace!("Aggregate reveal submitted successfully!");

                for result in results {
                    if let Err(error) = result {
                        error!(
                            "Failed to submit aggregate reveal to node: {}",
                            error.message
                        );
                    }
                }

                Ok(())
            })
            .into_box()
    }

    /// Handle submission of a consensus gossip message.
    fn handle_submit_consensus_gossip(
        inner: Arc<Inner>,
        recipient: Recipient,
        content: Content,
    ) -> BoxFuture<()> {
        // Prepare request.
        let mut request = api::ConsensusGossipRequest::new();
        request.set_content(content.into());

        inner
            .node_group
            .call_filtered(
                |_, node| match recipient {
                    Recipient::Node(node_id) => node.public_key == node_id,
                    Recipient::OnlyRole(role) => node.role == role,
                    Recipient::AllNodes => true,
                },
                move |client, _| client.consensus_gossip_async(&request),
            )
            .and_then(|results| {
                for result in results {
                    if let Err(error) = result {
                        error!(
                            "Failed to submit consensus gossip to node: {}",
                            error.message
                        );
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

    /// Submit a commit to the leader for aggregation.
    ///
    /// Returns the current leader of the computation group.
    pub fn submit_agg_commit(&self, commit: Commitment) -> CommitteeNode {
        self.inner
            .command_sender
            .unbounded_send(Command::SubmitAggCommit(commit))
            .unwrap();

        self.inner.leader.lock().unwrap().clone().unwrap()
    }

    /// Submit a reveal to the leader for aggregation.
    ///
    /// Returns the current leader of the computation group.
    pub fn submit_agg_reveal(&self, reveal: Reveal) -> CommitteeNode {
        self.inner
            .command_sender
            .unbounded_send(Command::SubmitAggReveal(reveal))
            .unwrap();

        self.inner.leader.lock().unwrap().clone().unwrap()
    }

    /// Check if given node public key belongs to the current committee leader.
    ///
    /// Returns current committee.
    pub fn check_remote_batch(&self, node_id: B256) -> Result<Vec<CommitteeNode>> {
        let committee = self.inner.committee.lock().unwrap();
        if !committee
            .iter()
            .any(|node| node.role == Role::Leader && node.public_key == node_id)
        {
            warn!("Dropping call batch not signed by compute committee leader");
            return Err(Error::new("not current committee leader"));
        }

        Ok(committee.clone())
    }

    /// Check if commitment/reveal comes from a worker and that we're the current
    /// leader, drop otherwise.
    ///
    /// Also note that the leader and backup workers also count as workers.
    pub fn check_aggregated(&self, node_id: B256) -> Result<Role> {
        let leader = self.inner.leader.lock().unwrap().clone().unwrap();

        if leader.public_key != self.inner.public_key {
            warn!("Dropping commit/reveal for aggregation, as we're not the current compute committee leader");
            return Err(Error::new("am not the current compute committee leader"));
        }

        let committee = self.inner.committee.lock().unwrap();

        // Find the node that signed this commitment.
        let node = committee.iter().find(|node| node.public_key == node_id);

        if node == None {
            warn!("Dropping commit/reveal for aggregation, as it was not signed by any node");
            return Err(Error::new("not signed by any node"));
        }

        // Get the role of the node that signed this commitment.
        let role = node.unwrap().role;

        if role != Role::Worker && role != Role::BackupWorker && role != Role::Leader {
            warn!(
                "Dropping commit/reveal for aggregation, as it was not signed by compute committee worker"
            );
            return Err(Error::new("not signed by compute committee worker"));
        }

        Ok(role)
    }

    /// Subscribe to notifications on our current role in the computation committee.
    pub fn watch_role(&self) -> BoxStream<Option<Role>> {
        self.inner.role_subscribers.subscribe().1
    }

    /// Get current committee.
    pub fn get_committee(&self) -> Vec<CommitteeNode> {
        self.inner.committee.lock().unwrap().clone()
    }

    /// Get number of workers (+ leader!) in the committee.
    pub fn get_number_of_workers(&self) -> usize {
        let committee = self.inner.committee.lock().unwrap();

        committee
            .iter()
            .filter(|node| node.role == Role::Worker || node.role == Role::Leader)
            .count()
    }

    /// Get number of backup workers in the committee.
    pub fn get_number_of_backup_workers(&self) -> usize {
        let committee = self.inner.committee.lock().unwrap();

        committee
            .iter()
            .filter(|node| node.role == Role::BackupWorker)
            .count()
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

    /// Deliver incoming consensus gossip from network backend.
    pub fn deliver_incoming_consensus_gossip(&self, message: Message) {
        // Ensure that message comes from a committee member.
        {
            let committee = self.inner.committee.lock().unwrap();
            if !committee
                .iter()
                .any(|node| node.public_key == message.sender)
            {
                warn!(
                    "Dropping incoming message from non-committee member {:?}",
                    message.sender
                );
                return;
            }
        }

        self.inner.message_subscribers.notify(&message);
    }
}

impl ConsensusNetwork for ComputationGroup {
    fn watch_messages(&self) -> BoxStream<Message> {
        self.inner.message_subscribers.subscribe().1
    }

    fn send(&self, recipient: Recipient, content: Content) {
        self.inner
            .command_sender
            .unbounded_send(Command::SubmitConsensusGossip(recipient, content))
            .unwrap();
    }
}
