//! Computation group structures.
use std::fmt;
use std::sync::{Arc, Mutex};

use ekiden_compute_api::{ComputationGroupClient, SubmitBatchRequest};
use ekiden_core::bytes::{B256, H256};
use ekiden_core::crash;
use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::streamfollow;
use ekiden_core::hash::EncodedHash;
use ekiden_core::identity::NodeIdentity;
use ekiden_core::node::Node;
use ekiden_core::node_group::NodeGroup;
use ekiden_core::subscribers::StreamSubscribers;
use ekiden_epochtime::interface::EpochTime;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_roothash_base::Header;
use ekiden_scheduler_base::{CommitteeNode, CommitteeType, Role, Scheduler};
use ekiden_storage_base::StorageBackend;
use ekiden_storage_frontend::StorageClient;

use super::statetransfer::transition_keys;

/// A node's role in a specific committee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRole {
    /// Role.
    pub role: Role,
    /// Committee.
    pub committee: Vec<CommitteeNode>,
    /// Epoch.
    pub epoch: EpochTime,
}

impl fmt::Display for GroupRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}/{}/{}",
            self.role,
            self.committee.get_encoded_hash(),
            self.epoch
        )
    }
}

/// Commands for communicating with the computation group from other tasks.
enum Command {
    /// Update committee.
    UpdateCommittee(EpochTime, Vec<CommitteeNode>),
}

struct Epoch {
    /// Current epoch number.
    number: EpochTime,
    /// Computation node group.
    node_group: NodeGroup<ComputationGroupClient, CommitteeNode>,
    /// Computation committee metadata.
    committee: Vec<CommitteeNode>,
    /// Node metadata.
    nodes: Vec<Node>,
    /// Local node's role. Can be `None` if node is not part of committee.
    role: Option<Role>,
    /// Kill handle for the task handling the epoch transition.
    transition_task: Option<KillHandle>,
    /// Batch submission task.
    batch_submission_task: Option<KillHandle>,
    /// Storage transfer task.
    storage_transfer_task: Option<KillHandle>,
}

impl Epoch {
    fn new(number: EpochTime, committee: Vec<CommitteeNode>, public_key: B256) -> Self {
        // Find our role.
        let role = committee
            .iter()
            .filter(|node| node.public_key == public_key)
            .map(|node| node.role.clone())
            .next();

        Epoch {
            number,
            node_group: NodeGroup::new(),
            committee,
            nodes: vec![],
            role,
            transition_task: None,
            batch_submission_task: None,
            storage_transfer_task: None,
        }
    }
}

impl Drop for Epoch {
    fn drop(&mut self) {
        // Ensure storage transfer task is killed when the epoch is dropped.
        if let Some(storage_transfer_task) = self.storage_transfer_task.take() {
            storage_transfer_task.kill();
        }

        // Ensure batch submission task is killed when the epoch is dropped.
        if let Some(batch_submission_task) = self.batch_submission_task.take() {
            batch_submission_task.kill();
        }

        // Ensure the task handling the epoch transition is killed when the
        // epoch is dropped.
        if let Some(transition_task) = self.transition_task.take() {
            transition_task.kill();
        }
    }
}

#[derive(Default)]
struct EpochTransitionState {
    /// Active epoch.
    active: Option<Epoch>,
    /// Epoch we are transitioning to.
    transitioning: Option<Epoch>,
}

struct Inner {
    /// Runtime identifier the computation group is for.
    runtime_id: B256,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Entity registry.
    entity_registry: Arc<EntityRegistryBackend>,
    /// Compute node's public key.
    public_key: B256,
    /// Storage backend for pulling active storage keys.
    storage: Arc<StorageBackend>,
    /// Environment.
    environment: Arc<Environment>,
    /// Node identity,
    identity: Arc<NodeIdentity>,
    /// Role subscribers.
    role_subscribers: StreamSubscribers<Option<GroupRole>>,
    /// Current epoch transition state.
    epochs: Mutex<EpochTransitionState>,
}

/// Structure that maintains connections to the current compute committee.
pub struct ComputationGroup {
    inner: Arc<Inner>,
}

impl ComputationGroup {
    /// Create new computation group.
    pub fn new(
        runtime_id: B256,
        scheduler: Arc<Scheduler>,
        entity_registry: Arc<EntityRegistryBackend>,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let instance = Self {
            inner: Arc::new(Inner {
                runtime_id,
                scheduler,
                entity_registry,
                public_key: identity.get_public_key(),
                storage,
                environment,
                identity,
                role_subscribers: StreamSubscribers::new(),
                epochs: Mutex::new(EpochTransitionState::default()),
            }),
        };
        instance.start();

        instance
    }

    /// Start computation group tasks.
    pub fn start(&self) {
        info!("Starting computation group services");

        let mut event_sources = stream::SelectAll::new();

        // Subscribe to computation group formations for given runtime and update nodes.
        let scheduler_init = self.inner.scheduler.clone();
        let runtime_id = self.inner.runtime_id.clone();

        event_sources.push(
            streamfollow::follow_skip(
                "ComputationGroup committees",
                move || {
                    scheduler_init
                        .watch_committees()
                        .filter(|committee| committee.kind == CommitteeType::Compute)
                        .filter(move |committee| committee.runtime_id == runtime_id)
                },
                |committee| committee.valid_for,
                |_err| false,
            ).map(|committee| Command::UpdateCommittee(committee.valid_for, committee.members))
                .into_box(),
        );

        // Process commands.
        self.inner.environment.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing group commands",
                move |command| match command {
                    Command::UpdateCommittee(epoch, members) => {
                        measure_counter_inc!("committee_updates_count");

                        Self::handle_update_committee(inner.clone(), epoch, members)
                    }
                },
            )
        });
    }

    /// Start storage transfer from previous epoch.
    fn start_storage_transfer(inner: Arc<Inner>, epochs: &mut EpochTransitionState) {
        if epochs.active.is_none() {
            // No previous epoch, so no need to transfer anything.
            return;
        }

        let storage_transfer_task = {
            let active_epoch = epochs.active.as_ref().unwrap();
            let next_epoch = epochs
                .transitioning
                .as_ref()
                .expect("transitioning to epoch");
            if next_epoch.role != Some(Role::Leader) && next_epoch.role != Some(Role::Worker) {
                return;
            }

            info!(
                "Starting storage transfer {} -> {}",
                active_epoch.number, next_epoch.number
            );

            // TODO: smarter choice of remote node.
            let storage_transfer_task;
            if let Some(node) = active_epoch.nodes.first() {
                let remote_client = Arc::new(StorageClient::from_node(
                    &node,
                    inner.environment.clone(),
                    inner.identity.clone(),
                ));

                // Get active key list.
                storage_transfer_task = Some(spawn_killable(transition_keys(
                    remote_client,
                    // TODO: Pass a storage backend that, when using multilayer storage, would
                    // allow transition_keys to insert into the local layer without hassling the
                    // last resort layer.
                    unimplemented!(),
                )));
            } else {
                warn!("No nodes in previous committee, skipping storage transfer");
                storage_transfer_task = None;
            }

            storage_transfer_task
        };

        let next_epoch = epochs.transitioning.as_mut().unwrap();
        next_epoch.storage_transfer_task = storage_transfer_task;
    }

    /// Handle committee update.
    fn handle_update_committee(
        inner: Arc<Inner>,
        epoch: EpochTime,
        members: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        let mut epochs = inner.epochs.lock().unwrap();
        let previous_epoch = epochs.active.as_ref().map_or(0, |e| e.number);
        info!(
            "Entering new epoch {} (previous epoch {})",
            epoch, previous_epoch
        );
        trace!("Committee for epoch {}: {:?}", epoch, members);

        // Start epoch transition. The previous epoch (if any) will remain active until the
        // transition completes. If a previous transition is still in progress, be sure to
        // stop it.
        if let Some(previous_transition) = epochs.transitioning.take() {
            measure_counter_inc!("killed_transition_task_count");
            warn!(
                "Transition to previous epoch ({}) is still in progress, will be killed",
                previous_transition.number,
            );
            drop(previous_transition);
        }

        let inner = inner.clone();
        let mut next_epoch = Epoch::new(epoch, members, inner.public_key);
        let transitioning_epoch_number = next_epoch.number;
        next_epoch.transition_task = Some(spawn_killable(
            inner
                .entity_registry
                .get_nodes(epoch)
                .and_then(move |nodes| {
                    let mut epochs = inner.epochs.lock().unwrap();

                    {
                        let epoch = epochs
                            .transitioning
                            .as_mut()
                            .expect("transitioning epoch to be set");
                        // Check if we are still processing the correct epoch as we might have been
                        // killed while waiting for the epochs lock.
                        if epoch.number != transitioning_epoch_number {
                            return Ok(());
                        }
                        // Clear transition task handle as we are done.
                        drop(epoch.transition_task.take());

                        // Filter nodes by committee.
                        let nodes: Vec<_> = nodes
                            .iter()
                            .filter_map(|node| {
                                epoch
                                    .committee
                                    .iter()
                                    .find(|m| m.public_key == node.id)
                                    .map(|member| (node, member.clone()))
                            })
                            .collect();

                        // Update group.
                        for (node, member) in nodes {
                            let channel =
                                node.connect(inner.environment.clone(), inner.identity.clone());
                            let client = ComputationGroupClient::new(channel);
                            epoch.nodes.push(node.clone());
                            epoch.node_group.add_node(client, member);
                        }

                        assert_eq!(epoch.nodes.len(), epoch.committee.len());
                    }

                    // Perform storage transfer.
                    // FIXME: storage transfer temporarily disabled (#818)
                    if false {
                        Self::start_storage_transfer(inner.clone(), &mut epochs);
                    }

                    // Finish epoch transition.
                    if let Some(ref active_epoch) = epochs.active {
                        info!(
                            "Epoch transition {} -> {} complete",
                            active_epoch.number,
                            epochs.transitioning.as_ref().unwrap().number
                        );
                    } else {
                        info!(
                            "Epoch transition None -> {} complete",
                            epochs.transitioning.as_ref().unwrap().number
                        );
                    }

                    epochs.active = epochs.transitioning.take();

                    let active_epoch = epochs.active.as_mut().expect("transition to an epoch");
                    if let Some(ref role) = active_epoch.role {
                        info!(
                            "Our new role in epoch {} is: {:?}",
                            active_epoch.number, role
                        );
                    } else {
                        info!(
                            "No longer a member of the computation group in epoch {}",
                            active_epoch.number
                        );
                    }

                    inner
                        .role_subscribers
                        .notify(&active_epoch.role.map(|role| GroupRole {
                            role,
                            committee: active_epoch.committee.clone(),
                            epoch: active_epoch.number,
                        }));

                    Ok(())
                })
                .or_else(|error| {
                    // Crash as this leaves the node in an inconsistent state.
                    crash!(
                        "Failed to resolve computation group from registry: {:?}",
                        error
                    );

                    #[allow(unreachable_code)]
                    Ok(())
                }),
        ));

        epochs.transitioning = Some(next_epoch);

        future::ok(()).into_box()
    }

    /// Submit batch to workers in the computation group.
    pub fn submit(&self, batch_hash: H256, block_header: Header, role: &GroupRole) -> bool {
        trace!("Submitting batch to workers");

        let mut epochs = self.inner.epochs.lock().unwrap();
        let active_epoch = epochs.active.as_mut().expect("no active epoch");

        // Ensure that the active epoch committee is still the same as before.
        if &role.committee != &active_epoch.committee || role.epoch != active_epoch.number {
            return false;
        }

        // Prepare request.
        let mut request = SubmitBatchRequest::new();
        request.set_batch_hash(batch_hash.to_vec());
        request.set_block_header(block_header.into());
        request.set_group_hash(active_epoch.committee.get_encoded_hash().to_vec());

        // If a batch submission task already exists, kill it as it is out of date.
        if let Some(handle) = active_epoch.batch_submission_task.take() {
            measure_counter_inc!("killed_batch_submission_task_count");
            warn!("Previous batch submission is still in progress, will be killed");
            handle.kill();
        }

        let inner = self.inner.clone();
        let active_epoch_number = active_epoch.number;
        active_epoch.batch_submission_task = Some(spawn_killable(
            active_epoch
                .node_group
                .call_filtered(
                    "ComputationGroup submit_batch",
                    |_, node| node.role == Role::Worker,
                    move |client, _| client.submit_batch_async(&request),
                )
                .and_then(move |results| {
                    for result in results {
                        if let Err(error) = result {
                            error!("Failed to submit batch to node: {}", error.message);
                        }
                    }

                    // Clear batch submission task.
                    let mut epochs = inner.epochs.lock().unwrap();
                    if let Some(active_epoch) = epochs.active.as_mut() {
                        if active_epoch.number == active_epoch_number {
                            drop(active_epoch.batch_submission_task.take());
                        }
                    }

                    Ok(())
                })
                .discard(),
        ));

        true
    }

    /// Check if given node public key belongs to the current committee leader.
    ///
    /// Returns current committee.
    pub fn check_remote_batch(&self, node_id: B256) -> Result<Vec<CommitteeNode>> {
        let epochs = self.inner.epochs.lock().unwrap();
        let active_epoch = epochs.active.as_ref().expect("no active epoch");

        if !active_epoch
            .committee
            .iter()
            .any(|node| node.role == Role::Leader && node.public_key == node_id)
        {
            warn!("Dropping call batch not signed by compute committee leader");
            return Err(Error::new("not current committee leader"));
        }

        Ok(active_epoch.committee.clone())
    }

    /// Subscribe to notifications on our current role in the computation committee.
    pub fn watch_role(&self) -> BoxStream<Option<GroupRole>> {
        self.inner.role_subscribers.subscribe().1
    }
}
