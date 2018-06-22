//! Consensus frontend.
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures_timer::Interval;
use serde_cbor;

use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, Event, Header, Reveal};
use ekiden_core::bytes::{B256, H256};
use ekiden_core::contract::batch::{CallBatch, OutputBatch};
use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::sync::{mpsc, oneshot};
use ekiden_core::hash::{empty_hash, EncodedHash};
use ekiden_core::signature::{Signed, Signer};
use ekiden_scheduler_base::{CommitteeNode, Role};
use ekiden_storage_base::{hash_storage_key, StorageBackend};

use super::group::ComputationGroup;
use super::worker::{ComputedBatch, Worker};

/// Commands for communicating with the consensus frontend from other tasks.
enum Command {
    /// Append to current batch.
    AppendBatch(CallBatch),
    /// Process remote batch.
    ProcessRemoteBatch(H256, Vec<CommitteeNode>),
    /// Process incoming queue.
    ProcessIncomingQueue,
    /// Process consensus block.
    ProcessBlock(Block),
    /// Process consensus backend event.
    ProcessEvent(Event),
    /// Update local role.
    UpdateRole(Option<Role>),
    /// Process commit for aggregation from node with given role.
    ProcessAggCommit(Commitment, Role),
    /// Process reveal for aggregation from node with given role.
    ProcessAggReveal(Reveal<Header>, Role),
}

/// State of the consensus frontend.
///
/// See the `transition` method for valid state transitions.
#[derive(Clone, Debug)]
enum State {
    /// We are waiting for the scheduler to include us in a computation group.
    NotReady,
    /// Based on our role:
    /// * `Leader`: We are waiting for enough calls to be queued in `incoming_queue` so
    ///   that we can start processing them.
    /// * `Worker`: We are waiting for a new remote batch from leader.
    /// * `BackupWorker`: We are waiting for a new remote batch from the consensus backend.
    WaitingForBatch(Role),
    /// A batch has been dispatched to the worker for processing.
    ProcessingBatch(Role),
    /// We have committed to a specific batch in the current consensus round and are
    /// waiting for the consensus backend to notify us to send reveals.
    ProposedBatch(Role, B256, Block),
    /// We have submitted a reveal for the committed batch in the current consensus
    /// round and are waiting ro the consensus backend to finalize the block.
    WaitingForFinalize(Role, Block),
}

impl State {
    /// Return current role based on state.
    pub fn get_role(&self) -> Option<Role> {
        match *self {
            State::WaitingForBatch(role) => Some(role),
            State::ProcessingBatch(role) => Some(role),
            State::ProposedBatch(role, ..) => Some(role),
            State::WaitingForFinalize(role, ..) => Some(role),
            _ => None,
        }
    }

    /// Return true if we are currently a leader.
    pub fn is_leader(&self) -> bool {
        if let Some(Role::Leader) = self.get_role() {
            true
        } else {
            false
        }
    }
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an error future is
/// returned.
macro_rules! require_state {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*, $message:expr) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => {}
            state => {
                return future::err(Error::new(format!(
                    "incorrect state for {}: {:?}",
                    $message, state
                ))).into_box()
            }
        }
    }};

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr, $message:expr) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => $output,
            state => {
                return future::err(Error::new(format!(
                    "incorrect state for {}: {:?}",
                    $message, state
                ))).into_box()
            }
        }
    }};
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an ok future is
/// returned.
macro_rules! require_state_ignore {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => {}
            _ => return future::ok(()).into_box(),
        }
    }};

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => $output,
            _ => return future::ok(()).into_box(),
        }
    }};
}

/// Queue of incoming contract calls which are pending to be included in a batch.
struct IncomingQueue {
    /// Instant when first item was queued.
    start: Instant,
    /// Queued contract calls.
    calls: CallBatch,
}

impl Default for IncomingQueue {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            calls: CallBatch::default(),
        }
    }
}

struct Inner {
    /// Current state of the consensus frontend.
    state: Mutex<State>,
    /// Contract identifier this consensus frontend is for.
    contract_id: B256,
    /// Environment.
    environment: Arc<Environment>,
    /// Consensus backend.
    backend: Arc<ConsensusBackend>,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Signer for the compute node.
    signer: Arc<Signer>,
    /// Worker that can process batches.
    worker: Arc<Worker>,
    /// Computation group that can process batches.
    computation_group: Arc<ComputationGroup>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Queue of incoming contract calls which are pending to be included in a batch.
    incoming_queue: Mutex<Option<IncomingQueue>>,
    /// Maximum batch size.
    max_batch_size: usize,
    /// Maximum batch timeout.
    max_batch_timeout: Duration,
    /// Call subscribers (call id -> list of subscribers).
    call_subscribers: Mutex<HashMap<H256, Vec<oneshot::Sender<Vec<u8>>>>>,
    /// Test-only configuration.
    test_only_config: ConsensusTestOnlyConfiguration,
    /// Commits from workers or leader waiting to be sent as an aggregation to the backend.
    agg_commits: Mutex<Vec<Commitment>>,
    /// Commits from backup workers waiting to be sent as an aggregation to the backend.
    agg_backup_commits: Mutex<Vec<Commitment>>,
    /// Reveals from workers or leader waiting to be sent as an aggregation to the backend.
    agg_reveals: Mutex<Vec<Reveal<Header>>>,
    /// Reveals from backup workers waiting to be sent as an aggregation to the backend.
    agg_backup_reveals: Mutex<Vec<Reveal<Header>>>,
}

/// Type of aggregation queue.
///
/// Used in handling of commits/reveals for aggregation to select the
/// appropriate queue in the Inner struct, based on the role of the node
/// that sent us the commit/reveal.
#[derive(Copy, Clone, Debug)]
enum AggregationQueueType {
    /// Primary commit/reveal queue (either agg_commits or agg_reveals).
    Primary,
    /// Backup commit/reveal queue (either agg_backup_commits or agg_backup_reveals).
    Backup,
}

/// Consensus test-only configuration.
#[derive(Clone)]
pub struct ConsensusTestOnlyConfiguration {
    /// Inject discrepancy when submitting commitment.
    pub inject_discrepancy: bool,
}

/// Consensus frontend configuration.
#[derive(Clone)]
pub struct ConsensusConfiguration {
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Maximum batch timeout.
    pub max_batch_timeout: u64,
    /// Test-only configuration.
    pub test_only: ConsensusTestOnlyConfiguration,
}

/// Compute node consensus frontend.
pub struct ConsensusFrontend {
    inner: Arc<Inner>,
}

impl ConsensusFrontend {
    /// Create a new consensus frontend.
    pub fn new(
        config: ConsensusConfiguration,
        contract_id: B256,
        environment: Arc<Environment>,
        worker: Arc<Worker>,
        computation_group: Arc<ComputationGroup>,
        backend: Arc<ConsensusBackend>,
        storage: Arc<StorageBackend>,
        signer: Arc<Signer>,
    ) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();

        let instance = Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::NotReady),
                contract_id,
                environment,
                backend,
                storage,
                signer,
                worker,
                computation_group,
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                incoming_queue: Mutex::new(None),
                max_batch_size: config.max_batch_size,
                max_batch_timeout: Duration::from_millis(config.max_batch_timeout),
                call_subscribers: Mutex::new(HashMap::new()),
                test_only_config: config.test_only.clone(),
                agg_commits: Mutex::new(Vec::new()),
                agg_backup_commits: Mutex::new(Vec::new()),
                agg_reveals: Mutex::new(Vec::new()),
                agg_backup_reveals: Mutex::new(Vec::new()),
            }),
        };
        instance.start();

        instance
    }

    /// Start consensus frontend.
    fn start(&self) {
        let mut event_sources = stream::SelectAll::new();

        // Subscribe to computation group updates.
        event_sources.push(
            self.inner
                .computation_group
                .watch_role()
                .map(|role| Command::UpdateRole(role))
                .into_box(),
        );

        // Subscribe to consensus events.
        event_sources.push(
            self.inner
                .backend
                .get_events(self.inner.contract_id)
                .map(|event| Command::ProcessEvent(event))
                .into_box(),
        );

        // Subscribe to consensus blocks.
        event_sources.push(
            self.inner
                .backend
                .get_blocks(self.inner.contract_id)
                .map(|block| Command::ProcessBlock(block))
                .into_box(),
        );

        // Periodically check for batches.
        event_sources.push(
            Interval::new(self.inner.max_batch_timeout)
                .map_err(|error| Error::from(error))
                .map(|_| Command::ProcessIncomingQueue)
                .into_box(),
        );

        // Subscribe to incoming command channel.
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

        // Process consensus commands.
        self.inner.environment.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing consensus commands",
                move |command| match command {
                    Command::AppendBatch(calls) => Self::handle_append_batch(inner.clone(), calls),
                    Command::ProcessRemoteBatch(batch_hash, committee) => {
                        Self::handle_remote_batch(inner.clone(), batch_hash, committee)
                    }
                    Command::ProcessIncomingQueue => {
                        Self::check_and_process_incoming_queue(inner.clone())
                    }
                    Command::ProcessBlock(block) => Self::handle_block(inner.clone(), block),
                    Command::ProcessEvent(Event::CommitmentsReceived(discrepancy)) => {
                        Self::handle_commitments_received(inner.clone(), discrepancy)
                    }
                    Command::ProcessEvent(Event::RoundFailed(error)) => {
                        Self::fail_batch(inner.clone(), format!("Round failed: {}", error.message))
                    }
                    Command::ProcessEvent(Event::DiscrepancyDetected(batch_hash)) => {
                        Self::handle_discrepancy_detected(inner.clone(), batch_hash)
                    }
                    Command::UpdateRole(Some(role)) => {
                        // Do nothing if the current role matches.
                        let current_role = inner.state.lock().unwrap().get_role();
                        if let Some(current_role) = current_role {
                            if current_role == role {
                                return future::ok(()).into_box();
                            }
                        }

                        Self::transition(inner.clone(), State::WaitingForBatch(role));
                        future::ok(()).into_box()
                    }
                    Command::UpdateRole(None) => Self::fail_batch(
                        inner.clone(),
                        "No longer part of computation group".to_string(),
                    ),
                    Command::ProcessAggCommit(commit, role) => {
                        Self::handle_agg_commit(inner.clone(), commit, role)
                    }
                    Command::ProcessAggReveal(reveal, role) => {
                        Self::handle_agg_reveal(inner.clone(), reveal, role)
                    }
                },
            )
        });
    }

    /// Transition the consensus frontend to a new state.
    ///
    /// # Panics
    ///
    /// This method will panic in case of an invalid state transition.
    fn transition(inner: Arc<Inner>, to: State) {
        let mut state = inner.state.lock().unwrap();
        match (&*state, &to) {
            // Transitions from NotReady state when node role is determined.
            (&State::NotReady, &State::WaitingForBatch(_)) => {}

            // Transitions from WaitingForBatch state. We can either transition to batch
            // processing in the same role or switch roles in case the committee changes.
            (&State::WaitingForBatch(role_a), &State::ProcessingBatch(role_b))
                if role_a == role_b => {}
            (&State::WaitingForBatch(role_a), &State::WaitingForBatch(role_b))
                if role_a != role_b => {}

            // Transitions from ProcessingBatch state. We can either transition to proposing
            // a batch (commit to batch) in the same role, abort the current batch and return
            // to waiting for a batch in the same role or switch roles in case the committee
            // changes.
            (&State::ProcessingBatch(role_a), &State::ProposedBatch(role_b, ..))
                if role_a == role_b => {}
            (&State::ProcessingBatch(_), &State::WaitingForBatch(_)) => {}

            // Transitions from the ProposedBatch state. We can either transition to submitting
            // a reveal and waiting for round finalization in the same role, abort the current
            // batch and return to waiting for a batch in the same role or switch roles in case
            // the committee changes.
            (&State::ProposedBatch(role_a, ..), &State::WaitingForFinalize(role_b, ..))
                if role_a == role_b => {}
            (&State::ProposedBatch(..), &State::WaitingForBatch(_)) => {}

            // Transitions from WaitingForFinalize state. We can transition to waiting for new
            // batches in either the current role or switch roles in case the committee changes.
            (&State::WaitingForFinalize(..), &State::WaitingForBatch(_)) => {}

            // We can stop being a member of the compute committee from any state.
            (_, &State::NotReady) => {}

            transition => panic!(
                "illegal consensus frontend state transition: {:?}",
                transition
            ),
        }

        trace!("Consensus frontend transitioning to {:?}", to);
        *state = to;
    }

    /// Handle append batch command.
    fn handle_append_batch(inner: Arc<Inner>, mut calls: CallBatch) -> BoxFuture<()> {
        // Ignore empty batches.
        if calls.is_empty() {
            return Box::new(future::ok(()));
        }

        // If we are not a leader, do not append to batch.
        {
            let state = inner.state.lock().unwrap();
            if !state.is_leader() {
                warn!("Ignoring append to batch as we are not the computation group leader");
                return Box::new(future::ok(()));
            }
        }

        // Append to batch.
        {
            let mut incoming_queue = inner.incoming_queue.lock().unwrap();
            let incoming_queue = incoming_queue.get_or_insert_with(|| IncomingQueue::default());
            incoming_queue.calls.append(&mut calls);

            measure_gauge!("incoming_queue_size", incoming_queue.calls.len());
        }

        // Check if batch is ready to be sent for processing.
        Self::check_and_process_incoming_queue(inner.clone())
    }

    /// Handle process remote batch command.
    fn handle_remote_batch(
        inner: Arc<Inner>,
        batch_hash: H256,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        let role = require_state!(
            inner,
            State::WaitingForBatch(role @ Role::Worker) |
            State::WaitingForBatch(role @ Role::BackupWorker) => role,
            "handling remote batch"
        );

        // Fetch batch from storage.
        inner
            .storage
            .get(batch_hash)
            .and_then(move |calls| {
                require_state!(
                    inner,
                    State::WaitingForBatch(current_role) if current_role == role,
                    "handling remote batch"
                );

                Self::transition(inner.clone(), State::ProcessingBatch(role));

                let calls = match serde_cbor::from_slice(&calls) {
                    Ok(calls) => calls,
                    Err(error) => return future::err(Error::from(error)).into_box(),
                };

                Self::process_batch(inner.clone(), calls, committee)
            })
            .or_else(move |error| {
                // Failed to fetch remote batch from storage.
                error!(
                    "Failed to fetch remote batch {:?} from storage: {}",
                    batch_hash, error.message
                );

                Ok(())
            })
            .into_box()
    }

    /// Handle commitments received event from consensus backend.
    fn handle_commitments_received(inner: Arc<Inner>, discrepancy: bool) -> BoxFuture<()> {
        let (role, nonce, block) = require_state_ignore!(
            inner,
            State::ProposedBatch(role, nonce, block) => (role, nonce, block)
        );

        assert!(!discrepancy || role == Role::BackupWorker);

        info!("Submitting reveal");

        // Generate and submit reveal.
        let reveal = Reveal::new(&inner.signer, &nonce, &block.header);

        Self::transition(inner.clone(), State::WaitingForFinalize(role, block));

        if role == Role::Leader {
            trace!("Commitments received, appending aggregate reveal on leader node (fast path)");

            // Leader can just append to its own aggregate reveals queue.
            Self::handle_agg_reveal(inner.clone(), reveal, role)
        } else {
            trace!("Commitments received, submitting aggregate reveal to leader");

            // Submit reveal to leader for aggregation.
            inner.computation_group.submit_agg_reveal(reveal);

            future::ok(()).into_box()
        }
    }

    /// Handle discrepancy detected event from consensus backend.
    fn handle_discrepancy_detected(inner: Arc<Inner>, batch_hash: H256) -> BoxFuture<()> {
        measure_counter_inc!("discrepancy_detected_count");

        warn!(
            "Discrepancy detected while processing batch {:?}",
            batch_hash
        );

        // Only backup workers can do anything during discrepancy resolution.
        require_state_ignore!(inner, State::WaitingForBatch(Role::BackupWorker));

        info!("Backup worker activating and processing batch");

        let committee = inner.computation_group.get_committee();
        Self::handle_remote_batch(inner, batch_hash, committee)
    }

    /// Handle new block from consensus backend.
    fn handle_block(inner: Arc<Inner>, block: Block) -> BoxFuture<()> {
        info!(
            "Received new block at round {:?} from consensus backend",
            block.header.round
        );

        // Check if this is a block for the same round that we proposed.
        let should_transition = {
            let state = inner.state.lock().unwrap();
            match &*state {
                &State::WaitingForFinalize(role, ref proposed_block) => {
                    if proposed_block.header.round >= block.header.round {
                        Some(role)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };

        if let Some(role) = should_transition {
            info!("Block is for the same round or newer as recently proposed block");
            info!("Considering the round finalized");

            // TODO: We should actually check if the proposed block was included.

            Self::transition(inner.clone(), State::WaitingForBatch(role));
        }

        if block.header.input_hash != empty_hash() {
            // Check if any subscribed transactions have been included in a block. To do that
            // we need to fetch transactions from storage first.
            inner
                .storage
                .get(block.header.input_hash)
                .join(inner.storage.get(block.header.output_hash))
                .and_then(move |(inputs, outputs)| {
                    let inputs: CallBatch = serde_cbor::from_slice(&inputs)?;
                    let outputs: OutputBatch = serde_cbor::from_slice(&outputs)?;
                    let mut call_subscribers = inner.call_subscribers.lock().unwrap();

                    for (input, output) in inputs.iter().zip(outputs.iter()) {
                        let call_id = input.get_encoded_hash();

                        if let Some(senders) = call_subscribers.remove(&call_id) {
                            for sender in senders {
                                // Explicitly ignore send errors as the receiver may have gone.
                                drop(sender.send(output.clone()));
                            }
                        }
                    }

                    Ok(())
                })
                .or_else(|error| {
                    error!(
                        "Failed to fetch transactions from storage: {}",
                        error.message
                    );

                    Ok(())
                })
                .into_box()
        } else {
            future::ok(()).into_box()
        }
    }

    /// Handle commit for aggregation command.
    fn handle_agg_commit(inner: Arc<Inner>, commit: Commitment, role: Role) -> BoxFuture<()> {
        require_state_ignore!(
            inner,
            State::ProcessingBatch(Role::Leader) | State::ProposedBatch(Role::Leader, ..)
                | State::WaitingForFinalize(Role::Leader, ..)
        );

        trace!("Adding commit from {:?} to aggregation queue", role);

        // Select appropriate queue based on the role of the node that sent
        // us the commitment.  Also calculate how many commitments we need
        // before we can send all the aggregated commitments to the backend.
        let mut agg_commits: MutexGuard<Vec<Commitment>>;
        let needed_commits: usize;
        let agg_queue: AggregationQueueType;

        match role {
            Role::Worker | Role::Leader => {
                agg_commits = inner.agg_commits.lock().unwrap();
                needed_commits = inner.computation_group.get_number_of_workers();
                agg_queue = AggregationQueueType::Primary;
            }
            Role::BackupWorker => {
                agg_commits = inner.agg_backup_commits.lock().unwrap();
                needed_commits = inner.computation_group.get_number_of_backup_workers();
                agg_queue = AggregationQueueType::Backup;
            }
        }

        // Add commit to the aggregation queue.
        agg_commits.push(commit);

        trace!(
            "Commits in {:?} queue aggregated so far: {}/{}",
            agg_queue,
            agg_commits.len(),
            needed_commits
        );

        // Check if it's time to send aggregated commits to the backend.
        //
        // For now, we only do this when we have aggregated commits from
        // all the workers in the committee, timeouts will be added later.
        //
        // TODO: We should probably explicitly check that each worker
        //       has sent exactly one commit instead of just checking
        //       the length of the array.
        if agg_commits.len() == needed_commits {
            trace!(
                "Submitting queued aggregated commits from {:?} queue to backend and clearing queue",
                agg_queue
            );

            // Drain the aggregated commits into a new vector for sending.
            let commits_to_send = agg_commits.drain(..).collect();

            let inner = inner.clone();
            inner
                .backend
                .commit_many(inner.contract_id, commits_to_send)
                .and_then(move |_| {
                    // Check that the aggregation queue is indeed empty.
                    match agg_queue {
                        AggregationQueueType::Primary => {
                            assert!(inner.agg_commits.lock().unwrap().is_empty());
                        }
                        AggregationQueueType::Backup => {
                            assert!(inner.agg_backup_commits.lock().unwrap().is_empty())
                        }
                    }

                    trace!(
                        "Queued aggregated commits from {:?} queue successfully sent to backend",
                        agg_queue
                    );

                    Ok(())
                })
                .or_else(move |error| {
                    error!(
                        "Aggregated commits from {:?} queue failed: {}",
                        agg_queue, error.message
                    );

                    // Should we do anything else here?

                    Ok(())
                })
                .into_box()
        } else {
            future::ok(()).into_box()
        }
    }

    /// Handle reveal for aggregation command.
    fn handle_agg_reveal(inner: Arc<Inner>, reveal: Reveal<Header>, role: Role) -> BoxFuture<()> {
        require_state_ignore!(
            inner,
            State::ProposedBatch(Role::Leader, ..) | State::WaitingForFinalize(Role::Leader, ..)
        );

        trace!("Adding reveal from {:?} to aggregation queue", role);

        // Select appropriate queue based on the role of the node that sent
        // us the reveal.  Also calculate how many reveals we need before we
        // can send all the aggregated reveals to the backend.
        let mut agg_reveals: MutexGuard<Vec<Reveal<Header>>>;
        let needed_reveals: usize;
        let agg_queue: AggregationQueueType;

        match role {
            Role::Worker | Role::Leader => {
                agg_reveals = inner.agg_reveals.lock().unwrap();
                needed_reveals = inner.computation_group.get_number_of_workers();
                agg_queue = AggregationQueueType::Primary;
            }
            Role::BackupWorker => {
                agg_reveals = inner.agg_backup_reveals.lock().unwrap();
                needed_reveals = inner.computation_group.get_number_of_backup_workers();
                agg_queue = AggregationQueueType::Backup;
            }
        }

        // Add reveal to the aggregation queue.
        agg_reveals.push(reveal);

        trace!(
            "Reveals in {:?} queue aggregated so far: {}/{}",
            agg_queue,
            agg_reveals.len(),
            needed_reveals
        );

        // Check if it's time to send aggregated reveals to the backend.
        //
        // For now, we only do this when we have aggregated reveals from
        // all the workers in the committee, timeouts will be added later.
        //
        // TODO: We should probably explicitly check that each worker
        //       has sent exactly one reveal instead of just checking
        //       the length of the array.
        if agg_reveals.len() == needed_reveals {
            trace!(
                "Submitting queued aggregated reveals from {:?} queue to backend and clearing queue",
                agg_queue
            );

            // Drain the aggregated reveals into a new vector for sending.
            let reveals_to_send = agg_reveals.drain(..).collect();

            let inner = inner.clone();
            inner
                .backend
                .reveal_many(inner.contract_id, reveals_to_send)
                .and_then(move |_| {
                    // Check that the aggregation queue is indeed empty.
                    match agg_queue {
                        AggregationQueueType::Primary => {
                            assert!(inner.agg_reveals.lock().unwrap().is_empty());
                        }
                        AggregationQueueType::Backup => {
                            assert!(inner.agg_backup_reveals.lock().unwrap().is_empty())
                        }
                    }

                    trace!(
                        "Queued aggregated reveals from {:?} queue successfully sent to backend",
                        agg_queue
                    );

                    Ok(())
                })
                .or_else(move |error| {
                    error!(
                        "Aggregated reveals from {:?} queue failed: {}",
                        agg_queue, error.message
                    );

                    // Should we do anything else here?

                    Ok(())
                })
                .into_box()
        } else {
            future::ok(()).into_box()
        }
    }

    /// Check if we need to send the current batch for processing.
    ///
    /// The batch is then sent for processing if either:
    /// * Number of calls it contains reaches `max_batch_size`.
    /// * More than `max_batch_timeout` time elapsed since batch was created.
    /// * No other batch is currently processing.
    fn check_and_process_incoming_queue(inner: Arc<Inner>) -> BoxFuture<()> {
        // We can only process the incoming queue if we are currently waiting for a
        // batch and are a leader.
        require_state_ignore!(inner, State::WaitingForBatch(Role::Leader));

        // Check if we should process.
        let mut incoming_queue = inner.incoming_queue.lock().unwrap();
        let should_process = if let Some(ref incoming_queue) = *incoming_queue {
            incoming_queue.calls.len() >= inner.max_batch_size
                || incoming_queue.start.elapsed() >= inner.max_batch_timeout
        } else {
            false
        };

        if should_process {
            // Note that we can only be a leader here.
            Self::transition(inner.clone(), State::ProcessingBatch(Role::Leader));

            // Take calls from current batch for processing. We only take up to max_batch_size
            // and leave the rest for the next batch, resetting the timestamp.
            let mut calls = incoming_queue.take().unwrap().calls;
            if calls.len() > inner.max_batch_size {
                let mut remaining = calls.split_off(inner.max_batch_size);
                let incoming_queue = incoming_queue.get_or_insert_with(|| IncomingQueue::default());
                incoming_queue.calls.append(&mut remaining);
            }

            // Persist batch into storage so that the workers can get it.
            // TODO: How to handle expiry of these items?
            let inner = inner.clone();
            let inner_clone = inner.clone();
            let encoded_calls = serde_cbor::to_vec(&calls).unwrap();
            let calls_hash = hash_storage_key(&encoded_calls);

            inner
                .storage
                .insert(encoded_calls, u64::max_value())
                .and_then(move |_| {
                    require_state!(
                        inner,
                        State::ProcessingBatch(Role::Leader),
                        "processing batch"
                    );

                    // Submit signed batch hash to the rest of the computation group so they can start work.
                    let committee = inner.computation_group.submit(calls_hash);
                    // Process batch locally.
                    Self::process_batch(inner, calls, committee)
                })
                .or_else(move |error| {
                    Self::fail_batch(
                        inner_clone,
                        format!("Failed to store call batch: {}", error.message),
                    )
                })
                .into_box()
        } else {
            future::ok(()).into_box()
        }
    }

    /// Process given batch locally and propose it when done.
    fn process_batch(
        inner: Arc<Inner>,
        calls: CallBatch,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        require_state!(inner, State::ProcessingBatch(_), "processing batch");

        // Fetch the latest block and request the worker to process the batch.
        let shared_inner = inner.clone();

        inner
            .backend
            .get_latest_block(inner.contract_id)
            .and_then(|block| {
                require_state!(inner, State::ProcessingBatch(_), "processing batch");
                measure_counter_inc!("processing_batch_count");

                // Send block and channel to worker.
                let process_batch = inner.worker.contract_call_batch(calls, block);

                // After the batch is processed, propose the batch.
                process_batch
                    .map_err(|_| Error::new("channel closed"))
                    .and_then(|result| Self::propose_batch(inner, result, committee))
                    .into_box()
            })
            .or_else(|error| {
                // Failed to get latest block, abort current batch.
                Self::fail_batch(
                    shared_inner,
                    format!("Failed to process batch: {}", error.message),
                )
            })
            .into_box()
    }

    /// Fail processing of current batch.
    ///
    /// This method should be called on any failures related to the currently proposed
    /// batch in order to allow new batches to be processed.
    fn fail_batch(inner: Arc<Inner>, reason: String) -> BoxFuture<()> {
        measure_counter_inc!("failed_batch_count");

        error!("{}", reason);

        // TODO: Should we move all failed calls back into the current batch?

        // TODO: Should we notify consensus backend that we aborted?

        // Also discard commits and reveals queued for aggregation.
        inner.agg_commits.lock().unwrap().clear();
        inner.agg_backup_commits.lock().unwrap().clear();
        inner.agg_reveals.lock().unwrap().clear();
        inner.agg_backup_reveals.lock().unwrap().clear();

        // Transition state.
        if let Some(role) = inner.state.lock().unwrap().get_role() {
            Self::transition(inner.clone(), State::WaitingForBatch(role));
        } else {
            Self::transition(inner.clone(), State::NotReady);
        }

        future::ok(()).into_box()
    }

    /// Propose a batch to consensus backend.
    fn propose_batch(
        inner: Arc<Inner>,
        computed_batch: Result<ComputedBatch>,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        let role = require_state!(inner, State::ProcessingBatch(role) => role, "proposing batch");

        // Check result of batch computation.
        let mut computed_batch = match computed_batch {
            Ok(computed_batch) => computed_batch,
            Err(error) => {
                return Self::fail_batch(
                    inner,
                    format!("Failed to compute batch: {}", error.message),
                );
            }
        };

        assert_eq!(computed_batch.calls.len(), computed_batch.outputs.len());

        // Byzantine mode: inject discrepancy into computed batch.
        if inner.test_only_config.inject_discrepancy {
            warn!("BYZANTINE MODE: injecting discrepancy into proposed block");

            for output in computed_batch.outputs.iter_mut() {
                *output = vec![];
            }
        }

        // Encode outputs.
        let encoded_outputs = serde_cbor::to_vec(&computed_batch.outputs).unwrap();

        // Create block from result batches.
        let mut block = Block::new_parent_of(&computed_batch.block);
        block.computation_group = committee;
        block.header.input_hash =
            hash_storage_key(&serde_cbor::to_vec(&computed_batch.calls).unwrap());
        block.header.output_hash = hash_storage_key(&encoded_outputs);
        block.header.state_root = computed_batch.new_state_root;
        block.update();

        info!(
            "Proposing new block with {} transaction(s)",
            computed_batch.calls.len()
        );

        // Generate commitment.
        let nonce = B256::random();
        let commitment = Commitment::new(&inner.signer, &nonce, &block.header);

        Self::transition(inner.clone(), State::ProposedBatch(role, nonce, block));

        // Store outputs and then commit to block.
        let inner_clone = inner.clone();

        inner
            .storage
            .insert(encoded_outputs, u64::max_value())
            .or_else(|error| {
                // Failed to store outputs, abort current batch.
                Self::fail_batch(
                    inner_clone,
                    format!("Failed to store outputs: {}", error.message),
                )
            })
            .and_then(move |_| {
                let role = require_state!(inner, State::ProposedBatch(role, ..) => role, "proposing batch");

                measure_counter_inc!("proposed_batch_count");

                if role == Role::Leader {
                    trace!(
                        "In propose_batch, appending aggregate commit on leader node (fast path)"
                    );

                    // Leader can just append to its own aggregate commits queue.
                    Self::handle_agg_commit(inner.clone(), commitment, role)
                } else {
                    trace!("In propose_batch, submitting aggregate commit to leader");

                    // Submit the commit to leader for aggregation.
                    inner.computation_group.submit_agg_commit(commitment);

                    future::ok(()).into_box()
                }
            })
            .into_box()
    }

    /// Append contract calls to current batch for eventual processing.
    pub fn append_batch(&self, calls: CallBatch) {
        self.inner
            .command_sender
            .unbounded_send(Command::AppendBatch(calls))
            .unwrap();
    }

    /// Directly process a batch from a remote leader.
    pub fn process_remote_batch(&self, batch_hash: Signed<H256>) -> Result<()> {
        // Open signed batch, verifying that it was signed by the leader and that the
        // committee matches.
        let (batch_hash, committee) = self.inner.computation_group.open_remote_batch(batch_hash)?;

        self.inner
            .command_sender
            .unbounded_send(Command::ProcessRemoteBatch(batch_hash, committee))
            .unwrap();

        Ok(())
    }

    /// Process a commit for aggregation.
    pub fn process_agg_commit(&self, signed_commit: Signed<Commitment>) -> Result<()> {
        // Open the signed commit, verifying that it was signed by a
        // worker and that the leader matches.
        let (commit, role) = self.inner.computation_group.open_agg_commit(signed_commit)?;

        self.inner
            .command_sender
            .unbounded_send(Command::ProcessAggCommit(commit, role))
            .unwrap();

        Ok(())
    }

    /// Process a reveal for aggregation.
    pub fn process_agg_reveal(&self, signed_reveal: Signed<Reveal<Header>>) -> Result<()> {
        // Open the signed reveal, verifying that it was signed by a
        // worker and that the leader matches.
        let (reveal, role) = self.inner.computation_group.open_agg_reveal(signed_reveal)?;

        self.inner
            .command_sender
            .unbounded_send(Command::ProcessAggReveal(reveal, role))
            .unwrap();

        Ok(())
    }

    /// Subscribe to being notified when specific call is included in a block.
    pub fn subscribe_call(&self, call_id: H256) -> oneshot::Receiver<Vec<u8>> {
        let (response_sender, response_receiver) = oneshot::channel();
        if self.inner.computation_group.is_leader() {
            let mut call_subscribers = self.inner.call_subscribers.lock().unwrap();
            match call_subscribers.entry(call_id) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(response_sender);
                }
                Entry::Vacant(entry) => {
                    entry.insert(vec![response_sender]);
                }
            }
        } else {
            // If we are not a leader, do not accept subscribers.
            warn!("Denying subscribe_call as we are not the leader");
            drop(response_sender);
        }

        response_receiver
    }
}
