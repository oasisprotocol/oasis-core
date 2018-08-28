//! Root hash frontend.
use std::collections::VecDeque;
use std::fmt;
#[cfg(feature = "testing")]
use std::process::abort;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_cbor;

use ekiden_core::bytes::{B256, H256};
use ekiden_core::contract::batch::CallBatch;
use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::streamfollow;
use ekiden_core::futures::sync::mpsc;
use ekiden_core::tokio::timer::Interval;
use ekiden_core::uint::U256;
use ekiden_roothash_base::{Block, Event, RootHashBackend, RootHashSigner};
use ekiden_scheduler_base::{CommitteeNode, Role};
use ekiden_storage_base::{hash_storage_key, BatchStorage};

use super::group::ComputationGroup;
use super::worker::{ComputedBatch, Worker};

/// Commands for communicating with the root hash frontend from other tasks.
enum Command {
    /// Process remote batch.
    ProcessRemoteBatch(H256, Vec<CommitteeNode>),
    /// Process incoming queue.
    ProcessIncomingQueue,
    /// Process root hash block.
    ProcessBlock(Block),
    /// Process root hash backend event.
    ProcessEvent(Event),
    /// Update local role.
    UpdateRole(Option<Role>),
}

/// State of the root hash frontend.
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
    /// * `BackupWorker`: We are waiting for a new remote batch from the root hash backend.
    WaitingForBatch(Role),
    /// A batch has been dispatched to the worker for processing.
    ProcessingBatch(Role, Arc<CallBatch>),
    /// We have committed to a specific batch in the current root hash round and are
    /// waiting for the root hash backend to finalize the block.
    WaitingForFinalize(Role, Arc<CallBatch>, Block),
    /// Computation group has changed.
    ComputationGroupChanged(Option<Role>, Option<Arc<CallBatch>>),
}

impl State {
    /// Return current role based on state.
    pub fn get_role(&self) -> Option<Role> {
        match *self {
            State::WaitingForBatch(role) => Some(role),
            State::ProcessingBatch(role, ..) => Some(role),
            State::WaitingForFinalize(role, ..) => Some(role),
            State::ComputationGroupChanged(role, ..) => role,
            _ => None,
        }
    }

    /// Return current batch based on state.
    pub fn get_batch(&self) -> Option<Arc<CallBatch>> {
        match *self {
            State::ProcessingBatch(_, ref batch) => Some(batch.clone()),
            State::WaitingForFinalize(_, ref batch, ..) => Some(batch.clone()),
            State::ComputationGroupChanged(_, ref maybe_batch) => maybe_batch.as_ref().cloned(),
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

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                State::NotReady => "NotReady".into(),
                State::WaitingForBatch(role, ..) => format!("WaitingForBatch({:?})", role),
                State::ProcessingBatch(role, ..) => format!("ProcessingBatch({:?})", role),
                State::WaitingForFinalize(role, ..) => format!("WaitingForFinalize({:?})", role),
                State::ComputationGroupChanged(Some(role), ..) => {
                    format!("ComputationGroupChanged({:?})", role)
                }
                State::ComputationGroupChanged(None, ..) => "ComputationGroupChanged(None)".into(),
            }
        )
    }
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an error future is
/// returned.
macro_rules! require_state {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*, $message:expr) => {
        require_state_impl!(@failed_future, $inner, $( $state )|* $(if $cond)*, $message)
    };

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr, $message:expr) => {
       require_state_impl!(@failed_future, $inner, $( $state )|* $(if $cond)* => $output, $message)
    };
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an error result is
/// returned.
macro_rules! require_state_result {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*, $message:expr) => {
        require_state_impl!(@failed_result, $inner, $( $state )|* $(if $cond)*, $message)
    };

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr, $message:expr) => {
       require_state_impl!(@failed_result, $inner, $( $state )|* $(if $cond)* => $output, $message)
    };
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an ok future is
/// returned.
macro_rules! require_state_ignore {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*) => {
        require_state_impl!(@ignore_future, $inner, $( $state )|* $(if $cond)*, "")
    };

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr, $message:expr) => {
       require_state_impl!(@ignore_future, $inner, $( $state )|* $(if $cond)* => $output, "")
    };
}

macro_rules! require_state_impl {
    (@failed_future $error:expr) => {
        return future::err($error).into_box()
    };

    (@failed_result $error:expr) => {
        return Err($error)
    };

    (@ignore_future $error:expr) => {
        return future::ok(()).into_box()
    };

    (@ignore_result $error:expr) => {
        return Ok(())
    };

    (
        @$failed_handler:ident,
        $inner:ident,
        $( $state:pat )|* $(if $cond:expr)*,
        $message:expr
    ) => {{
        let state = $inner.state.lock().unwrap();
        #[allow(unused_variables)]
        match state.clone() {
            $( $state )|* $(if $cond)* => {}
            state => {
                require_state_impl!(@$failed_handler Error::new(format!(
                    "incorrect state for {}: {}",
                    $message, state
                )))
            }
        }
    }};

    (
        @$failed_handler:ident,
        $inner:ident,
        $( $state:pat )|* $(if $cond:expr)* => $output:expr,
        $message:expr
    ) => {{
        let state = $inner.state.lock().unwrap();
        #[allow(unused_variables)]
        match state.clone() {
            $( $state )|* $(if $cond)* => $output,
            state => {
                require_state_impl!(@$failed_handler Error::new(format!(
                    "incorrect state for {}: {}",
                    $message, state
                )))
            }
        }
    }};
}

/// Queue of incoming contract calls which are pending to be included in a batch.
struct IncomingQueue {
    /// Instant when first item was queued.
    start: Instant,
    /// Queued contract calls.
    calls: VecDeque<Vec<u8>>,
}

impl Default for IncomingQueue {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            calls: VecDeque::new(),
        }
    }
}

struct Inner {
    /// Current state of the root hash frontend.
    state: Mutex<State>,
    /// Contract identifier this root hash frontend is for.
    contract_id: B256,
    /// Environment.
    environment: Arc<Environment>,
    /// Consensus backend.
    backend: Arc<RootHashBackend>,
    /// Consensus signer.
    signer: Arc<RootHashSigner>,
    /// Storage backend.
    storage: Arc<BatchStorage>,
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
    /// Test-only configuration.
    test_only_config: RootHashTestOnlyConfiguration,
    /// Notify incoming queue.
    incoming_queue_notified: AtomicBool,
}

/// Root hash frontend test-only configuration.
#[derive(Clone)]
pub struct RootHashTestOnlyConfiguration {
    /// Inject discrepancy when submitting commitment.
    pub inject_discrepancy: bool,
    /// Fail after commit.
    pub fail_after_commit: bool,
}

/// Root hash frontend configuration.
#[derive(Clone)]
pub struct RootHashConfiguration {
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Maximum batch timeout.
    pub max_batch_timeout: u64,
    /// Test-only configuration.
    pub test_only: RootHashTestOnlyConfiguration,
}

/// Compute node root hash frontend.
pub struct RootHashFrontend {
    inner: Arc<Inner>,
}

impl RootHashFrontend {
    /// Create a new root hash frontend.
    pub fn new(
        config: RootHashConfiguration,
        contract_id: B256,
        environment: Arc<Environment>,
        worker: Arc<Worker>,
        computation_group: Arc<ComputationGroup>,
        backend: Arc<RootHashBackend>,
        signer: Arc<RootHashSigner>,
        storage: Arc<BatchStorage>,
    ) -> Self {
        measure_configure!(
            "batch_insert_size",
            "Size of values inserted into storage for saving a batch of contract calls.",
            MetricConfig::Histogram {
                buckets: vec![0., 1., 4., 16., 64., 256., 1024., 4096., 16384.],
            }
        );
        measure_configure!(
            "outputs_insert_size",
            "Size of values inserted into storage for saving a batch of contract outputs.",
            MetricConfig::Histogram {
                buckets: vec![0., 1., 4., 16., 64., 256., 1024., 4096., 16384.],
            }
        );

        let (command_sender, command_receiver) = mpsc::unbounded();

        let instance = Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::NotReady),
                contract_id,
                environment,
                backend,
                signer,
                storage,
                worker,
                computation_group,
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                incoming_queue: Mutex::new(None),
                max_batch_size: config.max_batch_size,
                max_batch_timeout: Duration::from_millis(config.max_batch_timeout),
                test_only_config: config.test_only.clone(),
                incoming_queue_notified: AtomicBool::new(false),
            }),
        };
        instance.start();

        instance
    }

    /// Start root hash frontend.
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

        // Subscribe to root hash events.
        let backend_init = self.inner.backend.clone();
        let contract_id = self.inner.contract_id.clone();

        event_sources.push(
            streamfollow::follow_skip(
                move || backend_init.get_events(contract_id),
                |event: &Event| event.clone(),
                |_err| false,
            ).map(|event| Command::ProcessEvent(event))
                .into_box(),
        );

        // Subscribe to root hash blocks.
        let backend_init = self.inner.backend.clone();
        let backend_resume = self.inner.backend.clone();
        let contract_id = self.inner.contract_id.clone();

        event_sources.push(
            streamfollow::follow(
                move || backend_init.get_blocks(contract_id),
                move |round: &U256| backend_resume.get_blocks_since(contract_id, round.clone()),
                |block: &Block| block.header.round,
                |_err| false,
            ).map(|block: Block| Command::ProcessBlock(block))
                .into_box(),
        );

        // Periodically check for batches.
        event_sources.push(
            Interval::new(Instant::now(), self.inner.max_batch_timeout)
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

        // Process commands.
        self.inner.environment.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing commands",
                move |command| match command {
                    Command::ProcessRemoteBatch(batch_hash, committee) => {
                        Self::handle_remote_batch(inner.clone(), batch_hash, committee)
                    }
                    Command::ProcessIncomingQueue => {
                        Self::check_and_process_incoming_queue(inner.clone())
                    }
                    Command::ProcessBlock(block) => Self::handle_block(inner.clone(), block),
                    Command::ProcessEvent(Event::RoundFailed(error)) => {
                        Self::fail_batch(inner.clone(), format!("round failed: {}", error.message))
                    }
                    Command::ProcessEvent(Event::DiscrepancyDetected(batch_hash)) => {
                        Self::handle_discrepancy_detected(inner.clone(), batch_hash)
                    }
                    Command::UpdateRole(role) => Self::handle_update_role(inner.clone(), role),
                },
            )
        });
    }

    /// Transition the root hash frontend to a new state.
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
            (&State::WaitingForBatch(role_a, ..), &State::ProcessingBatch(role_b, ..))
                if role_a == role_b => {}
            (&State::WaitingForBatch(role_a, ..), &State::WaitingForBatch(role_b, ..))
                if role_a != role_b => {}

            // Transitions from the ProcessingBatch state. We can either transition to submitting
            // a commit and waiting for round finalization in the same role, abort the current
            // batch and return to waiting for a batch in the same role or switch roles in case
            // the committee changes.
            (&State::ProcessingBatch(role_a, ..), &State::WaitingForFinalize(role_b, ..))
                if role_a == role_b => {}
            (&State::ProcessingBatch(..), &State::WaitingForBatch(_)) => {}

            // Transitions from WaitingForFinalize state. We can transition to waiting for new
            // batches in either the current role or switch roles in case the committee changes.
            (&State::WaitingForFinalize(..), &State::WaitingForBatch(_)) => {}

            // Compute committee can change in any state.
            (_, &State::ComputationGroupChanged(..)) => {}
            (
                &State::ComputationGroupChanged(Some(role_a), ..),
                &State::WaitingForBatch(role_b),
            ) if role_a == role_b => {}
            (&State::ComputationGroupChanged(None, ..), &State::NotReady) => {}

            transition => panic!(
                "illegal root hash frontend state transition: {:?}",
                transition
            ),
        }

        trace!("Root hash frontend transitioning to {}", to);
        *state = to;
    }

    /// Handle update role command.
    fn handle_update_role(inner: Arc<Inner>, role: Option<Role>) -> BoxFuture<()> {
        let mut maybe_batch = inner.state.lock().unwrap().get_batch();

        // If we are not a leader, clear the incoming call queue to avoid processing
        // calls which the new leader should process.
        if role != Some(Role::Leader) {
            inner.incoming_queue.lock().unwrap().take();
            maybe_batch = None;
        }

        Self::transition(
            inner.clone(),
            State::ComputationGroupChanged(role, maybe_batch),
        );

        // Fail current batch (if any).
        Self::fail_batch(inner.clone(), "computation group has changed".to_string())
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
            .and_then(move |batch| {
                require_state!(
                    inner,
                    State::WaitingForBatch(current_role) if current_role == role,
                    "handling remote batch"
                );

                let batch = match serde_cbor::from_slice(&batch) {
                    Ok(batch) => Arc::new(batch),
                    Err(error) => return future::err(Error::from(error)).into_box(),
                };

                Self::transition(inner.clone(), State::ProcessingBatch(role, batch));

                Self::process_batch(inner.clone(), committee)
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

    /// Handle discrepancy detected event from root hash backend.
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

    /// Handle new block from root hash backend.
    fn handle_block(inner: Arc<Inner>, block: Block) -> BoxFuture<()> {
        info!(
            "Received new block at round {:?} from root hash backend",
            block.header.round
        );

        // Check if this is a block for the same round that we proposed.
        let should_transition = {
            let state = inner.state.lock().unwrap();
            match &*state {
                &State::WaitingForFinalize(role, _, ref proposed_block) => {
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

            // Since the round is finalized, we start processing a new batch immediately.
            inner
                .command_sender
                .unbounded_send(Command::ProcessIncomingQueue)
                .unwrap();
        }

        future::ok(()).into_box()
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

        // Clear incoming queue notified flag to allow new notifies from appends.
        inner.incoming_queue_notified.store(false, Ordering::SeqCst);

        // Check if we should process.
        let mut incoming_queue = inner.incoming_queue.lock().unwrap();
        let should_process = if let Some(ref incoming_queue) = *incoming_queue {
            incoming_queue.calls.len() >= inner.max_batch_size
                || incoming_queue.start.elapsed() >= inner.max_batch_timeout
        } else {
            false
        };

        if should_process {
            // Take calls from incoming queue for processing. We only take up to max_batch_size
            // and leave the rest for the next batch, resetting the timestamp.
            let mut batch = incoming_queue.take().unwrap().calls;
            if batch.len() > inner.max_batch_size {
                let mut remaining = batch.split_off(inner.max_batch_size);
                let incoming_queue = incoming_queue.get_or_insert_with(|| IncomingQueue::default());
                incoming_queue.calls.append(&mut remaining);
            }

            // Persist batch into storage so that the workers can get it.
            // Save it for one epoch so that the current committee can access it.
            let inner = inner.clone();
            let inner_clone = inner.clone();
            let encoded_batch = serde_cbor::to_vec(&batch).unwrap();
            let batch_hash = hash_storage_key(&encoded_batch);

            // Note that we can only be a leader here.
            Self::transition(
                inner.clone(),
                State::ProcessingBatch(Role::Leader, Arc::new(batch.into())),
            );

            inner.storage.start_batch();
            measure_histogram!("batch_insert_size", encoded_batch.len());
            inner
                .storage
                .insert(encoded_batch, 1)
                .join(inner.storage.end_batch())
                .and_then(move |_| {
                    require_state!(
                        inner,
                        State::ProcessingBatch(Role::Leader, _),
                        "processing batch"
                    );

                    // Submit signed batch hash to the rest of the computation group so they can start work.
                    let committee = inner.computation_group.submit(batch_hash);
                    // Process batch locally.
                    Self::process_batch(inner, committee)
                })
                .or_else(move |error| {
                    Self::fail_batch(
                        inner_clone,
                        format!("failed to store call batch: {}", error.message),
                    )
                })
                .into_box()
        } else {
            future::ok(()).into_box()
        }
    }

    /// Process given batch locally and propose it when done.
    fn process_batch(inner: Arc<Inner>, committee: Vec<CommitteeNode>) -> BoxFuture<()> {
        require_state!(inner, State::ProcessingBatch(..), "processing batch");

        // Fetch the latest block and request the worker to process the batch.
        let shared_inner = inner.clone();

        inner
            .backend
            .get_latest_block(inner.contract_id)
            .and_then(|block| {
                let batch = require_state!(inner, State::ProcessingBatch(_, batch) => batch, "processing batch");
                measure_counter_inc!("processing_batch_count");

                // Send block and channel to worker.
                let process_batch = inner.worker.contract_call_batch((*batch).clone(), block);

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
                    format!("failed to process batch: {}", error.message),
                )
            })
            .into_box()
    }

    /// Fail processing of current batch.
    ///
    /// This method should be called on any failures related to the currently proposed
    /// batch in order to allow new batches to be processed.
    fn fail_batch(inner: Arc<Inner>, reason: String) -> BoxFuture<()> {
        let new_state = {
            let state = inner.state.lock().unwrap();

            // Move failed calls back into the current batch.
            if let Some(batch) = state.get_batch() {
                measure_counter_inc!("failed_batch_count");
                error!("Aborting current batch ({} calls): {}", batch.len(), reason);

                // Move back to incoming queue.
                let mut incoming_queue = inner.incoming_queue.lock().unwrap();
                let incoming_queue = incoming_queue.get_or_insert_with(|| IncomingQueue::default());
                for item in batch.iter().rev() {
                    incoming_queue.calls.push_front(item.clone());
                }

                measure_gauge!("incoming_queue_size", incoming_queue.calls.len());
            }

            // Determine new state.
            if let Some(role) = state.get_role() {
                State::WaitingForBatch(role)
            } else {
                State::NotReady
            }
        };

        // TODO: Should we notify root hash backend that we aborted?

        // Transition state.
        Self::transition(inner.clone(), new_state);

        future::ok(()).into_box()
    }

    /// Propose a batch to root hash backend.
    fn propose_batch(
        inner: Arc<Inner>,
        computed_batch: Result<ComputedBatch>,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        let (role, batch) = require_state!(inner, State::ProcessingBatch(role, batch) => (role, batch), "proposing batch");

        // Check result of batch computation.
        let mut computed_batch = match computed_batch {
            Ok(computed_batch) => computed_batch,
            Err(error) => {
                return Self::fail_batch(
                    inner,
                    format!("failed to compute batch: {}", error.message),
                );
            }
        };

        assert_eq!(computed_batch.calls.len(), computed_batch.outputs.len());

        // Byzantine mode: inject discrepancy into computed batch.
        #[cfg(feature = "testing")]
        {
            if inner.test_only_config.inject_discrepancy {
                warn!("BYZANTINE MODE: injecting discrepancy into proposed block");

                for output in computed_batch.outputs.iter_mut() {
                    *output = vec![];
                }
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
        let commitment = match inner.signer.sign_commitment(&block.header) {
            Ok(result) => result,
            Err(error) => {
                return Self::fail_batch(
                    inner,
                    format!("error while signing commitment: {}", error.message),
                );
            }
        };

        Self::transition(inner.clone(), State::WaitingForFinalize(role, batch, block));

        // Store outputs and then commit to block.
        let inner_clone = inner.clone();

        inner.storage.start_batch();
        measure_histogram!("outputs_insert_size", encoded_outputs.len());
        inner
            .storage
            .insert(encoded_outputs, 2)
            .join(inner.storage.end_batch())
            .and_then(|((), ())| Ok(()))
            .or_else(|error| {
                // Failed to store outputs, abort current batch.
                Self::fail_batch(
                    inner_clone,
                    format!("failed to store outputs: {}", error.message),
                )
            })
            .and_then(move |_| {
                require_state!(inner, State::WaitingForFinalize(..), "proposing batch");

                measure_counter_inc!("proposed_batch_count");

                let shared_inner = inner.clone();

                inner
                    .backend
                    .commit(inner.contract_id, commitment)
                    .and_then(move |result| {
                        // Test mode: crash after commit.
                        #[cfg(feature = "testing")]
                        {
                            if inner.test_only_config.fail_after_commit {
                                error!("TEST MODE: crashing after commit");
                                abort();
                            }
                        }

                        Ok(result)
                    })
                    .or_else(|error| {
                        // Failed to commit a block, abort current batch.
                        Self::fail_batch(
                            shared_inner,
                            format!("Failed to propose block: {}", error.message),
                        )
                    })
                    .into_box()
            })
            .into_box()
    }

    /// Append contract calls to current batch for eventual processing.
    pub fn append_batch(&self, calls: CallBatch) -> Result<()> {
        // Ignore empty batches.
        if calls.is_empty() {
            return Ok(());
        }

        // If we are not a leader, do not append to batch.
        {
            let state = self.inner.state.lock().unwrap();
            if !state.is_leader() {
                warn!("Ignoring append to batch as we are not the computation group leader");
                return Err(Error::new("not computation group leader"));
            }
        }

        // Append to batch.
        {
            let mut incoming_queue = self.inner.incoming_queue.lock().unwrap();
            let incoming_queue = incoming_queue.get_or_insert_with(|| IncomingQueue::default());
            incoming_queue.calls.append(&mut calls.into());

            measure_gauge!("incoming_queue_size", incoming_queue.calls.len());
        }

        // Only submit incoming queue notification if we haven't already submitted one.
        if !self.inner
            .incoming_queue_notified
            .swap(true, Ordering::SeqCst)
        {
            self.inner
                .command_sender
                .unbounded_send(Command::ProcessIncomingQueue)
                .unwrap();
        }

        Ok(())
    }

    /// Directly process a batch from a remote leader.
    pub fn process_remote_batch(&self, node_id: B256, batch_hash: H256) -> Result<()> {
        let inner = &self.inner;

        // Check that batch comes from current committee leader.
        let committee = inner.computation_group.check_remote_batch(node_id)?;

        require_state_result!(
            inner,
            State::WaitingForBatch(Role::Worker) | State::WaitingForBatch(Role::BackupWorker),
            "requesting to process remote batch"
        );

        inner
            .command_sender
            .unbounded_send(Command::ProcessRemoteBatch(batch_hash, committee))
            .unwrap();

        Ok(())
    }
}
