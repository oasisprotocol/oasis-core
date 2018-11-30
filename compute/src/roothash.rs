//! Root hash frontend.
use std::collections::{HashSet, VecDeque};
use std::fmt;
#[cfg(feature = "testing")]
use std::process::abort;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustracing::tag;
use rustracing_jaeger::span::SpanContext;
use rustracing_jaeger::span::SpanHandle;
use rustracing_jaeger::Span;
use serde_cbor;

use ekiden_core::bytes::{B256, H256};
use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::streamfollow;
use ekiden_core::futures::sync::mpsc;
use ekiden_core::hash::{self, EncodedHash};
use ekiden_core::runtime::batch::CallBatch;
use ekiden_core::tokio::timer::Interval;
use ekiden_core::uint::U256;
use ekiden_roothash_base::{Block, Event, Header, HeaderType, RootHashBackend, RootHashSigner};
use ekiden_scheduler_base::{CommitteeNode, Role};
use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};
use ekiden_tracing;
use ekiden_worker_api::types::ComputedBatch;

use super::group::{ComputationGroup, GroupRole};
use super::worker::WorkerHost;

/// Error message for trying to append when not computation group leader.
pub const ERROR_APPEND_NOT_LEADER: &'static str = "not computation group leader";
/// Error message for trying to append a too large call.
pub const ERROR_APPEND_TOO_LARGE: &'static str = "call too large";

/// Commands for communicating with the root hash frontend from other tasks.
enum Command {
    /// Process remote batch.
    ProcessRemoteBatch(H256, Header, Vec<CommitteeNode>),
    /// Process incoming queue.
    ProcessIncomingQueue,
    /// Process root hash block.
    ProcessBlock(Block),
    /// Process root hash backend event.
    ProcessEvent(Event),
    /// Update local role.
    UpdateRole(GroupRole),
}

/// State of the root hash frontend.
///
/// See the `transition` method for valid state transitions.
#[derive(Clone, Debug, PartialEq)]
enum State {
    /// We are waiting for the scheduler to include us in a computation group.
    NotReady,
    /// Based on our role:
    /// * `Leader`: We are waiting for enough calls to be queued in `incoming_queue` so
    ///   that we can start processing them.
    /// * `Worker`: We are waiting for a new remote batch from leader.
    /// * `BackupWorker`: We are waiting for a new remote batch from the root hash backend.
    WaitingForBatch(GroupRole),
    /// Based on our role:
    /// * `Worker`: We are waiting to see a specific block, specified by the leader.
    /// * `BackupWorker`: We are waiting to see a specific block, specified by the root hash
    ///   backend.
    WaitingForBlock(GroupRole, Arc<CallBatch>, Header),
    /// We are waiting for a scheduler update.
    WaitingForGroup(H256),
    /// A batch has been dispatched to the worker for processing.
    ProcessingBatch(GroupRole, Arc<CallBatch>, Block),
    /// We have committed to a specific batch in the current root hash round and are
    /// waiting for the root hash backend to finalize the block.
    WaitingForFinalize(GroupRole, Arc<CallBatch>, Block),
    /// We have locally aborted and are waiting for the root hash backend to finalize
    /// the round.
    LocallyAborted(GroupRole),
}

impl State {
    /// Return current role based on state.
    pub fn get_role(&self) -> Option<GroupRole> {
        match *self {
            State::WaitingForBatch(ref role) => Some(role.clone()),
            State::WaitingForBlock(ref role, ..) => Some(role.clone()),
            State::ProcessingBatch(ref role, ..) => Some(role.clone()),
            State::WaitingForFinalize(ref role, ..) => Some(role.clone()),
            State::LocallyAborted(ref role) => Some(role.clone()),
            _ => None,
        }
    }

    /// Return current batch based on state.
    pub fn get_batch(&self) -> Option<Arc<CallBatch>> {
        match *self {
            State::WaitingForBlock(_, ref batch, ..) => Some(batch.clone()),
            State::ProcessingBatch(_, ref batch, _) => Some(batch.clone()),
            State::WaitingForFinalize(_, ref batch, ..) => Some(batch.clone()),
            _ => None,
        }
    }

    /// Return true if we are currently a leader.
    pub fn is_leader(&self) -> bool {
        match self.get_role() {
            Some(ref role) => match role.role {
                Some(role) if role == Role::Leader => true,
                _ => false,
            },
            _ => false,
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
                State::WaitingForBatch(ref role, ..) => format!("WaitingForBatch({})", role),
                State::WaitingForBlock(ref role, ..) => format!("WaitingForBlock({})", role),
                State::WaitingForGroup(group) => format!("WaitingForGroup({})", group),
                State::ProcessingBatch(ref role, ..) => format!("ProcessingBatch({})", role),
                State::WaitingForFinalize(ref role, ..) => format!("WaitingForFinalize({})", role),
                State::LocallyAborted(ref role) => format!("LocallyAborted({})", role),
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

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr) => {
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

/// A call plus bookkeeping for tracing correlation.
struct CallInfo {
    data: Vec<u8>,
    /// Correlation for when the call is first enqueued, or None if it was enqueued before and
    /// has returned.
    context: Option<SpanContext>,
}

/// Queue of incoming runtime calls which are pending to be included in a batch.
struct IncomingQueue {
    /// Instant when first item was queued.
    start: Instant,
    /// Queued runtime calls.
    calls: VecDeque<CallInfo>,
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
    /// Runtime identifier this root hash frontend is for.
    runtime_id: B256,
    /// Environment.
    environment: Arc<Environment>,
    /// Consensus backend.
    backend: Arc<RootHashBackend>,
    /// Consensus signer.
    signer: Arc<RootHashSigner>,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Worker that can process batches.
    worker: Arc<WorkerHost>,
    /// Computation group that can process batches.
    computation_group: Arc<ComputationGroup>,
    /// The most recent block as reported by the root hash backend.
    latest_block: Mutex<Option<Block>>,
    /// Role that will take effect at the next epoch transition block.
    pending_role: Mutex<Option<GroupRole>>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Queue of incoming runtime calls which are pending to be included in a batch.
    incoming_queue: Mutex<Option<IncomingQueue>>,
    /// Maximum batch size.
    max_batch_size: usize,
    /// Maximum batch size in bytes.
    max_batch_size_bytes: usize,
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
    /// Skip sending a commit until a given round.
    pub skip_commit_until_round: u64,
}

/// Root hash frontend configuration.
#[derive(Clone)]
pub struct RootHashConfiguration {
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Maximum batch size in bytes.
    pub max_batch_size_bytes: usize,
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
        runtime_id: B256,
        environment: Arc<Environment>,
        worker: Arc<WorkerHost>,
        computation_group: Arc<ComputationGroup>,
        backend: Arc<RootHashBackend>,
        signer: Arc<RootHashSigner>,
        storage: Arc<StorageBackend>,
    ) -> Self {
        measure_configure!(
            "batch_insert_size",
            "Size of values inserted into storage for saving a batch of runtime calls.",
            MetricConfig::Histogram {
                buckets: vec![
                    1024., 4096., 16384., 65536., 262144., 1048576., 4194304., 16777216., 67108864.,
                ],
            }
        );
        measure_configure!(
            "outputs_insert_size",
            "Size of values inserted into storage for saving a batch of runtime outputs.",
            MetricConfig::Histogram {
                buckets: vec![0., 1., 4., 16., 64., 256., 1024., 4096., 16384.],
            }
        );

        let (command_sender, command_receiver) = mpsc::unbounded();

        let instance = Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::NotReady),
                runtime_id,
                environment,
                backend,
                signer,
                storage,
                worker,
                computation_group,
                latest_block: Mutex::new(None),
                pending_role: Mutex::new(None),
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                incoming_queue: Mutex::new(None),
                max_batch_size: config.max_batch_size,
                max_batch_size_bytes: config.max_batch_size_bytes,
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
        let runtime_id = self.inner.runtime_id.clone();

        event_sources.push(
            streamfollow::follow_skip(
                "RootHashFrontend events",
                move || backend_init.get_events(runtime_id),
                |event: &Event| event.clone(),
                |_err| false,
            ).map(|event| Command::ProcessEvent(event))
                .into_box(),
        );

        // Subscribe to root hash blocks.
        let backend_init = self.inner.backend.clone();
        let backend_resume = self.inner.backend.clone();
        let runtime_id = self.inner.runtime_id.clone();

        event_sources.push(
            streamfollow::follow(
                "RootHashFrontend blocks",
                move || backend_init.get_blocks(runtime_id),
                move |round: &U256| backend_resume.get_blocks_since(runtime_id, round.clone()),
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
                    Command::ProcessRemoteBatch(batch_hash, header, committee) => {
                        Self::handle_remote_batch(inner.clone(), batch_hash, header, committee)
                    }
                    Command::ProcessIncomingQueue => {
                        Self::check_and_process_incoming_queue(inner.clone())
                    }
                    Command::ProcessBlock(block) => Self::handle_block(inner.clone(), block),
                    Command::ProcessEvent(Event::DiscrepancyDetected(batch_hash, header)) => {
                        Self::handle_discrepancy_detected(inner.clone(), batch_hash, header)
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
            // Transitions from NotReady state.
            (&State::NotReady, &State::WaitingForBatch(..)) => {}
            (&State::NotReady, &State::WaitingForGroup(_)) => {}
            (&State::NotReady, &State::NotReady) => {}

            // Transitions from WaitingForBatch state. We either transition to batch processing
            // processing in the same role.
            (&State::WaitingForBatch(ref role_a), &State::ProcessingBatch(ref role_b, ..))
                if role_a == role_b => {}
            (&State::WaitingForBatch(ref role_a), &State::WaitingForBlock(ref role_b, ..))
                if role_a == role_b => {}
            (&State::WaitingForBatch(ref role_a, ..), &State::LocallyAborted(ref role_b))
                if role_a == role_b => {}

            // Transitions from WaitingForBlock state.
            (&State::WaitingForBlock(ref role_a, ..), &State::ProcessingBatch(ref role_b, ..))
                if role_a == role_b => {}
            (&State::WaitingForBlock(ref role_a, ..), &State::LocallyAborted(ref role_b, ..))
                if role_a == role_b => {}

            // Transitions from the ProcessingBatch state. We can either transition to submitting
            // a commit and waiting for round finalization in the same role or abort the current
            // batch.
            (
                &State::ProcessingBatch(ref role_a, ..),
                &State::WaitingForFinalize(ref role_b, ..),
            ) if role_a == role_b => {}
            (&State::ProcessingBatch(ref role_a, ..), &State::LocallyAborted(ref role_b))
                if role_a == role_b => {}

            // Transitions from WaitingForFinalize state. We can transition to waiting for new
            // batches in the current role or abort the current batch.
            (&State::WaitingForFinalize(ref role_a, ..), &State::WaitingForBatch(ref role_b))
                if role_a == role_b => {}
            (&State::WaitingForFinalize(ref role_a, ..), &State::LocallyAborted(ref role_b))
                if role_a == role_b => {}

            // Transitions from WaitingForGroup state.
            (&State::WaitingForGroup(_), &State::WaitingForBatch(_)) => {}
            (&State::WaitingForGroup(_), &State::NotReady) => {}

            // Transitions from LocallyAborted state.
            (&State::LocallyAborted(_), &State::WaitingForBatch(_)) => {}
            (&State::LocallyAborted(_), &State::NotReady) => {}
            (&State::LocallyAborted(_), &State::WaitingForGroup(_)) => {}
            (&State::LocallyAborted(ref role_a), &State::LocallyAborted(ref role_b))
                if role_a == role_b => {}

            (from, to) => panic!(
                "illegal root hash frontend state transition: {} -> {}",
                from, to,
            ),
        }

        trace!("Root hash frontend transitioning {} -> {}", state, to);
        *state = to;
    }

    /// Handle update role command.
    fn handle_update_role(inner: Arc<Inner>, role: GroupRole) -> BoxFuture<()> {
        // If we are currently in the WaitingForGroup state, check if this is the group
        // that we were waiting for. Otherwise there is nothing to do here.
        let state = inner.state.lock().unwrap().clone();
        match state {
            State::WaitingForGroup(hash) if hash == role.committee.get_encoded_hash() => {
                // This is the group we are waiting for.
                Self::transition_role(inner.clone(), role);
            }
            _ => {
                // Not waiting for a group or not waiting for this group.
                let mut pending_role = inner.pending_role.lock().unwrap();
                *pending_role = Some(role);
            }
        }

        future::ok(()).into_box()
    }

    /// Perform transition into new role.
    fn transition_role(inner: Arc<Inner>, role: GroupRole) {
        // If we are not a leader, clear the incoming call queue to avoid processing
        // calls which the new leader should process.
        if let Some(Role::Leader) = role.role {
            inner.incoming_queue.lock().unwrap().take();
            measure_gauge!("incoming_queue_size", 0);
        } else {
            measure_gauge!(
                "incoming_queue_size",
                inner
                    .incoming_queue
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|queue| queue.calls.len())
                    .unwrap_or(0)
            );
        }

        if role.role.is_some() {
            Self::transition(inner, State::WaitingForBatch(role));
        } else {
            Self::transition(inner, State::NotReady);
        }
    }

    /// Handle process remote batch command.
    fn handle_remote_batch(
        inner: Arc<Inner>,
        batch_hash: H256,
        block_header: Header,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        let role = require_state!(
            inner,
            State::WaitingForBatch(ref role @ GroupRole{ role: Some(Role::Worker), .. }) |
            State::WaitingForBatch(ref role @ GroupRole{ role: Some(Role::BackupWorker), .. })
            if role.committee == committee => role.clone(),
            "handling remote batch"
        );

        // Fetch batch from storage.
        inner
            .storage
            .get(batch_hash)
            .and_then(move |batch| {
                require_state!(
                    inner,
                    State::WaitingForBatch(ref current_role) if current_role == &role,
                    "handling remote batch"
                );

                let batch = match serde_cbor::from_slice(&batch) {
                    Ok(batch) => Arc::new(batch),
                    Err(error) => return future::err(Error::from(error)).into_box(),
                };

                // Check if we have the correct block already available. In this case we can transition
                // directly to batch processing, otherwise we have to wait for the block to appear.
                let latest_block = inner.latest_block.lock().unwrap().clone();
                if let Some(ref block) = latest_block {
                    if block.header == block_header {
                        // We are all cought up and can directly start processing the batch.
                        Self::transition(
                            inner.clone(),
                            State::ProcessingBatch(role, batch, block.clone()),
                        );
                        // TODO: Correlate to an event source
                        let sh = Span::inactive().handle();
                        return Self::process_batch(inner, sh);
                    } else if block.header.round > block_header.round {
                        // We have already seen a newer block. Do not even start to process this batch.
                        warn!("Already seen a newer block than expected for latest batch, not processing");
                        return future::ok(()).into_box();
                    }
                }

                // Wait for block to appear.
                info!(
                    "Waiting for block at round {:?} to appear",
                    block_header.round
                );
                Self::transition(inner, State::WaitingForBlock(role, batch, block_header));

                future::ok(()).into_box()
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
    fn handle_discrepancy_detected(
        inner: Arc<Inner>,
        batch_hash: H256,
        block_header: Header,
    ) -> BoxFuture<()> {
        measure_counter_inc!("discrepancy_detected_count");

        warn!(
            "Discrepancy detected while processing batch {:?}",
            batch_hash
        );

        // Only backup workers can do anything during discrepancy resolution.
        let committee = require_state_ignore!(
            inner,
            State::WaitingForBatch(GroupRole{
                role: Some(Role::BackupWorker),
                committee,
                ..
            }) => committee
        );

        info!("Backup worker activating and processing batch");

        Self::handle_remote_batch(inner, batch_hash, block_header, committee)
    }

    /// Handle new block from root hash backend.
    fn handle_block(inner: Arc<Inner>, block: Block) -> BoxFuture<()> {
        info!(
            "Received new block at round {:?} from root hash backend",
            block.header.round
        );

        // Update latest block.
        {
            let mut latest_block = inner.latest_block.lock().unwrap();
            if let Some(previous_block) = latest_block.take() {
                assert!(block.header.round > previous_block.header.round);
            }

            *latest_block = Some(block.clone());
        }

        // Process epoch transitions. These can happen in any state so we must process them first.
        if block.header.header_type == HeaderType::EpochTransition {
            // Abort current batch.
            Self::fail_batch(inner.clone(), "epoch transition".to_string());

            // Check if our group view is up to date.
            let pending_role = inner.pending_role.lock().unwrap();
            if let Some(ref group_role) = *pending_role {
                if group_role.committee.get_encoded_hash() == block.header.group_hash {
                    // Our group is already up to date, we can transition to new role immediately.
                    Self::transition_role(inner.clone(), group_role.clone());
                    return future::ok(()).into_box();
                }
            }

            // We need to wait for a role update.
            info!("Waiting for committee role update");
            Self::transition(
                inner.clone(),
                State::WaitingForGroup(block.header.group_hash),
            );
            return future::ok(()).into_box();
        }

        // Decide what to do based on current state.
        let state = inner.state.lock().unwrap().clone();
        match state {
            State::NotReady | State::WaitingForBatch(..) | State::WaitingForGroup(..) => {
                future::ok(()).into_box()
            }
            State::WaitingForBlock(role, batch, header) => {
                // New block has been seen while waiting for a block. Check if it is the
                // block we are waiting for.
                if block.header == header {
                    info!("Received all blocks needed to process next batch");

                    Self::transition(inner.clone(), State::ProcessingBatch(role, batch, block));

                    // TODO: Correlate with what leads up to this
                    let sh = Span::inactive().handle();
                    Self::process_batch(inner, sh)
                } else if block.header.round >= header.round {
                    // New block has been seen while waiting for a historic block, abort.
                    Self::fail_batch(inner.clone(), "seen newer block".into());
                    Self::transition(inner, State::WaitingForBatch(role));
                    future::ok(()).into_box()
                } else {
                    info!("Still waiting for block at round {:?}", header.round);
                    future::ok(()).into_box()
                }
            }
            State::ProcessingBatch(role, ..) => {
                // New block has been seen while processing a batch, abort.
                Self::fail_batch(inner.clone(), "seen newer block".into());
                Self::transition(inner, State::WaitingForBatch(role));
                future::ok(()).into_box()
            }
            State::LocallyAborted(role) | State::WaitingForFinalize(role, ..) => {
                match block.header.header_type {
                    HeaderType::Normal => {
                        // Round has been finalized.
                        info!("Considering the round finalized");

                        // TODO: We should actually check if the proposed block was included and
                        //       in case it wasn't, abort the batch.
                    }
                    HeaderType::RoundFailed => {
                        // Round has failed.
                        Self::fail_batch(inner.clone(), "round has failed".into());
                    }
                    HeaderType::EpochTransition => unreachable!("must be handled above"),
                }

                Self::transition(inner.clone(), State::WaitingForBatch(role));

                // Since the round is finalized, we start processing a new batch immediately.
                inner
                    .command_sender
                    .unbounded_send(Command::ProcessIncomingQueue)
                    .unwrap();

                future::ok(()).into_box()
            }
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
        let role = require_state_ignore!(
            inner,
            State::WaitingForBatch(role @ GroupRole{ role: Some(Role::Leader), .. }) => role
        );

        // Clear incoming queue notified flag to allow new notifies from appends.
        inner.incoming_queue_notified.store(false, Ordering::SeqCst);

        // Check if a block is available from the roothash backend.
        let block = {
            if let Some(ref block) = *inner.latest_block.lock().unwrap() {
                block.clone()
            } else {
                warn!("No block available from roothash backend, cannot process queue");
                return future::ok(()).into_box();
            }
        };

        // Check if we should process.
        let mut incoming_queue = inner.incoming_queue.lock().unwrap();
        let should_process = if let Some(ref incoming_queue) = *incoming_queue {
            let queue_size_bytes = incoming_queue
                .calls
                .iter()
                .fold(0, |acc, call| acc + call.data.len());

            incoming_queue.calls.len() >= inner.max_batch_size
                || queue_size_bytes >= inner.max_batch_size_bytes
                || incoming_queue.start.elapsed() >= inner.max_batch_timeout
        } else {
            false
        };

        if should_process {
            let tracer = ekiden_tracing::get_tracer();
            let mut opts = Some(
                tracer
                    .span("process_incoming_queue")
                    .tag(tag::StdTag::span_kind("consumer")),
            );

            // Take calls from incoming queue for processing. We only take up to max_batch_size,
            // taking into account max_batch_size_bytes and leave the rest for the next batch.
            let mut batch_info = VecDeque::new();
            let mut current_batch_size = 0;
            let mut new_incoming_queue = IncomingQueue::default();
            // TODO: We could maintain this per-incoming queue but this would make it slightly
            //       more error-prone to ensure consistency between the deque and set. This
            //       would avoid potentially computing the same hashes multiple times and storing
            //       duplicates in the queue.
            let mut included_calls = HashSet::new();

            for item in incoming_queue.take().unwrap().calls {
                if batch_info.len() + 1 > inner.max_batch_size {
                    // Batch would overflow, put all remaining items back.
                    new_incoming_queue.calls.push_back(item);
                    continue;
                }

                if current_batch_size + item.data.len() > inner.max_batch_size_bytes {
                    // Batch would overflow, put the item back.
                    new_incoming_queue.calls.push_back(item);
                    continue;
                }

                let call_hash = hash::from_bytes(&item.data);
                if included_calls.contains(&call_hash) {
                    // Call already exists in batch, do not include it again and do not put
                    // it back as there is no sense in having duplicate items in the queue.
                    warn!("Duplicate runtime call {} discarded from batch", call_hash);
                    continue;
                }
                included_calls.insert(call_hash);

                current_batch_size += item.data.len();
                batch_info.push_back(item);
            }

            // If there are any items left over, put them back into the incoming queue.
            if !new_incoming_queue.calls.is_empty() {
                measure_gauge!("incoming_queue_size", new_incoming_queue.calls.len());
                *incoming_queue = Some(new_incoming_queue);
            } else {
                measure_gauge!("incoming_queue_size", 0);
            }

            let batch: Vec<_> = batch_info
                .into_iter()
                .map(|call_info| {
                    opts = Some(opts.take().unwrap().follows_from(&call_info.context));
                    call_info.data
                })
                .collect();
            let span = opts.unwrap().start();
            let sh = span.handle();

            // Persist batch into storage so that the workers can get it.
            // Save it for one epoch so that the current committee can access it.
            let inner = inner.clone();
            let inner_clone = inner.clone();
            let encoded_batch = serde_cbor::to_vec(&batch).unwrap();
            let batch_hash = hash_storage_key(&encoded_batch);

            Self::transition(
                inner.clone(),
                State::ProcessingBatch(role, Arc::new(batch.into()), block),
            );

            measure_histogram!("batch_insert_size", encoded_batch.len());
            inner
                .storage
                .insert(encoded_batch, 1, InsertOptions::default())
                .and_then(move |_| {
                    let (role, block) = require_state!(
                        inner,
                        State::ProcessingBatch(role, _, block) => (role, block),
                        "processing batch"
                    );

                    // Submit signed batch hash to the rest of the computation group so they can start work.
                    if !inner
                        .computation_group
                        .submit(batch_hash, block.header, &role)
                    {
                        return future::err(Error::new("committee changed while processing batch"))
                            .into_box();
                    }

                    // Process batch locally.
                    Self::process_batch(inner, sh)
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
    /// `sh` should come from the source that causes us to transition into ProcessingBatch.
    fn process_batch(inner: Arc<Inner>, sh: SpanHandle) -> BoxFuture<()> {
        let (role, batch, block) = require_state!(
            inner,
            State::ProcessingBatch(role, batch, block) => (role.role, batch, block),
            "processing batch"
        );

        measure_counter_inc!("processing_batch_count");

        // Send block and channel to worker. Only the leader and backup worker should commit
        // updated state to storage.
        let commit_storage = match role {
            Some(Role::Leader) => true,
            Some(Role::BackupWorker) => true,
            _ => false,
        };
        let process_batch =
            inner
                .worker
                .runtime_call_batch((*batch).clone(), block, sh, commit_storage);

        // After the batch is processed, propose the batch.
        process_batch
            .then(|result| Self::propose_batch(inner, result))
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
                    incoming_queue.calls.push_front(CallInfo {
                        data: item.clone(),
                        // We should have already correlated the original enqueueing site when we
                        // got these items out of `incoming_queue` the first time.
                        context: None,
                    });
                }

                measure_gauge!("incoming_queue_size", incoming_queue.calls.len());
            }

            // Determine new state.
            if let Some(role) = state.get_role() {
                State::LocallyAborted(role)
            } else {
                State::NotReady
            }
        };

        // Transition state.
        Self::transition(inner.clone(), new_state);

        future::ok(()).into_box()
    }

    /// Propose a batch to root hash backend.
    fn propose_batch(inner: Arc<Inner>, computed_batch: Result<ComputedBatch>) -> BoxFuture<()> {
        let (role, batch) = require_state!(
            inner,
            State::ProcessingBatch(role, batch, _) => (role, batch),
            "proposing batch"
        );

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
        block.header.group_hash = role.committee.get_encoded_hash();
        block.header.input_hash =
            hash_storage_key(&serde_cbor::to_vec(&computed_batch.calls).unwrap());
        block.header.output_hash = hash_storage_key(&encoded_outputs);
        block.header.state_root = computed_batch.new_state_root;

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

        measure_histogram!("outputs_insert_size", encoded_outputs.len());
        inner
            .storage
            .insert(encoded_outputs, 2, InsertOptions::default())
            .or_else(|error| {
                // Failed to store outputs, abort current batch.
                Self::fail_batch(
                    inner_clone,
                    format!("failed to store outputs: {}", error.message),
                )
            })
            .and_then(move |_| {
                require_state!(inner, State::WaitingForFinalize(..), "proposing batch");

                // Test mode: skip commit.
                #[cfg(feature = "testing")]
                {
                    if inner.test_only_config.skip_commit_until_round
                        > computed_batch.block.header.round.as_u64()
                    {
                        warn!("TEST MODE: skipping commit");
                        return future::ok(()).into_box();
                    }
                }

                measure_counter_inc!("proposed_batch_count");

                let shared_inner = inner.clone();

                inner
                    .backend
                    .commit(inner.runtime_id, commitment)
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

    /// Append a runtime call to current batch for eventual processing.
    pub fn append_batch(&self, data: Vec<u8>, context: Option<SpanContext>) -> Result<()> {
        // If we are not a leader, do not append to batch.
        {
            let state = self.inner.state.lock().unwrap();
            if !state.is_leader() {
                warn!("Ignoring append to batch as we are not the computation group leader");
                return Err(Error::new(ERROR_APPEND_NOT_LEADER));
            }
        }

        // If call is too big to process, reject it.
        {
            if data.len() > self.inner.max_batch_size_bytes {
                warn!("Rejecting oversized call ({} bytes)", data.len());
                return Err(Error::new(ERROR_APPEND_TOO_LARGE));
            }
        }

        // Append to batch.
        {
            let mut incoming_queue = self.inner.incoming_queue.lock().unwrap();
            let incoming_queue = incoming_queue.get_or_insert_with(|| IncomingQueue::default());
            incoming_queue.calls.push_back(CallInfo { data, context });

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
    pub fn process_remote_batch(
        &self,
        node_id: B256,
        batch_hash: H256,
        block_header: Header,
        group_hash: H256,
    ) -> Result<()> {
        let inner = &self.inner;

        // Check that batch comes from current committee leader.
        let committee = inner.computation_group.check_remote_batch(node_id)?;

        // Check that the current committee matches the leader's view.
        if group_hash != committee.get_encoded_hash() {
            return Err(Error::new("inconsistent view of computation group"));
        }

        require_state_result!(
            inner,
            State::WaitingForBatch(GroupRole{ role: Some(Role::Worker), .. }) |
            State::WaitingForBatch(GroupRole{ role: Some(Role::BackupWorker), .. }),
            "requesting to process remote batch"
        );

        inner
            .command_sender
            .unbounded_send(Command::ProcessRemoteBatch(
                batch_hash,
                block_header,
                committee,
            ))
            .unwrap();

        Ok(())
    }
}
