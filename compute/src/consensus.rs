//! Consensus frontend.
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_timer::Interval;
use serde_cbor;

use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, Event, Reveal};
use ekiden_core::bytes::{B256, H256};
use ekiden_core::contract::batch::{CallBatch, OutputBatch};
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::sync::{mpsc, oneshot};
use ekiden_core::futures::{future, BoxFuture, Executor, Future, FutureExt, Stream, StreamExt};
use ekiden_core::hash::{empty_hash, EncodedHash};
use ekiden_core::signature::{Signed, Signer};
use ekiden_scheduler_base::CommitteeNode;
use ekiden_storage_base::{hash_storage_key, StorageBackend};

use super::group::ComputationGroup;
use super::worker::{ComputedBatch, Worker};

/// Commands for communicating with the consensus frontend from other tasks.
enum Command {
    /// Append to current batch.
    AppendBatch(CallBatch),
    /// Process remote batch.
    ProcessRemoteBatch(H256, Vec<CommitteeNode>),
}

/// Proposed block.
struct ProposedBlock {
    /// Nonce used when generating commitment.
    nonce: B256,
    /// Proposed block we committed to.
    block: Block,
}

/// Call batch that is being constructed.
struct PendingBatch {
    /// Instant when first item was queued in the batch.
    start: Instant,
    /// Batch of contract calls.
    calls: CallBatch,
}

impl Default for PendingBatch {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            calls: CallBatch::default(),
        }
    }
}

struct Inner {
    /// Contract identifier this consensus frontend is for.
    contract_id: B256,
    /// Consensus backend.
    backend: Arc<ConsensusBackend>,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Signer for the compute node.
    signer: Arc<Signer + Send + Sync>,
    /// Worker that can process batches.
    worker: Arc<Worker>,
    /// Computation group that can process batches.
    computation_group: Arc<ComputationGroup>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Current batch.
    current_batch: Mutex<Option<PendingBatch>>,
    /// Maximum batch size.
    max_batch_size: usize,
    /// Maximum batch timeout.
    max_batch_timeout: Duration,
    /// Flag if a batch is currently processing.
    batch_processing: AtomicBool,
    /// Currently proposed block.
    proposed_block: Mutex<Option<ProposedBlock>>,
    /// Call subscribers (call id -> list of subscribers).
    call_subscribers: Mutex<HashMap<H256, Vec<oneshot::Sender<Vec<u8>>>>>,
    /// Test-only configuration.
    test_only_config: ConsensusTestOnlyConfiguration,
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
    /// Signer for the compute node.
    pub signer: Arc<Signer + Send + Sync>,
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
        worker: Arc<Worker>,
        computation_group: Arc<ComputationGroup>,
        backend: Arc<ConsensusBackend>,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();

        Self {
            inner: Arc::new(Inner {
                contract_id,
                backend,
                storage,
                signer: config.signer.clone(),
                worker,
                computation_group,
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                current_batch: Mutex::new(None),
                max_batch_size: config.max_batch_size,
                max_batch_timeout: Duration::from_millis(config.max_batch_timeout),
                batch_processing: AtomicBool::new(false),
                proposed_block: Mutex::new(None),
                call_subscribers: Mutex::new(HashMap::new()),
                test_only_config: config.test_only.clone(),
            }),
        }
    }

    /// Start consensus frontend.
    pub fn start(&self, executor: &mut Executor) {
        // Subscribe to consensus events.
        executor.spawn({
            let inner = self.inner.clone();

            self.inner
                .backend
                .get_events(self.inner.contract_id)
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error while processing consensus events",
                    move |event| match event {
                        Event::CommitmentsReceived(discrepancy) => {
                            Self::handle_commitments_received(inner.clone(), discrepancy)
                        }
                        Event::RoundFailed(error) => Self::fail_batch(
                            inner.clone(),
                            format!("Round failed: {}", error.message),
                        ),
                        Event::DiscrepancyDetected(batch_hash) => {
                            Self::handle_discrepancy_detected(inner.clone(), batch_hash)
                        }
                    },
                )
        });

        // Subscribe to consensus blocks.
        executor.spawn({
            let inner = self.inner.clone();

            self.inner
                .backend
                .get_blocks(self.inner.contract_id)
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error while processing consensus blocks",
                    move |block| Self::handle_block(inner.clone(), block),
                )
        });

        // Receive proposed batches from worker.
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
                    "Unexpected error while processing consensus commands",
                    move |command| match command {
                        Command::AppendBatch(calls) => {
                            Self::handle_append_batch(inner.clone(), calls)
                        }
                        Command::ProcessRemoteBatch(batch_hash, committee) => {
                            Self::handle_remote_batch(inner.clone(), batch_hash, committee)
                        }
                    },
                )
        });

        // Periodically check for batches.
        executor.spawn({
            let inner = self.inner.clone();

            Interval::new(self.inner.max_batch_timeout)
                .map_err(|error| Error::from(error))
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error while firing batch interval timer",
                    move |_| {
                        // Check if batch is ready to be sent for processing.
                        Self::check_and_process_current_batch(inner.clone())
                    },
                )
        });
    }

    /// Handle append batch command.
    fn handle_append_batch(inner: Arc<Inner>, mut calls: CallBatch) -> BoxFuture<()> {
        // Ignore empty batches.
        if calls.is_empty() {
            return Box::new(future::ok(()));
        }

        // If we are not a leader, do not append to batch.
        if !inner.computation_group.is_leader() {
            warn!("Ignoring append to batch as we are not the computation group leader");
            return Box::new(future::ok(()));
        }

        // Append to batch.
        {
            let mut current_batch = inner.current_batch.lock().unwrap();
            let current_batch = current_batch.get_or_insert_with(|| PendingBatch::default());
            current_batch.calls.append(&mut calls);
        }

        // Check if batch is ready to be sent for processing.
        Self::check_and_process_current_batch(inner.clone())
    }

    /// Handle process remote batch command.
    fn handle_remote_batch(
        inner: Arc<Inner>,
        batch_hash: H256,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        // TODO: Abort any batches that are currently being processed.

        // Fetch batch from storage.
        inner
            .storage
            .get(batch_hash)
            .and_then(move |calls| {
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
        // If this event has been emitted during discrepancy resolution, we should ignore
        // it if we are not a backup worker.
        if discrepancy && !inner.computation_group.is_backup_worker() {
            return future::ok(()).into_box();
        }

        // Ensure we have proposed a block in the current round.
        let proposed_block_guard = inner.proposed_block.lock().unwrap();
        if proposed_block_guard.is_none() {
            trace!("Ignoring commitments as we didn't propose any block");
            return future::ok(()).into_box();
        }

        let proposed_block = proposed_block_guard.as_ref().unwrap();

        info!("Submitting reveal");

        // Generate and submit reveal.
        let reveal = Reveal::new(
            &inner.signer,
            &proposed_block.nonce,
            &proposed_block.block.header,
        );

        let inner = inner.clone();
        inner
            .backend
            .reveal(inner.contract_id, reveal)
            .or_else(|error| {
                // Failed to submit reveal, abort current batch.
                Self::fail_batch(inner, format!("Failed to reveal block: {}", error.message))
            })
            .into_box()
    }

    /// Handle discrepancy detected event from consensus backend.
    fn handle_discrepancy_detected(inner: Arc<Inner>, batch_hash: H256) -> BoxFuture<()> {
        warn!(
            "Discrepancy detected while processing batch {:?}",
            batch_hash
        );

        // Only backup workers can do anything during discrepancy resolution.
        if !inner.computation_group.is_backup_worker() {
            trace!("I am not a backup worker, waiting for consensus to resolve discrepancy");
            return future::ok(()).into_box();
        }

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
        {
            let mut proposed_block = inner.proposed_block.lock().unwrap();
            let should_clear = {
                if let Some(ref proposed_block) = *proposed_block {
                    proposed_block.block.header.round >= block.header.round
                } else {
                    false
                }
            };

            if should_clear {
                info!("Block is for the same round or newer as recently proposed block");

                // Clear proposed block.
                proposed_block.take();
                // Clear batch processing flag.
                inner.batch_processing.store(false, SeqCst);
            }
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

    /// Check if we need to send the current batch for processing.
    ///
    /// The batch is then sent for processing if either:
    /// * Number of calls it contains reaches `max_batch_size`.
    /// * More than `max_batch_timeout` time elapsed since batch was created.
    /// * No other batch is currently processing.
    fn check_and_process_current_batch(inner: Arc<Inner>) -> BoxFuture<()> {
        // First check if a batch is already being processed.
        if inner.batch_processing.load(SeqCst) {
            return Box::new(future::ok(()));
        }

        // No batch yet, check if we should process.
        let mut current_batch = inner.current_batch.lock().unwrap();
        let should_process = if let Some(ref current_batch) = *current_batch {
            current_batch.calls.len() >= inner.max_batch_size
                || current_batch.start.elapsed() >= inner.max_batch_timeout
        } else {
            false
        };

        if should_process {
            // Take calls from current batch for processing. We only take up to max_batch_size
            // and leave the rest for the next batch, resetting the timestamp.
            let mut calls = current_batch.take().unwrap().calls;
            if calls.len() > inner.max_batch_size {
                let mut remaining = calls.split_off(inner.max_batch_size);
                let current_batch = current_batch.get_or_insert_with(|| PendingBatch::default());
                current_batch.calls.append(&mut remaining);
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
        // We have decided to process the current batch.
        inner.batch_processing.store(true, SeqCst);

        // Fetch the latest block and request the worker to process the batch.
        let shared_inner = inner.clone();
        Box::new(
            inner
                .backend
                .get_latest_block(inner.contract_id)
                .and_then(|block| {
                    // Send block and channel to worker.
                    let process_batch = inner.worker.contract_call_batch(calls, block);

                    // After the batch is processed, propose the batch.
                    process_batch
                        .map_err(|_| Error::new("channel closed"))
                        .and_then(|result| Self::propose_batch(inner, result, committee))
                })
                .or_else(|error| {
                    // Failed to get latest block, abort current batch.
                    Self::fail_batch(
                        shared_inner,
                        format!("Failed to process batch: {}", error.message),
                    )
                }),
        )
    }

    /// Fail processing of current batch.
    ///
    /// This method should be called on any failures related to the currently proposed
    /// batch in order to allow new batches to be processed.
    fn fail_batch(inner: Arc<Inner>, reason: String) -> BoxFuture<()> {
        error!("{}", reason);

        // TODO: Should we move all failed calls back into the current batch?

        // TODO: Should we notify consensus backend that we aborted?

        // Clear proposed block if any.
        drop(inner.proposed_block.lock().unwrap().take());

        // Clear batch processing flag.
        inner.batch_processing.store(false, SeqCst);

        future::ok(()).into_box()
    }

    /// Propose a batch to consensus backend.
    fn propose_batch(
        inner: Arc<Inner>,
        computed_batch: Result<ComputedBatch>,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
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

        // Store proposed block.
        {
            let mut proposed_block = inner.proposed_block.lock().unwrap();

            // Ensure no block was previously proposed. This should never happen as we always
            // check the batch_processing flag before processing a batch.
            assert!(
                proposed_block.is_none(),
                "tried to overwrite proposed block"
            );

            proposed_block.get_or_insert(ProposedBlock { nonce, block });
        }

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
            .and_then(|_| {
                inner
                    .backend
                    .commit(inner.contract_id, commitment)
                    .or_else(|error| {
                        // Failed to commit a block, abort current batch.
                        Self::fail_batch(
                            inner,
                            format!("Failed to propose block: {}", error.message),
                        )
                    })
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
