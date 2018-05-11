//! Consensus frontend.
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};

use futures_timer::Interval;
use lru_cache::LruCache;

use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, Event, Reveal, Transaction,
                            BLOCK_SUBMIT_SIGNATURE_CONTEXT};
use ekiden_core::bytes::{B256, H256};
use ekiden_core::contract::batch::CallBatch;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::{future, BoxFuture, Executor, Future, Stream};
use ekiden_core::futures::sync::{mpsc, oneshot};
use ekiden_core::hash::EncodedHash;
use ekiden_core::signature::{Signed, Signer};
use ekiden_scheduler_base::CommitteeNode;

use super::group::ComputationGroup;
use super::worker::{ComputedBatch, Worker};

/// Commands for communicating with the consensus frontend from other tasks.
enum Command {
    /// Append to current batch.
    AppendBatch(CallBatch),
    /// Process remote batch.
    ProcessRemoteBatch(CallBatch, Vec<CommitteeNode>),
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

struct ConsensusFrontendInner {
    /// Consensus backend.
    backend: Arc<ConsensusBackend>,
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
    /// Recently computed outputs.
    recent_outputs: Mutex<LruCache<H256, Vec<u8>>>,
    /// Call subscribers (call id -> list of subscribers).
    call_subscribers: Mutex<HashMap<H256, Vec<oneshot::Sender<Vec<u8>>>>>,
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
}

/// Compute node consensus frontend.
pub struct ConsensusFrontend {
    inner: Arc<ConsensusFrontendInner>,
}

impl ConsensusFrontend {
    /// Create a new consensus frontend.
    pub fn new(
        config: ConsensusConfiguration,
        worker: Arc<Worker>,
        computation_group: Arc<ComputationGroup>,
        backend: Arc<ConsensusBackend>,
    ) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();

        Self {
            inner: Arc::new(ConsensusFrontendInner {
                backend,
                signer: config.signer,
                worker,
                computation_group,
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                current_batch: Mutex::new(None),
                max_batch_size: config.max_batch_size,
                max_batch_timeout: Duration::from_millis(config.max_batch_timeout),
                batch_processing: AtomicBool::new(false),
                proposed_block: Mutex::new(None),
                recent_outputs: Mutex::new(LruCache::new(config.max_batch_size * 10)),
                call_subscribers: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Start consensus frontend.
    pub fn start(&self, executor: &mut Executor) {
        // Subscribe to consensus events.
        executor.spawn({
            let inner = self.inner.clone();

            Box::new(
                self.inner
                    .backend
                    .get_events()
                    .for_each(move |event| match event {
                        Event::CommitmentsReceived => {
                            Self::handle_commitments_received(inner.clone())
                        }
                        Event::RoundFailed(error) => {
                            Self::handle_round_failed(inner.clone(), error)
                        }
                    })
                    .then(|_| future::ok(())),
            )
        });

        // Subscribe to consensus blocks.
        executor.spawn({
            let inner = self.inner.clone();

            Box::new(
                self.inner
                    .backend
                    .get_blocks()
                    .for_each(move |block| Self::handle_block(inner.clone(), block))
                    .then(|_| future::ok(())),
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

            Box::new(
                command_receiver
                    .map_err(|_| Error::new("command channel closed"))
                    .for_each(move |command| match command {
                        Command::AppendBatch(calls) => {
                            Self::handle_append_batch(inner.clone(), calls)
                        }
                        Command::ProcessRemoteBatch(calls, committee) => {
                            Self::process_batch(inner.clone(), calls, committee)
                        }
                    })
                    .then(|_| future::ok(())),
            )
        });

        // Periodically check for batches.
        executor.spawn({
            let inner = self.inner.clone();

            Box::new(
                Interval::new(self.inner.max_batch_timeout)
                    .map_err(|error| Error::from(error))
                    .for_each(move |_| {
                        // Check if batch is ready to be sent for processing.
                        Self::check_and_process_current_batch(inner.clone())
                    })
                    .then(|_| future::ok(())),
            )
        });
    }

    /// Handle append batch command.
    fn handle_append_batch(
        inner: Arc<ConsensusFrontendInner>,
        mut calls: CallBatch,
    ) -> BoxFuture<()> {
        // Ignore empty batches.
        if calls.is_empty() {
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

    /// Handle commitments received event from consensus backend.
    fn handle_commitments_received(inner: Arc<ConsensusFrontendInner>) -> BoxFuture<()> {
        // Ensure we have proposed a block in the current round.
        let proposed_block_guard = inner.proposed_block.lock().unwrap();
        if proposed_block_guard.is_none() {
            trace!("Ignoring commitments as we didn't propose any block");
            return Box::new(future::ok(()));
        }

        let proposed_block = proposed_block_guard.as_ref().unwrap();

        info!("Submitting reveal and block");

        // Generate and submit reveal.
        let reveal = Reveal::new(
            &inner.signer,
            &proposed_block.nonce,
            &proposed_block.block.header,
        );
        let result = inner.backend.reveal(reveal);

        // If we are a leader, also submit the block.
        // TODO: Only submit block if we are a leader.
        let block = proposed_block.block.clone();
        let inner = inner.clone();
        Box::new(result.and_then(move |_| {
            // Sign and submit block.
            let signed_block = Signed::sign(&inner.signer, &BLOCK_SUBMIT_SIGNATURE_CONTEXT, block);
            inner.backend.submit(signed_block)
        }))
    }

    /// Handle round failed event from consensus backend.
    fn handle_round_failed(inner: Arc<ConsensusFrontendInner>, error: Error) -> BoxFuture<()> {
        error!("Round has failed: {:?}", error);

        // TODO: Should we move all failed calls back into the current batch?

        // If the round has failed and we have proposed a block, be sure to clean
        // up. Note that the transactions from the batch will still be stored in
        // recent_outputs, but we don't emit anything if these are not persisted
        // in a block.
        {
            let mut proposed_block = inner.proposed_block.lock().unwrap();
            drop(proposed_block.take());
        }

        // Clear batch processing flag.
        inner.batch_processing.store(false, SeqCst);

        Box::new(future::ok(()))
    }

    /// Handle new block from consensus backend.
    fn handle_block(inner: Arc<ConsensusFrontendInner>, block: Block) -> BoxFuture<()> {
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

        // Check if any subscribed transactions have been included in a block.
        let mut call_subscribers = inner.call_subscribers.lock().unwrap();
        let mut recent_outputs = inner.recent_outputs.lock().unwrap();
        for transaction in &block.transactions {
            let call_id = transaction.input.get_encoded_hash();
            // We can only generate replies for outputs that we recently computed as outputs
            // themselves are not included in blocks.
            if let Some(output) = recent_outputs.get_mut(&call_id) {
                if let Some(senders) = call_subscribers.remove(&call_id) {
                    for sender in senders {
                        // Explicitly ignore send errors as the receiver may have gone.
                        drop(sender.send(output.clone()));
                    }
                }
            }
        }

        Box::new(future::ok(()))
    }

    /// Check if we need to send the current batch for processing.
    ///
    /// The batch is then sent for processing if either:
    /// * Number of calls it contains reaches `max_batch_size`.
    /// * More than `max_batch_timeout` time elapsed since batch was created.
    /// * No other batch is currently processing.
    fn check_and_process_current_batch(inner: Arc<ConsensusFrontendInner>) -> BoxFuture<()> {
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

            // Submit signed batch to the rest of the computation group so they can start work.
            let committee = inner.computation_group.submit(calls.clone());
            // Process batch locally.
            Self::process_batch(inner.clone(), calls, committee)
        } else {
            Box::new(future::ok(()))
        }
    }

    /// Process given batch locally and propose it when done.
    fn process_batch(
        inner: Arc<ConsensusFrontendInner>,
        calls: CallBatch,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        // We have decided to process the current batch.
        inner.batch_processing.store(true, SeqCst);

        // Fetch the latest block and request the worker to process the batch.
        Box::new(inner.backend.get_latest_block().and_then(move |block| {
            // Send block and channel to worker.
            let process_batch = inner.worker.contract_call_batch(calls, block);

            // After the batch is processed, propose the batch.
            process_batch
                .map_err(|_| Error::new("channel closed"))
                .and_then(move |result| Self::propose_batch(inner, result, committee))
        }))
    }

    /// Propose a batch to consensus backend.
    fn propose_batch(
        inner: Arc<ConsensusFrontendInner>,
        computed_batch: Result<ComputedBatch>,
        committee: Vec<CommitteeNode>,
    ) -> BoxFuture<()> {
        // Check result of batch computation.
        let mut computed_batch = match computed_batch {
            Ok(computed_batch) => computed_batch,
            Err(error) => {
                error!("Failed to process batch: {}", error.message);
                // TODO: Should we move all failed calls back into the current batch?

                // Clear batch processing flag.
                inner.batch_processing.store(false, SeqCst);
                return Box::new(future::ok(()));
            }
        };

        // Create block from result batches.
        let mut block = Block::new_parent_of(&computed_batch.block);
        block.computation_group = committee;
        block.header.state_root = computed_batch.new_state_root;

        // Generate a list of transactions from call/output batches.
        {
            let mut recent_outputs = inner.recent_outputs.lock().unwrap();
            for (call, output) in computed_batch
                .calls
                .iter()
                .zip(computed_batch.outputs.drain(..))
            {
                block.transactions.push(Transaction {
                    input: call.clone(),
                    output_hash: output.get_encoded_hash(),
                });

                recent_outputs.insert(call.get_encoded_hash(), output);
            }
        }

        block.update();

        info!(
            "Proposing new block with {} transaction(s)",
            block.transactions.len()
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

        // Commit to block.
        inner.backend.commit(commitment)
    }

    /// Append contract calls to current batch for eventual processing.
    pub fn append_batch(&self, calls: CallBatch) {
        self.inner
            .command_sender
            .unbounded_send(Command::AppendBatch(calls))
            .unwrap();
    }

    /// Directly process a batch from a remote leader.
    pub fn process_remote_batch(&self, calls: Signed<CallBatch>) -> Result<()> {
        // Open signed batch, verifying that it was signed by the leader and that the
        // committee matches.
        let (calls, committee) = self.inner.computation_group.open_remote_batch(calls)?;

        self.inner
            .command_sender
            .unbounded_send(Command::ProcessRemoteBatch(calls, committee))
            .unwrap();

        Ok(())
    }

    /// Subscribe to being notified when specific call is included in a block.
    pub fn subscribe_call(&self, call_id: H256) -> oneshot::Receiver<Vec<u8>> {
        let (response_sender, response_receiver) = oneshot::channel();
        {
            let mut call_subscribers = self.inner.call_subscribers.lock().unwrap();
            match call_subscribers.entry(call_id) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(response_sender);
                }
                Entry::Vacant(entry) => {
                    entry.insert(vec![response_sender]);
                }
            }
        }

        response_receiver
    }
}
