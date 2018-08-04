//! Dummy root hash backend.
use std::collections::HashMap;
use std::convert::TryInto;
use std::path::Path;
use std::process::abort;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_cbor;

use ekiden_common::bytes::{B256, H256};
use ekiden_common::contract::Contract;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_common::hash::empty_hash;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_common::tokio::timer::Delay;
use ekiden_common::uint::U256;
use ekiden_registry_base::ContractRegistryBackend;
use ekiden_roothash_base::{Block, Commitment as OpaqueCommitment, Event, Header, RootHashBackend};
use ekiden_scheduler_base::{Committee, CommitteeNode, CommitteeType, Role, Scheduler};
use ekiden_storage_base::StorageBackend;
use ekiden_storage_mutablestate::StateStorage;

use super::commitment::Commitment;

/// Hard time limit for a round after at least one node has sent a commitment.
const ROUND_AFTER_COMMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Round state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum State {
    WaitingCommitments,
    DiscrepancyWaitingCommitments,
}

/// Try finalize result.
#[derive(Eq, PartialEq)]
enum FinalizationResult {
    StillWaiting(u64),
    Finalized(Block),
    DiscrepancyDetected(H256),
}

/// Serializable state needed for managing a protocol round.
#[derive(Serialize, Deserialize)]
struct RoundState {
    /// Contract metadata.
    contract: Contract,
    /// Computation committee.
    committee: Committee,
    /// Computation group, mapped by public key hashes.
    computation_group: HashMap<B256, CommitteeNode>,
    /// Commitments from computation group nodes.
    commitments: HashMap<B256, Commitment>,
    /// Current block.
    current_block: Block,
    /// Round state.
    state: State,
}

/// Wrapper for the state with extra stuff we need at runtime.
struct Round {
    /// Round state.
    round_state: RoundState,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Current round timer handle.
    timer_handle: Option<KillHandle>,
    /// Timeout flag.
    timeout: bool,
}

impl Round {
    /// Create new round descriptor.
    fn new(
        storage: Arc<StorageBackend>,
        contract: Contract,
        committee: Committee,
        block: Block,
    ) -> Self {
        // Index computation group members by their public key hash.
        let mut computation_group = HashMap::new();
        for node in &committee.members {
            computation_group.insert(node.public_key.clone(), node.clone());
        }

        Self {
            round_state: RoundState {
                contract,
                committee,
                computation_group,
                commitments: HashMap::new(),
                current_block: block,
                state: State::WaitingCommitments,
            },
            storage,
            timer_handle: None,
            timeout: false,
        }
    }

    /// Create new round descriptor with existing internal state.
    fn new_with_state(storage: Arc<StorageBackend>, round_state: RoundState) -> Self {
        Self {
            round_state,
            storage,
            timer_handle: None,
            timeout: false,
        }
    }

    /// Reset round.
    fn reset(&mut self) {
        self.round_state.commitments.clear();
        self.round_state.state = State::WaitingCommitments;
        self.timeout = false;
        if let Some(timer_handle) = self.timer_handle.take() {
            timer_handle.kill();
        }
    }

    /// Add new commitments from one or more nodes in this round.
    fn add_commitments(
        round: Arc<Mutex<Round>>,
        commitments: Vec<Commitment>,
    ) -> BoxFuture<Vec<Result<()>>> {
        // We're going to store the resulting futures for each commitment.
        let mut results: Vec<BoxFuture<()>> = Vec::with_capacity(commitments.len());

        for commitment in commitments.iter() {
            let shared_round = round.clone();
            let round = round.lock().unwrap();
            let commitment = commitment.clone();

            // Ensure each commitment is from a valid compute node and that we are in correct state.
            let node_id = commitment.get_public_key();
            {
                let node = match round.round_state.computation_group.get(&node_id) {
                    Some(node) => node,
                    None => {
                        results.push(
                            future::err(Error::new("node not part of computation group"))
                                .into_box(),
                        );
                        continue;
                    }
                };

                match (node.role, round.round_state.state) {
                    (Role::Worker, State::WaitingCommitments)
                    | (Role::Leader, State::WaitingCommitments) => {}

                    (Role::BackupWorker, State::DiscrepancyWaitingCommitments) => {}

                    _ => {
                        results.push(
                            future::err(Error::new("node has incorrect role for current state"))
                                .into_box(),
                        );
                        continue;
                    }
                }
            }

            let header = match commitment.open() {
                Ok(header) => header,
                Err(_) => {
                    results.push(
                        future::err(Error::new("commitment has invalid signature")).into_box(),
                    );
                    continue;
                }
            };

            // Ensure node did not already submit a commitment.
            if round.round_state.commitments.contains_key(&node_id) {
                results.push(future::err(Error::new("node already sent commitment")).into_box());
                continue;
            }

            // Check if block is based on the previous block.
            if !header.is_parent_of(&round.round_state.current_block.header) {
                results.push(
                    future::err(Error::new(
                        "submitted header is not based on previous block",
                    )).into_box(),
                );
                continue;
            }

            let mut storage_checks = vec![];

            // Check if storage backend contains correct input batch.
            if header.input_hash != empty_hash() {
                storage_checks.push(
                    round
                        .storage
                        .get(header.input_hash)
                        .map_err(|_error| Error::new("inputs not found in storage"))
                        .into_box(),
                );
            }

            // Check if storage backend contains correct output batch.
            if header.output_hash != empty_hash() {
                storage_checks.push(
                    round
                        .storage
                        .get(header.output_hash)
                        .map_err(|_error| Error::new("outputs not found in storage"))
                        .into_box(),
                );
            }

            // Check if storage backend contains correct state root.
            // TODO: Currently we just check a single key, we would need to check against a log.
            if header.state_root != empty_hash() {
                storage_checks.push(
                    round
                        .storage
                        .get(header.state_root)
                        .map_err(|_error| Error::new("state root not found in storage"))
                        .into_box(),
                );
            }

            results.push(
                future::join_all(storage_checks)
                    .and_then(move |_| {
                        let mut round = shared_round.lock().unwrap();
                        round.round_state.commitments.insert(node_id, commitment);

                        Ok(())
                    })
                    .into_box(),
            );
        }

        // Return a future returning a vector of results of the above futures
        // in the same order as the commitments were given.
        stream::futures_ordered(results)
            .then(|r| Ok(r))
            .collect()
            .into_box()
    }

    /// Check if the required number of nodes have sent commitments.
    ///
    /// If enough nodes have sent reveals this method returns `None`, otherwise it returns
    /// a finalization result to be returned.
    fn check_commitments<F>(&mut self, filter: F, num_required: u64) -> Option<FinalizationResult>
    where
        F: Fn(&CommitteeNode) -> bool,
    {
        let num_sent = self.round_state
            .commitments
            .iter()
            .filter(|&(id, _)| {
                let node = self.round_state.computation_group.get(id).unwrap();
                filter(node)
            })
            .count() as u64;

        if num_sent < num_required {
            info!("Still waiting for workers to commit");
            return Some(FinalizationResult::StillWaiting(num_sent));
        }

        None
    }

    /// Return the number of primary (leader, worker) nodes in the computation group.
    fn get_primary_node_count(&self) -> u64 {
        self.round_state
            .computation_group
            .iter()
            .filter(|&(_, node)| node.role == Role::Worker || node.role == Role::Leader)
            .count() as u64
    }

    /// Return the number of backup nodes (backup worker) in the computation group.
    fn get_backup_node_count(&self) -> u64 {
        self.round_state
            .computation_group
            .iter()
            .filter(|&(_, node)| node.role == Role::BackupWorker)
            .count() as u64
    }

    /// Return the number of primary nodes required to respond.
    fn get_required_primary_count(&self) -> u64 {
        // While a timer is running, all nodes are required to answer. After a timeout
        // we allow some stragglers.
        if self.timeout {
            self.get_primary_node_count() - self.round_state.contract.replica_allowed_stragglers
        } else {
            self.get_primary_node_count()
        }
    }

    /// Return the number of backup nodes required to respond.
    fn get_required_backup_count(&self) -> u64 {
        // While a timer is running, all nodes are required to answer. After a timeout
        // we allow some stragglers.
        if self.timeout {
            self.get_backup_node_count() - self.round_state.contract.replica_allowed_stragglers
        } else {
            self.get_backup_node_count()
        }
    }

    /// Cancel round timer if any is set.
    fn cancel_timer(&mut self) {
        trace!("Cancelling timer");
        self.timeout = false;
        if let Some(timer_handle) = self.timer_handle.take() {
            timer_handle.kill();
        }
    }

    /// Start round timer if none is set.
    fn start_timer<F>(round: Arc<Mutex<Round>>, duration: Duration, f: F)
    where
        F: FnOnce() -> BoxFuture<()> + Send + 'static,
    {
        let shared_round = round.clone();
        let mut round = round.lock().unwrap();
        if round.timer_handle.is_some() {
            trace!("Round timer already started, ignoring");
            return;
        }

        trace!("Installing round timer.");
        round.timer_handle = Some(spawn_killable(
            Delay::new(Instant::now() + duration)
                .map_err(|error| error.into())
                .and_then(move |_| {
                    // Set the timeout flag.
                    shared_round.lock().unwrap().timeout = true;

                    f()
                })
                .discard(),
        ));
    }

    /// Try to finalize the round.
    fn try_finalize(&mut self) -> BoxFuture<FinalizationResult> {
        // Check if all nodes sent commitments.
        match self.round_state.state {
            State::WaitingCommitments => {
                let required_primary_count = self.get_required_primary_count();
                if let Some(result) = self.check_commitments(
                    |node| node.role == Role::Worker || node.role == Role::Leader,
                    required_primary_count,
                ) {
                    return future::ok(result).into_box();
                }
            }
            State::DiscrepancyWaitingCommitments => {
                let required_backup_count = self.get_required_backup_count();
                if let Some(result) = self.check_commitments(
                    |node| node.role == Role::BackupWorker,
                    required_backup_count,
                ) {
                    return future::ok(result).into_box();
                }
            }
        }

        self.cancel_timer();

        // Everything is ready, try to finalize round.
        let header = match self.round_state.state {
            State::WaitingCommitments => {
                info!("Attempting to finalize round");

                // Check for discrepancies between computed results.
                let mut header = None;
                let mut discrepancy_detected = false;
                for (node_id, node) in self.round_state.computation_group.iter() {
                    if node.role == Role::BackupWorker {
                        continue;
                    }

                    let commitment = match self.round_state.commitments.get(node_id) {
                        Some(commitment) => commitment,
                        None => continue,
                    };
                    let proposed_header = commitment
                        .open()
                        .expect("commitment to be verified by add_commitments");

                    if header.is_none() {
                        header = Some(proposed_header.clone());
                    }

                    if header.as_ref().unwrap() != &proposed_header {
                        discrepancy_detected = true;
                        break;
                    }
                }

                let header = header.expect("there should be some commitments");

                if discrepancy_detected {
                    warn!("Discrepancy detected, at least one node reported different results");
                    measure_counter_inc!("detected_discrepancies");

                    // Activate the backup workers.
                    let input_hash = header.input_hash;
                    self.round_state.state = State::DiscrepancyWaitingCommitments;
                    return future::ok(FinalizationResult::DiscrepancyDetected(input_hash))
                        .into_box();
                }

                header
            }
            State::DiscrepancyWaitingCommitments => {
                info!("Attempting to finalize discrepancy resolution round");

                // Tally votes.
                let mut votes: HashMap<Header, u64> = HashMap::new();

                for (node_id, node) in self.round_state.computation_group.iter() {
                    if node.role != Role::BackupWorker {
                        continue;
                    }

                    let commitment = self.round_state.commitments.get(node_id).unwrap();
                    let vote = commitment
                        .open()
                        .expect("commitment to be verified by add_commitments");
                    let count = *votes.get(&vote).unwrap_or(&0);
                    votes.insert(vote, count + 1);
                }

                let min_votes = (self.get_backup_node_count() / 2) + 1;
                let winner = votes
                    .drain()
                    .filter(|&(_, votes)| votes >= min_votes)
                    .map(|(header, _)| header)
                    .next();
                match winner {
                    Some(header) => header,
                    None => {
                        error!("Not enough votes to finalize discrepancy resolution round");
                        return future::err(Error::new(
                            "not enough votes to finalize discrepancy resolution round",
                        )).into_box();
                    }
                }
            }
        };

        // Generate final block.
        let mut block = Block::new_parent_of(&self.round_state.current_block);
        block.header = header;
        block.computation_group = self.round_state.committee.members.clone();
        for node in &self.round_state.committee.members {
            block.commitments.push(
                self.round_state
                    .commitments
                    .get(&node.public_key)
                    .cloned()
                    .map(|commitment| commitment.into()),
            );
        }
        block.update();

        info!("Round has been finalized");
        measure_counter_inc!("finalized_rounds");
        future::ok(FinalizationResult::Finalized(block)).into_box()
    }
}

#[derive(Debug)]
enum Command {
    Commit(B256, Commitment, oneshot::Sender<Result<()>>),
}

struct Inner {
    /// Environment.
    environment: Arc<Environment>,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Contract registry backend.
    contract_registry: Arc<ContractRegistryBackend>,
    /// In-memory blockchain.
    blocks: Mutex<HashMap<B256, Vec<Block>>>,
    /// Current rounds.
    rounds: Mutex<HashMap<B256, Arc<Mutex<Round>>>>,
    /// Block subscribers.
    block_subscribers: StreamSubscribers<Block>,
    /// Event subscribers.
    event_subscribers: StreamSubscribers<(B256, Event)>,
    /// Shutdown signal sender (until used).
    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
    /// Shutdown signal receiver (until initialized).
    shutdown_receiver: Mutex<Option<oneshot::Receiver<()>>>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Local persistent state storage (for crash recovery).
    state_storage: Option<Arc<StateStorage>>,
}

/// A dummy root hash backend which simulates state in memory.
///
/// **This backend should only be used to test implementations that use the root hash
/// interface but it only simulates a root hash backend.***
pub struct DummyRootHashBackend {
    inner: Arc<Inner>,
}

impl DummyRootHashBackend {
    /// Create new dummy root hash backend.
    pub fn new(
        environment: Arc<Environment>,
        scheduler: Arc<Scheduler>,
        storage: Arc<StorageBackend>,
        contract_registry: Arc<ContractRegistryBackend>,
        local_db_path: Option<&str>,
    ) -> Self {
        // Create channels.
        let (command_sender, command_receiver) = mpsc::unbounded();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        let mut state_storage = None;

        if let Some(path) = local_db_path {
            info!(
                "Setting up local state storage for the dummy root hash backend at '{}'",
                path
            );

            // Open or create a new local state storage DB.
            state_storage = Some(Arc::new(match StateStorage::new(Path::new(path)) {
                Ok(ls) => ls,
                Err(e) => {
                    error!("Can't init local state storage: {}", e);
                    abort();
                }
            }));
        } else {
            info!("Not setting up local state storage for the dummy root hash backend");
        }

        let instance = Self {
            inner: Arc::new(Inner {
                environment,
                scheduler,
                storage,
                contract_registry,
                blocks: Mutex::new(HashMap::new()),
                rounds: Mutex::new(HashMap::new()),
                block_subscribers: StreamSubscribers::new(),
                event_subscribers: StreamSubscribers::new(),
                shutdown_sender: Mutex::new(Some(shutdown_sender)),
                shutdown_receiver: Mutex::new(Some(shutdown_receiver)),
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                state_storage,
            }),
        };
        instance.start();

        instance
    }

    fn start(&self) {
        if let Some(state_storage) = self.inner.state_storage.clone() {
            let state_storage = state_storage.clone();

            // Always load latest block from DB if present.
            match state_storage.get("latest_block_hash") {
                Ok(lbh) => {
                    let latest_block_hash: B256 = serde_cbor::from_slice(&lbh)
                        .expect("error deserializing latest block hash");

                    // The "latest_block_hash" key only stores the hash of the
                    // latest block, so we need to get to the actual block now.
                    let latest_block_key = format!("block_{}", latest_block_hash);

                    match state_storage.get(&latest_block_key) {
                        Ok(b) => {
                            let block: Vec<Block> = serde_cbor::from_slice(&b)
                                .expect("error deserializing latest block");

                            self.inner
                                .blocks
                                .lock()
                                .unwrap()
                                .insert(latest_block_hash, block);
                            info!("Loaded latest block from storage!");
                        }
                        _ => {
                            error!(
	                            "INTERNAL ERROR: Latest block pointer points to a nonexistent block!"
	                        );
                            abort();
                            // TODO: It might be a better idea to just nuke and
                            //       reinitialize the database here, since this
                            //       can only happen if there's DB corruption.
                        }
                    }
                }
                _ => {
                    // This isn't an error, since it's quite possible that the
                    // node simply didn't process any blocks yet or this is the
                    // very first run and we have a fresh DB.
                }
            }

            // Check whether our last shutdown was clean.
            match state_storage.get("node_running") {
                Ok(_) => {
                    // Unclean shutdown, recover round state!
                    warn!("Node wasn't cleanly shut down, recovering round state");
                    measure_counter_inc!("crashes");

                    match state_storage.get("round_state") {
                        Ok(rs) => {
                            let mut rs: RoundState = serde_cbor::from_slice(&rs)
                                .expect("error deserializing round state");

                            // Fix the Arc<Contract> in Committee struct.
                            // We don't ser/des that, so we need to fill it in
                            // before it's used anywhere!
                            rs.committee.contract = Arc::new(rs.contract.clone());

                            let recovered_round =
                                Round::new_with_state(self.inner.storage.clone(), rs);
                            let contract_id = recovered_round.round_state.contract.id;

                            let mut rounds = self.inner.rounds.lock().unwrap();
                            rounds.insert(contract_id, Arc::new(Mutex::new(recovered_round)));

                            // Call try_finalize to resolve any outstanding issues
                            // (e.g. timeouts and state changes).
                            Self::try_finalize(
                                self.inner.clone(),
                                rounds.get(&contract_id).unwrap().clone(),
                            );
                        }
                        _ => {
                            error!("Failed to recover round state!");
                            measure_counter_inc!("failed_crash_recoveries");
                        }
                    }

                    // NB: We can't also store and restore the event and block
                    //     subscribers, since they include channels for submitting
                    //     results back, so all subscribers should resubscribe!
                }
                _ => {
                    // Clean shutdown or first run.
                    state_storage
                        .insert("node_running", vec![1])
                        .expect("local storage DB error");
                }
            }
        }

        info!("Starting dummy root hash backend");

        // Create command processing channel.
        let command_receiver = self.inner
            .command_receiver
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        let command_processor: BoxFuture<()> = {
            let shared_inner = self.inner.clone();

            command_receiver
                .map_err(|_| Error::new("command channel closed"))
                .for_each(move |command| -> BoxFuture<()> {
                    let shared_inner = shared_inner.clone();

                    // Decode command.
                    let (contract_id, sender, command): (
                        _,
                        _,
                        Box<Fn(_) -> _ + Send>,
                    ) = match command {
                        Command::Commit(contract_id, commitment, sender) => (
                            contract_id,
                            sender,
                            Box::new(move |round| {
                                Round::add_commitments(round, vec![commitment.clone()])
                            }),
                        ),
                    };

                    // Fetch the current round and process command.
                    Self::get_round(shared_inner.clone(), contract_id)
                        .and_then(move |round| {
                            command(round.clone())
                                .and_then(move |_| Self::try_finalize(shared_inner.clone(), round))
                        })
                        .then(move |result| {
                            drop(sender.send(result));

                            Ok(())
                        })
                        .into_box()
                })
                .into_box()
        };

        // Create shutdown signal handler.
        let shutdown_receiver = self.inner
            .shutdown_receiver
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        let shutdown = Box::new(shutdown_receiver.then(|_| Err(Error::new("shutdown"))));

        self.inner.environment.spawn(Box::new(
            future::join_all(vec![command_processor, shutdown]).then(|_| future::ok(())),
        ));
    }

    pub fn shutdown(&self) {
        info!("Shutting down dummy root hash backend");

        if let Some(state_storage) = self.inner.state_storage.clone() {
            // Mark that we've cleanly shut down.
            state_storage
                .remove("node_running")
                .expect("local storage DB error");

            // Remove any lingering round_state.
            drop(state_storage.remove("round_state"));
        }

        if let Some(shutdown_sender) = self.inner.shutdown_sender.lock().unwrap().take() {
            drop(shutdown_sender.send(()));
        }
    }

    fn get_genesis_block(contract_id: B256) -> Block {
        let mut block = Block {
            header: Header {
                version: 0,
                namespace: contract_id,
                round: U256::from(0),
                previous_hash: H256::zero(),
                group_hash: H256::zero(),
                input_hash: empty_hash(),
                output_hash: empty_hash(),
                state_root: empty_hash(),
                commitments_hash: H256::zero(),
            },
            computation_group: vec![],
            commitments: vec![],
        };

        block.update();
        block
    }

    /// Send a command to the backend task.
    fn send_command(
        &self,
        command: Command,
        receiver: oneshot::Receiver<Result<()>>,
    ) -> BoxFuture<()> {
        if let Err(_) = self.inner.command_sender.unbounded_send(command) {
            return Box::new(future::err(Error::new("command channel closed")));
        }

        Box::new(receiver.then(|result| match result {
            Ok(result) => result,
            Err(_) => Err(Error::new("response channel closed")),
        }))
    }

    /// Get or create round for specified contract.
    fn get_round(inner: Arc<Inner>, contract_id: B256) -> BoxFuture<Arc<Mutex<Round>>> {
        Box::new(
            inner
                .scheduler
                .get_committees(contract_id)
                .and_then(move |mut committees| {
                    // Get the computation committee.
                    let committee = committees
                        .drain(..)
                        .filter(|c| c.kind == CommitteeType::Compute)
                        .next();
                    if let Some(committee) = committee {
                        let block = {
                            let mut blocks = inner.blocks.lock().unwrap();

                            if blocks.contains_key(&contract_id) {
                                // Get last block.
                                let blocks = blocks.get(&contract_id).unwrap();
                                blocks.last().unwrap().clone()
                            } else {
                                // No blockchain yet for this contract. Create a new one.
                                let block = Self::get_genesis_block(contract_id);
                                blocks.insert(contract_id.clone(), vec![block.clone()]);

                                if let Some(state_storage) = inner.state_storage.clone() {
                                    // Save block to local storage for recovery.
                                    state_storage
                                        .insert(
                                            &format!("block_{}", &contract_id),
                                            serde_cbor::to_vec(&vec![block.clone()]).unwrap(),
                                        )
                                        .expect("local storage DB error");
                                    state_storage
                                        .insert(
                                            "latest_block_hash",
                                            serde_cbor::to_vec(&contract_id).unwrap(),
                                        )
                                        .expect("local storage DB error");
                                }

                                block
                            }
                        };

                        // Check if we already have a round and if the round is for the same committee/block.
                        let mut rounds = inner.rounds.lock().unwrap();

                        let existing_round = if rounds.contains_key(&contract_id) {
                            // Round already exists for this contract.
                            let shared_round = rounds.get(&contract_id).unwrap();
                            let round = shared_round.lock().unwrap();

                            if round.round_state.current_block == block
                                && round.round_state.committee == committee
                            {
                                // Existing round is the same.
                                Some(shared_round.clone())
                            } else {
                                // New round needed as either block or committee has changed.
                                None
                            }
                        } else {
                            // No round exists for this contract.
                            None
                        };

                        match existing_round {
                            Some(round) => {
                                if let Some(state_storage) = inner.state_storage.clone() {
                                    // Save round state to local storage for recovery.
                                    state_storage
                                        .insert(
                                            "round_state",
                                            serde_cbor::to_vec(&round.lock().unwrap().round_state)
                                                .unwrap(),
                                        )
                                        .expect("local storage DB error");
                                }

                                future::ok(round).into_box()
                            }
                            None => {
                                // Fetch contract metadata and then create a new round.
                                let inner = inner.clone();
                                inner
                                    .contract_registry
                                    .get_contract(contract_id)
                                    .and_then(move |contract| {
                                        let mut rounds = inner.rounds.lock().unwrap();

                                        let new_round = Arc::new(Mutex::new(Round::new(
                                            inner.storage.clone(),
                                            contract,
                                            committee,
                                            block,
                                        )));
                                        rounds.insert(contract_id, new_round.clone());

                                        if let Some(state_storage) = inner.state_storage.clone() {
                                            // Save round state to local storage for recovery.
                                            state_storage
	                                            .insert(
	                                                "round_state",
	                                                serde_cbor::to_vec(
	                                                    &new_round.lock().unwrap().round_state,
	                                                ).unwrap(),
	                                            )
                                                .expect("local storage DB error");
                                        }

                                        Ok(new_round)
                                    })
                                    .into_box()
                            }
                        }
                    } else {
                        // No compute committee, this is an error.
                        error!("No compute committee received for current round");
                        panic!("scheduler gave us no compute committee");
                    }
                }),
        )
    }

    /// Attempt to finalize the current round.
    fn try_finalize(inner: Arc<Inner>, round: Arc<Mutex<Round>>) -> BoxFuture<()> {
        let round_clone = round.clone();
        let mut round_guard = round_clone.lock().unwrap();
        let inner = inner.clone();
        let contract_id = round_guard
            .round_state
            .current_block
            .header
            .namespace
            .clone();

        Box::new(round_guard.try_finalize().then(move |result| {
            match result {
                Ok(FinalizationResult::Finalized(block)) => {
                    // Round has been finalized, block is ready.
                    {
                        let mut blocks = inner.blocks.lock().unwrap();
                        let mut blockchain = blocks.get_mut(&contract_id).unwrap();
                        blockchain.push(block.clone());
                    }

                    inner.block_subscribers.notify(&block);

                    if let Some(state_storage) = inner.state_storage.clone() {
                        // Save blockchain to local storage for recovery.
                        state_storage
                            .insert(
                                &format!("block_{}", &contract_id),
                                serde_cbor::to_vec(&inner
                                    .blocks
                                    .lock()
                                    .unwrap()
                                    .get(&contract_id)
                                    .unwrap())
                                    .unwrap(),
                            )
                            .expect("local storage DB error");
                        state_storage
                            .insert(
                                "latest_block_hash",
                                serde_cbor::to_vec(&contract_id).unwrap(),
                            )
                            .expect("local storage DB error");
                    }
                }
                Ok(FinalizationResult::StillWaiting(done_count)) if done_count >= 1 => {
                    // Still waiting for some round participants.
                    Round::start_timer(round.clone(), ROUND_AFTER_COMMIT_TIMEOUT, move || {
                        warn!("Commit timer expired, forcing finalization");
                        measure_counter_inc!("commit_timer_expired_count");
                        Self::try_finalize(inner, round.clone())
                    });
                }
                Ok(FinalizationResult::StillWaiting(_)) => {
                    // Still waiting for some round participants.
                }
                Ok(FinalizationResult::DiscrepancyDetected(batch_hash)) => {
                    // Notify round participants that a discrepancy has been detected.
                    inner
                        .event_subscribers
                        .notify(&(contract_id.clone(), Event::DiscrepancyDetected(batch_hash)));
                }
                Err(error) => {
                    // Round has failed.
                    error!("Round has failed: {:?}", error);
                    measure_counter_inc!("failed_rounds");

                    {
                        let mut round = round.lock().unwrap();
                        round.reset();

                        if let Some(state_storage) = inner.state_storage.clone() {
                            // Save round state to local storage for recovery.
                            state_storage
                                .insert(
                                    "round_state",
                                    serde_cbor::to_vec(&round.round_state).unwrap(),
                                )
                                .expect("local storage DB error");
                        }
                    }

                    inner
                        .event_subscribers
                        .notify(&(contract_id.clone(), Event::RoundFailed(error)));
                }
            }

            Ok(())
        }))
    }
}

impl RootHashBackend for DummyRootHashBackend {
    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block> {
        let (sender, receiver) = self.inner.block_subscribers.subscribe();
        {
            let mut blocks = self.inner.blocks.lock().unwrap();
            let block = if blocks.contains_key(&contract_id) {
                let blockchain = blocks.get(&contract_id).unwrap();
                blockchain.last().expect("empty blockchain").clone()
            } else {
                // No blockchain yet for this contract. Create a new one.
                let block = Self::get_genesis_block(contract_id);
                blocks.insert(contract_id.clone(), vec![block.clone()]);

                if let Some(state_storage) = self.inner.state_storage.clone() {
                    // Save block to local storage for recovery.
                    state_storage
                        .insert(
                            &format!("block_{}", &contract_id),
                            serde_cbor::to_vec(&vec![block.clone()]).unwrap(),
                        )
                        .expect("local storage DB error");
                    state_storage
                        .insert(
                            "latest_block_hash",
                            serde_cbor::to_vec(&contract_id).unwrap(),
                        )
                        .expect("local storage DB error");
                }

                block
            };

            drop(sender.unbounded_send(block));
        }

        receiver
            .filter(move |block| block.header.namespace == contract_id)
            .into_box()
    }

    fn get_blocks_since(&self, contract_id: B256, round: U256) -> BoxStream<Block> {
        let (sender, receiver) = self.inner.block_subscribers.subscribe();
        {
            let blocks = self.inner.blocks.lock().unwrap();
            if blocks.contains_key(&contract_id) {
                let blockchain = blocks.get(&contract_id).unwrap();
                // TODO: check overflow lol
                let round_usize = round.0.low_u64() as usize;
                if round_usize >= blockchain.len() {
                    return stream::once(Err(Error::new(
                        "Dummy root hash backend: don't have this block yet",
                    ))).into_box();
                }
                let block_slice = &blockchain[round_usize..];
                assert!(block_slice.len() > 0);
                assert_eq!(block_slice[0].header.round, round);
                block_slice.iter().for_each(|block| {
                    drop(sender.unbounded_send(block.clone()));
                });
            } else {
                // Otherwise, no blockchain yet for this contract.
                // Could possibly define this to wait until a round and then start.
                return stream::once(Err(Error::new(
                    "Dummy root hash backend: don't have this contract",
                ))).into_box();
            };
        }

        receiver
            .filter(move |block| block.header.namespace == contract_id)
            .into_box()
    }

    fn get_events(&self, contract_id: B256) -> BoxStream<Event> {
        self.inner
            .event_subscribers
            .subscribe()
            .1
            .filter(move |&(cid, _)| cid == contract_id)
            .map(|(_, event)| event)
            .into_box()
    }

    fn commit(&self, contract_id: B256, commitment: OpaqueCommitment) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        let commitment = match commitment.try_into() {
            Ok(commitment) => commitment,
            Err(error) => return future::err(error).into_box(),
        };

        self.send_command(Command::Commit(contract_id, commitment, sender), receiver)
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "roothash-backend",
    DummyRootHashBackend,
    RootHashBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment = container.inject()?;
        let scheduler = container.inject()?;
        let storage = container.inject()?;
        let contract_registry = container.inject()?;

        let args = container.get_arguments().unwrap();
        let local_db_path = args.value_of("roothash-storage-path");

        let backend = DummyRootHashBackend::new(
            environment,       // Environment
            scheduler,         // Scheduler
            storage,           // StorageBackend
            contract_registry, // ContractRegistryBackend
            local_db_path,     // Optional local persistent storage DB path
        );

        let instance: Arc<RootHashBackend> = Arc::new(backend);
        Ok(Box::new(instance))
    }),
    [Arg::with_name("roothash-storage-path")
        .long("roothash-storage-path")
        .help("Path to local state storage directory for root hash backend crash recovery")
        .takes_value(true)]
);
