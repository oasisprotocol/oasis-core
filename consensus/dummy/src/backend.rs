//! Dummy consensus backend.
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
use ekiden_consensus_base::{Block, Commitment as OpaqueCommitment, ConsensusBackend, Event, Header};
use ekiden_registry_base::ContractRegistryBackend;
use ekiden_scheduler_base::{Committee, CommitteeNode, CommitteeType, Role, Scheduler};
use ekiden_storage_base::StorageBackend;

use super::commitment::Commitment;

/// Hard time limit for a round after at least one node has sent a commitment.
const ROUND_AFTER_COMMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Round state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// State needed for managing a protocol round.
struct Round {
    /// Storage backend.
    storage: Arc<StorageBackend>,
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
            storage,
            contract,
            committee,
            computation_group,
            commitments: HashMap::new(),
            current_block: block,
            state: State::WaitingCommitments,
            timer_handle: None,
            timeout: false,
        }
    }

    /// Reset round.
    fn reset(&mut self) {
        self.commitments.clear();
        self.state = State::WaitingCommitments;
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
                let node = match round.computation_group.get(&node_id) {
                    Some(node) => node,
                    None => {
                        results.push(
                            future::err(Error::new("node not part of computation group"))
                                .into_box(),
                        );
                        continue;
                    }
                };

                match (node.role, round.state) {
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
            if round.commitments.contains_key(&node_id) {
                results.push(future::err(Error::new("node already sent commitment")).into_box());
                continue;
            }

            // Check if block is based on the previous block.
            if !header.is_parent_of(&round.current_block.header) {
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
                        round.commitments.insert(node_id, commitment);

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
        let num_sent = self.commitments
            .iter()
            .filter(|&(id, _)| {
                let node = self.computation_group.get(id).unwrap();
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
        self.computation_group
            .iter()
            .filter(|&(_, node)| node.role == Role::Worker || node.role == Role::Leader)
            .count() as u64
    }

    /// Return the number of backup nodes (backup worker) in the computation group.
    fn get_backup_node_count(&self) -> u64 {
        self.computation_group
            .iter()
            .filter(|&(_, node)| node.role == Role::BackupWorker)
            .count() as u64
    }

    /// Return the number of primary nodes required to respond.
    fn get_required_primary_count(&self) -> u64 {
        // While a timer is running, all nodes are required to answer. After a timeout
        // we allow some stragglers.
        if self.timeout {
            self.get_primary_node_count() - self.contract.replica_allowed_stragglers
        } else {
            self.get_primary_node_count()
        }
    }

    /// Return the number of backup nodes required to respond.
    fn get_required_backup_count(&self) -> u64 {
        // While a timer is running, all nodes are required to answer. After a timeout
        // we allow some stragglers.
        if self.timeout {
            self.get_backup_node_count() - self.contract.replica_allowed_stragglers
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
        match self.state {
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
        let header = match self.state {
            State::WaitingCommitments => {
                info!("Attempting to finalize round");

                // Check for discrepancies between computed results.
                let mut header = None;
                let mut discrepancy_detected = false;
                for (node_id, node) in self.computation_group.iter() {
                    if node.role == Role::BackupWorker {
                        continue;
                    }

                    let commitment = match self.commitments.get(node_id) {
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

                    // Activate the backup workers.
                    let input_hash = header.input_hash;
                    self.state = State::DiscrepancyWaitingCommitments;
                    return future::ok(FinalizationResult::DiscrepancyDetected(input_hash))
                        .into_box();
                }

                header
            }
            State::DiscrepancyWaitingCommitments => {
                info!("Attempting to finalize discrepancy resolution round");

                // Tally votes.
                let mut votes: HashMap<Header, u64> = HashMap::new();

                for (node_id, node) in self.computation_group.iter() {
                    if node.role != Role::BackupWorker {
                        continue;
                    }

                    let commitment = self.commitments.get(node_id).unwrap();
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
        let mut block = Block::new_parent_of(&self.current_block);
        block.header = header;
        block.computation_group = self.committee.members.clone();
        for node in &self.committee.members {
            block.commitments.push(
                self.commitments
                    .get(&node.public_key)
                    .cloned()
                    .map(|commitment| commitment.into()),
            );
        }
        block.update();

        info!("Round has been finalized");
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
}

/// A dummy consensus backend which simulates consensus in memory.
///
/// **This backend should only be used to test implementations that use the consensus
/// interface but it only simulates a consensus backend.***
pub struct DummyConsensusBackend {
    inner: Arc<Inner>,
}

impl DummyConsensusBackend {
    /// Create new dummy consensus backend.
    pub fn new(
        environment: Arc<Environment>,
        scheduler: Arc<Scheduler>,
        storage: Arc<StorageBackend>,
        contract_registry: Arc<ContractRegistryBackend>,
    ) -> Self {
        // Create channels.
        let (command_sender, command_receiver) = mpsc::unbounded();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

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
            }),
        };
        instance.start();

        instance
    }

    fn start(&self) {
        info!("Starting dummy consensus backend");

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
        info!("Shutting down dummy consensus backend");

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

                                block
                            }
                        };

                        // Check if we already have a round and if the round is for the same committee/block.
                        let mut rounds = inner.rounds.lock().unwrap();

                        let existing_round = if rounds.contains_key(&contract_id) {
                            // Round already exists for this contract.
                            let shared_round = rounds.get(&contract_id).unwrap();
                            let round = shared_round.lock().unwrap();

                            if round.current_block == block && round.committee == committee {
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
                            Some(round) => future::ok(round).into_box(),
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
        let contract_id = round_guard.current_block.header.namespace.clone();

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
                }
                Ok(FinalizationResult::StillWaiting(done_count)) if done_count >= 1 => {
                    // Still waiting for some round participants.
                    Round::start_timer(round.clone(), ROUND_AFTER_COMMIT_TIMEOUT, move || {
                        warn!("Commit timer expired, forcing finalization");
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

                    {
                        let mut round = round.lock().unwrap();
                        round.reset();
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

impl ConsensusBackend for DummyConsensusBackend {
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

                block
            };

            drop(sender.unbounded_send(block));
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
    "consensus-backend",
    DummyConsensusBackend,
    ConsensusBackend,
    [
        Environment,
        Scheduler,
        StorageBackend,
        ContractRegistryBackend
    ]
);
