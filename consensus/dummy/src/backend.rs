//! Dummy consensus backend.
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_common::hash::empty_hash;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_common::uint::U256;
use ekiden_consensus_base::{Block, Commitment as OpaqueCommitment, ConsensusBackend, Event,
                            Header, Reveal as OpaqueReveal};
use ekiden_scheduler_base::{Committee, CommitteeNode, CommitteeType, Role, Scheduler};
use ekiden_storage_base::StorageBackend;

use super::commitment::{Commitment, Reveal};

/// Round state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    WaitingCommitments,
    WaitingReveals,
    DiscrepancyWaitingCommitments,
    DiscrepancyWaitingReveals,
}

/// Try finalize result.
#[derive(Eq, PartialEq)]
enum FinalizationResult {
    StillWaiting,
    NotifyReveals(bool),
    Finalized(Block),
    DiscrepancyDetected(H256),
}

/// State needed for managing a protocol round.
struct Round {
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Computation committee.
    committee: Committee,
    /// Computation group, mapped by public key hashes.
    computation_group: HashMap<B256, CommitteeNode>,
    /// Commitments from computation group nodes.
    commitments: HashMap<B256, Commitment>,
    /// Reveals from computation group nodes.
    reveals: HashMap<B256, Reveal<Header>>,
    /// Current block.
    current_block: Block,
    /// Round state.
    state: State,
}

impl Round {
    /// Create new round descriptor.
    fn new(storage: Arc<StorageBackend>, committee: Committee, block: Block) -> Self {
        // Index computation group members by their public key hash.
        let mut computation_group = HashMap::new();
        for node in &committee.members {
            computation_group.insert(node.public_key.clone(), node.clone());
        }

        Self {
            storage,
            committee,
            computation_group,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            current_block: block,
            state: State::WaitingCommitments,
        }
    }

    /// Reset round.
    fn reset(&mut self) {
        self.commitments.clear();
        self.reveals.clear();
        self.state = State::WaitingCommitments;
    }

    /// Add new commitments from one or more nodes in this round.
    fn add_commitments(
        round: Arc<Mutex<Round>>,
        commitments: &[Commitment],
    ) -> BoxFuture<Vec<Result<()>>> {
        let mut round = round.lock().unwrap();

        // We're going to store the resulting futures for each commitment.
        let mut results: Vec<BoxFuture<()>> = Vec::with_capacity(commitments.len());

        for commitment in commitments.iter() {
            // Ensure each commitment is from a valid compute node and that we are in correct state.
            let node_id = commitment.signature.public_key.clone();
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

            if !commitment.verify() {
                results
                    .push(future::err(Error::new("commitment has invalid signature")).into_box());
                continue;
            }

            // Ensure node did not already submit a commitment.
            if round.commitments.contains_key(&node_id) {
                results.push(future::err(Error::new("node already sent commitment")).into_box());
                continue;
            }

            round.commitments.insert(node_id, commitment.clone());

            results.push(future::ok(()).into_box());
        }

        // Return a future returning a vector of results of the above futures
        // in the same order as the commitments were given.
        stream::futures_ordered(results)
            .then(|r| Ok(r))
            .collect()
            .into_box()
    }

    /// Add new reveals from one or more nodes in this round.
    fn add_reveals(
        round: Arc<Mutex<Round>>,
        reveals: Vec<Reveal<Header>>,
    ) -> BoxFuture<Vec<Result<()>>> {
        // We're going to store the resulting futures for each reveal.
        let mut results: Vec<BoxFuture<()>> = Vec::with_capacity(reveals.len());

        for reveal in reveals.iter() {
            let shared_round = round.clone();
            let round = round.lock().unwrap();
            let reveal = reveal.clone();

            // Ensure each reveal is from a valid compute node and that we are in correct state.
            let node_id = reveal.signature.public_key.clone();
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
                    (Role::Worker, State::WaitingReveals)
                    | (Role::Leader, State::WaitingReveals) => {}

                    (Role::BackupWorker, State::DiscrepancyWaitingReveals) => {}

                    _ => {
                        results.push(
                            future::err(Error::new("node has incorrect role for current state"))
                                .into_box(),
                        );
                        continue;
                    }
                }
            }

            if !reveal.verify() {
                results.push(future::err(Error::new("reveal has invalid signature")).into_box());
                continue;
            }

            // Ensure node submitted a commitment.
            if !round.commitments.contains_key(&node_id) {
                results.push(future::err(Error::new("node did not send commitment")).into_box());
                continue;
            }

            // Ensure node did not already submit a reveal.
            if round.reveals.contains_key(&node_id) {
                results.push(future::err(Error::new("node already sent reveal")).into_box());
                continue;
            }

            // Check if block is based on the previous block.
            if !reveal.value.is_parent_of(&round.current_block.header) {
                results.push(
                    future::err(Error::new(
                        "submitted header is not based on previous block",
                    )).into_box(),
                );
                continue;
            }

            let mut storage_checks = vec![];

            // Check if storage backend contains correct input batch.
            if reveal.value.input_hash != empty_hash() {
                storage_checks.push(
                    round
                        .storage
                        .get(reveal.value.input_hash)
                        .map_err(|_error| Error::new("inputs not found in storage"))
                        .into_box(),
                );
            }

            // Check if storage backend contains correct output batch.
            if reveal.value.output_hash != empty_hash() {
                storage_checks.push(
                    round
                        .storage
                        .get(reveal.value.output_hash)
                        .map_err(|_error| Error::new("outputs not found in storage"))
                        .into_box(),
                );
            }

            // Check if storage backend contains correct state root.
            // TODO: Currently we just check a single key, we would need to check against a log.
            if reveal.value.state_root != empty_hash() {
                storage_checks.push(
                    round
                        .storage
                        .get(reveal.value.state_root)
                        .map_err(|_error| Error::new("state root not found in storage"))
                        .into_box(),
                );
            }

            results.push(
                future::join_all(storage_checks)
                    .and_then(move |_| {
                        let mut round = shared_round.lock().unwrap();
                        round.reveals.insert(node_id, reveal);

                        Ok(())
                    })
                    .into_box(),
            );
        }

        // Return a future returning a vector of results of the above futures
        // in the same order as the reveals were given.
        stream::futures_ordered(results)
            .then(|r| Ok(r))
            .collect()
            .into_box()
    }

    /// Try to finalize the round.
    fn try_finalize(&mut self) -> BoxFuture<FinalizationResult> {
        let num_nodes = self.computation_group.len();
        let num_primary = self.computation_group
            .iter()
            .filter(|&(_, node)| node.role == Role::Worker || node.role == Role::Leader)
            .count();
        let num_backup = num_nodes - num_primary;

        // Check if all nodes sent commitments.
        match self.state {
            State::WaitingCommitments => {
                if self.commitments.len() != num_primary {
                    info!("Still waiting for workers to commit");
                    return Box::new(future::ok(FinalizationResult::StillWaiting));
                } else {
                    info!("Commitments received, now waiting for reveals from workers");
                    self.state = State::WaitingReveals;
                    return Box::new(future::ok(FinalizationResult::NotifyReveals(false)));
                }
            }
            State::DiscrepancyWaitingCommitments => {
                if self.commitments.len() != num_nodes {
                    info!("Still waiting for backup workers to commit");
                    return Box::new(future::ok(FinalizationResult::StillWaiting));
                } else {
                    info!("Commitments received, now waiting for reveals from backup workers");
                    self.state = State::DiscrepancyWaitingReveals;
                    return Box::new(future::ok(FinalizationResult::NotifyReveals(true)));
                }
            }
            _ => {}
        }

        // Check if all nodes sent reveals.
        match self.state {
            State::WaitingReveals => {
                if self.reveals.len() != num_primary {
                    info!("Still waiting for other workers to reveal");
                    return Box::new(future::ok(FinalizationResult::StillWaiting));
                }
            }
            State::DiscrepancyWaitingReveals => {
                if self.reveals.len() != num_nodes {
                    info!("Still waiting for other backup workers to reveal");
                    return Box::new(future::ok(FinalizationResult::StillWaiting));
                }
            }
            _ => unreachable!(),
        }

        // Everything is ready, try to finalize round.
        let header = match self.state {
            State::WaitingReveals => {
                info!("Attempting to finalize round");

                // Check for discrepancies between computed results.
                let mut header = None;
                let mut discrepancy_detected = false;
                for (node_id, node) in self.computation_group.iter() {
                    if node.role == Role::BackupWorker {
                        continue;
                    }

                    let reveal = self.reveals.get(node_id).unwrap();
                    let commitment = self.commitments.get(node_id).unwrap();

                    if header.is_none() {
                        header = Some(reveal.value.clone());
                    }

                    if !reveal.verify_commitment(&commitment) {
                        // TODO: Slash bond.
                        // TODO: Should we instead treat this as if the node didn't submit a commitment?
                        discrepancy_detected = true;
                        break;
                    }

                    if !reveal.verify_value(header.as_ref().unwrap()) {
                        discrepancy_detected = true;
                        break;
                    }
                }

                let header = header.expect("there should be some reveals");

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
            State::DiscrepancyWaitingReveals => {
                info!("Attempting to finalize discrepancy resolution round");

                // Tally votes.
                let mut votes: HashMap<Header, usize> = HashMap::new();

                for (node_id, node) in self.computation_group.iter() {
                    if node.role != Role::BackupWorker {
                        continue;
                    }

                    let reveal = self.reveals.get(node_id).unwrap();
                    let commitment = self.commitments.get(node_id).unwrap();

                    if !reveal.verify_commitment(&commitment) {
                        // TODO: Slash bond.
                        break;
                    }

                    let vote = reveal.value.clone();
                    let count = *votes.get(&vote).unwrap_or(&0);
                    votes.insert(vote, count + 1);
                }

                let min_votes = (num_backup / 2) + 1;
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
            _ => unreachable!(),
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
    Reveal(B256, Reveal<Header>, oneshot::Sender<Result<()>>),
    CommitMany(B256, Vec<Commitment>, oneshot::Sender<Result<()>>),
    RevealMany(B256, Vec<Reveal<Header>>, oneshot::Sender<Result<()>>),
}

struct Inner {
    /// Environment.
    environment: Arc<Environment>,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Storage backend.
    storage: Arc<StorageBackend>,
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
    ) -> Self {
        // Create channels.
        let (command_sender, command_receiver) = mpsc::unbounded();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        let instance = Self {
            inner: Arc::new(Inner {
                environment,
                scheduler,
                storage,
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
                                Round::add_commitments(round, &vec![commitment.clone()])
                            }),
                        ),
                        Command::Reveal(contract_id, reveal, sender) => (
                            contract_id,
                            sender,
                            Box::new(move |round| Round::add_reveals(round, vec![reveal.clone()])),
                        ),
                        Command::CommitMany(contract_id, commitments, sender) => (
                            contract_id,
                            sender,
                            Box::new(move |round| Round::add_commitments(round, &commitments)),
                        ),
                        Command::RevealMany(contract_id, reveals, sender) => (
                            contract_id,
                            sender,
                            Box::new(move |round| Round::add_reveals(round, reveals.clone())),
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
                            Some(round) => Ok(round),
                            None => {
                                let new_round = Arc::new(Mutex::new(Round::new(
                                    inner.storage.clone(),
                                    committee,
                                    block,
                                )));
                                rounds.insert(contract_id.clone(), new_round.clone());

                                Ok(new_round)
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
                Ok(FinalizationResult::StillWaiting) => {
                    // Still waiting for some round participants.
                }
                Ok(FinalizationResult::NotifyReveals(discrepancy)) => {
                    // Notify round participants that they should reveal.
                    inner
                        .event_subscribers
                        .notify(&(contract_id.clone(), Event::CommitmentsReceived(discrepancy)));
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

    fn reveal(&self, contract_id: B256, reveal: OpaqueReveal) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        let reveal = match reveal.try_into() {
            Ok(reveal) => reveal,
            Err(error) => return future::err(error).into_box(),
        };

        self.send_command(Command::Reveal(contract_id, reveal, sender), receiver)
    }

    fn commit_many(
        &self,
        contract_id: B256,
        mut commitments: Vec<OpaqueCommitment>,
    ) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        let commitments = commitments
            .drain(..)
            .filter_map(|commitment| commitment.try_into().ok())
            .collect();
        self.send_command(
            Command::CommitMany(contract_id, commitments, sender),
            receiver,
        )
    }

    fn reveal_many(&self, contract_id: B256, mut reveals: Vec<OpaqueReveal>) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        let reveals = reveals
            .drain(..)
            .filter_map(|reveal| reveal.try_into().ok())
            .collect();
        self.send_command(Command::RevealMany(contract_id, reveals, sender), receiver)
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "consensus-backend",
    DummyConsensusBackend,
    ConsensusBackend,
    [Environment, Scheduler, StorageBackend]
);
