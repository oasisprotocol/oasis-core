//! Ekiden dummy consensus backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture, BoxStream, Executor, Future, Stream};
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_common::signature::Signed;
use ekiden_common::uint::U256;
use ekiden_consensus_base::*;

/// Round state.
#[derive(Eq, PartialEq)]
enum State {
    WaitingCommitments,
    WaitingRevealsAndBlock,
}

/// Try finalize result.
#[derive(Eq, PartialEq)]
enum FinalizationResult {
    StillWaiting,
    NotifyReveals,
    Finalized(Block),
}

/// State needed for managing a protocol round.
struct Round {
    /// Computation group, mapped by public key hashes.
    computation_group: HashMap<B256, CommitteeNode>,
    /// Commitments from computation group nodes.
    commitments: HashMap<B256, Commitment>,
    /// Reveals from computation group nodes.
    reveals: HashMap<B256, Reveal<Header>>,
    /// Current block.
    current_block: Block,
    /// Next block.
    next_block: Option<Block>,
    /// Round state.
    state: State,
}

impl Round {
    /// Create new round descriptor.
    fn new(block: Block) -> Self {
        // Index computation group members by their public key hash.
        let mut computation_group_map = HashMap::new();
        for node in &block.computation_group {
            computation_group_map.insert(node.public_key.clone(), node.clone());
        }

        Self {
            computation_group: computation_group_map,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            current_block: block,
            next_block: None,
            state: State::WaitingCommitments,
        }
    }

    /// Reset round.
    fn reset(&mut self, block: Option<Block>) {
        self.commitments.clear();
        self.reveals.clear();
        if let Some(block) = block {
            self.current_block = block;
        }
        self.next_block = None;
        self.state = State::WaitingCommitments;
    }

    /// Add new commitment from a node in this round.
    fn add_commitment(&mut self, commitment: Commitment) -> Result<()> {
        if self.state != State::WaitingCommitments {
            return Err(Error::new("commitment cannot be sent at this point"));
        }

        // Ensure commitment is from a valid compute node.
        let node_id = commitment.signature.public_key.clone();
        if !self.computation_group.contains_key(&node_id) {
            return Err(Error::new("node not part of computation group"));
        };

        if !commitment.verify() {
            return Err(Error::new("commitment has invalid signature"));
        }

        // Ensure node did not already submit a commitment.
        if self.commitments.contains_key(&node_id) {
            return Err(Error::new("node already sent commitment"));
        }

        self.commitments.insert(node_id, commitment);

        Ok(())
    }

    /// Add new reveal from a node in this round.
    fn add_reveal(&mut self, reveal: Reveal<Header>) -> Result<()> {
        if self.state != State::WaitingRevealsAndBlock {
            return Err(Error::new("reveal cannot be sent at this point"));
        }

        // Ensure commitment is from a valid compute node.
        let node_id = reveal.signature.public_key.clone();
        if !self.computation_group.contains_key(&node_id) {
            return Err(Error::new("node not part of computation group"));
        };

        if !reveal.verify() {
            return Err(Error::new("reveal has invalid signature"));
        }

        // Ensure node submitted a commitment.
        if !self.commitments.contains_key(&node_id) {
            return Err(Error::new("node did not send commitment"));
        }

        // Ensure node did not already submit a reveal.
        if self.reveals.contains_key(&node_id) {
            return Err(Error::new("node already sent reveal"));
        }

        self.reveals.insert(node_id, reveal);

        Ok(())
    }

    /// Add new block submission from a leader in this round.
    fn add_submit(&mut self, block: Signed<Block>) -> Result<()> {
        if self.state != State::WaitingRevealsAndBlock {
            return Err(Error::new("block cannot be sent at this point"));
        }

        // Ensure commitment is from a valid compute node and that the node is a leader.
        let node_id = block.signature.public_key.clone();
        let node = match self.computation_group.get(&node_id) {
            Some(node) => node,
            None => return Err(Error::new("node not part of computation group")),
        };

        if node.role != Role::Leader {
            return Err(Error::new("node is not a leader"));
        }

        // Ensure block has a valid signature.
        let block = block.open(&BLOCK_SUBMIT_SIGNATURE_CONTEXT)?;

        // Ensure node did not already submit a block.
        if self.next_block.is_some() {
            return Err(Error::new("node already sent block"));
        }

        self.next_block = Some(block);

        Ok(())
    }

    /// Try to finalize the round.
    fn try_finalize(&mut self) -> Result<FinalizationResult> {
        // Check if all nodes sent commitments.
        if self.commitments.len() != self.computation_group.len() {
            info!("Still waiting for other round participants to commit");
            return Ok(FinalizationResult::StillWaiting);
        }

        if self.state == State::WaitingCommitments {
            info!("Commitments received, now waiting for reveals");
            self.state = State::WaitingRevealsAndBlock;
            return Ok(FinalizationResult::NotifyReveals);
        }

        // Check if all nodes sent reveals.
        if self.reveals.len() != self.computation_group.len() {
            info!("Still waiting for other round participants to reveal");
            return Ok(FinalizationResult::StillWaiting);
        }

        // Check if leader sent the block.
        let block = match self.next_block.take() {
            Some(block) => block,
            None => return Ok(FinalizationResult::StillWaiting),
        };

        // Everything is ready, try to finalize round.
        info!("Attempting to finalize round");
        for node_id in self.computation_group.keys() {
            let reveal = self.reveals.get(node_id).unwrap();
            let commitment = self.commitments.get(node_id).unwrap();

            if !reveal.verify_commitment(&commitment) {
                return Err(Error::new(format!(
                    "commitment from node {} does not match reveal",
                    node_id
                )));
            }

            if !reveal.verify_value(&block.header) {
                return Err(Error::new(format!(
                    "reveal from node {} does not match block",
                    node_id
                )));
            }
        }

        // Check if block was internally consistent.
        if !block.is_internally_consistent() {
            return Err(Error::new("submitted block is not internally consistent"));
        }

        // Check if block is based on the previous block.
        if !block.header.is_parent_of(&self.current_block.header) {
            return Err(Error::new("submitted block is not based on previous block"));
        }

        // TODO: Check if storage backend contains correct state root.

        info!("Round has been finalized");
        Ok(FinalizationResult::Finalized(block))
    }
}

#[derive(Debug)]
enum Command {
    Commit(Commitment, oneshot::Sender<Result<()>>),
    Reveal(Reveal<Header>, oneshot::Sender<Result<()>>),
    Submit(Signed<Block>, oneshot::Sender<Result<()>>),
}

struct DummyConsensusBackendInner {
    /// In-memory blockchain.
    blocks: Mutex<Vec<Block>>,
    /// Current round.
    round: Mutex<Round>,
    /// Block subscribers.
    block_subscribers: Mutex<Vec<mpsc::UnboundedSender<Block>>>,
    /// Event subscribers.
    event_subscribers: Mutex<Vec<mpsc::UnboundedSender<Event>>>,
    /// Shutdown signal sender (until used).
    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
    /// Shutdown signal receiver (until initialized).
    shutdown_receiver: Mutex<Option<oneshot::Receiver<()>>>,
    /// Command sender.
    command_sender: mpsc::UnboundedSender<Command>,
    /// Command receiver (until initialized).
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
}

impl DummyConsensusBackendInner {
    /// Notify subscribers of a new block.
    fn notify_block(&self, block: &Block) {
        let mut block_subscribers = self.block_subscribers.lock().unwrap();
        block_subscribers.retain(|ref s| s.unbounded_send(block.clone()).is_ok());
    }

    /// Notify subscribers of a new event.
    fn notify_event(&self, event: &Event) {
        let mut event_subscribers = self.event_subscribers.lock().unwrap();
        event_subscribers.retain(|ref s| s.unbounded_send(event.clone()).is_ok());
    }

    /// Attempt to finalize the current round.
    fn try_finalize(&self) {
        let mut round = self.round.lock().unwrap();
        let result = round.try_finalize();

        match result {
            Ok(FinalizationResult::Finalized(block)) => {
                // Round has been finalized, block is ready.
                {
                    let mut blocks = self.blocks.lock().unwrap();
                    blocks.push(block.clone());
                }

                round.reset(Some(block.clone()));
                self.notify_block(&block);
            }
            Ok(FinalizationResult::StillWaiting) => {
                // Still waiting for some round participants.
            }
            Ok(FinalizationResult::NotifyReveals) => {
                // Notify round participants that they should reveal.
                self.notify_event(&Event::CommitmentsReceived);
            }
            Err(error) => {
                // Round has failed.
                error!("Round has failed: {:?}", error);

                round.reset(None);
                self.notify_event(&Event::RoundFailed(error));
            }
        }
    }
}

/// A dummy consensus backend which simulates consensus in memory.
///
/// **This backend should only be used to test implementations that use the consensus
/// interface but it only simulates a consensus backend.***
pub struct DummyConsensusBackend {
    inner: Arc<DummyConsensusBackendInner>,
}

impl DummyConsensusBackend {
    /// Create new dummy consensus backend.
    pub fn new(computation_group: Vec<CommitteeNode>) -> Self {
        info!(
            "Creating dummy consensus backend with {} member(s) in computation group",
            computation_group.len()
        );
        let genesis_block = Self::get_genesis_block(computation_group);

        // Create channels.
        let (command_sender, command_receiver) = mpsc::unbounded();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        Self {
            inner: Arc::new(DummyConsensusBackendInner {
                blocks: Mutex::new(vec![genesis_block.clone()]),
                round: Mutex::new(Round::new(genesis_block)),
                block_subscribers: Mutex::new(vec![]),
                event_subscribers: Mutex::new(vec![]),
                shutdown_sender: Mutex::new(Some(shutdown_sender)),
                shutdown_receiver: Mutex::new(Some(shutdown_receiver)),
                command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
            }),
        }
    }

    fn get_genesis_block(computation_group: Vec<CommitteeNode>) -> Block {
        let mut block = Block {
            header: Header {
                version: 0,
                namespace: B256::zero(),
                round: U256::from(0),
                previous_hash: H256::zero(),
                group_hash: H256::zero(),
                transaction_hash: H256::zero(),
                state_root: H256::zero(),
                commitments_hash: H256::zero(),
            },
            computation_group,
            transactions: vec![],
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
}

impl ConsensusBackend for DummyConsensusBackend {
    fn start(&self, executor: &mut Executor) {
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

            Box::new(
                command_receiver
                    .map_err(|_| Error::new("command channel closed"))
                    .for_each(move |command| -> BoxFuture<()> {
                        let (sender, result) = {
                            let mut round = shared_inner.round.lock().unwrap();

                            match command {
                                Command::Commit(commitment, sender) => {
                                    (sender, round.add_commitment(commitment))
                                }
                                Command::Reveal(reveal, sender) => {
                                    (sender, round.add_reveal(reveal))
                                }
                                Command::Submit(block, sender) => (sender, round.add_submit(block)),
                            }
                        };

                        shared_inner.try_finalize();
                        drop(sender.send(result));

                        Box::new(future::ok(()))
                    }),
            )
        };

        // Create shutdown signal handler.
        let shutdown_receiver = self.inner
            .shutdown_receiver
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        let shutdown = Box::new(shutdown_receiver.then(|_| Err(Error::new("shutdown"))));

        executor.spawn(Box::new(
            future::join_all(vec![command_processor, shutdown]).then(|_| future::ok(())),
        ));
    }

    fn shutdown(&self) {
        info!("Shutting down dummy consensus backend");

        if let Some(shutdown_sender) = self.inner.shutdown_sender.lock().unwrap().take() {
            drop(shutdown_sender.send(()));
        }
    }

    fn get_blocks(&self) -> BoxStream<Block> {
        let (sender, receiver) = mpsc::unbounded();
        {
            let blocks = self.inner.blocks.lock().unwrap();
            match blocks.last() {
                Some(block) => drop(sender.unbounded_send(block.clone())),
                None => {}
            }
        }

        let mut block_subscribers = self.inner.block_subscribers.lock().unwrap();
        block_subscribers.push(sender);

        Box::new(receiver.map_err(|_| Error::new("channel closed")))
    }

    fn get_events(&self) -> BoxStream<Event> {
        let (sender, receiver) = mpsc::unbounded();
        let mut event_subscribers = self.inner.event_subscribers.lock().unwrap();
        event_subscribers.push(sender);

        Box::new(receiver.map_err(|_| Error::new("channel closed")))
    }

    fn commit(&self, commitment: Commitment) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        self.send_command(Command::Commit(commitment, sender), receiver)
    }

    fn reveal(&self, reveal: Reveal<Header>) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        self.send_command(Command::Reveal(reveal, sender), receiver)
    }

    fn submit(&self, block: Signed<Block>) -> BoxFuture<()> {
        let (sender, receiver) = oneshot::channel();
        self.send_command(Command::Submit(block, sender), receiver)
    }
}
