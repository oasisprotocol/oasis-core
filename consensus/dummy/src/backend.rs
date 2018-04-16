//! Ekiden dummy consensus backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture, BoxStream, Stream};
use ekiden_common::futures::sync::mpsc;
use ekiden_common::ring::digest;
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
    computation_group: HashMap<H256, CommitteeNode>,
    /// Commitments from computation group nodes.
    commitments: HashMap<H256, Commitment>,
    /// Reveals from computation group nodes.
    reveals: HashMap<H256, Reveal<Header>>,
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
            computation_group_map.insert(
                H256::from(digest::digest(&digest::SHA512_256, &node.public_key).as_ref()),
                node.clone(),
            );
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
        let node_id = commitment.signature.public_key_id.clone();
        let node = match self.computation_group.get(&node_id) {
            Some(node) => node,
            None => return Err(Error::new("node not part of computation group")),
        };

        if !commitment.verify(&node.get_verifier()) {
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
        let node_id = reveal.signature.public_key_id.clone();
        let node = match self.computation_group.get(&node_id) {
            Some(node) => node,
            None => return Err(Error::new("node not part of computation group")),
        };

        if !reveal.verify(&node.get_verifier()) {
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
        let node_id = block.signature.public_key_id.clone();
        let node = match self.computation_group.get(&node_id) {
            Some(node) => node,
            None => return Err(Error::new("node not part of computation group")),
        };

        if node.role != Role::Leader {
            return Err(Error::new("node is not a leader"));
        }

        // Ensure block has a valid signature.
        let block = block.open(&node.get_verifier(), &BLOCK_SUBMIT_SIGNATURE_CONTEXT)?;

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
            return Ok(FinalizationResult::StillWaiting);
        }

        if self.state == State::WaitingCommitments {
            self.state = State::WaitingRevealsAndBlock;
            return Ok(FinalizationResult::NotifyReveals);
        }

        // Check if all nodes sent reveals.
        if self.reveals.len() != self.computation_group.len() {
            return Ok(FinalizationResult::StillWaiting);
        }

        // Check if leader sent the block.
        let block = match self.next_block.take() {
            Some(block) => block,
            None => return Ok(FinalizationResult::StillWaiting),
        };

        // Everything is ready, try to finalize round.
        for (node_id, node) in &self.computation_group {
            let reveal = self.reveals.get(node_id).unwrap();
            let commitment = self.commitments.get(node_id).unwrap();

            if !reveal.verify_commitment(&node.get_verifier(), &commitment) {
                return Err(Error::new(format!(
                    "commitment from node {} does not match reveal",
                    node_id
                )));
            }

            if !reveal.verify_value(&node.get_verifier(), &block.header) {
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

        Ok(FinalizationResult::Finalized(block))
    }
}

struct DummyConsensusBackendInner {
    /// In-memory blockchain.
    blocks: Vec<Block>,
    /// Current round.
    round: Round,
    /// Block subscribers.
    block_subscribers: Vec<mpsc::UnboundedSender<Block>>,
    /// Event subscribers.
    event_subscribers: Vec<mpsc::UnboundedSender<Event>>,
}

impl DummyConsensusBackendInner {
    /// Notify subscribers of a new block.
    fn notify_block(&mut self, block: &Block) {
        self.block_subscribers
            .retain(|ref s| s.unbounded_send(block.clone()).is_ok());
    }

    /// Notify subscribers of a new event.
    fn notify_event(&mut self, event: &Event) {
        self.event_subscribers
            .retain(|ref s| s.unbounded_send(event.clone()).is_ok());
    }

    /// Attempt to finalize the current round.
    fn try_finalize(&mut self) {
        let result = self.round.try_finalize();

        match result {
            Ok(FinalizationResult::Finalized(block)) => {
                // Round has been finalized, block is ready.
                self.blocks.push(block.clone());
                self.round.reset(Some(block.clone()));
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
                self.round.reset(None);
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
    inner: Arc<Mutex<DummyConsensusBackendInner>>,
}

impl DummyConsensusBackend {
    pub fn new(computation_group: Vec<CommitteeNode>) -> Self {
        let genesis_block = Self::get_genesis_block(computation_group);

        Self {
            inner: Arc::new(Mutex::new(DummyConsensusBackendInner {
                blocks: vec![genesis_block.clone()],
                round: Round::new(genesis_block),
                block_subscribers: vec![],
                event_subscribers: vec![],
            })),
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
}

impl ConsensusBackend for DummyConsensusBackend {
    fn get_blocks(&self) -> BoxStream<Block> {
        let mut inner = self.inner.lock().unwrap();

        let (sender, receiver) = mpsc::unbounded();
        match inner.blocks.last() {
            Some(block) => sender.unbounded_send(block.clone()).unwrap(),
            None => {}
        }
        inner.block_subscribers.push(sender);

        Box::new(receiver.map_err(|_| Error::new("channel closed")))
    }

    fn get_events(&self) -> BoxStream<Event> {
        let mut inner = self.inner.lock().unwrap();

        let (sender, receiver) = mpsc::unbounded();
        inner.event_subscribers.push(sender);

        Box::new(receiver.map_err(|_| Error::new("channel closed")))
    }

    fn commit(&self, commitment: Commitment) -> BoxFuture<()> {
        let inner = self.inner.clone();

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.round.add_commitment(commitment)?;
            inner.try_finalize();

            Ok(())
        }))
    }

    fn reveal(&self, reveal: Reveal<Header>) -> BoxFuture<()> {
        let inner = self.inner.clone();

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.round.add_reveal(reveal)?;
            inner.try_finalize();

            Ok(())
        }))
    }

    fn submit(&self, block: Signed<Block>) -> BoxFuture<()> {
        let inner = self.inner.clone();

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.round.add_submit(block)?;
            inner.try_finalize();

            Ok(())
        }))
    }
}
