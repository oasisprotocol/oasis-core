//! Utilities for testing consensus backends.
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future, Stream};
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::untrusted;

use super::*;

/// Command sent to a simulated compute node.
pub enum Command {
    /// Computation has been received.
    Compute,
}

/// Simulated batch of contract invocations.
pub struct SimulatedComputationBatch {
    /// Block produced by the computation batch.
    block: Block,
    /// Nonce used for commitment.
    nonce: B256,
}

impl SimulatedComputationBatch {
    /// Create new simulated computation batch.
    pub fn new(child: Block) -> Self {
        let mut block = Block::new_parent_of(&child);
        // We currently just assume that the computation group is fixed.
        block.computation_group = child.computation_group;
        block.update();

        // TODO: Include some simulated transactions.

        Self {
            block,
            nonce: B256::random(),
        }
    }
}

struct SimulatedNodeInner {
    /// Public part of the simulated node.
    public: CommitteeNode,
    /// Signer for the simulated node.
    signer: InMemorySigner,
    /// Shutdown channel.
    shutdown_channel: Option<oneshot::Sender<()>>,
    /// Command channel.
    command_channel: Option<mpsc::UnboundedSender<Command>>,
    /// Current simulated computation.
    computation: Option<SimulatedComputationBatch>,
}

/// A simulated node.
pub struct SimulatedNode {
    inner: Arc<Mutex<SimulatedNodeInner>>,
}

impl SimulatedNode {
    /// Create new simulated node.
    pub fn new(role: Role) -> Self {
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let public_key = B256::from(key_pair.public_key_bytes());
        let signer = InMemorySigner::new(key_pair);

        Self {
            inner: Arc::new(Mutex::new(SimulatedNodeInner {
                public: CommitteeNode { role, public_key },
                signer,
                command_channel: None,
                computation: None,
                shutdown_channel: None,
            })),
        }
    }

    /// Get public descriptor for this node.
    pub fn get_public(&self) -> CommitteeNode {
        let inner = self.inner.lock().unwrap();
        inner.public.clone()
    }

    /// Start simulated node.
    pub fn start<T>(&self, backend: Arc<T>) -> BoxFuture<()>
    where
        T: ConsensusBackend + Send + Sync + 'static,
    {
        // Create a channel for external commands. This is currently required because
        // there is no service discovery backend which we could subscribe to.
        let (sender, receiver) = mpsc::unbounded();
        {
            let mut inner = self.inner.lock().unwrap();
            assert!(inner.command_channel.is_none());
            inner.command_channel.get_or_insert(sender);
        }

        // Subscribe to new events.
        let event_processor: BoxFuture<()> = {
            let shared_inner = self.inner.clone();
            let backend = backend.clone();

            Box::new(
                backend
                    .get_events()
                    .for_each(move |event| -> BoxFuture<()> {
                        let mut inner = shared_inner.lock().unwrap();

                        match event {
                            Event::CommitmentsReceived => {
                                // Generate reveal.
                                let computation = inner.computation.take().unwrap();
                                let reveal = Reveal::new(
                                    &inner.signer,
                                    &computation.nonce,
                                    &computation.block.header,
                                );

                                // Send reveal.
                                let result = backend.reveal(reveal);

                                // Leader also submits block.
                                if inner.public.role == Role::Leader {
                                    let backend = backend.clone();
                                    let shared_inner = shared_inner.clone();

                                    Box::new(result.and_then(move |_| {
                                        let inner = shared_inner.lock().unwrap();

                                        // Sign block.
                                        let block = Signed::sign(
                                            &inner.signer,
                                            &BLOCK_SUBMIT_SIGNATURE_CONTEXT,
                                            computation.block,
                                        );

                                        // Submit block.
                                        backend.submit(block)
                                    }))
                                } else {
                                    Box::new(result)
                                }
                            }
                            Event::RoundFailed(error) => {
                                // Round has failed, so the test should abort.
                                panic!("round failed: {}", error);
                            }
                        }
                    }),
            )
        };

        // Process commands.
        let command_processor: BoxFuture<()> = {
            let shared_inner = self.inner.clone();
            let backend = backend.clone();

            Box::new(
                receiver
                    .map_err(|_| Error::new("command channel closed"))
                    .for_each(move |command| -> BoxFuture<()> {
                        match command {
                            Command::Compute => {
                                // Fetch latest block.
                                let latest_block = backend.get_latest_block();

                                let shared_inner = shared_inner.clone();
                                let backend = backend.clone();

                                Box::new(latest_block.and_then(move |block| {
                                    let mut inner = shared_inner.lock().unwrap();

                                    // Start new computation.
                                    let computation = SimulatedComputationBatch::new(block);

                                    // Generate commitment.
                                    let commitment = Commitment::new(
                                        &inner.signer,
                                        &computation.nonce,
                                        &computation.block.header,
                                    );

                                    // Store computation.
                                    assert!(inner.computation.is_none());
                                    inner.computation.get_or_insert(computation);

                                    // Commit.
                                    backend.commit(commitment)
                                }))
                            }
                        }
                    }),
            )
        };

        // Create shutdown channel.
        let (sender, receiver) = oneshot::channel();
        {
            let mut inner = self.inner.lock().unwrap();
            assert!(inner.shutdown_channel.is_none());
            inner.shutdown_channel.get_or_insert(sender);
        }

        let shutdown = Box::new(receiver.then(|_| Err(Error::new("shutdown"))));

        let tasks =
            future::join_all(vec![event_processor, command_processor, shutdown]).then(|_| Ok(()));

        Box::new(tasks)
    }

    /// Simulate delivery of a new computation.
    pub fn compute(&self) {
        let inner = self.inner.lock().unwrap();
        let channel = inner.command_channel.as_ref().unwrap();
        channel.unbounded_send(Command::Compute).unwrap();
    }

    /// Shutdown node.
    pub fn shutdown(&self) {
        let mut inner = self.inner.lock().unwrap();
        let channel = inner.shutdown_channel.take().unwrap();
        drop(channel.send(()));
    }
}

/// Create a new simulated computation group of the given size.
pub fn create_computation_group(computation_group_size: usize) -> Vec<SimulatedNode> {
    let mut result = vec![];
    result.push(SimulatedNode::new(Role::Leader));
    for _ in 0..computation_group_size - 1 {
        result.push(SimulatedNode::new(Role::Worker));
    }

    result
}
