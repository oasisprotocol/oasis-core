//! Utilities for testing consensus backends.
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_common::hash::empty_hash;
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signer};
use ekiden_common::untrusted;
use ekiden_common::x509;
use ekiden_scheduler_base::{CommitteeType, Role, Scheduler};
use ekiden_storage_base::{hash_storage_key, StorageBackend};

use super::*;

/// Command sent to a simulated compute node.
pub enum Command {
    /// Computation has been received.
    Compute(Vec<u8>),
}

/// Simulated batch of contract invocations.
pub struct SimulatedComputationBatch {
    /// Block produced by the computation batch.
    block: Block,
    /// Nonce used for commitment.
    nonce: Nonce,
}

struct SimulatedNodeIdentity {
    signer: Arc<InMemorySigner>,
}

impl SimulatedNodeIdentity {
    pub fn new() -> Self {
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let signer = Arc::new(InMemorySigner::new(key_pair));

        Self { signer }
    }
}

impl NodeIdentity for SimulatedNodeIdentity {
    fn get_node(&self) -> Node {
        unimplemented!();
    }

    fn get_node_signer(&self) -> Arc<Signer> {
        self.signer.clone()
    }

    fn get_tls_certificate(&self) -> &x509::Certificate {
        unimplemented!();
    }

    fn get_tls_private_key(&self) -> &x509::PrivateKey {
        unimplemented!();
    }
}

struct SimulatedNodeInner {
    /// Contract identifier.
    contract_id: B256,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Node identity.
    identity: Arc<SimulatedNodeIdentity>,
    /// Shutdown channel.
    shutdown_channel: Mutex<Option<oneshot::Sender<()>>>,
    /// Shutdown receiver.
    shutdown_signal: Mutex<Option<oneshot::Receiver<()>>>,
    /// Command channel.
    command_channel: mpsc::UnboundedSender<Command>,
    /// Command receiver.
    command_receiver: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Current simulated computation.
    computation: Mutex<Option<SimulatedComputationBatch>>,
}

/// A simulated node.
pub struct SimulatedNode {
    inner: Arc<SimulatedNodeInner>,
}

impl SimulatedNode {
    /// Create new simulated node.
    pub fn new(storage: Arc<StorageBackend>, contract_id: B256) -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        Self {
            inner: Arc::new(SimulatedNodeInner {
                contract_id,
                storage,
                identity: Arc::new(SimulatedNodeIdentity::new()),
                command_channel: command_sender,
                command_receiver: Mutex::new(Some(command_receiver)),
                computation: Mutex::new(None),
                shutdown_channel: Mutex::new(Some(shutdown_sender)),
                shutdown_signal: Mutex::new(Some(shutdown_receiver)),
            }),
        }
    }

    /// Get public key for this node.
    pub fn get_public_key(&self) -> B256 {
        self.get_identity().get_node_signer().get_public_key()
    }

    /// Get node identity.
    pub fn get_identity(&self) -> Arc<NodeIdentity> {
        self.inner.identity.clone()
    }

    /// Start simulated node.
    pub fn start(
        &self,
        backend: Arc<ConsensusBackend>,
        signer: Arc<ConsensusSigner>,
        scheduler: Arc<Scheduler>,
    ) -> BoxFuture<()> {
        // Create a channel for external commands. This is currently required because
        // there is no service discovery backend which we could subscribe to.
        let receiver = self.inner
            .command_receiver
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        let public_key = self.get_public_key();

        // Fetch current committee to get our role.
        let role = scheduler
            .watch_committees()
            .filter(|committee| committee.kind == CommitteeType::Compute)
            .take(1)
            .collect()
            .wait()
            .unwrap()
            .first()
            .unwrap()
            .members
            .iter()
            .filter(|node| node.public_key == public_key)
            .map(|node| node.role)
            .next()
            .unwrap();

        // Subscribe to new events.
        let event_processor: BoxFuture<()> = {
            let shared_inner = self.inner.clone();
            let backend = backend.clone();
            let signer = signer.clone();

            Box::new(backend.get_events(self.inner.contract_id).for_each(
                move |event| -> BoxFuture<()> {
                    match event {
                        Event::CommitmentsReceived(_) => {
                            // Generate reveal.
                            let computation = {
                                let mut computation = shared_inner.computation.lock().unwrap();

                                match computation.take() {
                                    Some(computation) => computation,
                                    None => return future::ok(()).into_box(),
                                }
                            };

                            let reveal = signer
                                .sign_reveal(&computation.block.header, &computation.nonce)
                                .unwrap();

                            // Send reveal.
                            backend.reveal(shared_inner.contract_id, reveal)
                        }
                        Event::RoundFailed(error) => {
                            // Round has failed, so the test should abort.
                            panic!("round failed: {}", error);
                        }
                        Event::DiscrepancyDetected(_) => {
                            // Discrepancy has been detected.
                            panic!("unexpected discrepancy detected during test");
                        }
                    }
                },
            ))
        };

        // Process commands.
        let command_processor: BoxFuture<()> = {
            let shared_inner = self.inner.clone();
            let backend = backend.clone();
            let signer = signer.clone();

            Box::new(
                receiver
                    .map_err(|_| Error::new("command channel closed"))
                    .for_each(move |command| -> BoxFuture<()> {
                        match command {
                            Command::Compute(output) => {
                                if role == Role::BackupWorker {
                                    // TODO: Support testing discrepancy resolution.
                                    return future::ok(()).into_box();
                                }

                                // Fetch latest block.
                                let latest_block =
                                    backend.get_latest_block(shared_inner.contract_id);

                                let shared_inner = shared_inner.clone();
                                let backend = backend.clone();
                                let signer = signer.clone();

                                Box::new(latest_block.and_then(move |child| {
                                    // Start new computation with some dummy output state.
                                    let mut block = Block::new_parent_of(&child);
                                    // We currently just assume that the computation group is fixed.
                                    block.computation_group = child.computation_group;
                                    block.header.input_hash = empty_hash();
                                    block.header.output_hash = empty_hash();
                                    block.header.state_root = hash_storage_key(&output);
                                    block.update();

                                    // Generate commitment.
                                    let (commitment, nonce) =
                                        signer.sign_commitment(&block.header).unwrap();
                                    let computation = SimulatedComputationBatch { block, nonce };

                                    // Store computation.
                                    {
                                        let mut current_computation =
                                            shared_inner.computation.lock().unwrap();
                                        assert!(current_computation.is_none());
                                        current_computation.get_or_insert(computation);
                                    }

                                    if !output.is_empty() {
                                        // Insert dummy result to storage and commit.
                                        shared_inner
                                            .storage
                                            .insert(output, 7)
                                            .and_then(move |_| {
                                                backend.commit(shared_inner.contract_id, commitment)
                                            })
                                            .into_box()
                                    } else {
                                        // Output is empty, no need to insert to storage.
                                        backend
                                            .commit(shared_inner.contract_id, commitment)
                                            .into_box()
                                    }
                                }))
                            }
                        }
                    })
                    .or_else(|error| {
                        panic!(
                            "error while processing simulated compute node command: {:?}",
                            error
                        );

                        #[allow(unreachable_code)]
                        Ok(())
                    }),
            )
        };

        // Create shutdown channel.
        let receiver = self.inner
            .shutdown_signal
            .lock()
            .unwrap()
            .take()
            .expect("start already called");
        let shutdown = Box::new(receiver.then(|_| Err(Error::new("shutdown"))));

        let tasks =
            future::join_all(vec![event_processor, command_processor, shutdown]).then(|_| Ok(()));

        Box::new(tasks)
    }

    /// Simulate delivery of a new computation.
    pub fn compute(&self, output: &[u8]) {
        self.inner
            .command_channel
            .unbounded_send(Command::Compute(output.to_vec()))
            .unwrap();
    }

    /// Shutdown node.
    pub fn shutdown(&self) {
        let channel = self.inner.shutdown_channel.lock().unwrap().take().unwrap();
        drop(channel.send(()));
    }
}

/// Generate the specified number of simulated compute nodes.
pub fn generate_simulated_nodes(
    count: usize,
    storage: Arc<StorageBackend>,
    contract_id: B256,
) -> Vec<SimulatedNode> {
    (0..count)
        .map(|_| SimulatedNode::new(storage.clone(), contract_id))
        .collect()
}
