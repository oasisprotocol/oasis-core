//! Optimistic consensus backend.
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::futures::prelude::*;
use ekiden_consensus_base::network::{ConsensusNetwork, Content, Message};
use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, Event, Reveal, RootHashBackend};

enum Command {
    NetworkMessage(Message),
    /// Notification on the new latest block.
    LatestBlock(Block),
}

struct Inner {
    /// Dispute resolution backend.
    root_hash: Arc<RootHashBackend>,
    /// Network layer.
    network: Arc<ConsensusNetwork>,
    /// Execution environment.
    environment: Arc<Environment>,
    /// Latest known block.
    latest_block: Mutex<Option<Block>>,
}

/// Optimistic consensus backend.
pub struct OptimisticConsensusBackend {
    inner: Arc<Inner>,
}

impl OptimisticConsensusBackend {
    /// Construct new optimistic consensus backend.
    pub fn new(
        root_hash: Arc<RootHashBackend>,
        network: Arc<ConsensusNetwork>,
        environment: Arc<Environment>,
    ) -> Self {
        let instance = Self {
            inner: Arc::new(Inner {
                root_hash,
                network,
                environment,
                latest_block: Mutex::new(None),
            }),
        };
        instance.start();

        instance
    }

    /// Start consensus backend.
    fn start(&self) {
        info!("Optimistic consensus backend starting");

        let mut event_sources = stream::SelectAll::new();

        // Subscribe to incoming network messages.
        event_sources.push(
            self.inner
                .network
                .watch_messages()
                .map(|message| Command::NetworkMessage(message))
                .into_box(),
        );

        // Subscribe to incoming blocks from dispute resolution backend.
        event_sources.push(
            self.inner
                .root_hash
                .watch_blocks()
                .map(|block| Command::LatestBlock(block))
                .into_box(),
        );

        // Process consensus commands.
        self.inner.environment.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing consensus commands",
                move |command| match command {
                    Command::NetworkMessage(message) => {
                        Self::handle_network_message(inner.clone(), message)
                    }
                    Command::LatestBlock(block) => Self::handle_latest_block(inner.clone(), block),
                },
            )
        });
    }

    /// Handle incoming network message.
    fn handle_network_message(inner: Arc<Inner>, message: Message) -> BoxFuture<()> {
        match message.content {
            Content::Commitment(commitment) => {
                Self::handle_commitment(inner, message.sender, commitment)
            }
            Content::Reveal(reveal) => Self::handle_reveal(inner, message.sender, reveal),
            Content::LatestBlock(block) => Self::handle_latest_block(inner, block),
        }
    }

    /// Handle new commitment from a specific node.
    fn handle_commitment(
        inner: Arc<Inner>,
        node_id: B256,
        commitment: Commitment,
    ) -> BoxFuture<()> {
        future::ok(()).into_box()
    }

    /// Handle new reveal from a specific node.
    fn handle_reveal(inner: Arc<Inner>, node_id: B256, reveal: Reveal) -> BoxFuture<()> {
        future::ok(()).into_box()
    }

    /// Handle latest block.
    fn handle_latest_block(inner: Arc<Inner>, block: Block) -> BoxFuture<()> {
        // TODO: Check that block is newer than local latest block.
        // TODO: Check that reveals are all in agreement (need consensus signer to verify sigs?).
        future::ok(()).into_box()
    }
}

impl ConsensusBackend for OptimisticConsensusBackend {
    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block> {
        unimplemented!();
    }

    fn get_events(&self, contract_id: B256) -> BoxStream<Event> {
        unimplemented!();
    }

    fn commit(&self, contract_id: B256, commitment: Commitment) -> BoxFuture<()> {
        unimplemented!();
    }

    fn reveal(&self, contract_id: B256, reveal: Reveal) -> BoxFuture<()> {
        unimplemented!();
    }

    fn commit_many(&self, contract_id: B256, mut commitments: Vec<Commitment>) -> BoxFuture<()> {
        unimplemented!();
    }

    fn reveal_many(&self, contract_id: B256, mut reveals: Vec<Reveal>) -> BoxFuture<()> {
        unimplemented!();
    }
}
