//! Optimistic consensus backend.
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_consensus_base::network::{ConsensusNetwork, Content, Message};
use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, ConsensusSigner, Event, Reveal,
                            RootHashBackend};
use ekiden_scheduler_base::{CommitteeNode, CommitteeType, Scheduler};

enum Command {
    /// Incoming network gossip.
    Gossip(Message),
    /// Notification on the new anchor block.
    AnchorBlock(Block),
    /// Committee update.
    UpdateCommittee(Vec<CommitteeNode>),
}

/// State of optimistic consensus.
///
/// See the `transition` method for valid state transitions.
#[derive(Clone, Debug)]
enum State {
    /// We are waiting for a valid anchor block and/or committee.
    NotReady(Option<Block>, Option<Vec<CommitteeNode>>),
    /// We are syncing intermediate blocks.
    SyncingBlocks(Block, Vec<CommitteeNode>),
    /// We are ready to process reveals.
    Ready(Block, Vec<CommitteeNode>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                State::NotReady(..) => "NotReady",
                State::SyncingBlocks(..) => "SyncingBlocks",
                State::Ready(..) => "Ready",
            }
        )
    }
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an error future is
/// returned.
macro_rules! require_state {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*, $message:expr) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => {}
            state => {
                return future::err(Error::new(format!(
                    "incorrect state for {}: {:?}",
                    $message, state
                ))).into_box()
            }
        }
    }};

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr, $message:expr) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => $output,
            state => {
                return future::err(Error::new(format!(
                    "incorrect state for {}: {:?}",
                    $message, state
                ))).into_box()
            }
        }
    }};
}

/// Helper macro for ensuring state is correct.
///
/// In case the state doesn't match the passed pattern, an ok future is
/// returned.
macro_rules! require_state_ignore {
    ($inner:ident, $( $state:pat )|* $(if $cond:expr)*) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => {}
            _ => return future::ok(()).into_box(),
        }
    }};

    ($inner:ident, $( $state:pat )|* $(if $cond:expr)* => $output:expr) => {{
        let state = $inner.state.lock().unwrap();
        match state.clone() {
            $( $state )|* $(if $cond)* => $output,
            _ => return future::ok(()).into_box(),
        }
    }};
}

struct Inner {
    /// Contract identifier.
    contract_id: B256,
    /// Root hash backend.
    root_hash: Arc<RootHashBackend>,
    /// Signer.
    signer: Arc<ConsensusSigner>,
    /// Network layer.
    network: Arc<ConsensusNetwork>,
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Execution environment.
    environment: Arc<Environment>,
    /// Block subscribers.
    block_subscribers: StreamSubscribers<Block>,
    /// Event subscribers.
    event_subscribers: StreamSubscribers<Event>,
    /// Current state.
    state: Mutex<State>,
    /// Reveals collected for the current round, keyed by signer.
    reveals: Mutex<HashMap<B256, Reveal>>,
}

/// Optimistic consensus backend.
pub struct OptimisticConsensusBackend {
    inner: Arc<Inner>,
}

impl OptimisticConsensusBackend {
    /// Construct new optimistic consensus backend.
    pub fn new(
        contract_id: B256,
        root_hash: Arc<RootHashBackend>,
        signer: Arc<ConsensusSigner>,
        network: Arc<ConsensusNetwork>,
        scheduler: Arc<Scheduler>,
        environment: Arc<Environment>,
    ) -> Self {
        let instance = Self {
            inner: Arc::new(Inner {
                contract_id,
                root_hash,
                signer,
                network,
                scheduler,
                environment,
                block_subscribers: StreamSubscribers::new(),
                event_subscribers: StreamSubscribers::new(),
                state: Mutex::new(State::NotReady(None, None)),
                reveals: Mutex::new(HashMap::new()),
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
                .map(|message| Command::Gossip(message))
                .into_box(),
        );

        // Subscribe to incoming blocks from dispute resolution backend.
        event_sources.push(
            self.inner
                .root_hash
                .watch_blocks()
                .map(|block| Command::AnchorBlock(block))
                .into_box(),
        );

        // Subscribe to scheduler committee updates.
        let contract_id = self.inner.contract_id;
        event_sources.push(
            self.inner
                .scheduler
                .watch_committees()
                .filter(|committee| committee.kind == CommitteeType::Compute)
                .filter(move |committee| committee.contract.id == contract_id)
                .map(|committee| Command::UpdateCommittee(committee.members))
                .into_box(),
        );

        // Process consensus commands.
        self.inner.environment.spawn({
            let inner = self.inner.clone();

            event_sources.for_each_log_errors(
                module_path!(),
                "Unexpected error while processing consensus commands",
                move |command| match command {
                    Command::Gossip(message) => Self::handle_gossip(inner.clone(), message),
                    Command::AnchorBlock(block) => Self::handle_anchor_block(inner.clone(), block),
                    Command::UpdateCommittee(members) => {
                        Self::handle_update_committee(inner.clone(), members)
                    }
                },
            )
        });
    }

    /// Transition the backend to a new state.
    ///
    /// # Panics
    ///
    /// This method will panic in case of an invalid state transition.
    fn transition(inner: Arc<Inner>, to: State) {
        let mut state = inner.state.lock().unwrap();
        match (&*state, &to) {
            // Transitions from NotReady when anchor block and committee are resolved.
            (&State::NotReady(None, None), &State::NotReady(Some(_), None)) => {}
            (&State::NotReady(None, None), &State::NotReady(None, Some(_))) => {}
            (&State::NotReady(None, None), &State::NotReady(Some(_), Some(_))) => {}
            (
                &State::NotReady(Some(ref block_a), None),
                &State::NotReady(Some(ref block_b), Some(_)),
            ) if block_a == block_b => {}
            (
                &State::NotReady(None, Some(ref committee_a)),
                &State::NotReady(Some(_), Some(ref committee_b)),
            ) if committee_a == committee_b => {}
            (
                &State::NotReady(Some(ref block_a), Some(ref committee_a)),
                &State::SyncingBlocks(ref block_b, ref committee_b),
            ) if block_a == block_b && committee_a == committee_b => {}

            // Transitions from SyncingBlocks.
            (&State::SyncingBlocks(_, ref committee_a), &State::Ready(_, ref committee_b))
                if committee_a == committee_b => {}

            // Transitions from Ready.
            (&State::Ready(_, ref committee_a), &State::Ready(_, ref committee_b))
                if committee_a == committee_b => {}

            transition => panic!(
                "illegal optimistic consensus state transition: {:?}",
                transition
            ),
        }

        trace!("Optimistic consensus transitioning to {}", to);
        *state = to;
    }

    /// Handle incoming gossip.
    fn handle_gossip(inner: Arc<Inner>, message: Message) -> BoxFuture<()> {
        match message.content {
            Content::Reveal(reveal) => Self::handle_gossip_reveal(inner, message.sender, reveal),
            Content::LatestBlock(block) => Self::handle_gossip_latest_block(inner, block),
        }
    }

    /// Handle new reveal gossip.
    fn handle_gossip_reveal(inner: Arc<Inner>, sender: B256, reveal: Reveal) -> BoxFuture<()> {
        let (block, committee) = require_state!(
            inner,
            State::Ready(block, committee) => (block, committee),
            "handling reveals"
        );

        // Check that sender is a member of the current committee.
        if !committee.iter().any(|member| member.public_key == sender) {
            warn!(
                "Discarding gossiped reveal from non-committee member {:?}",
                sender
            );
            return future::ok(()).into_box();
        }

        // Extract header from reveal.
        inner
            .signer
            .get_reveal_header(&reveal)
            .and_then(move |header| {
                // Check if header is based on previous block.
                if !header.is_parent_of(&block.header) {
                    warn!("Discarding gossiped reveal not based on previous block");
                    return future::ok(()).into_box();
                }

                // Check if reveal is valid and comes from sender.
                inner
                    .signer
                    .verify_reveal(sender, &header, &reveal)
                    .and_then(move |_| {
                        // Add to list of current reveals.
                        let mut reveals = inner.reveals.lock().unwrap();
                        reveals.insert(sender, reveal);

                        // Check if we have enough reveals for processing.
                        if reveals.len() == committee.len() {
                            // TODO: Process reveals.
                        }

                        Ok(())
                    })
                    .into_box()
            })
            .into_box()
    }

    /// Handle latest block gossip.
    fn handle_gossip_latest_block(inner: Arc<Inner>, block: Block) -> BoxFuture<()> {
        // TODO: Collect latest blocks from multiple committee members, ensure they match.

        // TODO: Validate that the latest block comes from the anchor block by traversing
        //       the chain of backward hashes through storage.

        future::ok(()).into_box()
    }

    fn start_syncing_blocks(inner: Arc<Inner>) -> BoxFuture<()> {
        // TODO: Implement requesting the latest block.

        future::ok(()).into_box()
    }

    /// Handle anchor block.
    fn handle_anchor_block(inner: Arc<Inner>, block: Block) -> BoxFuture<()> {
        let new_state = {
            let state = inner.state.lock().unwrap();
            match &*state {
                &State::NotReady(_, ref committee) => {
                    State::NotReady(Some(block), committee.clone())
                }
                &State::SyncingBlocks(..) => {
                    unimplemented!("anchor block change while syncing blocks");
                }
                &State::Ready(..) => {
                    unimplemented!("anchor block change while ready");
                }
            }
        };

        Self::transition(inner.clone(), new_state.clone());

        if let State::NotReady(Some(_), Some(_)) = new_state {
            // Start syncing blocks.
            Self::start_syncing_blocks(inner.clone())
        } else {
            future::ok(()).into_box()
        }
    }

    /// Handle committee update.
    fn handle_update_committee(inner: Arc<Inner>, members: Vec<CommitteeNode>) -> BoxFuture<()> {
        let new_state = {
            let state = inner.state.lock().unwrap();
            match &*state {
                &State::NotReady(ref block, _) => State::NotReady(block.clone(), Some(members)),
                &State::SyncingBlocks(..) => {
                    unimplemented!("committee update while syncing blocks");
                }
                &State::Ready(..) => {
                    unimplemented!("committee update while ready");
                }
            }
        };

        Self::transition(inner.clone(), new_state.clone());

        if let State::NotReady(Some(_), Some(_)) = new_state {
            // Start syncing blocks.
            Self::start_syncing_blocks(inner.clone())
        } else {
            future::ok(()).into_box()
        }
    }
}

impl ConsensusBackend for OptimisticConsensusBackend {
    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block> {
        assert!(contract_id == self.inner.contract_id);

        unimplemented!();
    }

    fn get_events(&self, contract_id: B256) -> BoxStream<Event> {
        assert!(contract_id == self.inner.contract_id);

        self.inner.event_subscribers.subscribe().1
    }

    fn commit(&self, contract_id: B256, commitment: Commitment) -> BoxFuture<()> {
        assert!(contract_id == self.inner.contract_id);

        // TODO: Remove this function.

        unimplemented!();
    }

    fn reveal(&self, contract_id: B256, reveal: Reveal) -> BoxFuture<()> {
        assert!(contract_id == self.inner.contract_id);

        // TODO: Gossip reveal to everyone.

        // TODO: Perform local reveal handling.

        unimplemented!();
    }

    fn commit_many(&self, contract_id: B256, commitments: Vec<Commitment>) -> BoxFuture<()> {
        assert!(contract_id == self.inner.contract_id);

        // TODO: Remove this function.

        unimplemented!();
    }

    fn reveal_many(&self, contract_id: B256, reveals: Vec<Reveal>) -> BoxFuture<()> {
        assert!(contract_id == self.inner.contract_id);

        // TODO: Remove this function.

        unimplemented!();
    }
}
