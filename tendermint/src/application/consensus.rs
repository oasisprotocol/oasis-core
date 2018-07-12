//! Ekiden consensus handling.
use ekiden_common::futures::prelude::*;
use ekiden_consensus_base::Header;

use super::super::commitment::Reveal;
use super::state::ApplicationState;

/// Consensus transaction.
#[derive(Clone, Serialize, Deserialize)]
pub enum ConsensusTransaction {
    Reveal(Reveal<Header>),
}

/// Consensus state.
#[derive(Clone, Debug, Default)]
struct State {
    //
}

/// Consensus module.
pub struct Consensus {
    /// Consensus state.
    state: ApplicationState<State>,
}

impl Consensus {
    pub fn new() -> Self {
        Self {
            state: ApplicationState::new(),
        }
    }

    pub fn check_tx(&self, transaction: ConsensusTransaction) -> BoxFuture<()> {
        let mut state = self.state.get_check_tx();
        // TODO.
        future::ok(()).into_box()
    }

    pub fn deliver_tx(&self, transaction: ConsensusTransaction) -> BoxFuture<()> {
        let mut state = self.state.get_deliver_tx();
        // TODO.
        future::ok(()).into_box()
    }

    pub fn commit(&self) {
        self.state.commit();
    }
}
