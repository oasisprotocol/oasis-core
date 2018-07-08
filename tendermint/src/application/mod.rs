//! Tendermint ABCI application.
//!
//! Applications implement the state machine that is replicated by Tendermint PBFT
//! and contain the Ekiden-specific logic. They communicate with the main Tendermint
//! process over ABCI.
use ekiden_common::futures::prelude::*;

use super::abci::{self, types};

mod consensus;

/// Ekiden Tendermint application.
///
/// Contains all logic required for Ekiden as related to PBFT consensus.
pub struct Application {
    // TODO: Add components.
}

impl Application {
    /// Create new application instance.
    pub fn new() -> Self {
        Self {}
    }
}

impl abci::Application for Application {
    fn echo(&self, mut request: types::RequestEcho) -> BoxFuture<types::ResponseEcho> {
        let mut response = types::ResponseEcho::new();
        response.set_message(request.take_message());
        future::ok(response).into_box()
    }
}
