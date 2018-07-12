//! Tendermint ABCI application.
//!
//! Applications implement the state machine that is replicated by Tendermint PBFT
//! and contain the Ekiden-specific logic. They communicate with the main Tendermint
//! process over ABCI.
use serde_cbor;

use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;

use super::abci::{self, types};

use self::consensus::Consensus;
use self::transaction::Transaction;

mod consensus;
mod state;
mod transaction;

/// Ekiden Tendermint application.
///
/// Contains all logic required for Ekiden as related to PBFT consensus.
pub struct Application {
    consensus: Consensus,
}

impl Application {
    /// Create new application instance.
    pub fn new() -> Self {
        Self {
            consensus: Consensus::new(),
        }
    }
}

impl abci::Application for Application {
    fn echo(&self, mut request: types::RequestEcho) -> BoxFuture<types::ResponseEcho> {
        let mut response = types::ResponseEcho::new();
        response.set_message(request.take_message());
        future::ok(response).into_box()
    }

    fn info(&self, request: types::RequestInfo) -> BoxFuture<types::ResponseInfo> {
        // TODO: Report current block height/hash to avoid replaying all blocks.
        future::ok(types::ResponseInfo::new()).into_box()
    }

    fn init_chain(&self, request: types::RequestInitChain) -> BoxFuture<types::ResponseInitChain> {
        future::ok(types::ResponseInitChain::new()).into_box()
    }

    fn query(&self, request: types::RequestQuery) -> BoxFuture<types::ResponseQuery> {
        future::ok(types::ResponseQuery::new()).into_box()
    }

    fn begin_block(
        &self,
        request: types::RequestBeginBlock,
    ) -> BoxFuture<types::ResponseBeginBlock> {
        future::ok(types::ResponseBeginBlock::new()).into_box()
    }

    fn check_tx(&self, request: types::RequestCheckTx) -> BoxFuture<types::ResponseCheckTx> {
        // Decode transaction.
        let transaction: Transaction = match serde_cbor::from_slice(request.get_tx()) {
            Ok(transaction) => transaction,
            Err(error) => return future::err(Error::new("malformed transaction")).into_box(),
        };

        // Based on transaction content, dispatch to appropriate module.
        let result = match transaction {
            Transaction::Consensus(transaction) => self.consensus.check_tx(transaction),
        };

        result
            .and_then(|()| Ok(types::ResponseCheckTx::new()))
            .into_box()
    }

    fn deliver_tx(&self, request: types::RequestDeliverTx) -> BoxFuture<types::ResponseDeliverTx> {
        // Decode transaction.
        let transaction: Transaction = match serde_cbor::from_slice(request.get_tx()) {
            Ok(transaction) => transaction,
            Err(error) => return future::err(Error::new("malformed transaction")).into_box(),
        };

        // Based on transaction content, dispatch to appropriate module.
        let result = match transaction {
            Transaction::Consensus(transaction) => self.consensus.deliver_tx(transaction),
        };

        result
            .and_then(|()| Ok(types::ResponseDeliverTx::new()))
            .into_box()
    }

    fn end_block(&self, request: types::RequestEndBlock) -> BoxFuture<types::ResponseEndBlock> {
        future::ok(types::ResponseEndBlock::new()).into_box()
    }

    fn commit(&self, request: types::RequestCommit) -> BoxFuture<types::ResponseCommit> {
        self.consensus.commit();

        future::ok(types::ResponseCommit::new()).into_box()
    }
}
