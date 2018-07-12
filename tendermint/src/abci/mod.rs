//! Tendermint ABCI application.
use ekiden_common::futures::prelude::*;

mod generated;

pub mod codec;
pub mod server;
pub mod service;

/// ABCI types.
pub mod types {
    pub use super::generated::types::*;
}

/// Tendermint ABCI application.
///
/// Specification: https://tendermint.readthedocs.io/en/master/abci-spec.html
///
/// # Default implementation
///
/// Default implementations for all ABCI request methods will return an empty response.
#[allow(unused_variables)]
pub trait Application: Send + Sync {
    fn echo(&self, request: types::RequestEcho) -> BoxFuture<types::ResponseEcho> {
        future::ok(types::ResponseEcho::new()).into_box()
    }

    fn flush(&self, request: types::RequestFlush) -> BoxFuture<types::ResponseFlush> {
        future::ok(types::ResponseFlush::new()).into_box()
    }

    fn info(&self, request: types::RequestInfo) -> BoxFuture<types::ResponseInfo> {
        future::ok(types::ResponseInfo::new()).into_box()
    }

    fn set_option(&self, request: types::RequestSetOption) -> BoxFuture<types::ResponseSetOption> {
        future::ok(types::ResponseSetOption::new()).into_box()
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
        future::ok(types::ResponseCheckTx::new()).into_box()
    }

    fn deliver_tx(&self, request: types::RequestDeliverTx) -> BoxFuture<types::ResponseDeliverTx> {
        future::ok(types::ResponseDeliverTx::new()).into_box()
    }

    fn end_block(&self, request: types::RequestEndBlock) -> BoxFuture<types::ResponseEndBlock> {
        future::ok(types::ResponseEndBlock::new()).into_box()
    }

    fn commit(&self, request: types::RequestCommit) -> BoxFuture<types::ResponseCommit> {
        future::ok(types::ResponseCommit::new()).into_box()
    }
}
