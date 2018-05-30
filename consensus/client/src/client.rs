//! Consensus gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, Environment};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::error::Error;
use ekiden_common::futures::{future, stream, BoxFuture, BoxStream, Executor, Future, Stream};
use ekiden_common::node::Node;
use ekiden_consensus_api as api;
use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, Event, Header, Reveal};

/// Consensus client implements the Consensus interface.
pub struct ConsensusClient(api::ConsensusClient);

impl ConsensusClient {
    pub fn new(channel: Channel) -> Self {
        ConsensusClient(api::ConsensusClient::new(channel))
    }

    pub fn from_node(node: Node, env: Arc<Environment>) -> Self {
        ConsensusClient::new(node.connect(env))
    }
}

impl ConsensusBackend for ConsensusClient {
    fn start(&self, _executor: &mut Executor) {
        // TODO: refactor / remove
    }

    fn shutdown(&self) {
        // TODO
    }

    fn get_latest_block(&self, contract_id: B256) -> BoxFuture<Block> {
        let mut req = api::LatestBlockRequest::new();
        req.set_contract_id(contract_id.to_vec());
        match self.0.get_latest_block_async(&req) {
            Ok(f) => Box::new(
                f.map(|r| Block::try_from(r.get_block().to_owned()).unwrap())
                    .map_err(|e| Error::new(e.description())),
            ),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }

    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block> {
        let mut req = api::BlockRequest::new();
        req.set_contract_id(contract_id.to_vec());
        match self.0.get_blocks(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => Ok(Block::try_from(r.get_block().to_owned())?),
                Err(e) => Err(Error::new(e.description())),
            })),
            Err(e) => Box::new(stream::once::<Block, _>(Err(Error::new(e.description())))),
        }
    }

    fn get_events(&self, contract_id: B256) -> BoxStream<Event> {
        let mut req = api::EventRequest::new();
        req.set_contract_id(contract_id.to_vec());
        match self.0.get_events(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => {
                    let event = r.get_event();

                    if event.has_commitments_received() {
                        Ok(Event::CommitmentsReceived(
                            event.get_commitments_received().get_discrepancy(),
                        ))
                    } else if event.has_round_failed() {
                        Ok(Event::RoundFailed(Error::new(
                            event.get_round_failed().get_error().to_owned(),
                        )))
                    } else if event.has_discrepancy_detected() {
                        Ok(Event::DiscrepancyDetected(H256::from(
                            event.get_discrepancy_detected().get_batch_hash(),
                        )))
                    } else {
                        Err(Error::new("unknown event type"))
                    }
                }
                Err(e) => Err(Error::new(e.description())),
            })),
            Err(e) => Box::new(stream::once::<Event, _>(Err(Error::new(e.description())))),
        }
    }

    fn commit(&self, contract_id: B256, commitment: Commitment) -> BoxFuture<()> {
        let mut req = api::CommitRequest::new();
        req.set_contract_id(contract_id.to_vec());
        req.set_commitment(commitment.into());
        match self.0.commit_async(&req) {
            Ok(f) => Box::new(f.map(|_r| ()).map_err(|e| Error::new(e.description()))),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }

    fn reveal(&self, contract_id: B256, reveal: Reveal<Header>) -> BoxFuture<()> {
        let mut req = api::RevealRequest::new();
        req.set_contract_id(contract_id.to_vec());
        req.set_header(reveal.value.into());
        req.set_nonce(reveal.nonce.to_vec());
        req.set_signature(reveal.signature.into());
        match self.0.reveal_async(&req) {
            Ok(f) => Box::new(f.map(|_r| ()).map_err(|e| Error::new(e.description()))),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }
}
