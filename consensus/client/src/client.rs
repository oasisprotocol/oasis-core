//! Consensus gRPC client.
use std::convert::TryFrom;
use std::sync::Arc;

use grpcio::{self, Channel, ChannelBuilder};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::environment::Environment;
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

    pub fn from_node(node: Node, env: Arc<grpcio::Environment>) -> Self {
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
                    .map_err(|e| e.into()),
            ),
            Err(e) => Box::new(future::err(e.into())),
        }
    }

    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block> {
        let mut req = api::BlockRequest::new();
        req.set_contract_id(contract_id.to_vec());
        match self.0.get_blocks(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => Ok(Block::try_from(r.get_block().to_owned())?),
                Err(e) => Err(e.into()),
            })),
            Err(e) => Box::new(stream::once::<Block, _>(Err(e.into()))),
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
                Err(e) => Err(e.into()),
            })),
            Err(e) => Box::new(stream::once::<Event, _>(Err(e.into()))),
        }
    }

    fn commit(&self, contract_id: B256, commitment: Commitment) -> BoxFuture<()> {
        let mut req = api::CommitRequest::new();
        req.set_contract_id(contract_id.to_vec());
        req.set_commitment(commitment.into());
        match self.0.commit_async(&req) {
            Ok(f) => Box::new(f.map(|_r| ()).map_err(|e| e.into())),
            Err(e) => Box::new(future::err(e.into())),
        }
    }

    fn reveal(&self, contract_id: B256, reveal: Reveal<Header>) -> BoxFuture<()> {
        let mut req = api::RevealRequest::new();
        req.set_contract_id(contract_id.to_vec());
        req.set_header(reveal.value.into());
        req.set_nonce(reveal.nonce.to_vec());
        req.set_signature(reveal.signature.into());
        match self.0.reveal_async(&req) {
            Ok(f) => Box::new(f.map(|_r| ()).map_err(|e| e.into())),
            Err(e) => Box::new(future::err(e.into())),
        }
    }
}

// Register for dependency injection.
create_component!(
    remote,
    "consensus-backend",
    ConsensusClient,
    ConsensusBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        let args = container.get_arguments().unwrap();
        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            args.value_of("consensus-client-host").unwrap(),
            args.value_of("consensus-client-port").unwrap(),
        ));

        let instance: Arc<ConsensusBackend> = Arc::new(ConsensusClient::new(channel));
        Ok(Box::new(instance))
    }),
    [
        Arg::with_name("consensus-client-host")
            .long("consensus-client-host")
            .help("(remote consensus backend) Host that the consensus client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1"),
        Arg::with_name("consensus-client-port")
            .long("consensus-client-port")
            .help("(remote consensus backend) Port that the consensus client should connect to")
            .takes_value(true)
            .default_value("42261")
    ]
);
