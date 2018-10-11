//! Root hash gRPC client.
use std::convert::TryFrom;
use std::sync::Arc;

use grpcio::{Channel, ChannelBuilder};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_common::uint::U256;
use ekiden_roothash_api as api;
use ekiden_roothash_base::{Block, Commitment, Event, Header, RootHashBackend};

/// Root hash client implements the root hash interface.
pub struct RootHashClient(api::RootHashClient);

impl RootHashClient {
    pub fn new(channel: Channel) -> Self {
        RootHashClient(api::RootHashClient::new(channel))
    }

    pub fn from_node(
        node: &Node,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        RootHashClient::new(node.connect(environment, identity))
    }
}

impl RootHashBackend for RootHashClient {
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

    fn get_blocks_since(&self, contract_id: B256, round: U256) -> BoxStream<Block> {
        let mut req = api::BlockSinceRequest::new();
        req.set_contract_id(contract_id.to_vec());
        req.set_round(round.to_vec_big_endian_compact());
        match self.0.get_blocks_since(&req) {
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

                    if event.has_round_failed() {
                        Ok(Event::RoundFailed(Error::new(
                            event.get_round_failed().get_error().to_owned(),
                        )))
                    } else if event.has_discrepancy_detected() {
                        Ok(Event::DiscrepancyDetected(
                            H256::from(event.get_discrepancy_detected().get_batch_hash()),
                            Header::try_from(
                                event.get_discrepancy_detected().get_block_header().clone(),
                            )?,
                        ))
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
}

// Register for dependency injection.
create_component!(
    remote,
    "roothash-backend",
    RootHashClient,
    RootHashBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        let args = container.get_arguments().unwrap();
        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            args.value_of("roothash-client-host").unwrap(),
            args.value_of("roothash-client-port").unwrap(),
        ));

        let instance: Arc<RootHashBackend> = Arc::new(RootHashClient::new(channel));
        Ok(Box::new(instance))
    }),
    [
        Arg::with_name("roothash-client-host")
            .long("roothash-client-host")
            .help("(remote roothash backend) Host that the roothash client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1"),
        Arg::with_name("roothash-client-port")
            .long("roothash-client-port")
            .help("(remote roothash backend) Port that the roothash client should connect to")
            .takes_value(true)
            .default_value("42261")
    ]
);
