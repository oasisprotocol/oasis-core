//! Root hash gRPC client.
use std::convert::TryFrom;

use grpcio::{Channel, ChannelBuilder};

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::futures::prelude::*;
use ekiden_common::remote_node::RemoteNode;
use ekiden_common::uint::U256;
use ekiden_roothash_api as api;
use ekiden_roothash_base::{Block, RootHashBackend};

/// Root hash client implements the root hash interface.
pub struct RootHashClient(api::RootHashClient);

impl RootHashClient {
    pub fn new(channel: Channel) -> Self {
        RootHashClient(api::RootHashClient::new(channel))
    }
}

impl RootHashBackend for RootHashClient {
    fn get_blocks(&self, runtime_id: B256) -> BoxStream<Block> {
        let mut req = api::BlockRequest::new();
        req.set_runtime_id(runtime_id.to_vec());
        match self.0.get_blocks(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => Ok(Block::try_from(r.get_block().to_owned())?),
                Err(e) => Err(e.into()),
            })),
            Err(e) => Box::new(stream::once::<Block, _>(Err(e.into()))),
        }
    }

    fn get_blocks_since(&self, runtime_id: B256, round: U256) -> BoxStream<Block> {
        let mut req = api::BlockSinceRequest::new();
        req.set_runtime_id(runtime_id.to_vec());
        req.set_round(round.to_vec_big_endian_compact());
        match self.0.get_blocks_since(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => Ok(Block::try_from(r.get_block().to_owned())?),
                Err(e) => Err(e.into()),
            })),
            Err(e) => Box::new(stream::once::<Block, _>(Err(e.into()))),
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

        // "node-host" and "node-port" arguments.
        let remote_node: Arc<RemoteNode> = container.inject()?;

        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            remote_node.get_node_host(),
            remote_node.get_node_port(),
        ));

        let instance: Arc<RootHashBackend> = Arc::new(RootHashClient::new(channel));
        Ok(Box::new(instance))
    }),
    []
);
