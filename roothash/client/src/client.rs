//! Root hash gRPC client.
use std::convert::TryFrom;

use grpcio::Channel;

use ekiden_common::bytes::B256;
use ekiden_common::futures::prelude::*;
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
