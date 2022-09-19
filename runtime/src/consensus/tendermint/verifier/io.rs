use std::sync::Arc;

use io_context::Context;

use tendermint_light_client::{
    components::{
        self,
        io::{AtHeight, IoError},
    },
    types::{LightBlock as TMLightBlock, PeerId},
};
use tendermint_rpc::error::Error as RpcError;

use crate::{
    consensus::{
        tendermint::{decode_light_block, merkle::Proof, LightBlockMeta},
        transaction::SignedTransaction,
        HEIGHT_LATEST,
    },
    protocol::Protocol,
    types::Body,
};

use super::types::Nonce;

pub struct Io {
    protocol: Arc<Protocol>,
}

impl Io {
    pub fn new(protocol: &Arc<Protocol>) -> Self {
        Self {
            protocol: protocol.clone(),
        }
    }

    fn fetch_light_block(&self, height: u64) -> Result<LightBlockMeta, IoError> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchConsensusBlockRequest { height },
            )
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract generic light block from response.
        let block = match result {
            Body::HostFetchConsensusBlockResponse { block } => block,
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        // Decode block as a Tendermint light block.
        let block = decode_light_block(block)
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        Ok(block)
    }

    pub fn fetch_genesis_height(&self) -> Result<u64, IoError> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchGenesisHeightRequest {},
            )
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract genesis height from response.
        let height = match result {
            Body::HostFetchGenesisHeightResponse { height } => height,
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        Ok(height)
    }

    pub fn fetch_freshness_proof(
        &self,
        nonce: &Nonce,
    ) -> Result<(SignedTransaction, u64, Proof), IoError> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostProveFreshnessRequest {
                    blob: nonce.to_vec(),
                },
            )
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract proof from response.
        let (signed_tx, proof) = match result {
            Body::HostProveFreshnessResponse { signed_tx, proof } => (signed_tx, proof),
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        // Decode raw proof as a Tendermint Merkle proof of inclusion.
        let merkle_proof = cbor::from_slice(&proof.raw_proof)
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        Ok((signed_tx, proof.height, merkle_proof))
    }
}

impl components::io::Io for Io {
    fn fetch_light_block(&self, height: AtHeight) -> Result<TMLightBlock, IoError> {
        let height = match height {
            AtHeight::At(height) => height.into(),
            AtHeight::Highest => HEIGHT_LATEST,
        };

        // Fetch light block at height and height+1.
        let block = Io::fetch_light_block(self, height)?;
        let height: u64 = block
            .signed_header
            .as_ref()
            .ok_or_else(|| IoError::rpc(RpcError::server("missing signed header".to_string())))?
            .header()
            .height
            .into();
        // NOTE: It seems that the requirement to fetch the next validator set is redundant and it
        //       should be handled at a higher layer of the light client.
        let next_block = Io::fetch_light_block(self, height + 1)?;

        Ok(TMLightBlock {
            signed_header: block.signed_header.unwrap(), // Checked above.
            validators: block.validators,
            next_validators: next_block.validators,
            provider: PeerId::new([0; 20]),
        })
    }
}
