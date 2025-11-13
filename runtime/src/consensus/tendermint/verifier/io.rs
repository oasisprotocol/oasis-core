use std::sync::Arc;

use tendermint_light_client::{
    components::{
        self,
        io::{AtHeight, IoError},
    },
    types::{LightBlock as TMLightBlock, PeerId, ValidatorSet as TMValidatorSet},
};
use tendermint_rpc::error::Error as RpcError;

use crate::{
    consensus::{
        tendermint::{decode_light_block, decode_validators, LightBlockMeta},
        transaction::SignedTransactionWithProof,
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
            .call_host(Body::HostFetchConsensusBlockRequest { height })
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

    fn fetch_validators(&self, height: u64) -> Result<TMValidatorSet, IoError> {
        let result = self
            .protocol
            .call_host(Body::HostFetchConsensusValidatorsRequest { height })
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract generic validators from response.
        let validators = match result {
            Body::HostFetchConsensusValidatorsResponse { validators } => validators,
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        // Decode validators as Tendermint validators.
        let validators = decode_validators(validators)
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        Ok(validators)
    }

    pub fn fetch_genesis_height(&self) -> Result<u64, IoError> {
        let result = self
            .protocol
            .call_host(Body::HostFetchGenesisHeightRequest {})
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
    ) -> Result<SignedTransactionWithProof, IoError> {
        let result = self
            .protocol
            .call_host(Body::HostProveFreshnessRequest {
                blob: nonce.to_vec(),
            })
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract proof from response.
        let (signed_tx, proof) = match result {
            Body::HostProveFreshnessResponse { signed_tx, proof } => (signed_tx, proof),
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        Ok(SignedTransactionWithProof { signed_tx, proof })
    }

    pub fn fetch_block_metadata(&self, height: u64) -> Result<SignedTransactionWithProof, IoError> {
        let result = self
            .protocol
            .call_host(Body::HostFetchBlockMetadataTxRequest { height })
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract proof from response.
        let (signed_tx, proof) = match result {
            Body::HostFetchBlockMetadataTxResponse { signed_tx, proof } => (signed_tx, proof),
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        Ok(SignedTransactionWithProof { signed_tx, proof })
    }
}

impl components::io::Io for Io {
    fn fetch_light_block(&self, height: AtHeight) -> Result<TMLightBlock, IoError> {
        let height = match height {
            AtHeight::At(height) => height.into(),
            AtHeight::Highest => HEIGHT_LATEST,
        };

        let block = Io::fetch_light_block(self, height)?;
        let height: u64 = block
            .signed_header
            .as_ref()
            .ok_or_else(|| IoError::rpc(RpcError::server("missing signed header".to_string())))?
            .header()
            .height
            .into();

        let next_validators = Io::fetch_validators(self, height + 1)?;

        Ok(TMLightBlock {
            signed_header: block.signed_header.unwrap(), // Checked above.
            validators: block.validators,
            next_validators,
            provider: PeerId::new([0; 20]),
        })
    }
}
