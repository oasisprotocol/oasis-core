use std::convert::{TryFrom, TryInto};

use anyhow::{anyhow, Result};
use tendermint::block::signed_header::SignedHeader as TMSignedHeader;
use tendermint_proto::{types::LightBlock as RawLightBlock, Protobuf};

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{Root, RootType},
};

/// Tendermint consensus backend name.
pub const BACKEND_NAME: &str = "tendermint";

/// Light consensus block.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub struct LightBlock {
    pub height: i64,
    pub meta: Vec<u8>,
}

impl LightBlock {
    pub fn decode_meta(self) -> Result<LightBlockMeta> {
        LightBlockMeta::decode_vec(&self.meta).map_err(|e| anyhow!("{}", e))
    }
}

/// Tendermint light consensus block metadata.
#[derive(Debug, Clone)]
pub struct LightBlockMeta {
    pub signed_header: TMSignedHeader,
    // TODO: add other fields if/when needed.
}

impl LightBlockMeta {
    pub fn get_state_root(&self) -> Root {
        let header = self.signed_header.header();
        let height: u64 = header.height.into();
        let hash: [u8; 32] = header
            .app_hash
            .value()
            .as_slice()
            .try_into()
            .expect("invalid app hash");

        Root {
            namespace: Namespace::default(),
            version: height - 1,
            root_type: RootType::State,
            hash: Hash(hash),
        }
    }
}

impl Protobuf<RawLightBlock> for LightBlockMeta {}

impl TryFrom<RawLightBlock> for LightBlockMeta {
    type Error = anyhow::Error;

    fn try_from(value: RawLightBlock) -> Result<Self> {
        Ok(LightBlockMeta {
            signed_header: value
                .signed_header
                .ok_or(anyhow!("missing signed header"))?
                .try_into()
                .map_err(|error| anyhow!("{}", error))?,
        })
    }
}

impl From<LightBlockMeta> for RawLightBlock {
    fn from(value: LightBlockMeta) -> Self {
        RawLightBlock {
            signed_header: Some(value.signed_header.into()),
            validator_set: None,
        }
    }
}
