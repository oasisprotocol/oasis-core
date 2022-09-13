//! Tendermint consensus layer backend.

pub mod merkle;
pub mod verifier;

use std::convert::{TryFrom, TryInto};

use anyhow::{anyhow, Result};
use tendermint::{
    block::signed_header::SignedHeader as TMSignedHeader, validator::Set as TMValidatorSet,
};
use tendermint_proto::{types::LightBlock as RawLightBlock, Protobuf};

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    consensus::LightBlock,
    storage::mkvs::{Root, RootType},
};

/// Tendermint consensus backend name.
pub const BACKEND_NAME: &str = "tendermint";

/// The domain separation context used by Oasis Core for Tendermint cryptography.
pub const TENDERMINT_CONTEXT: &[u8] = b"oasis-core/tendermint";

/// Decode the light block metadata as a Tendermint light block.
pub fn decode_light_block(light_block: LightBlock) -> Result<LightBlockMeta> {
    LightBlockMeta::decode_vec(&light_block.meta).map_err(|e| anyhow!("{}", e))
}

/// Encode the light block metadata to a Tendermint light block.
pub fn encode_light_block(light_block_meta: &LightBlockMeta) -> Result<LightBlock> {
    let height = u64::from(
        light_block_meta
            .signed_header
            .as_ref()
            .ok_or_else(|| anyhow!("signed header should be present"))?
            .header
            .height,
    );
    let meta = LightBlockMeta::encode_vec(light_block_meta).map_err(|e| anyhow!("{}", e))?;

    Ok(LightBlock { height, meta })
}

/// Extract state root from the given signed block header.
///
/// # Panics
///
/// The signed header must be present and the application hash must be a valid Oasis Core
/// application hash (state root hash).
pub fn state_root_from_header(signed_header: &TMSignedHeader) -> Root {
    let header = signed_header.header();
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

/// Tendermint light consensus block metadata.
#[derive(Debug, Clone)]
pub struct LightBlockMeta {
    pub signed_header: Option<TMSignedHeader>,
    pub validators: TMValidatorSet,
}

impl LightBlockMeta {
    /// State root specified by this light block.
    ///
    /// # Panics
    ///
    /// The signed header must be present and the application hash must be a valid Oasis Core
    /// application hash (state root hash).
    pub fn get_state_root(&self) -> Root {
        let header = self
            .signed_header
            .as_ref()
            .expect("signed header should be present");

        state_root_from_header(header)
    }
}

impl Protobuf<RawLightBlock> for LightBlockMeta {}

impl TryFrom<RawLightBlock> for LightBlockMeta {
    type Error = anyhow::Error;

    fn try_from(value: RawLightBlock) -> Result<Self> {
        Ok(LightBlockMeta {
            signed_header: value
                .signed_header
                .map(TryInto::try_into)
                .transpose()
                .map_err(|error| anyhow!("{}", error))?,
            validators: value
                .validator_set
                .ok_or_else(|| anyhow!("missing validator set"))?
                .try_into()
                .map_err(|error| anyhow!("{}", error))?,
        })
    }
}

impl From<LightBlockMeta> for RawLightBlock {
    fn from(value: LightBlockMeta) -> Self {
        RawLightBlock {
            signed_header: value.signed_header.map(Into::into),
            validator_set: Some(value.validators.into()),
        }
    }
}
