//! Consensus service interfaces.

pub mod address;
pub mod beacon;
pub mod registry;
pub mod roothash;
pub mod scheduler;
pub mod staking;
pub mod state;
pub mod tendermint;
pub mod verifier;

/// The height that represents the most recent block height.
pub const HEIGHT_LATEST: u64 = 0;

/// Light consensus block.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct LightBlock {
    pub height: u64,
    pub meta: Vec<u8>,
}
