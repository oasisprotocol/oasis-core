//! Consensus service interfaces.

pub mod address;
pub mod beacon;
pub mod keymanager;
pub mod registry;
pub mod roothash;
pub mod scheduler;
pub mod staking;
pub mod state;
pub mod tendermint;
pub mod transaction;
pub mod verifier;

/// The height that represents the most recent block height.
pub const HEIGHT_LATEST: u64 = 0;

/// Light consensus block.
#[derive(Clone, Default, Debug, cbor::Encode, cbor::Decode)]
pub struct LightBlock {
    pub height: u64,
    pub meta: Vec<u8>,
}

/// An event emitted by the consensus layer.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub enum Event {
    #[cbor(rename = "staking")]
    Staking(staking::Event),
    // TODO: Add support for other kind of events.
}
