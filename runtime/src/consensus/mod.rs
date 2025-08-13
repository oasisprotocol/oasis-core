//! Consensus service interfaces.

use crate::common::crypto::hash::Hash;

pub mod address;
pub mod beacon;
pub mod governance;
pub mod keymanager;
pub mod registry;
pub mod roothash;
pub mod scheduler;
pub mod staking;
pub mod state;
pub mod tendermint;
pub mod transaction;
pub mod verifier;

/// A unique module name for the consensus module.
pub const MODULE_NAME: &str = "consensus";

// Method name for the special block metadata transaction.
pub const METHOD_META: &str = "consensus.Meta";

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

/// BlockMetadata contains additional metadata related to the executing block.
///
/// The metadata is included in the form of a special transaction where this structure is the
/// transaction body.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct BlockMetadata {
    /// State root after executing all logic in the block.
    pub state_root: Hash,
    // Root hash of all events emitted in the block.
    pub events_root: Vec<u8>,
    // Hash of transaction results in the block.
    #[cbor(optional)]
    pub results_hash: Vec<u8>,
}
