use tokio::sync::oneshot;

use crate::{
    consensus::{
        beacon::EpochTime, roothash::Header, state::ConsensusState, verifier::Error, Event,
        LightBlock,
    },
    types::EventKind,
};

/// Size of nonce for prove freshness request.
pub const NONCE_SIZE: usize = 32;

/// Nonce for prove freshness request.
pub type Nonce = [u8; NONCE_SIZE];

/// Command sent to the verifier thread.
pub enum Command {
    Synchronize(u64, oneshot::Sender<Result<(), Error>>),
    Verify(
        LightBlock,
        Header,
        EpochTime,
        oneshot::Sender<Result<ConsensusState, Error>>,
        bool,
    ),
    LatestState(oneshot::Sender<Result<ConsensusState, Error>>),
    LatestHeight(oneshot::Sender<Result<u64, Error>>),
    StateAt(u64, oneshot::Sender<Result<ConsensusState, Error>>),
    EventsAt(u64, EventKind, oneshot::Sender<Result<Vec<Event>, Error>>),
}
