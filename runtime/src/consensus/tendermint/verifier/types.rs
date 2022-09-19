use crossbeam::channel;

use crate::{
    consensus::{
        beacon::EpochTime,
        roothash::{ComputeResultsHeader, Header},
        state::ConsensusState,
        verifier::Error,
        Event, LightBlock,
    },
    types::EventKind,
};

/// Size of nonce for prove freshness request.
pub const NONCE_SIZE: usize = 32;

/// Nonce for prove freshness request.
pub type Nonce = [u8; NONCE_SIZE];

pub enum Command {
    Synchronize(u64, channel::Sender<Result<(), Error>>),
    Verify(
        LightBlock,
        Header,
        EpochTime,
        channel::Sender<Result<ConsensusState, Error>>,
        bool,
    ),
    Trust(ComputeResultsHeader, channel::Sender<Result<(), Error>>),
    LatestState(channel::Sender<Result<ConsensusState, Error>>),
    LatestHeight(channel::Sender<Result<u64, Error>>),
    StateAt(u64, channel::Sender<Result<ConsensusState, Error>>),
    EventsAt(u64, EventKind, channel::Sender<Result<Vec<Event>, Error>>),
}
