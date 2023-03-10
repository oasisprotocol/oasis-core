use std::sync::Arc;

use async_trait::async_trait;
use crossbeam::channel;
use tokio::sync::oneshot;

use crate::{
    consensus::{
        beacon::EpochTime,
        roothash::{ComputeResultsHeader, Header},
        state::ConsensusState,
        tendermint::decode_light_block,
        verifier::{self, Error},
        Event, LightBlock,
    },
    protocol::Protocol,
    types::EventKind,
};

use super::types::Command;

pub struct Handle {
    pub protocol: Arc<Protocol>,
    pub command_sender: channel::Sender<Command>,
}

#[async_trait]
impl verifier::Verifier for Handle {
    async fn sync(&self, height: u64) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::Synchronize(height, sender))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn verify(
        &self,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::Verify(
                consensus_block,
                runtime_header,
                epoch,
                sender,
                false,
            ))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn verify_for_query(
        &self,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::Verify(
                consensus_block,
                runtime_header,
                epoch,
                sender,
                true,
            ))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn unverified_state(&self, consensus_block: LightBlock) -> Result<ConsensusState, Error> {
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        // NOTE: No actual verification is performed.
        let state_root = untrusted_block.get_state_root();
        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        ))
    }

    async fn latest_state(&self) -> Result<ConsensusState, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::LatestState(sender))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn state_at(&self, height: u64) -> Result<ConsensusState, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::StateAt(height, sender))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn events_at(&self, height: u64, kind: EventKind) -> Result<Vec<Event>, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::EventsAt(height, kind, sender))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn latest_height(&self) -> Result<u64, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::LatestHeight(sender))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }

    async fn trust(&self, header: &ComputeResultsHeader) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::Trust(header.clone(), sender))
            .map_err(|_| Error::Internal)?;

        receiver.await.map_err(|_| Error::Internal)?
    }
}
