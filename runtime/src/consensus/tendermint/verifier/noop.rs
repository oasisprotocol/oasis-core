use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use async_trait::async_trait;
use slog::info;

use crate::{
    common::{logger::get_logger, namespace::Namespace},
    consensus::{
        beacon::EpochTime,
        roothash::Header,
        state::ConsensusState,
        tendermint::decode_light_block,
        transaction::Transaction,
        verifier::{self, Error},
        BlockMetadata, Event, LightBlock, HEIGHT_LATEST, METHOD_META,
    },
    protocol::Protocol,
    storage::mkvs::{Root, RootType},
    types::{Body, EventKind, HostFetchConsensusEventsRequest, HostFetchConsensusEventsResponse},
};

struct Inner {
    latest_height: Option<u64>,
}

/// A verifier which performs no verification.
pub struct NopVerifier {
    protocol: Arc<Protocol>,
    inner: Arc<Mutex<Inner>>,
}

impl NopVerifier {
    /// Create a new non-verifying verifier.
    pub fn new(protocol: Arc<Protocol>) -> Self {
        Self {
            protocol,
            inner: Arc::new(Mutex::new(Inner {
                latest_height: None,
            })),
        }
    }

    /// Start the non-verifying verifier.
    pub fn start(&self) {
        let logger = get_logger("consensus/cometbft/verifier");
        info!(logger, "Starting consensus noop verifier");
    }

    async fn fetch_light_block(&self, height: u64) -> Result<LightBlock, Error> {
        let result = self
            .protocol
            .call_host_async(Body::HostFetchConsensusBlockRequest { height })
            .await
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        match result {
            Body::HostFetchConsensusBlockResponse { block } => Ok(block),
            _ => Err(Error::VerificationFailed(anyhow!("bad response from host"))),
        }
    }
}

#[async_trait]
impl verifier::Verifier for NopVerifier {
    async fn sync(&self, height: u64) -> Result<(), Error> {
        let height = self.fetch_light_block(height).await?.height; // Ensure height is valid.

        let mut inner = self.inner.lock().unwrap();
        inner.latest_height = Some(height);

        Ok(())
    }

    async fn verify(
        &self,
        consensus_block: LightBlock,
        _runtime_header: Header,
        _epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        self.unverified_state(consensus_block).await
    }

    async fn verify_for_query(
        &self,
        consensus_block: LightBlock,
        _runtime_header: Header,
        _epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        self.unverified_state(consensus_block).await
    }

    async fn unverified_state(&self, consensus_block: LightBlock) -> Result<ConsensusState, Error> {
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        // NOTE: No actual verification is performed.
        let state_root = untrusted_block.get_state_root();

        let mut inner = self.inner.lock().unwrap();
        if state_root.version + 1 > inner.latest_height.unwrap_or_default() {
            inner.latest_height = Some(state_root.version + 1);
        }

        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        ))
    }

    async fn latest_state(&self) -> Result<ConsensusState, Error> {
        let height = self.latest_height().await?;

        // When latest state is requested we always perform same-block execution verification.
        let result = self
            .protocol
            .call_host_async(Body::HostFetchBlockMetadataTxRequest { height })
            .await
            .map_err(|err| Error::StateRoot(err.into()))?;

        // NOTE: This is a noop verifier so we do not verify the Merkle proof.
        let signed_tx = match result {
            Body::HostFetchBlockMetadataTxResponse { signed_tx, .. } => signed_tx,
            _ => return Err(Error::StateRoot(anyhow!("bad response from host"))),
        };

        let tx: Transaction = cbor::from_slice(signed_tx.blob.as_slice()).map_err(|err| {
            Error::TransactionVerificationFailed(anyhow!("failed to decode transaction: {}", err))
        })?;

        if tx.method != METHOD_META {
            return Err(Error::StateRoot(anyhow!("invalid method name")));
        }

        let meta: BlockMetadata = cbor::from_value(tx.body).map_err(|err| {
            Error::StateRoot(anyhow!(
                "failed to decode block metadata transaction: {}",
                err
            ))
        })?;

        let state_root = Root {
            namespace: Namespace::default(),
            version: height,
            root_type: RootType::State,
            hash: meta.state_root,
        };

        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version,
            state_root,
        ))
    }

    async fn state_at(&self, height: u64) -> Result<ConsensusState, Error> {
        let block = self.fetch_light_block(height).await?;
        self.unverified_state(block).await
    }

    async fn events_at(&self, height: u64, kind: EventKind) -> Result<Vec<Event>, Error> {
        let result = self
            .protocol
            .call_host_async(Body::HostFetchConsensusEventsRequest(
                HostFetchConsensusEventsRequest { height, kind },
            ))
            .await
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        match result {
            Body::HostFetchConsensusEventsResponse(HostFetchConsensusEventsResponse { events }) => {
                Ok(events)
            }
            _ => Err(Error::VerificationFailed(anyhow!("bad response from host"))),
        }
    }

    async fn latest_height(&self) -> Result<u64, Error> {
        {
            let inner = self.inner.lock().unwrap();
            if let Some(latest_height) = inner.latest_height {
                return Ok(latest_height);
            }
        }

        let latest_height = self.fetch_light_block(HEIGHT_LATEST).await?.height;
        self.sync(latest_height).await?;
        Ok(latest_height)
    }
}
