//! Root hash backend interface.
use ekiden_common::bytes::{B256, H256};
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{BoxFuture, BoxStream, Future, Stream};

use super::{Block, Commitment, Header};

/// Notification of a protocol event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Discrepancy resolution required.
    ///
    /// This signals to the backup workers that they should re-execute the computation,
    /// where the argument is the hash of the [`CallBatch`].
    ///
    /// [`CallBatch`]: ekiden_contract_common::batch::CallBatch
    DiscrepancyDetected(H256),
    /// Round failed.
    RoundFailed(Error),
}

/// Root hash backend interface.
pub trait RootHashBackend: Sync + Send {
    /// Return the latest block.
    ///
    /// The metadata contained in this block can be further used to get the latest
    /// state from the storage backend.
    fn get_latest_block(&self, contract_id: B256) -> BoxFuture<Block> {
        Box::new(
            self.get_blocks(contract_id)
                .take(1)
                .into_future()
                .then(|result| match result {
                    Ok((Some(block), _)) => Ok(block),
                    Ok((None, _)) => Err(Error::new("no blocks in the chain")),
                    Err((error, _)) => Err(error),
                }),
        )
    }

    /// Return a stream of blocks.
    ///
    /// Blocks will get pushed into the stream as they are confirmed by the root hash
    /// backend.
    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block>;

    /// Return a stream of events.
    fn get_events(&self, contract_id: B256) -> BoxStream<Event>;

    /// Commit to results of processing a batch of contract invocations.
    fn commit(&self, contract_id: B256, commitment: Commitment) -> BoxFuture<()>;
}

/// Signer for given root hash backend.
pub trait RootHashSigner: Sync + Send {
    /// Sign a commitment for a given header.
    fn sign_commitment(&self, header: &Header) -> Result<Commitment>;
}
