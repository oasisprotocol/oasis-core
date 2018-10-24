//! Root hash backend interface.
use ekiden_common::bytes::{B256, H256};
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{BoxFuture, BoxStream, Future, Stream};
use ekiden_common::uint::U256;

use super::{Block, Commitment, Header};

/// Notification of a protocol event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Discrepancy resolution required.
    ///
    /// This signals to the backup workers that they should re-execute the computation,
    /// where the argument is the hash of the [`CallBatch`]. The second argument is the
    /// block [`Header`] which the computation should be based upon.
    ///
    /// [`CallBatch`]: ekiden_runtime_common::batch::CallBatch
    DiscrepancyDetected(H256, Header),
}

/// Root hash backend interface.
pub trait RootHashBackend: Sync + Send {
    /// Return the latest block.
    ///
    /// The metadata contained in this block can be further used to get the latest
    /// state from the storage backend.
    fn get_latest_block(&self, runtime_id: B256) -> BoxFuture<Block> {
        Box::new(
            self.get_blocks(runtime_id)
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
    /// The latest block will get pushed into the stream. Then, subsequent blocks will get pushed
    /// into the stream as they are confirmed by the root hash backend.
    fn get_blocks(&self, runtime_id: B256) -> BoxStream<Block>;

    /// Return a stream of blocks starting with the one from a specified round.
    ///
    /// The one at the specified round is included. Later blocks are pushed in order, and blocks
    /// will get pushed as they are confirmed.
    fn get_blocks_since(&self, runtime_id: B256, round: U256) -> BoxStream<Block>;

    /// Return a stream of events.
    fn get_events(&self, runtime_id: B256) -> BoxStream<Event>;

    /// Commit to results of processing a batch of runtime invocations.
    fn commit(&self, runtime_id: B256, commitment: Commitment) -> BoxFuture<()>;
}

/// Signer for given root hash backend.
pub trait RootHashSigner: Sync + Send {
    /// Sign a commitment for a given header.
    fn sign_commitment(&self, header: &Header) -> Result<Commitment>;
}
