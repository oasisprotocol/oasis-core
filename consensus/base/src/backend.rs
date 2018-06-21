//! Consensus backend interface.
use ekiden_common::bytes::{B256, H256};
use ekiden_common::error::Error;
use ekiden_common::futures::{BoxFuture, BoxStream, Future, Stream};

use super::{Block, Commitment, Header, Reveal};

/// Notification of a protocol event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// All commitments have been received for the current round.
    ///
    /// This signals to the worker that it can submit its reveal. The boolean flag
    /// indicates whether the event has been emitted during discrepancy resolution.
    CommitmentsReceived(bool),
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

/// Consensus backend implementing the Ekiden consensus interface.
pub trait ConsensusBackend: Sync + Send {
    /// Return the latest consensus block.
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

    /// Return a stream of consensus blocks.
    ///
    /// Blocks will get pushed into the stream as they are confirmed by the consensus
    /// backend.
    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block>;

    /// Return a stream of consensus events.
    fn get_events(&self, contract_id: B256) -> BoxStream<Event>;

    /// Commit to results of processing a batch of contract invocations.
    ///
    /// The passed `commitment` must be over the block header.
    fn commit(&self, contract_id: B256, commitment: Commitment) -> BoxFuture<()>;

    /// Reveal the block header that was committed to previously using `commit`.
    fn reveal(&self, contract_id: B256, reveal: Reveal<Header>) -> BoxFuture<()>;

    /// Commit to results of processing multiple batches of contract invocations.
    ///
    /// Each passed `commitment` must be over the block header.
    fn commit_many(&self, contract_id: B256, commitments: Vec<Commitment>) -> BoxFuture<()>;

    /// Reveal multiple block headers that were committed to previously using `commit` or `commit_many`.
    fn reveal_many(&self, contract_id: B256, reveals: Vec<Reveal<Header>>) -> BoxFuture<()>;
}
