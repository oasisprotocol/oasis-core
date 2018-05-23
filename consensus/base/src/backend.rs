//! Consensus backend interface.
use ekiden_common::bytes::{B256, B64};
use ekiden_common::error::Error;
use ekiden_common::futures::{BoxFuture, BoxStream, Executor, Future, Stream};
use ekiden_common::signature::Signed;

use super::{Block, Commitment, Header, Reveal};

/// Signature context used for block submissions.
pub const BLOCK_SUBMIT_SIGNATURE_CONTEXT: B64 = B64(*b"EkBlkSub");

/// Notification of a protocol event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// All commitments have been received for the current round.
    ///
    /// This signals to the worker that it can submit its reveal.
    CommitmentsReceived,
    /// Round failed.
    RoundFailed(Error),
}

/// Consensus backend implementing the Ekiden consensus interface.
pub trait ConsensusBackend: Sync + Send {
    /// Start consensus backend.
    fn start(&self, executor: &mut Executor);

    /// Ask the backend tasks to terminate.
    fn shutdown(&self);

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

    /// Submit the block for the current round.
    ///
    /// The signature should be made using `BLOCK_SUBMIT_SIGNATURE_CONTEXT`.
    fn submit(&self, contract_id: B256, block: Signed<Block>) -> BoxFuture<()>;
}
