use std::collections::HashMap;

use crate::common::crypto::{hash::Hash, signature::PublicKey};

use super::ExecutorCommitment;

/// Pool is a serializable pool of scheduler commitments that can be used
/// to perform discrepancy detection and resolution.
///
/// The pool is not safe for concurrent use.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct Pool {
    /// The rank of the highest-ranked scheduler among those who have submitted
    // a commitment for their own proposal. The maximum value indicates that
    // no scheduler has submitted a commitment.
    #[cbor(optional)]
    pub highest_rank: u64,

    /// A map that groups scheduler commitments and worker votes
    /// by the scheduler's rank.
    #[cbor(optional)]
    pub scheduler_commitments: HashMap<u64, SchedulerCommitment>,

    /// A flag signalling that a discrepancy has been detected.
    #[cbor(optional)]
    pub discrepancy: bool,
}

/// Structure for storing scheduler commitment and its votes.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SchedulerCommitment {
    /// Verified scheduler's commitment for which votes are being collected.
    #[cbor(optional)]
    pub commitment: Option<ExecutorCommitment>,

    /// Votes collected from nodes, keyed by commitment hashes.
    ///
    /// A `None` vote indicates a failure.
    pub votes: Option<HashMap<PublicKey, Option<Hash>>>,
}
