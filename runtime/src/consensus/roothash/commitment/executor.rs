use crate::common::crypto::hash::Hash;

/// Compute results header signature context.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
pub const COMPUTE_RESULTS_HEADER_CONTEXT: &[u8] = b"oasis-core/roothash: compute results header";

/// The header of a computed batch output by a runtime. This header is a
/// compressed representation (e.g., hashes instead of full content) of
/// the actual results.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/commitment/executor.go.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ComputeResultsHeader {
    /// Round number.
    pub round: u64,
    /// Hash of the previous block header this batch was computed against.
    pub previous_hash: Hash,

    /// The I/O merkle root.
    #[cbor(optional)]
    pub io_root: Option<Hash>,
    /// The root hash of the state after computing this batch.
    #[cbor(optional)]
    pub state_root: Option<Hash>,
    /// Hash of messages sent from this batch.
    #[cbor(optional)]
    pub messages_hash: Option<Hash>,

    /// The hash of processed incoming messages.
    #[cbor(optional)]
    pub in_msgs_hash: Option<Hash>,
    /// The number of processed incoming messages.
    #[cbor(optional)]
    pub in_msgs_count: u32,
}

impl ComputeResultsHeader {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use crate::common::crypto::hash::Hash;

    use super::*;

    #[test]
    fn test_consistent_hash_compute_results_header() {
        // NOTE: These hashes MUST be synced with go/roothash/api/commitment/executor_test.go.
        let empty = ComputeResultsHeader::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")
        );

        let populated = ComputeResultsHeader {
            round: 42,
            previous_hash: empty.encoded_hash(),
            io_root: Some(Hash::empty_hash()),
            state_root: Some(Hash::empty_hash()),
            messages_hash: Some(Hash::empty_hash()),
            in_msgs_hash: Some(Hash::empty_hash()),
            in_msgs_count: 0,
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("8459a9e6e3341cd2df5ada5737469a505baf92397aaa88b7100915324506d843")
        );
    }
}
