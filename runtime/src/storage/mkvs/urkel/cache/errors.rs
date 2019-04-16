use failure::Fail;

use crate::common::crypto::hash::Hash;

#[derive(Debug, Fail)]
pub enum CacheError {
    #[fail(display = "urkel: maximum depth exceeded")]
    MaximumDepthExceeded,
    #[fail(display = "urkel: invalid subtree pointer")]
    InvalidSubtreePointer,
    #[fail(display = "urkel: reconstructed root pointer is nil")]
    ReconstructedRootNil,
    #[fail(
        display = "urkel: syncer returned bad root (expected {:?}, got {:?})",
        expected_root, returned_root
    )]
    SyncerBadRoot {
        expected_root: Hash,
        returned_root: Hash,
    },
}
