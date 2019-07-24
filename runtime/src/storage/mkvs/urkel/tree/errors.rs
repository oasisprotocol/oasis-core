use failure::Fail;

use crate::common::crypto::hash::Hash;

#[derive(Debug, Fail)]
pub enum TreeError {
    #[fail(display = "urkel: node has dirty pointers")]
    DirtyPointers,
    #[fail(display = "urkel: node has dirty value")]
    DirtyValue,
    #[fail(
        display = "urkel: node/value hash mismatch (expected {:?}, computed {:?})",
        expected_hash, computed_hash
    )]
    HashMismatch {
        expected_hash: Hash,
        computed_hash: Hash,
    },
    #[fail(display = "urkel: malformed node")]
    MalformedNode,
    #[fail(display = "urkel: malformed key")]
    MalformedKey,
}
