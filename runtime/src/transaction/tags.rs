//! Transaction tags.
use crate::common::crypto::hash::Hash;

/// Tag is a key/value pair of arbitrary byte blobs with runtime-dependent
/// semantics which can be indexed to allow easier lookup of blocks and
/// transactions on runtime clients.
#[derive(Clone, Debug, Default)]
pub struct Tag {
    /// The tag key.
    pub key: Vec<u8>,
    /// The tag value.
    pub value: Vec<u8>,
    /// The hash of the transaction that emitted the tag.
    pub tx_hash: Hash,
}

/// A set of tags.
pub type Tags = Vec<Tag>;

impl Tag {
    /// Create a new tag.
    ///
    /// The transaction hash is not initialized.
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            key,
            value,
            ..Default::default()
        }
    }
}
