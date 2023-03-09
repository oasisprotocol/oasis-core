//! The read-only tree sync interface.
mod errors;
mod host;
mod merge;
mod noop;
mod proof;
mod stats;

pub use errors::*;
pub use host::*;
pub use merge::*;
pub use noop::*;
pub use proof::*;
pub use stats::*;

use std::any::Any;

use anyhow::Result;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{tree::*, Prefix},
};

/// Identifies a specific tree and a position within that tree.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct TreeID {
    /// The Merkle tree root.
    pub root: Root,
    /// The caller's position in the tree structure to allow
    /// returning partial proofs if possible.
    pub position: Hash,
}

/// Request for the SyncGet operation.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct GetRequest {
    pub tree: TreeID,
    pub key: Vec<u8>,
    #[cbor(optional)]
    pub include_siblings: bool,
}

/// Request for the SyncGetPrefixes operation.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct GetPrefixesRequest {
    pub tree: TreeID,
    pub prefixes: Vec<Prefix>,
    pub limit: u16,
}

/// Request for the SyncIterate operation.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct IterateRequest {
    pub tree: TreeID,
    pub key: Vec<u8>,
    pub prefetch: u16,
}

/// Response for requests that produce proofs.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct ProofResponse {
    pub proof: Proof,
}

/// ReadSync is the interface for synchronizing the in-memory cache
/// with another (potentially untrusted) MKVS.
pub trait ReadSync {
    /// Return `self` as an `Any` object, useful for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Fetch a single key and returns the corresponding proof.
    fn sync_get(&mut self, request: GetRequest) -> Result<ProofResponse>;

    /// Fetch all keys under the given prefixes and returns the corresponding proofs.
    fn sync_get_prefixes(&mut self, request: GetPrefixesRequest) -> Result<ProofResponse>;

    /// Seek to a given key and then fetch the specified number of following items
    /// based on key iteration order.
    fn sync_iterate(&mut self, request: IterateRequest) -> Result<ProofResponse>;
}

#[cfg(test)]
mod test;
