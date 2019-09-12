use std::any::Any;

use failure::Fallible;
use io_context::Context;
use serde_bytes;
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{urkel::tree::*, Prefix},
};

use super::Proof;

/// Identifies a specific tree and a position within that tree.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TreeID {
    /// The Merkle tree root.
    pub root: Root,
    /// The caller's position in the tree structure to allow
    /// returning partial proofs if possible.
    pub position: Hash,
}

/// Request for the SyncGet operation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GetRequest {
    pub tree: TreeID,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    #[serde(default)]
    pub include_siblings: bool,
}

/// Request for the SyncGetPrefixes operation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GetPrefixesRequest {
    pub tree: TreeID,
    pub prefixes: Vec<Prefix>,
    pub limit: u16,
}

/// Request for the SyncIterate operation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IterateRequest {
    pub tree: TreeID,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    pub prefetch: u16,
}

/// Response for requests that produce proofs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProofResponse {
    pub proof: Proof,
}

/// ReadSync is the interface for synchronizing the in-memory cache
/// with another (potentially untrusted) MKVS.
pub trait ReadSync {
    /// Return `self` as an `Any` object, useful for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Fetch a single key and returns the corresponding proof.
    fn sync_get(&mut self, ctx: Context, request: GetRequest) -> Fallible<ProofResponse>;

    /// Fetch all keys under the given prefixes and returns the corresponding proofs.
    fn sync_get_prefixes(
        &mut self,
        ctx: Context,
        request: GetPrefixesRequest,
    ) -> Fallible<ProofResponse>;

    /// Seek to a given key and then fetch the specified number of following items
    /// based on key iteration order.
    fn sync_iterate(&mut self, ctx: Context, request: IterateRequest) -> Fallible<ProofResponse>;
}
