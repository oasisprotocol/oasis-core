use std::sync::Arc;

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::{cache::*, sync::*, tree::*};

pub(super) struct FetcherSyncGet<'a> {
    key: &'a Key,
    include_siblings: bool,
}

impl<'a> FetcherSyncGet<'a> {
    pub(super) fn new(key: &'a Key, include_siblings: bool) -> Self {
        Self {
            key,
            include_siblings,
        }
    }
}

impl<'a> ReadSyncFetcher for FetcherSyncGet<'a> {
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Fallible<Proof> {
        let rsp = rs.sync_get(
            ctx,
            GetRequest {
                tree: TreeID {
                    root,
                    position: ptr.borrow().hash,
                },
                key: self.key.clone(),
                include_siblings: self.include_siblings,
            },
        )?;
        Ok(rsp.proof)
    }
}

impl Tree {
    /// Get an existing key.
    pub fn get(&self, ctx: Context, key: &[u8]) -> Fallible<Option<Vec<u8>>> {
        self._get_top(ctx, key, false)
    }

    /// Check if the key exists in the local cache.
    pub fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        match self._get_top(ctx, key, true) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false,
        }
    }

    fn _get_top(&self, ctx: Context, key: &[u8], check_only: bool) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();

        // If the key has been modified locally, no need to perform any lookups.
        if let Some(PendingLogEntry { ref value, .. }) = self.pending_write_log.get(&boxed_key) {
            return Ok(value.clone());
        }

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        Ok(self._get(&ctx, pending_root, 0, &boxed_key, 0, check_only)?)
    }

    fn _get(
        &self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        depth: Depth,
        check_only: bool,
    ) -> Fallible<Option<Value>> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            ptr,
            if check_only {
                None
            } else {
                Some(FetcherSyncGet::new(key, false))
            },
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                // Reached a nil node, there is nothing here.
                return Ok(None);
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                    // Internal node.
                    // Does lookup key end here? Look into LeafNode.
                    if key.bit_length() == bit_depth + n.label_bit_length {
                        return self._get(
                            ctx,
                            n.leaf_node.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth,
                            check_only,
                        );
                    }

                    // Lookup key is too short for the current n.Label. It's not stored.
                    if key.bit_length() < bit_depth + n.label_bit_length {
                        return Ok(None);
                    }

                    // Continue recursively based on a bit value.
                    if key.get_bit(bit_depth + n.label_bit_length) {
                        return self._get(
                            ctx,
                            n.right.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth + 1,
                            check_only,
                        );
                    } else {
                        return self._get(
                            ctx,
                            n.left.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth + 1,
                            check_only,
                        );
                    }
                }

                unreachable!("node kind is internal node");
            }
            NodeKind::Leaf => {
                // Reached a leaf node, check if key matches.
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == *key {
                    return Ok(Some(noderef_as!(node_ref, Leaf).value.clone()));
                } else {
                    return Ok(None);
                }
            }
        };
    }
}
