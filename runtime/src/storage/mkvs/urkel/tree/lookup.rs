use std::sync::Arc;

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, tree::*};

impl UrkelTree {
    /// Get an existing key.
    pub fn get(&self, ctx: Context, key: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();
        Ok(self._get(&ctx, pending_root, 0, boxed_key)?)
    }

    fn _get(
        &self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        depth: DepthType,
        key: Key,
    ) -> Fallible<Option<Value>> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: &key,
                depth: depth,
            },
            ptr,
            Some(&key),
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                // Reached a nil node, there is nothing here.
                return Ok(None);
            }
            NodeKind::Internal => {
                // Internal node.
                // Is lookup key a prefix of longer stored keys? Look in node_ref.leaf_node.
                let node_ref = node_ref.unwrap();
                if key.bit_length() == depth {
                    return self._get(
                        ctx,
                        noderef_as!(node_ref, Internal).leaf_node.clone(),
                        depth,
                        key,
                    );
                }
                // Continue recursively based on a bit value.
                else if key.get_bit(depth) {
                    return self._get(
                        ctx,
                        noderef_as!(node_ref, Internal).right.clone(),
                        depth + 1,
                        key,
                    );
                } else {
                    return self._get(
                        ctx,
                        noderef_as!(node_ref, Internal).left.clone(),
                        depth + 1,
                        key,
                    );
                }
            }
            NodeKind::Leaf => {
                // Reached a leaf node, check if key matches.
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == key {
                    return Ok(self
                        .cache
                        .borrow_mut()
                        .deref_value_ptr(ctx, noderef_as!(node_ref, Leaf).value.clone())?);
                } else {
                    return Ok(None);
                }
            }
        };
    }
}
