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
        Ok(self._get(&ctx, pending_root, 0, &boxed_key, 0)?)
    }

    fn _get(
        &self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        depth: Depth,
    ) -> Fallible<Option<Value>> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: &key,
                bit_depth: bit_depth,
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
                        );
                    } else {
                        return self._get(
                            ctx,
                            n.left.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth + 1,
                        );
                    }
                }

                unreachable!("node kind is internal node");
            }
            NodeKind::Leaf => {
                // Reached a leaf node, check if key matches.
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == *key {
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
