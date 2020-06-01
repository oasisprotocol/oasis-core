use std::{mem, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::{cache::*, tree::*};

use super::lookup::FetcherSyncGet;

impl Tree {
    /// Insert a key/value pair into the tree.
    pub fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        let boxed_key = key.to_vec();
        let boxed_val = value.to_vec();

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        let (new_root, old_val) =
            self._insert(&ctx, pending_root, 0, &boxed_key, boxed_val.clone(), 0)?;
        let existed = old_val != None;
        match self.pending_write_log.get_mut(&boxed_key) {
            None => {
                self.pending_write_log.insert(
                    boxed_key,
                    PendingLogEntry {
                        key: key.to_vec(),
                        value: Some(boxed_val.clone()),
                        existed: existed,
                    },
                );
            }
            Some(ref mut entry) => {
                entry.value = Some(boxed_val.clone());
            }
        };
        self.cache.borrow_mut().set_pending_root(new_root.clone());

        Ok(old_val)
    }

    fn _insert(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        val: Value,
        depth: Depth,
    ) -> Fallible<(NodePtrRef, Option<Value>)> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            ptr.clone(),
            Some(FetcherSyncGet::new(key, false)),
        )?;

        let (_, key_remainder) = key.split(bit_depth, key.bit_length());

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                return Ok((self.cache.borrow_mut().new_leaf_node(key, val), None));
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
                let cp_len: Depth;
                let label_prefix: Key;
                if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                    cp_len = n.label.common_prefix_len(
                        n.label_bit_length,
                        &key_remainder,
                        key.bit_length() - bit_depth,
                    );

                    if cp_len == n.label_bit_length {
                        // The current part of key matched the node's Label. Do recursion.
                        let r: (NodePtrRef, Option<Value>);
                        if key.bit_length() == bit_depth + n.label_bit_length {
                            // Key to insert ends exactly at this node. Add it to the
                            // existing internal node as LeafNode.
                            r = self._insert(
                                ctx,
                                n.leaf_node.clone(),
                                bit_depth + n.label_bit_length,
                                key,
                                val,
                                depth,
                            )?;
                            n.leaf_node = r.0;
                        } else if key.get_bit(bit_depth + n.label_bit_length) {
                            // Insert recursively based on the bit value.
                            r = self._insert(
                                ctx,
                                n.right.clone(),
                                bit_depth + n.label_bit_length,
                                key,
                                val,
                                depth + 1,
                            )?;
                            n.right = r.0;
                        } else {
                            r = self._insert(
                                ctx,
                                n.left.clone(),
                                bit_depth + n.label_bit_length,
                                key,
                                val,
                                depth + 1,
                            )?;
                            n.left = r.0;
                        }

                        if !n.leaf_node.borrow().clean
                            || !n.left.borrow().clean
                            || !n.right.borrow().clean
                        {
                            n.clean = false;
                            ptr.borrow_mut().clean = false;
                            // No longer eligible for eviction as it is dirty.
                            self.cache
                                .borrow_mut()
                                .rollback_node(ptr.clone(), NodeKind::Internal);
                        }

                        return Ok((ptr, r.1));
                    }

                    // Key mismatches the label at position cp_len. Split the edge and
                    // insert new leaf.
                    let label_split = n.label.split(cp_len, n.label_bit_length);
                    label_prefix = label_split.0;
                    n.label = label_split.1;
                    n.label_bit_length = n.label_bit_length - cp_len;
                    n.clean = false;
                    ptr.borrow_mut().clean = false;
                    // No longer eligible for eviction as it is dirty.
                    self.cache
                        .borrow_mut()
                        .rollback_node(ptr.clone(), NodeKind::Internal);

                    let new_leaf = self.cache.borrow_mut().new_leaf_node(key, val);
                    if key.bit_length() - bit_depth == cp_len {
                        // The key is a prefix of existing path.
                        leaf_node = new_leaf;
                        if n.label.get_bit(0) {
                            left = NodePointer::null_ptr();
                            right = ptr;
                        } else {
                            left = ptr;
                            right = NodePointer::null_ptr();
                        }
                    } else {
                        leaf_node = NodePointer::null_ptr();
                        if key_remainder.get_bit(cp_len) {
                            left = ptr;
                            right = new_leaf;
                        } else {
                            left = new_leaf;
                            right = ptr;
                        }
                    }
                } else {
                    return Err(format_err!(
                        "insert.rs: unknown internal node_ref {:?}",
                        node_ref
                    ));
                }

                return Ok((
                    self.cache.borrow_mut().new_internal_node(
                        &label_prefix,
                        cp_len,
                        leaf_node,
                        left,
                        right,
                    ),
                    None,
                ));
            }
            NodeKind::Leaf => {
                // If the key matches, we can just update the value.
                let node_ref = node_ref.unwrap();
                let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
                let cp_len: Depth;
                let label_prefix: Key;
                if let NodeBox::Leaf(ref mut n) = *node_ref.borrow_mut() {
                    // Should always succeed.
                    if n.key == *key {
                        // If the key matches, we can just update the value.
                        if n.value == val {
                            return Ok((ptr.clone(), Some(val)));
                        }
                        let old_val = mem::replace(&mut n.value, val);
                        n.clean = false;
                        ptr.borrow_mut().clean = false;
                        // No longer eligible for eviction as it is dirty.
                        self.cache
                            .borrow_mut()
                            .rollback_node(ptr.clone(), NodeKind::Leaf);
                        return Ok((ptr.clone(), Some(old_val)));
                    }

                    let (_, leaf_key_remainder) = n.key.split(bit_depth, n.key.bit_length());
                    cp_len = leaf_key_remainder.common_prefix_len(
                        n.key.bit_length() - bit_depth,
                        &key_remainder,
                        key.bit_length() - bit_depth,
                    );

                    // Key mismatches the label at position cp_len. Split the edge.
                    label_prefix = leaf_key_remainder
                        .split(cp_len, leaf_key_remainder.bit_length())
                        .0;
                    let new_leaf = self.cache.borrow_mut().new_leaf_node(key, val);

                    if key.bit_length() - bit_depth == cp_len {
                        // Inserted key is a prefix of the label.
                        leaf_node = new_leaf;
                        if leaf_key_remainder.get_bit(cp_len) {
                            left = NodePointer::null_ptr();
                            right = ptr;
                        } else {
                            left = ptr;
                            right = NodePointer::null_ptr();
                        }
                    } else if n.key.bit_length() - bit_depth == cp_len {
                        // Label is a prefix of the inserted key.
                        leaf_node = ptr;
                        if key_remainder.get_bit(cp_len) {
                            left = NodePointer::null_ptr();
                            right = new_leaf;
                        } else {
                            left = new_leaf;
                            right = NodePointer::null_ptr();
                        }
                    } else {
                        leaf_node = NodePointer::null_ptr();
                        if key_remainder.get_bit(cp_len) {
                            left = ptr;
                            right = new_leaf;
                        } else {
                            left = new_leaf;
                            right = ptr;
                        }
                    }
                } else {
                    return Err(format_err!(
                        "insert.rs: invalid leaf node_ref {:?}",
                        node_ref
                    ));
                }

                let new_internal = self.cache.borrow_mut().new_internal_node(
                    &label_prefix,
                    cp_len,
                    leaf_node,
                    left,
                    right,
                );
                return Ok((new_internal, None));
            }
        }
    }
}
