use std::sync::Arc;

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{
        cache::*,
        tree::*,
        utils::{self, *},
    },
};

impl UrkelTree {
    /// Remove a key from the tree and return true if the tree was modified.
    pub fn remove(&mut self, ctx: Context, key: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();

        let (new_root, changed, old_val) = self._remove(&ctx, pending_root, 0, &boxed_key)?;
        match self.pending_write_log.get_mut(&boxed_key) {
            None => {
                self.pending_write_log.insert(
                    boxed_key.clone(),
                    PendingLogEntry {
                        key: boxed_key,
                        value: None,
                        existed: changed,
                    },
                );
            }
            Some(ref mut entry) => {
                entry.value = None;
            }
        };
        self.cache.borrow_mut().set_pending_root(new_root);

        Ok(old_val)
    }

    fn _remove(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        depth: DepthType,
        key: &Key,
    ) -> Fallible<(NodePtrRef, bool, Option<Value>)> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: key,
                depth: depth,
            },
            ptr.clone(),
            Some(key),
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                return Ok((NodePointer::null_ptr(), false, None));
            }
            NodeKind::Internal => {
                // Remove from internal node and recursively collapse the path, if needed.
                let node_ref = node_ref.unwrap();
                let (changed, old_val) = {
                    let (new_child, changed, old_val) = if key.bit_length() == depth {
                        self._remove(
                            ctx,
                            noderef_as!(node_ref, Internal).leaf_node.clone(),
                            depth,
                            key,
                        )?
                    } else if key.get_bit(depth) {
                        self._remove(
                            ctx,
                            noderef_as!(node_ref, Internal).right.clone(),
                            depth + 1,
                            key,
                        )?
                    } else {
                        self._remove(
                            ctx,
                            noderef_as!(node_ref, Internal).left.clone(),
                            depth + 1,
                            key,
                        )?
                    };

                    if key.bit_length() == depth {
                        noderef_as_mut!(node_ref, Internal).leaf_node = new_child;
                    } else if key.get_bit(depth) {
                        noderef_as_mut!(node_ref, Internal).right = new_child;
                    } else {
                        noderef_as_mut!(node_ref, Internal).left = new_child;
                    }
                    (changed, old_val)
                };

                let lr_id = NodeID {
                    path: &key,
                    depth: depth + 1,
                };

                let remaining_leaf = self.cache.borrow_mut().deref_node_ptr(
                    ctx,
                    NodeID {
                        path: &key,
                        depth: depth,
                    },
                    noderef_as!(node_ref, Internal).leaf_node.clone(),
                    None,
                )?;
                let remaining_left = self.cache.borrow_mut().deref_node_ptr(
                    ctx,
                    lr_id.clone(),
                    noderef_as!(node_ref, Internal).left.clone(),
                    None,
                )?;
                let remaining_right = self.cache.borrow_mut().deref_node_ptr(
                    ctx,
                    lr_id.clone(),
                    noderef_as!(node_ref, Internal).right.clone(),
                    None,
                )?;

                // Check the remaining children: If exactly one leaf remains (either leaf_node,
                // left, or right), collapse it.
                match remaining_leaf {
                    Some(_) => match remaining_left {
                        Some(_) => (),
                        None => match remaining_right {
                            None => {
                                let node = noderef_as!(node_ref, Internal).leaf_node.clone();
                                noderef_as_mut!(node_ref, Internal).leaf_node =
                                    NodePointer::null_ptr();
                                self.cache.borrow_mut().remove_node(ptr.clone());
                                return Ok((node, true, old_val));
                            }
                            Some(_) => (),
                        },
                    },
                    None => match remaining_left {
                        Some(_) => match classify_noderef!(?remaining_left) {
                            NodeKind::Leaf => match remaining_right {
                                None => {
                                    let node = noderef_as!(node_ref, Internal).left.clone();
                                    noderef_as_mut!(node_ref, Internal).left =
                                        NodePointer::null_ptr();
                                    self.cache.borrow_mut().remove_node(ptr.clone());
                                    return Ok((node, true, old_val));
                                }
                                Some(_) => (),
                            },
                            _ => (),
                        },
                        None => match remaining_right {
                            None => (),
                            Some(_) => match classify_noderef!(?remaining_right) {
                                NodeKind::Leaf => {
                                    let node = noderef_as!(node_ref, Internal).right.clone();
                                    noderef_as_mut!(node_ref, Internal).right =
                                        NodePointer::null_ptr();
                                    self.cache.borrow_mut().remove_node(ptr.clone());
                                    return Ok((node, true, old_val));
                                }
                                _ => (),
                            },
                        },
                    },
                };

                // Two or more children including LeafNode remain, just mark dirty bit.
                if changed {
                    if let NodeBox::Internal(ref mut int) = *node_ref.borrow_mut() {
                        int.clean = false;
                    }
                    ptr.borrow_mut().clean = false;
                    // No longer eligible for eviction as it is dirty.
                    self.cache
                        .borrow_mut()
                        .rollback_node(ptr.clone(), NodeKind::Internal);
                }

                return Ok((ptr.clone(), changed, old_val));
            }
            NodeKind::Leaf => {
                // Remove from leaf node.
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == *key {
                    let old_val = noderef_as!(node_ref, Leaf).value.borrow().value.clone();
                    self.cache.borrow_mut().remove_node(ptr.clone());
                    return Ok((NodePointer::null_ptr(), true, old_val));
                }
                return Ok((ptr.clone(), false, None));
            }
        };
    }
}
