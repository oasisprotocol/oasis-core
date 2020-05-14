use std::sync::Arc;

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::{cache::*, tree::*};

use super::lookup::FetcherSyncGet;

impl Tree {
    /// Remove a key from the tree and return true if the tree was modified.
    pub fn remove(&mut self, ctx: Context, key: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();

        // If the key has already been removed locally, don't try to remove it again.
        if let Some(PendingLogEntry { value: None, .. }) = self.pending_write_log.get(&boxed_key) {
            return Ok(None);
        }

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        let (new_root, changed, old_val) = self._remove(&ctx, pending_root, 0, &boxed_key, 0)?;
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
        bit_depth: Depth,
        key: &Key,
        depth: Depth,
    ) -> Fallible<(NodePtrRef, bool, Option<Value>)> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            ptr.clone(),
            Some(FetcherSyncGet::new(key, true)),
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                // Remove from nil node.
                return Ok((NodePointer::null_ptr(), false, None));
            }
            NodeKind::Internal => {
                // Remove from internal node and recursively collapse the path, if needed.
                let node_ref = node_ref.unwrap();
                let (changed, old_val): (bool, Option<Value>);
                let (remaining_leaf, remaining_left, remaining_right): (
                    Option<NodeRef>,
                    Option<NodeRef>,
                    Option<NodeRef>,
                );
                if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                    // Remove from internal node and recursively collapse the branch, if
                    // needed.
                    let bit_length = bit_depth + n.label_bit_length;

                    if key.bit_length() < bit_length {
                        // Lookup key is too short for the current n.Label, so it doesn't exist.
                        return Ok((ptr.clone(), false, None));
                    }

                    let (new_child, c, o) = if key.bit_length() == bit_length {
                        self._remove(ctx, n.leaf_node.clone(), bit_depth, key, depth)?
                    } else if key.get_bit(bit_length) {
                        self._remove(ctx, n.right.clone(), bit_length, key, depth + 1)?
                    } else {
                        self._remove(ctx, n.left.clone(), bit_length, key, depth + 1)?
                    };

                    changed = c;
                    old_val = o;

                    if key.bit_length() == bit_length {
                        n.leaf_node = new_child;
                    } else if key.get_bit(bit_length) {
                        n.right = new_child;
                    } else {
                        n.left = new_child;
                    }

                    // Fetch and check the remaining children.
                    // NOTE: The leaf node is always included with the internal node.
                    remaining_leaf = n.leaf_node.borrow().node.clone();
                    remaining_left = self.cache.borrow_mut().deref_node_ptr(
                        ctx,
                        n.left.clone(),
                        Some(FetcherSyncGet::new(key, true)),
                    )?;
                    remaining_right = self.cache.borrow_mut().deref_node_ptr(
                        ctx,
                        n.right.clone(),
                        Some(FetcherSyncGet::new(key, true)),
                    )?;
                } else {
                    unreachable!("node kind is Internal");
                }

                // If exactly one child including LeafNode remains, collapse it.
                match remaining_leaf {
                    Some(_) => match remaining_left {
                        Some(_) => (),
                        None => match remaining_right {
                            None => {
                                let nd_leaf = noderef_as!(node_ref, Internal).leaf_node.clone();
                                noderef_as_mut!(node_ref, Internal).leaf_node =
                                    NodePointer::null_ptr();
                                self.cache.borrow_mut().remove_node(ptr.clone());
                                return Ok((nd_leaf, true, old_val));
                            }
                            Some(_) => (),
                        },
                    },
                    None => {
                        let mut nd_child: Option<NodeRef> = None;
                        let mut node_ptr: NodePtrRef = NodePointer::null_ptr();
                        let mut both_children = true;
                        match remaining_left {
                            Some(_) => match remaining_right {
                                None => {
                                    node_ptr = noderef_as!(node_ref, Internal).left.clone();
                                    noderef_as_mut!(node_ref, Internal).left =
                                        NodePointer::null_ptr();
                                    nd_child = remaining_left;
                                    both_children = false;
                                }
                                Some(_) => (),
                            },
                            None => match remaining_right {
                                None => (),
                                Some(_) => {
                                    node_ptr = noderef_as!(node_ref, Internal).right.clone();
                                    noderef_as_mut!(node_ref, Internal).right =
                                        NodePointer::null_ptr();
                                    nd_child = remaining_right;
                                    both_children = false;
                                }
                            },
                        }

                        if !both_children {
                            // If child is an internal node, also fix the label.
                            match nd_child {
                                Some(_) => match classify_noderef!(?nd_child) {
                                    NodeKind::Internal => {
                                        if let NodeBox::Internal(ref mut inode) =
                                            *nd_child.unwrap().borrow_mut()
                                        {
                                            inode.label =
                                                noderef_as!(node_ref, Internal).label.merge(
                                                    noderef_as!(node_ref, Internal)
                                                        .label_bit_length,
                                                    &inode.label,
                                                    inode.label_bit_length,
                                                );
                                            inode.label_bit_length +=
                                                noderef_as!(node_ref, Internal).label_bit_length;
                                            inode.clean = false;
                                            node_ptr.borrow_mut().clean = false;
                                        }
                                    }
                                    _ => (),
                                },
                                _ => (),
                            }

                            self.cache.borrow_mut().remove_node(ptr.clone());
                            return Ok((node_ptr, true, old_val));
                        }
                    }
                };

                // Two or more children including leaf_node remain, just mark dirty bit.
                if changed {
                    noderef_as_mut!(node_ref, Internal).clean = false;
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
                    let old_val = noderef_as!(node_ref, Leaf).value.clone();
                    self.cache.borrow_mut().remove_node(ptr.clone());
                    return Ok((NodePointer::null_ptr(), true, Some(old_val)));
                }

                return Ok((ptr.clone(), false, None));
            }
        };
    }
}
