use std::{cell::RefCell, rc::Rc, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, tree::*};

impl UrkelTree {
    /// Insert a key/value pair into the tree.
    pub fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        let boxed_key = key.to_vec();
        let boxed_val = value.to_vec();

        let (new_root, old_val) =
            self._insert(&ctx, pending_root, &boxed_key, boxed_val.clone())?;
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

    /// Iterative version of the insertion due to rust stack limit for longer keys.
    ///
    /// First we find the spot and insert or update the Leaf. Along the path, we keep track of
    /// visited nodes (stack) which we then update from the leaf back to the root.
    fn _insert(
        &mut self,
        ctx: &Arc<Context>,
        root_ptr_ref: NodePtrRef,
        key: &Key,
        val: Value,
    ) -> Fallible<(NodePtrRef, Option<Value>)> {
        // new_node is the deep-most internal node containing the newly inserted/updated leaf as its
        // child. The second tuple element is the old value, if the leaf has been updated.
        let mut new_node: (NodePtrRef, Option<Value>) = (NodePointer::null_ptr(), None);

        // stack contains all *internal nodes* from the root to the point of insertion.
        let mut stack: Vec<NodePtrRef> = Vec::new();

        // node_ptr_ref is the current pointer to the node in the iteration.
        let mut node_ptr_ref: NodePtrRef = root_ptr_ref;

        // d is the current depth in the iteration.
        let mut d: DepthType = 0;
        while new_node.0.borrow().is_null() {
            let node_ref = self.cache.borrow_mut().deref_node_ptr(
                ctx,
                NodeID {
                    path: key,
                    depth: d,
                },
                node_ptr_ref.clone(),
                None,
            )?;
            match classify_noderef!(?node_ref) {
                NodeKind::None => {
                    // Empty tree, insert a leaf and finish.
                    return Ok((self.cache.borrow_mut().new_leaf_node(key, val), None));
                }
                NodeKind::Internal => {
                    stack.push(node_ptr_ref.clone());

                    if key.bit_length() == d {
                        // Insert the new node as leaf node and finish. Don't care for existing leaf
                        // node at this depth.
                        let new_leaf_node = self.cache.borrow_mut().new_leaf_node(key, val);
                        noderef_as_mut!(node_ref.clone().unwrap(), Internal).leaf_node = new_leaf_node.clone();
                        new_node = (
                            self.cache.borrow_mut().new_internal_node(
                                new_leaf_node,
                                noderef_as!(node_ref.clone().unwrap(), Internal).left.clone(),
                                noderef_as!(node_ref.clone().unwrap(), Internal).right.clone(),
                            ),
                            None,
                        );
                        break;
                    } else {
                        // We haven't reached and of key yet, find corresponding child.
                        let go_right = key.get_bit(d);

                        let child_ptr_ref = if go_right {
                            noderef_as!(node_ref.clone().unwrap(), Internal).right.clone()
                        } else {
                            noderef_as!(node_ref.clone().unwrap(), Internal).left.clone()
                        };
                        let child_ref = self.cache.borrow_mut().deref_node_ptr(
                            ctx,
                            NodeID {
                                path: key,
                                depth: d + 1,
                            },
                            child_ptr_ref.clone(),
                            None,
                        )?;
                        match classify_noderef!(?child_ref) {
                            NodeKind::None => {
                                // If we reached the end of the tree, insert a new leaf and finish.
                                let new_child_node = self.cache.borrow_mut().new_leaf_node(key, val);
                                new_node = if go_right {
                                    (
                                        self.cache.borrow_mut().new_internal_node(
                                            noderef_as!(node_ref.clone().unwrap(), Internal).leaf_node.clone(),
                                            noderef_as!(node_ref.clone().unwrap(), Internal).left.clone(),
                                            new_child_node,
                                        ),
                                        None,
                                    )
                                } else {
                                    (
                                        self.cache.borrow_mut().new_internal_node(
                                            noderef_as!(node_ref.clone().unwrap(), Internal).leaf_node.clone(),
                                            new_child_node,
                                            noderef_as!(node_ref.clone().unwrap(), Internal).right.clone(),
                                        ),
                                        None,
                                    )
                                };
                                break;
                            }
                            NodeKind::Internal | NodeKind::Leaf => {
                                // If there's another node on the way, we will take care of it the
                                // next iteration.
                                node_ptr_ref = child_ptr_ref.clone();
                            }
                        }
                    }
                }
                NodeKind::Leaf => {
                    // split_node is newly inserted internal node or updated leaf and will be a
                    // child of new_node.
                    let mut split_node: (NodePtrRef, Option<Value>) = (NodePointer::null_ptr(), None);
                    // leaf_node, left, right pointers for split_node.
                    let mut split_node_ptrs: Option<(NodePtrRef, NodePtrRef, NodePtrRef)> = None;

                    if let NodeBox::Leaf(ref mut leaf) = *node_ref.unwrap().borrow_mut() {
                        // If the key matches, we can just update the value.
                        if leaf.key == *key {
                            match leaf.value.borrow().value {
                                // TODO check comparison; hash
                                Some(ref leaf_val) => {
                                    if leaf_val == &val {
                                        // Value also matches, do nothing.
                                        split_node =
                                            (node_ptr_ref.clone(), leaf.value.borrow().value.clone());
                                    }
                                }
                                _ => unreachable!(),
                            };

                            if split_node.0.borrow().is_null() {
                                // Value mismatches, update it.
                                self.cache.borrow_mut().remove_value(leaf.value.clone());
                                let old_val = leaf.value.borrow().value.clone();
                                leaf.value = self.cache.borrow_mut().new_value(val);
                                leaf.clean = false;
                                node_ptr_ref.borrow_mut().clean = false;
                                split_node = (node_ptr_ref.clone(), old_val);
                            }
                        } else if key.bit_length() == d {
                            // Case 1: key is a prefix of leaf.key
                            split_node_ptrs = if leaf.key.get_bit(d) {
                                Some((
                                    /* leaf_node */
                                    self.cache.borrow_mut().new_leaf_node(key, val),
                                    /* left */ NodePointer::null_ptr(),
                                    /* right */ node_ptr_ref.clone(),
                                ))
                            } else {
                                Some((
                                    /* leaf_node */
                                    self.cache.borrow_mut().new_leaf_node(key, val),
                                    /* left */ node_ptr_ref.clone(),
                                    /* right */ NodePointer::null_ptr(),
                                ))
                            }
                        } else if leaf.key.bit_length() == d {
                            // Case 2: leaf.key is a prefix of key
                            split_node_ptrs = if key.get_bit(d) {
                                Some((
                                    /* leaf_node */ node_ptr_ref.clone(),
                                    /* left */ NodePointer::null_ptr(),
                                    /* right */ self.cache.borrow_mut().new_leaf_node(key, val),
                                ))
                            } else {
                                Some((
                                    /* leaf_node */ node_ptr_ref.clone(),
                                    /* left */ self.cache.borrow_mut().new_leaf_node(key, val),
                                    /* right */ NodePointer::null_ptr(),
                                ))
                            }
                        } else {
                            // Case 3: length of common prefix of leaf.key and key is shorter than
                            //         len(leaf.Key) and len(key)
                            if key.get_bit(d) != leaf.key.get_bit(d) {
                                split_node_ptrs = if leaf.key.get_bit(d) {
                                    Some((
                                        /* leaf_node */ NodePointer::null_ptr(),
                                        /* left */
                                        self.cache.borrow_mut().new_leaf_node(key, val),
                                        /* right */ node_ptr_ref.clone(),
                                    ))
                                } else {
                                    Some((
                                        /* leaf_node */ NodePointer::null_ptr(),
                                        /* left */ node_ptr_ref.clone(),
                                        /* right */
                                        self.cache.borrow_mut().new_leaf_node(key, val),
                                    ))
                                }
                            };
                            // Else: Bits matched, increase d in the next iteration and try again.
                        }
                    }

                    match split_node_ptrs {
                        Some(ptrs) => {
                            split_node = (
                                self.cache.borrow_mut().new_internal_node(
                                    ptrs.0,
                                    ptrs.1,
                                    ptrs.2,
                                ),
                                None,
                            );
                        },
                        None => (), // split_node is a leaf
                    };

                    // Update pointers of the split_node's parent. To do this, we need to access
                    // the internal node from the previous iteration by using stack.
                    if stack.len()>0 {
                        let parent_node_ptr_ref = match stack.last() {
                            Some(parent) => parent,
                            _ => unreachable!(),
                        };
                        let parent_node_ref = self.cache.borrow_mut().deref_node_ptr(
                            ctx,
                            NodeID {
                                path: key,
                                depth: d,
                            },
                            parent_node_ptr_ref.clone(),
                            None,
                        )?;
                        new_node = if noderef_as!(parent_node_ref.clone().unwrap(), Internal).left
                            == node_ptr_ref
                        {
                            (
                                self.cache.borrow_mut().new_internal_node(
                                    noderef_as!(parent_node_ref.clone().unwrap(), Internal).leaf_node.clone(),
                                    split_node.0,
                                    noderef_as!(parent_node_ref.clone().unwrap(), Internal).right.clone(),
                                ),
                                split_node.1,
                            )
                        } else if noderef_as!(parent_node_ref.clone().unwrap(), Internal).right
                            == node_ptr_ref
                        {
                            (
                                self.cache.borrow_mut().new_internal_node(
                                    noderef_as!(parent_node_ref.clone().unwrap(), Internal).leaf_node.clone(),
                                    noderef_as!(parent_node_ref.clone().unwrap(), Internal).left.clone(),
                                    split_node.0,
                                ),
                                split_node.1,
                            )
                        } else {
                            unreachable!()
                        };
                    } else {
                        // If stack is empty, then the only element in the tree was a single leaf.
                        // split_node will become the new root.
                        new_node = (split_node.0, split_node.1);
                    }
                    break;
                }
            }
            d += 1;
        }

        // Go back from leaf to root. Repeatedly replace the pointer to the last node in the stack
        // stored in its parent with new_node. The newly obtained pointer is stored as new_node and
        // procedure is repeated until we reach root.
        while stack.len() > 1 {
            let child_ptr_ref = match stack.pop() {
                Some(c) => c,
                None => unreachable!(),
            };

            let child_ref = self.cache.borrow_mut().deref_node_ptr(
                ctx,
                NodeID {
                    path: key,
                    depth: stack.len() as DepthType,
                },
                child_ptr_ref.clone(),
                None,
            )?;

            new_node = match classify_noderef!(?child_ref) {
                NodeKind::None | NodeKind::Leaf => {
                    // This should never happen - stack contains only internal nodes!
                    unreachable!()
                }
                NodeKind::Internal => {
                    node_ptr_ref = match stack.last() {
                        Some(ptr) => ptr.clone(),
                        None => unreachable!(),
                    };
                    let node_ref = self.cache.borrow_mut().deref_node_ptr(
                        ctx,
                        NodeID {
                            path: key,
                            depth: (stack.len() - 1) as DepthType,
                        },
                        node_ptr_ref.clone(),
                        None,
                    )?;

                    if noderef_as!(node_ref.clone().unwrap(), Internal).left == child_ptr_ref {
                        noderef_as_mut!(node_ref.clone().unwrap(), Internal).left = new_node.0;
                    } else if noderef_as!(node_ref.clone().unwrap(), Internal).right == child_ptr_ref {
                        noderef_as_mut!(node_ref.clone().unwrap(), Internal).right = new_node.0;
                    } else {
                        unreachable!()
                    }

                    if let NodeBox::Internal(ref mut int) = *node_ref.unwrap().borrow_mut() {
                        if !int.left.borrow().clean || !int.right.borrow().clean {
                            int.clean = false;
                            node_ptr_ref.borrow_mut().clean = false;
                        }
                    }
                    (node_ptr_ref.clone(), new_node.1)
                }
            }
        }

        // Return the last remaining node in the stack i.e. the pointer to the root node.
        Ok(new_node)
    }
}
