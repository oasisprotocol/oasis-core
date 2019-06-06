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
            self._insert(&ctx, pending_root, 0, &boxed_key, boxed_val.clone())?;
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
        root_ptr_ref: NodePtrRef,
        depth: DepthType,
        key: &Key,
        val: Value,
    ) -> Fallible<(NodePtrRef, Option<Value>)> {
        /// Iterative version of the insertion due to rust stack limit for longer keys.
        /// First we find the spot to insert the Leaf and keep track of the path (stack). Then, we
        /// go back from the leaf to the root and update the nodes accordingly.

        // new_node is the deep-most internal node containing the newly inserted/updated leaf as its
        // child.
        let mut new_node: (NodePtrRef, Option<Value>);

        // stack contains all internal nodes from the root to the leaf (excl. leaf).
        let mut stack: Vec<NodePtrRef> = Vec::new();

        // node_ptr_ref is the current node in the iteration.
        let mut node_ptr_ref: NodePtrRef = root_ptr_ref;

        // d is the current depth in the iteration.
        let mut d: DepthType = 0;
        while true {
            let node_ref = self.cache.borrow_mut().deref_node_ptr(
                ctx,
                NodeID {
                    path: key,
                    depth: depth,
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
                    stack.push(
                        match *node_ref.unwrap().borrow() {
                            NodeBox::Internal(ref int) => {
                                if key.bit_length() == d {
                                    int.leaf_node.clone()
                                } else if key.get_bit(d) {
                                    int.right.clone()
                                } else {
                                    int.left.clone()
                                }
                            }
                            _ => unreachable!(),
                        }
                    );

                    if key.bit_length() == d {
                        // Insert the new node as leaf node and finish.
                        let new_leaf_node = self.cache.borrow_mut().new_leaf_node(key, val);
                        noderef_as!(node_ref.unwrap(), Internal).leaf_node = (new_leaf_node, None);
                        new_node = (self
                                        .cache
                                        .borrow_mut()
                                        .new_internal_node(
                                            new_leaf_node,
                                            noderef_as!(node_ref.unwrap(), Internal).left,
                                            noderef_as!(node_ref.unwrap(), Internal).right,
                                        ), None);
                        break;
                    } else {
                        // Check the corresponding child.
                        let go_right = key.get_bit(d);

                        let child_ptr_ref: NodePtrRef;
                        if go_right {
                            child_ptr_ref = noderef_as!(node_ref.unwrap(), Internal).right;
                        } else {
                            child_ptr_ref = noderef_as!(node_ref.unwrap(), Internal).left;
                        }
                        let child_ref = self.cache.borrow_mut().deref_node_ptr(
                            ctx,
                            NodeID {
                                path: key,
                                depth: depth + 1,
                            },
                            child_ptr_ref.clone(),
                            None,
                        )?;
                        match classify_noderef!(?child_ref) {
                            NodeKind::None => {
                                // If it's the end, insert a new leaf and finish.
                                let new_child_node = (self.cache.borrow_mut().new_leaf_node(key, val), None);
                                if go_right {
                                    new_node = (self
                                                    .cache
                                                    .borrow_mut()
                                                    .new_internal_node(
                                                        noderef_as!(node_ref.unwrap(), Internal).leaf_node,
                                                        noderef_as!(node_ref.unwrap(), Internal).left,
                                                        new_child_node
                                                    ), None);
                                } else {
                                    new_node = (self
                                                    .cache
                                                    .borrow_mut()
                                                    .new_internal_node(
                                                        noderef_as!(node_ref.unwrap(), Internal).leaf_node,
                                                        new_child_node,
                                                        noderef_as!(node_ref.unwrap(), Internal).right,
                                                    ), None);
                                }
                                break;
                            }
                            NodeKind::Internal | NodeKind::Leaf => {
                                // If it's another node, we will take care of it the next iteration.
                                node_ptr_ref =
                                    if go_right {
                                        noderef_as!(node_ref.unwrap(), Internal).right
                                    } else {
                                        noderef_as!(node_ref.unwrap(), Internal).left
                                    };
                            }
                        }
                    }
                }
                NodeKind::Leaf => {
                    let mut pointers: (NodePtrRef, NodePtrRef, NodePtrRef); // leaf_node, left, right
                    let none_ptr = Rc::new(RefCell::new(NodePointer {
                        node: None,
                        ..Default::default()
                    }));

                    let mut leaf = noderef_as!(node_ref.unwrap(), Leaf);
                    let mut split_node: NodePtrRef = None;
                    if leaf.key == *key {
                        // If the key matches, we can just update the value.
                        match leaf.value.borrow().value {
                            // TODO check comparison; hash
                            Some(ref leaf_val) => {
                                if leaf_val == &val {
                                    // Values match, do nothing.
                                    split_node = (node_ptr_ref.clone(), leaf.value.borrow().value.clone());
                                }
                            }
                            _ => unreachable!(),
                        };
                        if split_node == None {
                            self.cache.borrow_mut().remove_value(leaf.value.clone());
                            let old_val = leaf.value.borrow().value.clone();
                            leaf.value = self.cache.borrow_mut().new_value(val);
                            leaf.clean = false;
                            node_ptr_ref.borrow_mut().clean = false;
                            split_node = (node_ptr_ref.clone(), old_val);
                        }
                    } else if key.bit_length() == depth {
                        // If the key mismatches, three cases are possible:
                        // Case 1: key is a prefix of leaf.key
                        pointers = if leaf.key.get_bit(depth) {
                            (
                                /* leaf_node */
                                self.cache.borrow_mut().new_leaf_node(key, val),
                                /* left */ none_ptr.clone(),
                                /* right */ node_ref_ptr.clone(),
                            )
                        } else {
                            (
                                /* leaf_node */
                                self.cache.borrow_mut().new_leaf_node(key, val),
                                /* left */ node_ref_ptr.clone(),
                                /* right */ none_ptr.clone(),
                            )
                        }
                    } else if leaf.key.bit_length() == depth {
                        // Case 2: leaf.key is a prefix of key
                        pointers = if key.get_bit(depth) {
                            (
                                /* leaf_node */ node_ref_ptr.clone(),
                                /* left */ none_ptr.clone(),
                                /* right */ self.cache.borrow_mut().new_leaf_node(key, val),
                            )
                        } else {
                            (
                                /* leaf_node */ node_ref_ptr.clone(),
                                /* left */ self.cache.borrow_mut().new_leaf_node(key, val),
                                /* right */ none_ptr.clone(),
                            )
                        }
                    } else {
                        // Case 3: length of common prefix of leaf.key and key is shorter than
                        //         len(leaf.Key) and len(key)
                        if key.get_bit(depth) != leaf.key.get_bit(depth) {
                            pointers =
                                if leaf_key.get_bit(depth) {
                                    (
                                        /* leaf_node */ none_ptr.clone(),
                                        /* left */
                                        self.cache.borrow_mut().new_leaf_node(key, val),
                                        /* right */ ptr.clone(),
                                    )
                                } else {
                                    (
                                        /* leaf_node */ none_ptr.clone(),
                                        /* left */ ptr.clone(),
                                        /* right */
                                        self.cache.borrow_mut().new_leaf_node(key, val),
                                    )
                                }
                        };
                        // Else: Bits matched, increase depth in the next iteration and try again.
                    }

                    if pointers != (None, None, None) {
                        split_node = self
                            .cache
                            .borrow_mut()
                            .new_internal_node(pointers.0, pointers.1, pointers.2);
                    }

                    if stack.len() {
                        let parent_node_ref = self.cache.borrow_mut().deref_node_ptr(
                            ctx,
                            NodeID {
                                path: key,
                                depth: depth,
                            },
                            stack.last().clone(),
                            None,
                        )?;
                        new_node = if noderef_as!(parent_node_ref.unwrap(), Internal).left == node_ptr_ref {
                            (self
                                 .cache
                                 .borrow_mut()
                                 .new_internal_node(
                                     noderef_as!(parent_node_ref.unwrap(), Internal).leaf_node,
                                     split_node,
                                     noderef_as!(parent_node_ref.unwrap(), Internal).right,
                                 ), None)
                        } else if noderef_as!(parent_node_ref.unwrap(), Internal).right == node_ptr_ref {
                            (self
                                 .cache
                                 .borrow_mut()
                                 .new_internal_node(
                                     noderef_as!(parent_node_ref.unwrap(), Internal).leaf_node,
                                     noderef_as!(parent_node_ref.unwrap(), Internal).left,
                                     split_node,
                                 ), None)
                        } else {
                            unreachable!()
                        };
                    } else {
                        new_node = (split_node.clone(), None);
                    }
                    break;
                }
            }
            d += 1;
        }

        // Go back from leaf to root. Since pointers to nodes are immutable, each iteration replace
        // the last node in the stack with new_node and update new_node with the pre-last. Quit the
        // function returning the last (root) node.
        while stack.len()>1 {
            let child_ptr_ref = stack.pop()?;

            let child_ref = self.cache.borrow_mut().deref_node_ptr(
                ctx,
                NodeID {
                    path: key,
                    depth: stack.len(),
                },
                child_ptr_ref.clone(),
                None,
            )?;

            new_node = match classify_noderef!(?child_ref) {
                NodeKind::None => {
                    unreachable!()
                }
                NodeKind::Internal => {
                    node_ptr_ref = stack.last()?;
                    let node_ref = self.cache.borrow_mut().deref_node_ptr(
                        ctx,
                        NodeID {
                            path: key,
                            depth: stack.len()-1,
                        },
                        node_ptr_ref.clone(),
                        None,
                    )?;

                    if noderef_as_mut!(node_ref, Internal).left == child_ptr_ref {
                        noderef_as_mut!(node_ref, Internal).left = new_node.0;
                    } else if noderef_as_mut!(node_ref, Internal).right == child_ptr_ref {
                        noderef_as_mut!(node_ref, Internal).left = new_node.0;
                    } else {
                        unreachable!()
                    }

                    if let NodeBox::Internal(ref mut int) = *node_ref.borrow_mut() {
                        if !int.left.borrow().clean || !int.right.borrow().clean {
                            int.clean = false;
                            node_ptr_ref.borrow_mut().clean = false;
                        }
                    }
                    (node_ptr_ref.clone(), new_node.1)
                }
                NodeKind::Leaf => {
                    unreachable!()
                }
            }
        }

        new_node
    }
}
