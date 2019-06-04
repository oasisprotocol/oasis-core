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
        ptr: NodePtrRef,
        depth: DepthType,
        key: &Key,
        val: Value,
    ) -> Fallible<(NodePtrRef, Option<Value>)> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: key,
                depth: depth,
            },
            ptr.clone(),
            None,
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                return Ok((self.cache.borrow_mut().new_leaf_node(key, val), None));
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();

                let rec_node = match *node_ref.borrow() {
                    NodeBox::Internal(ref int) => {
                        if key.bit_length() == depth {
                            int.leaf_node.clone()
                        } else if key.get_bit(depth) {
                            int.right.clone()
                        } else {
                            int.left.clone()
                        }
                    }
                    _ => unreachable!(),
                };
                let mut new_depth = depth + 1;
                if key.bit_length() == depth {
                    new_depth = depth;
                }

                let (new_root, old_val) = self._insert(ctx, rec_node, new_depth, key, val)?;

                if key.bit_length() == depth {
                    noderef_as_mut!(node_ref, Internal).leaf_node = new_root;
                } else if key.get_bit(depth) {
                    noderef_as_mut!(node_ref, Internal).right = new_root;
                } else {
                    noderef_as_mut!(node_ref, Internal).left = new_root;
                }

                if let NodeBox::Internal(ref mut int) = *node_ref.borrow_mut() {
                    if !int.left.borrow().clean || !int.right.borrow().clean {
                        int.clean = false;
                        ptr.borrow_mut().clean = false;
                    }
                }
                return Ok((ptr.clone(), old_val));
            }
            NodeKind::Leaf => {
                // If the key matches, we can just update the value.
                let node_ref = node_ref.unwrap();
                let mut pointers: (NodePtrRef, NodePtrRef, NodePtrRef); // leaf_node, left, right
                let none_ptr = Rc::new(RefCell::new(NodePointer {
                    node: None,
                    ..Default::default()
                }));

                let mut leaf_key = Key::new();
                if let NodeBox::Leaf(ref mut leaf) = *node_ref.borrow_mut() {
                    leaf_key = leaf.key.clone();

                    // Should always succeed.
                    if leaf_key == *key {
                        match leaf.value.borrow().value {
                            // TODO check comparison; hash
                            Some(ref leaf_val) => {
                                if leaf_val == &val {
                                    return Ok((ptr.clone(), leaf.value.borrow().value.clone()));
                                }
                            }
                            _ => {}
                        };
                        self.cache.borrow_mut().remove_value(leaf.value.clone());
                        let old_val = leaf.value.borrow().value.clone();
                        leaf.value = self.cache.borrow_mut().new_value(val);
                        leaf.clean = false;
                        ptr.borrow_mut().clean = false;
                        return Ok((ptr.clone(), old_val));
                    }
                }

                // If the key mismatches, three cases are possible:
                if key.bit_length() == depth {
                    // Case 1: key is a prefix of n.Key
                    pointers = if leaf_key.get_bit(depth) {
                        (
                            /* leaf_node */
                            self.cache.borrow_mut().new_leaf_node(key, val),
                            /* left */ none_ptr.clone(),
                            /* right */ ptr.clone(),
                        )
                    } else {
                        (
                            /* leaf_node */
                            self.cache.borrow_mut().new_leaf_node(key, val),
                            /* left */ ptr.clone(),
                            /* right */ none_ptr.clone(),
                        )
                    }
                } else if leaf_key.bit_length() == depth {
                    // Case 2: n.Key is a prefix of key
                    pointers = if key.get_bit(depth) {
                        (
                            /* leaf_node */ ptr.clone(),
                            /* left */ none_ptr.clone(),
                            /* right */ self.cache.borrow_mut().new_leaf_node(key, val),
                        )
                    } else {
                        (
                            /* leaf_node */ ptr.clone(),
                            /* left */ self.cache.borrow_mut().new_leaf_node(key, val),
                            /* right */ none_ptr.clone(),
                        )
                    }
                } else {
                    // Case 3: length of common prefix of n.Key and key is shorter than
                    //         len(n.Key) and len(key)
                    pointers = if key.get_bit(depth) != leaf_key.get_bit(depth) {
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
                    } else {
                        let (new_root, _) = self._insert(ctx, ptr.clone(), depth + 1, key, val)?;
                        if leaf_key.get_bit(depth) {
                            // (leaf_node, left, right)
                            (none_ptr.clone(), none_ptr.clone(), new_root)
                        } else {
                            // (leaf_node, left, right)
                            (none_ptr.clone(), new_root, none_ptr.clone())
                        }
                    };
                }

                let new_internal = self
                    .cache
                    .borrow_mut()
                    .new_internal_node(pointers.0, pointers.1, pointers.2);
                return Ok((new_internal.clone(), None));
            }
        }
    }
}
