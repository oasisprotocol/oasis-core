use std::{cell::RefCell, rc::Rc, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, tree::*, utils::*},
};

impl UrkelTree {
    /// Insert a key/value pair into the tree.
    pub fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let hkey = Hash::digest_bytes(key);
        let pending_root = self.cache.borrow().get_pending_root();
        let boxed_val = value.to_vec();

        let (new_root, old_val) = self._insert(&ctx, pending_root, 0, hkey, boxed_val.clone())?;
        let existed = old_val != None;
        match self.pending_write_log.get_mut(&hkey) {
            None => {
                self.pending_write_log.insert(
                    hkey,
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
        depth: u8,
        key: Hash,
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

                let go_right = get_key_bit(&key, depth);
                let rec_node = match *node_ref.borrow() {
                    NodeBox::Internal(ref int) => {
                        if go_right {
                            int.right.clone()
                        } else {
                            int.left.clone()
                        }
                    }
                    _ => unreachable!(),
                };
                let (new_root, old_val) = self._insert(ctx, rec_node, depth + 1, key, val)?;

                if go_right {
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
                let node_ref = node_ref.unwrap();
                if let NodeBox::Leaf(ref mut leaf) = *node_ref.borrow_mut() {
                    // Should always succeed.
                    if leaf.key == key {
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

                let existing_bit = if let NodeBox::Leaf(ref leaf) = *node_ref.borrow() {
                    get_key_bit(&leaf.key, depth)
                } else {
                    unreachable!();
                };
                let new_bit = get_key_bit(&key, depth);

                let none_ptr = Rc::new(RefCell::new(NodePointer {
                    node: None,
                    ..Default::default()
                }));
                let pointers = if new_bit != existing_bit {
                    if existing_bit {
                        (
                            /* left */ self.cache.borrow_mut().new_leaf_node(key, val),
                            /* right */ ptr.clone(),
                        )
                    } else {
                        (
                            /* left */ ptr.clone(),
                            /* right */ self.cache.borrow_mut().new_leaf_node(key, val),
                        )
                    }
                } else {
                    let (new_root, _) = self._insert(ctx, ptr.clone(), depth + 1, key, val)?;
                    if existing_bit {
                        (none_ptr.clone(), new_root) // (left, right)
                    } else {
                        (new_root, none_ptr.clone()) // (left, right)
                    }
                };
                let new_internal = self
                    .cache
                    .borrow_mut()
                    .new_internal_node(pointers.0, pointers.1);
                return Ok((new_internal.clone(), None));
            }
        }
    }
}
