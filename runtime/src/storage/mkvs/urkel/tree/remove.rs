use failure::Fallible;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, tree::*, utils::*},
};

impl UrkelTree {
    /// Remove a key from the tree and return true if the tree was modified.
    pub fn remove(&mut self, key: &[u8]) -> Fallible<bool> {
        let hkey = Hash::digest_bytes(key);
        let pending_root = self.cache.borrow().get_pending_root();

        let (new_root, changed) = self._remove(pending_root, 0, hkey)?;
        match self.pending_write_log.get_mut(&hkey) {
            None => {
                self.pending_write_log.insert(
                    hkey,
                    PendingLogEntry {
                        key: key.to_vec(),
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

        Ok(changed)
    }

    fn _remove(&mut self, ptr: NodePtrRef, depth: u8, key: Hash) -> Fallible<(NodePtrRef, bool)> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            NodeID {
                path: key,
                depth: depth,
            },
            ptr.clone(),
            Some(key),
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                return Ok((NodePointer::null_ptr(), false));
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                let changed = {
                    let go_right = get_key_bit(&key, depth);

                    let child = if go_right {
                        noderef_as!(node_ref, Internal).right.clone()
                    } else {
                        noderef_as!(node_ref, Internal).left.clone()
                    };

                    let (child, changed) = self._remove(child, depth + 1, key)?;

                    if go_right {
                        noderef_as_mut!(node_ref, Internal).right = child;
                    } else {
                        noderef_as_mut!(node_ref, Internal).left = child;
                    }
                    changed
                };
                let (int_left, int_right) = (
                    noderef_as!(node_ref, Internal).left.clone(),
                    noderef_as!(node_ref, Internal).right.clone(),
                );

                let lr_id = NodeID {
                    path: key,
                    depth: depth + 1,
                };

                let left_ref = self.cache.borrow_mut().deref_node_ptr(
                    lr_id.clone(),
                    int_left.clone(),
                    None,
                )?;
                match left_ref {
                    None => {
                        let right_ref = self.cache.borrow_mut().deref_node_ptr(
                            lr_id,
                            int_right.clone(),
                            None,
                        )?;
                        let right_ref = match right_ref {
                            None => {
                                // No more children, delete the internal node as well.
                                self.cache.borrow_mut().try_remove_node(ptr.clone());
                                return Ok((NodePointer::null_ptr(), true));
                            }
                            Some(node_ref) => node_ref,
                        };
                        if let NodeBox::Leaf(_) = *right_ref.borrow() {
                            // Left is None, right is a leaf, merge nodes back.
                            return Ok((int_right.clone(), true));
                        };
                    }
                    Some(left_ref) => {
                        if let NodeBox::Leaf(_) = *left_ref.borrow() {
                            let right_ref = self.cache.borrow_mut().deref_node_ptr(
                                lr_id,
                                int_right.clone(),
                                None,
                            )?;
                            if let None = right_ref {
                                // Right is None, left is a leaf, merge nodes back.
                                return Ok((int_left.clone(), true));
                            };
                        }
                    }
                };

                if changed {
                    if let NodeBox::Internal(ref mut int) = *node_ref.borrow_mut() {
                        int.clean = false;
                    }
                    ptr.borrow_mut().clean = false;
                }

                return Ok((ptr.clone(), changed));
            }
            NodeKind::Leaf => {
                // Remove from leaf node.
                let node_ref = node_ref.unwrap();
                let mut remove = false;
                if noderef_as!(node_ref, Leaf).key == key {
                    remove = true;
                }
                if remove {
                    self.cache.borrow_mut().try_remove_node(ptr.clone());
                    return Ok((NodePointer::null_ptr(), true));
                }
                return Ok((ptr.clone(), false));
            }
        };
    }
}
