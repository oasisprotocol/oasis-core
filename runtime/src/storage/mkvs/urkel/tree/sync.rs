use failure::{Error, Fallible};
use std::{any::Any, cell::RefCell, rc::Rc};

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, sync::*, tree::*, utils},
};

impl ReadSync for UrkelTree {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(&mut self, root_hash: Hash, id: NodeID, max_depth: u8) -> Fallible<Subtree> {
        let pending_root = self.cache.borrow().get_pending_root();
        if root_hash != pending_root.borrow().hash {
            return Err(SyncerError::InvalidRoot.into());
        }
        if !pending_root.borrow().clean {
            return Err(SyncerError::DirtyRoot.into());
        }

        let subtree_root = self.cache.borrow_mut().deref_node_id(id)?;
        if subtree_root.borrow().is_null() {
            return Err(SyncerError::NodeNotFound.into());
        }

        let path = Hash::empty_hash();
        let mut subtree = Subtree::new();

        let root_ptr = self._get_subtree(subtree_root, 0, path, &mut subtree, max_depth)?;
        subtree.root = root_ptr;
        if !subtree.root.valid {
            Err(SyncerError::InvalidRoot.into())
        } else {
            Ok(subtree)
        }
    }

    fn get_path(&mut self, root_hash: Hash, key: Hash, start_depth: u8) -> Fallible<Subtree> {
        if root_hash != self.cache.borrow().get_pending_root().borrow().hash {
            return Err(SyncerError::InvalidRoot.into());
        }
        if !self.cache.borrow().get_pending_root().borrow().clean {
            return Err(SyncerError::DirtyRoot.into());
        }

        let subtree_root = self
            .cache
            .borrow_mut()
            .deref_node_id(NodeID {
                path: key,
                depth: start_depth,
            })
            .map_err(|_| Error::from(SyncerError::NodeNotFound))?;

        let mut subtree = Subtree::new();
        subtree.root = self._get_path(subtree_root, start_depth, key, &mut subtree)?;
        if !subtree.root.valid {
            Err(SyncerError::InvalidRoot.into())
        } else {
            Ok(subtree)
        }
    }

    fn get_node(&mut self, root_hash: Hash, id: NodeID) -> Fallible<NodeRef> {
        if root_hash != self.cache.borrow().get_pending_root().borrow().hash {
            Err(SyncerError::InvalidRoot.into())
        } else if !self.cache.borrow().get_pending_root().borrow().clean {
            Err(SyncerError::DirtyRoot.into())
        } else {
            let ptr = self
                .cache
                .borrow_mut()
                .deref_node_id(id)
                .map_err(|_| Error::from(SyncerError::NodeNotFound))?;
            let node = self
                .cache
                .borrow_mut()
                .deref_node_ptr(id, ptr, None)
                .map_err(|_| Error::from(SyncerError::NodeNotFound))?;
            Ok(node.unwrap().borrow().extract())
        }
    }

    fn get_value(&mut self, root_hash: Hash, id: Hash) -> Fallible<Option<Value>> {
        if root_hash != self.cache.borrow().get_pending_root().borrow().hash {
            Err(SyncerError::InvalidRoot.into())
        } else if !self.cache.borrow().get_pending_root().borrow().clean {
            Err(SyncerError::DirtyRoot.into())
        } else {
            self.cache
                .borrow_mut()
                .deref_value_ptr(Rc::new(RefCell::new(ValuePointer {
                    clean: true,
                    hash: id,
                    ..Default::default()
                })))
        }
    }
}

impl UrkelTree {
    fn _get_subtree(
        &mut self,
        ptr: NodePtrRef,
        depth: u8,
        path: Hash,
        st: &mut Subtree,
        max_depth: u8,
    ) -> Fallible<SubtreePointer> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            NodeID {
                path: path,
                depth: depth,
            },
            ptr.clone(),
            None,
        )?;
        let node_ref = match node_ref {
            None => {
                return Ok(SubtreePointer {
                    index: SubtreeIndex::invalid(),
                    valid: true,
                    ..Default::default()
                })
            }
            Some(node_ref) => node_ref,
        };

        if depth >= max_depth {
            // Nodes at max_depth are always full nodes.
            let idx = st.add_full_node(node_ref.borrow().extract())?;
            return Ok(SubtreePointer {
                index: idx,
                full: true,
                valid: true,
            });
        }

        match classify_noderef!(node_ref) {
            NodeKind::None => unreachable!(),
            NodeKind::Internal => {
                let mut summary = InternalNodeSummary {
                    ..Default::default()
                };

                summary.left = self._get_subtree(
                    noderef_as!(node_ref, Internal).left.clone(),
                    depth + 1,
                    utils::set_key_bit(&path, depth, false),
                    st,
                    max_depth,
                )?;
                summary.right = self._get_subtree(
                    noderef_as!(node_ref, Internal).right.clone(),
                    depth + 1,
                    utils::set_key_bit(&path, depth, true),
                    st,
                    max_depth,
                )?;

                let idx = st.add_summary(&summary)?;
                return Ok(SubtreePointer {
                    index: idx,
                    valid: true,
                    ..Default::default()
                });
            }
            NodeKind::Leaf => {
                let idx = st.add_full_node(node_ref.borrow().extract())?;
                return Ok(SubtreePointer {
                    index: idx,
                    full: true,
                    valid: true,
                });
            }
        };
    }

    fn _get_path(
        &mut self,
        ptr: NodePtrRef,
        depth: u8,
        key: Hash,
        st: &mut Subtree,
    ) -> Fallible<SubtreePointer> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            NodeID {
                path: key,
                depth: depth,
            },
            ptr.clone(),
            Some(key),
        )?;
        let node_ref = match node_ref {
            None => {
                return Ok(SubtreePointer {
                    index: SubtreeIndex::invalid(),
                    valid: true,
                    ..Default::default()
                })
            }
            Some(node_ref) => node_ref,
        };

        if !utils::get_key_bit(&key, depth) {
            // Off-path nodes are always full nodes.
            let idx = st.add_full_node(node_ref.borrow().extract())?;
            return Ok(SubtreePointer {
                index: idx,
                full: true,
                valid: true,
            });
        }

        match classify_noderef!(node_ref) {
            NodeKind::None => unreachable!(),
            NodeKind::Internal => {
                let mut summary = InternalNodeSummary {
                    ..Default::default()
                };

                summary.left = self._get_path(
                    noderef_as!(node_ref, Internal).left.clone(),
                    depth + 1,
                    key,
                    st,
                )?;
                summary.right = self._get_path(
                    noderef_as!(node_ref, Internal).right.clone(),
                    depth + 1,
                    key,
                    st,
                )?;

                let idx = st.add_summary(&summary)?;
                return Ok(SubtreePointer {
                    index: idx,
                    full: false,
                    valid: true,
                    ..Default::default()
                });
            }
            NodeKind::Leaf => {
                // All encountered leaves are always full nodes.
                let idx = st.add_full_node(node_ref.borrow().extract())?;
                return Ok(SubtreePointer {
                    index: idx,
                    full: true,
                    valid: true,
                });
            }
        };
    }
}
