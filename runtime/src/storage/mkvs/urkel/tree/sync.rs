use std::{any::Any, sync::Arc};

use failure::{Error, Fallible};
use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, sync::*, tree::*};

impl ReadSync for UrkelTree {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        ctx: Context,
        root: Root,
        id: NodeID,
        max_depth: Depth,
    ) -> Fallible<Subtree> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        if root != self.cache.borrow().get_sync_root() {
            return Err(SyncerError::InvalidRoot.into());
        }
        if !pending_root.borrow().clean {
            return Err(SyncerError::DirtyRoot.into());
        }

        let (subtree_root, bd) = self.cache.borrow_mut().deref_node_id(&ctx, id)?;
        if subtree_root.borrow().is_null() {
            return Err(SyncerError::NodeNotFound.into());
        }

        // path corresponds to already navigated prefix of the key up to bd bits.
        let (path, _) = id.path.split(bd, id.path.bit_length());
        let mut subtree = Subtree::new();

        let root_ptr = self._get_subtree(
            &ctx,
            subtree_root,
            bd,
            &path,
            &mut subtree,
            0,
            max_depth,
            if id.path.len() > 0 {
                id.path.get_bit(bd)
            } else {
                false
            },
        )?;
        subtree.root = root_ptr;
        if !subtree.root.valid {
            Err(SyncerError::InvalidRoot.into())
        } else {
            Ok(subtree)
        }
    }

    fn get_path(
        &mut self,
        ctx: Context,
        root: Root,
        key: &Key,
        start_bit_depth: Depth,
    ) -> Fallible<Subtree> {
        let ctx = ctx.freeze();
        if root != self.cache.borrow().get_sync_root() {
            return Err(SyncerError::InvalidRoot.into());
        }
        if !self.cache.borrow().get_pending_root().borrow().clean {
            return Err(SyncerError::DirtyRoot.into());
        }

        let (subtree_root, bd) = self
            .cache
            .borrow_mut()
            .deref_node_id(
                &ctx,
                NodeID {
                    path: key,
                    bit_depth: start_bit_depth,
                },
            )
            .map_err(|_| Error::from(SyncerError::NodeNotFound))?;

        let mut subtree = Subtree::new();

        // path corresponds to already navigated prefix of the key up to bd bits.
        let (path, _) = key.split(bd, key.bit_length());
        subtree.root = self._get_path(
            &ctx,
            subtree_root,
            bd,
            &path,
            Some(key),
            &mut subtree,
            if key.len() > 0 {
                key.get_bit(bd)
            } else {
                false
            },
        )?;
        if !subtree.root.valid {
            Err(SyncerError::InvalidRoot.into())
        } else {
            Ok(subtree)
        }
    }

    fn get_node(&mut self, ctx: Context, root: Root, id: NodeID) -> Fallible<NodeRef> {
        let ctx = ctx.freeze();
        if root != self.cache.borrow().get_sync_root() {
            Err(SyncerError::InvalidRoot.into())
        } else if !self.cache.borrow().get_pending_root().borrow().clean {
            Err(SyncerError::DirtyRoot.into())
        } else {
            let ptr = self
                .cache
                .borrow_mut()
                .deref_node_id(&ctx, id)
                .map_err(|_| Error::from(SyncerError::NodeNotFound))?
                .0;
            let node = self
                .cache
                .borrow_mut()
                .deref_node_ptr(&ctx, id, ptr, None)
                .map_err(|_| Error::from(SyncerError::NodeNotFound))?;
            Ok(node.unwrap().borrow().extract())
        }
    }
}

impl UrkelTree {
    fn _get_subtree(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        path: &Key,
        st: &mut Subtree,
        depth: Depth,
        max_depth: Depth,
        right: bool,
    ) -> Fallible<SubtreePointer> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: &path.append_bit(bit_depth, right),
                bit_depth: bit_depth + 1,
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

                summary.label = noderef_as!(node_ref, Internal).label.clone();
                summary.label_bit_length = noderef_as!(node_ref, Internal).label_bit_length;

                let new_path = path.merge(
                    bit_depth,
                    &noderef_as!(node_ref, Internal).label,
                    noderef_as!(node_ref, Internal).label_bit_length,
                );
                summary.leaf_node = self._get_subtree(
                    ctx,
                    noderef_as!(node_ref, Internal).leaf_node.clone(),
                    bit_depth + noderef_as!(node_ref, Internal).label_bit_length,
                    &new_path,
                    st,
                    depth,
                    max_depth,
                    false,
                )?;
                summary.left = self._get_subtree(
                    ctx,
                    noderef_as!(node_ref, Internal).left.clone(),
                    bit_depth + noderef_as!(node_ref, Internal).label_bit_length,
                    &new_path,
                    st,
                    depth + 1,
                    max_depth,
                    false,
                )?;
                summary.right = self._get_subtree(
                    ctx,
                    noderef_as!(node_ref, Internal).right.clone(),
                    bit_depth + noderef_as!(node_ref, Internal).label_bit_length,
                    &new_path,
                    st,
                    depth + 1,
                    max_depth,
                    true,
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
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        path: &Key,
        key: Option<&Key>,
        st: &mut Subtree,
        right: bool,
    ) -> Fallible<SubtreePointer> {
        let ext_path = path.append_bit(bit_depth, right);
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: &ext_path,
                bit_depth: bit_depth + 1,
            },
            ptr.clone(),
            Some(&ext_path),
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

        if key.is_none() {
            // Off-path nodes are always full nodes.
            let idx = st.add_full_node(node_ref.borrow().extract())?;
            return Ok(SubtreePointer {
                index: idx,
                full: true,
                valid: true,
            });
        }
        let key = key.expect("key is not none");

        match classify_noderef!(node_ref) {
            NodeKind::None => unreachable!(),
            NodeKind::Internal => {
                // Determine which subtree is off-path.
                let (mut left_key, mut right_key) = (None, None);
                if bit_depth + noderef_as!(node_ref, Internal).label_bit_length < key.bit_length() {
                    if key.get_bit(bit_depth + noderef_as!(node_ref, Internal).label_bit_length) {
                        // Left subtree is off-path.
                        right_key = Some(key)
                    } else {
                        // Right subtree is off-path.
                        left_key = Some(key)
                    }
                }

                let mut summary = InternalNodeSummary {
                    ..Default::default()
                };

                summary.label = noderef_as!(node_ref, Internal).label.clone();
                summary.label_bit_length = noderef_as!(node_ref, Internal).label_bit_length;

                let new_path = path.merge(
                    bit_depth,
                    &noderef_as!(node_ref, Internal).label,
                    noderef_as!(node_ref, Internal).label_bit_length,
                );
                summary.leaf_node = self._get_path(
                    ctx,
                    noderef_as!(node_ref, Internal).leaf_node.clone(),
                    bit_depth + noderef_as!(node_ref, Internal).label_bit_length,
                    &new_path,
                    Some(&path),
                    st,
                    false,
                )?;
                summary.left = self._get_path(
                    ctx,
                    noderef_as!(node_ref, Internal).left.clone(),
                    bit_depth + noderef_as!(node_ref, Internal).label_bit_length,
                    &new_path,
                    left_key,
                    st,
                    false,
                )?;
                summary.right = self._get_path(
                    ctx,
                    noderef_as!(node_ref, Internal).right.clone(),
                    bit_depth + noderef_as!(node_ref, Internal).label_bit_length,
                    &new_path,
                    right_key,
                    st,
                    true,
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
