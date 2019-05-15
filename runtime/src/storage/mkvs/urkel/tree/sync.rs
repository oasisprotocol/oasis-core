use std::{any::Any, sync::Arc};

use failure::{Error, Fallible};
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, sync::*, tree::*},
};

impl ReadSync for UrkelTree {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        ctx: Context,
        root: Root,
        id: NodeID,
        max_depth: DepthType,
    ) -> Fallible<Subtree> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        if root != self.cache.borrow().get_sync_root() {
            return Err(SyncerError::InvalidRoot.into());
        }
        if !pending_root.borrow().clean {
            return Err(SyncerError::DirtyRoot.into());
        }

        let subtree_root = self.cache.borrow_mut().deref_node_id(&ctx, id)?;
        if subtree_root.borrow().is_null() {
            return Err(SyncerError::NodeNotFound.into());
        }

        let path = Key::new();
        let mut subtree = Subtree::new();

        let root_ptr = self._get_subtree(&ctx, subtree_root, 0, path, &mut subtree, max_depth)?;
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
        start_depth: DepthType,
    ) -> Fallible<Subtree> {
        let ctx = ctx.freeze();
        if root != self.cache.borrow().get_sync_root() {
            return Err(SyncerError::InvalidRoot.into());
        }
        if !self.cache.borrow().get_pending_root().borrow().clean {
            return Err(SyncerError::DirtyRoot.into());
        }

        let subtree_root = self
            .cache
            .borrow_mut()
            .deref_node_id(
                &ctx,
                NodeID {
                    path: key,
                    depth: start_depth,
                },
            )
            .map_err(|_| Error::from(SyncerError::NodeNotFound))?;

        let mut subtree = Subtree::new();
        // We can use key as path as all the bits up to start_depth must match key. We
        // could clear all of the bits after start_depth, but there is no reason to do so.
        subtree.root = self._get_path(
            &ctx,
            subtree_root,
            start_depth,
            key,
            Some(key),
            &mut subtree,
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
                .map_err(|_| Error::from(SyncerError::NodeNotFound))?;
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
        depth: DepthType,
        path: Key,
        st: &mut Subtree,
        max_depth: DepthType,
    ) -> Fallible<SubtreePointer> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: &path,
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

                summary.leaf_node = self._get_subtree(
                    ctx,
                    noderef_as!(node_ref, Internal).leaf_node.clone(),
                    depth,
                    path.set_bit(depth, false),
                    st,
                    max_depth,
                )?;
                summary.left = self._get_subtree(
                    ctx,
                    noderef_as!(node_ref, Internal).left.clone(),
                    depth + 1,
                    path.set_bit(depth, false),
                    st,
                    max_depth,
                )?;
                summary.right = self._get_subtree(
                    ctx,
                    noderef_as!(node_ref, Internal).right.clone(),
                    depth + 1,
                    path.set_bit(depth, true),
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
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        depth: DepthType,
        path: &Key,
        key: Option<&Key>,
        st: &mut Subtree,
    ) -> Fallible<SubtreePointer> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID { path, depth },
            ptr.clone(),
            key,
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

        if key.is_none() && depth < key.bit_length() {
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
                if utils::get_key_bit(&key, depth) {
                    // Left subtree is off-path.
                    right_key = Some(key)
                } else {
                    // Right subtree is off-path.
                    left_key = Some(key)
                }

                let mut summary = InternalNodeSummary {
                    ..Default::default()
                };

                summary.leaf_node = self._get_path(
                    ctx,
                    noderef_as!(node_ref, Internal).leaf_node.clone(),
                    depth,
                    key,
                    st,
                )?;
                summary.left = self._get_path(
                    ctx,
                    noderef_as!(node_ref, Internal).left.clone(),
                    depth + 1,
                    utils::set_key_bit(&path, depth, false),
                    left_key,
                    st,
                )?;
                summary.right = self._get_path(
                    ctx,
                    noderef_as!(node_ref, Internal).right.clone(),
                    depth + 1,
                    utils::set_key_bit(&path, depth, true),
                    right_key,
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
