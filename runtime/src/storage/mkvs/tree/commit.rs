use std::sync::Arc;

use anyhow::Result;
use io_context::Context;

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{cache::*, tree::*},
};

impl Tree {
    /// Commit tree updates to the underlying database and return
    /// the write log and new merkle root.
    pub fn commit(&mut self, ctx: Context, namespace: Namespace, version: u64) -> Result<Hash> {
        let ctx = ctx.freeze();
        let mut update_list: UpdateList<LRUCache> = UpdateList::new();
        let pending_root = self.cache.borrow().get_pending_root();
        let new_hash = _commit(&ctx, pending_root.clone(), &mut update_list, Some(version))?;

        update_list.commit(&mut self.cache.borrow_mut());

        self.cache.borrow_mut().set_sync_root(Root {
            namespace,
            version,
            root_type: self.root_type,
            hash: new_hash,
        });

        Ok(new_hash)
    }
}

pub fn _commit<C: Cache>(
    ctx: &Arc<Context>,
    ptr: NodePtrRef,
    update_list: &mut UpdateList<C>,
    version: Option<u64>,
) -> Result<Hash> {
    if ptr.borrow().clean {
        return Ok(ptr.borrow().hash);
    }

    match classify_noderef!(? ptr.borrow().node) {
        NodeKind::None => {
            ptr.borrow_mut().hash = Hash::empty_hash();
        }
        NodeKind::Internal => {
            let some_node_ref = ptr.borrow().get_node();
            if some_node_ref.borrow().is_clean() {
                ptr.borrow_mut().hash = some_node_ref.borrow().get_hash();
            } else {
                let int_leaf_node = noderef_as!(some_node_ref, Internal).leaf_node.clone();
                let int_left = noderef_as!(some_node_ref, Internal).left.clone();
                let int_right = noderef_as!(some_node_ref, Internal).right.clone();

                _commit(ctx, int_leaf_node.clone(), update_list, version)?;
                _commit(ctx, int_left.clone(), update_list, version)?;
                _commit(ctx, int_right.clone(), update_list, version)?;

                if let Some(version) = version {
                    noderef_as_mut!(some_node_ref, Internal).version = version;
                }
                some_node_ref.borrow_mut().update_hash();
                ptr.borrow_mut().hash = some_node_ref.borrow().get_hash();

                let closure_node_ref = some_node_ref.clone();
                update_list.push(Box::new(move |_| {
                    noderef_as_mut!(closure_node_ref, Internal).clean = true
                }));
            }
        }
        NodeKind::Leaf => {
            let node_ref = ptr.borrow().get_node();
            if node_ref.borrow().is_clean() {
                ptr.borrow_mut().hash = node_ref.borrow().get_hash();
            } else {
                if let Some(version) = version {
                    noderef_as_mut!(node_ref, Leaf).version = version;
                }
                node_ref.borrow_mut().update_hash();
                ptr.borrow_mut().hash = node_ref.borrow().get_hash();

                let closure_node_ref = node_ref.clone();
                update_list.push(Box::new(move |_| {
                    noderef_as_mut!(closure_node_ref, Leaf).clean = true
                }));
            }
        }
    };

    let closure_ptr = ptr.clone();
    update_list.push(Box::new(move |cache| {
        closure_ptr.borrow_mut().clean = true;
        // Make node eligible for eviction.
        cache.commit_node(closure_ptr.clone());
    }));

    Ok(ptr.borrow().hash)
}
