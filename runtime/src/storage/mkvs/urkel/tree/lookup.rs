use std::sync::Arc;

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, tree::*, utils::*},
};

impl UrkelTree {
    /// Get an existing key.
    pub fn get(&self, ctx: Context, key: &[u8]) -> Fallible<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let hkey = Hash::digest_bytes(key);
        let pending_root = self.cache.borrow().get_pending_root();
        Ok(self._get(&ctx, pending_root, 0, hkey)?)
    }

    fn _get(
        &self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        depth: u8,
        key: Hash,
    ) -> Fallible<Option<Value>> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            NodeID {
                path: key,
                depth: depth,
            },
            ptr,
            Some(key),
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                return Ok(None);
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                if get_key_bit(&key, depth) {
                    return self._get(
                        ctx,
                        noderef_as!(node_ref, Internal).right.clone(),
                        depth + 1,
                        key,
                    );
                } else {
                    return self._get(
                        ctx,
                        noderef_as!(node_ref, Internal).left.clone(),
                        depth + 1,
                        key,
                    );
                }
            }
            NodeKind::Leaf => {
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == key {
                    return Ok(self
                        .cache
                        .borrow_mut()
                        .deref_value_ptr(ctx, noderef_as!(node_ref, Leaf).value.clone())?);
                } else {
                    return Ok(None);
                }
            }
        };
    }
}
