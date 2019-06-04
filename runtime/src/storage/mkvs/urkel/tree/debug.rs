use std::{cmp::max, collections::BTreeMap, iter::repeat, sync::Arc};

use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, tree::*};

impl UrkelTree {
    /// Traverse the tree and return some statistics about it.
    pub fn stats(&mut self, ctx: Context, max_depth: DepthType) -> UrkelStats {
        let ctx = ctx.freeze();
        let mut stats = UrkelStats {
            left_subtree_max_depths: BTreeMap::new(),
            right_subtree_max_depths: BTreeMap::new(),
            cache: self.cache.borrow_mut().stats(),
            ..Default::default()
        };
        let pending_root = self.cache.borrow().get_pending_root();
        self._stats(&ctx, &mut stats, pending_root, Key::new(), 0, max_depth);
        stats
    }

    fn _stats(
        &mut self,
        ctx: &Arc<Context>,
        stats: &mut UrkelStats,
        ptr: NodePtrRef,
        path: Key,
        depth: DepthType,
        max_depth: DepthType,
    ) -> DepthType {
        if max_depth > 0 && depth > max_depth {
            return depth;
        }

        if depth > stats.max_depth {
            stats.max_depth = depth;
        }

        let node_ref = self
            .cache
            .borrow_mut()
            .deref_node_ptr(
                ctx,
                NodeID {
                    path: &path,
                    depth: depth,
                },
                ptr,
                None,
            )
            .ok()
            .unwrap_or(None);

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                stats.dead_node_count += 1;
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                stats.internal_node_count += 1;

                let left_depth = self._stats(
                    ctx,
                    stats,
                    noderef_as!(node_ref, Internal).left.clone(),
                    path.set_bit(depth, false),
                    depth + 1,
                    max_depth,
                );
                if left_depth - depth > *stats.left_subtree_max_depths.get(&depth).unwrap_or(&0) {
                    stats
                        .left_subtree_max_depths
                        .insert(depth, left_depth - depth);
                }

                let right_depth = self._stats(
                    ctx,
                    stats,
                    noderef_as!(node_ref, Internal).right.clone(),
                    path.set_bit(depth, true),
                    depth + 1,
                    max_depth,
                );
                if right_depth - depth > *stats.right_subtree_max_depths.get(&depth).unwrap_or(&0) {
                    stats
                        .right_subtree_max_depths
                        .insert(depth, right_depth - depth);
                }

                return max(left_depth, right_depth);
            }
            NodeKind::Leaf => {
                let node_ref = node_ref.unwrap();
                let value = self
                    .cache
                    .borrow_mut()
                    .deref_value_ptr(ctx, noderef_as!(node_ref, Leaf).value.clone());
                let value = match value {
                    Err(err) => panic!("{}", err),
                    Ok(value) => value,
                };

                stats.leaf_node_count += 1;
                if let Some(ref value) = value {
                    stats.leaf_value_size += value.len();
                }
            }
        };

        depth
    }

    /// Get an object that can be formatted using `{:#?}`.
    pub fn get_dumpable(&mut self) -> NodePtrRef {
        self.cache.borrow().get_pending_root().clone()
    }

    /// Dump the tree into the given writer.
    pub fn dump(&mut self, ctx: Context, w: &mut impl ::std::io::Write) -> ::std::io::Result<()> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        self._dump(&ctx, w, pending_root, Key::new(), 0)?;
        writeln!(w, "")
    }

    fn _dump(
        &mut self,
        ctx: &Arc<Context>,
        w: &mut impl ::std::io::Write,
        ptr: NodePtrRef,
        path: Key,
        depth: DepthType,
    ) -> ::std::io::Result<()> {
        let prefix = repeat(" ").take(depth as usize * 2).collect::<String>();

        let node = self
            .cache
            .borrow_mut()
            .deref_node_ptr(
                ctx,
                NodeID {
                    path: &path,
                    depth: depth,
                },
                ptr,
                None,
            )
            .ok()
            .unwrap_or(None);

        match classify_noderef!(?node) {
            NodeKind::None => write!(w, "{}<nil>", prefix),
            NodeKind::Internal => {
                let some_node_ref = match node {
                    Some(ref node) => node,
                    _ => unreachable!(),
                };
                write!(
                    w,
                    "{}+ [{}/{:?}]: {{\n",
                    prefix,
                    noderef_as!(some_node_ref, Internal).clean,
                    noderef_as!(some_node_ref, Internal).hash
                )?;
                self._dump(
                    ctx,
                    w,
                    noderef_as!(some_node_ref, Internal).left.clone(),
                    path.set_bit(depth, false),
                    depth + 1,
                )?;
                writeln!(w, ",")?;
                self._dump(
                    ctx,
                    w,
                    noderef_as!(some_node_ref, Internal).right.clone(),
                    path.set_bit(depth, true),
                    depth + 1,
                )?;
                writeln!(w, "")?;
                write!(w, "{}}}", prefix)
            }
            NodeKind::Leaf => {
                let some_node_ref = match node {
                    Some(ref node) => node,
                    _ => unreachable!(),
                };
                let value = self
                    .cache
                    .borrow_mut()
                    .deref_value_ptr(ctx, noderef_as!(some_node_ref, Leaf).value.clone());
                match value {
                    Err(err) => write!(w, "<ERROR: {}>", err.as_fail()),
                    Ok(value) => write!(
                        w,
                        "{}- {:?} -> {:?} [{}/{:?}]",
                        prefix,
                        noderef_as!(some_node_ref, Leaf).key,
                        value,
                        noderef_as!(some_node_ref, Leaf).clean,
                        noderef_as!(some_node_ref, Leaf).hash
                    ),
                }
            }
        }
    }
}
