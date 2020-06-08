use anyhow::{anyhow, Result};

use crate::storage::mkvs::tree::*;

/// Merges a previously verified subtree with an existing tree.
pub fn merge_verified_subtree(
    dst: NodePtrRef,
    subtree: NodePtrRef,
    updater: &mut Vec<NodePtrRef>,
) -> Result<()> {
    let dst_ref = dst;
    let mut dst = dst_ref.borrow_mut();
    let subtree = subtree.borrow();
    if dst.is_null() || subtree.is_null() {
        return Ok(());
    }

    if !dst.clean {
        // TODO: Support merging into non-clean subtrees. If a subtree
        //       is not clean, this means that the tree structure may
        //       be changed.
        return Err(anyhow!(
            "merger: merging into non-clean subtree not yet supported"
        ));
    }

    // If the destination pointer is clean, sanity check that we are
    // merging correct nodes.
    if dst.hash != subtree.hash {
        return Err(anyhow!(
            "merger: hash mismatch during merge (expected: {:?} got: {:?})",
            dst.hash,
            subtree.hash,
        ));
    }

    // If the subtree node is nil, there is nothing more to merge.
    if subtree.node.is_none() {
        return Ok(());
    }

    // If destination node is nil, we can simply replace the whole subtree.
    if dst.node.is_none() {
        dst.node = subtree.node.clone();
        drop(dst);
        updater.push(dst_ref);
        return Ok(());
    }

    if let NodeBox::Internal(ref int_dst) = *dst.node.as_ref().unwrap().borrow() {
        if let NodeBox::Internal(ref int_subtree) = *subtree.node.as_ref().unwrap().borrow() {
            // Proceed with merging children.
            merge_verified_subtree(int_dst.left.clone(), int_subtree.left.clone(), updater)?;
            merge_verified_subtree(int_dst.right.clone(), int_subtree.right.clone(), updater)?;
        } else {
            panic!("hash was the same so nodes must be of the same type");
        }
    }

    Ok(())
}
