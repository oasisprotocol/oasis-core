use anyhow::Result;

use crate::storage::mkvs::{
    cache::{Cache, ReadSyncFetcher},
    sync::{GetRequest, Proof, ProofBuilder, ReadSync, TreeID},
    tree::{Depth, Key, KeyTrait, NodeBox, NodeKind, NodePtrRef, Root, Tree, Value},
};

pub(super) struct FetcherSyncGet<'a> {
    key: &'a Key,
    include_siblings: bool,
}

impl<'a> FetcherSyncGet<'a> {
    pub(super) fn new(key: &'a Key, include_siblings: bool) -> Self {
        Self {
            key,
            include_siblings,
        }
    }
}

impl ReadSyncFetcher for FetcherSyncGet<'_> {
    fn fetch(&self, root: Root, ptr: NodePtrRef, rs: &mut Box<dyn ReadSync>) -> Result<Proof> {
        let rsp = rs.sync_get(GetRequest {
            tree: TreeID {
                root,
                position: ptr.borrow().hash,
            },
            key: self.key.clone(),
            include_siblings: self.include_siblings,
        })?;
        Ok(rsp.proof)
    }
}

impl Tree {
    /// Get an existing key.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self._get_top(key, false)
    }

    pub fn get_proof(&self, key: &[u8]) -> Result<Option<Proof>> {
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        let mut proof_builder = ProofBuilder::new(pending_root.as_ref().borrow().hash);

        let result = self._get(pending_root, 0, &boxed_key, false, Some(&mut proof_builder))?;
        match result {
            Some(_) => Ok(Some(proof_builder.build())),
            None => Ok(None),
        }
    }

    /// Check if the key exists in the local cache.
    pub fn cache_contains_key(&self, key: &[u8]) -> bool {
        match self._get_top(key, true) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false,
        }
    }

    fn _get_top(&self, key: &[u8], check_only: bool) -> Result<Option<Vec<u8>>> {
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        self._get(pending_root, 0, &boxed_key, check_only, None)
    }

    fn _get(
        &self,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        check_only: bool,
        mut proof_builder: Option<&mut ProofBuilder>,
    ) -> Result<Option<Value>> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ptr,
            if check_only {
                None
            } else {
                Some(FetcherSyncGet::new(key, false))
            },
        )?;

        // Include nodes in proof if we have a proof builder.
        if let (Some(pb), Some(node_ref)) = (proof_builder.as_mut(), &node_ref) {
            pb.include(&node_ref.borrow());
        }

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                // Reached a nil node, there is nothing here.
                Ok(None)
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                    // Internal node.
                    // Does lookup key end here? Look into LeafNode.
                    if key.bit_length() == bit_depth + n.label_bit_length {
                        return self._get(
                            n.leaf_node.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            check_only,
                            proof_builder,
                        );
                    }

                    // Lookup key is too short for the current n.Label. It's not stored.
                    if key.bit_length() < bit_depth + n.label_bit_length {
                        return Ok(None);
                    }

                    // Continue recursively based on a bit value.
                    if key.get_bit(bit_depth + n.label_bit_length) {
                        return self._get(
                            n.right.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            check_only,
                            proof_builder,
                        );
                    } else {
                        return self._get(
                            n.left.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            check_only,
                            proof_builder,
                        );
                    }
                }

                unreachable!("node kind is internal node");
            }
            NodeKind::Leaf => {
                // Reached a leaf node, check if key matches.
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == *key {
                    Ok(Some(noderef_as!(node_ref, Leaf).value.clone()))
                } else {
                    Ok(None)
                }
            }
        }
    }
}
