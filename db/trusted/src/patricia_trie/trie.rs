use std::sync::Arc;

use bincode;

use ekiden_common::bytes::H256;
#[cfg(not(target_env = "sgx"))]
use ekiden_common::futures::Future;
#[cfg(target_env = "sgx")]
use ekiden_common::futures::FutureExt;
use ekiden_storage_base::StorageMapper;

use super::nibble::NibbleVec;
use super::node::{Node, NodePointer};

/// A merkle patricia tree backed by storage.
pub struct PatriciaTrie {
    /// Storage.
    storage: Arc<StorageMapper>,
}

impl PatriciaTrie {
    // TODO: Handle storage expiry.
    const STORAGE_EXPIRY_TIME: u64 = u64::max_value();

    /// Construct a new merkle patricia tree backed by given storage.
    pub fn new(storage: Arc<StorageMapper>) -> Self {
        Self { storage }
    }

    /// Return pointer to root node.
    fn get_root_pointer(&self, root: Option<H256>) -> NodePointer {
        match root {
            Some(root) => NodePointer::Pointer(root),
            None => NodePointer::Null,
        }
    }

    /// Perform a path lookup step based on a node pointer.
    fn get_path_by_pointer(&self, path: NibbleVec, pointer: NodePointer) -> Option<Vec<u8>> {
        match pointer {
            NodePointer::Null => None,
            NodePointer::Pointer(pointer) => {
                let node = self.storage
                    .get(pointer)
                    .wait()
                    .expect("failed to fetch from storage");
                self.get_path_by_node(path, bincode::deserialize(&node).expect("corrupted state"))
            }
            NodePointer::Embedded(node) => self.get_path_by_node(path, node.as_ref().clone()),
        }
    }

    /// Perform a path lookup step based on a node.
    fn get_path_by_node(&self, path: NibbleVec, node: Node) -> Option<Vec<u8>> {
        match node {
            Node::Branch { children, value } => {
                if path.is_empty() {
                    value
                } else {
                    // Fetch the next node in path.
                    self.get_path_by_pointer(path[1..].into(), children[path[0] as usize].clone())
                }
            }
            Node::Leaf {
                path: node_path,
                value,
            } => {
                if node_path == path {
                    Some(value)
                } else {
                    None
                }
            }
            Node::Extension {
                path: node_path,
                pointer,
            } => {
                if path.starts_with(&node_path) {
                    // Fetch the next node in path.
                    self.get_path_by_pointer(path[node_path.len()..].into(), pointer)
                } else {
                    None
                }
            }
        }
    }

    /// Lookup key.
    pub fn get(&self, root: Option<H256>, key: &[u8]) -> Option<Vec<u8>> {
        let path = NibbleVec::from_key(key);
        self.get_path_by_pointer(path, self.get_root_pointer(root))
    }

    /// Insert a new node and return a pointer to that node.
    fn insert_node(&self, node: Node) -> NodePointer {
        if node.is_embeddable() {
            // Node is embeddable, so no need to insert anything into storage.
            NodePointer::Embedded(Box::new(node))
        } else {
            // Node is not embeddable, insert it into storage and return a pointer.
            NodePointer::Pointer(
                self.storage
                    .insert(
                        bincode::serialize(&node).unwrap(),
                        PatriciaTrie::STORAGE_EXPIRY_TIME,
                    )
                    .wait()
                    .expect("failed to insert to storage"),
            )
        }
    }

    /// Dereferences a node pointer.
    fn deref_node_pointer(&self, pointer: NodePointer) -> Node {
        match pointer {
            NodePointer::Null => panic!("null node pointer dereference"),
            NodePointer::Pointer(pointer) => {
                let node = self.storage
                    .get(pointer)
                    .wait()
                    .expect("failed to fetch from storage");

                bincode::deserialize(&node).expect("corrupted state")
            }
            NodePointer::Embedded(node) => node.as_ref().clone(),
        }
    }

    /// Perform key insertion step based on a node pointer.
    fn insert_path_by_pointer(
        &self,
        path: NibbleVec,
        value: &[u8],
        pointer: NodePointer,
    ) -> NodePointer {
        let new_node = match pointer {
            NodePointer::Null => {
                // Create a new leaf node at this point.
                Node::Leaf {
                    path,
                    value: value.to_vec(),
                }
            }
            NodePointer::Pointer(_) => {
                // Existing node is stored as a separate key.
                self.insert_path_by_node(path, value, self.deref_node_pointer(pointer))
            }
            NodePointer::Embedded(node) => {
                self.insert_path_by_node(path, value, node.as_ref().clone())
            }
        };

        self.insert_node(new_node)
    }

    /// Perform key insertion step based on a node.
    fn insert_path_by_node(&self, path: NibbleVec, value: &[u8], node: Node) -> Node {
        match node {
            Node::Branch {
                mut children,
                value: node_value,
            } => {
                if children.is_empty() {
                    // No children, store value at this branch node.
                    Node::Branch {
                        children,
                        value: Some(value.to_vec()),
                    }
                } else {
                    // We need to insert to the correct child node pointer.
                    let child_index = path[0] as usize;
                    children[child_index] = self.insert_path_by_pointer(
                        path[1..].into(),
                        value,
                        children[child_index].clone(),
                    );

                    Node::Branch {
                        children,
                        value: node_value,
                    }
                }
            }
            Node::Leaf {
                path: node_path,
                value: node_value,
            } => {
                if path == node_path {
                    // Simplfy replace the leaf node.
                    Node::Leaf {
                        path,
                        value: value.to_vec(),
                    }
                } else {
                    // Expand leaf node. The common part of old and new paths is transformed into an
                    // extension node while the non-common part is transformed into a branch node with
                    // two leaves (one for each value).
                    let common_prefix = node_path.common_prefix(&path);

                    // Create branch node with two leaves. The first non-common nibble decides child
                    // positions. If any child has exactly the common prefix as path, it is added to
                    // the branch node.
                    let mut target_children = NodePointer::null_children();
                    let mut target_value = None;
                    {
                        let mut add_leaf = |path: &NibbleVec, value| {
                            if common_prefix.len() == path.len() {
                                // Move value to branch itself.
                                assert!(target_value.is_none());
                                target_value = Some(value);
                            } else {
                                // Create a new leaf node.
                                let branch_index = common_prefix.len();

                                target_children[path[branch_index] as usize] =
                                    self.insert_node(Node::Leaf {
                                        path: path[(branch_index + 1)..].into(),
                                        value,
                                    });
                            }
                        };

                        add_leaf(&node_path, node_value);
                        add_leaf(&path, value.to_vec());
                    }

                    let branch = Node::Branch {
                        children: target_children,
                        value: target_value,
                    };

                    if common_prefix.len() > 0 {
                        Node::Extension {
                            path: common_prefix.into(),
                            pointer: self.insert_node(branch),
                        }
                    } else {
                        branch
                    }
                }
            }
            Node::Extension {
                path: node_path,
                pointer,
            } => {
                if path.starts_with(&node_path) {
                    // Update extension node.
                    let pointer =
                        self.insert_path_by_pointer(path[node_path.len()..].into(), value, pointer);

                    Node::Extension {
                        path: node_path,
                        pointer,
                    }
                } else {
                    // Split extension node. The common part of old and new paths is transformed into an
                    // extension node while the non-common part is transformed into a branch node with
                    // one leaf and one extension node.
                    let common_prefix = node_path.common_prefix(&path);

                    // Create branch node with one leaf and one extension node. The first non-common nibble
                    // decides child positions. If any child has exactly the common prefix as path, it is
                    // added to the branch node.
                    let mut target_children = NodePointer::null_children();
                    let mut target_value = None;

                    // Extension node. Path cannot be equal to the common prefix as in this case we would
                    // be in the upper branch.
                    assert!(common_prefix.len() < node_path.len());

                    let branch_nibble = node_path[common_prefix.len()] as usize;
                    let remaining_path = &node_path[(common_prefix.len() + 1)..];
                    if remaining_path.is_empty() {
                        // Move pointer to branch itself since there is no remaining path and so an
                        // extension node is not required.
                        target_children[branch_nibble] = pointer;
                    } else {
                        // Create a new extension node.
                        target_children[branch_nibble] = self.insert_node(Node::Extension {
                            path: remaining_path.into(),
                            pointer,
                        });
                    }

                    // Leaf node.
                    if common_prefix.len() == path.len() {
                        // Move value to branch itself.
                        target_value = Some(value.to_vec());
                    } else {
                        // Create a new leaf node.
                        let branch_index = common_prefix.len();

                        target_children[path[branch_index] as usize] =
                            self.insert_node(Node::Leaf {
                                path: path[(branch_index + 1)..].into(),
                                value: value.to_vec(),
                            });
                    }

                    let branch = Node::Branch {
                        children: target_children,
                        value: target_value,
                    };

                    if common_prefix.len() > 0 {
                        Node::Extension {
                            path: common_prefix.into(),
                            pointer: self.insert_node(branch),
                        }
                    } else {
                        branch
                    }
                }
            }
        }
    }

    /// Insert key.
    pub fn insert(&self, root: Option<H256>, key: &[u8], value: &[u8]) -> H256 {
        let path = NibbleVec::from_key(key);
        let new_root = self.insert_path_by_pointer(path, value, self.get_root_pointer(root));
        // Old root will be removed once it expires, there is no way to remove it early.
        match new_root {
            NodePointer::Null => unreachable!("insert operation cannot remove root"),
            NodePointer::Pointer(pointer) => pointer,
            NodePointer::Embedded(node) => {
                // Store embedded root node.
                self.storage
                    .insert(
                        bincode::serialize(&node).unwrap(),
                        PatriciaTrie::STORAGE_EXPIRY_TIME,
                    )
                    .wait()
                    .expect("failed to insert to storage")
            }
        }
    }

    /// Perform key removal step based on a node pointer.
    fn remove_path_by_pointer(&self, path: NibbleVec, pointer: NodePointer) -> Option<Node> {
        match pointer {
            NodePointer::Null => None,
            NodePointer::Pointer(_) => {
                // Existing node is stored as a separate key.
                self.remove_path_by_node(path, self.deref_node_pointer(pointer))
            }
            NodePointer::Embedded(node) => self.remove_path_by_node(path, node.as_ref().clone()),
        }
    }

    /// Perform key removal step based on a node.
    fn remove_path_by_node(&self, path: NibbleVec, node: Node) -> Option<Node> {
        match node {
            Node::Branch {
                mut children,
                value: mut node_value,
            } => {
                let collapse;

                if path.is_empty() {
                    // Embedded value at this node should be removed.
                    collapse = true;
                    node_value = None;
                } else {
                    let child_index = path[0] as usize;

                    match self.remove_path_by_pointer(
                        path[1..].into(),
                        children[child_index].clone(),
                    ) {
                        Some(node) => {
                            children[child_index] = self.insert_node(node);
                            collapse = false;
                        }
                        None => {
                            children[child_index] = NodePointer::Null;
                            collapse = true;
                        }
                    }
                }

                if collapse {
                    // We may need to collapse the branch. Compute the number of child nodes where
                    // an embedded value at the branch also counts as a child.
                    let child_count = children
                        .iter()
                        .filter(|child| child != &&NodePointer::Null)
                        .count() + node_value.iter().count();

                    match child_count {
                        // If there are no children, we can simply remove this branch.
                        0 => None,
                        // If there is only the embedded value, we can replace it with a leaf node.
                        1 if node_value.is_some() => Some(Node::Leaf {
                            path: NibbleVec::new(),
                            value: node_value.unwrap(),
                        }),
                        // Only one child, but it is not the embedded value.
                        1 => {
                            // Get child and its index.
                            let (child_index, pointer) = children
                                .iter()
                                .enumerate()
                                .filter(|&(_, child)| child != &NodePointer::Null)
                                .map(|(index, child)| (index as u8, child.clone()))
                                .next()
                                .unwrap();

                            match self.deref_node_pointer(pointer) {
                                // Child is a branch. Replace current node with an extension for the
                                // index nibble.
                                branch @ Node::Branch { .. } => Some(Node::Extension {
                                    path: NibbleVec(vec![child_index]),
                                    pointer: self.insert_node(branch),
                                }),
                                // Child is a leaf. Replace current node with a leaf with the index
                                // nibble inserted at the beginning of the path.
                                Node::Leaf { mut path, value } => {
                                    path.insert(0, child_index);
                                    Some(Node::Leaf { path, value })
                                }
                                // Child is an extension. Replace current node with an extension with
                                // the index nibble inserted at the beginning of the path.
                                Node::Extension { mut path, pointer } => {
                                    assert!(pointer != NodePointer::Null);

                                    path.insert(0, child_index);
                                    Some(Node::Extension { path, pointer })
                                }
                            }
                        }
                        // More than one child, leave it as is.
                        _ => Some(Node::Branch {
                            children,
                            value: node_value,
                        }),
                    }
                } else {
                    // No collapse needed, leave it as is.
                    Some(Node::Branch {
                        children,
                        value: node_value,
                    })
                }
            }
            Node::Leaf {
                path: node_path,
                value: node_value,
            } => {
                if path == node_path {
                    // Just remove the leaf.
                    None
                } else {
                    // Nothing should change.
                    Some(Node::Leaf {
                        path: node_path,
                        value: node_value,
                    })
                }
            }
            Node::Extension {
                path: mut node_path,
                pointer,
            } => {
                if path.starts_with(&node_path) {
                    match self.remove_path_by_pointer(path[node_path.len()..].into(), pointer) {
                        // Child branch node, update pointer.
                        Some(branch @ Node::Branch { .. }) => Some(Node::Extension {
                            path: node_path,
                            pointer: self.insert_node(branch),
                        }),
                        // Child leaf node, replace extension node with the merged path leaf node.
                        Some(Node::Leaf { mut path, value }) => {
                            node_path.append(&mut path);
                            Some(Node::Leaf {
                                path: node_path,
                                value,
                            })
                        }
                        // Child extension node, replace extension node with merged path extension node.
                        Some(Node::Extension { mut path, pointer }) => {
                            node_path.append(&mut path);
                            Some(Node::Extension {
                                path: node_path,
                                pointer,
                            })
                        }
                        // Child pointer was removed, no need for the current node.
                        None => None,
                    }
                } else {
                    // Nothing should change.
                    Some(Node::Extension {
                        path: node_path,
                        pointer,
                    })
                }
            }
        }
    }

    /// Remove key.
    pub fn remove(&self, root: Option<H256>, key: &[u8]) -> Option<H256> {
        if root.is_none() {
            return None;
        }

        let path = NibbleVec::from_key(key);
        let new_root = self.remove_path_by_pointer(path, self.get_root_pointer(root));
        // Old root will be removed once it expires, there is no way to remove it early.
        match new_root {
            None => None,
            Some(node) => {
                // Store embedded root node.
                Some(
                    self.storage
                        .insert(
                            bincode::serialize(&node).unwrap(),
                            PatriciaTrie::STORAGE_EXPIRY_TIME,
                        )
                        .wait()
                        .expect("failed to insert to storage"),
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    extern crate test;

    use std::sync::Arc;

    use self::test::Bencher;

    use ekiden_storage_dummy::DummyStorageBackend;

    use super::*;

    #[test]
    fn test_basic_ops() {
        let storage = Arc::new(DummyStorageBackend::new());
        let tree = PatriciaTrie::new(storage);

        assert_eq!(tree.get(None, b"foo"), None);
        let new_root = tree.insert(None, b"foo", b"bar");
        assert_eq!(tree.get(Some(new_root), b"foo"), Some(b"bar".to_vec()));
        assert_eq!(
            new_root,
            H256::from("0xbc218e864cca90f1ae20ab1af191ef1aa31ac12b5af51c63ce6e7bdd6199992a")
        );

        let new_root = tree.insert(Some(new_root), b"hello", b"world");
        assert_eq!(tree.get(Some(new_root), b"foo"), Some(b"bar".to_vec()));
        assert_eq!(tree.get(Some(new_root), b"hello"), Some(b"world".to_vec()));
        assert_eq!(
            new_root,
            H256::from("0x44de9699b3aa1e9b94a390899fbada775accd13e3e748d98fc12866d8ae69085")
        );

        let pairs = [
            (b"another".to_vec(), b"value1".to_vec()),
            (b"anotherrrrrr".to_vec(), b"value2".to_vec()),
            (b"anotherrr".to_vec(), b"value3".to_vec()),
            (b"bar".to_vec(), b"value4".to_vec()),
            (b"goo".to_vec(), b"value5".to_vec()),
            (b"moo".to_vec(), b"value4".to_vec()),
        ];

        let mut new_root = new_root;
        for &(ref key, ref value) in pairs.iter() {
            new_root = tree.insert(Some(new_root), key, value);
        }

        for &(ref key, ref value) in pairs.iter() {
            assert_eq!(tree.get(Some(new_root), key), Some(value.clone()));
        }

        assert_eq!(
            new_root,
            H256::from("0x4c859bcb7c7b33365ce1bbd19921a57b0f36b91075630e44d37d8a6c9b7d1ed5")
        );

        for &(ref key, _) in pairs.iter() {
            new_root = tree.remove(Some(new_root), key).unwrap();
            assert_eq!(tree.get(Some(new_root), key), None);
        }

        // Should be equal as before all items were inserted.
        assert_eq!(
            new_root,
            H256::from("0x44de9699b3aa1e9b94a390899fbada775accd13e3e748d98fc12866d8ae69085")
        );

        assert_eq!(tree.get(Some(new_root), b"foo"), Some(b"bar".to_vec()));
        assert_eq!(tree.get(Some(new_root), b"hello"), Some(b"world".to_vec()));

        new_root = tree.remove(Some(new_root), b"hello").unwrap();
        assert_eq!(tree.get(Some(new_root), b"hello"), None);

        // Should be equal as before hello was inserted.
        assert_eq!(
            new_root,
            H256::from("0xbc218e864cca90f1ae20ab1af191ef1aa31ac12b5af51c63ce6e7bdd6199992a")
        );

        // After removing foo the root should be gone as well.
        assert_eq!(tree.remove(Some(new_root), b"foo"), None);
    }

    /// Test an insertion in a deep node.
    #[test]
    fn test_feather() {
        let storage = Arc::new(DummyStorageBackend::new());
        let tree = PatriciaTrie::new(storage);
        let mut root_hash = None;
        let mut key_buf = *b"\x83gStateDbhaccountsx(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let val = b"don't embed don't embed don't embed don't embed don't embed";
        root_hash = Some(tree.insert(root_hash, &key_buf, val));
        for i in 20..60 {
            key_buf[i] = b'3';
            root_hash = Some(tree.insert(root_hash, &key_buf, val));
            key_buf[i] = b'2';
            root_hash = Some(tree.insert(root_hash, &key_buf, val));
        }
        key_buf[59] = b'4';
        root_hash = Some(tree.insert(root_hash, &key_buf, val));
        drop(root_hash);
    }

    #[bench]
    fn bench_feather(b: &mut Bencher) {
        let storage = Arc::new(DummyStorageBackend::new());
        let tree = PatriciaTrie::new(storage);
        let mut root_hash = None;
        let mut key_buf = *b"\x83gStateDbhaccountsx(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let val = b"don't embed don't embed don't embed don't embed don't embed";
        root_hash = Some(tree.insert(root_hash, &key_buf, val));
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % 39;
            key_buf[20 + i] = b'3';
            root_hash = Some(tree.insert(root_hash, &key_buf, val));
            key_buf[20 + i] = b'2';
            root_hash = Some(tree.insert(root_hash, &key_buf, val));
        });
        key_buf[59] = b'4';
        root_hash = Some(tree.insert(root_hash, &key_buf, val));
        drop(root_hash);
    }
}
