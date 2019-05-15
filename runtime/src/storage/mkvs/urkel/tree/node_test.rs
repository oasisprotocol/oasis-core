use std::{cell::RefCell, rc::Rc, str::FromStr};

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{marshal::*, tree::*},
};

#[test]
fn test_serialization_leaf() {
    let key = b"a golden key".to_vec();
    let value_hash = Hash::digest_bytes(b"value");

    let leaf_node = LeafNode {
        key: key,
        value: Rc::new(RefCell::new(ValuePointer {
            clean: true,
            hash: value_hash,
            value: Some(b"value".to_vec()),
            ..Default::default()
        })),
        ..Default::default()
    };

    let marshaled = leaf_node.marshal_binary().expect("marshal");

    let mut decoded_leaf_node = LeafNode {
        ..Default::default()
    };
    decoded_leaf_node
        .unmarshal_binary(marshaled.as_slice())
        .expect("unmarshal");

    assert_eq!(true, decoded_leaf_node.clean);
    assert_eq!(leaf_node.key, decoded_leaf_node.key);
    assert_eq!(true, decoded_leaf_node.value.borrow().clean);
    assert_eq!(
        leaf_node.value.borrow().value,
        decoded_leaf_node.value.borrow().value
    );
    assert_ne!(None, decoded_leaf_node.value.borrow().value);
}

#[test]
fn test_serialization_internal() {
    let mut leaf_node = LeafNode {
        key: b"a golden key".to_vec(),
        value: Rc::new(RefCell::new(ValuePointer {
            clean: true,
            hash: Hash::digest_bytes(b"value"),
            value: Some(b"value".to_vec()),
            ..Default::default()
        })),
        ..Default::default()
    };
    leaf_node.update_hash();
    let left_hash = Hash::digest_bytes(b"everyone move to the left");
    let right_hash = Hash::digest_bytes(b"everyone move to the right");

    let int_node = InternalNode {
        leaf_node: Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: leaf_node.get_hash(),
            node: Some(Rc::new(RefCell::new(NodeBox::Leaf(leaf_node)))),
            ..Default::default()
        })),
        left: Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: left_hash,
            ..Default::default()
        })),
        right: Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: right_hash,
            ..Default::default()
        })),
        ..Default::default()
    };

    let marshaled = int_node.marshal_binary().expect("marshal");

    let mut decoded_int_node = InternalNode {
        ..Default::default()
    };
    decoded_int_node
        .unmarshal_binary(marshaled.as_slice())
        .expect("unmarshal");

    assert_eq!(true, decoded_int_node.clean);
    assert_eq!(
        int_node.leaf_node.borrow().hash,
        decoded_int_node.leaf_node.borrow().hash
    );
    assert_eq!(
        int_node.left.borrow().hash,
        decoded_int_node.left.borrow().hash
    );
    assert_eq!(
        int_node.right.borrow().hash,
        decoded_int_node.right.borrow().hash
    );
    assert_eq!(true, decoded_int_node.leaf_node.borrow().clean);
    assert_eq!(true, decoded_int_node.left.borrow().clean);
    assert_eq!(true, decoded_int_node.right.borrow().clean);
    assert_eq!(true, decoded_int_node.leaf_node.borrow().node.is_some());
    assert_eq!(false, decoded_int_node.left.borrow().node.is_some());
    assert_eq!(false, decoded_int_node.right.borrow().node.is_some());
}

#[test]
fn test_hash_leaf() {
    let key = b"a golden key".to_vec();
    let value_hash = Hash::digest_bytes(b"value");

    let mut leaf_node = LeafNode {
        key: key,
        value: Rc::new(RefCell::new(ValuePointer {
            clean: true,
            hash: value_hash,
            value: Some(Vec::from("value")),
            ..Default::default()
        })),
        ..Default::default()
    };

    leaf_node.update_hash();
    assert_eq!(
        leaf_node.hash,
        Hash::from_str("1736c1ac9fe17539c40e8b4c4d73c5c5a4a6e808c0b8247ebf4b1802ceace4d2").unwrap()
    );
}

#[test]
fn test_hash_internal() {
    let leaf_node_hash = Hash::digest_bytes(b"everyone stop here");
    let left_hash = Hash::digest_bytes(b"everyone move to the left");
    let right_hash = Hash::digest_bytes(b"everyone move to the right");

    let mut int_node = InternalNode {
        leaf_node: Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: leaf_node_hash,
            ..Default::default()
        })),
        left: Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: left_hash,
            ..Default::default()
        })),
        right: Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: right_hash,
            ..Default::default()
        })),
        ..Default::default()
    };

    int_node.update_hash();
    assert_eq!(
        int_node.hash,
        Hash::from_str("2046be7373eac5777c4dc7c7b1ac05974656b66dfba97eaead803f553ae2ee3c").unwrap()
    );
}
