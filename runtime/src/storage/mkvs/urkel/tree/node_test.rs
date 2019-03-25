use std::{cell::RefCell, rc::Rc, str::FromStr};

use crate::{common::crypto::hash::Hash, storage::mkvs::urkel::tree::*};

#[test]
fn test_serialization_leaf() {
    let key = Hash::digest_bytes("a golden key".as_bytes());
    let value_hash = Hash::digest_bytes("value".as_bytes());

    let leaf_node = LeafNode {
        key: key,
        value: Rc::new(RefCell::new(ValuePointer {
            clean: true,
            hash: value_hash,
            value: Some("value".as_bytes().to_vec()),
            ..Default::default()
        })),
        ..Default::default()
    };

    let marshaled = leaf_node.marshal_binary().expect("marshal");

    let mut decoded_leaf_node = LeafNode {
        ..Default::default()
    };
    decoded_leaf_node
        .unmarshal_binary(marshaled)
        .expect("unmarshal");

    assert_eq!(false, decoded_leaf_node.clean);
    assert_eq!(leaf_node.key, decoded_leaf_node.key);
    assert_eq!(true, decoded_leaf_node.value.borrow().clean);
    assert_eq!(
        leaf_node.value.borrow().hash,
        decoded_leaf_node.value.borrow().hash
    );
    assert_eq!(None, decoded_leaf_node.value.borrow().value);
}

#[test]
fn test_serialization_internal() {
    let left_hash = Hash::digest_bytes("everyone move to the left".as_bytes());
    let right_hash = Hash::digest_bytes("everyone move to the right".as_bytes());

    let int_node = InternalNode {
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
        .unmarshal_binary(marshaled)
        .expect("unmarshal");

    assert_eq!(false, decoded_int_node.clean);
    assert_eq!(
        int_node.left.borrow().hash,
        decoded_int_node.left.borrow().hash
    );
    assert_eq!(
        int_node.right.borrow().hash,
        decoded_int_node.right.borrow().hash
    );
    assert_eq!(true, decoded_int_node.left.borrow().clean);
    assert_eq!(true, decoded_int_node.right.borrow().clean);
    assert_eq!(false, decoded_int_node.left.borrow().node.is_some());
    assert_eq!(false, decoded_int_node.right.borrow().node.is_some());
}

#[test]
fn test_hash_leaf() {
    let key = Hash::digest_bytes("a golden key".as_bytes());
    let value_hash = Hash::digest_bytes("value".as_bytes());

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
        Hash::from_str("63a651558d7a38c9cf03ac1be3c6d38964b8c39568a10a84056728d024d09646").unwrap()
    );
}

#[test]
fn test_hash_internal() {
    let left_hash = Hash::digest_bytes("everyone move to the left".as_bytes());
    let right_hash = Hash::digest_bytes("everyone move to the right".as_bytes());

    let mut int_node = InternalNode {
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
        Hash::from_str("4aed14e40ba69eae81b78b441b277f834b6202097a11ad3ba668c46f44d3717b").unwrap()
    );
}
