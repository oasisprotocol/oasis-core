use std::{cell::RefCell, rc::Rc, str::FromStr};

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{marshal::*, tree::*},
};

#[test]
fn test_serialization_leaf() {
    let leaf_node = LeafNode {
        key: b"a golden key".to_vec(),
        value: b"value".to_vec(),
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
    assert_eq!(leaf_node.value, decoded_leaf_node.value);
}

#[test]
fn test_serialization_internal() {
    let mut leaf_node = LeafNode {
        key: b"a golden key".to_vec(),
        value: b"value".to_vec(),
        ..Default::default()
    };
    leaf_node.update_hash();
    let left_hash = Hash::digest_bytes(b"everyone move to the left");
    let right_hash = Hash::digest_bytes(b"everyone move to the right");

    let label: Key = b"abc".to_vec();
    let label_bit_length = 24 as Depth;

    let int_node = InternalNode {
        label: label,
        label_bit_length: label_bit_length,
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
    assert_eq!(int_node.label, decoded_int_node.label);
    assert_eq!(int_node.label_bit_length, decoded_int_node.label_bit_length);
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
    let mut leaf_node = LeafNode {
        key: b"a golden key".to_vec(),
        value: b"value".to_vec(),
        ..Default::default()
    };

    leaf_node.update_hash();
    assert_eq!(
        leaf_node.hash,
        Hash::from_str("5c05183d4158b5920b16833acb78ccda464da83f720f824177b3a55a75f9fd88").unwrap()
    );
}

#[test]
fn test_hash_internal() {
    let leaf_node_hash = Hash::digest_bytes(b"everyone stop here");
    let left_hash = Hash::digest_bytes(b"everyone move to the left");
    let right_hash = Hash::digest_bytes(b"everyone move to the right");

    let mut int_node = InternalNode {
        label: b"abc".to_vec(),
        label_bit_length: 23,
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
        Hash::from_str("75c37c67c265e2c836f76dec35173fa336e976938ea46f088390a983e46efced").unwrap()
    );
}

#[test]
fn test_depth_type() {
    assert_eq! {0, (0 as Depth).to_bytes()};
    assert_eq! {2, (16 as Depth).to_bytes()};
    assert_eq! {3, (17 as Depth).to_bytes()};

    let mut dt: Depth = 0;
    assert_eq! {[0x0a as u8, 0x00].to_vec(), (10 as Depth).marshal_binary().unwrap()};
    dt.unmarshal_binary(&[0x0a, 0x00]).expect("unmarshal");
    assert_eq! {(10 as Depth), dt};
    assert_eq! {[0x04 as u8, 0x01].to_vec(), (260 as Depth).marshal_binary().unwrap()};
    dt.unmarshal_binary(&[0x04, 0x01]).expect("unmarshal");
    assert_eq! {(260 as Depth), dt};
}

#[test]
fn test_key_append_split_merge() {
    // append a single bit
    let key: Key = vec![0xf0];
    let new_key = key.append_bit(4, true);
    assert_eq!(vec![0xf8], new_key);
    let key: Key = vec![0xff];
    let new_key = key.append_bit(4, false);
    assert_eq!(vec![0xf7], new_key);
    let key: Key = vec![0xff];
    let new_key = key.append_bit(8, true);
    assert_eq!(vec![0xff, 0x80], new_key);
    let key: Key = vec![0xff];
    let new_key = key.append_bit(8, false);
    assert_eq!(vec![0xff, 0x00], new_key);

    // byte-aligned split
    let key: Key = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let (p, s) = key.split(16, 32);
    assert_eq!(vec![0xaa, 0xbb], p);
    assert_eq!(vec![0xcc, 0xdd], s);

    // byte-aligned merge
    let key: Key = vec![0xaa, 0xbb];
    let new_key = key.merge(16, &vec![0xcc, 0xdd], 16);
    assert_eq!(vec![0xaa, 0xbb, 0xcc, 0xdd], new_key);

    // empty/full splits
    let key: Key = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let (p, s) = key.split(0, 32);
    assert_eq!(Key::new(), p);
    assert_eq!(key, s);
    let (p, s) = key.split(32, 32);
    assert_eq!(key, p);
    assert_eq!(Key::new(), s);

    // empty merges
    let new_key = Key::new().merge(0, &vec![0xaa, 0xbb], 16);
    assert_eq!(vec![0xaa, 0xbb], new_key);
    let new_key: Key = vec![0xaa, 0xbb].merge(16, &Key::new(), 0);
    assert_eq!(vec![0xaa, 0xbb], new_key);

    // non byte-aligned split
    let key: Key = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let (p, s) = key.split(17, 64);
    assert_eq!(vec![0x01, 0x23, 0x00], p);
    assert_eq!(vec![0x8a, 0xcf, 0x13, 0x57, 0x9b, 0xde], s);

    // ...and merge
    let new_key = p.merge(17, &s, 64 - 17);
    assert_eq!(key, new_key);

    // non byte-aligned key length split.
    let key: Key = vec![0xff, 0xff, 0xff, 0xff];
    let (p, s) = key.split(21, 29);
    // Check that split cleans the last 3 unused bits!
    assert_eq!(vec![0xff, 0xff, 0xf8], p);
    assert_eq!(vec![0xff], s);

    // ...and merge
    let new_key = p.merge(21, &s, 8);
    // Merge doesn't obtain original key, because the split cleaned unused bits!
    assert_eq!(vec![0xff, 0xff, 0xff, 0xf8], new_key);

    // Special case with zero-length key.
    let key: Key = vec![0x80];
    let new_key = key.merge(0, &vec![0xf0], 4);
    assert_eq!(vec![0xf0], new_key);

    // Special case with extra bytes.
    let key: Key = vec![0x41, 0x6b, 0x00];
    let new_key = key.merge(16, &vec![0x37], 8);
    assert_eq!(vec![0x41, 0x6b, 0x37], new_key);
}

#[test]
fn test_key_common_prefix_len() {
    let key = Key::new();
    assert_eq!(0, key.common_prefix_len(0, &Key::new(), 0));

    let key: Key = vec![0xff, 0xff];
    assert_eq!(16, key.common_prefix_len(16, &vec![0xff, 0xff, 0xff], 24));

    let key: Key = vec![0xff, 0xff, 0xff];
    assert_eq!(16, key.common_prefix_len(24, &vec![0xff, 0xff], 16));

    let key: Key = vec![0xff, 0xff, 0xff];
    assert_eq!(24, key.common_prefix_len(24, &vec![0xff, 0xff, 0xff], 24));

    let key: Key = vec![0xab, 0xcd, 0xef, 0xff];
    assert_eq!(
        23,
        key.common_prefix_len(32, &vec![0xab, 0xcd, 0xee, 0xff], 32)
    );

    let key: Key = vec![0xab, 0xcd];
    assert_eq!(12, key.common_prefix_len(13, &vec![0xab, 0xcd], 12));
    assert_eq!(12, key.common_prefix_len(12, &vec![0xab, 0xcd], 13));
}
