extern crate ekiden_common;

use std::collections::HashSet;

use ekiden_common::usize_iterable_hashset::UsizeIterableHashSet;

#[test]
fn test_empty_hashset() {
    let e: UsizeIterableHashSet<u32> = UsizeIterableHashSet::new();
    assert_eq!(e.len(), 0);
    assert!(!e.contains(&0u32));
    assert!(!e.contains(&!(0u32)));
    assert!(!e.contains(&(1u32 << 16)));
}

#[test]
fn test_add_contains() {
    let mut e: UsizeIterableHashSet<i32> = UsizeIterableHashSet::new();
    e.insert(-1234);
    e.insert(31415926);
    assert!(e.contains(&-1234));
    assert!(e.contains(&31415926));
    assert!(!e.contains(&271828));
    assert!(!e.contains(&1618034));
}

#[test]
fn test_add_remove_contains() {
    let mut e: UsizeIterableHashSet<i32> = UsizeIterableHashSet::new();
    e.insert(-1234);
    e.insert(31415926);
    e.insert(31415926);
    assert!(e.contains(&-1234));
    assert!(e.contains(&31415926));
    e.remove(&31415926);
    assert!(!e.contains(&31415926));
    assert!(!e.contains(&271828));
    assert!(!e.contains(&1618034));
}

#[test]
fn test_len() {
    let mut e: UsizeIterableHashSet<i32> = UsizeIterableHashSet::new();
    e.insert(-1234);
    e.insert(31415926);
    e.insert(31415926);
    assert_eq!(e.len(), 2);
    e.insert(271828);
    assert_eq!(e.len(), 3);
    e.remove(&31415926);
    assert_eq!(e.len(), 2);
}

#[test]
fn test_iteration() {
    let mut e: UsizeIterableHashSet<i32> = UsizeIterableHashSet::new();
    let mut expected: HashSet<i32> = HashSet::new();
    {
        let mut iboth = |v| {
            e.insert(v);
            expected.insert(v);
        };
        iboth(-1234);
        iboth(31415926);
        iboth(271828);
        iboth(14142);
    }
    assert!(e.contains(&-1234));
    assert!(e.contains(&31415926));
    {
        let mut rboth = |v| {
            e.remove(v);
            expected.remove(v);
        };
        rboth(&31415926);
    }
    assert!(!e.contains(&31415926));
    assert!(e.contains(&271828));
    assert!(!e.contains(&1618034));
    assert!(e.contains(&14142));
    let mut actual: HashSet<i32> = HashSet::new();
    for ix in 0..e.len() {
        actual.insert(*e.iter_get(ix).unwrap());
    }
    let diff: Vec<&i32> = actual.symmetric_difference(&actual).collect();
    assert_eq!(diff.len(), 0);
}
