use std::fmt::Display;
use std::cmp::{Eq, Ordering};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

pub struct UsizeIterableHashSet<K> {
    map: HashMap<Arc<K>, usize>,
    store: Vec<Arc<K>>,
}

impl<K: Hash + Eq + Display> UsizeIterableHashSet<K> {
    pub fn new() -> Self {
        Self { map: HashMap::new(), store: vec![] }
    }

    #[test]
    pub fn dump(&self) {
        println!("map");
        for (k, v) in &self.map {
            println!("{} -> {}", k, v);
        }
        println!("store");
        for k in &self.store {
            println!("{}", k);
        }
    }

    pub fn insert(&mut self, k: K) {
        let rck = Arc::new(k);
        let loc = match self.map.get(&rck) {
            None => None,
            Some(ix) => Some(*ix),
        };
        match loc {
            None => {
                self.map.insert(rck.clone(), self.store.len());
                self.store.push(rck);
            },
            Some(ix) => {
                let r = self.store.get_mut(ix).unwrap();
                self.map.insert(rck.clone(), ix);
                *r = rck;
            }
        }
    }

    pub fn contains(&self, k: &K) -> bool {
        match self.map.get(k) {
            None => false,
            Some(_ix) => true,
        }
    }

    pub fn remove(&mut self, k: &K) {
        let ix = match self.map.get(k) {
            None => return,
            Some(ix) => *ix,
        };
        // move last element to ix, shrink
        let last = self.store.len() - 1;
        if ix != last {
            let rck = self.store.pop().unwrap();
            self.store[ix] = rck.clone();
            self.map.insert(rck, ix);
        } else {
            self.store.pop().unwrap();
        }
        self.map.remove(k).unwrap();
    }

    pub fn iter_get(&self, ix: usize) -> Option<&K> {
        if ix < self.len() {
            Some(&self.store[ix])
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }
}

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
        let mut iboth = |v| { e.insert(v); expected.insert(v); };
        iboth(-1234);
        iboth(31415926);
        iboth(271828);
        iboth(14142);
    }
    assert!(e.contains(&-1234));
    assert!(e.contains(&31415926));
    {
        let mut rboth = |v| { e.remove(v); expected.remove(v); };
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
