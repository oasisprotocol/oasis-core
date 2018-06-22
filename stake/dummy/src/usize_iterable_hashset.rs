use std::cmp::{Eq, Ordering};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

pub struct UsizeIterableHashSet<K> {
    map: HashMap<Arc<K>, usize>,
    store: Vec<Arc<K>>,
}

impl<K: Hash + Eq> UsizeIterableHashSet<K> {
    pub fn new() -> Self {
        Self { map: HashMap::new(), store: vec![] }
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
