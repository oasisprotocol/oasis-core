use std::cmp::{Eq, Ordering};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

pub struct UsizeIterableHashMap<K, V> {
    map: HashMap<Arc<K>, usize>,
    store: Vec<(Arc<K>, V)>,
}

impl<K: Hash + Eq, V> UsizeIterableHashMap<K, V> {
    pub fn new() -> Self {
        Self { map: HashMap::new(), store: vec![] }
    }

    pub fn insert(&mut self, k: K, v: V) {
        let rck = Arc::new(k);
        let entry = (rck.clone(), v);
        let loc = match self.map.get(&rck) {
            None => None,
            Some(ix) => Some(*ix),
        };
        match loc {
            None => {
                self.map.insert(rck, self.store.len());
                self.store.push(entry);
            },
            Some(ix) => {
                let r = self.store.get_mut(ix).unwrap();
                self.map.insert(rck, ix);
                *r = entry;
            }
        }
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        match self.map.get(k) {
            None => return None,
            Some(ix) => {
                let e = self.store.get(*ix).unwrap();
                Some(&e.1)
            }
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
            let entry = self.store.pop().unwrap();
            let rck = entry.0.clone();
            self.store[ix] = entry;
            self.map.insert(rck, ix);
        } else {
            self.store.pop().unwrap();
        }
        self.map.remove(k).unwrap();
    }

    pub fn iter_get(&self, ix: usize) -> Option<&V> {
        if ix < self.len() {
            Some(&self.store[ix].1)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }
}
