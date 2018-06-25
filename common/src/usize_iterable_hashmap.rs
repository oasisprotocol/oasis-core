use std::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

/// UsizeIterableHashMap implements the basic operations of a HashMap
/// (insert, get, remove) and adds an iterator scheme that uses a
/// usize as the iterator state.  The reason for this, as opposed to
/// the iterator that HashSet returns, is that it is easy to
/// externalize the usize in an RPC.  There is no need to maintain a
/// mapping from an externally used name to an iterator object and
/// deal with possible memory leaks due to abandoned iterators
/// (distributed GC across other languages is obviously not solved by
/// Rust's lifetime scheme).  The iterator is invalidated, as is
/// typical, when the UsizeIterableHashMap object with which the
/// iterator is associated is modified, but there is no "undefined
/// behavior" due to dangling pointers etc.
pub struct UsizeIterableHashMap<K, V> {
    // The invariant is that |store| is dense and contains all the
    // entries inserted into the UsizeIterableHashSet object, and that
    // |map| takes a given key into the index in |store| where the
    // entry is kept.  An entry is the key-value tuple.  The |store|
    // object contains the key so that on removal, we can swap the
    // entry with the last entry in |store| and shrink the |store|
    // vector, to maintain the dense-vector invariant, and to do that
    // we need to know the key with which to update the |map|.
    map: HashMap<Arc<K>, usize>,
    store: Vec<(Arc<K>, V)>,
}

impl<K: Hash + Eq, V> UsizeIterableHashMap<K, V> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            store: vec![],
        }
    }

    /// Insert the value |v| into the map under the key |k|.  The old
    /// value, if any, is discarded.
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
            }
            Some(ix) => {
                let r = self.store.get_mut(ix).unwrap();
                self.map.insert(rck, ix);
                *r = entry;
            }
        }
    }

    /// Fetch the value, if any, stored under the key |k|; returns
    /// None if there are no values associated with |k|.
    pub fn get(&self, k: &K) -> Option<&V> {
        match self.map.get(k) {
            None => return None,
            Some(ix) => {
                let e = self.store.get(*ix).unwrap();
                Some(&e.1)
            }
        }
    }

    /// Remove the value associated with the key |k| from the map.
    pub fn remove(&mut self, k: &K) {
        let ix = match self.map.get(k) {
            None => return,
            Some(ix) => *ix,
        };
        // move last element to ix, shrink the store vector
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

    /// Gets the value associated with iterator |ix| if it exists,
    /// and None otherwise.  Iteration starts with |ix| = 0.
    pub fn iter_get(&self, ix: usize) -> Option<&V> {
        if ix < self.len() {
            Some(&self.store[ix].1)
        } else {
            None
        }
    }

    /// Returns the total number of elments in the map.
    pub fn len(&self) -> usize {
        self.store.len()
    }
}
