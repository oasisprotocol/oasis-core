use std::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

/// UsizeIterableHashSet implements the basic operations of a HashSet
/// (insert, remove, contains) and adds an iterator scheme that uses a
/// usize as the iterator state.  The reason for this, as opposed to
/// the iterator that HashSet returns, is that it is easy to
/// externalize the usize in an RPC.  There is no need to maintain a
/// mapping from an externally used name to an iterator object and
/// deal with possible memory leaks due to abandoned iterators
/// (distributed GC across other languages is obviously not solved by
/// Rust's lifetime scheme).  The iterator is invalidated, as is
/// typical, when the UsizeIterableHashSet object with which the
/// iterator is associated is modified, but there is no "undefined
/// behavior" due to dangling pointers etc.
pub struct UsizeIterableHashSet<K> {
    // The invariant is that |store| is dense and contains all the
    // entries inserted into the UsizeIterableHashSet object, and that
    // |map| takes a given key into the index in |store| where the
    // entry is kept.  An entry is the key itself.  The |store| object
    // contains the key so that on removal, we can swap the entry with
    // the last entry in |store| and shrink the |store| vector, to
    // maintain the dense-vector invariant, and to do that we need to
    // know the key with which to update the |map|.
    map: HashMap<Arc<K>, usize>,
    store: Vec<Arc<K>>,
}

impl<K: Hash + Eq> UsizeIterableHashSet<K> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            store: vec![],
        }
    }

    /// Insert the value |k| into the set.  If the key is already in
    /// the set, this should essentially be a no-op (this is not a
    /// multiset).
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
            }
            Some(ix) => {
                let r = self.store.get_mut(ix).unwrap();
                self.map.insert(rck.clone(), ix);
                *r = rck;
            }
        }
    }

    // Boolean predicate for determining if the value |k| is in the set.
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
        // move last element to ix, shrink the store vector.
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
