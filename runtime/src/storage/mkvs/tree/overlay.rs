use std::{
    collections::{btree_map, BTreeMap, HashSet},
    iter::{Iterator, Peekable},
};

use anyhow::{Error, Result};
use io_context::Context;

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{self, tree::*},
};

/// A key-value tree overlay that holds all updates in memory and only commits them if requested.
/// This can be used to create snapshots that can be discarded.
///
/// While updates (inserts, removes) are stored in the overlay, reads are not cached in the overlay
/// as the inner tree has its own cache and double caching makes less sense.
pub struct OverlayTree<T: mkvs::FallibleMKVS> {
    inner: T,
    overlay: BTreeMap<Vec<u8>, Vec<u8>>,
    dirty: HashSet<Vec<u8>>,
}

impl<T: mkvs::FallibleMKVS> OverlayTree<T> {
    /// Create a new overlay tree.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            overlay: BTreeMap::new(),
            dirty: HashSet::new(),
        }
    }

    /// Get an existing key.
    pub fn get(&self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // For dirty values, check the overlay.
        if self.dirty.contains(key) {
            return Ok(self.overlay.get(key).map(|v| v.clone()));
        }

        // Otherwise fetch from inner tree.
        self.inner.get(ctx, key)
    }

    /// Insert a key/value pair into the tree.
    pub fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let previous = self.get(ctx, key)?;

        self.overlay.insert(key.to_owned(), value.to_owned());
        self.dirty.insert(key.to_owned());

        Ok(previous)
    }

    /// Remove entry with given key, returning the value at the key if the key was previously
    /// in the database.
    pub fn remove(&mut self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // For dirty values, remove from the overlay.
        if self.dirty.contains(key) {
            return Ok(self.overlay.remove(key).map(|v| v.clone()));
        }

        let value = self.inner.get(ctx, key)?;

        // Do not treat a value as dirty if it was not dirty before and did not exist in the inner tree.
        if value.is_some() {
            self.dirty.insert(key.to_owned());
        }
        Ok(value)
    }

    /// Return an iterator over the tree.
    pub fn iter(&self, ctx: Context) -> OverlayTreeIterator<T> {
        OverlayTreeIterator::new(ctx, self)
    }

    /// Commit any modifications to the underlying tree.
    pub fn commit(&mut self, ctx: Context) -> Result<mkvs::WriteLog> {
        let ctx = ctx.freeze();
        let mut log: mkvs::WriteLog = Vec::new();

        // Insert all items present in the overlay.
        for (key, value) in &self.overlay {
            self.inner
                .insert(Context::create_child(&ctx), &key, &value)?;
            self.dirty.remove(key);

            log.push(mkvs::LogEntry {
                key: key.clone(),
                value: Some(value.clone()),
            });
        }
        self.overlay.clear();

        // Any remaining dirty items must have been removed.
        for key in &self.dirty {
            self.inner.remove(Context::create_child(&ctx), key)?;

            log.push(mkvs::LogEntry {
                key: key.clone(),
                value: None,
            });
        }
        self.dirty.clear();

        Ok(log)
    }

    /// Commit any modifications to the underlying tree and then immediately commit the underlying
    /// tree, returning the new root hash.
    pub fn commit_both(
        &mut self,
        ctx: Context,
        namespace: Namespace,
        version: u64,
    ) -> Result<(mkvs::WriteLog, Hash)> {
        let ctx = ctx.freeze();
        // First commit modifications to the underlying tree.
        let write_log = self.commit(Context::create_child(&ctx))?;
        // Then commit the underlying tree.
        let root_hash = self
            .inner
            .commit(Context::create_child(&ctx), namespace, version)?;

        Ok((write_log, root_hash))
    }
}

/// An iterator over the `OverlayTree`.
pub struct OverlayTreeIterator<'tree, T: mkvs::FallibleMKVS> {
    tree: &'tree OverlayTree<T>,

    inner: Box<dyn mkvs::Iterator + 'tree>,
    overlay: Peekable<btree_map::Range<'tree, Vec<u8>, Vec<u8>>>,
    overlay_valid: bool,

    key: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
}

impl<'tree, T: mkvs::FallibleMKVS> OverlayTreeIterator<'tree, T> {
    fn new(ctx: Context, tree: &'tree OverlayTree<T>) -> Self {
        Self {
            tree,
            inner: tree.inner.iter(ctx),
            overlay: tree.overlay.range(vec![]..).peekable(),
            overlay_valid: true,
            key: None,
            value: None,
        }
    }

    fn update_iterator_position(&mut self) {
        // Skip over any dirty entries from the inner iterator.
        loop {
            if !self.inner.is_valid()
                || !self
                    .tree
                    .dirty
                    .contains(self.inner.get_key().as_ref().expect("inner.is_valid"))
            {
                break;
            }
            self.inner.next();
        }

        let i_key = self.inner.get_key();
        let o_item = self.overlay.peek();
        self.overlay_valid = o_item.is_some();

        if self.inner.is_valid()
            && (!self.overlay_valid
                || i_key.as_ref().expect("inner.is_valid") < o_item.expect("overlay_valid").0)
        {
            // Key of inner iterator is smaller than the key of the overlay iterator.
            self.key = i_key.clone();
            self.value = self.inner.get_value().clone();
        } else if self.overlay_valid {
            // Key of overlay iterator is smaller than or equal to the key of the inner iterator.
            let (o_key, o_value) = o_item.expect("overlay_valid");
            self.key = Some(o_key.to_vec());
            self.value = Some(o_value.to_vec());
        } else {
            // Both iterators are invalid.
            self.key = None;
            self.value = None;
        }
    }

    fn next(&mut self) {
        if !self.overlay_valid
            || (self.inner.is_valid()
                && self.inner.get_key().as_ref().expect("inner.is_valid")
                    <= self.overlay.peek().expect("overlay_valid").0)
        {
            // Key of inner iterator is smaller or equal than the key of the overlay iterator.
            self.inner.next();
        } else {
            // Key of inner iterator is greater than the key of the overlay iterator.
            self.overlay.next();
        }

        self.update_iterator_position();
    }
}

impl<'tree, T: mkvs::FallibleMKVS> Iterator for OverlayTreeIterator<'tree, T> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        use mkvs::Iterator;

        if !self.is_valid() {
            return None;
        }

        let key = self.key.as_ref().expect("iterator is valid").clone();
        let value = self.value.as_ref().expect("iterator is valid").clone();
        OverlayTreeIterator::next(self);

        Some((key, value))
    }
}

impl<'tree, T: mkvs::FallibleMKVS> mkvs::Iterator for OverlayTreeIterator<'tree, T> {
    fn set_prefetch(&mut self, prefetch: usize) {
        self.inner.set_prefetch(prefetch)
    }

    fn is_valid(&self) -> bool {
        // If either iterator is valid, the merged iterator is valid.
        self.inner.is_valid() || self.overlay_valid
    }

    fn error(&self) -> &Option<Error> {
        self.inner.error()
    }

    fn rewind(&mut self) {
        self.seek(&[]);
    }

    fn seek(&mut self, key: &[u8]) {
        self.inner.seek(key);
        self.overlay = self.tree.overlay.range(key.to_vec()..).peekable();

        self.update_iterator_position();
    }

    fn get_key(&self) -> &Option<Key> {
        &self.key
    }

    fn get_value(&self) -> &Option<Vec<u8>> {
        &self.value
    }

    fn next(&mut self) {
        OverlayTreeIterator::next(self)
    }
}

impl<T: mkvs::FallibleMKVS> mkvs::MKVS for OverlayTree<T> {
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        self.get(ctx, key).unwrap()
    }

    fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        // For dirty values, check the overlay.
        if self.dirty.contains(key) {
            return self.overlay.contains_key(key);
        }
        self.inner.cache_contains_key(ctx, key)
    }

    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        self.insert(ctx, key, value).unwrap()
    }

    fn remove(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        self.remove(ctx, key).unwrap()
    }

    fn prefetch_prefixes(&self, ctx: Context, prefixes: &Vec<mkvs::Prefix>, limit: u16) {
        self.inner.prefetch_prefixes(ctx, prefixes, limit).unwrap()
    }

    fn iter(&self, ctx: Context) -> Box<dyn mkvs::Iterator + '_> {
        Box::new(self.iter(ctx))
    }

    fn commit(
        &mut self,
        ctx: Context,
        namespace: Namespace,
        version: u64,
    ) -> Result<(mkvs::WriteLog, Hash)> {
        self.commit_both(ctx, namespace, version)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::mkvs::{sync::NoopReadSyncer, tree::iterator::test::test_iterator_with};

    #[test]
    fn test_overlay() {
        let mut tree = Tree::make()
            .with_root_type(RootType::State)
            .new(Box::new(NoopReadSyncer));

        // Generate some items.
        let items = vec![
            (b"key".to_vec(), b"first".to_vec()),
            (b"key 1".to_vec(), b"one".to_vec()),
            (b"key 2".to_vec(), b"two".to_vec()),
            (b"key 5".to_vec(), b"five".to_vec()),
            (b"key 8".to_vec(), b"eight".to_vec()),
            (b"key 9".to_vec(), b"nine".to_vec()),
        ];

        let tests = vec![
            (b"k".to_vec(), 0),
            (b"key 1".to_vec(), 1),
            (b"key 3".to_vec(), 3),
            (b"key 4".to_vec(), 3),
            (b"key 5".to_vec(), 3),
            (b"key 6".to_vec(), 4),
            (b"key 7".to_vec(), 4),
            (b"key 8".to_vec(), 4),
            (b"key 9".to_vec(), 5),
            (b"key A".to_vec(), -1),
        ];

        // Create an overlay over an empty tree and insert some items into the overlay.
        let mut overlay = OverlayTree::new(&mut tree);
        for (key, value) in items.iter() {
            overlay.insert(Context::background(), key, value).unwrap();
        }

        // Test that an overlay-only iterator works correctly.
        let it = overlay.iter(Context::background());
        test_iterator_with(&items, it, &tests);

        // Insert some items into the underlying tree.
        for (key, value) in items.iter() {
            tree.insert(Context::background(), key, value).unwrap();
        }

        // Create a tree pointer so we can unsafely peek into the tree later.
        let tree_ref = &tree as *const Tree;

        // Create an overlay.
        let mut overlay = OverlayTree::new(&mut tree);

        // Test that all keys can be fetched from an empty overlay.
        for (k, expected_v) in &items {
            let v = overlay.get(Context::background(), &k).unwrap();
            assert_eq!(v.as_ref(), Some(expected_v));
        }

        // Test that merged iterator works correctly on an empty overlay (it should behave exactly
        // the same as for the inner tree).
        let it = overlay.iter(Context::background());
        test_iterator_with(&items, it, &tests);

        // Add some updates to the overlay.
        overlay.remove(Context::background(), b"key 2").unwrap();
        overlay
            .insert(Context::background(), b"key 7", b"seven")
            .unwrap();
        overlay.remove(Context::background(), b"key 5").unwrap();
        overlay
            .insert(Context::background(), b"key 5", b"fivey")
            .unwrap();

        // Make sure updates did not propagate to the inner tree.
        // NOTE: This is unsafe as we are otherwise not allowed to reference the inner tree.
        unsafe {
            let tree_ref = &*tree_ref;

            let value = tree_ref.get(Context::background(), b"key 2").unwrap();
            assert_eq!(
                value,
                Some(b"two".to_vec()),
                "value in inner tree should be unchanged"
            );
            let value = tree_ref.get(Context::background(), b"key 7").unwrap();
            assert_eq!(value, None, "value should not exist in inner tree");
        }

        // State of overlay after updates.
        let items = vec![
            (b"key".to_vec(), b"first".to_vec()),
            (b"key 1".to_vec(), b"one".to_vec()),
            (b"key 5".to_vec(), b"fivey".to_vec()),
            (b"key 7".to_vec(), b"seven".to_vec()),
            (b"key 8".to_vec(), b"eight".to_vec()),
            (b"key 9".to_vec(), b"nine".to_vec()),
        ];

        let tests = vec![
            (b"k".to_vec(), 0),
            (b"key 1".to_vec(), 1),
            (b"key 3".to_vec(), 2),
            (b"key 4".to_vec(), 2),
            (b"key 5".to_vec(), 2),
            (b"key 6".to_vec(), 3),
            (b"key 7".to_vec(), 3),
            (b"key 8".to_vec(), 4),
            (b"key 9".to_vec(), 5),
            (b"key A".to_vec(), -1),
        ];

        // Test that all keys can be fetched from an updated overlay.
        for (k, expected_v) in &items {
            let v = overlay.get(Context::background(), &k).unwrap();
            assert_eq!(v.as_ref(), Some(expected_v));
        }

        // Make sure that merged overlay iterator works.
        let it = overlay.iter(Context::background());
        test_iterator_with(&items, it, &tests);

        // Commit the overlay.
        overlay.commit(Context::background()).unwrap();

        // Test that all keys can be fetched from an updated tree.
        for (k, expected_v) in &items {
            let v = tree.get(Context::background(), &k).unwrap();
            assert_eq!(v.as_ref(), Some(expected_v));
        }

        // Make sure that the updated tree is correct.
        let it = tree.iter(Context::background());
        test_iterator_with(&items, it, &tests);
    }
}
