//! Read/write set.
use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    iter::FromIterator,
};

use failure::Fallible;
use io_context::Context;
use serde_bytes;
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::{crypto::hash::Hash, roothash::Namespace},
    storage::mkvs::{Prefix, WriteLog, MKVS},
};

/// Read-write set validation error.
#[derive(Debug, Fail)]
enum ReadWriteSetValidationError {
    #[fail(display = "predicted read/write set differs from actual")]
    Misprediction,
}

/// A coarsened key prefix that represents any key that starts with
/// this prefix.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct CoarsenedKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl AsRef<[u8]> for CoarsenedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Into<Vec<u8>> for CoarsenedKey {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for CoarsenedKey {
    fn from(v: Vec<u8>) -> CoarsenedKey {
        CoarsenedKey(v)
    }
}

impl Borrow<[u8]> for CoarsenedKey {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

/// A set of coarsened keys.
pub type CoarsenedSet = Vec<CoarsenedKey>;

/// A read/write set.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ReadWriteSet {
    /// Size of the key prefixes (in bytes) used for coarsening the keys.
    pub granularity: u16,
    /// The read set.
    pub read_set: CoarsenedSet,
    /// The write set.
    pub write_set: CoarsenedSet,
}

impl ReadWriteSet {
    /// Returns true if this read/write set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.granularity == 0 && self.read_set.is_empty() && self.write_set.is_empty()
    }

    /// Turns this read-write set into a verifeir.
    pub fn into_verifier(self, mkvs: &mut dyn MKVS) -> Verifier {
        Verifier::new(self, mkvs)
    }
}

/// A read/write set verifier makes sure that all MKVS queries conform to
/// the provided read-write set.
///
/// To do this it wraps an existing MKVS implementation and intercepts all
/// read and write operations. The wrapped MKVS is always the one from the
/// current storage context.
pub struct Verifier<'a> {
    mkvs: &'a mut dyn MKVS,
    granularity: usize,
    read_set: HashSet<CoarsenedKey>,
    write_set: HashSet<CoarsenedKey>,
    updates: HashMap<Vec<u8>, Option<Vec<u8>>>,
    valid: bool,
}

impl<'a> Verifier<'a> {
    /// Create a new verifier.
    pub fn new(rw_set: ReadWriteSet, mkvs: &'a mut dyn MKVS) -> Self {
        Self {
            mkvs,
            granularity: rw_set.granularity as usize,
            read_set: HashSet::from_iter(rw_set.read_set.into_iter()),
            write_set: HashSet::from_iter(rw_set.write_set.into_iter()),
            updates: HashMap::new(),
            valid: true,
        }
    }

    /// Commit updates to the wrapped MKVS storage backends in case read
    /// write set matched predictions.
    ///
    /// In case of mismatch this will return an error and not commit any
    /// updates.
    pub fn commit(self, ctx: Context) -> Fallible<()> {
        if !self.valid {
            return Err(ReadWriteSetValidationError::Misprediction.into());
        }

        // Apply updates to backing store if read-write set matches.
        let ctx = ctx.freeze();
        for (key, value) in self.updates {
            let ctx = Context::create_child(&ctx);
            match value {
                Some(value) => self.mkvs.insert(ctx, &key, &value),
                None => self.mkvs.remove(ctx, &key),
            };
        }

        Ok(())
    }

    fn check_read(&mut self, key: &[u8]) {
        if !self.read_set.contains(&key[0..self.granularity])
            && !self.write_set.contains(&key[0..self.granularity])
        {
            self.valid = false;
        }
    }

    fn check_write(&mut self, key: &[u8]) {
        if !self.write_set.contains(&key[0..self.granularity]) {
            self.valid = false;
        }
    }
}

impl<'a> MKVS for Verifier<'a> {
    fn get(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        self.check_read(key);

        // Check local update map first.
        if let Some(value) = self.updates.get(key) {
            return value.clone();
        }

        self.mkvs.get(ctx, key)
    }

    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        self.check_write(key);
        let previous = self.get(ctx, key);
        self.updates.insert(key.to_owned(), Some(value.to_owned()));
        previous
    }

    fn remove(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        self.check_write(key);
        let previous = self.get(ctx, key);
        self.updates.insert(key.to_owned(), None);
        previous
    }

    fn prefetch_prefixes(&self, ctx: Context, prefixes: &Vec<Prefix>, limit: u16) {
        // Pass-through as it has no effect on either reads or writes.
        self.mkvs.prefetch_prefixes(ctx, prefixes, limit)
    }

    fn commit(
        &mut self,
        _ctx: Context,
        _namespace: Namespace,
        _round: u64,
    ) -> Fallible<(WriteLog, Hash)> {
        panic!("should not call commit on read/write set verification wrapper");
    }

    fn rollback(&mut self) {
        panic!("should not call rollback on read/write set verification wrapper");
    }
}

#[cfg(test)]
mod test {
    use io_context::Context;

    use crate::{
        common::cbor,
        storage::mkvs::{
            urkel::{sync::NoopReadSyncer, UrkelTree},
            MKVS,
        },
    };

    use super::*;

    #[test]
    fn test_serialization() {
        let rw_set = ReadWriteSet {
            granularity: 3,
            read_set: vec![b"foo".to_vec().into(), b"bar".to_vec().into()],
            write_set: vec![b"moo".to_vec().into()],
        };

        let enc = cbor::to_vec(&rw_set);

        let dec_rw_set: ReadWriteSet = cbor::from_slice(&enc).unwrap();
        assert_eq!(rw_set, dec_rw_set, "serialization should round-trip");
    }

    #[test]
    fn test_verifier() {
        let rw_set = ReadWriteSet {
            granularity: 3,
            read_set: vec![b"foo".to_vec().into(), b"bar".to_vec().into()],
            write_set: vec![b"bar".to_vec().into()],
        };

        // Create a pre-populated tree.
        let mut tree = UrkelTree::make().new(Box::new(NoopReadSyncer {}));
        tree.insert(Context::background(), b"foobar", b"prepopulated")
            .unwrap();
        tree.insert(Context::background(), b"barfoo", b"prepopulated2")
            .unwrap();

        let mut verifier = rw_set.into_verifier(&mut tree);

        // Do some operations.
        assert_eq!(
            verifier.get(Context::background(), b"foobar"),
            Some(b"prepopulated".to_vec())
        );
        assert_eq!(
            verifier.get(Context::background(), b"barfoo"),
            Some(b"prepopulated2".to_vec())
        );
        verifier.insert(Context::background(), b"barfoo", b"blah");
        assert_eq!(
            verifier.get(Context::background(), b"barfoo"),
            Some(b"blah".to_vec())
        );
        verifier.remove(Context::background(), b"barfoo");
        assert_eq!(verifier.get(Context::background(), b"barfoo"), None);

        let result = verifier.commit(Context::background());
        assert!(result.is_ok(), "read/write verification should succeed");

        // Make sure the operations are committed.
        assert_eq!(tree.get(Context::background(), b"barfoo").unwrap(), None);

        // Test read set violation.
        let rw_set = ReadWriteSet {
            granularity: 3,
            read_set: vec![b"xxx".to_vec().into()],
            write_set: vec![b"bar".to_vec().into()],
        };
        let mut verifier = rw_set.into_verifier(&mut tree);

        // Do some operations.
        assert_eq!(
            verifier.get(Context::background(), b"foobar"),
            Some(b"prepopulated".to_vec())
        );
        verifier.insert(Context::background(), b"barfoo", b"blah");

        let result = verifier.commit(Context::background());
        assert!(result.is_err(), "read/write verification should fail");

        // Make sure the operations are not committed.
        assert_eq!(tree.get(Context::background(), b"barfoo").unwrap(), None);

        // Test write set violation.
        let rw_set = ReadWriteSet {
            granularity: 3,
            read_set: vec![b"bar".to_vec().into()],
            write_set: vec![],
        };
        let mut verifier = rw_set.into_verifier(&mut tree);

        // Do some operations.
        assert_eq!(verifier.get(Context::background(), b"barfoo"), None);
        verifier.insert(Context::background(), b"barfoo", b"blah");

        let result = verifier.commit(Context::background());
        assert!(result.is_err(), "read/write verification should fail");

        // Make sure the operations are not committed.
        assert_eq!(tree.get(Context::background(), b"barfoo").unwrap(), None);
    }
}
