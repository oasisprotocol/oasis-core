package pebbledb

import (
	"bytes"
	"fmt"

	"github.com/cockroachdb/pebble"
)

type iterator struct {
	source  *pebble.Iterator
	prefix  []byte
	valid   bool
	version uint64
}

func versionedIterator(db *pebble.DB, prefix []byte, version uint64) *iterator {
	source, _ := db.NewIter(&pebble.IterOptions{})
	iter := &iterator{
		source:  source,
		prefix:  prefix,
		valid:   true,
		version: version,
	}
	// Seek to first if no prefix is provided.
	if prefix == nil {
		iter.valid = source.First()
		return iter
	}

	// Otherwise go to the first key before the prefix.
	// Two cases are possible here:
	// 1. The prefix is the first key in the DB, SeekLT will put it into an invalid state before it.
	// 2. The prefix is not the first key in the DB, SeekLT will put it into a valid state at the key before it.
	// In both cases we call Next() to move it into the the first key matching the prefix (or an invalid case if no such key exist).
	_ = source.SeekLT(prefix)
	iter.Next()

	return iter
}

func (iter *iterator) Key() []byte {
	iter.assertIsValid()

	// Key version is checked to be valid in Next().
	key, _, ok := decodeMVCCKey(iter.source.Key())
	if !ok {
		panic(fmt.Sprintf("invalid PebbleDB MVCC key: %s", iter.source.Key()))
	}

	return key
}

func (iter *iterator) Value() []byte {
	iter.assertIsValid()

	// Val ensured to not be a tombstone in Next().
	val, tombstone := decodeMVCCValue(iter.source.Value())
	if tombstone {
		panic(fmt.Sprintf("unexpected tombstone value in iteration: %s", iter.source.Value()))
	}

	return val
}

func (iter *iterator) Close() {
	iter.valid = false
	iter.source.Close()
	iter.source = nil
}

func (iter *iterator) Valid() bool {
	// Once invalid, always invalid.
	if !iter.valid {
		return false
	}

	// If iterator is not valid, we are done.
	if !iter.source.Valid() {
		iter.valid = false
		return false
	}

	// Check for errors.
	if err := iter.source.Error(); err != nil {
		iter.valid = false
		return false
	}

	return true
}

func (iter *iterator) Next() bool {
	if !iter.valid {
		return false
	}

	// This moves the iterator to the next prefix (as defined by the Comparer.Split).
	// In our case this skips the keys with the same version as the current key.
	iter.valid = iter.source.NextPrefix()
	if !iter.valid {
		return iter.valid
	}

	// We are now at the first (smallest) version of the next key.
	nextKey, newVersionRaw, ok := decodeMVCCKey(iter.source.Key())
	if !ok {
		panic(fmt.Sprintf("invalid PebbleDB MVCC key: %s", iter.source.Key()))
	}
	// Ensure the key still has the same prefix.
	if !bytes.HasPrefix(nextKey, iter.prefix) {
		iter.valid = false
		return false
	}

	// Check next key version.
	nextKeyVersion, err := decodeVersion(newVersionRaw)
	if err != nil {
		panic(fmt.Sprintf("invalid PebbleDB MVCC key: %s", iter.source.Key()))
	}
	switch {
	case nextKeyVersion > iter.version:
		// This key's smallest version is greater than the iterator version, so skip this key prefix entirely.
		return iter.Next()
	case nextKeyVersion < iter.version:
		// The minimal version of this key is smaller than the iterator version.Next
		// Find the largest version of the key which is smaller than the iterator version.
		iter.valid = iter.source.SeekLT(encodeMVCCKey(nextKey, iter.version+1))
		if !iter.valid {
			return false
		}
	default:
		// We are alraedy at the key with the exact version.
	}

	// Ensure not tombstone.
	if mvccIsTombstone(iter.source.Value()) {
		// If the value is a tombstone, we skip to the next key.
		iter.Next()
	}
	return iter.valid
}

func (iter *iterator) assertIsValid() {
	if !iter.valid {
		panic("iterator is invalid")
	}
}
