package pebbledb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/cockroachdb/pebble"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

const tombstoneVal = "TOMBSTONE"

// MVCCComparer returns a PebbleDB Comparer with encoding and decoding routines
// for MVCC control, used to compare and store versioned keys.
//
// Note: This Comparer implementation is largely based on PebbleDB's internal
// MVCC example, which can be found here:
// https://github.com/cockroachdb/pebble/blob/master/cmd/pebble/mvcc.go
var MVCCComparer = &pebble.Comparer{
	Name: "ss_pebbledb_comparator",

	Compare: MVCCKeyCompare,

	AbbreviatedKey: func(k []byte) uint64 {
		key, _, ok := SplitMVCCKey(k)
		if !ok {
			return 0
		}

		return pebble.DefaultComparer.AbbreviatedKey(key)
	},

	Equal: func(a, b []byte) bool {
		return MVCCKeyCompare(a, b) == 0
	},

	Separator: func(dst, a, b []byte) []byte {
		aKey, _, ok := SplitMVCCKey(a)
		if !ok {
			return append(dst, a...)
		}

		bKey, _, ok := SplitMVCCKey(b)
		if !ok {
			return append(dst, a...)
		}

		// if the keys are the same return a.
		if bytes.Equal(aKey, bKey) {
			return append(dst, a...)
		}

		n := len(dst)

		// MVCC key comparison uses bytes.Compare on the roachpb.Key, which is the
		// same semantics as pebble.DefaultComparer, so reuse the latter's Separator
		// implementation.
		dst = pebble.DefaultComparer.Separator(dst, aKey, bKey)

		// Did we pick a separator different than aKey? If we did not, we can't do
		// better than a.
		buf := dst[n:]
		if bytes.Equal(aKey, buf) {
			return append(dst[:n], a...)
		}

		// The separator is > aKey, so we only need to add the timestamp sentinel.
		return append(dst, 0)
	},

	ImmediateSuccessor: func(dst, a []byte) []byte {
		// The key `a` is guaranteed to be a bare prefix: It's a key without a version
		// — just a trailing 0-byte to signify the length of the version. For example
		// the user key "foo" is encoded as: "foo\0". We need to encode the immediate
		// successor to "foo", which in the natural byte ordering is "foo\0". Append
		// a single additional zero, to encode the user key "foo\0" with a zero-length
		// version.
		return append(append(dst, a...), 0)
	},

	Successor: func(dst, a []byte) []byte {
		aKey, _, ok := SplitMVCCKey(a)
		if !ok {
			return append(dst, a...)
		}

		n := len(dst)

		// MVCC key comparison uses bytes.Compare on the roachpb.Key, which is the
		// same semantics as pebble.DefaultComparer, so reuse the latter's Successor
		// implementation.
		dst = pebble.DefaultComparer.Successor(dst, aKey)

		// Did we pick a successor different than aKey? If we did not, we can't do
		// better than a.
		buf := dst[n:]
		if bytes.Equal(aKey, buf) {
			return append(dst[:n], a...)
		}

		// The successor is > aKey, so we only need to add the timestamp sentinel.
		return append(dst, 0)
	},

	FormatKey: func(k []byte) fmt.Formatter {
		return mvccKeyFormatter{key: k}
	},

	Split: func(k []byte) int {
		key, _, ok := SplitMVCCKey(k)
		if !ok {
			return len(k)
		}

		// This matches the behavior of libroach/KeyPrefix. RocksDB requires that
		// keys generated via a SliceTransform be comparable with normal encoded
		// MVCC keys. Encoded MVCC keys have a suffix indicating the number of
		// bytes of timestamp data. MVCC keys without a timestamp have a suffix of
		// 0. We're careful in EncodeKey to make sure that the user-key always has
		// a trailing 0. If there is no timestamp this falls out naturally. If
		// there is a timestamp we prepend a 0 to the encoded timestamp data.
		return len(key) + 1
	},
}

type mvccKeyFormatter struct {
	key []byte
}

func (f mvccKeyFormatter) Format(s fmt.State, _ rune) {
	k, vBz, ok := SplitMVCCKey(f.key)
	if ok {
		v, _ := decodeUint64Ascending(vBz)
		fmt.Fprintf(s, "versioned: %s/%d (fullk: %s)", k, v, f.key)
	} else {
		fmt.Fprintf(s, "not versioned: %s", f.key)
	}
}

// SplitMVCCKey accepts an MVCC key and returns the "user" key, the MVCC version,
// and a boolean indicating if the provided key is an MVCC key.
//
// Note, internally, we must make a copy of the provided mvccKey argument, which
// typically comes from the Key() method as it's not safe.
func SplitMVCCKey(mvccKey []byte) (key, version []byte, ok bool) {
	if len(mvccKey) == 0 {
		return nil, nil, false
	}
	mvccKeyCopy := bytes.Clone(mvccKey)

	// If first byte bellow 0x80 this key is not versioned (TODO: could return version 0).
	if mvccKeyCopy[0] < 0x80 {
		return mvccKeyCopy, nil, false
	}

	n := len(mvccKeyCopy) - 1    // last item
	tsLen := int(mvccKeyCopy[n]) // int(last item)=timestamp length
	if n < tsLen {
		return nil, nil, false
	}

	key = mvccKeyCopy[:n-tsLen] // key=[0:n-tsLen], version=[n-tsLen+1: n]
	if tsLen > 0 {
		version = mvccKeyCopy[n-tsLen+1 : n]
	}

	return key, version, true
}

// SplitMVCCValue accepts an MVCC key and returns the "user" key, the MVCC version,
// and a boolean indicating if the provided key is an MVCC key.
//
// Note, internally, we must make a copy of the provided mvccKey argument, which
// typically comes from the Key() method as it's not safe.
func SplitMVCCValue(mvccKey []byte) (key, version []byte, ok bool) {
	if len(mvccKey) == 0 {
		return nil, nil, false
	}
	mvccKeyCopy := bytes.Clone(mvccKey)

	n := len(mvccKeyCopy) - 1    // last item
	tsLen := int(mvccKeyCopy[n]) // int(last item)=timestamp length
	if n < tsLen {
		return nil, nil, false
	}

	key = mvccKeyCopy[:n-tsLen] // key=[0:n-tsLen], version=[n-tsLen+1: n]
	if tsLen > 0 {
		version = mvccKeyCopy[n-tsLen+1 : n]
	}

	return key, version, true
}

// MVCCKeyCompare compares two MVCC keys.
func MVCCKeyCompare(a, b []byte) int {
	aEnd := len(a) - 1
	bEnd := len(b) - 1
	if aEnd < 0 || bEnd < 0 {
		// This should never happen unless there is some sort of corruption of
		// the keys. This is a little bizarre, but the behavior exactly matches
		// engine/db.cc:DBComparator.
		return bytes.Compare(a, b)
	}

	// If first byte bellow 0x80 this key is not versioned (TODO: could return version 0).
	if a[0] < 0x80 && b[0] < 0x80 {
		return bytes.Compare(a, b)
	}

	// Compute the index of the separator between the key and the timestamp.
	aSep := aEnd - int(a[aEnd])
	bSep := bEnd - int(b[bEnd])
	if aSep < 0 || bSep < 0 {
		// This should never happen unless there is some sort of corruption of
		// the keys. This is a little bizarre, but the behavior exactly matches
		// engine/db.cc:DBComparator.
		return bytes.Compare(a, b)
	}

	// compare the "user key" part of the key
	if c := bytes.Compare(a[:aSep], b[:bSep]); c != 0 {
		return c
	}

	// compare the timestamp part of the key
	aTS := a[aSep:aEnd]
	bTS := b[bSep:bEnd]
	if len(aTS) == 0 {
		if len(bTS) == 0 {
			return 0
		}
		return -1
	} else if len(bTS) == 0 {
		return 1
	}

	return bytes.Compare(aTS, bTS)
}

// MVCCEncode encodes a MVCC key with the specified version.
//
// <key>\x00[<version>]<#version-bytes>
func MVCCEncode(key []byte, version uint64) (dst []byte) {
	dst = append(dst, key...)
	dst = append(dst, 0)

	if version != 0 {
		extra := byte(1 + 8)
		dst = encodeUint64Ascending(dst, version)
		dst = append(dst, extra)
	}

	return dst
}

// encodeUint64Ascending encodes the uint64 value using a big-endian 8 byte
// representation. The bytes are appended to the supplied buffer and
// the final buffer is returned.
func encodeUint64Ascending(dst []byte, v uint64) []byte {
	return append(
		dst,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

// decodeUint64Ascending decodes a uint64 from the input buffer, treating
// the input as a big-endian 8 byte uint64 representation. The decoded uint64 is
// returned.
func decodeUint64Ascending(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(b) < 8 {
		return 0, fmt.Errorf("insufficient bytes to decode uint64 int value; expected 8; got %d", len(b))
	}

	v := binary.BigEndian.Uint64(b)
	return v, nil
}

func tombstoneVersion(val []byte) (uint64, bool) {
	_, tombBz, ok := SplitMVCCValue(val)
	if !ok {
		panic(fmt.Sprintf("not a valid mvcc value: %s", val))
	}

	// Not a tombstone.
	if len(tombBz) == 0 {
		return 0, false
	}

	// Decode tombstone.
	tombstone, err := decodeUint64Ascending(tombBz)
	if err != nil {
		panic(fmt.Sprintf("not a valid tombstone in mvcc value: %s", val))
	}
	return tombstone, true
}

// existsVersioned checks if the key at the given MVCC key exists at the given version.
func existsVersioned(db *pebble.DB, key []byte, version uint64) error {
	// End domain is exclusive, so increment the version.
	if version < math.MaxUint64 {
		version++
	}

	iter, _ := db.NewIter(&pebble.IterOptions{
		LowerBound: key,
		UpperBound: MVCCEncode(key, version),
	})
	defer iter.Close()

	// Move the iterator to the last key matching the bounds.
	if !iter.Last() {
		return errNotFound
	}

	// Check if value is a tombstone.
	val := iter.Value()
	tv, isTomb := tombstoneVersion(val)
	if isTomb && tv <= version {
		// Tombstone in the past, the key was deleted.
		return errNotFound
	}

	return nil
}

// fetchVersionedRaw fetches and the raw value at the given MVCC key and version.
//
// errNotFound is returned if the key does not exist.
func fetchVersionedRaw(db *pebble.DB, key []byte, version uint64) ([]byte, error) {
	// End domain is exclusive, so increment the version.
	if version < math.MaxUint64 {
		version++
	}

	iter, _ := db.NewIter(&pebble.IterOptions{
		LowerBound: key,
		UpperBound: MVCCEncode(key, version),
	})
	defer iter.Close()

	// Move the iterator to the last key matching the bounds.
	if !iter.Last() {
		return nil, errNotFound
	}

	// Check if value is a tombstone.
	val := iter.Value()
	tv, isTomb := tombstoneVersion(val)
	if isTomb && tv <= version {
		// Tombstone -> the key was deleted.
		return nil, errNotFound
	}
	v, _, _ := SplitMVCCKey(val) // TODO: hack, update tombstone version???

	return v, nil
}

// fetchVersioned fetches and seriliazes the value at the given MVCC key and version.
//
// errNotFound is returned if the key does not exist.
func fetchVersioned(db *pebble.DB, key []byte, version uint64, ret interface{}) error {
	v, err := fetchVersionedRaw(db, key, version)
	if err != nil {
		return err
	}
	return cbor.Unmarshal(v, ret)
}

// deleteVersioned deletes the MVCC versioned key at the given version.
func deleteVersioned(batch *pebble.Batch, key []byte, version uint64) error {
	// Write a tombstone, instead of deleting the key.
	return batch.Set(MVCCEncode(key, version), MVCCEncode([]byte(tombstoneVal), version), nil) // TODO: not sure why value is done this way, but this is what cosmos does.
}

// putVersioned puts the MVCC versioned key at the given version.
func putVersioned(batch *pebble.Batch, key []byte, version uint64, value []byte) error {
	return batch.Set(MVCCEncode(key, version), MVCCEncode(value, 0), nil)
}
