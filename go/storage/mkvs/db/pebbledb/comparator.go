package pebbledb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/cockroachdb/pebble"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

const (
	// mvccKeyIndicator marks keys as being version-controlled under the MVCC scheme.
	// It's part of the key prefix where any prefix value greater than 0x7F indicates an MVCC key.
	// This serves as a contract within the database to differentiate between MVCC and non-MVCC keys.
	mvccKeyIndicator = 0x7F
)

var errVersionedNotFound = fmt.Errorf("mkvs/pebbledb: versioned key not found")

// MVCCComparer returns a PebbleDB Comparer with encoding and decoding routines
// for MVCC control, used to compare and store versioned keys.
//
// Based on:
//
// https://github.com/cockroachdb/pebble/blob/master/cmd/pebble/mvcc.go
// https://github.com/cockroachdb/cockroach/blob/049d54d18aead4c10308ebb9e996451dffe2c9c4/pkg/storage/pebble.go#L379-L488
// https://github.com/cosmos/cosmos-sdk/blob/e4fabebfc5e1fe4dddb8ea7583bf2ba2a891649b/store/storage/pebbledb/comparator.go#L17
var MVCCComparer = &pebble.Comparer{
	Name: "pebbledb_comparator",

	Compare: mvccKeyCompare,

	Equal: func(a, b []byte) bool {
		return mvccKeyCompare(a, b) == 0
	},

	AbbreviatedKey: func(k []byte) uint64 {
		key, _, ok := decodeMVCCKey(k)
		if !ok {
			return 0
		}

		return pebble.DefaultComparer.AbbreviatedKey(key)
	},

	Separator: func(dst, a, b []byte) []byte {
		aKey, _, ok := decodeMVCCKey(a)
		if !ok {
			return append(dst, a...)
		}

		bKey, _, ok := decodeMVCCKey(b)
		if !ok {
			return append(dst, a...)
		}

		// If the keys are the same just return a.
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
		aKey, _, ok := decodeMVCCKey(a)
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
		key, _, ok := decodeMVCCKey(k)
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
	k, vBz, ok := decodeMVCCKey(f.key)
	if ok {
		v, _ := decodeVersion(vBz)
		fmt.Fprintf(s, "mvcc: %s/%d (fullkey: %s)", k, v, f.key)
	} else {
		fmt.Fprintf(s, "non-mvcc: %s", f.key)
	}
}

// decodeMVCCValue accepts a raw MVCC value and returns the "user" value, and
// a boolean indecating if the provided value is a tombstone.
func decodeMVCCValue(mvccValue []byte) ([]byte, bool) {
	// Tombstone.
	if len(mvccValue) == 0 {
		return nil, true
	}
	// Otherwise this is not a tombstone, copy and return the user value.
	value := bytes.Clone(mvccValue)
	return value[:len(mvccValue)-1], false
}

// encodeMVVCValue returns an encoded a MVCC value.
//
// Tombstones are encoded as empty values, normal values are encoded as [value] + [1].
func encodeMVVCValue(value []byte, tombstone bool) []byte {
	if tombstone {
		return []byte{}
	}
	return append(value, 0x1)
}

// mvccKeyCompare compares two MVCC keys.
func mvccKeyCompare(a, b []byte) int {
	// For performance, this routine manually splits the key into the user-key
	// and version components rather than using DecodeEngineKey.
	aEnd := len(a) - 1
	bEnd := len(b) - 1
	if aEnd < 0 || bEnd < 0 {
		// This should never happen unless there is some sort of corruption of
		// the keys.
		return bytes.Compare(a, b)
	}

	// If any of the keys are not versioned, compare as regular keys.
	if a[0] < mvccKeyIndicator || b[0] < mvccKeyIndicator {
		return bytes.Compare(a, b)
	}

	// Compute the index of the separator between the key and the version. If the
	// separator is found to be at -1 for both keys, then we are comparing bare
	// suffixes without a user key part. Pebble requires bare suffixes to be
	// comparable with the same ordering as if they had a common user key.
	aSep := aEnd - int(a[aEnd])
	bSep := bEnd - int(b[bEnd])
	if aSep == -1 && bSep == -1 {
		aSep, bSep = 0, 0 // comparing bare suffixes
	}
	if aSep < 0 || bSep < 0 {
		// This should never happen unless there is some sort of corruption of
		// the keys.
		return bytes.Compare(a, b)
	}

	// Compare the "user key" part of the key.
	if c := bytes.Compare(a[:aSep], b[:bSep]); c != 0 {
		return c
	}

	// Compare the version part of the key.
	// Since versions are encoded as big-endian, we can compare the raw bytes.
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

// encodeMVCCKey encodes a MVCC key with the specified version.
//
// <key>\x00<version><#version-bytes>
func encodeMVCCKey(key []byte, version uint64) []byte {
	if len(key) > 0 && key[0] <= mvccKeyIndicator {
		panic(fmt.Sprintf("invalid key: first byte doesn't indicate a mvcc key: %s", key))
	}

	dst := make([]byte, 0, len(key)+1+8+1)

	// <key>
	dst = append(dst, key...)
	// \x00
	dst = append(dst, 0)
	// <version>
	dst = encodeVersion(dst, version)
	// <# version-bytes>
	dst = append(dst, 9)

	return dst
}

// decodeMVCCKey accepts an MVCC key and returns the "user" key, the MVCC version,
// and a boolean indicating if the provided key is an MVCC key.
// MVCC version is returned raw.
func decodeMVCCKey(mvccKey []byte) (key, version []byte, ok bool) {
	if len(mvccKey) == 0 {
		return nil, nil, false
	}
	mvccKeyCopy := bytes.Clone(mvccKey)

	// If first byte bellow 0x80 this key is not versioned.
	if mvccKeyCopy[0] < mvccKeyIndicator {
		return mvccKeyCopy, nil, false
	}

	n := len(mvccKeyCopy) - 1
	tsLen := int(mvccKeyCopy[n]) // Last iterm is timestamp length.
	if n < tsLen {
		// Invalid key.
		return nil, nil, false
	}

	// Key is [0:n-tsLen]
	key = mvccKeyCopy[:n-tsLen]
	if tsLen > 0 {
		// Version is: [n-tsLen+1:n].
		version = mvccKeyCopy[n-tsLen+1 : n]
	}
	return key, version, true
}

// encodeVersion encodes the uint64 version value using a big-endian 8 byte
// representation.
func encodeVersion(dst []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(dst, v)
}

// decodeVersion decodes a uint64 version value from the input buffer, treating
// the input as a big-endian 8 byte uint64 representation.
func decodeVersion(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(b) < 8 {
		return 0, fmt.Errorf("insufficient bytes to decode uint64 int value; expected 8; got %d", len(b))
	}

	v := binary.BigEndian.Uint64(b)
	return v, nil
}

func mvccIsTombstone(val []byte) bool {
	// Tombstones are encoded as empty values.
	return len(val) == 0
}

// existsVersioned checks if the key at the given MVCC key exists at the given version.
func existsVersioned(db *pebble.DB, key []byte, version uint64) error {
	// End domain is exclusive, so increment the version.
	if version < math.MaxUint64 {
		version++
	}

	iter, _ := db.NewIter(&pebble.IterOptions{
		LowerBound: key,
		UpperBound: encodeMVCCKey(key, version),
	})
	defer iter.Close()

	// Move the iterator to the last key matching the bounds.
	if !iter.Last() {
		return errVersionedNotFound
	}

	// Check if value is a tombstone.
	if mvccIsTombstone(iter.Value()) {
		return errVersionedNotFound
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
		UpperBound: encodeMVCCKey(key, version),
	})
	defer iter.Close()

	// Move the iterator to the last key matching the bounds.
	if !iter.Last() {
		return nil, errVersionedNotFound
	}

	// Decode MVCC value.
	val, isTomb := decodeMVCCValue(iter.Value())
	if isTomb {
		// Tombstone -> the key was deleted.
		return nil, errVersionedNotFound
	}

	return val, nil
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
	return batch.Set(encodeMVCCKey(key, version), encodeMVVCValue(nil, true), nil)
}

// putVersioned puts the MVCC versioned key at the given version.
func putVersioned(batch *pebble.Batch, key []byte, version uint64, value []byte) error {
	return batch.Set(encodeMVCCKey(key, version), encodeMVVCValue(value, false), nil)
}
