package rocksdb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/linxGnu/grocksdb"
)

// Versions (u64) are used as timestamps.
const timestampSize = 8

// createTimestampComparator is identical to the RocksDB builtin u64 timestamp comparator.
// https://github.com/facebook/rocksdb/blob/526f36b48381dd640a0426bd748dbc0bb5797c75/util/comparator.cc#L234-L307.
func createTimestampComparator() *grocksdb.Comparator {
	return grocksdb.NewComparatorWithTimestamp(
		// Use the builtin "leveldb.BytewiseComparator.u64ts" as name,
		// so that the builtin tools `ldb`/`sst_dump` can work with the db.
		"leveldb.BytewiseComparator.u64ts",
		timestampSize,
		compareTimestampKeys,
		compareTimestamp,
		compareWithoutTimestamp,
	)
}

// gorocksdb.Comparing.
func compareTimestampKeys(a, b []byte) int {
	// First compare keys without timestamps.
	if ret := compareWithoutTimestamp(a, true, b, true); ret != 0 {
		return ret
	}

	// In case the key is the same, compare the timestamp (larger first).
	return -compareTimestamp(a[len(a)-timestampSize:], b[len(b)-timestampSize:])
}

// gorocksdb.Comparing.
func compareTimestamp(a, b []byte) int {
	ts1 := binary.LittleEndian.Uint64(a)
	ts2 := binary.LittleEndian.Uint64(b)

	switch {
	case ts1 < ts2:
		return -1
	case ts1 > ts2:
		return 1
	default:
		return 0
	}
}

// gorocksdb.ComparingWithoutTimestamp.
func compareWithoutTimestamp(a []byte, aHasTs bool, b []byte, bHasTs bool) int {
	if aHasTs {
		a = a[:len(a)-timestampSize]
	}
	if bHasTs {
		b = b[:len(b)-timestampSize]
	}
	return bytes.Compare(a, b)
}

func timestampFromVersion(version uint64) [timestampSize]byte {
	var ts [timestampSize]byte
	binary.LittleEndian.PutUint64(ts[:], version)
	return ts
}

// timestampReadOptions returns ReadOptions used in the RocksDB column family read.
func timestampReadOptions(version uint64) *grocksdb.ReadOptions {
	ts := timestampFromVersion(version)

	readOpts := grocksdb.NewDefaultReadOptions()
	readOpts.SetTimestamp(ts[:])

	return readOpts
}

func versionFromTimestamp(ts *grocksdb.Slice) (uint64, error) {
	if !ts.Exists() {
		return 0, fmt.Errorf("timestamp empty")
	}
	defer ts.Free()
	return binary.LittleEndian.Uint64(ts.Data()), nil
}
