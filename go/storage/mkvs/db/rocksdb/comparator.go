package rocksdb

import (
	"bytes"
	"encoding/binary"

	"github.com/linxGnu/grocksdb"
)

const timestampSize = 8

// CreateTSComparator should behavior identical with rocksdb builtin timestamp comparator.
// we also use the same builtin comparator name so the builtin tools `ldb`/`sst_dump` can work with the database.
func createTimestampComparator() *grocksdb.Comparator {
	return grocksdb.NewComparatorWithTimestamp(
		"leveldb.BytewiseComparator.u64ts",
		timestampSize,
		// All of the Go comparator implementations should replicate leveldb.BytewiseComparator.u64ts.
		compareTimestampKeys,
		compareTimestamp,
		compareWithoutTimestamp,
	)
}

func compareTimestampKeys(a, b []byte) int {
	// First compare keys without timestamps.
	if ret := compareWithoutTimestamp(a, true, b, true); ret != 0 {
		return ret
	}

	// In case the key is the same, compare the timestamp (larger first).
	return -compareTimestamp(a[len(a)-timestampSize:], b[len(b)-timestampSize:])
}

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

func compareWithoutTimestamp(a []byte, aHasTs bool, b []byte, bHasTs bool) int {
	if aHasTs {
		a = a[:len(a)-timestampSize]
	}
	if bHasTs {
		b = b[:len(b)-timestampSize]
	}
	return bytes.Compare(a, b)
}
