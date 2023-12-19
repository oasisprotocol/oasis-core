//go:build rocksdb
// +build rocksdb

package rocksdb

import (
	"bytes"
	"slices"

	"github.com/linxGnu/grocksdb"
)

type iterator struct {
	source  *grocksdb.Iterator
	prefix  []byte
	invalid bool
}

func prefixIterator(source *grocksdb.Iterator, prefix []byte) *iterator {
	if prefix == nil {
		source.SeekToFirst()
	} else {
		source.Seek(prefix)
	}

	return &iterator{
		source:  source,
		prefix:  prefix,
		invalid: !source.Valid(),
	}
}

func readOnlySlice(s *grocksdb.Slice) []byte {
	if !s.Exists() {
		return nil
	}

	return s.Data()
}

// copyAndFreeSlice will copy a given RocksDB slice and free it. If the slice does
// not exist, <nil> will be returned.
func copyAndFreeSlice(s *grocksdb.Slice) []byte {
	defer s.Free()
	if !s.Exists() {
		return nil
	}

	return slices.Clone(s.Data())
}

func (itr *iterator) Valid() bool {
	// Once invalid, always invalid.
	if itr.invalid {
		return false
	}

	// Check for errors.
	if err := itr.source.Err(); err != nil {
		itr.invalid = true
		return false
	}

	// If iterator is not valid, we are done.
	if !itr.source.Valid() {
		itr.invalid = true
		return false
	}

	// If key does not match prefix, we are done.
	if !bytes.HasPrefix(readOnlySlice(itr.source.Key()), itr.prefix) {
		itr.invalid = true
		return false
	}

	return true
}

func (itr *iterator) Key() []byte {
	itr.assertIsValid()
	return copyAndFreeSlice(itr.source.Key())
}

func (itr *iterator) Timestamp() []byte {
	itr.assertIsValid()
	return copyAndFreeSlice(itr.source.Timestamp())
}

func (itr *iterator) Value() []byte {
	itr.assertIsValid()
	return copyAndFreeSlice(itr.source.Value())
}

func (itr iterator) Next() bool {
	if itr.invalid {
		return false
	}

	itr.source.Next()

	return itr.Valid()
}

func (itr *iterator) Error() error {
	return itr.source.Err()
}

func (itr *iterator) Close() {
	if itr.source != nil {
		itr.source.Close()
	}
	itr.source = nil
	itr.invalid = true
}

func (itr *iterator) assertIsValid() {
	if itr.invalid {
		panic("iterator is invalid")
	}
}
