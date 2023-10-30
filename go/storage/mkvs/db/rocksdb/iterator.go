package rocksdb

import (
	"bytes"
	"slices"

	"github.com/linxGnu/grocksdb"
)

type iterator struct {
	source     *grocksdb.Iterator
	start, end []byte
	reverse    bool
	invalid    bool
}

// TODO: add support for prefix, on valid, check if prefix matches.
func newIterator(source *grocksdb.Iterator, start, end []byte, reverse bool) *iterator {
	switch reverse {
	case false:
		if start == nil {
			source.SeekToFirst()
		} else {
			source.Seek(start)
		}
	case true:
		if end == nil {
			source.SeekToLast()
		} else {
			source.Seek(end)

			if source.Valid() {
				// We are either at the matching key, or the next key.
				eoaKey := readOnlySlice(source.Key())
				if bytes.Compare(end, eoaKey) <= 0 { // end == aoaKey, or end < eaoKey
					// End is exclusive, so move to the previous key.
					source.Prev()
				}
			} else {
				// Past the end of the db, move to the last key.
				source.SeekToLast()
			}
		}

	}

	return &iterator{
		source:  source,
		start:   start,
		end:     end,
		reverse: reverse,
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
	// once invalid, forever invalid
	if itr.invalid {
		return false
	}

	// if source has error, consider it invalid
	if err := itr.source.Err(); err != nil {
		itr.invalid = true
		return false
	}

	// if source is invalid, consider it invalid
	if !itr.source.Valid() {
		itr.invalid = true
		return false
	}

	// if key is at the end or past it, consider it invalid
	start := itr.start
	end := itr.end
	key := readOnlySlice(itr.source.Key())

	if itr.reverse {
		if start != nil && bytes.Compare(key, start) < 0 {
			itr.invalid = true
			return false
		}
	} else {
		if end != nil && bytes.Compare(end, key) <= 0 {
			itr.invalid = true
			return false
		}
	}

	return true
}

func (itr *iterator) Key() []byte {
	itr.assertIsValid()
	return copyAndFreeSlice(itr.source.Key())
}

func (itr *iterator) Value() []byte {
	itr.assertIsValid()
	return copyAndFreeSlice(itr.source.Value())
}

func (itr iterator) Next() bool {
	if itr.invalid {
		return false
	}

	if itr.reverse {
		itr.source.Prev()
	} else {
		itr.source.Next()
	}

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
