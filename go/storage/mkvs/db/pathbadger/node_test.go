package pathbadger

import (
	"testing"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

func FuzzPtr(f *testing.F) {
	// Seed corpus.
	ptr := &node.Pointer{
		DBInternal: &dbPtr{},
	}
	f.Add(ptrToDb(ptr))

	// Fuzzing.
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, ptr, err := ptrFromDb(data)
		if err != nil {
			return
		}

		_ = ptrToDb(ptr)
	})
}

func FuzzNode(f *testing.F) {
	// Seed corpus.
	ptr := &node.Pointer{
		Node: &node.LeafNode{
			Key:   []byte("foo"),
			Value: []byte("bar"),
		},
		DBInternal: &dbPtr{},
	}
	_, value, err := nodeToDb(ptr)
	if err != nil {
		panic(err)
	}
	f.Add(value)

	ptr = &node.Pointer{
		Node: &node.InternalNode{
			LeafNode: &node.Pointer{
				Node: &node.LeafNode{
					Key:   []byte("moo"),
					Value: []byte("goo"),
				},
				DBInternal: &dbPtr{},
			},
			Left: &node.Pointer{
				DBInternal: &dbPtr{
					version: 42,
					index:   7,
				},
			},
		},
		DBInternal: &dbPtr{},
	}
	_, value, err = nodeToDb(ptr)
	if err != nil {
		panic(err)
	}
	f.Add(value)

	// Fuzzing.
	f.Fuzz(func(_ *testing.T, data []byte) {
		n, err := nodeFromDb(data)
		if err != nil {
			return
		}

		ptr := &node.Pointer{Node: n, DBInternal: &dbPtr{}}
		_, _, err = nodeToDb(ptr)
		if err != nil {
			panic(err)
		}
	})
}
