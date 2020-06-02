package db

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	writeLogSize = 100
)

func makeWriteLog() writelog.WriteLog {
	wl := make(writelog.WriteLog, writeLogSize)

	for i := 0; i < writeLogSize; i++ {
		wl[i] = writelog.LogEntry{
			Key:   []byte(fmt.Sprintf("key %d", i)),
			Value: []byte(fmt.Sprintf("value %d", i)),
		}
	}

	return wl
}

func TestHashedWriteLog(t *testing.T) {
	wl := makeWriteLog()
	wla := make(writelog.Annotations, len(wl))
	hashes := make(map[hash.Hash]*node.Pointer)
	for i := 0; i < len(wl); i++ {
		h := hash.NewFromBytes(wl[i].Value)
		ptr := &node.Pointer{
			Clean: true,
			Hash:  h,
			Node: &node.LeafNode{
				Clean: true,
				Hash:  h,
				Key:   wl[i].Key,
				Value: wl[i].Value,
			},
		}
		wla[i] = writelog.LogEntryAnnotation{
			InsertedNode: ptr,
		}
		hashes[ptr.Hash] = ptr
	}

	hashed := api.MakeHashedDBWriteLog(wl, wla)

	var done bool
	it, err := api.ReviveHashedDBWriteLogs(context.Background(),
		func() (node.Root, api.HashedDBWriteLog, error) {
			if done {
				return node.Root{}, nil, nil
			}
			done = true

			return node.Root{}, hashed, nil
		},
		func(root node.Root, h hash.Hash) (*node.LeafNode, error) {
			return hashes[h].Node.(*node.LeafNode), nil
		},
		func() {},
	)
	require.NoError(t, err, "ReviveHashedDBWriteLogs")

	i := 0
	for {
		more, err := it.Next()
		require.NoError(t, err, "it.Next()")
		if !more {
			break
		}
		entry, err := it.Value()
		require.NoError(t, err, "it.Value()")
		require.Equal(t, entry, wl[i])
		i++
	}
	require.Equal(t, i, len(wl))
}
