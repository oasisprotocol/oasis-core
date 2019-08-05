package db

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
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
		var h hash.Hash
		h.FromBytes(wl[i].Value)
		ptr := &node.Pointer{
			Clean: true,
			Hash:  h,
			Node: &node.LeafNode{
				Clean: true,
				Hash:  h,
				Key:   wl[i].Key,
				Value: &node.Value{
					Clean: true,
					Hash:  h,
					Value: wl[i].Value,
				},
			},
		}
		wla[i] = writelog.LogEntryAnnotation{
			InsertedNode: ptr,
		}
		hashes[ptr.Hash] = ptr
	}

	hashed := api.MakeHashedDBWriteLog(wl, wla)

	it, err := api.ReviveHashedDBWriteLog(context.Background(), hashed, func(h hash.Hash) (*node.LeafNode, error) {
		return hashes[h].Node.(*node.LeafNode), nil
	})
	require.NoError(t, err, "ReviveHashedDBWriteLog")

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
