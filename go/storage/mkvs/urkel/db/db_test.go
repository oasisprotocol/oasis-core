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

func TestStaticWriteLogIterator(t *testing.T) {
	var more bool
	var err error
	var val writelog.LogEntry

	wl := makeWriteLog()

	it := api.NewStaticWriteLogIterator(wl)

	for _, ent := range wl {
		more, err = it.Next()
		require.NoError(t, err, "it.Next()")
		require.Equal(t, more, true)
		val, err = it.Value()
		require.NoError(t, err, "it.Value()")
		require.Equal(t, val, ent)
	}
	more, err = it.Next()
	require.NoError(t, err, "last it.Next()")
	require.Equal(t, more, false)
	_, err = it.Value()
	require.Error(t, err, "last it.Value()")

	var wl2 writelog.WriteLog
	it = api.NewStaticWriteLogIterator(wl2)
	more, err = it.Next()
	require.NoError(t, err, "empty it.Next()")
	require.Equal(t, more, false)
}

func TestPipeWriteLogIterator(t *testing.T) {
	var err error
	var more bool
	var val writelog.LogEntry

	wl := makeWriteLog()
	pipe := api.NewPipeWriteLogIterator(context.Background())

	for idx := range wl {
		err = pipe.Put(&wl[idx])
		require.NoError(t, err, "pipe.Put()")
	}
	pipe.Close()

	for _, ent := range wl {
		more, err = pipe.Next()
		require.NoError(t, err, "pipe.Next()")
		require.Equal(t, more, true)
		val, err = pipe.Value()
		require.NoError(t, err, "pipe.Value()")
		require.Equal(t, val, ent)
	}
	more, err = pipe.Next()
	require.NoError(t, err, "last pipe.Next()")
	require.Equal(t, more, false)
	_, err = pipe.Value()
	require.Error(t, err, "last pipe.Value()")
}

func TestHashedWriteLog(t *testing.T) {
	wl := makeWriteLog()
	wla := make(writelog.WriteLogAnnotations, len(wl))
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
				Key:   h,
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
