// Package tests is a collection of storage implementation test cases.
package tests

import (
	"bytes"
	"context"
	"io"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var testValues = [][]byte{
	[]byte("Thou seest Me as Time who kills, Time who brings all to doom,"),
	[]byte("The Slayer Time, Ancient of Days, come hither to consume;"),
	[]byte("Excepting thee, of all these hosts of hostile chiefs arrayed,"),
	[]byte("There shines not one shall leave alive the battlefield!"),
	[]byte("Thou seest Me as Time who kills, Time who brings all to doom,"),
	[]byte("The Slayer Time, Ancient of Days, come hither to consume;"),
	[]byte("Excepting thee, of all these hosts of hostile chiefs arrayed,"),
	[]byte("There shines not one shall leave alive the battlefield!"),
	[]byte("Thou seest Me as Time who kills, Time who brings all to doom,"),
	[]byte("The Slayer Time, Ancient of Days, come hither to consume;"),
	[]byte("Excepting thee, of all these hosts of hostile chiefs arrayed,"),
	[]byte("There shines not one shall leave alive the battlefield!"),
}

func makeWriteLogLess(wl api.WriteLog) func(i, j int) bool {
	return func(i, j int) bool {
		result := bytes.Compare(wl[i].Key, wl[j].Key)
		if result == 0 {
			return bytes.Compare(wl[i].Value, wl[j].Value) < 0
		}
		return result < 0
	}
}

func prepareWriteLog(values [][]byte) api.WriteLog {
	var wl api.WriteLog
	for i, v := range testValues {
		wl = append(wl, api.LogEntry{Key: []byte(strconv.Itoa(i)), Value: v})
	}
	return wl
}

func CalculateExpectedNewRoot(t *testing.T, wl api.WriteLog, namespace common.Namespace, round uint64) hash.Hash {
	// Use in-memory MKVS tree to calculate the expected new root.
	// Root type doesn't matter, we only need the hash.
	tree := mkvs.New(nil, nil, api.RootTypeState)
	for _, logEntry := range wl {
		err := tree.Insert(context.Background(), logEntry.Key, logEntry.Value)
		require.NoError(t, err, "error inserting writeLog entry into MKVS tree")
	}
	_, expectedNewRoot, err := tree.Commit(context.Background(), namespace, round)
	require.NoError(t, err, "error calculating mkvs' expectedNewRoot")
	return expectedNewRoot
}

func foldWriteLogIterator(t *testing.T, w api.WriteLogIterator) api.WriteLog {
	writeLog := api.WriteLog{}

	for {
		more, err := w.Next()
		require.NoError(t, err, "error iterating over WriteLogIterator")
		if !more {
			break
		}

		val, err := w.Value()
		require.NoError(t, err, "error iterating over WriteLogIterator")
		writeLog = append(writeLog, val)
	}
	return writeLog
}

// StorageImplementationTests exercises the basic functionality of a storage
// backend.
func StorageImplementationTests(t *testing.T, localBackend api.LocalBackend, backend api.Backend, namespace common.Namespace, round uint64) {
	<-backend.Initialized()

	t.Run("Basic", func(t *testing.T) {
		testBasic(t, localBackend, backend, namespace, round)
	})
}

func testBasic(t *testing.T, localBackend api.LocalBackend, backend api.Backend, namespace common.Namespace, round uint64) {
	ctx := context.Background()

	var rootHash hash.Hash
	rootHash.Empty()

	wl := prepareWriteLog(testValues)
	expectedNewRoot := CalculateExpectedNewRoot(t, wl, namespace, round)

	// Apply write log to an empty root.
	err := localBackend.Apply(ctx, &api.ApplyRequest{
		Namespace: namespace,
		RootType:  api.RootTypeState,
		SrcRound:  round,
		SrcRoot:   rootHash,
		DstRound:  round,
		DstRoot:   expectedNewRoot,
		WriteLog:  wl,
	})
	require.NoError(t, err, "Apply() should not return an error")

	newRoot := api.Root{
		Namespace: namespace,
		Version:   round,
		Type:      api.RootTypeState,
		Hash:      expectedNewRoot,
	}

	// Test individual fetches.
	t.Run("SyncGet", func(t *testing.T) {
		tree := mkvs.NewWithRoot(backend, nil, newRoot)
		defer tree.Close()
		for _, entry := range wl {
			value, werr := tree.Get(ctx, entry.Key)
			require.NoError(t, werr, "Get")
			require.EqualValues(t, entry.Value, value)
		}
	})

	// Test prefetch.
	t.Run("SyncGetPrefixes", func(t *testing.T) {
		tree := mkvs.NewWithRoot(backend, nil, newRoot)
		defer tree.Close()
		err = tree.PrefetchPrefixes(ctx, [][]byte{[]byte("1")}, 10)
		require.NoError(t, err, "PrefetchPrefixes")
	})

	// Test iteration.
	t.Run("SyncIterate", func(t *testing.T) {
		tree := mkvs.NewWithRoot(backend, nil, newRoot)
		defer tree.Close()
		it := tree.NewIterator(ctx)
		defer it.Close()

		var idx int
		for it.Rewind(); it.Valid(); it.Next() {
			idx++
		}
		require.NoError(t, it.Err(), "iterator should not error")
		require.EqualValues(t, len(wl), idx, "iterator should visit all items")
	})

	// Get the write log, it should be the same as what we stuffed in.
	root := api.Root{
		Namespace: namespace,
		Version:   round,
		Type:      api.RootTypeState,
		Hash:      rootHash,
	}
	it, err := backend.GetDiff(ctx, &api.GetDiffRequest{StartRoot: root, EndRoot: newRoot})
	require.NoError(t, err, "GetDiff()")
	getDiffWl := foldWriteLogIterator(t, it)
	originalWl := make(api.WriteLog, len(wl))
	copy(originalWl, wl)
	sort.Slice(originalWl, makeWriteLogLess(originalWl))
	sort.Slice(getDiffWl, makeWriteLogLess(getDiffWl))
	require.Equal(t, getDiffWl, originalWl)

	// Now try applying the same operations again, we should get the same root.
	err = localBackend.Apply(ctx, &api.ApplyRequest{
		Namespace: namespace,
		RootType:  api.RootTypeState,
		SrcRound:  round,
		SrcRoot:   rootHash,
		DstRound:  round,
		DstRoot:   expectedNewRoot,
		WriteLog:  wl,
	})
	require.NoError(t, err, "Apply() should not return an error")

	// Test checkpoints.
	t.Run("Checkpoints", func(t *testing.T) {
		// Create a new checkpoint with the local backend.
		cp, err := localBackend.Checkpointer().CreateCheckpoint(ctx, newRoot, 16*1024)
		require.NoError(t, err, "CreateCheckpoint")

		cps, err := backend.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: namespace})
		require.NoError(t, err, "GetCheckpoints")
		require.Contains(t, cps, cp, "GetCheckpoints should return correct checkpoint metadata")
		require.Len(t, cp.Chunks, 1, "checkpoint should have a single chunk")

		var buf bytes.Buffer
		chunk, err := cp.GetChunkMetadata(0)
		require.NoError(t, err, "GetChunkMetadata")
		err = backend.GetCheckpointChunk(ctx, chunk, &buf)
		require.NoError(t, err, "GetCheckpointChunk")

		hb := hash.NewBuilder()
		_, err = io.Copy(hb, &buf)
		require.NoError(t, err, "Copy")
		require.Equal(t, cp.Chunks[0], hb.Build(), "GetCheckpointChunk must return correct chunk")
	})
}
