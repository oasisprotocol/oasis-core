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
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
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
	genesisTestHelpers.SetTestChainContext()

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
	expectedNewRootType := api.RootTypeState
	var receipts []*api.Receipt
	var receiptBody api.ReceiptBody
	var err error

	// Apply write log to an empty root.
	receipts, err = backend.Apply(ctx, &api.ApplyRequest{
		Namespace: namespace,
		RootType:  api.RootTypeState,
		SrcRound:  round,
		SrcRoot:   rootHash,
		DstRound:  round,
		DstRoot:   expectedNewRoot,
		WriteLog:  wl,
	})
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, namespace, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, round, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRootType, receiptBody.RootTypes[0], "receiptBody root type should equal the expected new root type")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// Prepare another write log and form a set of apply operations.
	wl2 := prepareWriteLog(testValues[0:2])
	expectedNewRoot2 := CalculateExpectedNewRoot(t, wl2, namespace, round)
	applyOps := []api.ApplyOp{
		{RootType: api.RootTypeState, SrcRound: round, SrcRoot: rootHash, DstRoot: expectedNewRoot, WriteLog: wl},
		{RootType: api.RootTypeState, SrcRound: round, SrcRoot: rootHash, DstRoot: expectedNewRoot2, WriteLog: wl2},
	}

	// Apply a batch of operations against the MKVS.
	receipts, err = backend.ApplyBatch(ctx, &api.ApplyBatchRequest{Namespace: namespace, DstRound: round, Ops: applyOps})
	require.NoError(t, err, "ApplyBatch() should not return an error")
	require.NotNil(t, receipts, "ApplyBatch() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, namespace, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, round, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, len(applyOps), len(receiptBody.Roots), "receiptBody should contain as many roots as there were applyOps")
		for i, applyOp := range applyOps {
			require.EqualValues(t, applyOp.DstRoot, receiptBody.Roots[i], "receiptBody root for an applyOp should equal the expected new root")
			require.EqualValues(t, applyOp.RootType, receiptBody.RootTypes[i], "receiptBody root type for an applyOp should equal the expected new root type")
		}
	}

	newRoot := api.Root{
		Namespace: namespace,
		Version:   round,
		Type:      api.RootTypeState,
		Hash:      receiptBody.Roots[0],
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
	receipts, err = backend.Apply(ctx, &api.ApplyRequest{
		Namespace: namespace,
		RootType:  api.RootTypeState,
		SrcRound:  round,
		SrcRoot:   rootHash,
		DstRound:  round,
		DstRoot:   receiptBody.Roots[0],
		WriteLog:  wl,
	})
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, namespace, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, round, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
		require.EqualValues(t, expectedNewRootType, receiptBody.RootTypes[0], "receiptBody root should equal the expected new root")
	}

	// Test checkpoints.
	t.Run("Checkpoints", func(t *testing.T) {
		// Create a new checkpoint with the local backend.
		cp, err := localBackend.Checkpointer().CreateCheckpoint(ctx, newRoot, 16*1024)
		require.NoError(t, err, "CreateCheckpoint")

		cps, err := backend.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: namespace})
		require.NoError(t, err, "GetCheckpoints")
		require.Len(t, cps, 1, "GetCheckpoints should return one checkpoint")
		require.Equal(t, cp, cps[0], "GetCheckpoints should return correct checkpoint metadata")
		require.Len(t, cps[0].Chunks, 1, "checkpoint should have a single chunk")

		var buf bytes.Buffer
		chunk, err := cps[0].GetChunkMetadata(0)
		require.NoError(t, err, "GetChunkMetadata")
		err = backend.GetCheckpointChunk(ctx, chunk, &buf)
		require.NoError(t, err, "GetCheckpointChunk")

		hb := hash.NewBuilder()
		_, err = io.Copy(hb, &buf)
		require.NoError(t, err, "Copy")
		require.Equal(t, cp.Chunks[0], hb.Build(), "GetCheckpointChunk must return correct chunk")
	})
}
