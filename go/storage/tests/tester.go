// Package tests is a collection of storage implementation test cases.
package tests

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	genesisTestHelpers "github.com/oasislabs/oasis-core/go/genesis/tests"
	"github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
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
	// Use in-memory Urkel tree to calculate the expected new root.
	tree := urkel.New(nil, nil)
	for _, logEntry := range wl {
		err := tree.Insert(context.Background(), logEntry.Key, logEntry.Value)
		require.NoError(t, err, "error inserting writeLog entry into Urkel tree")
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
func StorageImplementationTests(t *testing.T, backend api.Backend, namespace common.Namespace, round uint64) {
	genesisTestHelpers.SetTestChainContext()

	<-backend.Initialized()

	t.Run("Basic", func(t *testing.T) {
		testBasic(t, backend, namespace, round)
	})
	t.Run("Merge", func(t *testing.T) {
		testMerge(t, backend, namespace, round)
	})
}

func testBasic(t *testing.T, backend api.Backend, namespace common.Namespace, round uint64) {
	ctx := context.Background()

	var rootHash hash.Hash
	rootHash.Empty()

	wl := prepareWriteLog(testValues)
	expectedNewRoot := CalculateExpectedNewRoot(t, wl, namespace, round)
	var receipts []*api.Receipt
	var receiptBody api.ReceiptBody
	var err error

	// Apply write log to an empty root.
	receipts, err = backend.Apply(ctx, &api.ApplyRequest{
		Namespace: namespace,
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
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// Prepare another write log and form a set of apply operations.
	wl2 := prepareWriteLog(testValues[0:2])
	expectedNewRoot2 := CalculateExpectedNewRoot(t, wl2, namespace, round)
	applyOps := []api.ApplyOp{
		api.ApplyOp{SrcRound: round, SrcRoot: rootHash, DstRoot: expectedNewRoot, WriteLog: wl},
		api.ApplyOp{SrcRound: round, SrcRoot: rootHash, DstRoot: expectedNewRoot2, WriteLog: wl2},
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
		}
	}

	newRoot := api.Root{
		Namespace: namespace,
		Round:     round,
		Hash:      receiptBody.Roots[0],
	}

	// Test individual fetches.
	t.Run("SyncGet", func(t *testing.T) {
		tree := urkel.NewWithRoot(backend, nil, newRoot)
		defer tree.Close()
		for _, entry := range wl {
			value, werr := tree.Get(ctx, entry.Key)
			require.NoError(t, werr, "Get")
			require.EqualValues(t, entry.Value, value)
		}
	})

	// Test prefetch.
	t.Run("SyncGetPrefixes", func(t *testing.T) {
		tree := urkel.NewWithRoot(backend, nil, newRoot)
		defer tree.Close()
		err = tree.PrefetchPrefixes(ctx, [][]byte{[]byte("1")}, 10)
		require.NoError(t, err, "PrefetchPrefixes")
	})

	// Test iteration.
	t.Run("SyncIterate", func(t *testing.T) {
		tree := urkel.NewWithRoot(backend, nil, newRoot)
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
		Round:     round,
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
	}

	// Test GetCheckpoint.
	logsIter, err := backend.GetCheckpoint(ctx, &api.GetCheckpointRequest{Root: newRoot})
	require.NoError(t, err, "GetCheckpoint()")
	logs := foldWriteLogIterator(t, logsIter)
	// Applying the writeLog should return same root.
	logsRootHash := CalculateExpectedNewRoot(t, logs, namespace, round)
	require.EqualValues(t, logsRootHash, receiptBody.Roots[0])

	// Single node tree.
	root.Empty()
	wl3 := prepareWriteLog([][]byte{testValues[0]})
	expectedNewRoot3 := CalculateExpectedNewRoot(t, wl3, namespace, round)

	receipts, err = backend.Apply(ctx, &api.ApplyRequest{
		Namespace: namespace,
		SrcRound:  round,
		SrcRoot:   rootHash,
		DstRound:  round,
		DstRoot:   expectedNewRoot3,
		WriteLog:  wl3,
	})
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	for i, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "mkvs receipt version should be 1")
		require.Equal(t, 1, len(receiptBody.Roots), "mkvs receipt should contain 1 root")
		require.EqualValues(t, expectedNewRoot3, receiptBody.Roots[0], "mkvs receipt root should equal the expected new root")
		if i == 0 {
			newRoot.Hash = receiptBody.Roots[0]
		}
	}

	logsIter, err = backend.GetCheckpoint(ctx, &api.GetCheckpointRequest{Root: newRoot})
	require.NoError(t, err, "GetCheckpoint()")
	logs = foldWriteLogIterator(t, logsIter)
	// Applying the writeLog should return same root.
	logsRootHash = CalculateExpectedNewRoot(t, logs, namespace, round)
	require.EqualValues(t, logsRootHash, newRoot.Hash)
}

func testMerge(t *testing.T, backend api.Backend, namespace common.Namespace, round uint64) {
	ctx := context.Background()

	writeLogs := []api.WriteLog{
		// Base root.
		api.WriteLog{
			api.LogEntry{Key: []byte("foo"), Value: []byte("i am base")},
		},
		// First root.
		api.WriteLog{
			api.LogEntry{Key: []byte("first"), Value: []byte("i am first root")},
		},
		// Second root.
		api.WriteLog{
			api.LogEntry{Key: []byte("second"), Value: []byte("i am second root")},
		},
		// Third root.
		api.WriteLog{
			api.LogEntry{Key: []byte("third"), Value: []byte("i am third root")},
		},
	}

	// Create all roots.
	var roots []hash.Hash
	for idx, writeLog := range writeLogs {
		var dstRound uint64
		var baseRoot hash.Hash
		if idx == 0 {
			baseRoot.Empty()
			dstRound = round
		} else {
			baseRoot = roots[0]
			dstRound = round + 1
		}

		// Generate expected root hash.
		tree := urkel.NewWithRoot(backend, nil, api.Root{Namespace: namespace, Round: dstRound, Hash: baseRoot})
		defer tree.Close()
		err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
		require.NoError(t, err, "ApplyWriteLog")
		var root hash.Hash
		_, root, err = tree.Commit(ctx, namespace, dstRound)
		require.NoError(t, err, "Commit")

		// Apply to storage backend.
		_, err = backend.Apply(ctx, &api.ApplyRequest{
			Namespace: namespace,
			SrcRound:  round,
			SrcRoot:   baseRoot,
			DstRound:  dstRound,
			DstRoot:   root,
			WriteLog:  writeLog,
		})
		require.NoError(t, err, "Apply")

		roots = append(roots, root)
	}

	// Try to merge with only specifying the base.
	_, err := backend.Merge(ctx, &api.MergeRequest{Namespace: namespace, Round: round, Base: roots[0]})
	require.Error(t, err, "Merge without other roots should return an error")

	// Try to merge with only specifying the base and first root.
	receipts, err := backend.Merge(ctx, &api.MergeRequest{Namespace: namespace, Round: round, Base: roots[0], Others: roots[1:2]})
	require.NoError(t, err, "Merge")
	require.NotNil(t, receipts, "Merge should return receipts")

	for _, receipt := range receipts {
		var receiptBody api.ReceiptBody
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open")
		require.Len(t, receiptBody.Roots, 1, "receipt should contain 1 root")
		require.EqualValues(t, roots[1], receiptBody.Roots[0], "merged root should be equal to the only other root")
	}

	// Try to merge with specifying the base and all three roots.
	receipts, err = backend.Merge(ctx, &api.MergeRequest{Namespace: namespace, Round: round, Base: roots[0], Others: roots[1:]})
	require.NoError(t, err, "Merge")
	require.NotNil(t, receipts, "Merge should return receipts")

	var mergedRoot hash.Hash
	for _, receipt := range receipts {
		var receiptBody api.ReceiptBody
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open")
		require.Len(t, receiptBody.Roots, 1, "receipt should contain 1 root")

		mergedRoot = receiptBody.Roots[0]
	}

	// Make sure that the merged root is the same as applying all write logs against
	// the base root.
	tree := urkel.NewWithRoot(backend, nil, api.Root{Namespace: namespace, Round: round, Hash: roots[0]})
	defer tree.Close()
	for _, writeLog := range writeLogs[1:] {
		err = tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
		require.NoError(t, err, "ApplyWriteLog")
	}
	_, expectedRoot, err := tree.Commit(ctx, namespace, round+1)
	require.NoError(t, err, "Commit")

	require.Equal(t, expectedRoot, mergedRoot, "merged root should match expected root")
}
