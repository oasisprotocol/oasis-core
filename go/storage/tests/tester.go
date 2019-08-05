// Package tests is a collection of storage implementation test cases.
package tests

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
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
func StorageImplementationTests(t *testing.T, backend api.Backend, namespace common.Namespace) {
	<-backend.Initialized()

	t.Run("Basic", func(t *testing.T) {
		testBasic(t, backend, namespace)
	})
	t.Run("Merge", func(t *testing.T) {
		testMerge(t, backend, namespace)
	})
}

func testBasic(t *testing.T, backend api.Backend, namespace common.Namespace) {
	var rootHash hash.Hash
	rootHash.Empty()

	wl := prepareWriteLog(testValues)
	expectedNewRoot := CalculateExpectedNewRoot(t, wl, namespace, 1)
	var receipts []*api.Receipt
	var receiptBody api.ReceiptBody
	var err error

	// Apply write log to an empty root.
	receipts, err = backend.Apply(context.Background(), namespace, 0, rootHash, 1, expectedNewRoot, wl)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, namespace, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, 1, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// Prepare another write log and form a set of apply operations.
	wl2 := prepareWriteLog(testValues[0:2])
	expectedNewRoot2 := CalculateExpectedNewRoot(t, wl2, namespace, 1)
	applyOps := []api.ApplyOp{
		api.ApplyOp{SrcRound: 0, SrcRoot: rootHash, DstRoot: expectedNewRoot, WriteLog: wl},
		api.ApplyOp{SrcRound: 0, SrcRoot: rootHash, DstRoot: expectedNewRoot2, WriteLog: wl2},
	}

	// Apply a batch of operations against the MKVS.
	receipts, err = backend.ApplyBatch(context.Background(), namespace, 1, applyOps)
	require.NoError(t, err, "ApplyBatch() should not return an error")
	require.NotNil(t, receipts, "ApplyBatch() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, namespace, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, 1, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, len(applyOps), len(receiptBody.Roots), "receiptBody should contain as many roots as there were applyOps")
		for i, applyOp := range applyOps {
			require.EqualValues(t, applyOp.DstRoot, receiptBody.Roots[i], "receiptBody root for an applyOp should equal the expected new root")
		}
	}

	emptyPath := api.Key{}

	newRoot := api.Root{
		Namespace: namespace,
		Round:     1,
		Hash:      receiptBody.Roots[0],
	}

	// Get a subtree summary of the new root.
	st, err := backend.GetSubtree(context.Background(), newRoot, api.NodeID{Path: emptyPath, BitDepth: 0}, 10)
	require.NoError(t, err, "GetSubtree()")
	require.NotNil(t, st, "subtree returned by GetSubtree()")

	// Get a path summary of the new root.
	st, err = backend.GetPath(context.Background(), newRoot, api.NodeID{Path: emptyPath, BitDepth: 0}, emptyPath)
	require.NoError(t, err, "GetPath()")
	require.NotNil(t, st, "subtree returned by GetPath()")

	// Get the root node.
	n, err := backend.GetNode(context.Background(), newRoot, api.NodeID{Path: emptyPath, BitDepth: 0})
	require.NoError(t, err, "GetNode()")
	require.NotNil(t, n)

	// Get the write log, it should be the same as what we stuffed in.
	root := api.Root{
		Namespace: namespace,
		Round:     0,
		Hash:      rootHash,
	}
	it, err := backend.GetDiff(context.Background(), root, newRoot)
	require.NoError(t, err, "GetDiff()")
	getDiffWl := foldWriteLogIterator(t, it)
	originalWl := make(api.WriteLog, len(wl))
	copy(originalWl, wl)
	sort.Slice(originalWl, makeWriteLogLess(originalWl))
	sort.Slice(getDiffWl, makeWriteLogLess(getDiffWl))
	require.Equal(t, getDiffWl, originalWl)

	// Now try applying the same operations again, we should get the same root.
	receipts, err = backend.Apply(context.Background(), namespace, 0, rootHash, 1, receiptBody.Roots[0], wl)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, namespace, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, 1, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// Test GetCheckpoint.
	logsIter, err := backend.GetCheckpoint(context.Background(), newRoot)
	require.NoError(t, err, "GetCheckpoint()")
	logs := foldWriteLogIterator(t, logsIter)
	// Applying the writeLog should return same root.
	logsRootHash := CalculateExpectedNewRoot(t, logs, namespace, 1)
	require.EqualValues(t, logsRootHash, receiptBody.Roots[0])

	// Single node tree.
	root.Empty()
	wl3 := prepareWriteLog([][]byte{testValues[0]})
	expectedNewRoot3 := CalculateExpectedNewRoot(t, wl3, namespace, 1)

	receipts, err = backend.Apply(context.Background(), namespace, 0, rootHash, 1, expectedNewRoot3, wl3)
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

	logsIter, err = backend.GetCheckpoint(context.Background(), newRoot)
	require.NoError(t, err, "GetCheckpoint()")
	logs = foldWriteLogIterator(t, logsIter)
	// Applying the writeLog should return same root.
	logsRootHash = CalculateExpectedNewRoot(t, logs, namespace, 1)
	require.EqualValues(t, logsRootHash, newRoot.Hash)
}

func testMerge(t *testing.T, backend api.Backend, namespace common.Namespace) {
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
		var round uint64
		var baseRoot hash.Hash
		if idx == 0 {
			baseRoot.Empty()
			round = 1
		} else {
			baseRoot = roots[0]
			round = 2
		}

		// Generate expected root hash.
		tree, err := urkel.NewWithRoot(ctx, backend, nil, api.Root{Namespace: namespace, Round: round, Hash: baseRoot})
		require.NoError(t, err, "NewWithRoot")
		err = tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
		require.NoError(t, err, "ApplyWriteLog")
		var root hash.Hash
		_, root, err = tree.Commit(ctx, namespace, round)
		require.NoError(t, err, "Commit")

		// Apply to storage backend.
		_, err = backend.Apply(ctx, namespace, 1, baseRoot, round, root, writeLog)
		require.NoError(t, err, "Apply")

		roots = append(roots, root)
	}

	// Try to merge with only specifying the base.
	_, err := backend.Merge(ctx, namespace, 1, roots[0], nil)
	require.Error(t, err, "Merge without other roots should return an error")

	// Try to merge with only specifying the base and first root.
	receipts, err := backend.Merge(ctx, namespace, 1, roots[0], roots[1:2])
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
	receipts, err = backend.Merge(ctx, namespace, 1, roots[0], roots[1:])
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
	var tree *urkel.Tree
	tree, err = urkel.NewWithRoot(ctx, backend, nil, api.Root{Namespace: namespace, Round: 1, Hash: roots[0]})
	require.NoError(t, err, "NewWithRoot")
	for _, writeLog := range writeLogs[1:] {
		err = tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
		require.NoError(t, err, "ApplyWriteLog")
	}
	_, expectedRoot, err := tree.Commit(ctx, namespace, 2)
	require.NoError(t, err, "Commit")

	require.Equal(t, expectedRoot, mergedRoot, "merged root should match expected root")
}
