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

func CalculateExpectedNewRoot(t *testing.T, wl api.WriteLog, namespace common.Namespace) hash.Hash {
	// Use in-memory Urkel tree to calculate the expected new root.
	tree := urkel.New(nil, nil)
	for _, logEntry := range wl {
		err := tree.Insert(context.Background(), logEntry.Key, logEntry.Value)
		require.NoError(t, err, "error inserting writeLog entry into Urkel tree")
	}
	_, expectedNewRoot, err := tree.Commit(context.Background(), namespace, 0)
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

	// Test MKVS storage.
	var rootHash hash.Hash
	rootHash.Empty()

	wl := prepareWriteLog(testValues)
	expectedNewRoot := CalculateExpectedNewRoot(t, wl, namespace)
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
	expectedNewRoot2 := CalculateExpectedNewRoot(t, wl2, namespace)
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
	st, err = backend.GetPath(context.Background(), newRoot, emptyPath, 0)
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
	logsRootHash := CalculateExpectedNewRoot(t, logs, namespace)
	require.EqualValues(t, logsRootHash, receiptBody.Roots[0])

	// Single node tree.
	root.Empty()
	wl3 := prepareWriteLog([][]byte{testValues[0]})
	expectedNewRoot3 := CalculateExpectedNewRoot(t, wl3, namespace)

	receipts, err = backend.Apply(context.Background(), namespace, 0, rootHash, 1, expectedNewRoot3, wl3)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return a receipts")

	for i, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipts.Open() should not return an error")
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
	logsRootHash = CalculateExpectedNewRoot(t, logs, namespace)
	require.EqualValues(t, logsRootHash, newRoot.Hash)
}
