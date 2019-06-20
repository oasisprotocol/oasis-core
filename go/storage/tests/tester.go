// Package tests is a collection of storage implementation test cases.
package tests

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
)

var testValues = [][]byte{
	[]byte("Thou seest Me as Time who kills, Time who brings all to doom,"),
	[]byte("The Slayer Time, Ancient of Days, come hither to consume;"),
	[]byte("Excepting thee, of all these hosts of hostile chiefs arrayed,"),
	[]byte("There shines not one shall leave alive the battlefield!"),
}

func prepareWriteLog(values [][]byte) api.WriteLog {
	var wl api.WriteLog
	for i, v := range testValues {
		wl = append(wl, api.LogEntry{Key: []byte(strconv.Itoa(i)), Value: v})
	}
	return wl
}

func CalculateExpectedNewRoot(t *testing.T, wl api.WriteLog) hash.Hash {
	// Use in-memory Urkel tree to calculate the expected new root.
	tree := urkel.New(nil, nil)
	for _, logEntry := range wl {
		err := tree.Insert(context.Background(), logEntry.Key, logEntry.Value)
		require.NoError(t, err, "error inserting writeLog entry into Urkel tree")
	}
	_, expectedNewRoot, err := tree.Commit(context.Background())
	require.NoError(t, err, "error calculating mkvs' expectedNewRoot")
	return expectedNewRoot
}

// StorageImplementationTests exercises the basic functionality of a storage
// backend.
func StorageImplementationTests(t *testing.T, backend api.Backend) {
	<-backend.Initialized()

	// Test MKVS storage.
	var root hash.Hash
	root.Empty()
	wl := prepareWriteLog(testValues)
	expectedNewRoot := CalculateExpectedNewRoot(t, wl)
	var receipts []*api.MKVSReceipt
	var receiptBody api.MKVSReceiptBody
	var err error

	// Apply write log to an empty root.
	receipts, err = backend.Apply(context.Background(), root, expectedNewRoot, wl)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// Prepare another write log and form a set of apply operations.
	wl2 := prepareWriteLog(testValues[0:2])
	expectedNewRoot2 := CalculateExpectedNewRoot(t, wl2)
	applyOps := []api.ApplyOp{
		api.ApplyOp{Root: root, ExpectedNewRoot: expectedNewRoot, WriteLog: wl},
		api.ApplyOp{Root: root, ExpectedNewRoot: expectedNewRoot2, WriteLog: wl2},
	}

	// Apply a batch of operations against the MKVS.
	receipts, err = backend.ApplyBatch(context.Background(), applyOps)
	require.NoError(t, err, "ApplyBatch() should not return an error")
	require.NotNil(t, receipts, "ApplyBatch() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, len(applyOps), len(receiptBody.Roots), "receiptBody should contain as many roots as there were applyOps")
		for i, applyOp := range applyOps {
			require.EqualValues(t, applyOp.ExpectedNewRoot, receiptBody.Roots[i], "receiptBody root for an applyOp should equal the expected new root")
		}
	}

	var emptyPath hash.Hash

	// Get a subtree summary of the new root.
	st, err := backend.GetSubtree(context.Background(), receiptBody.Roots[0], api.NodeID{Path: emptyPath, Depth: 0}, 10)
	require.NoError(t, err, "GetSubtree()")
	require.NotNil(t, st, "subtree returned by GetSubtree()")

	// Get a path summary of the new root.
	st, err = backend.GetPath(context.Background(), receiptBody.Roots[0], emptyPath, 0)
	require.NoError(t, err, "GetPath()")
	require.NotNil(t, st, "subtree returned by GetPath()")

	// Get the root node.
	n, err := backend.GetNode(context.Background(), receiptBody.Roots[0], api.NodeID{Path: emptyPath, Depth: 0})
	require.NoError(t, err, "GetNode()")
	require.NotNil(t, n)

	// Get the value using its hash.
	origValue := testValues[2]
	var hash hash.Hash
	hash.FromBytes(origValue)
	value, err := backend.GetValue(context.Background(), receiptBody.Roots[0], hash)
	require.NoError(t, err, "GetValue() should not return an error")
	require.NotNil(t, value, "GetValue() should return a value")
	require.Equal(t, value, origValue, "GetValue()'s returned value should equal the original value")

	// Now try applying the same operations again, we should get the same root.
	receipts, err = backend.Apply(context.Background(), root, receiptBody.Roots[0], wl)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, uint16(1), receiptBody.Version, "receiptBody version should be 1")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}
}
