// Package tests is a collection of storage implementation test cases.
package tests

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/api"
)

var testValues = [][]byte{
	[]byte("Thou seest Me as Time who kills, Time who brings all to doom,"),
	[]byte("The Slayer Time, Ancient of Days, come hither to consume;"),
	[]byte("Excepting thee, of all these hosts of hostile chiefs arrayed,"),
	[]byte("There shines not one shall leave alive the battlefield!"),
}

// StorageImplementationTests exercises the basic functionality of
// a storage backend.
func StorageImplementationTests(t *testing.T, backend api.Backend) {
	<-backend.Initialized()

	// Test MKVS storage.
	var wl api.WriteLog
	for i, v := range testValues {
		wl = append(wl, api.LogEntry{Key: []byte(strconv.Itoa(i)), Value: v})
	}
	var root hash.Hash
	root.Empty()
	expectedNewRoot := [...]byte{82, 3, 202, 16, 125, 182, 175, 25, 51, 188, 131, 181, 118, 76, 249, 15, 53, 89, 59, 224, 95, 75, 239, 182, 157, 30, 80, 48, 237, 108, 90, 22}

	mkvsReceipt, err := backend.Apply(context.Background(), root, expectedNewRoot, wl)
	require.NoError(t, err, "Apply()")
	require.NotNil(t, mkvsReceipt, "mkvsReceipt")

	// Check the MKVS receipt and obtain the new root from it.
	var rb api.MKVSReceiptBody
	err = mkvsReceipt.Open(&rb)
	require.NoError(t, err, "mkvsReceipt.Open()")
	require.Equal(t, uint16(1), rb.Version, "mkvs receipt version")
	require.Equal(t, 1, len(rb.Roots), "mkvs receipt roots")
	require.NotEqual(t, root, rb.Roots[0], "mkvs receipt root")
	require.EqualValues(t, expectedNewRoot, rb.Roots[0], "mkvs receipt root")

	var emptyPath hash.Hash

	// Get a subtree summary of the new root.
	st, err := backend.GetSubtree(context.Background(), rb.Roots[0], api.NodeID{Path: emptyPath, Depth: 0}, 10)
	require.NoError(t, err, "GetSubtree()")
	require.NotNil(t, st, "subtree returned by GetSubtree()")

	// Get a path summary of the new root.
	st, err = backend.GetPath(context.Background(), rb.Roots[0], emptyPath, 0)
	require.NoError(t, err, "GetPath()")
	require.NotNil(t, st, "subtree returned by GetPath()")

	// Get the root node.
	n, err := backend.GetNode(context.Background(), rb.Roots[0], api.NodeID{Path: emptyPath, Depth: 0})
	require.NoError(t, err, "GetNode()")
	require.NotNil(t, n)

	// Now try applying the same operations again, we should get the same root.
	mkvsReceipt, err = backend.Apply(context.Background(), root, rb.Roots[0], wl)
	require.NoError(t, err, "Apply()")
	require.NotNil(t, mkvsReceipt, "mkvsReceipt")
	err = mkvsReceipt.Open(&rb)
	require.NoError(t, err, "mkvsReceipt.Open()")
	require.Equal(t, uint16(1), rb.Version, "mkvs receipt version")
	require.Equal(t, 1, len(rb.Roots), "mkvs receipt roots")
	require.NotEqual(t, root, rb.Roots[0], "mkvs receipt root")
	require.EqualValues(t, expectedNewRoot, rb.Roots[0], "mkvs receipt root")
}
