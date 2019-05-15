// Package tests is a collection of storage implementation test cases.
package tests

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	"github.com/oasislabs/ekiden/go/storage/api"
)

var testValues = [][]byte{
	[]byte("Thou seest Me as Time who kills, Time who brings all to doom,"),
	[]byte("The Slayer Time, Ancient of Days, come hither to consume;"),
	[]byte("Excepting thee, of all these hosts of hostile chiefs arrayed,"),
	[]byte("There shines not one shall leave alive the battlefield!"),
}

var testValuesBatch = [][]byte{
	[]byte("No longer be! Arise! obtain renown! destroy thy foes!"),
	[]byte("Fight for the kingdom waiting thee when thou hast vanquished those."),
	[]byte("By Me they fall- not thee! the stroke of death is dealt them now,"),
	[]byte("Even as they show thus gallantly; My instrument art thou!"),
}

// StorageImplementationTests exercises the basic functionality of
// a storage backend.
func StorageImplementationTests(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend, expiry bool) {
	<-backend.Initialized()

	var hashes []api.Key
	for _, v := range testValues {
		hashes = append(hashes, api.HashStorageKey(v))
	}

	for i, v := range testValues {
		err := backend.Insert(context.Background(), v, 1, api.InsertOptions{})
		require.NoError(t, err, "Insert(%d)", i)
	}

	for i, h := range hashes {
		v, err := backend.Get(context.Background(), h)
		require.NoError(t, err, "Get(%d)", i)
		require.EqualValues(t, testValues[i], v, "Get(%d)", i)
	}

	var batchHashes []api.Key
	var batchValues []api.Value
	for _, v := range testValuesBatch {
		batchHashes = append(batchHashes, api.HashStorageKey(v))
		batchValues = append(batchValues, api.Value{Data: v, Expiration: 1})
	}

	err := backend.InsertBatch(context.Background(), batchValues, api.InsertOptions{})
	require.NoError(t, err, "InsertBatch(testValuesBatch)")

	v, err := backend.GetBatch(context.Background(), hashes)
	require.NoError(t, err, "GetBatch(hashes)")
	require.EqualValues(t, testValues, v, "GetBatch(hashes)")

	v, err = backend.GetBatch(context.Background(), batchHashes)
	require.NoError(t, err, "GetBatch(batchHashes)")
	require.EqualValues(t, testValuesBatch, v, "GetBatch(batchHashes)")

	var missingKey api.Key
	copy(missingKey[:], []byte("00000000000000000000000000000000"))

	v, err = backend.GetBatch(
		context.Background(),
		[]api.Key{
			hashes[0],
			missingKey,
			hashes[1],
		},
	)
	require.NoError(t, err, "GetBatch(missing key)")
	require.EqualValues(t, [][]byte{
		testValues[0],
		nil,
		testValues[1],
	}, v, "GetBatch(missing key)")

	if expiry {
		seenKeys := make(map[api.Key]bool)
		keyInfos, errr := backend.GetKeys(context.Background())
		require.NoError(t, errr, "GetKeys()")
		i := 0
		for ki := range keyInfos {
			seenKeys[ki.Key] = true
			require.Equal(t, epochtime.EpochTime(1), ki.Expiration, "KeyInfo[%d]: Expiration", i)
			i++
		}
		for i, h := range hashes {
			require.True(t, seenKeys[h], "KeyInfo[%d]: Key", i)
		}

		epochtimeTests.MustAdvanceEpoch(t, timeSource, 2)
		time.Sleep(1 * time.Second) // Wait for the sweeper to purge keys.

		keyInfos, errr = backend.GetKeys(context.Background())
		require.NoError(t, errr, "GetKeys(), after epoch advance")
		require.Empty(t, keyInfos, "GetKeys(), after epoch advance")

		for i, h := range hashes {
			v, errrr := backend.Get(context.Background(), h)
			require.Error(t, errrr, "Get(%d)", i)
			require.Nil(t, v, "Get(%d), i")
		}
	}

	// Test MKVS storage as well -- start by inserting test values.
	var wl api.WriteLog
	for i, v := range testValues {
		wl = append(wl, api.LogEntry{Key: []byte(strconv.Itoa(i)), Value: v})
	}
	var root hash.Hash
	root.Empty()
	expectedNewRoot := [...]byte{0x3a, 0x6f, 0xc8, 0x7f, 0x1b, 0x49, 0x97, 0xd4, 0x6e, 0x47, 0x69, 0x93, 0x24, 0x80, 0xb0, 0xa1, 0x97, 0xae, 0x95, 0x8a, 0x5c, 0xd4, 0x8b, 0x9c, 0xf, 0xc2, 0x86, 0xa3, 0xf3, 0xeb, 0x9b, 0xbf}

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

	var emptyPath = api.MKVSKey{}

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
