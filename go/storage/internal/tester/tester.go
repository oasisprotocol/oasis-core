// Package tester is a collection of storage implementation test cases.
package tester

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
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

// StorageImplementationTest exercises the basic functionality of
// a storage backend.
func StorageImplementationTest(t *testing.T, backend storage.Backend, timeSource epochtime.SetableBackend) {
	<-backend.Initialized()

	var hashes []storage.Key
	for _, v := range testValues {
		hashes = append(hashes, storage.HashStorageKey(v))
	}

	epoch, _, _ := timeSource.GetEpoch(context.Background())

	for i, v := range testValues {
		err := backend.Insert(context.Background(), v, 1)
		require.NoError(t, err, "Insert(%d)", i)
	}

	for i, h := range hashes {
		v, err := backend.Get(context.Background(), h)
		require.NoError(t, err, "Get(%d)", i)
		require.EqualValues(t, testValues[i], v, "Get(%d)", i)
	}

	var batchHashes []storage.Key
	var batchValues []storage.Value
	for _, v := range testValuesBatch {
		batchHashes = append(batchHashes, storage.HashStorageKey(v))
		batchValues = append(batchValues, storage.Value{Data: v, Expiration: 1})
	}

	err := backend.InsertBatch(context.Background(), batchValues)
	require.NoError(t, err, "InsertBatch(testValuesBatch)")

	v, err := backend.GetBatch(context.Background(), hashes)
	require.NoError(t, err, "GetBatch(hashes)")
	require.EqualValues(t, testValues, v, "GetBatch(hashes)")

	v, err = backend.GetBatch(context.Background(), batchHashes)
	require.NoError(t, err, "GetBatch(batchHashes)")
	require.EqualValues(t, testValuesBatch, v, "GetBatch(batchHashes)")

	var missingKey storage.Key
	copy(missingKey[:], []byte("00000000000000000000000000000000"))

	v, err = backend.GetBatch(
		context.Background(),
		[]storage.Key{
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

	seenKeys := make(map[storage.Key]bool)
	keyInfos, err := backend.GetKeys(context.Background())
	require.NoError(t, err, "GetKeys()")
	for i, ki := range keyInfos {
		seenKeys[ki.Key] = true
		require.Equal(t, epochtime.EpochTime(1), ki.Expiration, "KeyInfo[%d]: Expiration", i)
	}
	for i, h := range hashes {
		require.True(t, seenKeys[h], "KeyInfo[%d]: Key", i)
	}

	_ = timeSource.SetEpoch(context.Background(), epoch+2, 0)
	time.Sleep(1 * time.Second) // Wait for the sweeper to purge keys.

	keyInfos, err = backend.GetKeys(context.Background())
	require.NoError(t, err, "GetKeys(), after epoch advance")
	require.Empty(t, keyInfos, "GetKeys(), after epoch advance")

	for i, h := range hashes {
		v, err := backend.Get(context.Background(), h)
		require.Error(t, err, "Get(%d)", i)
		require.Nil(t, v, "Get(%d), i")
	}
}
