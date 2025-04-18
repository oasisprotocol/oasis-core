package tdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCidPool(t *testing.T) {
	require := require.New(t)

	_, err := NewCidPool(2, 10)
	require.Error(err, "NewCidPool should fail when range includes reserved identifiers")

	cp, err := NewCidPool(10, 90)
	require.NoError(err, "NewCidPool should work")
	cid, err := cp.Allocate()
	require.NoError(err, "Allocate")
	require.True(cid >= 10 && cid < 100)
	cp.Release(cid)

	cids := make([]uint32, 0, 90)
	for range 90 {
		cid, err = cp.Allocate()
		require.NoError(err, "Allocate")
		cids = append(cids, cid)
	}

	_, err = cp.Allocate()
	require.Error(err, "Allocate should fail when pool depleated")

	for _, cid := range cids {
		cp.Release(cid)
	}

	_, err = cp.Allocate()
	require.NoError(err, "Allocate")
}
