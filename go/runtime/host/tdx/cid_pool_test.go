package tdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCidPool(t *testing.T) {
	require := require.New(t)

	_, err := NewCidPool(2, 10)
	require.Error(err, "NewCidPool should fail when range includes reserved identifiers")

	_, err = NewCidPool(4294966296, 2000)
	require.Error(err, "NewCidPool should fail when range would overflow")

	_, err = NewCidPool(1000, 5000)
	require.Error(err, "NewCidPool should fail when range is too large")

	cp, err := NewCidPool(10, 90)
	require.NoError(err, "NewCidPool should work")
	cid, err := cp.Allocate()
	require.NoError(err, "Allocate")
	require.True(cid >= 10 && cid < 100)
	ok := cp.Release(cid)
	require.True(ok, "Release should return true")

	err = cp.AllocateExact(2)
	require.Error(err, "AllocateExact should fail when out of range")
	err = cp.AllocateExact(110)
	require.Error(err, "AllocateExact should fail when out of range")
	err = cp.AllocateExact(42)
	require.NoError(err, "AllocateExact should work")
	err = cp.AllocateExact(42)
	require.Error(err, "AllocateExact should fail when already allocated")
	ok = cp.Release(42)
	require.True(ok, "Release should return true")
	ok = cp.Release(42)
	require.False(ok, "Release should return false when not allocated")

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
