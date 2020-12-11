package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiff(t *testing.T) {
	require := require.New(t)

	for _, tc := range []struct {
		e1   EpochTime
		e2   EpochTime
		diff EpochTime
	}{
		{
			e1:   100,
			e2:   200,
			diff: 100,
		},
		{
			e1:   100,
			e2:   100,
			diff: 0,
		},
		{
			e1:   200,
			e2:   100,
			diff: 100,
		},
	} {
		require.Equal(tc.e1.AbsDiff(tc.e2), tc.diff)
	}
}
