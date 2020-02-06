package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/quantity"
)

func TestConsensusParameters(t *testing.T) {
	require := require.New(t)

	// Default consensus parameters.
	var emptyParams ConsensusParameters
	require.Error(emptyParams.SanityCheck(), "default consensus parameters should be invalid")

	// Valid thresholds.
	validThresholds := map[ThresholdKind]quantity.Quantity{
		KindEntity:            *quantity.NewQuantity(),
		KindValidator:         *quantity.NewQuantity(),
		KindCompute:           *quantity.NewQuantity(),
		KindStorage:           *quantity.NewQuantity(),
		KindRuntimeCompute:    *quantity.NewQuantity(),
		KindRuntimeKeyManager: *quantity.NewQuantity(),
	}
	validThresholdsParams := ConsensusParameters{
		Thresholds:   validThresholds,
		FeeSplitVote: mustInitQuantity(t, 1),
	}
	require.NoError(validThresholdsParams.SanityCheck(), "consensus parameters with valid thresholds should be valid")

	// NOTE: There is currently no way to construct invalid thresholds.

	// Degenerate fee split.
	degenerateFeeSplit := ConsensusParameters{
		Thresholds:      validThresholds,
		FeeSplitVote:    mustInitQuantity(t, 0),
		FeeSplitPropose: mustInitQuantity(t, 0),
	}
	require.Error(degenerateFeeSplit.SanityCheck(), "consensus parameters with degenerate fee split should be invalid")
}
