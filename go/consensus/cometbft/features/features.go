package features

import (
	"fmt"

	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci/state"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

// IsFeatureVersion returns true iff the consensus feature version is high
// enough for the feature to be enabled.
func IsFeatureVersion(ctx *tmapi.Context, minVersion string) (bool, error) {
	// Consensus parameters.
	consState := consensusState.NewMutableState(ctx.State())
	consParams, err := consState.ConsensusParameters(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to load consensus parameters: %w", err)
	}

	return consParams.IsFeatureVersion(minVersion)
}
