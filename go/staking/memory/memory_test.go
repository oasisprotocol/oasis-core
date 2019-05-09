package memory

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/staking/tests"
)

func TestStakingMemory(t *testing.T) {
	genesisState, err := api.NewGenesis(tests.InitialBalancesArg)
	require.NoError(t, err, "NewGenesis")

	backend, err := New(genesisState)
	require.NoError(t, err, "New")

	tests.StakingImplementationTests(t, backend)
}
