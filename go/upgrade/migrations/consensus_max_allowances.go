package migrations

import (
	"fmt"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
)

const (
	// ConsensusMaxAllowances16Handler is the name of the upgrade that sets the
	// staking max allowances consensus parameter to 16.
	ConsensusMaxAllowances16Handler = "consensus-max-allowances-16"
)

var _ Handler = (*maxAllowances16Handler)(nil)

type maxAllowances16Handler struct{}

func (th *maxAllowances16Handler) StartupUpgrade(ctx *Context) error {
	return nil
}

func (th *maxAllowances16Handler) ConsensusUpgrade(ctx *Context, privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do during begin block.
	case abciAPI.ContextEndBlock:
		// Update a consensus parameter during EndBlock.
		state := stakingState.NewMutableState(abciCtx.State())

		params, err := state.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load staking consensus parameters: %w", err)
		}

		params.MaxAllowances = 16

		if err = state.SetConsensusParameters(abciCtx, params); err != nil {
			return fmt.Errorf("failed to update staking consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(ConsensusMaxAllowances16Handler, &maxAllowances16Handler{})
}
