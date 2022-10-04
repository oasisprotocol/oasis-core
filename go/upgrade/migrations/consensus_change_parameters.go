package migrations

import (
	"fmt"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
)

const (
	// ChangeParametersProposalHandler is the name of the upgrade that enables change
	// parameters proposal.
	ChangeParametersProposalHandler = "change-parameters-proposal"
)

var _ Handler = (*changeParametersProposalHandler)(nil)

type changeParametersProposalHandler struct{}

func (h *changeParametersProposalHandler) StartupUpgrade(ctx *Context) error {
	return nil
}

func (h *changeParametersProposalHandler) ConsensusUpgrade(ctx *Context, privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do during begin block.
	case abciAPI.ContextEndBlock:
		// Update a consensus parameter during EndBlock.
		state := governanceState.NewMutableState(abciCtx.State())

		params, err := state.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load governance consensus parameters: %w", err)
		}

		params.EnableChangeParametersProposal = true

		if err = state.SetConsensusParameters(abciCtx, params); err != nil {
			return fmt.Errorf("failed to update governance consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(ChangeParametersProposalHandler, &changeParametersProposalHandler{})
}
