package migrations

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// ConsensusParamsUpdate202108 is the name of the "consensus-params-update-2021-08"
	// upgrade handler.
	ConsensusParamsUpdate202108 = "consensus-params-update-2021-08"
)

var _ Handler = (*consensusParameters202108Handler)(nil)

type consensusParameters202108Handler struct{}

func (th *consensusParameters202108Handler) StartupUpgrade(ctx *Context) error {
	return nil
}

func (th *consensusParameters202108Handler) ConsensusUpgrade(ctx *Context, privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do during begin block.
	case abciAPI.ContextEndBlock:
		// Update consensus parameters during EndBlock.

		stakingState := stakingState.NewMutableState(abciCtx.State())
		stakingParams, err := stakingState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load staking consensus parameters: %w", err)
		}

		governanceState := governanceState.NewMutableState(abciCtx.State())
		governanceParams, err := governanceState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load governance consensus parameters: %w", err)
		}

		roothashState := roothashState.NewMutableState(abciCtx.State())
		roothashParams, err := roothashState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load roothash consensus parameters: %w", err)
		}

		schedulerState := schedulerState.NewMutableState(abciCtx.State())
		schedulerParams, err := schedulerState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load scheduler consensus parameters: %w", err)
		}

		// Staking consensus parameters.
		// Set MaxAllowances to 16.
		stakingParams.MaxAllowances = 16
		// Gas costs.
		if stakingParams.GasCosts == nil {
			stakingParams.GasCosts = make(transaction.Costs)
		}
		stakingParams.GasCosts[stakingAPI.GasOpAmendCommissionSchedule] = 1000
		stakingParams.GasCosts[stakingAPI.GasOpAllow] = 1000
		stakingParams.GasCosts[stakingAPI.GasOpWithdraw] = 1000

		// Governance consensus parameters.
		// Gas costs.
		if governanceParams.GasCosts == nil {
			governanceParams.GasCosts = make(transaction.Costs)
		}
		governanceParams.GasCosts[governanceAPI.GasOpCastVote] = 1000
		governanceParams.GasCosts[governanceAPI.GasOpSubmitProposal] = 1000

		// Roothash consensus parameters.
		// Gas costs.
		if roothashParams.GasCosts == nil {
			roothashParams.GasCosts = make(transaction.Costs)
		}
		roothashParams.GasCosts[roothashAPI.GasOpEvidence] = 5000
		roothashParams.GasCosts[roothashAPI.GasOpProposerTimeout] = 5000

		// Scheduler consensus parameters.
		// Max validators.
		schedulerParams.MaxValidators = 110

		if err = stakingState.SetConsensusParameters(abciCtx, stakingParams); err != nil {
			return fmt.Errorf("failed to update staking consensus parameters: %w", err)
		}
		if err = governanceState.SetConsensusParameters(abciCtx, governanceParams); err != nil {
			return fmt.Errorf("failed to update governance consensus parameters: %w", err)
		}
		if err = roothashState.SetConsensusParameters(abciCtx, roothashParams); err != nil {
			return fmt.Errorf("failed to update roothash consensus parameters: %w", err)
		}
		if err = schedulerState.SetConsensusParameters(abciCtx, schedulerParams); err != nil {
			return fmt.Errorf("failed to update scheduler consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(ConsensusParamsUpdate202108, &consensusParameters202108Handler{})
}
