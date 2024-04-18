package migrations

import (
	"fmt"

	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci/state"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/state"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

const (
	// Consensus240 is the name of the upgrade that enables features introduced in Oasis Core 24.0.
	//
	// This upgrade enables the key manager CHURP extension and updates the MaxTxSize/MaxBlockSize
	// in order to accommodate larger node registrations.
	Consensus240 = "consensus240"
)

var _ Handler = (*Handler240)(nil)

// Handler240 is the upgrade handler that transitions Oasis Core
// from version 23.0.x to 24.0.0.
type Handler240 struct{}

// StartupUpgrade implements Handler.
func (h *Handler240) StartupUpgrade() error {
	return nil
}

// ConsensusUpgrade implements Handler.
func (h *Handler240) ConsensusUpgrade(privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do.
	case abciAPI.ContextEndBlock:
		// Consensus parameters.
		consState := consensusState.NewMutableState(abciCtx.State())

		consParams, err := consState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("failed to load consensus parameters: %w", err)
		}
		consParams.MaxTxSize = 131072     // 32 KiB -> 128 KiB
		consParams.MaxBlockSize = 4194304 // 1 MiB  -> 4 MiB

		if err = consState.SetConsensusParameters(abciCtx, consParams); err != nil {
			return fmt.Errorf("failed to set consensus parameters: %w", err)
		}

		// Registry.
		regState := registryState.NewMutableState(abciCtx.State())

		regParams, err := regState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("failed to load registry consensus parameters: %w", err)
		}
		regParams.EnableKeyManagerCHURP = true

		if err = regState.SetConsensusParameters(abciCtx, regParams); err != nil {
			return fmt.Errorf("failed to update registry consensus parameters: %w", err)
		}

		// CHURP.
		state := churpState.NewMutableState(abciCtx.State())

		if err = state.SetConsensusParameters(abciCtx, &churp.DefaultConsensusParameters); err != nil {
			return fmt.Errorf("failed to set CHURP consensus parameters: %w", err)
		}

		// Governance.
		govState := governanceState.NewMutableState(abciCtx.State())

		govParams, err := govState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("failed to load governance consensus parameters: %w", err)
		}
		govParams.AllowVoteWithoutEntity = true

		if err = govState.SetConsensusParameters(abciCtx, govParams); err != nil {
			return fmt.Errorf("failed to update governance consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(Consensus240, &Handler240{})
}
