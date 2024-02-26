package migrations

import (
	"fmt"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
)

const (
	// Consensus241 is the name of the upgrade that transitions Oasis Core
	// from version 24.0.x to 24.1.0.
	//
	// This upgrade removes the code previously necessary to enable the key
	// manager CHURP extension.
	Consensus241 = "consensus241"
)

var _ Handler = (*Handler241)(nil)

// Handler241 is the upgrade handler that transitions Oasis Core
// from version 24.0.x to 24.1.0.
type Handler241 struct{}

// StartupUpgrade implements Handler.
func (h *Handler241) StartupUpgrade() error {
	return nil
}

// ConsensusUpgrade implements Handler.
func (h *Handler241) ConsensusUpgrade(privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do.
	case abciAPI.ContextEndBlock:
		// Registry.
		regState := registryState.NewMutableState(abciCtx.State())

		regParams, err := regState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("failed to load registry consensus parameters: %w", err)
		}
		regParams.DeprecatedEnableKeyManagerCHURP = false // nolint: staticcheck

		if err = regState.SetConsensusParameters(abciCtx, regParams); err != nil {
			return fmt.Errorf("failed to update registry consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(Consensus241, &Handler241{})
}
