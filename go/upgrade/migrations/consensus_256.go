package migrations

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
)

// Consensus256 is the name of the upgrade that enables features introduced up to and including
// Oasis Core 25.6.
//
// This upgrade includes:
//   - The `MayQuery“ field in the CHURP SGX policy, which defines which enclave identities
//     are allowed to query runtime key shares.
//   - An updated events root in the block metadata system transaction to capture all events
//     emitted in the block.
//   - A results hash in the block metadata system transaction.
const Consensus256 = "consensus256"

// Version256 is the Oasis Core 25.6 version.
var Version256 = version.MustFromString("25.6")

var _ Handler = (*Handler256)(nil)

// Handler256 is the upgrade handler that transitions Oasis Core from version 24.1 to 25.6.
type Handler256 struct{}

// HasStartupUpgrade implements Handler.
func (h *Handler256) HasStartupUpgrade() bool {
	return false
}

// StartupUpgrade implements Handler.
func (h *Handler256) StartupUpgrade() error {
	return nil
}

// ConsensusUpgrade implements Handler.
func (h *Handler256) ConsensusUpgrade(privateCtx any) error {
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

		consParams.FeatureVersion = &Version256

		if err = consState.SetConsensusParameters(abciCtx, consParams); err != nil {
			return fmt.Errorf("failed to set consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(Consensus256, &Handler256{})
}
