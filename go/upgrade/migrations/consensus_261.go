package migrations

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
)

// Consensus261 is the name of the upgrade that enables features introduced in Oasis Core 26.1.
//
// This upgrade includes:
//   - The `MayQuery` field in the CHURP SGX policy, which defines which enclave identities
//     are allowed to query runtime key shares.
//   - The `FMSPCWhitelist` field in the quote policy, which defines which processor packages
//     and platform instances are allowed.
//   - The `KeyManagerAccessPolicy` field in the `SGXConstraints`, which defines additional
//     policy that may overwrite the default policy when verifying TEE attestations for nodes
//     that can access the key manager.
//   - An updated key manager policy update transaction that applies a new policy at the epoch
//     boundary.
//   - A stricter node registration rule where observer nodes must include runtimes.
//   - Removal of previous runtime owner on runtime update.
const Consensus261 = "consensus261"

// Version261 is the Oasis Core 26.1 version.
var Version261 = version.MustFromString("26.1")

var _ Handler = (*Handler261)(nil)

// Handler261 is the upgrade handler that transitions Oasis Core to feature version 26.1.
type Handler261 struct{}

// HasStartupUpgrade implements Handler.
func (h *Handler261) HasStartupUpgrade() bool {
	return false
}

// StartupUpgrade implements Handler.
func (h *Handler261) StartupUpgrade() error {
	return nil
}

// ConsensusUpgrade implements Handler.
func (h *Handler261) ConsensusUpgrade(privateCtx any) error {
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

		consParams.FeatureVersion = &Version261

		if err = consState.SetConsensusParameters(abciCtx, consParams); err != nil {
			return fmt.Errorf("failed to set consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(Consensus261, &Handler261{})
}
