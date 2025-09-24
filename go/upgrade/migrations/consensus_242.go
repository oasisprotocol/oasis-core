package migrations

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
)

// Consensus242 is the name of the upgrade that enables features introduced in Oasis Core 24.2.
//
// This upgrade includes:
//   - The `MayQuery` field in the CHURP SGX policy, which defines which enclave identities
//     are allowed to query runtime key shares.
//   - The `FMSPCWhitelist` field in the quote policy, which defines which processor packages
//     and platform instances are allowed.
//   - An updated key manager policy update transaction that applies a new policy at the epoch
//     boundary.
const Consensus242 = "consensus242"

// Version242 is the Oasis Core 24.2 version.
var Version242 = version.MustFromString("24.2")

var _ Handler = (*Handler242)(nil)

// Handler242 is the upgrade handler that transitions Oasis Core from version 24.1 to 24.2.
type Handler242 struct{}

// HasStartupUpgrade implements Handler.
func (h *Handler242) HasStartupUpgrade() bool {
	return false
}

// StartupUpgrade implements Handler.
func (h *Handler242) StartupUpgrade() error {
	return nil
}

// ConsensusUpgrade implements Handler.
func (h *Handler242) ConsensusUpgrade(privateCtx any) error {
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

		consParams.FeatureVersion = &Version242

		if err = consState.SetConsensusParameters(abciCtx, consParams); err != nil {
			return fmt.Errorf("failed to set consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(Consensus242, &Handler242{})
}
