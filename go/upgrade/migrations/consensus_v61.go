package migrations

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	// ConsensusV61 is the name of the upgrade that enables multiple features added in Oasis Core
	// version 22.2.x, specifically PCS support for Intel SGX, remote attestation binding to node
	// identities and client freshness proofs.
	ConsensusV61 = "consensus-v61"
)

var _ Handler = (*v61Handler)(nil)

type v61Handler struct{}

func (th *v61Handler) StartupUpgrade(ctx *Context) error {
	return nil
}

func (th *v61Handler) ConsensusUpgrade(ctx *Context, privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do during begin block.
	case abciAPI.ContextEndBlock:
		// Update a consensus parameters during EndBlock.

		// Registry.
		regState := registryState.NewMutableState(abciCtx.State())

		regParams, err := regState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load registry consensus parameters: %w", err)
		}

		regParams.TEEFeatures = &node.TEEFeatures{
			SGX: node.TEEFeaturesSGX{
				PCS:                      true,
				SignedAttestations:       true,
				DefaultMaxAttestationAge: 1200, // ~2 hours at 6 sec per block.
			},
			FreshnessProofs: true,
		}

		// Configure the default gas cost for freshness proofs.
		regParams.GasCosts[registry.GasOpProveFreshness] = registry.DefaultGasCosts[registry.GasOpProveFreshness]

		if err = regState.SetConsensusParameters(abciCtx, regParams); err != nil {
			return fmt.Errorf("failed to update registry consensus parameters: %w", err)
		}

		// Governance.
		govState := governanceState.NewMutableState(abciCtx.State())

		govParams, err := govState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load governance consensus parameters: %w", err)
		}

		govParams.EnableChangeParametersProposal = true

		if err = govState.SetConsensusParameters(abciCtx, govParams); err != nil {
			return fmt.Errorf("failed to update governance consensus parameters: %w", err)
		}
	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(ConsensusV61, &v61Handler{})
}
