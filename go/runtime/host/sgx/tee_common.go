package sgx

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

type teeStateImplCommon struct {
	runtimeID common.Namespace
	version   version.Version
}

// getQuotePolicies gets the current quote policies from the consensus layer.
func (tsc *teeStateImplCommon) getQuotePolicies(ctx context.Context, sp *sgxProvisioner) (*sgxQuote.Policy, error) {
	rt, err := sp.consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height:           consensus.HeightLatest,
		ID:               tsc.runtimeID,
		IncludeSuspended: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query runtime descriptor: %w", err)
	}
	if d := rt.DeploymentForVersion(tsc.version); d != nil {
		var sc node.SGXConstraints
		if err = cbor.Unmarshal(d.TEE, &sc); err != nil {
			return nil, fmt.Errorf("malformed runtime SGX constraints: %w", err)
		}

		return sc.Policy, nil
	}
	return nil, nil
}
