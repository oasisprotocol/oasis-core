package registry

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

// QuotePolicyProvider is a provider backed by the latest runtime descriptors on
// the consensus layer.
type QuotePolicyProvider struct {
	Consensus consensus.Service
	// UseKMAPolicy specifies whether to use keymanager access policy when one exists.
	UseKMAPolicy bool
}

func (p *QuotePolicyProvider) Get(
	ctx context.Context,
	runtimeID common.Namespace,
	compID component.ID,
	version version.Version,
) (*quote.Policy, error) {
	if !compID.IsRONL() { // ROFL components have no policy on the consensus.
		return nil, nil
	}

	rt, err := p.Consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height:           consensus.HeightLatest,
		ID:               runtimeID,
		IncludeSuspended: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query runtime descriptor: %w", err)
	}
	if d := rt.DeploymentForVersion(version); d != nil {
		var sc node.SGXConstraints
		if err = cbor.Unmarshal(d.TEE, &sc); err != nil {
			return nil, fmt.Errorf("malformed runtime SGX constraints: %w", err)
		}
		return sc.ResolvePolicy(p.UseKMAPolicy), nil
	}
	return nil, nil
}
