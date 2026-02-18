package keymanager

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
)

type quotePolicyProvider struct {
	cs        consensus.Service
	runtimeID common.Namespace
	version   version.Version
}

// Get implements host.QuotePolicyProvider.
func (p *quotePolicyProvider) Get(ctx context.Context) (*quote.Policy, error) {
	rt, err := p.cs.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height:           consensus.HeightLatest,
		ID:               p.runtimeID,
		IncludeSuspended: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query runtime descriptor: %w", err)
	}
	if d := rt.DeploymentForVersion(p.version); d != nil {
		var sc node.SGXConstraints
		if err = cbor.Unmarshal(d.TEE, &sc); err != nil {
			return nil, fmt.Errorf("malformed runtime SGX constraints: %w", err)
		}
		return sc.Policy, nil
	}
	return nil, nil
}
