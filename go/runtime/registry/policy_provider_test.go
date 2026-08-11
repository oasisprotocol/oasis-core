package registry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

// mockRegistry implements the part of registry.Backend used by the provider.
// The embedded interface is nil, so any other method panics.
type mockRegistry struct {
	registry.Backend

	rt *registry.Runtime
}

func (m *mockRegistry) GetRuntime(context.Context, *registry.GetRuntimeQuery) (*registry.Runtime, error) {
	return m.rt, nil
}

// mockConsensus implements the part of consensus.Service used by the provider.
// The embedded interface is nil, so any other method panics.
type mockConsensus struct {
	consensus.Service

	registry registry.Backend
}

func (m *mockConsensus) Registry() registry.Backend {
	return m.registry
}

func TestConsensusQuotePolicyProvider(t *testing.T) {
	rtVersion := version.Version{Major: 1}
	policy := &quote.Policy{
		PCS: &pcs.QuotePolicy{TCBValidityPeriod: 30},
	}

	constraints := node.SGXConstraints{
		Versioned: cbor.NewVersioned(node.LatestSGXConstraintsVersion),
		Policy:    policy,
	}
	reg := &mockRegistry{
		rt: &registry.Runtime{
			Deployments: []*registry.VersionInfo{
				{Version: rtVersion, TEE: cbor.Marshal(&constraints)},
			},
		},
	}
	provider := &QuotePolicyProvider{Consensus: &mockConsensus{registry: reg}}

	t.Run("RONL", func(t *testing.T) {
		p, err := provider.Get(context.Background(), common.Namespace{}, component.ID_RONL, rtVersion)
		require.NoError(t, err)
		require.Equal(t, policy, p, "RONL should get the policy from the runtime descriptor")
	})

	t.Run("ROFL", func(t *testing.T) {
		compID := component.ID{Kind: component.ROFL, Name: "test"}
		p, err := provider.Get(context.Background(), common.Namespace{}, compID, rtVersion)
		require.NoError(t, err)
		require.Nil(t, p, "ROFL has no policy on the consensus layer")
	})
}
