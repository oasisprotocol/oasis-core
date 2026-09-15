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
	kmaPolicy := &quote.Policy{
		PCS: &pcs.QuotePolicy{FMSPCWhitelist: []string{"00606A000000"}},
	}

	constraints := node.SGXConstraints{
		Versioned:              cbor.NewVersioned(node.LatestSGXConstraintsVersion),
		Policy:                 policy,
		KeyManagerAccessPolicy: kmaPolicy,
	}
	reg := &mockRegistry{
		rt: &registry.Runtime{
			Deployments: []*registry.VersionInfo{
				{Version: rtVersion, TEE: cbor.Marshal(&constraints)},
			},
		},
	}

	for _, tc := range []struct {
		name         string
		compID       component.ID
		useKMAPolicy bool
		expected     *quote.Policy
	}{
		{
			name:     "RONL/default policy",
			compID:   component.ID_RONL,
			expected: policy,
		},
		{
			name:         "RONL/key manager access policy",
			compID:       component.ID_RONL,
			useKMAPolicy: true,
			expected:     kmaPolicy,
		},
		{
			name:   "ROFL",
			compID: component.ID{Kind: component.ROFL, Name: "test"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &QuotePolicyProvider{
				Consensus:    &mockConsensus{registry: reg},
				UseKMAPolicy: tc.useKMAPolicy,
			}
			p, err := provider.Get(context.Background(), common.Namespace{}, tc.compID, rtVersion)
			require.NoError(t, err)
			require.Equal(t, tc.expected, p)
		})
	}
}
