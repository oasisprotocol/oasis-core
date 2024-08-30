package churp

import (
	"testing"

	"github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

var (
	kmRuntimeID common.Namespace
	_           = kmRuntimeID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
)

func createTestRegistryGenesis() registry.Genesis {
	return registry.Genesis{
		Parameters: registry.ConsensusParameters{
			DebugAllowTestRuntimes: true,
			EnableRuntimeGovernanceModels: map[registry.RuntimeGovernanceModel]bool{
				registry.GovernanceEntity: true,
			},
		},
		Runtimes: []*registry.Runtime{
			{
				Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
				ID:          kmRuntimeID,
				EntityID:    signature.PublicKey{},
				Kind:        registry.KindKeyManager,
				TEEHardware: node.TEEHardwareIntelSGX,
				Deployments: []*registry.VersionInfo{
					{
						TEE: cbor.Marshal(node.SGXConstraints{
							Enclaves: []sgx.EnclaveIdentity{{}},
						}),
					},
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					EntityWhitelist: &registry.EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]registry.EntityWhitelistConfig{},
					},
				},
				GovernanceModel: registry.GovernanceEntity,
			},
		},
	}
}

func createTestChurpGenesis() *churp.Genesis {
	return &churp.Genesis{
		Parameters: churp.ConsensusParameters{
			GasCosts: churp.DefaultGasCosts,
		},
		Statuses: []*churp.Status{
			{
				Identity: churp.Identity{
					ID:        1,
					RuntimeID: kmRuntimeID,
				},
				Threshold:       5,
				HandoffInterval: 0,
				NextHandoff:     churp.HandoffsDisabled,
			},
			{
				Identity: churp.Identity{
					ID:        2,
					RuntimeID: kmRuntimeID,
				},
				Threshold:       10,
				HandoffInterval: 1,
				NextHandoff:     100,
				NextChecksum:    &hash.Hash{1, 2, 3},
				Applications: map[signature.PublicKey]churp.Application{
					keymanager.InsecureRAK: {
						Checksum:      hash.Hash{1, 2, 3},
						Reconstructed: true,
					},
				},
			},
		},
	}
}

func TestInitChain(t *testing.T) {
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextInitChain)
	defer ctx.Close()

	state := churpState.NewMutableState(ctx.State())
	app := &churpExt{
		state: appState,
	}

	// Empty state.
	doc := api.Document{}
	err := app.InitChain(ctx, types.RequestInitChain{}, &doc)
	require.NoError(t, err, "failed to initialize empty state")

	params, err := state.ConsensusParameters(ctx)
	require.NoError(t, err)
	require.Equal(t, churp.ConsensusParameters{}, *params)

	statuses, err := state.AllStatuses(ctx)
	require.NoError(t, err)
	require.Empty(t, statuses)

	// Non-empty state.
	doc = api.Document{
		KeyManager: keymanager.Genesis{
			Churp: createTestChurpGenesis(),
		},
		Registry: createTestRegistryGenesis(),
	}

	err = app.InitChain(ctx, types.RequestInitChain{}, &doc)
	require.NoError(t, err, "failed to initialize non-empty state")

	params, err = state.ConsensusParameters(ctx)
	require.NoError(t, err)
	require.Equal(t, churp.DefaultConsensusParameters, *params)

	statuses, err = state.AllStatuses(ctx)
	require.NoError(t, err)
	require.Len(t, statuses, 2)

	require.Equal(t, uint8(1), statuses[0].ID)
	require.Equal(t, uint8(5), statuses[0].Threshold)
	require.Equal(t, beacon.EpochTime(0), statuses[0].HandoffInterval)
	require.Equal(t, churp.HandoffsDisabled, statuses[0].NextHandoff) // Should be disabled.
	require.Nil(t, statuses[0].NextChecksum)
	require.Nil(t, statuses[0].Applications)

	require.Equal(t, uint8(2), statuses[1].ID)
	require.Equal(t, uint8(10), statuses[1].Threshold)
	require.Equal(t, beacon.EpochTime(1), statuses[1].HandoffInterval)
	require.Equal(t, beacon.EpochTime(1), statuses[1].NextHandoff) // Should be set.
	require.Nil(t, statuses[1].NextChecksum)
	require.Nil(t, statuses[1].Applications)
}

func TestGenesis(t *testing.T) {
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	state := churpState.NewMutableState(ctx.State())
	q := NewQuery(state.ImmutableState)

	// Empty state.
	g, err := q.Genesis(ctx)
	require.NoError(t, err)

	require.Equal(t, churp.ConsensusParameters{}, g.Parameters)
	require.Len(t, g.Statuses, 0)

	// Prepare state that should be exported into the expected genesis.
	genesis := createTestChurpGenesis()

	err = state.SetConsensusParameters(ctx, &genesis.Parameters)
	require.NoError(t, err)

	for _, status := range genesis.Statuses {
		err = state.SetStatus(ctx, status)
		require.NoError(t, err)
	}

	// Exported genesis disables handoffs for all instances
	for i := range genesis.Statuses {
		genesis.Statuses[i].NextHandoff = churp.HandoffsDisabled
		genesis.Statuses[i].NextChecksum = nil
		genesis.Statuses[i].Applications = nil
	}

	// Non-empty state.
	g, err = q.Genesis(ctx)
	require.NoError(t, err)

	require.Equal(t, genesis.Parameters, g.Parameters)
	require.EqualValues(t, genesis.Statuses, g.Statuses)
}
