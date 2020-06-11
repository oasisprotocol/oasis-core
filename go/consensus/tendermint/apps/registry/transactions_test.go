package registry

import (
	"testing"
	"time"

	requirePkg "github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestRegisterNode(t *testing.T) {
	require := requirePkg.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	app := registryApplication{appState}
	state := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	// Set up default staking consensus parameters.
	defaultStakeParameters := staking.ConsensusParameters{
		Thresholds: map[staking.ThresholdKind]quantity.Quantity{
			staking.KindEntity:            *quantity.NewFromUint64(0),
			staking.KindNodeValidator:     *quantity.NewFromUint64(0),
			staking.KindNodeCompute:       *quantity.NewFromUint64(0),
			staking.KindNodeStorage:       *quantity.NewFromUint64(0),
			staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
			staking.KindRuntimeCompute:    *quantity.NewFromUint64(0),
			staking.KindRuntimeKeyManager: *quantity.NewFromUint64(0),
		},
	}
	// Set up registry consensus parameters.
	err := state.SetConsensusParameters(ctx, &registry.ConsensusParameters{
		MaxNodeExpiration: 5,
	})
	require.NoError(err, "registry.SetConsensusParameters")

	tcs := []struct {
		name        string
		prepareFn   func(n *node.Node) []signature.Signer
		stakeParams *staking.ConsensusParameters
		valid       bool
	}{
		// Node without any roles.
		{"WithoutRoles", nil, nil, false},
		// A simple validator node.
		{
			"Validator",
			func(n *node.Node) []signature.Signer {
				n.AddRoles(node.RoleValidator)
				return nil
			},
			nil,
			true,
		},
		// An expired validator node.
		{
			"ExpiredValidator",
			func(n *node.Node) []signature.Signer {
				n.AddRoles(node.RoleValidator)
				n.Expiration = 0
				return nil
			},
			nil,
			false,
		},
		// Validator without enough stake.
		{
			"ValidatorWithoutStake",
			func(n *node.Node) []signature.Signer {
				n.AddRoles(node.RoleValidator)
				return nil
			},
			&staking.ConsensusParameters{
				Thresholds: map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            *quantity.NewFromUint64(0),
					staking.KindNodeValidator:     *quantity.NewFromUint64(1000),
					staking.KindNodeCompute:       *quantity.NewFromUint64(0),
					staking.KindNodeStorage:       *quantity.NewFromUint64(0),
					staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
					staking.KindRuntimeCompute:    *quantity.NewFromUint64(0),
					staking.KindRuntimeKeyManager: *quantity.NewFromUint64(0),
				},
			},
			false,
		},
		// Compute node.
		{
			"ComputeNode",
			func(n *node.Node) []signature.Signer {
				// Create a new runtime.
				rtSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: runtime signer: ComputeNode")
				rt := registry.Runtime{
					DescriptorVersion: registry.LatestRuntimeDescriptorVersion,
					ID:                common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNode"), 0),
					Kind:              registry.KindCompute,
				}
				sigRt, _ := registry.SignRuntime(rtSigner, registry.RegisterRuntimeSignatureContext, &rt)
				_ = state.SetRuntime(ctx, &rt, sigRt, false)

				n.AddRoles(node.RoleComputeWorker)
				n.Runtimes = []*node.Runtime{
					&node.Runtime{ID: rt.ID},
				}
				return nil
			},
			nil,
			true,
		},
		// Compute node without per-runtime stake.
		{
			"ComputeNodeWithoutPerRuntimeStake",
			func(n *node.Node) []signature.Signer {
				// Create a new runtime.
				rtSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: runtime signer: ComputeNodeWithoutPerRuntimeStake")
				rt := registry.Runtime{
					DescriptorVersion: registry.LatestRuntimeDescriptorVersion,
					ID:                common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithoutPerRuntimeStake"), 0),
					Kind:              registry.KindCompute,
					Staking: registry.RuntimeStakingParameters{
						Thresholds: map[staking.ThresholdKind]quantity.Quantity{
							staking.KindNodeCompute: *quantity.NewFromUint64(1000),
						},
					},
				}
				sigRt, _ := registry.SignRuntime(rtSigner, registry.RegisterRuntimeSignatureContext, &rt)
				_ = state.SetRuntime(ctx, &rt, sigRt, false)

				n.AddRoles(node.RoleComputeWorker)
				n.Runtimes = []*node.Runtime{
					&node.Runtime{ID: rt.ID},
				}
				return nil
			},
			nil,
			false,
		},
		// Compute node with ehough per-runtime stake.
		{
			"ComputeNodeWithPerRuntimeStake",
			func(n *node.Node) []signature.Signer {
				// Create a new runtime.
				rtSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: runtime signer: ComputeNodeWithPerRuntimeStake")
				rt := registry.Runtime{
					DescriptorVersion: registry.LatestRuntimeDescriptorVersion,
					ID:                common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithPerRuntimeStake"), 0),
					Kind:              registry.KindCompute,
					Staking: registry.RuntimeStakingParameters{
						Thresholds: map[staking.ThresholdKind]quantity.Quantity{
							staking.KindNodeCompute: *quantity.NewFromUint64(1000),
						},
					},
				}
				sigRt, _ := registry.SignRuntime(rtSigner, registry.RegisterRuntimeSignatureContext, &rt)
				_ = state.SetRuntime(ctx, &rt, sigRt, false)

				// Add bonded stake (hacky, without a self-delegation).
				_ = stakeState.SetAccount(ctx, staking.NewAddress(n.EntityID), &staking.Account{
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance: *quantity.NewFromUint64(10_000),
						},
					},
				})

				n.AddRoles(node.RoleComputeWorker)
				n.Runtimes = []*node.Runtime{
					&node.Runtime{ID: rt.ID},
				}
				return nil
			},
			nil,
			true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			require = requirePkg.New(t)

			// Reset staking consensus parameters.
			stakeParams := tc.stakeParams
			if stakeParams == nil {
				stakeParams = &defaultStakeParameters
			}
			err = stakeState.SetConsensusParameters(ctx, stakeParams)
			require.NoError(err, "staking.SetConsensusParameters")

			// Prepare default signers.
			entitySigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: entity signer: " + tc.name)
			nodeSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: node signer: " + tc.name)
			consensusSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: consensus signer: " + tc.name)
			p2pSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: p2p signer: " + tc.name)
			tlsSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: tls signer: " + tc.name)

			// Prepare a test entity that owns the nodes.
			ent := entity.Entity{
				DescriptorVersion: entity.LatestEntityDescriptorVersion,
				ID:                entitySigner.Public(),
				Nodes:             []signature.PublicKey{nodeSigner.Public()},
			}
			sigEnt, err := entity.SignEntity(entitySigner, registry.RegisterEntitySignatureContext, &ent)
			require.NoError(err, "SignEntity")
			err = state.SetEntity(ctx, &ent, sigEnt)
			require.NoError(err, "SetEntity")

			// Prepare a new minimal node.
			var address node.Address
			err = address.UnmarshalText([]byte("8.8.8.8:1234"))
			require.NoError(err, "address.UnmarshalText")

			n := node.Node{
				DescriptorVersion: node.LatestNodeDescriptorVersion,
				ID:                nodeSigner.Public(),
				EntityID:          ent.ID,
				Expiration:        3,
				P2P: node.P2PInfo{
					ID:        p2pSigner.Public(),
					Addresses: []node.Address{address},
				},
				Consensus: node.ConsensusInfo{
					ID: consensusSigner.Public(),
					Addresses: []node.ConsensusAddress{
						{ID: consensusSigner.Public(), Address: address},
					},
				},
				TLS: node.TLSInfo{
					PubKey: tlsSigner.Public(),
					Addresses: []node.TLSAddress{
						{PubKey: tlsSigner.Public(), Address: address},
					},
				},
			}
			var signers []signature.Signer
			if tc.prepareFn != nil {
				signers = tc.prepareFn(&n)
			}
			if signers == nil {
				signers = []signature.Signer{nodeSigner, p2pSigner, consensusSigner, tlsSigner}
			}

			// Sign the node.
			sigNode, err := node.MultiSignNode(signers, registry.RegisterNodeSignatureContext, &n)
			require.NoError(err, "MultiSignNode")

			// Attempt to register the node.
			ctx.SetTxSigner(nodeSigner.Public())
			err = app.registerNode(ctx, state, sigNode)
			switch tc.valid {
			case true:
				require.NoError(err, "node registration should succeed")

				// Make sure the node has been registered.
				var regNode *node.Node
				regNode, err = state.Node(ctx, n.ID)
				require.NoError(err, "node should be registered")
				require.EqualValues(&n, regNode, "registered node descriptor should be correct")
			case false:
				require.Error(err, "node registration should fail")

				// Make sure the state has not changed.
				_, err = state.Node(ctx, n.ID)
				require.Error(err, "node should not be registered")
				require.Equal(registry.ErrNoSuchNode, err)
			}
		})
	}
}
