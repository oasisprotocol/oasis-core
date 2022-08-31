package registry

import (
	"testing"
	"time"

	requirePkg "github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestRegisterNode(t *testing.T) {
	require := requirePkg.New(t)

	now := time.Unix(1580461674, 0)
	cfg := abciAPI.MockApplicationStateConfig{}
	appState := abciAPI.NewMockApplicationState(&cfg)
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	var md abciAPI.NoopMessageDispatcher
	app := registryApplication{appState, &md}
	state := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())
	beaconState := beaconState.NewMutableState(ctx.State())

	// Set up default staking consensus parameters.
	defaultStakeParameters := staking.ConsensusParameters{
		Thresholds: map[staking.ThresholdKind]quantity.Quantity{
			staking.KindEntity:            *quantity.NewFromUint64(0),
			staking.KindNodeValidator:     *quantity.NewFromUint64(0),
			staking.KindNodeCompute:       *quantity.NewFromUint64(0),
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

	// Setup beacon consensus parameters.
	err = beaconState.SetConsensusParameters(ctx, &beacon.ConsensusParameters{
		Backend: beacon.BackendInsecure,
	})
	require.NoError(err, "beacon.SetConsensusParameters")

	// Store all successful registrations in a map for easier reference in later test cases.
	type testCaseData struct {
		// Signers.
		entitySigner    signature.Signer
		nodeSigner      signature.Signer
		consensusSigner signature.Signer
		p2pSigner       signature.Signer
		tlsSigner       signature.Signer
		vrfSigner       signature.VRFSigner

		// Node descriptor.
		node node.Node
	}
	tcData := make(map[string]*testCaseData)

	tcs := []struct {
		name        string
		prepareFn   func(tcd *testCaseData)
		stakeParams *staking.ConsensusParameters
		valid       bool
		exists      bool
	}{
		// Node without any roles.
		{"WithoutRoles", nil, nil, false, false},
		// A simple validator node.
		{
			"Validator",
			func(tcd *testCaseData) {
				tcd.node.AddRoles(node.RoleValidator)
			},
			nil,
			true,
			true,
		},
		// An expired validator node.
		{
			"ExpiredValidator",
			func(tcd *testCaseData) {
				tcd.node.AddRoles(node.RoleValidator)
				tcd.node.Expiration = 0
			},
			nil,
			false,
			false,
		},
		// Validator without enough stake.
		{
			"ValidatorWithoutStake",
			func(tcd *testCaseData) {
				tcd.node.AddRoles(node.RoleValidator)
			},
			&staking.ConsensusParameters{
				Thresholds: map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            *quantity.NewFromUint64(0),
					staking.KindNodeValidator:     *quantity.NewFromUint64(1000),
					staking.KindNodeCompute:       *quantity.NewFromUint64(0),
					staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
					staking.KindRuntimeCompute:    *quantity.NewFromUint64(0),
					staking.KindRuntimeKeyManager: *quantity.NewFromUint64(0),
				},
			},
			false,
			false,
		},
		// Compute node.
		{
			"ComputeNode",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt := registry.Runtime{
					Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:              common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNode"), 0),
					Kind:            registry.KindCompute,
					GovernanceModel: registry.GovernanceEntity,
				}
				_ = state.SetRuntime(ctx, &rt, false)

				tcd.node.AddRoles(node.RoleComputeWorker)
				tcd.node.Runtimes = []*node.Runtime{
					{ID: rt.ID},
				}
			},
			nil,
			true,
			true,
		},
		// Compute node without per-runtime stake.
		{
			"ComputeNodeWithoutPerRuntimeStake",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt := registry.Runtime{
					Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:        common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithoutPerRuntimeStake"), 0),
					Kind:      registry.KindCompute,
					Staking: registry.RuntimeStakingParameters{
						Thresholds: map[staking.ThresholdKind]quantity.Quantity{
							staking.KindNodeCompute: *quantity.NewFromUint64(1000),
						},
					},
					GovernanceModel: registry.GovernanceEntity,
				}
				_ = state.SetRuntime(ctx, &rt, false)

				tcd.node.AddRoles(node.RoleComputeWorker)
				tcd.node.Runtimes = []*node.Runtime{
					{ID: rt.ID},
				}
			},
			nil,
			false,
			false,
		},
		// Compute node with enough per-runtime stake.
		{
			"ComputeNodeWithPerRuntimeStake",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt := registry.Runtime{
					Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:        common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithPerRuntimeStake"), 0),
					Kind:      registry.KindCompute,
					Staking: registry.RuntimeStakingParameters{
						Thresholds: map[staking.ThresholdKind]quantity.Quantity{
							staking.KindNodeCompute: *quantity.NewFromUint64(1000),
						},
					},
					GovernanceModel: registry.GovernanceEntity,
				}
				_ = state.SetRuntime(ctx, &rt, false)

				// Add bonded stake (hacky, without a self-delegation).
				_ = stakeState.SetAccount(ctx, staking.NewAddress(tcd.node.EntityID), &staking.Account{
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance: *quantity.NewFromUint64(10_000),
						},
					},
				})

				tcd.node.AddRoles(node.RoleComputeWorker)
				tcd.node.Runtimes = []*node.Runtime{
					{ID: rt.ID},
					// Include the same runtime with a different version to test this works.
					{ID: rt.ID, Version: version.Version{Major: 1}},
				}
			},
			nil,
			true,
			true,
		},
		// Compute node with enough (per-runtime) stake for one runtime, but not for two.
		{
			"ComputeNodeWithoutPerRuntimeStakeMulti",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt1 := registry.Runtime{
					Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:        common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithoutPerRuntimeStakeMulti 1"), 0),
					Kind:      registry.KindCompute,
					Staking: registry.RuntimeStakingParameters{
						Thresholds: map[staking.ThresholdKind]quantity.Quantity{
							staking.KindNodeCompute: *quantity.NewFromUint64(1000),
						},
					},
					GovernanceModel: registry.GovernanceEntity,
				}
				_ = state.SetRuntime(ctx, &rt1, false)

				// Create another runtime with a different identifier.
				rt2 := rt1
				rt2.ID = common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithoutPerRuntimeStakeMulti 2"), 0)
				_ = state.SetRuntime(ctx, &rt2, false)

				// Add bonded stake (hacky, without a self-delegation).
				_ = stakeState.SetAccount(ctx, staking.NewAddress(tcd.node.EntityID), &staking.Account{
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance: *quantity.NewFromUint64(1000),
						},
					},
				})

				tcd.node.AddRoles(node.RoleComputeWorker)
				tcd.node.Runtimes = []*node.Runtime{
					{ID: rt1.ID},
					// Include the same runtime with a different version to test this works.
					{ID: rt1.ID, Version: version.Version{Major: 1}},
					{ID: rt2.ID},
				}
			},
			nil,
			false,
			false,
		},
		// Compute node with enough (global) stake for one runtime, but not for two.
		{
			"ComputeNodeWithoutGlobalStakeMulti",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt1 := registry.Runtime{
					Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:              common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithoutGlobalStakeMulti 1"), 0),
					Kind:            registry.KindCompute,
					GovernanceModel: registry.GovernanceEntity,
				}
				_ = state.SetRuntime(ctx, &rt1, false)

				// Create another runtime with a different identifier.
				rt2 := rt1
				rt2.ID = common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: ComputeNodeWithoutGlobalStakeMulti 2"), 0)
				_ = state.SetRuntime(ctx, &rt2, false)

				// Add bonded stake (hacky, without a self-delegation).
				_ = stakeState.SetAccount(ctx, staking.NewAddress(tcd.node.EntityID), &staking.Account{
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance: *quantity.NewFromUint64(1000),
						},
					},
				})

				tcd.node.AddRoles(node.RoleComputeWorker)
				tcd.node.Runtimes = []*node.Runtime{
					{ID: rt1.ID},
					// Include the same runtime with a different version to test this works.
					{ID: rt1.ID, Version: version.Version{Major: 1}},
					{ID: rt2.ID},
				}
			},
			&staking.ConsensusParameters{
				Thresholds: map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            *quantity.NewFromUint64(0),
					staking.KindNodeValidator:     *quantity.NewFromUint64(0),
					staking.KindNodeCompute:       *quantity.NewFromUint64(1000),
					staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
					staking.KindRuntimeCompute:    *quantity.NewFromUint64(0),
					staking.KindRuntimeKeyManager: *quantity.NewFromUint64(0),
				},
			},
			false,
			false,
		},
		// Updating a node should be allowed.
		{
			"UpdateValidator",
			func(tcd *testCaseData) {
				// Use a previous node descriptor and just increase the expiration.
				*tcd = *tcData["Validator"]
				tcd.node.Expiration++
			},
			nil,
			true,
			true,
		},
		// Changing the consensus key should not be allowed.
		{
			"UpdateValidatorConsensusKeyNotAllowed",
			func(tcd *testCaseData) {
				// Use a previous node and just update the consensus key.
				newConsensusSigner := tcd.consensusSigner
				*tcd = *tcData["Validator"]

				tcd.consensusSigner = newConsensusSigner
				tcd.node.Consensus.ID = tcd.consensusSigner.Public()
			},
			nil,
			false,
			true, // We tried to update an existing node, so it should keep existing.
		},
		// Changing the consensus key with a previously expired node should not be allowed.
		{
			"UpdateValidatorExpiredConsensusKeyNotAllowed",
			func(tcd *testCaseData) {
				// Use a previous node and just update the consensus key.
				newConsensusSigner := tcd.consensusSigner
				*tcd = *tcData["Validator"]

				tcd.consensusSigner = newConsensusSigner
				tcd.node.Consensus.ID = tcd.consensusSigner.Public()
				tcd.node.Expiration = 12

				// But with a twist -- first make the existing node expired.
				cfg.CurrentEpoch = 10
			},
			nil,
			false,
			true, // We tried to update an existing node, so it should keep existing.
		},
		// Changing the roles of an active node should be allowed.
		{
			"UpdateValidatorRolesNotAllowed",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt := registry.Runtime{
					Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:              common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: UpdateValidatorNotAllowed"), 0),
					Kind:            registry.KindCompute,
					GovernanceModel: registry.GovernanceEntity,
				}

				_ = state.SetRuntime(ctx, &rt, false)
				*tcd = *tcData["Validator"]
				tcd.node.Expiration++
				tcd.node.Roles = node.RoleComputeWorker
				tcd.node.Runtimes = []*node.Runtime{{ID: rt.ID}}
			},
			nil,
			false,
			true,
		},
		// Changing the roles of an expired node should be allowed.
		{
			"UpdateValidatorExpiredRolesAllowed",
			func(tcd *testCaseData) {
				// Create a new runtime.
				rt := registry.Runtime{
					Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
					ID:              common.NewTestNamespaceFromSeed([]byte("consensus/tendermint/apps/registry: runtime: UpdateValidatorExpiredAllowed"), 0),
					Kind:            registry.KindCompute,
					GovernanceModel: registry.GovernanceEntity,
				}
				_ = state.SetRuntime(ctx, &rt, false)
				*tcd = *tcData["Validator"]
				tcd.node.Roles = node.RoleComputeWorker
				tcd.node.Runtimes = []*node.Runtime{{ID: rt.ID}}
				tcd.node.Expiration = 12

				// Make the existing node expired.
				cfg.CurrentEpoch = 10
			},
			nil,
			true,
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
			vrfSigner := memorySigner.NewTestSigner("consensus/tendermint/apps/registry: vrf signer: " + tc.name).(signature.VRFSigner)
			tcd := &testCaseData{
				entitySigner:    memorySigner.NewTestSigner("consensus/tendermint/apps/registry: entity signer: " + tc.name),
				nodeSigner:      memorySigner.NewTestSigner("consensus/tendermint/apps/registry: node signer: " + tc.name),
				consensusSigner: memorySigner.NewTestSigner("consensus/tendermint/apps/registry: consensus signer: " + tc.name),
				p2pSigner:       memorySigner.NewTestSigner("consensus/tendermint/apps/registry: p2p signer: " + tc.name),
				tlsSigner:       memorySigner.NewTestSigner("consensus/tendermint/apps/registry: tls signer: " + tc.name),
				vrfSigner:       vrfSigner,
			}

			// Prepare a test entity that owns the nodes.
			ent := entity.Entity{
				Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
				ID:        tcd.entitySigner.Public(),
				Nodes:     []signature.PublicKey{tcd.nodeSigner.Public()},
			}
			sigEnt, err := entity.SignEntity(tcd.entitySigner, registry.RegisterEntitySignatureContext, &ent)
			require.NoError(err, "SignEntity")
			err = state.SetEntity(ctx, &ent, sigEnt)
			require.NoError(err, "SetEntity")

			// Prepare a new minimal node.
			var address node.Address
			err = address.UnmarshalText([]byte("8.8.8.8:1234"))
			require.NoError(err, "address.UnmarshalText")

			tcd.node = node.Node{
				Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
				ID:         tcd.nodeSigner.Public(),
				EntityID:   ent.ID,
				Expiration: 3,
				P2P: node.P2PInfo{
					ID:        tcd.p2pSigner.Public(),
					Addresses: []node.Address{address},
				},
				Consensus: node.ConsensusInfo{
					ID: tcd.consensusSigner.Public(),
					Addresses: []node.ConsensusAddress{
						{ID: tcd.consensusSigner.Public(), Address: address},
					},
				},
				TLS: node.TLSInfo{
					PubKey: tcd.tlsSigner.Public(),
					Addresses: []node.TLSAddress{
						{PubKey: tcd.tlsSigner.Public(), Address: address},
					},
				},
				VRF: &node.VRFInfo{
					ID: tcd.vrfSigner.Public(),
				},
			}
			if tc.prepareFn != nil {
				tc.prepareFn(tcd)
			}
			signers := []signature.Signer{tcd.nodeSigner, tcd.p2pSigner, tcd.consensusSigner, tcd.tlsSigner, tcd.vrfSigner}

			// Sign the node.
			sigNode, err := node.MultiSignNode(signers, registry.RegisterNodeSignatureContext, &tcd.node)
			require.NoError(err, "MultiSignNode")

			// Attempt to register the node.
			txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
			defer txCtx.Close()
			txCtx.SetTxSigner(tcd.nodeSigner.Public())
			err = app.registerNode(txCtx, state, sigNode)
			switch tc.valid {
			case true:
				require.NoError(err, "node registration should succeed")
			case false:
				require.Error(err, "node registration should fail")
			}

			switch tc.exists {
			case true:
				// Make sure the node has been registered.
				var regNode *node.Node
				regNode, err = state.Node(ctx, tcd.node.ID)
				require.NoError(err, "node should be registered")

				if tc.valid {
					require.EqualValues(&tcd.node, regNode, "registered node descriptor should be correct")
				}
			case false:
				// Make sure the state has not changed.
				_, err = state.Node(ctx, tcd.node.ID)
				require.Error(err, "node should not be registered")
				require.Equal(registry.ErrNoSuchNode, err)
			}

			tcData[tc.name] = tcd
		})
	}
}

func TestProofFreshness(t *testing.T) {
	require := requirePkg.New(t)

	now := time.Unix(1580461674, 0)
	cfg := abciAPI.MockApplicationStateConfig{}
	appState := abciAPI.NewMockApplicationState(&cfg)
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	var md abciAPI.NoopMessageDispatcher
	app := registryApplication{appState, &md}
	state := registryState.NewMutableState(ctx.State())

	setTEEFeaturesFn := func(TEEFeatures *node.TEEFeatures) {
		err := state.SetConsensusParameters(ctx, &registry.ConsensusParameters{
			TEEFeatures: TEEFeatures,
		})
		require.NoError(err, "registry.SetConsensusParameters")
	}

	var blob [32]byte

	t.Run("happy path", func(t *testing.T) {
		setTEEFeaturesFn(&node.TEEFeatures{FreshnessProofs: true})

		err := app.proveFreshness(ctx, state, blob)
		require.NoError(err, "freshness proofs should succeed")
	})

	t.Run("not enabled", func(t *testing.T) {
		// Freshness proofs disabled.
		setTEEFeaturesFn(&node.TEEFeatures{FreshnessProofs: false})

		err := app.proveFreshness(ctx, state, blob)
		require.Error(err, "freshness proofs should not be enabled")
		require.Equal(registry.ErrInvalidArgument, err)

		// No TEE features.
		setTEEFeaturesFn(nil)

		err = app.proveFreshness(ctx, state, blob)
		require.Error(err, "freshness proofs should not be enabled")
		require.Equal(registry.ErrInvalidArgument, err)
	})
}
