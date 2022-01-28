// Package tests is a collection of registry implementation test cases.
package tests

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	recvTimeout = 5 * time.Second

	testRuntimeNodeExpiration beacon.EpochTime = 15

	// Runtime owning test entity and validator node entity.
	preExistingEntities = 2
	// Validator node.
	preExistingNodes = 1
)

var (
	entityNodeSeed = []byte("testRegistryEntityNodes")

	invalidPK = signature.NewBlacklistedPublicKey("0000000000000000000000000000000000000000000000000000000000000000")
)

// RegistryImplementationTests exercises the basic functionality of a
// registry backend.
//
// WARNING: This assumes that the registry is empty, and will leave
// a Runtime registered.
func RegistryImplementationTests(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, validatorEntityID signature.PublicKey) {
	EnsureRegistryClean(t, backend)

	// We need a runtime ID as otherwise the registry will not allow us to
	// register nodes for roles which require runtimes.
	var runtimeID, runtimeEWID common.Namespace
	t.Run("Runtime", func(t *testing.T) {
		runtimeID, runtimeEWID = testRegistryRuntime(t, backend, consensus)
	})

	testRegistryEntityNodes(t, backend, consensus, runtimeID, runtimeEWID, validatorEntityID)
}

// Add node's ID to node list if it's not already on it.
func addToNodeList(nodes []signature.PublicKey, node signature.PublicKey) []signature.PublicKey {
	retNodes := nodes

	var exists bool
	for _, npk := range nodes {
		if npk.Equal(node) {
			exists = true
			break
		}
	}

	if !exists {
		retNodes = append(retNodes, node)
	}

	return retNodes
}

func testRegistryEntityNodes( // nolint: gocyclo
	t *testing.T,
	backend api.Backend,
	consensus consensusAPI.Backend,
	runtimeID common.Namespace,
	runtimeEWID common.Namespace,
	validatorEntityID signature.PublicKey,
) {
	ctx := context.Background()

	// Generate the entities used for the test cases.
	entities, err := NewTestEntities(entityNodeSeed, 4)
	require.NoError(t, err, "NewTestEntities")

	timeSource := consensus.Beacon().(beacon.SetableBackend)
	epoch, err := timeSource.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(t, err, "GetEpoch")

	// All of these tests are combined because the Entity and Node structures
	// are linked together.

	entityCh, entitySub, err := backend.WatchEntities(ctx)
	require.NoError(t, err, "WatchEntities")
	defer entitySub.Close()

	// We rely on the runtime tests running before this registering a runtime.
	nodeRuntimes := []*node.Runtime{{ID: runtimeID}}

	// Allocate nodes before registering entities, so that all the node IDs
	// are present in the entity's node list (or they'll fail to register).
	var numNodes int
	nodes := make([][]*TestNode, 0, len(entities))
	for i, te := range entities {
		// Stagger the expirations so that it's possible to test it.
		var entityNodes []*TestNode
		entityNodes, err = te.NewTestNodes(i+1, nil, nodeRuntimes, epoch+beacon.EpochTime(i)+1, consensus)
		require.NoError(t, err, "NewTestNodes")

		// Append nodes to entity's list of nodes & update registration.
		for _, en := range entityNodes {
			te.Entity.Nodes = addToNodeList(te.Entity.Nodes, en.Node.ID)
		}
		te.SignedRegistration, err = entity.SignEntity(te.Signer, api.RegisterEntitySignatureContext, te.Entity)
		require.NoError(t, err, "SignEntity")

		nodes = append(nodes, entityNodes)
		numNodes += len(entityNodes)
	}

	nodeRuntimesEW := []*node.Runtime{{ID: runtimeEWID}}
	whitelistedNodes, err := entities[1].NewTestNodes(1, []byte("whitelistedNodes"), nodeRuntimesEW, epoch+2, consensus)
	require.NoError(t, err, "NewTestNodes whitelisted")
	nonWhitelistedNodes, err := entities[0].NewTestNodes(1, []byte("nonWhitelistedNodes"), nodeRuntimesEW, epoch+2, consensus)
	require.NoError(t, err, "NewTestNodes non-whitelisted")

	// Append nodes used for testing the MaxNodes whitelist.
	// Entity 3 is allowed to have only one compute node.  This is set-up in
	// "EntityWhitelist" test in testRegistryRuntime() below.
	ent3nodes, err := entities[3].NewTestNodes(2, []byte("ent3nodes"), nodeRuntimesEW, epoch+2, consensus)
	require.NoError(t, err, "NewTestNodes for entity 3")

	// Update entity node lists for the whitelist test nodes as well.
	for _, n := range nonWhitelistedNodes {
		entities[0].Entity.Nodes = addToNodeList(entities[0].Entity.Nodes, n.Node.ID)
	}
	for _, n := range whitelistedNodes {
		entities[1].Entity.Nodes = addToNodeList(entities[1].Entity.Nodes, n.Node.ID)
	}
	for _, n := range ent3nodes {
		entities[3].Entity.Nodes = addToNodeList(entities[3].Entity.Nodes, n.Node.ID)
	}

	entities[0].SignedRegistration, err = entity.SignEntity(entities[0].Signer, api.RegisterEntitySignatureContext, entities[0].Entity)
	require.NoError(t, err, "SignEntity0")
	entities[1].SignedRegistration, err = entity.SignEntity(entities[1].Signer, api.RegisterEntitySignatureContext, entities[1].Entity)
	require.NoError(t, err, "SignEntity1")
	entities[3].SignedRegistration, err = entity.SignEntity(entities[3].Signer, api.RegisterEntitySignatureContext, entities[3].Entity)
	require.NoError(t, err, "SignEntity3")

	whitelistedNodes = append(whitelistedNodes, ent3nodes[0])
	nonWhitelistedNodes = append(nonWhitelistedNodes, ent3nodes[1])

	t.Run("EntityRegistration", func(t *testing.T) {
		require := require.New(t)

		for _, v := range entities {
			// First try registering invalid cases and make sure they fail.
			for _, inv := range v.invalidBefore {
				err = v.Register(consensus, inv.signed)
				require.Error(err, inv.descr)
			}

			err = v.Register(consensus, v.SignedRegistration)
			require.NoError(err, "RegisterEntity")

			select {
			case ev := <-entityCh:
				require.EqualValues(v.Entity, ev.Entity, "registered entity")
				require.True(ev.IsRegistration, "event is registration")

				// Make sure that GetEvents also returns the registration event.
				evts, grr := backend.GetEvents(ctx, consensusAPI.HeightLatest)
				require.NoError(grr, "GetEvents")
				var gotIt bool
				for _, evt := range evts {
					if evt.EntityEvent != nil {
						if evt.EntityEvent.Entity.ID.Equal(ev.Entity.ID) && evt.EntityEvent.IsRegistration {
							require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
							require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
							gotIt = true
							break
						}
					}
				}
				require.EqualValues(true, gotIt, "GetEvents should return entity registration event")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive entity registration event")
			}
		}

		for _, v := range entities {
			var ent *entity.Entity
			ent, err = backend.GetEntity(ctx, &api.IDQuery{ID: v.Entity.ID, Height: consensusAPI.HeightLatest})
			require.NoError(err, "GetEntity")
			require.EqualValues(v.Entity, ent, "retrieved entity")
		}

		var registeredEntities []*entity.Entity
		registeredEntities, err = backend.GetEntities(ctx, consensusAPI.HeightLatest)
		require.NoError(err, "GetEntities")
		testEntity, _, _ := entity.TestEntity()
		require.Len(registeredEntities, len(entities)+preExistingEntities, "entities after registration")

		seen := make(map[signature.PublicKey]bool)
		for _, ent := range registeredEntities {
			// Skip test entity.
			if ent.ID.Equal(testEntity.ID) {
				continue
			}
			// Skip validator entity.
			if ent.ID.Equal(validatorEntityID) {
				continue
			}

			var isValid bool
			for _, v := range entities {
				if v.Entity.ID.Equal(ent.ID) {
					require.EqualValues(v.Entity, ent, "bulk retrieved entity")
					seen[ent.ID] = true
					isValid = true
					break
				}
			}
			require.True(isValid, "bulk retrieved entity was the one registered")
		}
		require.Len(seen, len(entities), "unique bulk retrieved entities")
	})

	nodeCh, nodeSub, err := backend.WatchNodes(ctx)
	require.NoError(t, err, "WatchNodes")
	defer nodeSub.Close()

	t.Run("NodeRegistration", func(t *testing.T) {
		require := require.New(t)

		for _, tns := range nodes {
			for _, tn := range tns {
				for _, v := range tn.invalidBefore {
					err = tn.Register(consensus, v.signed)
					require.Error(err, v.descr)
				}

				err = tn.Register(consensus, tn.SignedRegistration)
				require.NoError(err, "RegisterNode")

				select {
				case ev := <-nodeCh:
					require.EqualValues(tn.Node, ev.Node, "registered node")
					require.True(ev.IsRegistration, "event is registration")

					// Make sure that GetEvents also returns the registration event.
					evts, grr := backend.GetEvents(ctx, consensusAPI.HeightLatest)
					require.NoError(grr, "GetEvents")
					var gotIt bool
					for _, evt := range evts {
						if evt.NodeEvent != nil {
							if evt.NodeEvent.Node.ID.Equal(tn.Node.ID) && evt.NodeEvent.IsRegistration {
								require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
								require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
								gotIt = true
								break
							}
						}
					}
					require.EqualValues(true, gotIt, "GetEvents should return node registration event")
				case <-time.After(recvTimeout):
					t.Fatalf("failed to receive node registration event")
				}

				var nod *node.Node
				nod, err = backend.GetNode(ctx, &api.IDQuery{ID: tn.Node.ID, Height: consensusAPI.HeightLatest})
				require.NoError(err, "GetNode")
				require.EqualValues(tn.Node, nod, "retrieved node")

				var nodeByConsensus *node.Node
				nodeByConsensus, err = backend.GetNodeByConsensusAddress(
					ctx,
					&api.ConsensusAddressQuery{
						Address: []byte(tmcrypto.PublicKeyToTendermint(&tn.Node.Consensus.ID).Address()),
						Height:  consensusAPI.HeightLatest,
					},
				)
				require.NoError(err, "GetNodeByConsensusAddress")
				require.EqualValues(tn.Node, nodeByConsensus, "retrieved node by Consensus Address")

				for _, v := range tn.invalidAfter {
					err = tn.Register(consensus, v.signed)
					require.Error(err, v.descr)
					require.ErrorIs(err, api.ErrInvalidArgument)
				}

				err = tn.Register(consensus, tn.SignedValidReRegistration)
				require.NoError(err, "Re-registering a node with different address and more runtimes should work")

				for _, v := range tn.invalidReReg {
					err = tn.Register(consensus, v.signed)
					require.Error(err, v.descr)
				}

				select {
				case ev := <-nodeCh:
					require.EqualValues(tn.UpdatedNode, ev.Node, "updated node")
					require.True(ev.IsRegistration, "event is registration")
				case <-time.After(recvTimeout):
					t.Fatalf("failed to receive node registration event")
				}
			}
		}

		for _, tn := range whitelistedNodes {
			require.NoError(tn.Register(consensus, tn.SignedRegistration), "register node from whitelisted entity (%s)", tn.Node.ID)

			select {
			case ev := <-nodeCh:
				require.EqualValues(tn.Node, ev.Node, "registered node, whitelisted")
				require.True(ev.IsRegistration, "event is registration, whitelisted")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive node registration event, whitelisted")
			}
		}
		for ti, tn := range nonWhitelistedNodes {
			require.Error(tn.Register(consensus, tn.SignedRegistration), fmt.Sprintf("register node from non whitelisted entity (index %d)", ti))
		}
	})

	getExpectedNodeList := func() []*node.Node {
		// Derive the expected node list.
		l := make([]*node.Node, 0, numNodes+len(whitelistedNodes)+preExistingNodes)
		for _, tns := range nodes {
			for _, tn := range tns {
				l = append(l, tn.UpdatedNode)
			}
		}
		for _, tn := range whitelistedNodes {
			l = append(l, tn.Node)
		}
		api.SortNodeList(l)

		return l
	}

	t.Run("NodeList", func(t *testing.T) {
		require := require.New(t)

		expectedNodeList := getExpectedNodeList()
		epoch = beaconTests.MustAdvanceEpoch(t, timeSource)

		registeredNodes, nerr := backend.GetNodes(ctx, consensusAPI.HeightLatest)
		require.NoError(nerr, "GetNodes")

		// Remove the pre-exiting validator node.
		for i, nd := range registeredNodes {
			if nd.EntityID.Equal(validatorEntityID) {
				registeredNodes = append(registeredNodes[:i], registeredNodes[i+1:]...)
				break
			}
		}
		require.EqualValues(expectedNodeList, registeredNodes, "node list")
	})

	t.Run("NodeUnfreeze", func(t *testing.T) {
		require := require.New(t)

		entity := entities[0]
		node := nodes[0][0]

		// Get node status.
		var nodeStatus *api.NodeStatus
		nodeStatus, err = backend.GetNodeStatus(ctx, &api.IDQuery{ID: node.Node.ID, Height: consensusAPI.HeightLatest})
		require.NoError(err, "GetNodeStatus")
		require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
		require.False(nodeStatus.IsFrozen(), "IsFrozen() should return false")

		// Try to unfreeze a node.
		tx := api.NewUnfreezeNodeTx(0, nil, &api.UnfreezeNode{
			NodeID: node.Node.ID,
		})
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, entity.Signer, tx)
		require.NoError(err, "UnfreezeNode")

		// Try to unfreeze an invalid node (should fail).
		var unfreeze api.UnfreezeNode
		// Generate arbitrary invalid node ID.
		err = unfreeze.NodeID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		require.NoError(err, "UnmarshalHex")
		tx = api.NewUnfreezeNodeTx(0, nil, &unfreeze)
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, entity.Signer, tx)
		require.Error(err, "UnfreezeNode (with invalid node)")
		require.Equal(err, api.ErrNoSuchNode)

		// Try to unfreeze a node using the node signing key (should fail
		// as unfreeze must be signed by entity signing key).
		tx = api.NewUnfreezeNodeTx(0, nil, &api.UnfreezeNode{
			NodeID: node.Node.ID,
		})
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, node.Signer, tx)
		require.Error(err, "UnfreezeNode (with invalid signer)")
		require.Equal(err, api.ErrBadEntityForNode)
	})

	t.Run("NodeExpiration", func(t *testing.T) {
		require := require.New(t)

		// Advancing the epoch should result in the 0th entity's nodes
		// being deregistered due to expiration.
		expectedDeregEvents := len(nodes[0])
		deregisteredNodes := make(map[signature.PublicKey]*node.Node)

		epoch = beaconTests.MustAdvanceEpoch(t, timeSource)

		var deregEvents int
		for deregEvents < expectedDeregEvents {
			select {
			case ev := <-nodeCh:
				// Skip events by the pre-existing validator node.
				if ev.Node.EntityID.Equal(validatorEntityID) {
					continue
				}

				deregEvents++
				require.False(ev.IsRegistration, "event is deregistration")
				deregisteredNodes[ev.Node.ID] = ev.Node

				// Make sure that GetEvents also returns the deregistration event.
				evts, grr := backend.GetEvents(ctx, consensusAPI.HeightLatest)
				require.NoError(grr, "GetEvents")
				var gotIt bool
				for _, evt := range evts {
					if evt.NodeEvent != nil {
						if evt.NodeEvent.Node.ID.Equal(ev.Node.ID) && !evt.NodeEvent.IsRegistration {
							require.True(evt.TxHash.IsEmpty(), "Node expiration event hash should be empty")
							require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
							gotIt = true
							break
						}
					}
				}
				require.EqualValues(true, gotIt, "GetEvents should return node deregistration event")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive node deregistration event")
			}
		}
		require.Len(deregisteredNodes, expectedDeregEvents, "deregistration events")

		for _, v := range nodes[0] {
			n, ok := deregisteredNodes[v.Node.ID]
			require.True(ok, "got deregister event for node")
			require.EqualValues(v.UpdatedNode, n, "deregistered node")
		}

		// Remove the expired nodes from the test driver's view of
		// registered nodes.
		expiredNode := nodes[0][0]
		nodes = nodes[1:]
		numNodes -= expectedDeregEvents

		// Ensure the node list doesn't have the expired nodes.
		expectedNodeList := getExpectedNodeList()
		registeredNodes, nerr := backend.GetNodes(ctx, consensusAPI.HeightLatest)
		require.NoError(nerr, "GetNodes")
		// Remove the pre-exiting validator node.
		for i, nd := range registeredNodes {
			if nd.EntityID.Equal(validatorEntityID) {
				registeredNodes = append(registeredNodes[:i], registeredNodes[i+1:]...)
				break
			}
		}
		require.EqualValues(expectedNodeList, registeredNodes, "node list")

		// Ensure that registering an expired node will fail.
		err = expiredNode.Register(consensus, expiredNode.SignedRegistration)
		require.Error(err, "RegisterNode with expired node")
		require.Equal(err, api.ErrNodeExpired)
	})

	t.Run("EntityDeregistration", func(t *testing.T) {
		require := require.New(t)

		// It shouldn't be possible to deregister any entities at this point as
		// they all have registered nodes. While nodes for entity 0 have all
		// expired (in NodeExpiration test), they are still present in the registry
		// until after the debonding period (1 epoch) expires.
		for _, v := range entities {
			err := v.Deregister(consensus)
			require.Error(err, "DeregisterEntity")
			require.Equal(err, api.ErrEntityHasNodes)
		}

		// Advance the epoch to trigger 0th entity nodes to be removed.
		_ = beaconTests.MustAdvanceEpoch(t, timeSource)

		// At this point it should only be possible to deregister 0th entity nodes.
		err := entities[0].Deregister(consensus)
		require.NoError(err, "DeregisterEntity - 0th entity")

		select {
		case ev := <-entityCh:
			require.EqualValues(entities[0].Entity, ev.Entity, "deregistered entity")
			require.False(ev.IsRegistration, "event is deregistration")

			// Make sure that GetEvents also returns the deregistration event.
			evts, err := backend.GetEvents(ctx, consensusAPI.HeightLatest)
			require.NoError(err, "GetEvents")
			var gotIt bool
			for _, evt := range evts {
				if evt.EntityEvent != nil {
					if evt.EntityEvent.Entity.ID.Equal(ev.Entity.ID) && !evt.EntityEvent.IsRegistration {
						require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
						require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
						gotIt = true
						break
					}
				}
			}
			require.EqualValues(true, gotIt, "GetEvents should return entity deregistration event")
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive entity deregistration event")
		}

		// All other entities should still fail.
		for _, v := range entities[1:] {
			err := v.Deregister(consensus)
			require.Error(err, "DeregisterEntity")
			require.Equal(err, api.ErrEntityHasNodes)
		}

		// Advance the epoch to trigger all nodes to expire and be removed.
		_ = beaconTests.MustAdvanceEpochMulti(t, timeSource, consensus.Registry(), uint64(len(entities)+2))

		// Now it should be possible to deregister all remaining entities.
		for _, v := range entities[1:] {
			err := v.Deregister(consensus)
			require.NoError(err, "DeregisterEntity")

			select {
			case ev := <-entityCh:
				require.EqualValues(v.Entity, ev.Entity, "deregistered entity")
				require.False(ev.IsRegistration, "event is deregistration")

				// Make sure that GetEvents also returns the deregistration event.
				evts, err := backend.GetEvents(ctx, consensusAPI.HeightLatest)
				require.NoError(err, "GetEvents")
				var gotIt bool
				for _, evt := range evts {
					if evt.EntityEvent != nil {
						if evt.EntityEvent.Entity.ID.Equal(ev.Entity.ID) && !evt.EntityEvent.IsRegistration {
							require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
							require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
							gotIt = true
							break
						}
					}
				}
				require.EqualValues(true, gotIt, "GetEvents should return entity deregistration event")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive entity deregistration event")
			}
		}

		// There should be no more entities.
		for _, v := range entities {
			_, err := backend.GetEntity(ctx, &api.IDQuery{ID: v.Entity.ID, Height: consensusAPI.HeightLatest})
			require.Equal(api.ErrNoSuchEntity, err, "GetEntity")
		}
	})

	t.Run("RemainingNodeExpiration", func(t *testing.T) {
		require := require.New(t)

		deregisteredNodes := make(map[signature.PublicKey]*node.Node)

		var deregEvents int
		for deregEvents < numNodes+len(whitelistedNodes) {
			select {
			case ev := <-nodeCh:
				// Skip events by the pre-existing validator node.
				if ev.Node.EntityID.Equal(validatorEntityID) {
					continue
				}

				deregEvents++
				require.False(ev.IsRegistration, "event is deregistration")
				deregisteredNodes[ev.Node.ID] = ev.Node
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive node deregistration event")
			}
		}
		require.Len(deregisteredNodes, numNodes+len(whitelistedNodes), "deregistration events")

		for _, tns := range nodes {
			for _, tn := range tns {
				n, ok := deregisteredNodes[tn.Node.ID]
				require.True(ok, "got deregister event for node")
				require.EqualValues(tn.UpdatedNode, n, "deregistered node")
			}
		}
		for _, tn := range whitelistedNodes {
			n, ok := deregisteredNodes[tn.Node.ID]
			require.True(ok, "got deregister event for node, whitelisted")
			require.EqualValues(tn.Node, n, "deregistered node, whitelisted")
		}
	})

	// TODO: Test the various failures. (ErrNoSuchEntity is already covered)

	EnsureRegistryClean(t, backend)
}

func testRegistryRuntime(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) (common.Namespace, common.Namespace) {
	require := require.New(t)

	query := &api.GetRuntimesQuery{Height: consensusAPI.HeightLatest, IncludeSuspended: false}
	existingRuntimes, err := backend.GetRuntimes(context.Background(), query)
	require.NoError(err, "GetRuntimes(includeSuspended=false)")
	query.IncludeSuspended = true
	existingAllRuntimes, err := backend.GetRuntimes(context.Background(), query)
	require.NoError(err, "GetRuntimes(includeSuspended=true)")
	require.ElementsMatch(existingRuntimes, existingAllRuntimes, "no suspended runtimes")

	// We must use the test entity for runtime registrations as registering a runtime will prevent
	// the entity from being deregistered and the other node tests already use the test entity for
	// deregistration.
	testEntity, testEntitySigner, _ := entity.TestEntity()
	entity := &TestEntity{
		Entity: testEntity,
		Signer: testEntitySigner,
	}

	// Runtime registration test cases.
	rtMapByName := make(map[string]*api.Runtime)
	tcs := []struct {
		name       string
		prepareFn  func(rt *api.Runtime)
		keyManager bool
		valid      bool
	}{
		// Runtime without key manager set.
		{"WithoutKM", nil, false, true},
		// Runtime using entity whitelist node admission policy.
		{
			"EntityWhitelist",
			func(rt *api.Runtime) {
				var nodeEntities []*TestEntity
				nodeEntities, err = NewTestEntities(entityNodeSeed, 4)
				require.NoError(err, "NewTestEntities with entity node seed")
				rt.AdmissionPolicy = api.RuntimeAdmissionPolicy{
					EntityWhitelist: &api.EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]api.EntityWhitelistConfig{
							nodeEntities[1].Entity.ID: {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 2,
									node.RoleStorageRPC:    2,
								},
							},
							nodeEntities[3].Entity.ID: {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 1,
									node.RoleStorageRPC:    1,
								},
							},
						},
					},
				}
			},
			false,
			true,
		},
		// Runtime with unset node admission policy.
		{
			"UnsetAdmissionPolicy",
			func(rt *api.Runtime) {
				rt.AdmissionPolicy = api.RuntimeAdmissionPolicy{}
			},
			false,
			false,
		},
		// Runtime using custom staking thresholds.
		{
			"StakingThresholds",
			func(rt *api.Runtime) {
				var q quantity.Quantity
				_ = q.FromUint64(1000)

				rt.Staking = api.RuntimeStakingParameters{
					Thresholds: map[staking.ThresholdKind]quantity.Quantity{
						staking.KindNodeCompute: q,
					},
				}
			},
			false,
			true,
		},
		// Runtime using invalid custom staking thresholds.
		{
			"StakingThresholdsInvalid1",
			func(rt *api.Runtime) {
				var q quantity.Quantity
				_ = q.FromUint64(1000)

				rt.Staking = api.RuntimeStakingParameters{
					Thresholds: map[staking.ThresholdKind]quantity.Quantity{
						staking.KindNodeCompute:   q,
						staking.KindNodeValidator: q,
					},
				}
			},
			false,
			false,
		},
		{
			"StakingThresholdsInvalid2",
			func(rt *api.Runtime) {
				var q quantity.Quantity
				_ = q.FromUint64(1000)

				rt.Staking = api.RuntimeStakingParameters{
					Thresholds: map[staking.ThresholdKind]quantity.Quantity{
						staking.KindNodeKeyManager: q,
					},
				}
			},
			false,
			false,
		},
		// Hardware Invalid Key manager runtime.
		{
			"HardwareInvalidKeyManager",
			func(rt *api.Runtime) {
				rt.Kind = api.KindKeyManager
				rt.TEEHardware = node.TEEHardwareInvalid
				// Set non-test runtime.
				rt.ID = newNamespaceFromSeed([]byte("HardwareInvalidKeyManager"), common.NamespaceKeyManager)
			},
			true,
			false,
		},
		// Hardware Reserved Key manager runtime.
		{
			"HardwareReservedInvalidKeyManager",
			func(rt *api.Runtime) {
				rt.Kind = api.KindKeyManager
				rt.TEEHardware = node.TEEHardwareReserved
				// Set non-test runtime.
				rt.ID = newNamespaceFromSeed([]byte("HardwareReservedInvalidKeyManager"), common.NamespaceKeyManager)
			},
			true,
			false,
		},
		// SGX Key manager runtime.
		{
			"SGXKeyManager",
			func(rt *api.Runtime) {
				rt.Kind = api.KindKeyManager
				rt.TEEHardware = node.TEEHardwareIntelSGX

				cs := node.SGXConstraints{
					Enclaves: []sgx.EnclaveIdentity{{}},
				}
				rt.Version.TEE = cbor.Marshal(cs)
				// Set non-test runtime.
				rt.ID = newNamespaceFromSeed([]byte("SGXKeyManager"), common.NamespaceKeyManager)
			},
			true,
			true,
		},
		// Test Key manager runtime.
		{
			"KeyManager",
			func(rt *api.Runtime) {
				rt.Kind = api.KindKeyManager
			},
			true,
			true,
		},
		// Runtime with key manager set, without SGX.
		{
			"NoSGXWithKM",
			func(rt *api.Runtime) {
				rt.KeyManager = &rtMapByName["KeyManager"].ID
				// Set non-test runtime.
				rt.ID = newNamespaceFromSeed([]byte("NoSGXWithKM"), 0)
			},
			false,
			false,
		},
		// SGX Runtime with key manager set.
		{
			"SGXWithKM",
			func(rt *api.Runtime) {
				rt.KeyManager = &rtMapByName["KeyManager"].ID
				rt.TEEHardware = node.TEEHardwareIntelSGX

				cs := node.SGXConstraints{
					Enclaves: []sgx.EnclaveIdentity{{}},
				}
				rt.Version.TEE = cbor.Marshal(cs)
				// Set non-test runtime.
				rt.ID = newNamespaceFromSeed([]byte("SGXWithKM"), 0)
			},
			false,
			true,
		},
		// Test Runtime with key manager set.
		{
			"WithKM",
			func(rt *api.Runtime) {
				rt.KeyManager = &rtMapByName["KeyManager"].ID
			},
			false,
			true,
		},
		// Runtime with bad key manager.
		{
			"WithInvalidKM",
			func(rt *api.Runtime) {
				rt.KeyManager = &common.Namespace{0xab}
			},
			false,
			false,
		},
		// Runtime with too large MaxMessages parameter.
		{
			"TooBigMaxMessages",
			func(rt *api.Runtime) {
				rt.Executor.MaxMessages = 64 // MaxRuntimeMessages in these tests is 32.
			},
			false,
			false,
		},
		// Runtime with too large MaxInMessages parameter.
		{
			"TooBigMaxMessages",
			func(rt *api.Runtime) {
				rt.TxnScheduler.MaxInMessages = 64 // MaxInRuntimeMessages in these tests is 32.
			},
			false,
			false,
		},
		// Runtime with consensus governance after genesis time.
		{
			"ConsensusGovernanceAfterGenesis",
			func(rt *api.Runtime) {
				rt.GovernanceModel = api.GovernanceConsensus
			},
			false,
			false,
		},
	}

	rtMap := make(map[common.Namespace]*api.Runtime)
	for _, tc := range tcs {
		var rt *TestRuntime
		rt, err = NewTestRuntime([]byte(tc.name), entity, tc.keyManager)
		require.NoError(err, "NewTestRuntime (%s)", tc.name)
		if tc.prepareFn != nil {
			tc.prepareFn(rt.Runtime)
		}

		switch tc.valid {
		case true:
			rtMap[rt.Runtime.ID] = rt.Runtime
			rt.MustRegister(t, backend, consensus)
		case false:
			rt.MustNotRegister(t, backend, consensus)
		}

		rtMapByName[tc.name] = rt.Runtime
	}

	registeredRuntimes, err := backend.GetRuntimes(context.Background(), query)
	require.NoError(err, "GetRuntimes")
	require.Len(registeredRuntimes, len(existingRuntimes)+len(rtMap), "registry has all the new runtimes")
	for _, regRuntime := range registeredRuntimes {
		if rtMap[regRuntime.ID] != nil {
			require.EqualValues(rtMap[regRuntime.ID], regRuntime, "expected runtime is registered")
			delete(rtMap, regRuntime.ID)
		}
	}
	require.Len(rtMap, 0, "all runtimes were registered")

	// Test runtime re-registration.
	var re *TestRuntime
	re, err = NewTestRuntime([]byte("Runtime re-registration test 1"), entity, false)
	require.NoError(err, "NewTestRuntime (re-registration test 1)")
	re.MustRegister(t, backend, consensus)
	// Entity to runtime governance transition should succeed.
	re.Runtime.GovernanceModel = api.GovernanceRuntime
	re.MustRegister(t, backend, consensus)
	// Runtime to consensus governance transition should fail.
	re.Runtime.GovernanceModel = api.GovernanceConsensus
	re.MustNotRegister(t, backend, consensus)
	// Runtime back to entity governance transition should fail.
	re.Runtime.GovernanceModel = api.GovernanceEntity
	re.MustNotRegister(t, backend, consensus)
	// Any updates to runtime parameters should fail for runtime-governed runtimes.
	re.Runtime.GovernanceModel = api.GovernanceRuntime
	re.Runtime.TxnScheduler.ProposerTimeout = 6
	re.MustNotRegister(t, backend, consensus)

	re, err = NewTestRuntime([]byte("Runtime re-registration test 2"), entity, true)
	require.NoError(err, "NewTestRuntime (re-registration test 2)")
	re.Runtime.Kind = api.KindKeyManager
	re.MustRegister(t, backend, consensus)
	// Non-compute runtimes cannot transition to runtime governance.
	re.Runtime.GovernanceModel = api.GovernanceRuntime
	re.MustNotRegister(t, backend, consensus)
	// Entity to consensus governance transition should fail for KM runtimes too.
	re.Runtime.GovernanceModel = api.GovernanceConsensus
	re.MustNotRegister(t, backend, consensus)

	re, err = NewTestRuntime([]byte("Runtime re-registration test 3"), entity, false)
	require.NoError(err, "NewTestRuntime (re-registration test 3)")
	re.MustRegister(t, backend, consensus)
	// Entity to consensus governance transition should fail.
	re.Runtime.GovernanceModel = api.GovernanceConsensus
	re.MustNotRegister(t, backend, consensus)

	// No way to de-register the runtime or the controlling entity, so it will be left there.

	return rtMapByName["WithoutKM"].ID, rtMapByName["EntityWhitelist"].ID
}

// EnsureRegistryClean enforces that the registry is in a clean state before running the registry tests.
func EnsureRegistryClean(t *testing.T, backend api.Backend) {
	registeredEntities, err := backend.GetEntities(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetEntities")
	// Allow runtime-controlling and the validator node entities.
	require.Len(t, registeredEntities, preExistingEntities, "registered entities")

	// Allow validator node registered.
	registeredNodes, err := backend.GetNodes(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetNodes")
	require.Len(t, registeredNodes, preExistingNodes, "registered nodes")
}

// TestEntity is a testing Entity and some common pre-generated/signed
// blobs useful for testing.
type TestEntity struct {
	Entity *entity.Entity
	Signer signature.Signer

	SignedRegistration *entity.SignedEntity

	invalidBefore []*invalidEntityRegistration
}

type invalidEntityRegistration struct {
	descr  string
	signed *entity.SignedEntity
}

// Register attempts to register an entity.
func (ent *TestEntity) Register(consensus consensusAPI.Backend, sigEnt *entity.SignedEntity) error {
	return consensusAPI.SignAndSubmitTx(context.Background(), consensus, ent.Signer, api.NewRegisterEntityTx(0, nil, sigEnt))
}

// Deregister attempts to deregister the entity.
func (ent *TestEntity) Deregister(consensus consensusAPI.Backend) error {
	return consensusAPI.SignAndSubmitTx(context.Background(), consensus, ent.Signer, api.NewDeregisterEntityTx(0, nil))
}

// TestNode is a testing Node and some common pre-generated/signed blobs
// useful for testing.
type TestNode struct {
	Entity *TestEntity

	Node        *node.Node
	UpdatedNode *node.Node
	Signer      signature.Signer

	SignedRegistration        *node.MultiSignedNode
	SignedValidReRegistration *node.MultiSignedNode

	invalidBefore []*invalidNodeRegistration
	invalidAfter  []*invalidNodeRegistration
	invalidReReg  []*invalidNodeRegistration
}

type invalidNodeRegistration struct {
	descr  string
	signed *node.MultiSignedNode
}

// Register attempts to register a node.
func (n *TestNode) Register(consensus consensusAPI.Backend, sigNode *node.MultiSignedNode) error {
	return consensusAPI.SignAndSubmitTx(context.Background(), consensus, n.Signer, api.NewRegisterNodeTx(0, nil, sigNode))
}

func randomIdentity(rng *drbg.Drbg) *identity.Identity {
	mustGenerateSigner := func() signature.Signer {
		signer, err := memorySigner.NewSigner(rng)
		if err != nil {
			panic(err)
		}
		return signer
	}

	ident := &identity.Identity{
		NodeSigner:      mustGenerateSigner(),
		P2PSigner:       mustGenerateSigner(),
		ConsensusSigner: mustGenerateSigner(),
		VRFSigner:       mustGenerateSigner(),
	}
	ident.VRFSigner.(*memorySigner.Signer).UnsafeSetRole(signature.SignerVRF)

	cert, err := tls.Generate(identity.CommonName)
	if err != nil {
		panic(err)
	}
	ident.SetTLSCertificate(cert)

	return ident
}

// NewTestNodes returns the specified number of TestNodes, generated
// deterministically using the entity's public key as the seed.
func (ent *TestEntity) NewTestNodes(nCompute int, idNonce []byte, runtimes []*node.Runtime, expiration beacon.EpochTime, consensus consensusAPI.Backend) ([]*TestNode, error) { // nolint: gocyclo
	if nCompute <= 0 || nCompute > 254 {
		return nil, errors.New("registry/tests: test node count out of bounds")
	}
	n := nCompute

	rng, err := drbg.New(crypto.SHA512, hashForDrbg(ent.Entity.ID[:]), idNonce, []byte("TestNodes"))
	if err != nil {
		return nil, err
	}

	nodes := make([]*TestNode, 0, n)
	for i := 0; i < n; i++ {
		nodeIdentity := randomIdentity(rng)
		nodeSigners := []signature.Signer{
			nodeIdentity.NodeSigner,
			nodeIdentity.P2PSigner,
			nodeIdentity.ConsensusSigner,
			nodeIdentity.VRFSigner,
			nodeIdentity.GetTLSSigner(),
		}
		invalidIdentity := randomIdentity(rng)

		var nod TestNode
		nod.Signer = nodeIdentity.NodeSigner
		nod.Entity = ent

		var role node.RolesMask
		if i < nCompute {
			role = node.RoleComputeWorker | node.RoleStorageRPC
		}

		nod.Node = &node.Node{
			Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:         nod.Signer.Public(),
			EntityID:   ent.Entity.ID,
			Expiration: uint64(expiration),
			VRF: &node.VRFInfo{
				ID: nodeIdentity.VRFSigner.Public(),
			},
			Runtimes: runtimes,
			Roles:    role,
		}
		addr := node.Address{
			TCPAddr: net.TCPAddr{
				IP:   []byte{192, 0, 2, byte(i + 1)},
				Port: 451,
			},
		}
		nod.Node.P2P.ID = nodeIdentity.P2PSigner.Public()
		nod.Node.P2P.Addresses = append(nod.Node.P2P.Addresses, addr)
		nod.Node.Consensus.ID = nodeIdentity.ConsensusSigner.Public()
		// Generate dummy TLS certificate.
		nod.Node.TLS.PubKey = nodeIdentity.GetTLSSigner().Public()
		nod.Node.TLS.Addresses = []node.TLSAddress{
			{
				PubKey:  nod.Node.TLS.PubKey,
				Address: addr,
			},
		}

		nod.SignedRegistration, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, nod.Node)
		if err != nil {
			return nil, err
		}

		// Append node's ID to entity's list of nodes, so we can register it.
		ent.Entity.Nodes = append(ent.Entity.Nodes, nod.Node.ID)

		// Add a registration with no P2P addresses.
		if nod.Node.Roles&node.RoleComputeWorker != 0 {
			invalid1 := &invalidNodeRegistration{
				descr: "register committee node without P2P addresses",
			}
			invNode1 := *nod.Node
			invNode1.P2P.Addresses = nil
			invalid1.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode1)
			if err != nil {
				return nil, err
			}
			nod.invalidBefore = append(nod.invalidBefore, invalid1)
		}

		// Add a registration with no TLS addresses.
		invalid2 := &invalidNodeRegistration{
			descr: "register node without TLS addresses",
		}
		invNode2 := *nod.Node
		invNode2.TLS.Addresses = nil
		invalid2.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode2)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid2)

		// Add a registration with no TLS public key.
		invalid3 := &invalidNodeRegistration{
			descr: "register node without TLS public key",
		}
		invNode3 := *nod.Node
		invNode3.TLS.PubKey = signature.PublicKey{}
		invalid3.signed, err = node.MultiSignNode(
			[]signature.Signer{
				nodeIdentity.NodeSigner,
				nodeIdentity.P2PSigner,
				nodeIdentity.ConsensusSigner,
				nodeIdentity.VRFSigner,
			},
			api.RegisterNodeSignatureContext,
			&invNode3,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid3)

		// Add a registration without any roles.
		invalid4 := &invalidNodeRegistration{
			descr: "register node without roles",
		}
		invNode4 := *nod.Node
		invNode4.Roles = 0
		invalid4.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode4)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid4)

		// Add a registration with reserved roles.
		invalid5 := &invalidNodeRegistration{
			descr: "register node with reserved roles",
		}
		invNode5 := *nod.Node
		invNode5.Roles = 0xFFFFFFFF
		invalid5.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode5)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid5)

		// Add a registration without a P2P ID.
		if nod.Node.Roles&node.RoleComputeWorker != 0 {
			invalid6 := &invalidNodeRegistration{
				descr: "register node without a valid p2p id",
			}
			invNode6 := *nod.Node
			invNode6.P2P.ID = signature.PublicKey{}
			invalid6.signed, err = node.MultiSignNode(
				[]signature.Signer{
					nodeIdentity.NodeSigner,
					nodeIdentity.ConsensusSigner,
					nodeIdentity.VRFSigner,
					nodeIdentity.GetTLSSigner(),
				},
				api.RegisterNodeSignatureContext,
				&invNode6,
			)
			if err != nil {
				return nil, err
			}
			nod.invalidBefore = append(nod.invalidBefore, invalid6)
		}

		// Add a registration without any runtimes.
		if nod.Node.Roles&node.RoleComputeWorker != 0 {
			invalid7 := &invalidNodeRegistration{
				descr: "register node without runtimes",
			}
			invNode7 := *nod.Node
			invNode7.Runtimes = nil
			invalid7.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode7)
			if err != nil {
				return nil, err
			}
			nod.invalidBefore = append(nod.invalidBefore, invalid7)
		}

		// Add a registration with invalid runtimes.
		invalid8 := &invalidNodeRegistration{
			descr: "register node with invalid runtimes",
		}
		invNode8 := *nod.Node
		invNode8.Runtimes = []*node.Runtime{{ID: publicKeyToNamespace(ent.Signer.Public(), false)}}
		invalid8.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode8)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid8)

		// Add a registration with invalid consensus address.
		invalid9 := &invalidNodeRegistration{
			descr: "register node with invalid consensus address",
		}
		invNode9 := *nod.Node
		invNode9.Consensus.Addresses = []node.ConsensusAddress{
			{
				ID:      invalidPK,
				Address: addr,
			},
		}
		invalid9.signed, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, &invNode9)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid9)

		// Add a registration with same consensus and P2P IDs.
		invalid10 := &invalidNodeRegistration{
			descr: "register node with same consensus and p2p IDs",
		}
		invNode10 := *nod.Node
		invNode10.Consensus.ID = invNode10.P2P.ID
		invalid10.signed, err = node.MultiSignNode(
			[]signature.Signer{
				nodeIdentity.NodeSigner,
				nodeIdentity.P2PSigner,
				nodeIdentity.VRFSigner,
				nodeIdentity.GetTLSSigner(),
			},
			api.RegisterNodeSignatureContext,
			&invNode10,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid10)

		// Add a registration with duplicate P2P ID.
		invalid11 := &invalidNodeRegistration{
			descr: "register node with duplicate p2p id",
		}
		invNode11 := *nod.Node
		invNode11.ID = invalidIdentity.NodeSigner.Public()
		invNode11.Consensus.ID = invalidIdentity.ConsensusSigner.Public()
		invNode11.TLS.PubKey = invalidIdentity.GetTLSSigner().Public()
		invalid11.signed, err = node.MultiSignNode(
			[]signature.Signer{
				invalidIdentity.NodeSigner,
				invalidIdentity.ConsensusSigner,
				nodeIdentity.P2PSigner,
				invalidIdentity.VRFSigner,
				invalidIdentity.GetTLSSigner(),
			},
			api.RegisterNodeSignatureContext,
			&invNode11,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidAfter = append(nod.invalidAfter, invalid11)

		// Add a registration with duplicate consensus ID.
		invalid12 := &invalidNodeRegistration{
			descr: "register node with duplicate consensus id",
		}
		invNode12 := *nod.Node
		invNode12.ID = invalidIdentity.NodeSigner.Public()
		invNode12.P2P.ID = invalidIdentity.ConsensusSigner.Public()
		invNode12.TLS.PubKey = invalidIdentity.GetTLSSigner().Public()
		invalid12.signed, err = node.MultiSignNode(
			[]signature.Signer{
				invalidIdentity.NodeSigner,
				nodeIdentity.ConsensusSigner,
				invalidIdentity.P2PSigner,
				invalidIdentity.VRFSigner,
				invalidIdentity.GetTLSSigner(),
			},
			api.RegisterNodeSignatureContext,
			&invNode12,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidAfter = append(nod.invalidAfter, invalid12)

		// Add a registration with duplicate public keys.
		invalid13 := &invalidNodeRegistration{
			descr: "register node with duplicate public keys",
		}
		invNode13 := *nod.Node
		invNode13.ID = invalidIdentity.NodeSigner.Public()
		invNode13.Consensus.ID = invalidIdentity.ConsensusSigner.Public()
		invNode13.P2P.ID = invalidIdentity.ConsensusSigner.Public()
		invalid13.signed, err = node.MultiSignNode(
			[]signature.Signer{
				invalidIdentity.NodeSigner,
				invalidIdentity.ConsensusSigner,
				invalidIdentity.P2PSigner,
				invalidIdentity.VRFSigner,
				nodeIdentity.GetTLSSigner(),
			},
			api.RegisterNodeSignatureContext,
			&invNode13,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidAfter = append(nod.invalidAfter, invalid13)

		// Add another Re-Registration with different address field and more runtimes.
		moreRuntimes := append([]*node.Runtime(nil), runtimes...)
		q := &api.GetRuntimesQuery{Height: consensusAPI.HeightLatest, IncludeSuspended: false}
		registeredRuntimes, err := consensus.Registry().GetRuntimes(context.Background(), q)
		if err != nil {
			return nil, err
		}
		rtMap := make(map[common.Namespace]*node.Runtime)
		for _, rt := range moreRuntimes {
			rtMap[rt.ID] = rt
		}
		for _, rt := range registeredRuntimes {
			if rt.Kind != api.KindCompute {
				continue
			}
			if _, exists := rtMap[rt.ID]; !exists {
				moreRuntimes = append(moreRuntimes, &node.Runtime{ID: rt.ID})
				break
			}
		}
		if len(moreRuntimes) <= len(runtimes) {
			panic("should find one additional compute runtime")
		}
		nod.UpdatedNode = &node.Node{
			Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:         nod.Signer.Public(),
			EntityID:   ent.Entity.ID,
			Expiration: uint64(expiration),
			Runtimes:   moreRuntimes,
			Roles:      role,
			VRF:        nod.Node.VRF,
		}
		addr = node.Address{
			TCPAddr: net.TCPAddr{
				IP:   []byte{192, 0, 2, byte(i + 1)},
				Port: 452,
			},
		}
		nod.UpdatedNode.P2P.ID = nod.Node.P2P.ID
		nod.UpdatedNode.P2P.Addresses = append(nod.UpdatedNode.P2P.Addresses, addr)
		nod.UpdatedNode.TLS.PubKey = nod.Node.TLS.PubKey
		nod.UpdatedNode.TLS.Addresses = nod.Node.TLS.Addresses
		nod.UpdatedNode.Consensus.ID = nod.Node.Consensus.ID // This should remain the same or we'll get "node update not allowed".
		nod.SignedValidReRegistration, err = node.MultiSignNode(nodeSigners, api.RegisterNodeSignatureContext, nod.UpdatedNode)
		if err != nil {
			return nil, err
		}

		// Add invalid Re-Registration with different runtimes.
		invalid14 := &invalidNodeRegistration{
			descr: "Re-registering a node with different runtimes should fail",
		}
		testRuntimeSigner := memorySigner.NewTestSigner("invalid-registration-runtime-seed")
		newRuntimes := []*node.Runtime{
			{ID: publicKeyToNamespace(testRuntimeSigner.Public(), false)},
		}
		newNode := &node.Node{
			Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:         nod.Signer.Public(),
			EntityID:   ent.Entity.ID,
			Expiration: uint64(expiration),
			Runtimes:   newRuntimes,
			Roles:      role,
			P2P:        nod.Node.P2P,
			TLS:        nod.Node.TLS,
		}
		newNode.P2P.ID = invalidIdentity.P2PSigner.Public()
		newNode.Consensus.ID = invalidIdentity.ConsensusSigner.Public()
		newNode.VRF = &node.VRFInfo{
			ID: invalidIdentity.VRFSigner.Public(),
		}
		newNode.TLS.PubKey = invalidIdentity.GetTLSSigner().Public()
		invalid14.signed, err = node.MultiSignNode(
			[]signature.Signer{
				nodeIdentity.NodeSigner,
				invalidIdentity.ConsensusSigner,
				invalidIdentity.P2PSigner,
				invalidIdentity.VRFSigner,
				invalidIdentity.GetTLSSigner(),
			},
			api.RegisterNodeSignatureContext,
			newNode,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidReReg = append(nod.invalidReReg, invalid14)

		// Add a registration with an old version.
		invalid15 := &invalidNodeRegistration{
			descr: "Registering with an old descriptor should fail",
		}
		invNode15 := *nod.Node
		invNode15.Versioned.V = 0
		invalid15.signed, err = node.MultiSignNode(
			[]signature.Signer{
				nodeIdentity.NodeSigner,
				nodeIdentity.ConsensusSigner,
				nodeIdentity.P2PSigner,
				nodeIdentity.VRFSigner,
				nodeIdentity.GetTLSSigner(),
			},
			api.RegisterNodeSignatureContext,
			&invNode15,
		)
		if err != nil {
			return nil, err
		}
		nod.invalidBefore = append(nod.invalidBefore, invalid15)

		nodes = append(nodes, &nod)
	}

	return nodes, nil
}

// NewTestEntities returns the specified number of TestEntities, generated
// deterministically from the seed.
func NewTestEntities(seed []byte, n int) ([]*TestEntity, error) {
	rng, err := drbg.New(crypto.SHA512, hashForDrbg(seed), nil, []byte("TestEntity"))
	if err != nil {
		return nil, err
	}

	entities := make([]*TestEntity, 0, n)
	for i := 0; i < n; i++ {
		var ent TestEntity
		if ent.Signer, err = memorySigner.NewSigner(rng); err != nil {
			return nil, err
		}
		ent.Entity = &entity.Entity{
			Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
			ID:        ent.Signer.Public(),
		}

		ent.SignedRegistration, err = entity.SignEntity(ent.Signer, api.RegisterEntitySignatureContext, ent.Entity)
		if err != nil {
			return nil, err
		}

		// Add a registration with an old version.
		invalid1 := &invalidEntityRegistration{
			descr: "Registering with an old descriptor should fail",
		}
		invEnt1 := *ent.Entity
		invEnt1.Versioned.V = 0
		invalid1.signed, err = entity.SignEntity(ent.Signer, api.RegisterEntitySignatureContext, &invEnt1)
		if err != nil {
			return nil, err
		}
		ent.invalidBefore = append(ent.invalidBefore, invalid1)

		entities = append(entities, &ent)
	}

	return entities, nil
}

// TestRuntime is a testing Runtime and some common pre-generated/signed
// blobs useful for testing.
type TestRuntime struct {
	Runtime *api.Runtime
	Signer  signature.Signer

	entity *TestEntity
	nodes  []*TestNode

	didRegister bool
}

// MustRegister registers the TestRuntime with the provided registry.
func (rt *TestRuntime) MustRegister(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	ch, sub, err := backend.WatchRuntimes(context.Background())
	require.NoError(err, "WatchRuntimes")
	defer sub.Close()

	tx := api.NewRegisterRuntimeTx(0, nil, rt.Runtime)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, rt.Signer, tx)
	require.NoError(err, "RegisterRuntime")

	var seen int
	for {
		select {
		case v := <-ch:
			if !rt.Runtime.ID.Equal(&v.ID) {
				continue
			}

			// If the runtime is expected to already be in the registry
			// (this is a re-registration), skip the event emitted
			// corresponding to the pre-existing entry.
			if seen > 0 || !rt.didRegister {
				require.EqualValues(rt.Runtime, v, "registered runtime")
				rt.didRegister = true

				// Make sure that GetEvents also returns the registration event.
				evts, err := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
				require.NoError(err, "GetEvents")
				var gotIt bool
				for _, evt := range evts {
					if evt.RuntimeEvent != nil {
						if evt.RuntimeEvent.Runtime.ID.Equal(&v.ID) {
							require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
							require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
							gotIt = true
							break
						}
					}
				}
				require.EqualValues(true, gotIt, "GetEvents should return runtime registration event")

				return
			}
			seen++
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive runtime registration event")
		}
	}
}

// MustNotRegister attempts to register the TestRuntime with the provided registry and expects failure.
func (rt *TestRuntime) MustNotRegister(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	tx := api.NewRegisterRuntimeTx(0, nil, rt.Runtime)
	err := consensusAPI.SignAndSubmitTx(context.Background(), consensus, rt.Signer, tx)
	require.Error(err, "RegisterRuntime failure")
}

// Populate populates the registry for a given TestRuntime.
func (rt *TestRuntime) Populate(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, seed []byte) []*node.Node {
	require := require.New(t)

	require.Nil(rt.entity, "runtime has no associated entity")
	require.Nil(rt.nodes, "runtime has no associated nodes")

	return BulkPopulate(t, backend, consensus, []*TestRuntime{rt}, seed)
}

// PopulateBulk bulk populates the registry for the given TestRuntimes.
func BulkPopulate(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, runtimes []*TestRuntime, seed []byte) []*node.Node {
	require := require.New(t)

	require.True(len(runtimes) > 0, "at least one runtime")
	EnsureRegistryClean(t, backend)

	// Create the one entity that has ownership of every single node.
	entityCh, entitySub, err := backend.WatchEntities(context.Background())
	require.NoError(err, "WatchEntities")
	defer entitySub.Close()

	entities, err := NewTestEntities(seed, 1)
	require.NoError(err, "NewTestEntities")
	ent := entities[0]

	var rts []*node.Runtime
	for _, v := range runtimes {
		v.MustRegister(t, backend, consensus)
		rts = append(rts, &node.Runtime{ID: v.Runtime.ID})
	}

	epoch, err := consensus.Beacon().GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	numCompute := int(runtimes[0].Runtime.Executor.GroupSize + runtimes[0].Runtime.Executor.GroupBackupSize)
	nodes, err := ent.NewTestNodes(numCompute, nil, rts, epoch+testRuntimeNodeExpiration, consensus)
	require.NoError(err, "NewTestNodes")

	for _, n := range nodes {
		ent.Entity.Nodes = addToNodeList(ent.Entity.Nodes, n.Node.ID)
	}
	ent.SignedRegistration, err = entity.SignEntity(ent.Signer, api.RegisterEntitySignatureContext, ent.Entity)
	require.NoError(err, "SignEntity")

	err = ent.Register(consensus, ent.SignedRegistration)
	require.NoError(err, "RegisterEntity")
	select {
	case ev := <-entityCh:
		require.EqualValues(ent.Entity, ev.Entity, "registered entity")
		require.True(ev.IsRegistration, "event is registration")

		// Make sure that GetEvents also returns the registration event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.EntityEvent != nil {
				if evt.EntityEvent.Entity.ID.Equal(ev.Entity.ID) && evt.EntityEvent.IsRegistration {
					require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
					require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return entity registration event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive entity registration event")
	}

	// For the sake of simplicity, require that all runtimes have the same
	// number of nodes for now.

	nodeCh, nodeSub, err := backend.WatchNodes(context.Background())
	require.NoError(err, "WatchNodes")
	defer nodeSub.Close()

	ret := make([]*node.Node, 0, numCompute)
	for _, node := range nodes {
		err = node.Register(consensus, node.SignedRegistration)
		require.NoError(err, "RegisterNode")
		select {
		case ev := <-nodeCh:
			require.EqualValues(node.Node, ev.Node, "registered node")
			require.True(ev.IsRegistration, "event is registration")

			// Make sure that GetEvents also returns the registration event.
			evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
			require.NoError(grr, "GetEvents")
			var gotIt bool
			for _, evt := range evts {
				if evt.NodeEvent != nil {
					if evt.NodeEvent.Node.ID.Equal(ev.Node.ID) && evt.NodeEvent.IsRegistration {
						require.False(evt.TxHash.IsEmpty(), "Event transaction hash should not be empty")
						require.Greater(evt.Height, int64(0), "Event height should be greater than zero")
						gotIt = true
						break
					}
				}
			}
			require.EqualValues(true, gotIt, "GetEvents should return node registration event")
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive node registration event")
		}
		ret = append(ret, node.Node)
	}

	for _, v := range runtimes {
		numNodes := v.Runtime.Executor.GroupSize + v.Runtime.Executor.GroupBackupSize
		require.EqualValues(len(nodes), numNodes, "runtime wants the expected number of nodes")
		v.entity = ent
		v.nodes = nodes
	}

	return ret
}

// TestNodes returns the test runtime's TestNodes.
func (rt *TestRuntime) TestNodes() []*TestNode {
	return rt.nodes
}

// Cleanup deregisteres the entity and nodes for a given TestRuntime.
func (rt *TestRuntime) Cleanup(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	require.NotNil(rt.entity, "runtime has an associated entity")
	require.NotNil(rt.nodes, "runtime has associated nodes")

	entityCh, entitySub, err := backend.WatchEntities(context.Background())
	require.NoError(err, "WatchEntities")
	defer entitySub.Close()

	nodeCh, nodeSub, err := backend.WatchNodes(context.Background())
	require.NoError(err, "WatchNodes")
	defer nodeSub.Close()

	// Make sure all nodes expire so we can remove the entity.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	_ = beaconTests.MustAdvanceEpochMulti(t, timeSource, consensus.Registry(), uint64(testRuntimeNodeExpiration+2))

	err = rt.entity.Deregister(consensus)
	require.NoError(err, "DeregisterEntity")

	select {
	case ev := <-entityCh:
		require.EqualValues(rt.entity.Entity, ev.Entity, "deregistered entity")
		require.False(ev.IsRegistration, "event is deregistration")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive entity deregistration event")
	}

	var numDereg int
	for numDereg < len(rt.nodes) {
		select {
		case ev := <-nodeCh:
			// Skip events not by runtime nodes.
			var found bool
			for _, nRt := range ev.Node.Runtimes {
				if nRt.ID.Equal(&rt.Runtime.ID) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
			require.False(ev.IsRegistration, "event is deregistration")
			numDereg++
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive node deregistration event")
		}
	}

	EnsureRegistryClean(t, backend)
	rt.entity = nil
	rt.nodes = nil
}

// NewTestRuntime returns a pre-generated TestRuntime for use with various
// tests, generated deterministically from the seed.
func NewTestRuntime(seed []byte, ent *TestEntity, isKeyManager bool) (*TestRuntime, error) {
	if ent == nil {
		ent = new(TestEntity)
		ent.Entity, ent.Signer, _ = entity.TestEntity()
	}

	flags := common.NamespaceTest
	if isKeyManager {
		flags = flags | common.NamespaceKeyManager
	}
	id := common.NewTestNamespaceFromSeed(seed, flags)

	var rt TestRuntime
	rt.Signer = ent.Signer
	rt.Runtime = &api.Runtime{
		Versioned: cbor.NewVersioned(api.LatestRuntimeDescriptorVersion),
		ID:        id,
		EntityID:  ent.Entity.ID,
		Kind:      api.KindCompute,
		Executor: api.ExecutorParameters{
			GroupSize:         3,
			GroupBackupSize:   5,
			AllowedStragglers: 1,
			RoundTimeout:      10,
			MaxMessages:       32,
		},
		TxnScheduler: api.TxnSchedulerParameters{
			Algorithm:         api.TxnSchedulerSimple,
			BatchFlushTimeout: 20 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			ProposerTimeout:   5,
		},
		AdmissionPolicy: api.RuntimeAdmissionPolicy{
			AnyNode: &api.AnyNodeRuntimeAdmissionPolicy{},
		},
		Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]api.SchedulingConstraints{
			scheduler.KindComputeExecutor: {
				scheduler.RoleWorker: {
					MinPoolSize: &api.MinPoolSizeConstraint{
						Limit: 3,
					},
				},
				scheduler.RoleBackupWorker: {
					MinPoolSize: &api.MinPoolSizeConstraint{
						Limit: 5,
					},
				},
			},
		},
		GovernanceModel: api.GovernanceEntity,
		Staking: api.RuntimeStakingParameters{
			Slashing: map[staking.SlashReason]staking.Slash{
				staking.SlashRuntimeEquivocation: {
					Amount: *quantity.NewFromUint64(math.MaxInt64),
				},
			},
			RewardSlashEquvocationRuntimePercent: 100,
		},
	}
	rt.Runtime.Genesis.StateRoot.Empty()

	return &rt, nil
}

func hashForDrbg(seed []byte) []byte {
	h := crypto.SHA512.New()
	_, _ = h.Write(seed)
	return h.Sum(nil)
}

func publicKeyToNamespace(pk signature.PublicKey, isKeyManager bool) common.Namespace {
	flags := common.NamespaceTest
	if isKeyManager {
		flags = flags | common.NamespaceKeyManager
	}

	// For testing purposes only, since this is sort of convenient.
	var rtID [common.NamespaceIDSize]byte
	copy(rtID[:], pk[:])
	ns, _ := common.NewNamespace(rtID, flags)

	return ns
}

// Similar to common.NewTestNamespaceFromSeed but doesn't assume test flag.
func newNamespaceFromSeed(seed []byte, flags common.NamespaceFlag) common.Namespace {
	h := hash.NewFromBytes(seed)

	var rtID [common.NamespaceIDSize]byte
	copy(rtID[:], h[:])

	ns, _ := common.NewNamespace(rtID, flags)
	return ns
}
