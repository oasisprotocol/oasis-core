// Package tests is a collection of registry implementation test cases.
package tests

import (
	"context"
	"crypto"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	"github.com/oasislabs/oasis-core/go/registry/api"
)

const (
	recvTimeout = 5 * time.Second

	testRuntimeNodeExpiration epochtime.EpochTime = 100
)

var entityNodeSeed = []byte("testRegistryEntityNodes")

// RegistryImplementationTests exercises the basic functionality of a
// registry backend.
//
// WARNING: This assumes that the registry is empty, and will leave
// a Runtime registered.
func RegistryImplementationTests(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	EnsureRegistryEmpty(t, backend)

	// We need a runtime ID as otherwise the registry will not allow us to
	// register nodes for roles which require runtimes.
	var runtimeID, runtimeEWID common.Namespace
	t.Run("Runtime", func(t *testing.T) {
		runtimeID, runtimeEWID = testRegistryRuntime(t, backend, consensus)
	})

	testRegistryEntityNodes(t, backend, consensus, runtimeID, runtimeEWID)
}

func testRegistryEntityNodes( // nolint: gocyclo
	t *testing.T,
	backend api.Backend,
	consensus consensusAPI.Backend,
	runtimeID common.Namespace,
	runtimeEWID common.Namespace,
) {
	// Generate the entities used for the test cases.
	entities, err := NewTestEntities(entityNodeSeed, 3)
	require.NoError(t, err, "NewTestEntities")

	timeSource := consensus.EpochTime().(epochtime.SetableBackend)
	epoch, err := timeSource.GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetEpoch")

	// All of these tests are combined because the Entity and Node structures
	// are linked togehter.

	entityCh, entitySub, err := backend.WatchEntities(context.Background())
	require.NoError(t, err, "WatchEntities")
	defer entitySub.Close()

	t.Run("EntityRegistration", func(t *testing.T) {
		require := require.New(t)

		for _, v := range entities {
			err = v.Register(consensus)
			require.NoError(err, "RegisterEntity")

			select {
			case ev := <-entityCh:
				require.EqualValues(v.Entity, ev.Entity, "registered entity")
				require.True(ev.IsRegistration, "event is registration")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive entity registration event")
			}
		}

		for _, v := range entities {
			var ent *entity.Entity
			ent, err = backend.GetEntity(context.Background(), &api.IDQuery{ID: v.Entity.ID, Height: consensusAPI.HeightLatest})
			require.NoError(err, "GetEntity")
			require.EqualValues(v.Entity, ent, "retrieved entity")
		}

		var registeredEntities []*entity.Entity
		registeredEntities, err = backend.GetEntities(context.Background(), consensusAPI.HeightLatest)
		require.NoError(err, "GetEntities")
		require.Len(registeredEntities, len(entities), "entities after registration")

		seen := make(map[signature.PublicKey]bool)
		for _, ent := range registeredEntities {
			var isValid bool
			for _, v := range entities {
				if v.Entity.ID.Equal(ent.ID) {
					require.EqualValues(v.Entity, ent, "bulk retrieved entity")
					seen[ent.ID] = true
					isValid = true
					break
				}
			}
			require.True(isValid, "bulk retrived entity was one registered")
		}
		require.Len(seen, len(entities), "unique bulk retrived entities")
	})

	// We rely on the runtime tests running before this registering a runtime.
	nodeRuntimes := []*node.Runtime{&node.Runtime{ID: runtimeID}}

	// Node tests, because there needs to be entities.
	var numNodes int
	nodes := make([][]*TestNode, 0, len(entities))
	for i, te := range entities {
		// Stagger the expirations so that it's possible to test it.
		var entityNodes []*TestNode
		entityNodes, err = te.NewTestNodes(i+1, 1, nil, nodeRuntimes, epoch+epochtime.EpochTime(i)+1)
		require.NoError(t, err, "NewTestNodes")

		nodes = append(nodes, entityNodes)
		numNodes += len(entityNodes)
	}
	nodeRuntimesEW := []*node.Runtime{&node.Runtime{ID: runtimeEWID}}
	whitelistedNodes, err := entities[1].NewTestNodes(1, 1, []byte("whitelistedNodes"), nodeRuntimesEW, epoch+2)
	require.NoError(t, err, "NewTestNodes whitelisted")
	nonWhitelistedNodes, err := entities[0].NewTestNodes(1, 1, []byte("nonWhitelistedNodes"), nodeRuntimesEW, epoch+2)
	require.NoError(t, err, "NewTestNodes non-whitelisted")

	nodeCh, nodeSub, err := backend.WatchNodes(context.Background())
	require.NoError(t, err, "WatchNodes")
	defer nodeSub.Close()

	t.Run("NodeRegistration", func(t *testing.T) {
		require := require.New(t)

		for _, tns := range nodes {
			for _, tn := range tns {
				if tn.Node.Roles&node.RoleComputeWorker != 0 {
					err = tn.Register(consensus, tn.SignedInvalidRegistration1)
					require.Error(err, "register committee node without P2P addresses")
					require.Equal(err, api.ErrInvalidArgument)
				}

				err = tn.Register(consensus, tn.SignedInvalidRegistration2)
				require.Error(err, "register committee node without committee addresses")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration3)
				require.Error(err, "register committee node without committee certificate")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration4)
				require.Error(err, "register node without roles")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration5)
				require.Error(err, "register node with reserved roles")
				require.Equal(err, api.ErrInvalidArgument)

				if tn.Node.Roles&node.RoleComputeWorker != 0 {
					err = tn.Register(consensus, tn.SignedInvalidRegistration6)
					require.Error(err, "register node without a valid p2p id")
					require.Equal(err, api.ErrInvalidArgument)
				}

				if tn.Node.Roles&node.RoleComputeWorker != 0 {
					err = tn.Register(consensus, tn.SignedInvalidRegistration7)
					require.Error(err, "register node without runtimes")
					require.Equal(err, api.ErrInvalidArgument)
				}

				err = tn.Register(consensus, tn.SignedInvalidRegistration8)
				require.Error(err, "register node with invalid runtimes")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration9)
				require.Error(err, "register node with invalid consensus address")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration10)
				require.Error(err, "register node with same consensus and p2p IDs")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedRegistration)
				require.NoError(err, "RegisterNode")

				select {
				case ev := <-nodeCh:
					require.EqualValues(tn.Node, ev.Node, "registered node")
					require.True(ev.IsRegistration, "event is registration")
				case <-time.After(recvTimeout):
					t.Fatalf("failed to receive node registration event")
				}

				var nod *node.Node
				nod, err = backend.GetNode(context.Background(), &api.IDQuery{ID: tn.Node.ID, Height: consensusAPI.HeightLatest})
				require.NoError(err, "GetNode")
				require.EqualValues(tn.Node, nod, "retrieved node")

				err = tn.Register(consensus, tn.SignedInvalidRegistration11)
				require.Error(err, "register node with duplicate p2p id")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration12)
				require.Error(err, "register node with duplicate consensus id")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedInvalidRegistration13)
				require.Error(err, "register node with duplicate certificate")
				require.Equal(err, api.ErrInvalidArgument)

				err = tn.Register(consensus, tn.SignedValidReRegistration)
				require.NoError(err, "Re-registering a node with different address should work")

				err = tn.Register(consensus, tn.SignedInvalidReRegistration)
				require.Error(err, "Re-registering a node with different runtimes should fail")
				require.Equal(err, api.ErrInvalidArgument)

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
			require.NoError(tn.Register(consensus, tn.SignedRegistration), "register node from whitelisted entity")

			select {
			case ev := <-nodeCh:
				require.EqualValues(tn.Node, ev.Node, "registered node, whitelisted")
				require.True(ev.IsRegistration, "event is registration, whitelisted")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive node registration event, whitelisted")
			}
		}
		for _, tn := range nonWhitelistedNodes {
			require.Error(tn.Register(consensus, tn.SignedRegistration), "register node from non whitelisted entity")
		}
	})

	getExpectedNodeList := func() []*node.Node {
		// Derive the expected node list.
		l := make([]*node.Node, 0, numNodes+len(whitelistedNodes))
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
		epoch = epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

		registeredNodes, nerr := backend.GetNodes(context.Background(), consensusAPI.HeightLatest)
		require.NoError(nerr, "GetNodes")
		require.EqualValues(expectedNodeList, registeredNodes, "node list")
	})

	t.Run("NodeUnfreeze", func(t *testing.T) {
		require := require.New(t)

		entity := entities[0]
		node := nodes[0][0]

		ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
		defer cancel()

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
		err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, entity.Signer, tx)
		require.NoError(err, "UnfreezeNode")

		// Try to unfreeze an invalid node (should fail).
		var unfreeze api.UnfreezeNode
		// Generate arbitrary invalid node ID.
		err = unfreeze.NodeID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		require.NoError(err, "UnmarshalHex")
		tx = api.NewUnfreezeNodeTx(0, nil, &unfreeze)
		err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, entity.Signer, tx)
		require.Error(err, "UnfreezeNode (with invalid node)")
		require.Equal(err, api.ErrNoSuchNode)

		// Try to unfreeze a node using the node signing key (should fail
		// as unfreeze must be signed by entity signing key).
		tx = api.NewUnfreezeNodeTx(0, nil, &api.UnfreezeNode{
			NodeID: node.Node.ID,
		})
		err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, node.Signer, tx)
		require.Error(err, "UnfreezeNode (with invalid signer)")
		require.Equal(err, api.ErrBadEntityForNode)
	})

	t.Run("NodeExpiration", func(t *testing.T) {
		require := require.New(t)

		// Advancing the epoch should result in the 0th entity's nodes
		// being deregistered due to expiration.
		expectedDeregEvents := len(nodes[0])
		deregisteredNodes := make(map[signature.PublicKey]*node.Node)

		epoch = epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

		for i := 0; i < expectedDeregEvents; i++ {
			select {
			case ev := <-nodeCh:
				require.False(ev.IsRegistration, "event is deregistration")
				deregisteredNodes[ev.Node.ID] = ev.Node
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
		registeredNodes, nerr := backend.GetNodes(context.Background(), consensusAPI.HeightLatest)
		require.NoError(nerr, "GetNodes")
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
		_ = epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

		// At this point it should only be possible to deregister 0th entity nodes.
		err := entities[0].Deregister(consensus)
		require.NoError(err, "DeregisterEntity - 0th entity")

		select {
		case ev := <-entityCh:
			require.EqualValues(entities[0].Entity, ev.Entity, "deregistered entity")
			require.False(ev.IsRegistration, "event is deregistration")
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
		_ = epochtimeTests.MustAdvanceEpoch(t, timeSource, uint64(len(entities)+2))

		// Now it should be possible to deregister all remaining entities.
		for _, v := range entities[1:] {
			err := v.Deregister(consensus)
			require.NoError(err, "DeregisterEntity")

			select {
			case ev := <-entityCh:
				require.EqualValues(v.Entity, ev.Entity, "deregistered entity")
				require.False(ev.IsRegistration, "event is deregistration")
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive entity deregistration event")
			}
		}

		// There should be no more entities.
		for _, v := range entities {
			_, err := backend.GetEntity(context.Background(), &api.IDQuery{ID: v.Entity.ID, Height: consensusAPI.HeightLatest})
			require.Equal(api.ErrNoSuchEntity, err, "GetEntity")
		}
	})

	t.Run("RemainingNodeExpiration", func(t *testing.T) {
		require := require.New(t)

		deregisteredNodes := make(map[signature.PublicKey]*node.Node)

		for i := 0; i < numNodes+len(whitelistedNodes); i++ {
			select {
			case ev := <-nodeCh:
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

	EnsureRegistryEmpty(t, backend)
}

func testRegistryRuntime(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) (common.Namespace, common.Namespace) {
	require := require.New(t)

	existingRuntimes, err := backend.GetRuntimes(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetRuntimes")

	entities, err := NewTestEntities([]byte("testRegistryEntity"), 1)
	require.NoError(err, "NewTestEntities()")

	entity := entities[0]
	err = entity.Register(consensus)
	require.NoError(err, "RegisterEntity")

	// Runtime without key manager set.
	rtMap := make(map[common.Namespace]*api.Runtime)
	rt, err := NewTestRuntime([]byte("testRegistryRuntime"), entity, false)
	require.NoError(err, "NewTestRuntime")
	rtMap[rt.Runtime.ID] = rt.Runtime

	rt.MustRegister(t, backend, consensus)

	// Runtime using entity whitelist node admission policy.
	rtEW, err := NewTestRuntime([]byte("testRegistryRuntimeEntityWhitelist"), entity, false)
	require.NoError(err, "NewTestRuntime entity whitelist")
	nodeEntities, err := NewTestEntities(entityNodeSeed, 3)
	require.NoError(err, "NewTestEntities with entity node seed")
	rtEW.Runtime.AdmissionPolicy = api.RuntimeAdmissionPolicy{
		EntityWhitelist: &api.EntityWhitelistRuntimeAdmissionPolicy{
			Entities: map[signature.PublicKey]bool{
				nodeEntities[1].Entity.ID: true,
			},
		},
	}
	rtMap[rtEW.Runtime.ID] = rtEW.Runtime

	rtEW.MustRegister(t, backend, consensus)

	// Runtime with unset node admission policy.
	rtUnsetAdmissionPolicy, err := NewTestRuntime([]byte("testRegistryRuntimeUnsetAdmissionPolicy"), entity, false)
	require.NoError(err, "NewTestRuntime unset admission policy")
	rtUnsetAdmissionPolicy.Runtime.AdmissionPolicy = api.RuntimeAdmissionPolicy{}

	rtUnsetAdmissionPolicy.MustNotRegister(t, backend, consensus)

	// Register key manager runtime.
	km, err := NewTestRuntime([]byte("testRegistryKM"), entity, true)
	km.Runtime.Kind = api.KindKeyManager
	require.NoError(err, "NewTestKm")
	km.MustRegister(t, backend, consensus)
	rtMap[km.Runtime.ID] = km.Runtime

	// Runtime with key manager set.
	rtKm, err := NewTestRuntime([]byte("testRegistryRuntimeWithKM"), entity, false)
	require.NoError(err, "NewTestRuntimeWithKM")
	rtKm.Runtime.KeyManager = &km.Runtime.ID
	rtKm.MustRegister(t, backend, consensus)
	rtMap[rtKm.Runtime.ID] = rtKm.Runtime

	registeredRuntimes, err := backend.GetRuntimes(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetRuntimes")
	// NOTE: There can be two runtimes registered here instead of one because the worker
	//       tests that run before this register their own runtime and this runtime
	//       cannot be deregistered.
	require.Len(registeredRuntimes, len(existingRuntimes)+4, "registry has four new runtimes")
	for _, regRuntime := range registeredRuntimes {
		if rtMap[regRuntime.ID] != nil {
			require.EqualValues(rtMap[regRuntime.ID], regRuntime, "expected runtime is registered")
			delete(rtMap, regRuntime.ID)
		}
	}
	require.Len(rtMap, 0, "all runtimes were registered")

	// Test runtime registration failures.
	// Non-existent key manager.
	rtWrongKm, err := NewTestRuntime([]byte("testRegistryRuntimeWithWrongKM"), entity, false)
	require.NoError(err, "NewTestRuntimeWithWrongKM")
	// Set Key manager ID to some wrong value.
	rtWrongKm.Runtime.KeyManager = &common.Namespace{0xab}

	rtWrongKm.MustNotRegister(t, backend, consensus)

	registeredRuntimesAfterFailures, err := backend.GetRuntimes(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetRuntimes")
	require.Len(registeredRuntimesAfterFailures, len(registeredRuntimes), "wrong runtimes not registered")

	// Subscribe to entity deregistration event.
	ch, sub, err := backend.WatchEntities(context.Background())
	require.NoError(err, "WatchEntities")
	defer sub.Close()

	err = entity.Deregister(consensus)
	require.NoError(err, "DeregisterEntity")

	select {
	case ev := <-ch:
		require.False(ev.IsRegistration, "expected entity deregistration event")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive entity deregistration event")
	}

	// No way to de-register the runtime, so it will be left there.

	return rt.Runtime.ID, rtEW.Runtime.ID
}

// EnsureRegistryEmpty enforces that the registry has no entities or nodes
// registered.
//
// Note: Runtimes are allowed, as there is no way to deregister them.
func EnsureRegistryEmpty(t *testing.T, backend api.Backend) {
	registeredEntities, err := backend.GetEntities(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetEntities")
	require.Len(t, registeredEntities, 0, "registered entities")

	registeredNodes, err := backend.GetNodes(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetNodes")
	require.Len(t, registeredNodes, 0, "registered nodes")
}

// TestEntity is a testing Entity and some common pre-generated/signed
// blobs useful for testing.
type TestEntity struct {
	Entity *entity.Entity
	Signer signature.Signer

	SignedRegistration *entity.SignedEntity
}

// Register attempts to register the entity.
func (ent *TestEntity) Register(consensus consensusAPI.Backend) error {
	return consensusAPI.SignAndSubmitTx(context.Background(), consensus, ent.Signer, api.NewRegisterEntityTx(0, nil, ent.SignedRegistration))
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

	SignedRegistration          *node.SignedNode
	SignedInvalidRegistration1  *node.SignedNode
	SignedInvalidRegistration2  *node.SignedNode
	SignedInvalidRegistration3  *node.SignedNode
	SignedInvalidRegistration4  *node.SignedNode
	SignedInvalidRegistration5  *node.SignedNode
	SignedInvalidRegistration6  *node.SignedNode
	SignedInvalidRegistration7  *node.SignedNode
	SignedInvalidRegistration8  *node.SignedNode
	SignedInvalidRegistration9  *node.SignedNode
	SignedInvalidRegistration10 *node.SignedNode
	SignedInvalidRegistration11 *node.SignedNode
	SignedInvalidRegistration12 *node.SignedNode
	SignedInvalidRegistration13 *node.SignedNode
	SignedValidReRegistration   *node.SignedNode
	SignedInvalidReRegistration *node.SignedNode
}

// Register attempts to register a node.
func (n *TestNode) Register(consensus consensusAPI.Backend, sigNode *node.SignedNode) error {
	// NOTE: Node registrations in tests are entity-signed.
	return consensusAPI.SignAndSubmitTx(context.Background(), consensus, n.Entity.Signer, api.NewRegisterNodeTx(0, nil, sigNode))
}

func randomPK(rng *drbg.Drbg) signature.PublicKey {
	signer, err := memorySigner.NewSigner(rng)
	if err != nil {
		panic(err)
	}
	return signer.Public()
}

func randomCert() []byte {
	tlsCert, err := tls.Generate(identity.CommonName)
	if err != nil {
		panic(err)
	}
	return tlsCert.Certificate[0]
}

// NewTestNodes returns the specified number of TestNodes, generated
// deterministically using the entity's public key as the seed.
func (ent *TestEntity) NewTestNodes(nCompute int, nStorage int, idNonce []byte, runtimes []*node.Runtime, expiration epochtime.EpochTime) ([]*TestNode, error) {
	if nCompute <= 0 || nStorage <= 0 || nCompute > 254 || nStorage > 254 {
		return nil, errors.New("registry/tests: test node count out of bounds")
	}
	n := nCompute + nStorage

	rng, err := drbg.New(crypto.SHA512, hashForDrbg(ent.Entity.ID[:]), idNonce, []byte("TestNodes"))
	if err != nil {
		return nil, err
	}

	nodes := make([]*TestNode, 0, n)
	for i := 0; i < n; i++ {
		var nod TestNode
		if nod.Signer, err = memorySigner.NewSigner(rng); err != nil {
			return nil, err
		}
		nod.Entity = ent

		var role node.RolesMask
		if i < nCompute {
			role = node.RoleComputeWorker
		} else {
			role = node.RoleStorageWorker
		}

		nod.Node = &node.Node{
			ID:         nod.Signer.Public(),
			EntityID:   ent.Entity.ID,
			Expiration: uint64(expiration),
			Runtimes:   runtimes,
			Roles:      role,
		}
		addr := node.Address{
			TCPAddr: net.TCPAddr{
				IP:   []byte{192, 0, 2, byte(i + 1)},
				Port: 451,
			},
		}
		nod.Node.P2P.ID = randomPK(rng)
		nod.Node.P2P.Addresses = append(nod.Node.P2P.Addresses, addr)
		nod.Node.Consensus.ID = randomPK(rng)
		// Generate dummy TLS certificate.
		nod.Node.Committee.Certificate = randomCert()
		nod.Node.Committee.Addresses = []node.CommitteeAddress{
			node.CommitteeAddress{
				Certificate: nod.Node.Committee.Certificate,
				Address:     addr,
			},
		}

		nod.SignedRegistration, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, nod.Node)
		if err != nil {
			return nil, err
		}

		// Add a registration with no P2P addresses.
		invalid1 := *nod.Node
		invalid1.P2P.Addresses = nil

		nod.SignedInvalidRegistration1, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid1)
		if err != nil {
			return nil, err
		}

		// Add a registration with no committee addresses.
		invalid2 := *nod.Node
		invalid2.Committee.Addresses = nil

		nod.SignedInvalidRegistration2, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid2)
		if err != nil {
			return nil, err
		}

		// Add a registration with no committee certificate.
		invalid3 := *nod.Node
		invalid3.Committee.Certificate = nil

		nod.SignedInvalidRegistration3, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid3)
		if err != nil {
			return nil, err
		}

		// Add a registration without any roles.
		invalid4 := *nod.Node
		invalid4.Roles = 0

		nod.SignedInvalidRegistration4, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid4)
		if err != nil {
			return nil, err
		}

		// Add a registration with reserved roles.
		invalid5 := *nod.Node
		invalid5.Roles = 0xFFFFFFFF

		nod.SignedInvalidRegistration5, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid5)
		if err != nil {
			return nil, err
		}

		// Add a registration without a P2P ID.
		invalid6 := *nod.Node
		invalid6.P2P.ID = signature.PublicKey{}

		nod.SignedInvalidRegistration6, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid6)
		if err != nil {
			return nil, err
		}

		// Add a registration without any runtimes.
		invalid7 := *nod.Node
		invalid7.Runtimes = nil

		nod.SignedInvalidRegistration7, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid7)
		if err != nil {
			return nil, err
		}

		// Add a registration with invalid runtimes.
		invalid8 := *nod.Node
		invalid8.Runtimes = []*node.Runtime{&node.Runtime{ID: publicKeyToNamespace(ent.Signer.Public(), false)}}

		nod.SignedInvalidRegistration8, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid8)
		if err != nil {
			return nil, err
		}

		// Add a registration with invalid consensus address.
		invalid9 := *nod.Node
		invalid9.Consensus.Addresses = []node.ConsensusAddress{
			node.ConsensusAddress{
				// ID: invalid
				Address: addr,
			},
		}

		nod.SignedInvalidRegistration9, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid9)
		if err != nil {
			return nil, err
		}

		// Add a registration with same consensus and P2P IDs.
		invalid10 := *nod.Node
		invalid10.P2P.ID = randomPK(rng)
		invalid10.Consensus.ID = invalid10.P2P.ID

		nod.SignedInvalidRegistration10, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid10)
		if err != nil {
			return nil, err
		}

		// Add a registration with duplicate P2P ID.
		invalid11 := *nod.Node
		invalid11.ID = randomPK(rng)
		invalid11.Consensus.ID = randomPK(rng)
		invalid11.Committee.Certificate = randomCert()

		nod.SignedInvalidRegistration11, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid11)
		if err != nil {
			return nil, err
		}

		// Add a registration with duplicate consensus ID.
		invalid12 := *nod.Node
		invalid12.ID = randomPK(rng)
		invalid12.P2P.ID = randomPK(rng)
		invalid12.Committee.Certificate = randomCert()

		nod.SignedInvalidRegistration12, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid12)
		if err != nil {
			return nil, err
		}

		// Add a registration with duplicate certificate.
		invalid13 := *nod.Node
		invalid13.ID = randomPK(rng)
		invalid13.P2P.ID = randomPK(rng)
		invalid13.Consensus.ID = randomPK(rng)

		nod.SignedInvalidRegistration13, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, &invalid13)
		if err != nil {
			return nil, err
		}

		// Add another Re-Registration with different address field.
		nod.UpdatedNode = &node.Node{
			ID:         nod.Signer.Public(),
			EntityID:   ent.Entity.ID,
			Expiration: uint64(expiration),
			Runtimes:   runtimes,
			Roles:      role,
		}
		addr = node.Address{
			TCPAddr: net.TCPAddr{
				IP:   []byte{192, 0, 2, byte(i + 1)},
				Port: 452,
			},
		}
		nod.UpdatedNode.P2P.ID = nod.Node.P2P.ID
		nod.UpdatedNode.P2P.Addresses = append(nod.UpdatedNode.P2P.Addresses, addr)
		nod.UpdatedNode.Committee.Certificate = nod.Node.Committee.Certificate
		nod.UpdatedNode.Committee.Addresses = nod.Node.Committee.Addresses
		nod.UpdatedNode.Consensus.ID = nod.Node.Consensus.ID // This should remain the same or we'll get "node update not allowed".
		nod.SignedValidReRegistration, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, nod.UpdatedNode)
		if err != nil {
			return nil, err
		}

		// Add invalid Re-Registration with changed Runtimes field.
		testRuntimeSigner := memorySigner.NewTestSigner("invalid-registration-runtime-seed")
		newRuntimes := append([]*node.Runtime(nil), runtimes...)
		newRuntimes = append(newRuntimes, &node.Runtime{ID: publicKeyToNamespace(testRuntimeSigner.Public(), false)})
		newNode := &node.Node{
			ID:         nod.Signer.Public(),
			EntityID:   ent.Entity.ID,
			Expiration: uint64(expiration),
			Runtimes:   newRuntimes,
			Roles:      role,
			P2P:        nod.Node.P2P,
			Committee:  nod.Node.Committee,
		}
		newNode.P2P.ID = randomPK(rng)
		newNode.Consensus.ID = randomPK(rng)
		newNode.Committee.Certificate = randomCert()
		nod.SignedInvalidReRegistration, err = node.SignNode(ent.Signer, api.RegisterNodeSignatureContext, newNode)
		if err != nil {
			return nil, err
		}

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
			ID:                     ent.Signer.Public(),
			AllowEntitySignedNodes: true,
		}

		signed, err := signature.SignSigned(ent.Signer, api.RegisterEntitySignatureContext, ent.Entity)
		if err != nil {
			return nil, err
		}
		ent.SignedRegistration = &entity.SignedEntity{Signed: *signed}

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

	signed, err := signature.SignSigned(rt.Signer, api.RegisterRuntimeSignatureContext, rt.Runtime)
	require.NoError(err, "signed runtime descriptor")

	tx := api.NewRegisterRuntimeTx(0, nil, &api.SignedRuntime{Signed: *signed})
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

	signed, err := signature.SignSigned(rt.Signer, api.RegisterRuntimeSignatureContext, rt.Runtime)
	require.NoError(err, "signed runtime descriptor")

	tx := api.NewRegisterRuntimeTx(0, nil, &api.SignedRuntime{Signed: *signed})
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, rt.Signer, tx)
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
	EnsureRegistryEmpty(t, backend)

	// Create the one entity that has ownership of every single node
	// that will be associated with every runtime.
	entityCh, entitySub, err := backend.WatchEntities(context.Background())
	require.NoError(err, "WatchEntities")
	defer entitySub.Close()

	entities, err := NewTestEntities(seed, 1)
	require.NoError(err, "NewTestEntities")
	entity := entities[0]
	err = entity.Register(consensus)
	require.NoError(err, "RegisterEntity")
	select {
	case ev := <-entityCh:
		require.EqualValues(entity.Entity, ev.Entity, "registered entity")
		require.True(ev.IsRegistration, "event is registration")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive entity registration event")
	}

	var rts []*node.Runtime
	for _, v := range runtimes {
		v.Signer = entity.Signer
		v.MustRegister(t, backend, consensus)
		rts = append(rts, &node.Runtime{ID: v.Runtime.ID})
	}

	// For the sake of simplicity, require that all runtimes have the same
	// number of nodes for now.

	nodeCh, nodeSub, err := backend.WatchNodes(context.Background())
	require.NoError(err, "WatchNodes")
	defer nodeSub.Close()

	epoch, err := consensus.EpochTime().GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	numCompute := int(runtimes[0].Runtime.Executor.GroupSize + runtimes[0].Runtime.Executor.GroupBackupSize)
	numStorage := int(runtimes[0].Runtime.Storage.GroupSize)
	nodes, err := entity.NewTestNodes(numCompute, numStorage, nil, rts, epoch+testRuntimeNodeExpiration)
	require.NoError(err, "NewTestNodes")

	ret := make([]*node.Node, 0, numCompute+numStorage)
	for _, node := range nodes {
		err = node.Register(consensus, node.SignedRegistration)
		require.NoError(err, "RegisterNode")
		select {
		case ev := <-nodeCh:
			require.EqualValues(node.Node, ev.Node, "registered node")
			require.True(ev.IsRegistration, "event is registration")
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive node registration event")
		}
		ret = append(ret, node.Node)
	}

	for _, v := range runtimes {
		numNodes := v.Runtime.Executor.GroupSize + v.Runtime.Executor.GroupBackupSize + v.Runtime.Storage.GroupSize
		require.EqualValues(len(nodes), numNodes, "runtime wants the expected number of nodes")
		v.entity = entity
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
	timeSource := consensus.EpochTime().(epochtime.SetableBackend)
	_ = epochtimeTests.MustAdvanceEpoch(t, timeSource, uint64(testRuntimeNodeExpiration+2))

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
			require.False(ev.IsRegistration, "event is deregistration")
			numDereg++
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive node deregistration event")
		}
	}

	EnsureRegistryEmpty(t, backend)
	rt.entity = nil
	rt.nodes = nil
}

// NewTestRuntime returns a pre-generated TestRuntime for use with various
// tests, generated deterministically from the seed.
func NewTestRuntime(seed []byte, entity *TestEntity, isKeyManager bool) (*TestRuntime, error) {
	rng, err := drbg.New(crypto.SHA512, hashForDrbg(seed), nil, []byte("TestRuntime"))
	if err != nil {
		return nil, err
	}

	var rt TestRuntime
	if rt.Signer, err = memorySigner.NewSigner(rng); err != nil {
		return nil, err
	}

	rt.Runtime = &api.Runtime{
		ID:   publicKeyToNamespace(rt.Signer.Public(), isKeyManager),
		Kind: api.KindCompute,
		Executor: api.ExecutorParameters{
			GroupSize:         3,
			GroupBackupSize:   5,
			AllowedStragglers: 1,
			RoundTimeout:      20 * time.Second,
		},
		Merge: api.MergeParameters{
			GroupSize:         3,
			GroupBackupSize:   5,
			AllowedStragglers: 1,
			RoundTimeout:      20 * time.Second,
		},
		TxnScheduler: api.TxnSchedulerParameters{
			GroupSize:         3,
			Algorithm:         api.TxnSchedulerAlgorithmBatching,
			BatchFlushTimeout: 20 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1000,
		},
		Storage: api.StorageParameters{GroupSize: 3},
		AdmissionPolicy: api.RuntimeAdmissionPolicy{
			AnyNode: &api.AnyNodeRuntimeAdmissionPolicy{},
		},
	}
	if entity != nil {
		rt.Signer = entity.Signer
	}

	// TODO: Test with non-empty state root when enabled.
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
