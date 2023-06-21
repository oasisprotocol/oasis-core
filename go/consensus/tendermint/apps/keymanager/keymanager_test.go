package keymanager

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func TestGenerateStatus(t *testing.T) {
	// Prepare context.
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	// Prepare app.
	app := &keymanagerApplication{
		state: appState,
	}

	// Prepare vars.
	params := &registry.ConsensusParameters{}
	policy := api.SignedPolicySGX{
		Policy: api.PolicySGX{
			Serial: 1,
		},
	}
	policyChecksum := sha3.Sum256(cbor.Marshal(policy))
	epoch := beacon.EpochTime(10)
	checksum := []byte{1, 2, 3, 4, 5}

	// Prepare two responses so that we can test nodes running different versions.
	rakSigner := api.TestSigners[0]
	initResponse := api.InitResponse{
		IsSecure:       true,
		Checksum:       checksum,
		PolicyChecksum: policyChecksum[:],
	}
	sigInitResponse, err := api.SignInitResponse(rakSigner, &initResponse)
	require.NoError(t, err, "SignInitResponse")

	initResponse.IsSecure = false
	sigInitResponseInsecure, err := api.SignInitResponse(rakSigner, &initResponse)
	require.NoError(t, err, "SignInitResponse")

	// Two key manager runtimes, one compute runtime.
	runtimeIDs := make([]common.Namespace, 3)
	require.NoError(t, runtimeIDs[0].UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"), "runtime 0 (keymanager)")
	require.NoError(t, runtimeIDs[1].UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001"), "runtime 1 (keymanager)")
	require.NoError(t, runtimeIDs[2].UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000002"), "runtime 2")

	// Initial key manager statuses.
	initializedStatus := &api.Status{
		ID:            runtimeIDs[0],
		IsInitialized: true,
		IsSecure:      true,
		Checksum:      checksum,
		Policy:        &policy,
	}
	uninitializedStatus := &api.Status{
		ID:     runtimeIDs[0],
		Policy: &policy,
	}

	// Node runtimes.
	nodeRuntimes := []*node.Runtime{
		// Key manager 1, version 1.0.0 (insecure enclave)
		{
			ID:        runtimeIDs[0],
			Version:   version.Version{Major: 1, Minor: 0, Patch: 0},
			ExtraInfo: cbor.Marshal(sigInitResponseInsecure),
		},
		// Key manager 1, version 2.0.0
		{
			ID:        runtimeIDs[0],
			Version:   version.Version{Major: 2, Minor: 0, Patch: 0},
			ExtraInfo: cbor.Marshal(sigInitResponse),
		},
		// Key manager 1, version 3.0.0
		{
			ID:        runtimeIDs[0],
			Version:   version.Version{Major: 3, Minor: 0, Patch: 0},
			ExtraInfo: cbor.Marshal(sigInitResponse),
		},
		// Key manager 2, version 1.0.0
		{
			ID:        runtimeIDs[1],
			Version:   version.Version{Major: 1, Minor: 0, Patch: 0},
			ExtraInfo: cbor.Marshal(sigInitResponse),
		},
		// Key manager 2, version 2.0.0
		{
			ID:        runtimeIDs[1],
			Version:   version.Version{Major: 2, Minor: 0, Patch: 0},
			ExtraInfo: cbor.Marshal(sigInitResponse),
		},
		// Runtime 1, version 1.0.0
		{
			ID:      runtimeIDs[2],
			Version: version.Version{Major: 1, Minor: 0, Patch: 0},
		},
	}

	// Key manager runtimes.
	runtimes := []*registry.Runtime{
		{
			ID:          runtimeIDs[0],
			TEEHardware: node.TEEHardwareInvalid,
		},
		{
			ID:          runtimeIDs[1],
			TEEHardware: node.TEEHardwareInvalid,
		},
	}

	// Nodes
	nodes := []*node.Node{
		// Validator node.
		{
			ID:         memorySigner.NewTestSigner("node 0").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleValidator,
			Runtimes:   nodeRuntimes[0:1],
		},
		// Expired.
		{
			ID:         memorySigner.NewTestSigner("node 1").Public(),
			Expiration: uint64(epoch) - 1,
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[0:1],
		},
		// No runtimes.
		{
			ID:         memorySigner.NewTestSigner("node 2").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   []*node.Runtime{},
		},
		// Compute runtime.
		{
			ID:         memorySigner.NewTestSigner("node 3").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[5:6],
		},
		// The second key manager.
		{
			ID:         memorySigner.NewTestSigner("node 4").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[3:5],
		},
		// One key manager, incompatible versions.
		{
			ID:         memorySigner.NewTestSigner("node 5").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[0:3],
		},
		// One key manager, one version (secure = false).
		{
			ID:         memorySigner.NewTestSigner("node 6").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[0:1],
		},
		// One key managers, two versions (secure = true).
		{
			ID:         memorySigner.NewTestSigner("node 7").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[1:3],
		},
		// Two key managers, two versions.
		{
			ID:         memorySigner.NewTestSigner("node 8").Public(),
			Expiration: uint64(epoch),
			Roles:      node.RoleKeyManager,
			Runtimes:   nodeRuntimes[1:5],
		},
	}

	t.Run("No nodes", func(t *testing.T) {
		require := require.New(t)

		newStatus := app.generateStatus(ctx, runtimes[0], uninitializedStatus, nodes[0:6], params, epoch)
		require.Equal(uninitializedStatus, newStatus, "key manager committee should be empty")

		newStatus = app.generateStatus(ctx, runtimes[0], initializedStatus, nodes[0:6], params, epoch)
		require.Equal(initializedStatus, newStatus, "key manager committee should be empty")
	})

	t.Run("One node", func(t *testing.T) {
		require := require.New(t)

		// Node 6 (secure = false)
		expStatus := &api.Status{
			ID:            runtimeIDs[0],
			IsInitialized: true,
			IsSecure:      false,
			Checksum:      checksum,
			Policy:        &policy,
			Nodes:         []signature.PublicKey{nodes[6].ID},
		}
		newStatus := app.generateStatus(ctx, runtimes[0], uninitializedStatus, nodes[6:7], params, epoch)
		require.Equal(expStatus, newStatus, "node 6 should form the committee if key manager not initialized")

		newStatus = app.generateStatus(ctx, runtimes[0], expStatus, nodes[6:7], params, epoch)
		require.Equal(expStatus, newStatus, "node 6 should form the committee if key manager is not secure")

		expStatus.IsSecure = true
		expStatus.Nodes = nil
		newStatus = app.generateStatus(ctx, runtimes[0], initializedStatus, nodes[6:7], params, epoch)
		require.Equal(expStatus, newStatus, "node 6 should not be added to the committee if key manager is secure")
	})

	t.Run("Multiple nodes", func(t *testing.T) {
		require := require.New(t)

		// The first node is the source of truth when constructing a committee. If the node 6 is
		// processed before nodes 7 and 8, the latter won't be accepted as they are secure.
		expStatus := &api.Status{
			ID:            runtimeIDs[0],
			IsInitialized: true,
			IsSecure:      false,
			Checksum:      checksum,
			Policy:        &policy,
			Nodes:         []signature.PublicKey{nodes[6].ID},
		}
		newStatus := app.generateStatus(ctx, runtimes[0], uninitializedStatus, nodes, params, epoch)
		require.Equal(expStatus, newStatus, "node 6 should form the committee if node 6 is the source of truth")

		// If the order is reversed, it should be the other way around.
		expStatus.IsSecure = true
		expStatus.Nodes = []signature.PublicKey{nodes[8].ID, nodes[7].ID}
		newStatus = app.generateStatus(ctx, runtimes[0], uninitializedStatus, reverse(nodes), params, epoch)
		require.Equal(expStatus, newStatus, "node 7 and 8 should form the committee if node 8 is the source of truth")

		// If the key manager is not secure, then nodes 7 and 8 are ignored.
		initializedStatus.IsSecure = false
		expStatus.IsSecure = false
		expStatus.Nodes = []signature.PublicKey{nodes[6].ID}
		newStatus = app.generateStatus(ctx, runtimes[0], initializedStatus, reverse(nodes), params, epoch)
		require.Equal(expStatus, newStatus, "node 6 should form the committee if key manager is not secure")

		// If the key manager is secure, then node 6 is ignored.
		initializedStatus.IsSecure = true
		expStatus.IsSecure = true
		expStatus.Nodes = []signature.PublicKey{nodes[7].ID, nodes[8].ID}
		newStatus = app.generateStatus(ctx, runtimes[0], initializedStatus, nodes, params, epoch)
		require.Equal(expStatus, newStatus, "node 7 and 8 should form the committee if key manager is secure")

		// The second key manager.
		expStatus.ID = runtimes[1].ID
		expStatus.Nodes = []signature.PublicKey{nodes[4].ID, nodes[8].ID}
		newStatus = app.generateStatus(ctx, runtimes[1], uninitializedStatus, nodes, params, epoch)
		require.Equal(expStatus, newStatus, "node 4 and 8 should form the committee")

		newStatus = app.generateStatus(ctx, runtimes[1], initializedStatus, nodes, params, epoch)
		require.Equal(expStatus, newStatus, "node 4 and 8 should form the committee")

		expStatus.Nodes = []signature.PublicKey{nodes[8].ID, nodes[4].ID}
		newStatus = app.generateStatus(ctx, runtimes[1], initializedStatus, reverse(nodes), params, epoch)
		require.Equal(expStatus, newStatus, "node 4 and 8 should form the committee")
	})
}

func reverse(nodes []*node.Node) []*node.Node {
	reversed := make([]*node.Node, len(nodes))
	for i, n := range nodes {
		reversed[len(nodes)-1-i] = n
	}
	return reversed
}
