package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

type mockNodeLookup struct {
	nodesList []*node.Node
}

func (n *mockNodeLookup) NodeBySubKey(ctx context.Context, key signature.PublicKey) (*node.Node, error) {
	for _, nd := range n.nodesList {
		if nd.ID.Equal(key) {
			return nd, nil
		}
		if nd.Consensus.ID.Equal(key) {
			return nd, nil
		}
		if nd.P2P.ID.Equal(key) {
			return nd, nil
		}
		if nd.TLS.PubKey.Equal(key) {
			return nd, nil
		}
	}
	return nil, ErrNoSuchNode
}

func (n *mockNodeLookup) Nodes(ctx context.Context) ([]*node.Node, error) {
	return n.nodesList, nil
}

type mockRuntimeLookup struct {
	runtimes map[common.Namespace]*Runtime
}

func (rl *mockRuntimeLookup) Runtime(ctx context.Context, id common.Namespace) (*Runtime, error) {
	panic("not implemented")
}

func (rl *mockRuntimeLookup) SuspendedRuntime(ctx context.Context, id common.Namespace) (*Runtime, error) {
	panic("not implemented")
}

func (rl *mockRuntimeLookup) AnyRuntime(ctx context.Context, id common.Namespace) (*Runtime, error) {
	if rl.runtimes[id] != nil {
		return rl.runtimes[id], nil
	}
	return nil, ErrNoSuchRuntime
}

func (rl *mockRuntimeLookup) AllRuntimes(ctx context.Context) ([]*Runtime, error) {
	panic("not implemented")
}

func (rl *mockRuntimeLookup) Runtimes(ctx context.Context) ([]*Runtime, error) {
	panic("not implemented")
}

func TestVerifyRegisterNodeArgs(t *testing.T) {
	require := require.New(t)

	logger := logging.GetLogger("registry/api/tests")

	entityID1 := signature.NewPublicKey("1000000000000000000000000000000000000000000000000000000000000001")
	nodeSigner := memorySigner.NewTestSigner("node tests signer")
	nodeConsensusSigner := memorySigner.NewTestSigner("node registry tests consensus signer")
	nodeP2PSigner := memorySigner.NewTestSigner("node registry tests P2P signer")
	nodeTLSSigner := memorySigner.NewTestSigner("node registry tests TLS signer")
	nodeVRFSigner := memorySigner.NewTestSigner("node registry tests VRF signer")
	nodeSigners := []signature.Signer{
		nodeSigner,
		nodeP2PSigner,
		nodeTLSSigner,
		nodeVRFSigner,
		nodeConsensusSigner,
	}

	params := &ConsensusParameters{
		DebugAllowUnroutableAddresses: true,
		MaxNodeExpiration:             10,
		EnableRuntimeGovernanceModels: map[RuntimeGovernanceModel]bool{
			GovernanceConsensus: true,
			GovernanceEntity:    true,
			GovernanceRuntime:   true,
		},
	}
	ndLookup := &mockNodeLookup{}
	rtLookup := &mockRuntimeLookup{
		runtimes: map[common.Namespace]*Runtime{},
	}

	entity := &entity.Entity{
		ID:    entityID1,
		Nodes: []signature.PublicKey{nodeSigner.Public()},
	}

	for _, tc := range []struct {
		n   node.Node
		err error
		msg string
	}{
		{
			node.Node{
				Versioned: cbor.NewVersioned(2),
				ID:        nodeSigner.Public(),
				EntityID:  entityID1,
				Consensus: node.ConsensusInfo{
					ID: nodeConsensusSigner.Public(),
					Addresses: []node.ConsensusAddress{
						{ID: nodeConsensusSigner.Public(), Address: node.Address{IP: net.IPv4(127, 0, 0, 1), Port: 9000}},
					},
				},
				TLS: node.TLSInfo{
					PubKey: nodeTLSSigner.Public(),
				},
				P2P: node.P2PInfo{
					ID: nodeP2PSigner.Public(),
				},
				VRF: &node.VRFInfo{
					ID: nodeVRFSigner.Public(),
				},
				Roles:      node.RoleConsensusRPC,
				Expiration: 11,
			},
			ErrInvalidArgument,
			"invalid consensus RPC node (missing TLS address)",
		},
		{
			node.Node{
				Versioned: cbor.NewVersioned(2),
				ID:        nodeSigner.Public(),
				EntityID:  entityID1,
				Consensus: node.ConsensusInfo{
					ID: nodeConsensusSigner.Public(),
					Addresses: []node.ConsensusAddress{
						{ID: nodeConsensusSigner.Public(), Address: node.Address{IP: net.IPv4(127, 0, 0, 1), Port: 9000}},
					},
				},
				TLS: node.TLSInfo{
					PubKey: nodeTLSSigner.Public(),
					Addresses: []node.TLSAddress{
						{
							PubKey:  nodeTLSSigner.Public(),
							Address: node.Address{IP: net.IPv4(127, 0, 0, 2), Port: 9001},
						},
					},
				},
				P2P: node.P2PInfo{
					ID: nodeP2PSigner.Public(),
				},
				VRF: &node.VRFInfo{
					ID: nodeVRFSigner.Public(),
				},
				Roles:      node.RoleConsensusRPC,
				Expiration: 11,
			},
			nil,
			"valid consensus RPC node",
		},
		{
			node.Node{
				Versioned: cbor.NewVersioned(2),
				ID:        nodeSigner.Public(),
				EntityID:  entityID1,
				Consensus: node.ConsensusInfo{
					ID: nodeConsensusSigner.Public(),
					Addresses: []node.ConsensusAddress{
						{ID: nodeConsensusSigner.Public(), Address: node.Address{IP: net.IPv4(127, 0, 0, 1), Port: 9000}},
					},
				},
				TLS: node.TLSInfo{
					PubKey: nodeTLSSigner.Public(),
					Addresses: []node.TLSAddress{
						{
							PubKey:  nodeTLSSigner.Public(),
							Address: node.Address{IP: net.IPv4(127, 0, 0, 2), Port: 9001},
						},
					},
				},
				P2P: node.P2PInfo{
					ID: nodeP2PSigner.Public(),
				},
				VRF: &node.VRFInfo{
					ID: nodeVRFSigner.Public(),
				},
				Roles:      node.RoleComputeWorker,
				Expiration: 11,
				Runtimes: []*node.Runtime{
					nil,
				},
			},
			ErrInvalidArgument,
			"invalid compute worker node (nil runtime)",
		},
	} {

		signedNode, err := node.MultiSignNode(
			nodeSigners,
			RegisterGenesisNodeSignatureContext,
			&tc.n,
		)
		require.NoError(err, "singing node")
		_, _, err = VerifyRegisterNodeArgs(context.Background(), params, logger, signedNode, entity, time.Now(), 1, false, false, beacon.EpochTime(10), rtLookup, ndLookup)
		switch {
		case tc.err == nil:
			require.NoError(err, tc.msg)
		default:
			require.True(errors.Is(err, tc.err), fmt.Sprintf("expected err: '%v', got: '%v', for: %s", tc.err, err, tc.msg))
		}
	}
}

func TestVerifyNodeUpdate(t *testing.T) {
	logger := logging.GetLogger("registry/api/tests")

	rtID1 := common.NewTestNamespaceFromSeed([]byte("runtime 1"), 0)
	nodeID1 := signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000001")
	nodeID2 := signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000002")
	consensusID1 := signature.NewPublicKey("0100000000000000000000000000000000000000000000000000000000000001")
	consensusID2 := signature.NewPublicKey("0100000000000000000000000000000000000000000000000000000000000002")
	entityID1 := signature.NewPublicKey("1000000000000000000000000000000000000000000000000000000000000001")
	entityID2 := signature.NewPublicKey("1000000000000000000000000000000000000000000000000000000000000002")

	lookup := &mockRuntimeLookup{
		runtimes: map[common.Namespace]*Runtime{
			rtID1: {
				Deployments: []*VersionInfo{{}},
			},
		},
	}

	existingNode := node.Node{
		ID:       nodeID1,
		EntityID: entityID1,
		Consensus: node.ConsensusInfo{
			ID: consensusID1,
		},
		Roles: node.RoleComputeWorker,
		Runtimes: []*node.Runtime{
			{ID: rtID1},
		},
		Expiration: 1,
	}
	for _, tc := range []struct {
		nodeFn func() *node.Node
		epoch  beacon.EpochTime
		err    error
		msg    string
	}{
		{
			nodeFn: func() *node.Node {
				return &existingNode
			},
			epoch: 0,
			err:   nil,
			msg:   "same node update should be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.ID = nodeID2
				return &nd
			},
			epoch: 0,
			err:   ErrNodeUpdateNotAllowed,
			msg:   "node ID update should not be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.EntityID = entityID2
				return &nd
			},
			epoch: 0,
			err:   ErrNodeUpdateNotAllowed,
			msg:   "node entity ID update should not be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.Consensus.ID = consensusID2
				return &nd
			},
			epoch: 0,
			err:   ErrNodeUpdateNotAllowed,
			msg:   "node consensus ID update should not be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.Roles = 0
				return &nd
			},
			epoch: 0,
			err:   ErrNodeUpdateNotAllowed,
			msg:   "node roles update should not be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.Runtimes = []*node.Runtime{}
				return &nd
			},
			epoch: 0,
			err:   ErrNodeUpdateNotAllowed,
			msg:   "node removing runtimes update should not be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.Roles = 0
				return &nd
			},
			epoch: 10,
			err:   nil,
			msg:   "expired node roles update should be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.Runtimes = []*node.Runtime{}
				return &nd
			},
			epoch: 10,
			err:   nil,
			msg:   "expired node removing runtimes update should be allowed",
		},
		{
			nodeFn: func() *node.Node {
				nd := existingNode
				nd.Consensus.ID = consensusID2
				return &nd
			},
			epoch: 10,
			err:   ErrNodeUpdateNotAllowed,
			msg:   "expired node consensus ID update should not be allowed",
		},
		// TODO: Add checks for runtime versions.
	} {
		err := VerifyNodeUpdate(context.Background(), logger, &existingNode, tc.nodeFn(), lookup, tc.epoch)
		require.Equal(t, tc.err, err, tc.msg)
	}
}
