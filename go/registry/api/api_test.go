package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

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
