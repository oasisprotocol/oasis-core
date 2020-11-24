package nodes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/node"
)

func TestTagsForRoleMask(t *testing.T) {
	cases := map[node.RolesMask][]string{
		node.RoleComputeWorker: {tagForRole(node.RoleComputeWorker)},
		node.RoleComputeWorker | node.RoleKeyManager: {
			tagForRole(node.RoleComputeWorker),
			tagForRole(node.RoleKeyManager),
		},
		node.RoleComputeWorker | node.RoleKeyManager | node.RoleConsensusRPC: {
			tagForRole(node.RoleComputeWorker),
			tagForRole(node.RoleKeyManager),
			tagForRole(node.RoleConsensusRPC),
		},
	}

	for tc, expected := range cases {
		require.EqualValues(t, TagsForRoleMask(tc), expected)
	}
}
