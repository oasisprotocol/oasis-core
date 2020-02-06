package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
)

func TestNodeDescriptor(t *testing.T) {
	require := require.New(t)

	n := Node{
		Expiration: 42,
	}

	require.False(n.HasRoles(RoleComputeWorker))
	require.False(n.HasRoles(RoleStorageWorker))
	n.AddRoles(RoleComputeWorker)
	require.True(n.HasRoles(RoleComputeWorker))
	require.False(n.HasRoles(RoleStorageWorker))

	require.False(n.IsExpired(0))
	require.False(n.IsExpired(10))
	require.False(n.IsExpired(42))
	require.True(n.IsExpired(43))

	ns1 := common.NewTestNamespaceFromSeed([]byte("node descriptor test"), 0)
	rt1 := n.AddOrUpdateRuntime(ns1)
	require.Equal(rt1.ID, ns1, "created runtime id must be correct")
	rt2 := n.AddOrUpdateRuntime(ns1)
	require.Equal(&rt1, &rt2, "AddOrUpdateRuntime should return the same reference for same id")
	require.Len(n.Runtimes, 1)
}
