package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

func TestRolesMask(t *testing.T) {
	require := require.New(t)

	testVectors := []struct {
		rolesMaskString            string
		rolesMask                  RolesMask
		rolesMaskStringUnmarshable bool
		rolesMaskStringCanonical   bool
		errMsg                     string
	}{
		// Valid single roles.
		{"compute", 1, true, true, ""},
		{"storage", 2, true, true, ""},
		{"key-manager", 4, true, true, ""},
		{"validator", 8, true, true, ""},
		{"consensus-rpc", 16, true, true, ""},
		{"storage-rpc", 32, true, true, ""},
		// Valid multiple roles.
		{"compute,storage", 3, true, true, ""},
		{"compute,storage,validator", 11, true, true, ""},
		{"compute,storage,validator,consensus-rpc", 27, true, true, ""},
		{"validator,consensus-rpc", 24, true, true, ""},
		{"storage,storage-rpc", 34, true, true, ""},

		// Invalid - extra spaces.
		{"compute ", 1, false, false, "node: invalid role: 'compute '"},
		{"compute ,", 1, false, false, "node: invalid role: 'compute '"},
		{" validator", 1, false, false, "node: invalid role: ' validator'"},
		{"compute, storage", 1, false, false, "node: invalid role: ' storage'"},
		// Invalid - unknown role.
		{"master", 1, false, false, "node: invalid role: 'master'"},
		// Invalid - role mask string not in canonical order.
		{"storage-rpc,storage", 34, true, false, ""},
		// Invalid - duplicate role in role mask string.
		{"compute,compute", 8, false, false, "node: duplicate role: 'compute'"},
		{"storage,storage", 8, false, false, "node: duplicate role: 'storage'"},
		{"key-manager,key-manager", 8, false, false, "node: duplicate role: 'key-manager'"},
		{"validator,validator", 8, false, false, "node: duplicate role: 'validator'"},
		{"consensus-rpc,consensus-rpc", 8, false, false, "node: duplicate role: 'consensus-rpc'"},
		{"storage-rpc,storage-rpc", 8, false, false, "node: duplicate role: 'storage-rpc'"},
		{"compute,storage,compute", 1, false, false, "node: duplicate role: 'compute'"},
	}

	for _, v := range testVectors {
		var unmarshaledRolesMask RolesMask
		err := unmarshaledRolesMask.UnmarshalText([]byte(v.rolesMaskString))
		if !v.rolesMaskStringUnmarshable {
			require.EqualErrorf(
				err,
				v.errMsg,
				"Unmarshaling invalid roles mask: '%s' should fail with expected error message",
				v.rolesMaskString,
			)
		} else {
			require.NoErrorf(err, "Failed to unmarshal a valid roles mask: '%s'", v.rolesMaskString)
			require.Equal(
				v.rolesMask,
				unmarshaledRolesMask,
				"Unmarshaled roles mask doesn't equal expected roles mask",
			)
		}

		textRolesMask, err := v.rolesMask.MarshalText()
		require.NoError(err, "Failed to marshal a valid roles mask: '%s'", v.rolesMask)
		if v.rolesMaskStringCanonical {
			require.Equal(
				v.rolesMaskString,
				string(textRolesMask),
				"Marshaled roles mask doesn't equal expected text roles mask",
			)
		}
	}
}

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

	b := cbor.Marshal(n)
	var n2 Node
	err := cbor.Unmarshal(b, &n2)
	require.NoError(err, "deserialize descriptor")
	require.EqualValues(n, n2, "s11n roundtrip")
}
