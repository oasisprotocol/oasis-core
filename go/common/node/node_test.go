package node

import (
	"encoding/base64"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/version"
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
		{"key-manager", 4, true, true, ""},
		{"validator", 8, true, true, ""},
		{"consensus-rpc", 16, true, true, ""},
		{"storage-rpc", 32, true, true, ""},
		// Valid multiple roles.
		{"compute,validator", 9, true, true, ""},
		{"compute,validator,consensus-rpc", 25, true, true, ""},
		{"validator,consensus-rpc", 24, true, true, ""},
		{"compute,storage-rpc", 33, true, true, ""},

		// Invalid - extra spaces.
		{"compute ", 1, false, false, "node: invalid role: 'compute '"},
		{"compute ,", 1, false, false, "node: invalid role: 'compute '"},
		{" validator", 1, false, false, "node: invalid role: ' validator'"},
		{"compute, storage-rpc", 1, false, false, "node: invalid role: ' storage-rpc'"},
		// Invalid - unknown role.
		{"master", 1, false, false, "node: invalid role: 'master'"},
		// Invalid - role mask string not in canonical order.
		{"storage-rpc,compute", 33, true, false, ""},
		// Invalid - duplicate role in role mask string.
		{"compute,compute", 8, false, false, "node: duplicate role: 'compute'"},
		{"key-manager,key-manager", 8, false, false, "node: duplicate role: 'key-manager'"},
		{"validator,validator", 8, false, false, "node: duplicate role: 'validator'"},
		{"consensus-rpc,consensus-rpc", 8, false, false, "node: duplicate role: 'consensus-rpc'"},
		{"storage-rpc,storage-rpc", 8, false, false, "node: duplicate role: 'storage-rpc'"},
		{"compute,storage-rpc,compute", 1, false, false, "node: duplicate role: 'compute'"},
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
		Versioned:  cbor.NewVersioned(LatestNodeDescriptorVersion),
		Expiration: 42,
	}

	require.False(n.HasRoles(RoleComputeWorker))
	require.False(n.HasRoles(RoleStorageRPC))
	n.AddRoles(RoleComputeWorker)
	require.True(n.HasRoles(RoleComputeWorker))
	require.False(n.HasRoles(RoleStorageRPC))

	require.False(n.IsExpired(0))
	require.False(n.IsExpired(10))
	require.False(n.IsExpired(42))
	require.True(n.IsExpired(43))

	ns1 := common.NewTestNamespaceFromSeed([]byte("node descriptor test"), 0)
	rt1 := n.AddOrUpdateRuntime(ns1, version.Version{Major: 1, Minor: 2, Patch: 3})
	require.Equal(rt1.ID, ns1, "created runtime id must be correct")
	rt2 := n.AddOrUpdateRuntime(ns1, version.Version{Major: 1, Minor: 2, Patch: 3})
	require.Equal(&rt1, &rt2, "AddOrUpdateRuntime should return the same reference for same id")
	require.Len(n.Runtimes, 1)

	b := cbor.Marshal(n)
	var n2 Node
	err := cbor.Unmarshal(b, &n2)
	require.NoError(err, "deserialize descriptor")
	require.EqualValues(n, n2, "s11n roundtrip")
}

func TestReservedRoles(t *testing.T) {
	require := require.New(t)

	n := Node{
		Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion),
		Roles:     0xFFFFFFFF,
	}
	err := n.ValidateBasic(false)
	require.Error(err, "ValidateBasic should fail for reserved roles")

	n.Roles = 0
	err = n.ValidateBasic(false)
	require.Error(err, "ValidateBasic should fail for empty roles")
}

func TestNodeDescriptorV1(t *testing.T) {
	require := require.New(t)

	v1 := Node{
		Versioned: cbor.NewVersioned(1),
		Roles:     RoleComputeWorker | roleReserved2,
	}
	raw := cbor.Marshal(v1)

	var v2 Node
	err := cbor.Unmarshal(raw, &v2)
	require.NoError(err, "cbor.Unmarshal")

	err = v2.ValidateBasic(false)
	require.NoError(err, "ValidateBasic")
	require.True(v2.HasRoles(RoleComputeWorker))
	require.False(v2.HasRoles(roleReserved2))

	v1 = Node{
		Versioned: cbor.NewVersioned(1),
		Roles:     RoleComputeWorker,
	}
	raw = cbor.Marshal(v1)

	err = cbor.Unmarshal(raw, &v2)
	require.NoError(err, "cbor.Unmarshal")

	err = v2.ValidateBasic(false)
	require.NoError(err, "ValidateBasic")
	require.True(v2.HasRoles(RoleComputeWorker))
	require.False(v2.HasRoles(roleReserved2))
}

func TestNodeSerialization(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	require.NoError(runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"), "runtime id")
	var keymanagerID common.Namespace
	require.NoError(keymanagerID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001"), "keymanager id")
	var h hash.Hash
	h.FromBytes([]byte("stateroot hash"))

	// NOTE: These cases should be synced with tests in runtime/src/consensus/registry.rs.
	for _, tc := range []struct {
		node           Node
		expectedBase64 string
	}{
		{Node{Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion)}, "qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAA=="},
	} {
		enc := cbor.Marshal(tc.node)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Node
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.node, dec, "Node serialization should round-trip")
	}
}

func TestNodeForTestSerialization(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	require.NoError(runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000010"), "runtime id")
	var runtimeID2 common.Namespace
	require.NoError(runtimeID2.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000011"), "runtime id 2")

	// NOTE: These cases should be synced with tests in runtime/src/consensus/registry.rs.
	for _, tc := range []struct {
		node           Node
		expectedBase64 string
	}{
		{
			Node{Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion)},
			"qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAA==",
		},
		{
			Node{
				Versioned:  cbor.NewVersioned(LatestNodeDescriptorVersion),
				ID:         signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
				EntityID:   signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
				Expiration: 32,
				TLS: TLSInfo{
					PubKey:     signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
					NextPubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
					Addresses: []TLSAddress{
						{
							PubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
							Address: Address{
								IP:   net.IPv4(127, 0, 0, 1),
								Port: 1111,
							},
						},
					},
				},
				P2P: P2PInfo{
					ID: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5"),
				},
				Consensus: ConsensusInfo{
					ID:        signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6"),
					Addresses: []ConsensusAddress{},
				},
				VRF: &VRFInfo{
					ID: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7"),
				},
				Runtimes: []*Runtime{
					{
						ID:      runtimeID,
						Version: version.FromU64(321),
					},
					{
						ID:      runtimeID2,
						Version: version.FromU64(123),
						Capabilities: Capabilities{TEE: &CapabilityTEE{
							Hardware:    TEEHardwareIntelSGX,
							RAK:         signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8"),
							Attestation: []byte{0, 1, 2, 3, 4, 5},
						}},
						ExtraInfo: []byte{5, 3, 2, 1},
					},
				},
			},
			"qmF2AmJpZFgg//////////////////////////////////////////BjcDJwomJpZFgg//////////////////////////////////////////VpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIP/////////////////////////////////////////yaWFkZHJlc3Nlc4GiZ2FkZHJlc3OjYklQUAAAAAAAAAAAAAD//38AAAFkUG9ydBkEV2Rab25lYGdwdWJfa2V5WCD/////////////////////////////////////////9GxuZXh0X3B1Yl9rZXlYIP/////////////////////////////////////////zY3ZyZqFiaWRYIP/////////////////////////////////////////3ZXJvbGVzAGhydW50aW1lc4KkYmlkWCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGd2ZXJzaW9uoWVwYXRjaBkBQWpleHRyYV9pbmZv9mxjYXBhYmlsaXRpZXOgpGJpZFgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFndmVyc2lvbqFlcGF0Y2gYe2pleHRyYV9pbmZvRAUDAgFsY2FwYWJpbGl0aWVzoWN0ZWWjY3Jha1gg//////////////////////////////////////////hoaGFyZHdhcmUBa2F0dGVzdGF0aW9uRgABAgMEBWljb25zZW5zdXOiYmlkWCD/////////////////////////////////////////9mlhZGRyZXNzZXOAaWVudGl0eV9pZFgg//////////////////////////////////////////FqZXhwaXJhdGlvbhgg",
		},
	} {
		enc := cbor.Marshal(tc.node)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Node
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.node, dec, "Node serialization should round-trip")

		var t map[string]interface{}
		err = cbor.Unmarshal(enc, &t)
		require.NoError(err, "Unamarshal inter")
	}
}

func TestNodeDeserialization(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	require.NoError(runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000010"), "runtime id")

	// NOTE: These cases should be synced with tests in runtime/src/consensus/registry.rs.
	for _, tc := range []struct {
		rawBase64    string
		expectedNode Node
	}{
		{
			"qmF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAHBzb2Z0d2FyZV92ZXJzaW9u9g==",
			Node{Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion)},
		},
		{
			"qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXOBomJpZFgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBndmVyc2lvbvZpY29uc2Vuc3VzomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamV4cGlyYXRpb24A",
			Node{
				Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion),
				Runtimes: []*Runtime{
					{
						ID:      runtimeID,
						Version: version.FromU64(0),
					},
				},
			},
		},
	} {
		raw, err := base64.StdEncoding.DecodeString(tc.rawBase64)
		require.NoError(err, "DecodeString")

		var dec Node
		err = cbor.Unmarshal(raw, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.expectedNode, dec, "Node serialization should round-trip")
	}
}
