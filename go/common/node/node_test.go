package node

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

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
		{"storage-rpc", 32, true, true, ""},
		// Valid multiple roles.
		{"compute,validator", 9, true, true, ""},
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

func TestNodeDescriptorV2(t *testing.T) {
	require := require.New(t)

	v1 := Node{
		Versioned: cbor.NewVersioned(2),
		Roles:     RoleComputeWorker | roleReserved3,
	}
	require.Error(v1.ValidateBasic(false), "V1 descriptors should not be allowed anymore")

	v2 := nodeV2{
		Versioned: cbor.NewVersioned(2),
		Roles:     RoleComputeWorker | roleReserved3,
		TLS: nodeV2TLSInfo{
			PubKey:               signature.PublicKey{},
			DeprecatedNextPubKey: signature.PublicKey{},
			DeprecatedAddresses:  []TLSAddress{{PubKey: signature.PublicKey{}, Address: Address{IP: net.IPv4(127, 0, 0, 1), Port: 9000}}},
		},
	}
	raw := cbor.Marshal(v2)

	var v3 Node
	err := cbor.Unmarshal(raw, &v3)
	require.NoError(err, "cbor.Unmarshal")

	err = v3.ValidateBasic(false)
	require.NoError(err, "ValidateBasic")
	require.True(v3.HasRoles(RoleComputeWorker))
	require.False(v3.HasRoles(roleReserved3))

	v2 = nodeV2{
		Versioned: cbor.NewVersioned(2),
		Roles:     RoleComputeWorker,
	}
	raw = cbor.Marshal(v2)

	err = cbor.Unmarshal(raw, &v3)
	require.NoError(err, "cbor.Unmarshal")

	err = v3.ValidateBasic(false)
	require.NoError(err, "ValidateBasic")
	require.True(v3.HasRoles(RoleComputeWorker))
	require.False(v3.HasRoles(roleReserved2))
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
		{Node{Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion)}, "qmF2A2JpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOhZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY3ZyZqFiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZXJvbGVzAGhydW50aW1lc/ZpY29uc2Vuc3VzomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamV4cGlyYXRpb24A"},
	} {
		enc := cbor.Marshal(tc.node)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Node
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.node, dec, "Node serialization should round-trip")
	}
}

func TestNodeForTestSerializationV2(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	require.NoError(runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000010"), "runtime id")
	var runtimeID2 common.Namespace
	require.NoError(runtimeID2.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000011"), "runtime id 2")

	// NOTE: These cases should be synced with tests in runtime/src/consensus/registry.rs.
	for _, tc := range []struct {
		node           nodeV2
		expectedBase64 string
	}{
		{
			nodeV2{Versioned: cbor.NewVersioned(2)},
			"qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZsbmV4dF9wdWJfa2V5WCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAA==",
		},
		{
			nodeV2{
				Versioned: cbor.NewVersioned(2),
				TLS: nodeV2TLSInfo{
					PubKey:               signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
					DeprecatedNextPubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
					DeprecatedAddresses:  []TLSAddress{},
				},
			},
			"qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIP/////////////////////////////////////////yaWFkZHJlc3Nlc4BsbmV4dF9wdWJfa2V5WCD/////////////////////////////////////////82Vyb2xlcwBocnVudGltZXP2aWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAA==",
		},
		{
			nodeV2{
				Versioned: cbor.NewVersioned(2),
				TLS: nodeV2TLSInfo{
					PubKey:               signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
					DeprecatedNextPubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
					DeprecatedAddresses: []TLSAddress{
						{
							PubKey:  signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
							Address: Address{IP: net.IPv4(127, 0, 0, 1), Port: 123},
						},
						{
							PubKey:  signature.NewPublicKey("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc4"),
							Address: Address{IP: net.IPv4(192, 168, 1, 1), Port: 4000},
						},
						{
							PubKey:  signature.NewPublicKey("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd4"),
							Address: Address{IP: net.IPv4(234, 100, 99, 88), Port: 8000},
						},
					},
				},
			},
			"qWF2AmJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIP/////////////////////////////////////////yaWFkZHJlc3Nlc4OiZ2FkZHJlc3OjYklQUAAAAAAAAAAAAAD//38AAAFkUG9ydBh7ZFpvbmVgZ3B1Yl9rZXlYIP/////////////////////////////////////////0omdhZGRyZXNzo2JJUFAAAAAAAAAAAAAA///AqAEBZFBvcnQZD6BkWm9uZWBncHViX2tleVgg/////////////////////////////////////////8SiZ2FkZHJlc3OjYklQUAAAAAAAAAAAAAD//+pkY1hkUG9ydBkfQGRab25lYGdwdWJfa2V5WCD/////////////////////////////////////////1GxuZXh0X3B1Yl9rZXlYIP/////////////////////////////////////////zZXJvbGVzAGhydW50aW1lc/ZpY29uc2Vuc3VzomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamV4cGlyYXRpb24A",
		},
		{
			nodeV2{
				Versioned:  cbor.NewVersioned(2),
				ID:         signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
				EntityID:   signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
				Expiration: 32,
				TLS: nodeV2TLSInfo{
					PubKey:               signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
					DeprecatedNextPubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
					DeprecatedAddresses: []TLSAddress{
						{
							PubKey:  signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
							Address: Address{IP: net.IPv4(127, 0, 0, 1), Port: 123},
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
			"qmF2AmJpZFgg//////////////////////////////////////////BjcDJwomJpZFgg//////////////////////////////////////////VpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIP/////////////////////////////////////////yaWFkZHJlc3Nlc4GiZ2FkZHJlc3OjYklQUAAAAAAAAAAAAAD//38AAAFkUG9ydBh7ZFpvbmVgZ3B1Yl9rZXlYIP/////////////////////////////////////////0bG5leHRfcHViX2tleVgg//////////////////////////////////////////NjdnJmoWJpZFgg//////////////////////////////////////////dlcm9sZXMAaHJ1bnRpbWVzgqRiaWRYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQZ3ZlcnNpb26hZXBhdGNoGQFBamV4dHJhX2luZm/2bGNhcGFiaWxpdGllc6CkYmlkWCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEWd2ZXJzaW9uoWVwYXRjaBh7amV4dHJhX2luZm9EBQMCAWxjYXBhYmlsaXRpZXOhY3RlZaNjcmFrWCD/////////////////////////////////////////+GhoYXJkd2FyZQFrYXR0ZXN0YXRpb25GAAECAwQFaWNvbnNlbnN1c6JiaWRYIP/////////////////////////////////////////2aWFkZHJlc3Nlc4BpZW50aXR5X2lkWCD/////////////////////////////////////////8WpleHBpcmF0aW9uGCA=",
		},
		{
			nodeV2{
				Versioned:  cbor.NewVersioned(2),
				ID:         signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
				EntityID:   signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
				Expiration: 32,
				TLS: nodeV2TLSInfo{
					PubKey:               signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
					DeprecatedNextPubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
					DeprecatedAddresses: []TLSAddress{
						{
							PubKey:  signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
							Address: Address{IP: net.IPv4(127, 0, 0, 1), Port: 123},
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
							REK:         &x25519.PublicKey{},
							Attestation: []byte{0, 1, 2, 3, 4, 5},
						}},
						ExtraInfo: []byte{5, 3, 2, 1},
					},
				},
			},
			"qmF2AmJpZFgg//////////////////////////////////////////BjcDJwomJpZFgg//////////////////////////////////////////VpYWRkcmVzc2Vz9mN0bHOjZ3B1Yl9rZXlYIP/////////////////////////////////////////yaWFkZHJlc3Nlc4GiZ2FkZHJlc3OjYklQUAAAAAAAAAAAAAD//38AAAFkUG9ydBh7ZFpvbmVgZ3B1Yl9rZXlYIP/////////////////////////////////////////0bG5leHRfcHViX2tleVgg//////////////////////////////////////////NjdnJmoWJpZFgg//////////////////////////////////////////dlcm9sZXMAaHJ1bnRpbWVzgqRiaWRYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQZ3ZlcnNpb26hZXBhdGNoGQFBamV4dHJhX2luZm/2bGNhcGFiaWxpdGllc6CkYmlkWCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEWd2ZXJzaW9uoWVwYXRjaBh7amV4dHJhX2luZm9EBQMCAWxjYXBhYmlsaXRpZXOhY3RlZaRjcmFrWCD/////////////////////////////////////////+GNyZWtYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaGhhcmR3YXJlAWthdHRlc3RhdGlvbkYAAQIDBAVpY29uc2Vuc3VzomJpZFgg//////////////////////////////////////////ZpYWRkcmVzc2VzgGllbnRpdHlfaWRYIP/////////////////////////////////////////xamV4cGlyYXRpb24YIA==",
		},
	} {
		enc := cbor.Marshal(tc.node)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Node
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Deserialization into Node v3 should work")

		var t map[string]interface{}
		err = cbor.Unmarshal(enc, &t)
		require.NoError(err, "Unamarshal inter")
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
			"qmF2A2JpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOhZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY3ZyZqFiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZXJvbGVzAGhydW50aW1lc/ZpY29uc2Vuc3VzomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamV4cGlyYXRpb24A",
		},
		{
			Node{
				Versioned:  cbor.NewVersioned(LatestNodeDescriptorVersion),
				ID:         signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
				EntityID:   signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
				Expiration: 32,
				TLS: TLSInfo{
					PubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
				},
				P2P: P2PInfo{
					ID: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5"),
				},
				Consensus: ConsensusInfo{
					ID:        signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6"),
					Addresses: []ConsensusAddress{},
				},
				VRF: VRFInfo{
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
			"qmF2A2JpZFgg//////////////////////////////////////////BjcDJwomJpZFgg//////////////////////////////////////////VpYWRkcmVzc2Vz9mN0bHOhZ3B1Yl9rZXlYIP/////////////////////////////////////////yY3ZyZqFiaWRYIP/////////////////////////////////////////3ZXJvbGVzAGhydW50aW1lc4KkYmlkWCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGd2ZXJzaW9uoWVwYXRjaBkBQWpleHRyYV9pbmZv9mxjYXBhYmlsaXRpZXOgpGJpZFgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFndmVyc2lvbqFlcGF0Y2gYe2pleHRyYV9pbmZvRAUDAgFsY2FwYWJpbGl0aWVzoWN0ZWWjY3Jha1gg//////////////////////////////////////////hoaGFyZHdhcmUBa2F0dGVzdGF0aW9uRgABAgMEBWljb25zZW5zdXOiYmlkWCD/////////////////////////////////////////9mlhZGRyZXNzZXOAaWVudGl0eV9pZFgg//////////////////////////////////////////FqZXhwaXJhdGlvbhgg",
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
			"qmF2A2JpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOhZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY3ZyZqFiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZXJvbGVzAGhydW50aW1lc/ZpY29uc2Vuc3VzomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamV4cGlyYXRpb24A",
			Node{Versioned: cbor.NewVersioned(LatestNodeDescriptorVersion)},
		},
		{
			"qWF2A2JpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjcDJwomJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpYWRkcmVzc2Vz9mN0bHOhZ3B1Yl9rZXlYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZXJvbGVzAGhydW50aW1lc4GkYmlkWCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGd2ZXJzaW9uoGpleHRyYV9pbmZv9mxjYXBhYmlsaXRpZXOgaWNvbnNlbnN1c6JiaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWFkZHJlc3Nlc/ZpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGpleHBpcmF0aW9uAA==",
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

func TestNodeSoftwareVersion(t *testing.T) {
	require := require.New(t)

	sw := SoftwareVersion("")
	require.NoError(sw.ValidateBasic(), "empty software version is allowed")

	sw = SoftwareVersion(version.SoftwareVersion)
	require.NoError(sw.ValidateBasic(), "software version is allowed")

	sw = SoftwareVersion(strings.Repeat("a", 1000))
	require.Error(sw.ValidateBasic(), "invalid software version")
}
