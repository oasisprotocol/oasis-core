package entity

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestEntityDescriptorVersioning(t *testing.T) {
	require := require.New(t)

	type EntityV1 struct {
		Entity
		AllowEntitySignedNodes bool `json:"allow_entity_signed_nodes,omitempty"`
	}

	k1 := memorySigner.NewTestSigner("test entity v1")
	k1n1 := memorySigner.NewTestSigner("test entity v1 node 1")
	k1n2 := memorySigner.NewTestSigner("test entity v1 node 2")
	var ev1 EntityV1
	ev1.Versioned = cbor.NewVersioned(1)
	ev1.ID = k1.Public()
	ev1.Nodes = []signature.PublicKey{k1n1.Public(), k1n2.Public()}

	var uv1t1 Entity
	require.NoError(cbor.Unmarshal(cbor.Marshal(ev1), &uv1t1), "v1 unmarshal with no AllowEntitySignedNodes field should pass")
	require.EqualValues(ev1.ID, uv1t1.ID)
	require.EqualValues(ev1.Nodes, uv1t1.Nodes)
	require.EqualValues(cbor.NewVersioned(2), uv1t1.Versioned)

	var uv1t2 Entity
	ev1.AllowEntitySignedNodes = false
	require.NoError(cbor.Unmarshal(cbor.Marshal(ev1), &uv1t2), "v1 unmarshal with AllowEntitySignedNodes field set to false should pass")
	require.EqualValues(ev1.ID, uv1t2.ID)
	require.EqualValues(ev1.Nodes, uv1t2.Nodes)
	require.EqualValues(cbor.NewVersioned(2), uv1t2.Versioned)

	var uv1t3 Entity
	ev1.AllowEntitySignedNodes = true
	require.Error(cbor.Unmarshal(cbor.Marshal(ev1), &uv1t3), "v1 unmarshal with AllowEntitySignedNodes field set to true should fail")

	k2 := memorySigner.NewTestSigner("test entity v2")
	k2n1 := memorySigner.NewTestSigner("test entity v2 node 1")
	k2n2 := memorySigner.NewTestSigner("test entity v2 node 2")
	ev2 := Entity{
		Versioned: cbor.NewVersioned(2),
		ID:        k2.Public(),
		Nodes:     []signature.PublicKey{k2n1.Public(), k2n2.Public()},
	}

	var uv2t1 Entity
	require.NoError(cbor.Unmarshal(cbor.Marshal(ev2), &uv2t1), "v2 unmarshal should pass")
	require.EqualValues(ev2.ID, uv2t1.ID)
	require.EqualValues(ev2.Nodes, uv2t1.Nodes)
	require.EqualValues(cbor.NewVersioned(2), uv2t1.Versioned)
}
