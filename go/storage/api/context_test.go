package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestNodePriorityHint(t *testing.T) {
	require := require.New(t)

	ctx := context.Background()
	nodes := NodePriorityHintFromContext(ctx)
	require.Nil(nodes, "must return nil when node priority hint is not present")

	var pk1, pk2, pk3 signature.PublicKey
	_ = pk1.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")
	_ = pk2.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000001")
	_ = pk3.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000002")
	ctx1 := WithNodePriorityHint(ctx, []signature.PublicKey{pk1, pk2, pk3})
	nodes = NodePriorityHintFromContext(ctx1)
	require.Len(nodes, 3, "all node ids must be there")
	require.EqualValues([]signature.PublicKey{pk1, pk2, pk3}, nodes, "all node ids must be the same")

	var sig1, sig2, sig3 signature.Signature
	sig1.PublicKey = pk1
	sig2.PublicKey = pk2
	sig3.PublicKey = pk3
	ctx2 := WithNodePriorityHintFromSignatures(ctx, []signature.Signature{sig1, sig2, sig3})
	nodes = NodePriorityHintFromContext(ctx2)
	require.Len(nodes, 3, "all node ids must be there")
	require.EqualValues([]signature.PublicKey{pk1, pk2, pk3}, nodes, "all node ids must be the same")

	ctx3 := WithNodePriorityHintFromMap(ctx, map[signature.PublicKey]bool{
		pk1: true,
		pk2: false,
		pk3: true,
	})
	nodes = NodePriorityHintFromContext(ctx3)
	require.Len(nodes, 2, "node ids must be there")
	require.ElementsMatch([]signature.PublicKey{pk1, pk3}, nodes, "node ids must be correct")
}
