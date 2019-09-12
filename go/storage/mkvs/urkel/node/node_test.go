package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

func TestSerializationLeafNode(t *testing.T) {
	key := Key("a golden key")
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))

	leafNode := &LeafNode{
		Round: 0xDEADBEEF,
		Key:   key,
		Value: &Value{
			Clean: true,
			Hash:  valueHash,
			Value: []byte("value"),
		},
	}

	rawLeafNodeFull, err := leafNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")
	rawLeafNodeCompact, err := leafNode.CompactMarshalBinary()
	require.NoError(t, err, "CompactMarshalBinary")

	for _, rawLeafNode := range [][]byte{rawLeafNodeFull, rawLeafNodeCompact} {
		var decodedLeafNode LeafNode
		err = decodedLeafNode.UnmarshalBinary(rawLeafNode)
		require.NoError(t, err, "UnmarshalBinary")

		require.True(t, decodedLeafNode.Clean)
		require.Equal(t, leafNode.Round, decodedLeafNode.Round)
		require.Equal(t, leafNode.Key, decodedLeafNode.Key)
		require.True(t, decodedLeafNode.Value.Clean)
		require.Equal(t, leafNode.Value.Value, decodedLeafNode.Value.Value)
		require.NotNil(t, decodedLeafNode.Value.Value)
	}
}

func TestSerializationInternalNode(t *testing.T) {
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))
	var leafNode = &LeafNode{
		Key: []byte("a golden key"),
		Value: &Value{
			Clean: true,
			Hash:  valueHash,
			Value: []byte("value"),
		},
	}
	leafNode.UpdateHash()

	var leftHash hash.Hash
	leftHash.FromBytes([]byte("everyone move to the left"))
	var rightHash hash.Hash
	rightHash.FromBytes([]byte("everyone move to the right"))
	var label = Key("abc")
	var labelBitLength = Depth(24)

	intNode := &InternalNode{
		Round:          0xDEADBEEF,
		Label:          label,
		LabelBitLength: labelBitLength,
		LeafNode:       &Pointer{Clean: true, Node: leafNode, Hash: leafNode.Hash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	rawIntNodeFull, err := intNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")
	rawIntNodeCompact, err := intNode.CompactMarshalBinary()
	require.NoError(t, err, "CompactMarshalBinary")

	for idx, rawIntNode := range [][]byte{rawIntNodeFull, rawIntNodeCompact} {
		var decodedIntNode InternalNode
		err = decodedIntNode.UnmarshalBinary(rawIntNode)
		require.NoError(t, err, "UnmarshalBinary")

		require.True(t, decodedIntNode.Clean)
		require.Equal(t, intNode.Round, decodedIntNode.Round)
		require.Equal(t, intNode.Label, decodedIntNode.Label)
		require.Equal(t, intNode.LabelBitLength, decodedIntNode.LabelBitLength)
		require.Equal(t, intNode.LeafNode.Hash, decodedIntNode.LeafNode.Hash)
		require.True(t, decodedIntNode.LeafNode.Clean)
		require.NotNil(t, decodedIntNode.LeafNode.Node)

		// Only check left/right for non-compact encoding.
		if idx == 0 {
			require.Equal(t, intNode.Left.Hash, decodedIntNode.Left.Hash)
			require.Equal(t, intNode.Right.Hash, decodedIntNode.Right.Hash)
			require.True(t, decodedIntNode.Left.Clean)
			require.True(t, decodedIntNode.Right.Clean)
			require.Nil(t, decodedIntNode.Left.Node)
			require.Nil(t, decodedIntNode.Right.Node)
		}
	}
}

func TestHashLeafNode(t *testing.T) {
	key := Key("a golden key")
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))

	leafNode := &LeafNode{
		Round: 0xDEADBEEF,
		Key:   key,
		Value: &Value{
			Clean: true,
			Hash:  valueHash,
			Value: []byte("value"),
		},
	}

	leafNode.UpdateHash()

	require.Equal(t, leafNode.Hash.String(), "7fc8d2e9142d15de712757dba87f6efd82a04a4ed1488e21ee95e3a7ec7a5fce")
}

func TestHashInternalNode(t *testing.T) {
	var leafNodeHash hash.Hash
	leafNodeHash.FromBytes([]byte("everyone stop here"))
	var leftHash hash.Hash
	leftHash.FromBytes([]byte("everyone move to the left"))
	var rightHash hash.Hash
	rightHash.FromBytes([]byte("everyone move to the right"))

	intNode := &InternalNode{
		Round:          0xDEADBEEF,
		Label:          Key("abc"),
		LabelBitLength: 23,
		LeafNode:       &Pointer{Clean: true, Hash: leafNodeHash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	intNode.UpdateHash()

	require.Equal(t, "e760353e9796f41b3bb2cfa2cf45f7e00ca687b6b84dc658e0ecadc906d5d21e", intNode.Hash.String())
}

func TestExtractLeafNode(t *testing.T) {
	key := Key("a golden key")
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))

	leafNode := &LeafNode{
		Clean: true,
		Round: 0xDEADBEEF,
		Key:   key,
		Value: &Value{
			Clean: true,
			Hash:  valueHash,
			Value: []byte("value"),
		},
	}

	exLeafNode := leafNode.Extract().(*LeafNode)

	require.False(t, leafNode == exLeafNode, "extracted node must have a different address")
	require.False(t, leafNode.Value == exLeafNode.Value, "extracted value must have a different address")
	require.Equal(t, true, exLeafNode.Clean, "extracted leaf must be clean")
	require.Equal(t, leafNode.Round, exLeafNode.Round, "extracted leaf must have the same round")
	require.Equal(t, key, exLeafNode.Key, "extracted leaf must have the same key")
	require.Equal(t, true, exLeafNode.Value.Clean, "extracted leaf must have clean value")
	require.Equal(t, valueHash, exLeafNode.Value.Hash, "extracted leaf's value must have the same hash")
	require.NotNil(t, exLeafNode.Value.Value, "extracted leaf's value must have non-nil value")
}

func TestExtractInternalNode(t *testing.T) {
	var leftHash hash.Hash
	leftHash.FromBytes([]byte("everyone move to the left"))
	var rightHash hash.Hash
	rightHash.FromBytes([]byte("everyone move to the right"))

	intNode := &InternalNode{
		Clean: true,
		Round: 0xDEADBEEF,
		Left:  &Pointer{Clean: true, Hash: leftHash},
		Right: &Pointer{Clean: true, Hash: rightHash},
	}

	exIntNode := intNode.Extract().(*InternalNode)

	require.False(t, intNode == exIntNode, "extracted node must have a different address")
	require.False(t, intNode.Left == exIntNode.Left, "extracted left pointer must have a different address")
	require.False(t, intNode.Right == exIntNode.Right, "extracted right pointer must have a different address")
	require.Equal(t, true, exIntNode.Clean, "extracted internal node must be clean")
	require.Equal(t, intNode.Round, exIntNode.Round, "extracted internal node must have the same round")
	require.Equal(t, leftHash, exIntNode.Left.Hash, "extracted left pointer must have the same hash")
	require.Equal(t, true, exIntNode.Left.Clean, "extracted left pointer must be clean")
	require.Equal(t, rightHash, exIntNode.Right.Hash, "extracted right pointer must have the same hash")
	require.Equal(t, true, exIntNode.Right.Clean, "extracted right pointer must be clean")
}
