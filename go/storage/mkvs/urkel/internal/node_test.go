package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

func TestSerializationLeafNode(t *testing.T) {
	var key Key = []byte("a golden key")
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))

	leafNode := &LeafNode{
		Key: key,
		Value: &Value{
			Clean: true,
			Hash:  valueHash,
			Value: []byte("value"),
		},
	}

	rawLeafNode, err := leafNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")

	var decodedLeafNode LeafNode
	err = decodedLeafNode.UnmarshalBinary(rawLeafNode)
	require.NoError(t, err, "UnmarshalBinary")

	require.True(t, decodedLeafNode.Clean)
	require.Equal(t, leafNode.Key, decodedLeafNode.Key)
	require.True(t, decodedLeafNode.Value.Clean)
	require.Equal(t, leafNode.Value.Value, decodedLeafNode.Value.Value)
	require.NotNil(t, decodedLeafNode.Value.Value)
}

func TestSerializationInternalNode(t *testing.T) {
	var leftHash hash.Hash
	leftHash.FromBytes([]byte("everyone move to the left"))
	var rightHash hash.Hash
	rightHash.FromBytes([]byte("everyone move to the right"))

	intNode := &InternalNode{
		Left:  &Pointer{Clean: true, Hash: leftHash},
		Right: &Pointer{Clean: true, Hash: rightHash},
	}

	rawIntNode, err := intNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")

	var decodedIntNode InternalNode
	err = decodedIntNode.UnmarshalBinary(rawIntNode)
	require.NoError(t, err, "UnmarshalBinary")

	require.True(t, decodedIntNode.Clean)
	require.Equal(t, intNode.Left.Hash, decodedIntNode.Left.Hash)
	require.Equal(t, intNode.Right.Hash, decodedIntNode.Right.Hash)
	require.True(t, decodedIntNode.Left.Clean)
	require.True(t, decodedIntNode.Right.Clean)
	require.Nil(t, decodedIntNode.Left.Node)
	require.Nil(t, decodedIntNode.Right.Node)
}

func TestHashLeafNode(t *testing.T) {
	var key Key = []byte("a golden key")
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))

	leafNode := &LeafNode{
		Key: key,
		Value: &Value{
			Clean: true,
			Hash:  valueHash,
			Value: []byte("value"),
		},
	}

	leafNode.UpdateHash()

	require.Equal(t, leafNode.Hash.String(), "1736c1ac9fe17539c40e8b4c4d73c5c5a4a6e808c0b8247ebf4b1802ceace4d2")
}

func TestHashInternalNode(t *testing.T) {
	var leftHash hash.Hash
	leftHash.FromBytes([]byte("everyone move to the left"))
	var rightHash hash.Hash
	rightHash.FromBytes([]byte("everyone move to the right"))

	intNode := &InternalNode{
		Left:  &Pointer{Clean: true, Hash: leftHash},
		Right: &Pointer{Clean: true, Hash: rightHash},
	}

	intNode.UpdateHash()

	require.Equal(t, intNode.Hash.String(), "51472b6931929c00f2f3150bcf23e6138d1991669b68958c6ca701e4c8b2f929")
}

func TestExtractLeafNode(t *testing.T) {
	var key Key = []byte("a golden key")
	var valueHash hash.Hash
	valueHash.FromBytes([]byte("value"))

	leafNode := &LeafNode{
		Clean: true,
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
		Left:  &Pointer{Clean: true, Hash: leftHash},
		Right: &Pointer{Clean: true, Hash: rightHash},
	}

	exIntNode := intNode.Extract().(*InternalNode)

	require.False(t, intNode == exIntNode, "extracted node must have a different address")
	require.False(t, intNode.Left == exIntNode.Left, "extracted left pointer must have a different address")
	require.False(t, intNode.Right == exIntNode.Right, "extracted right pointer must have a different address")
	require.Equal(t, true, exIntNode.Clean, "extracted internal node must be clean")
	require.Equal(t, leftHash, exIntNode.Left.Hash, "extracted left pointer must have the same hash")
	require.Equal(t, true, exIntNode.Left.Clean, "extracted left pointer must be clean")
	require.Equal(t, rightHash, exIntNode.Right.Hash, "extracted right pointer must have the same hash")
	require.Equal(t, true, exIntNode.Right.Clean, "extracted right pointer must be clean")
}
