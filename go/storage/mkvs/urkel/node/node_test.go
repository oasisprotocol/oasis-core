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
		Label:          label,
		LabelBitLength: labelBitLength,
		LeafNode:       &Pointer{Clean: true, Node: leafNode, Hash: leafNode.Hash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	rawIntNode, err := intNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")

	var decodedIntNode InternalNode
	err = decodedIntNode.UnmarshalBinary(rawIntNode)
	require.NoError(t, err, "UnmarshalBinary")

	require.True(t, decodedIntNode.Clean)
	require.Equal(t, intNode.Label, decodedIntNode.Label)
	require.Equal(t, intNode.LabelBitLength, decodedIntNode.LabelBitLength)
	require.Equal(t, intNode.LeafNode.Hash, decodedIntNode.LeafNode.Hash)
	require.Equal(t, intNode.Left.Hash, decodedIntNode.Left.Hash)
	require.Equal(t, intNode.Right.Hash, decodedIntNode.Right.Hash)
	require.True(t, decodedIntNode.LeafNode.Clean)
	require.True(t, decodedIntNode.Left.Clean)
	require.True(t, decodedIntNode.Right.Clean)
	require.NotNil(t, decodedIntNode.LeafNode.Node)
	require.Nil(t, decodedIntNode.Left.Node)
	require.Nil(t, decodedIntNode.Right.Node)
}

func TestHashLeafNode(t *testing.T) {
	key := Key("a golden key")
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
	var leafNodeHash hash.Hash
	leafNodeHash.FromBytes([]byte("everyone stop here"))
	var leftHash hash.Hash
	leftHash.FromBytes([]byte("everyone move to the left"))
	var rightHash hash.Hash
	rightHash.FromBytes([]byte("everyone move to the right"))

	intNode := &InternalNode{
		Label:          Key("abc"),
		LabelBitLength: 23,
		LeafNode:       &Pointer{Clean: true, Hash: leafNodeHash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	intNode.UpdateHash()

	require.Equal(t, "aa31d03fdf2fddf6ada5db43ccba0f137cb6f696110a71ac59f8936d1bef2bf8", intNode.Hash.String())
}

func TestExtractLeafNode(t *testing.T) {
	key := Key("a golden key")
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

func TestDepth(t *testing.T) {
	require.Equal(t, 0, Depth(0).ToBytes())
	require.Equal(t, 2, Depth(16).ToBytes())
	require.Equal(t, 3, Depth(17).ToBytes())

	var dt Depth
	require.Equal(t, []byte{0x0a, 0x00}, Depth(10).MarshalBinary())
	_, err := dt.UnmarshalBinary([]byte{0x0a, 0x00})
	require.NoError(t, err, "UnmarshalBinary")
	require.Equal(t, Depth(10), dt)

	require.Equal(t, []byte{0x04, 0x01}, Depth(260).MarshalBinary())
	_, err = dt.UnmarshalBinary([]byte{0x04, 0x01})
	require.NoError(t, err, "UnmarshalBinary")
	require.Equal(t, Depth(260), dt)
}

func TestKeyAppendSplitMerge(t *testing.T) {
	var key, newKey Key

	// append a single bit
	key = Key{0xf0}
	newKey = key.AppendBit(4, true)
	require.Equal(t, Key{0xf8}, newKey)
	key = Key{0xff}
	newKey = key.AppendBit(4, false)
	require.Equal(t, Key{0xf7}, newKey)
	key = Key{0xff}
	newKey = key.AppendBit(8, true)
	require.Equal(t, Key{0xff, 0x80}, newKey)
	key = Key{0xff}
	newKey = key.AppendBit(8, false)
	require.Equal(t, Key{0xff, 0x00}, newKey)

	// byte-aligned split
	key = Key{0xaa, 0xbb, 0xcc, 0xdd}
	p, s := key.Split(16, 32)
	require.Equal(t, Key{0xaa, 0xbb}, p)
	require.Equal(t, Key{0xcc, 0xdd}, s)

	// byte-aligned merge
	key = Key{0xaa, 0xbb}
	newKey = key.Merge(16, Key{0xcc, 0xdd}, 16)
	require.Equal(t, Key{0xaa, 0xbb, 0xcc, 0xdd}, newKey)

	// empty/full splits
	key = Key{0xaa, 0xbb, 0xcc, 0xdd}
	p, s = key.Split(0, 32)
	require.Equal(t, Key{}, p)
	require.Equal(t, key, s)
	p, s = key.Split(32, 32)
	require.Equal(t, key, p)
	require.Equal(t, Key{}, s)

	// empty merges
	newKey = Key{}.Merge(0, Key{0xaa, 0xbb}, 16)
	require.Equal(t, Key{0xaa, 0xbb}, newKey)
	newKey = Key{0xaa, 0xbb}.Merge(16, Key{}, 0)
	require.Equal(t, Key{0xaa, 0xbb}, newKey)

	// non byte-aligned split
	key = Key{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	p, s = key.Split(17, 64)
	require.Equal(t, Key{0x01, 0x23, 0x00}, p)
	require.Equal(t, Key{0x8a, 0xcf, 0x13, 0x57, 0x9b, 0xde}, s)

	// ...and merge
	newKey = p.Merge(17, s, 64-17)
	require.Equal(t, key, newKey)

	// non byte-aligned key length split.
	key = Key{0xff, 0xff, 0xff, 0xff}
	p, s = key.Split(21, 29)
	// Check that split cleans the last 3 unused bits!
	require.Equal(t, Key{0xff, 0xff, 0xf8}, p)
	require.Equal(t, Key{0xff}, s)

	// ...and merge
	newKey = p.Merge(21, s, 8)
	// Merge doesn't obtain original key, because the split cleaned unused bits!
	require.Equal(t, Key{0xff, 0xff, 0xff, 0xf8}, newKey)
}

func TestKeyCommonPrefixLen(t *testing.T) {
	key := Key{}
	require.Equal(t, Depth(0), key.CommonPrefixLen(0, Key{}, 0))

	key = Key{0xff, 0xff}
	require.Equal(t, Depth(16), key.CommonPrefixLen(16, Key{0xff, 0xff, 0xff}, 24))

	key = Key{0xff, 0xff, 0xff}
	require.Equal(t, Depth(16), key.CommonPrefixLen(24, Key{0xff, 0xff}, 16))

	key = Key{0xff, 0xff, 0xff}
	require.Equal(t, Depth(24), key.CommonPrefixLen(24, Key{0xff, 0xff, 0xff}, 24))

	key = Key{0xab, 0xcd, 0xef, 0xff}
	require.Equal(t, Depth(23), key.CommonPrefixLen(32, Key{0xab, 0xcd, 0xee, 0xff}, 32))
}
