package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

func TestSerializationLeafNode(t *testing.T) {
	leafNode := &LeafNode{
		Key:   []byte("a golden key"),
		Value: []byte("value"),
	}

	rawLeafNodeFull, err := leafNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")
	rawLeafNodeCompactV0, err := leafNode.CompactMarshalBinaryV0()
	require.NoError(t, err, "CompactMarshalBinaryV1")
	rawLeafNodeCompactV1, err := leafNode.CompactMarshalBinaryV1()
	require.NoError(t, err, "CompactMarshalBinaryV1")

	for _, rawLeafNode := range [][]byte{rawLeafNodeFull, rawLeafNodeCompactV0, rawLeafNodeCompactV1} {
		var decodedLeafNode LeafNode
		err = decodedLeafNode.UnmarshalBinary(rawLeafNode)
		require.NoError(t, err, "UnmarshalBinary")

		require.True(t, decodedLeafNode.Clean)
		require.Equal(t, leafNode.Key, decodedLeafNode.Key)
		require.Equal(t, leafNode.Value, decodedLeafNode.Value)
	}
}

func TestSerializationInternalNode(t *testing.T) {
	leafNode := &LeafNode{
		Key:   []byte("a golden key"),
		Value: []byte("value"),
	}
	leafNode.UpdateHash()

	leftHash := hash.NewFromBytes([]byte("everyone move to the left"))
	rightHash := hash.NewFromBytes([]byte("everyone move to the right"))
	label := Key("abc")
	labelBitLength := Depth(24)

	intNode := &InternalNode{
		Label:          label,
		LabelBitLength: labelBitLength,
		LeafNode:       &Pointer{Clean: true, Node: leafNode, Hash: leafNode.Hash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	rawIntNodeFull, err := intNode.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")
	rawIntNodeCompactV0, err := intNode.CompactMarshalBinaryV0()
	require.NoError(t, err, "CompactMarshalBinary")
	rawIntNodeCompactV1, err := intNode.CompactMarshalBinaryV1()
	require.NoError(t, err, "CompactMarshalBinary")

	for idx, rawIntNode := range [][]byte{rawIntNodeFull, rawIntNodeCompactV0, rawIntNodeCompactV1} {
		var decodedIntNode InternalNode
		err = decodedIntNode.UnmarshalBinary(rawIntNode)
		require.NoError(t, err, "UnmarshalBinary")

		require.True(t, decodedIntNode.Clean)
		require.Equal(t, intNode.Label, decodedIntNode.Label)
		require.Equal(t, intNode.LabelBitLength, decodedIntNode.LabelBitLength)

		// Only check leaf/left/right for non-compact encoding.
		if idx == 0 {
			require.Equal(t, intNode.LeafNode.Hash, decodedIntNode.LeafNode.Hash)
			require.True(t, decodedIntNode.LeafNode.Clean)
			require.NotNil(t, decodedIntNode.LeafNode.Node)
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
	leafNode := &LeafNode{
		Key:   []byte("a golden key"),
		Value: []byte("value"),
	}

	leafNode.UpdateHash()

	require.Equal(t, "5c05183d4158b5920b16833acb78ccda464da83f720f824177b3a55a75f9fd88", leafNode.Hash.String())
}

func TestHashInternalNode(t *testing.T) {
	leafNodeHash := hash.NewFromBytes([]byte("everyone stop here"))
	leftHash := hash.NewFromBytes([]byte("everyone move to the left"))
	rightHash := hash.NewFromBytes([]byte("everyone move to the right"))

	intNode := &InternalNode{
		Label:          Key("abc"),
		LabelBitLength: 23,
		LeafNode:       &Pointer{Clean: true, Hash: leafNodeHash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	intNode.UpdateHash()

	require.Equal(t, "75c37c67c265e2c836f76dec35173fa336e976938ea46f088390a983e46efced", intNode.Hash.String())
}

func TestExtractLeafNode(t *testing.T) {
	leafNode := &LeafNode{
		Clean: true,
		Key:   []byte("a golden key"),
		Value: []byte("value"),
	}

	exLeafNode := leafNode.Extract().(*LeafNode)

	require.False(t, leafNode == exLeafNode, "extracted node must have a different address")
	require.False(t, &leafNode.Value == &exLeafNode.Value, "extracted value must have a different address")
	require.Equal(t, true, exLeafNode.Clean, "extracted leaf must be clean")
	require.EqualValues(t, leafNode.Key, exLeafNode.Key, "extracted leaf must have the same key")
	require.EqualValues(t, leafNode.Value, exLeafNode.Value, "extracted leaf's value must have the same value")
}

func TestExtractInternalNode(t *testing.T) {
	leftHash := hash.NewFromBytes([]byte("everyone move to the left"))
	rightHash := hash.NewFromBytes([]byte("everyone move to the right"))

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

func FuzzNode(f *testing.F) {
	// Seed corpus.
	leafNode := &LeafNode{
		Key:   []byte("a golden key"),
		Value: []byte("value"),
	}
	leafNode.UpdateHash()

	rawLeafNodeFull, _ := leafNode.MarshalBinary()
	rawLeafNodeCompactV0, _ := leafNode.CompactMarshalBinaryV0()
	rawLeafNodeCompactV1, _ := leafNode.CompactMarshalBinaryV1()
	f.Add(rawLeafNodeFull)
	f.Add(rawLeafNodeCompactV0)
	f.Add(rawLeafNodeCompactV1)

	leftHash := hash.NewFromBytes([]byte("everyone move to the left"))
	rightHash := hash.NewFromBytes([]byte("everyone move to the right"))
	label := Key("abc")
	labelBitLength := Depth(24)

	intNode := &InternalNode{
		Label:          label,
		LabelBitLength: labelBitLength,
		LeafNode:       &Pointer{Clean: true, Node: leafNode, Hash: leafNode.Hash},
		Left:           &Pointer{Clean: true, Hash: leftHash},
		Right:          &Pointer{Clean: true, Hash: rightHash},
	}

	rawIntNodeFull, _ := intNode.MarshalBinary()
	rawIntNodeCompactV0, _ := intNode.CompactMarshalBinaryV0()
	rawIntNodeCompactV1, _ := intNode.CompactMarshalBinaryV1()
	f.Add(rawIntNodeFull)
	f.Add(rawIntNodeCompactV0)
	f.Add(rawIntNodeCompactV1)

	// Fuzzing.
	f.Fuzz(func(_ *testing.T, data []byte) {
		n, err := UnmarshalBinary(data)
		if err != nil {
			return
		}

		_, err = n.CompactMarshalBinaryV0()
		if err != nil {
			panic(err)
		}

		_, err = n.CompactMarshalBinaryV1()
		if err != nil {
			panic(err)
		}
	})
}
