package lru

import (
	"testing"
	_ "unsafe"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

func TestSizeAccounting(t *testing.T) {
	item := nodeCacheItem{
		// Cache key: 32 bytes
		Node: &node.InternalNode{
			// Hash: 32 bytes
			// Round: 8 bytes
			// Label (slice pointers): 24 bytes
			Label: node.Key([]byte("my label")), // 8 bytes
			// LabelBitLength: 2 bytes
			// Clean: 1 byte
			// LeafNode (pointer): 8 bytes
			LeafNode: &node.Pointer{
				// Clean: 1 byte
				// Hash: 32 bytes
				// Node (interface): 16 bytes
				Node: &node.LeafNode{
					// Clean: 1 byte
					// Hash: 32 bytes
					// Round: 8 bytes
					// Key (slice pointers): 24 bytes
					Key: node.Key([]byte("key")), // 3 bytes
					// Value (slice pointers): 24 bytes
					Value: []byte("value"), // 5 bytes
					// Padding: 7 bytes
				},
				// LRU (nil pointer): 8 bytes
				// DBInternal (nil interface): 16 bytes
				// Padding: 7 bytes
			},
			// Left (nil pointer): 8 bytes
			// Right (nil pointer): 8 bytes
			// Padding: 5 bytes
		},
	}

	// Total size is computed based on the breakdown above.
	totalSize := 32 +
		// Node:
		32 + // .Hash
		8 + // .Round
		24 + // .Label
		8 + // .Label
		2 + // .LabelBitLength
		1 + // .Clean
		// Node.LeafNode:
		(8 + // .LeafNode
			1 + // .Clean
			32 + // .Hash
			16 + // .Node
			// Node.LeafNode.Node:
			(1 + // .Clean
				32 + // .Hash
				8 + // .Round
				24 + // .Key
				3 + // .Key
				24 + // .Value
				5 + // .Value
				7) + // (padding)
			// ---
			8 + // .LRU
			16 + // .DBInternal
			7) + // (padding)
		// ---
		8 + // .Left
		8 + // .Right
		5 // (padding)

	require.EqualValues(t, totalSize, item.Size(), "cached item size should be correct")
}
