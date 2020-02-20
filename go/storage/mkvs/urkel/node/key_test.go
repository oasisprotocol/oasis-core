package node

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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

	// Special case with zero-length key.
	key = Key{0x80}
	newKey = key.Merge(0, Key{0xf0}, 4)
	require.Equal(t, Key{0xf0}, newKey)

	// Special case with extra bytes.
	key = Key{0x41, 0x6b, 0x00}
	newKey = key.Merge(16, Key{0x37}, 8)
	require.Equal(t, Key{0x41, 0x6b, 0x37}, newKey)
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
