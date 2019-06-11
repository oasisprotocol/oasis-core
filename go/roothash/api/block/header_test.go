package block

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

func TestConsistentHash(t *testing.T) {
	// NOTE: These hashes MUST be synced with runtime/src/common/roothash.rs.
	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("4d449a81ebd463bc77718dc6d93ff38baa0c3c1587437dc283b96c3605c2cbea")

	var empty Header
	require.EqualValues(t, emptyHeaderHash, empty.EncodedHash())

	var populatedHeaderHash hash.Hash
	_ = populatedHeaderHash.UnmarshalHex("a97b8cb29db5cbe9d4e68d274402985b705b2e2d9e6a83491f2df6e1d9a8b0f6")

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var ns Namespace
	_ = ns.UnmarshalBinary(emptyRoot[:])

	populated := Header{
		Version:      42,
		Namespace:    ns,
		Round:        1000,
		Timestamp:    1560257841,
		HeaderType:   RoundFailed,
		PreviousHash: emptyHeaderHash,
		IORoot:       emptyRoot,
		StateRoot:    emptyRoot,
	}
	require.EqualValues(t, populatedHeaderHash, populated.EncodedHash())
}
