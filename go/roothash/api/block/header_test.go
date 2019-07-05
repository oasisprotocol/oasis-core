package block

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

func TestConsistentHash(t *testing.T) {
	// NOTE: These hashes MUST be synced with runtime/src/common/roothash.rs.
	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("fb1a6451509ddc17e94582df50e0fd1842ffce903a9a8d362ff90a3084e8dbdd")

	var empty Header
	require.EqualValues(t, emptyHeaderHash, empty.EncodedHash())

	var populatedHeaderHash hash.Hash
	_ = populatedHeaderHash.UnmarshalHex("091d12549887474e7fc6651c73711bf1da4dc567cdc845f6b14afd7f376305fc")

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var ns common.Namespace
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
