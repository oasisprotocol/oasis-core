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
	_ = emptyHeaderHash.UnmarshalHex("96227abf446627117cd990023d9201f79ee2e3cc5119eded59259b913a1d79f5")

	var empty Header
	require.EqualValues(t, emptyHeaderHash, empty.EncodedHash())

	var populatedHeaderHash hash.Hash
	_ = populatedHeaderHash.UnmarshalHex("036e67a988b0ea6371a4482f708138322c3f7c4dd4ae4610e4018f96d78e1153")

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
		RoothashMessages: []*RoothashMessage{
			{
				DummyRoothashMessage: &DummyRoothashMessage{Greeting: "hi"},
			},
		},
	}
	require.EqualValues(t, populatedHeaderHash, populated.EncodedHash())
}
