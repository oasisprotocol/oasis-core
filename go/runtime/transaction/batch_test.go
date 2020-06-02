package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

func TestConsistentHash(t *testing.T) {
	// NOTE: These hashes MUST be synced with runtime/src/transaction/types.rs.
	batch := RawBatch{[]byte("foo"), []byte("bar"), []byte("aaa")}
	h := hash.NewFrom(batch)

	var expectedHash hash.Hash
	_ = expectedHash.UnmarshalHex("c451dd4fd065b815e784aac6b300e479b2167408f0eebbb95a8bd36b9e71e34d")
	require.EqualValues(t, h, expectedHash)
}
