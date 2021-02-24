package api

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestRoundResultsSerialization(t *testing.T) {
	require := require.New(t)

	// NOTE: These cases should be synced with tests in runtime/src/consensus/roothash.rs.
	for _, tc := range []struct {
		rr             RoundResults
		expectedBase64 string
	}{
		{RoundResults{}, "oA=="},
		{RoundResults{Messages: []*MessageEvent{{Module: "test", Code: 1, Index: 0}}}, "oWhtZXNzYWdlc4GiZGNvZGUBZm1vZHVsZWR0ZXN0"},
		{RoundResults{
			Messages: []*MessageEvent{{Module: "test", Code: 42, Index: 1}},
			GoodComputeNodes: []signature.PublicKey{
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000000"),
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000001"),
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000002"),
			},
		}, "omhtZXNzYWdlc4GjZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3RyZ29vZF9jb21wdXRlX25vZGVzg1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg=="},
		{RoundResults{
			Messages: []*MessageEvent{{Module: "test", Code: 42, Index: 1}},
			GoodComputeNodes: []signature.PublicKey{
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000000"),
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000002"),
			},
			BadComputeNodes: []signature.PublicKey{
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000001"),
			},
		}, "o2htZXNzYWdlc4GjZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3RxYmFkX2NvbXB1dGVfbm9kZXOBWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXJnb29kX2NvbXB1dGVfbm9kZXOCWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec RoundResults
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "RoundResults serialization should round-trip")
	}
}
