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
			Messages: []*MessageEvent{{Module: "test", Code: 42, Index: 1, Result: cbor.Marshal("test-result")}},
			GoodComputeEntities: []signature.PublicKey{
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000000"),
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000001"),
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000002"),
			},
		}, "omhtZXNzYWdlc4GkZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3RmcmVzdWx0a3Rlc3QtcmVzdWx0dWdvb2RfY29tcHV0ZV9lbnRpdGllc4NYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="},
		{RoundResults{
			Messages: []*MessageEvent{{Module: "test", Code: 42, Index: 1, Result: cbor.Marshal("test-result")}},
			GoodComputeEntities: []signature.PublicKey{
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000000"),
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000002"),
			},
			BadComputeEntities: []signature.PublicKey{
				signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000001"),
			},
		}, "o2htZXNzYWdlc4GkZGNvZGUYKmVpbmRleAFmbW9kdWxlZHRlc3RmcmVzdWx0a3Rlc3QtcmVzdWx0dGJhZF9jb21wdXRlX2VudGl0aWVzgVggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF1Z29vZF9jb21wdXRlX2VudGl0aWVzglggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC"},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec RoundResults
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "RoundResults serialization should round-trip")
	}
}
