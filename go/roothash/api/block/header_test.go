package block

import (
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/oasislabs/ekiden/go/grpc/roothash"
)

func TestLegacyRound(t *testing.T) {
	for i, vec := range []struct {
		value   uint64
		encoded []byte
	}{
		{0xcafedeadbeeff00d, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0d}},
		{0xcafedeadbeeff0, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xf0}},
		{0xcafedeadbeef, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef}},
		{0xcafedeadbe, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe}},
		{0xcafedead, []byte{0xca, 0xfe, 0xde, 0xad}},
		{0xcafede, []byte{0xca, 0xfe, 0xde}},
		{0xcafe, []byte{0xca, 0xfe}},
		{0xca, []byte{0xca}},
		{0, []byte{}},
	} {
		pbHeader := pb.Header{
			Namespace:       make([]byte, NamespaceSize),
			RoundLegacy:     vec.encoded,
			PreviousHash:    make([]byte, 32),
			GroupHash:       make([]byte, 32),
			InputHash:       make([]byte, 32),
			OutputHash:      make([]byte, 32),
			TagHash:         make([]byte, 32),
			StateRoot:       make([]byte, 32),
			CommitmentsHash: make([]byte, 32),
		}

		var header Header
		err := header.FromProto(&pbHeader)
		require.NoError(t, err, "[%d]: FromProto(legacy)", i)
		require.EqualValues(t, vec.value, header.Round, "[%d]: FromProto(legacy)", i)

		// Test without legacy round.
		pbHeader.RoundLegacy = nil
		pbHeader.Round = vec.value

		header = Header{}
		err = header.FromProto(&pbHeader)
		require.NoError(t, err, "[%d]: FromProto(new)", i)
		require.EqualValues(t, vec.value, header.Round, "[%d]: FromProto(new)", i)
	}
}
