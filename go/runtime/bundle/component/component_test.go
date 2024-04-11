package component

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestID(t *testing.T) {
	require := require.New(t)

	for _, cid := range []ID{
		{Kind: RONL, Name: ""},
		{Kind: ROFL, Name: "a"},
		{Kind: ROFL, Name: "b.c.d"},
	} {
		raw, err := cid.MarshalText()
		require.NoError(err, "MarshalText")

		var dec ID
		err = dec.UnmarshalText(raw)
		require.NoError(err, "UnmarshalText")
		require.EqualValues(cid, dec, "serialization should round-trip")
	}

	for _, tc := range []struct {
		data string
		cid  *ID
	}{
		{"ronl", &ID{Kind: RONL, Name: ""}},
		{"ronl.", nil},
		{"ronl.foo", nil},
		{"ro", nil},
		{"bonl", nil},
		{"rofl", &ID{Kind: ROFL, Name: ""}},
		{"rofl.a", &ID{Kind: ROFL, Name: "a"}},
		{"rofl.b.c.d", &ID{Kind: ROFL, Name: "b.c.d"}},
	} {
		var dec ID
		err := dec.UnmarshalText([]byte(tc.data))
		if tc.cid == nil {
			require.Error(err, "UnmarshalText should fail on malformed inputs (%s)", tc.data)
		} else {
			require.NoError(err, "UnmarshalText should not fail (%s)", tc.data)
			require.EqualValues(dec, *tc.cid, "deserialization should be correct")
		}
	}
}
