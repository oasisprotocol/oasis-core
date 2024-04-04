package bundle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComponentID(t *testing.T) {
	require := require.New(t)

	for _, cid := range []ComponentID{
		{Kind: ComponentRONL, Name: ""},
		{Kind: ComponentROFL, Name: "a"},
		{Kind: ComponentROFL, Name: "b.c.d"},
	} {
		raw, err := cid.MarshalText()
		require.NoError(err, "MarshalText")

		var dec ComponentID
		err = dec.UnmarshalText(raw)
		require.NoError(err, "UnmarshalText")
		require.EqualValues(cid, dec, "serialization should round-trip")
	}

	for _, tc := range []struct {
		data string
		cid  *ComponentID
	}{
		{"ronl", &ComponentID{Kind: ComponentRONL, Name: ""}},
		{"ronl.", nil},
		{"ronl.foo", nil},
		{"ro", nil},
		{"bonl", nil},
		{"rofl", &ComponentID{Kind: ComponentROFL, Name: ""}},
		{"rofl.a", &ComponentID{Kind: ComponentROFL, Name: "a"}},
		{"rofl.b.c.d", &ComponentID{Kind: ComponentROFL, Name: "b.c.d"}},
	} {
		var dec ComponentID
		err := dec.UnmarshalText([]byte(tc.data))
		if tc.cid == nil {
			require.Error(err, "UnmarshalText should fail on malformed inputs (%s)", tc.data)
		} else {
			require.NoError(err, "UnmarshalText should not fail (%s)", tc.data)
			require.EqualValues(dec, *tc.cid, "deserialization should be correct")
		}
	}
}
