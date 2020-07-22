package cbor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersioned(t *testing.T) {
	require := require.New(t)

	type a struct {
		A string
	}

	raw := Marshal(&a{
		A: "Open still remaineth the earth for great souls.",
	})
	_, err := GetVersion(raw)
	require.Equal(ErrInvalidVersion, err, "missing version should error")

	type b struct {
		Versioned
		a
	}

	const testVersion uint16 = 451
	raw = Marshal(&b{
		Versioned: NewVersioned(testVersion),
		a: a{
			A: "Empty are still many sites for lone ones and twain ones",
		},
	})
	version, err := GetVersion(raw)
	require.NoError(err, "versioned blobs should deserialize")
	require.Equal(testVersion, version, "the version should be correct")
}
