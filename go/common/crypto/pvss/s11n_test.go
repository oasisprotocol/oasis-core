package pvss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPointMarshalText(t *testing.T) {
	require := require.New(t)

	// Valid point.
	_, p, err := NewKeyPair()
	require.NoError(err, "NewKeyPair")
	enc, err := p.MarshalText()
	require.NoError(err, "MarshalText")
	var u Point
	err = u.UnmarshalText(enc)
	require.NoError(err, "UnmarshalText")
	require.Equal(p, &u, "point should round-trip")

	// Invalid point.
	p = &Point{}
	_, err = p.MarshalText()
	require.Error(err, "MarshalText on invalid point should error")
}
