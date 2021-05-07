package api

import (
	"crypto/rand"
	"testing"

	curve25519 "github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"github.com/stretchr/testify/require"
)

func Test_GenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeyPair(rand.Reader)
	require.NoError(t, err, "GenerateKeyPair")

	var pubTmp [32]byte
	curve25519.ScalarBaseMult(&pubTmp, priv)
	require.EqualValues(t, pub, &pubTmp, "scalarBaseMult(priv) ?= pub")
}
