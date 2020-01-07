package oasis

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"

	"github.com/oasislabs/ed25519"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
)

func generateDeterministicNodeKeys(t *testing.T, rawSeed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := crypto.SHA512.New()
	n, err := h.Write([]byte(rawSeed))
	require.Equal(t, len(rawSeed), n, "SHA512 Write bytes")
	require.NoError(t, err, "SHA512 Write")
	seed := h.Sum(nil)

	rng, err := drbg.New(crypto.SHA512, seed, nil, []byte("deterministic node identities test"))
	require.NoError(t, err, "drbg New")
	pub, priv, err := ed25519.GenerateKey(rng)
	require.NoError(t, err, "ed25519 GenerateKey")
	return pub, priv
}

func TestNodeIdentity(t *testing.T) {
	c0, _ := generateDeterministicNodeKeys(t, fmt.Sprintf(computeIdentitySeedTemplate, 0)) // Dbeo
	c1, _ := generateDeterministicNodeKeys(t, fmt.Sprintf(computeIdentitySeedTemplate, 1)) // oWk0
	c2, _ := generateDeterministicNodeKeys(t, fmt.Sprintf(computeIdentitySeedTemplate, 2)) // hcWV
	require.Equal(t, 1, bytes.Compare(c2, c0))
	require.Equal(t, 1, bytes.Compare(c1, c2))

	b0, _ := generateDeterministicNodeKeys(t, ByzantineDefaultIdentitySeed)
	b1, _ := generateDeterministicNodeKeys(t, ByzantineIndex1IdentitySeed)
	b2, _ := generateDeterministicNodeKeys(t, ByzantineIndex2IdentitySeed)
	b3, _ := generateDeterministicNodeKeys(t, ByzantineIndex3IdentitySeed)
	require.Equal(t, 1, bytes.Compare(c0, b0))
	require.Equal(t, 1, bytes.Compare(b1, c0))
	require.Equal(t, 1, bytes.Compare(c2, b1))
	require.Equal(t, 1, bytes.Compare(b2, c2))
	require.Equal(t, 1, bytes.Compare(c1, b2))
	require.Equal(t, 1, bytes.Compare(b3, c1))
}
