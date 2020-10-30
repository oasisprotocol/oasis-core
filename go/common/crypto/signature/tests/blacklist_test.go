package tests

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestBlacklist(t *testing.T) {
	require := require.New(t)

	key := memorySigner.NewTestSigner("oasis blacklist")
	key2 := memorySigner.NewTestSigner("oasis blacklist 2")

	pk := key.Public()
	pk2 := key2.Public()

	require.True(pk.IsValid(), "test key should initially be valid")
	require.False(pk.IsBlacklisted(), "test key should not initially be blacklisted")

	err := pk.Blacklist()
	require.NoError(err, "adding test key to blacklist should not fail")
	require.True(pk.IsBlacklisted(), "test key should now be blacklisted")
	require.False(pk.IsValid(), "test key should now be invalid")

	pkHex := hex.EncodeToString(pk[:])
	require.Panics(func() { signature.NewBlacklistedPublicKey(pkHex) },
		"trying to blacklist the same public key twice should panic",
	)

	pk2Hex := hex.EncodeToString(pk2[:])
	require.NotPanics(func() { signature.NewBlacklistedPublicKey(pk2Hex) })
	require.True(pk2.IsBlacklisted(), "test key 2 should be blacklisted")
	require.False(pk2.IsValid(), "test key 2 should be invalid")
}
