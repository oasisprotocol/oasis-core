package crypto

import (
	"crypto/rand"
	"testing"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"

	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestSignatureConversions(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	tmSk := SignerToCometBFT(signer)

	pk := signer.Public()
	tmPk := tmSk.PubKey().(cmted25519.PubKey)
	require.Equal(t, pk[:], tmPk.Bytes(), "Private key: Public keys")

	tmPk = PublicKeyToCometBFT(&pk)
	require.Equal(t, pk[:], tmPk.Bytes(), "Public key: ToCometBFT")

	pk2 := PublicKeyFromCometBFT(&tmPk)
	require.Equal(t, pk[:], pk2[:], "Public key: FromCometBFT")
}
