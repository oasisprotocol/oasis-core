package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	tmed "github.com/tendermint/tendermint/crypto/ed25519"

	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestSignatureConversions(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	tmSk := SignerToTendermint(signer)

	pk := signer.Public()
	tmPk := tmSk.PubKey().(tmed.PubKey)
	require.Equal(t, pk[:], tmPk.Bytes(), "Private key: Public keys")

	tmPk = PublicKeyToTendermint(&pk)
	require.Equal(t, pk[:], tmPk.Bytes(), "Public key: ToTendermint")

	pk2 := PublicKeyFromTendermint(&tmPk)
	require.Equal(t, pk[:], pk2[:], "Public key: FromTendermint")
}
