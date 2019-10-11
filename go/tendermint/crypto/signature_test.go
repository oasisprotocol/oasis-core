package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	tmed "github.com/tendermint/tendermint/crypto/ed25519"

	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestSignatureConversions(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	tmSk := UnsafeSignerToTendermint(signer)
	require.Equal(t, signer.UnsafeBytes(), tmSk[:], "Private key: ToTendermint")

	pk := signer.Public()
	tmPk := tmSk.PubKey().(tmed.PubKeyEd25519)
	require.Equal(t, []byte(pk[:]), tmPk[:], "Private key: Public keys")

	tmPk = PublicKeyToTendermint(&pk)
	require.Equal(t, []byte(pk[:]), tmPk[:], "Public key: ToTendermint")

	pk2 := PublicKeyFromTendermint(&tmPk)
	require.Equal(t, []byte(pk[:]), []byte(pk2[:]), "Public key: FromTendermint")
}
