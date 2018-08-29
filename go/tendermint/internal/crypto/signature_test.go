package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	tmed "github.com/tendermint/tendermint/crypto/ed25519"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

func TestSignatureConversions(t *testing.T) {
	sk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")

	tmSk := PrivateKeyToTendermint(&sk)
	require.Equal(t, []byte(sk[:]), []byte(tmSk[:]), "Private key: ToTendermint")

	pk := sk.Public()
	tmPk := tmSk.PubKey().(tmed.PubKeyEd25519)
	require.Equal(t, []byte(pk[:]), []byte(tmPk[:]), "Private key: Public keys")

	sk2 := PrivateKeyFromTendermint(&tmSk)
	require.Equal(t, []byte(sk[:]), []byte(sk2[:]), "Private key: FromTendermint")

	tmPk = PublicKeyToTendermint(&pk)
	require.Equal(t, []byte(pk[:]), []byte(tmPk[:]), "Public key: ToTendermint")

	pk2 := PublicKeyFromTendermint(&tmPk)
	require.Equal(t, []byte(pk[:]), []byte(pk2[:]), "Public key: FromTendermint")
}
