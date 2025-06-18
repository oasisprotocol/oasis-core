package api

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestLabelAttstation(t *testing.T) {
	require := require.New(t)

	la := LabelAttestation{
		Labels: map[string]string{
			"foo": "bar",
		},
		RAK: signature.NewPublicKey("4242424242424242424242424242424242424242424242424242424242424242"),
	}
	signer := memory.NewTestSigner("label attestation test")
	enc, sig, err := AttestLabels(signer, la)
	pk := signer.Public()
	require.NoError(err, "AttestLabels")
	require.Equal("a26372616b58204242424242424242424242424242424242424242424242424242424242424242666c6162656c73a163666f6f63626172", hex.EncodeToString(enc))
	require.Equal("4b386050bd904dbe4de4f6f0040ab64a18f8a305c9609231bcf90aa1dbd14a3c", hex.EncodeToString(pk[:]))
	require.Equal("6e7103250a95ed0b560dfabddec022bcd5416b96db1a999c725373e7d033dbfa14b8af29572fbe4b5cb2d30ac839ff4a465bb967169e5dcf888d06af90a3c809", hex.EncodeToString(sig[:]))
}
