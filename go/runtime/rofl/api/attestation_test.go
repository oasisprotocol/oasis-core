package api

import (
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
	sig, err := AttestLabels(signer, la)
	require.NoError(err, "AttestLabels")
	require.Equal("bnEDJQqV7QtWDfq93sAivNVBa5bbGpmcclNz59Az2/oUuK8pVy++S1yy0wrIOf9KRlu5ZxaeXc+IjQavkKPICQ==", sig.String())
}
