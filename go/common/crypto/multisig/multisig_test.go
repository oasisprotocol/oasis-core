package multisig

import (
	"crypto/rand"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestAccount(t *testing.T) {
	require := require.New(t)

	signer, err := memory.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	// Bad version
	badVersion := &Account{
		Versioned: cbor.Versioned{
			V: 1,
		},
	}
	err = badVersion.Verify()
	require.Error(err, "Account.Verify(): bad version")

	// No signers
	noSigners := &Account{
		Threshold: 1,
	}
	err = noSigners.Verify()
	require.Error(err, "Account.Verify(): no signers")

	// Bad threshold
	badThreshold := &Account{
		Signers: []AccountSigner{
			{
				PublicKey: signer.Public(),
				Weight:    1,
			},
		},
		Threshold: 0,
	}
	err = badThreshold.Verify()
	require.Error(err, "Account.Verify(): zero threshold")
	badThreshold.Threshold = 5
	err = badThreshold.Verify()
	require.Error(err, "Account.Verify(): impossible threshold")

	// Bad weight
	badWeight := &Account{
		Signers: []AccountSigner{
			{
				PublicKey: signer.Public(),
				Weight:    0,
			},
		},
		Threshold: 1,
	}
	err = badWeight.Verify()
	require.Error(err, "Account.Verify(): invalid signing weight")

	// Duplicate signer
	dupSigner := &Account{
		Signers: []AccountSigner{
			{
				PublicKey: signer.Public(),
				Weight:    1,
			},
			{
				PublicKey: signer.Public(),
				Weight:    2,
			},
		},
		Threshold: 1,
	}
	err = dupSigner.Verify()
	require.Error(err, "Account.Verify(): duplicate signer")

	// Weight overflow
	signer2, err := memory.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	weightOverflow := &Account{
		Signers: []AccountSigner{
			{
				PublicKey: signer.Public(),
				Weight:    math.MaxUint64,
			},
			{
				PublicKey: signer2.Public(),
				Weight:    1,
			},
		},
		Threshold: 1,
	}
	err = weightOverflow.Verify()
	require.Error(err, "Account.Verify(): weight overflow")

	// Ok
	account := &Account{
		Signers: []AccountSigner{
			{
				PublicKey: signer.Public(),
				Weight:    1,
			},
			{
				PublicKey: signer2.Public(),
				Weight:    1,
			},
		},
		Threshold: 1,
	}
	err = account.Verify()
	require.NoError(err, "Account.Verify()")
}

func TestEnvelope(t *testing.T) {
	require := require.New(t)

	// Define a random test payload
	type testPayload struct {
		TestData string
	}
	data := testPayload{
		TestData: "Hasta el suelo, Mi amigo linoleo, Linoleo",
	}
	payload := cbor.Marshal(data)

	// Define a test account
	signer1, err := memory.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	signer2, err := memory.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	signer3, err := memory.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	account := &Account{
		Signers: []AccountSigner{
			{
				PublicKey: signer1.Public(),
				Weight:    1,
			},
			{
				PublicKey: signer2.Public(),
				Weight:    1,
			},
			{
				PublicKey: signer3.Public(),
				Weight:    1,
			},
		},
		Threshold: 2,
	}

	// Make the signatures we'll need
	signature.SetChainContext("test: oasis-core tests")
	context := signature.NewContext("oasis-core/crypto/multisig: tests", signature.WithChainSeparation())
	sig1, err := Sign(signer1, account, context, payload)
	require.NoError(err, "Sign: signer1")
	sig2, err := Sign(signer2, account, context, payload)
	require.NoError(err, "Sign: signer2")
	sig3, err := Sign(signer3, account, context, payload)
	require.NoError(err, "Sign: signer3")

	// All signatures
	var dest testPayload
	envelope, err := NewEnvelope(account, []*signature.Signature{sig1, sig2, sig3}, payload)
	require.NoError(err, "NewEnvelope: all signatures")
	err = envelope.Open(context, &dest)
	require.NoError(err, "Open: all signatures")
	require.Equal(data, dest, "envelope roundtrips")

	// 2 signatures
	envelope, err = NewEnvelope(account, []*signature.Signature{sig2, sig3}, payload)
	require.NoError(err, "NewEnvelope: 2 signatures")
	err = envelope.Open(context, &dest)
	require.NoError(err, "Open: 2 signatures")

	// 1 signature
	envelope, err = NewEnvelope(account, []*signature.Signature{sig1}, payload)
	require.NoError(err, "NewEnvelope: 1 signature")
	err = envelope.Open(context, &dest)
	require.Error(err, "Open: 1 signatures")

	// Bad signature
	envelope.Signatures[0][0] ^= 0xa5
	err = envelope.Open(context, &dest)
	require.Error(err, "Open: bad signature")

	// Invalid number of signatures/sentinels
	envelope.Signatures = envelope.Signatures[:2]
	err = envelope.Open(context, &dest)
	require.Error(err, "Open: invalid number of signatures/sentinels")
}
