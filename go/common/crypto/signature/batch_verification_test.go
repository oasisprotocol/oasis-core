package signature

import (
	"errors"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/stretchr/testify/require"
)

func TestBatchVerifier(t *testing.T) {
	ctx := NewContext("batch verifier test context")

	msg := []byte("test message")
	data, err := PrepareSignerMessage(ctx, msg)
	require.NoError(t, err, "PrepareSignerMessage")

	pubKey, privKey := genTestKeypair(t)
	sig := ed25519.Sign(privKey, data)

	t.Run("EmptyBatch", func(t *testing.T) {
		var v BatchVerifier
		allOk, errs := v.Verify()
		require.True(t, allOk, "v.Verify(empty) - allOk")
		require.Len(t, errs, 0, "v.Verify(empty) - erros length")
	})

	t.Run("GoodBatch", func(t *testing.T) {
		v := NewBatchVerifier()
		v.Add(pubKey, ctx, msg, sig)
		v.Add(pubKey, ctx, msg, sig)

		allOk, errs := v.Verify()
		require.True(t, allOk, "v.Verify(good) - all ok")
		require.Len(t, errs, 2, "v.Verify(good) - errors length")
		for i, v := range errs {
			require.Nil(t, v, "v.Verify(good)[%d]", i)
		}
	})

	t.Run("BadBatch", func(t *testing.T) {
		errTest := errors.New("signature: batch verifier test error")

		v := NewBatchVerifierWithCapacity(5)
		v.Add(pubKey, ctx, msg, sig)
		v.AddError(errTest)
		v.Add(pubKey, ctx, nil, sig)
		v.Add(pubKey, ctx, msg, sig[:SignatureSize-1])
		v.Add(pubKey, Context("bad context"), msg, sig)

		allOk, errs := v.Verify()
		require.False(t, allOk, "v.Verify(bad) - all ok")
		require.Len(t, errs, 5, "v.Verify(bad) - errors length")

		expectedErrors := []error{
			nil,
			errTest,
			ErrVerifyFailed,
			ErrMalformedSignature,
			errUnregisteredContext,
		}
		for i, v := range errs {
			require.Equal(t, expectedErrors[i], v, "v.Verify(bad)[%d]", i)
		}
	})
}

func genTestKeypair(t *testing.T) (PublicKey, ed25519.PrivateKey) {
	// Can't use the memory signer because of import loops.
	rawPubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "GenerateKey")

	var pubKey PublicKey
	copy(pubKey[:], rawPubKey)

	return pubKey, privKey
}
