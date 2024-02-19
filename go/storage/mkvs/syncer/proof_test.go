package syncer

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

func TestProofExtraNodes(t *testing.T) {
	require := require.New(t)

	var rootHash hash.Hash
	err := rootHash.UnmarshalHex("59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613")
	require.NoError(err)

	// V0 Proof.
	rawProofV0, _ := base64.StdEncoding.DecodeString("omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=")
	var proof Proof
	err = cbor.Unmarshal(rawProofV0, &proof)
	require.NoError(err, "failed to unmarshal V0 proof")
	require.EqualValues(0, proof.V)
	// Verify the proof as a sanity check.
	var verifier ProofVerifier
	_, err = verifier.VerifyProof(context.Background(), rootHash, &proof)
	require.NoError(err)
	wl, err := verifier.VerifyProofToWriteLog(context.Background(), rootHash, &proof)
	require.NoError(err)
	require.Empty(wl)

	// Duplicate some nodes and add them to the end.
	proof.Entries = append(proof.Entries, proof.Entries[0])

	_, err = verifier.VerifyProof(context.Background(), rootHash, &proof)
	require.Error(err, "proof with extra data should fail to validate")

	// V1 Proof.
	rawProofV1, _ := base64.StdEncoding.DecodeString("o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9kYBAQEAAAL2WCECwWW1hGEPh0DAc506YSKBjWvTakkfoieGKJsqWH2d5iVYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCBZ5nwv3Ai44Q3Qi7a47+YU/Mll7LiWJfl/F/h/BxBGEw==")
	err = cbor.Unmarshal(rawProofV1, &proof)
	require.NoError(err, "failed to unmarshal V1 proof")
	require.EqualValues(1, proof.V)
	// Verify the proof as a sanity check.
	_, err = verifier.VerifyProof(context.Background(), rootHash, &proof)
	require.NoError(err)
	wl, err = verifier.VerifyProofToWriteLog(context.Background(), rootHash, &proof)
	require.NoError(err)
	require.Empty(wl)

	// Duplicate some nodes and add them to the end.
	proof.Entries = append(proof.Entries, proof.Entries[0])

	_, err = verifier.VerifyProof(context.Background(), rootHash, &proof)
	require.Error(err, "proof with extra data should fail to validate")
}

func FuzzProof(f *testing.F) {
	// Seed corpus.
	rawProofV0, _ := base64.StdEncoding.DecodeString("omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=")
	f.Add(rawProofV0)
	rawProofV1, _ := base64.StdEncoding.DecodeString("o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9lghAibniky28BTAIiYrb3z9/rTq7r91woTo2EqR91Pf16P9RgEBAwCAAvZYIQIwwW7eyXCi2yXyFCzFD9U+Ssy1gwSwiskBQfk+9KCUA1QBAAUAa2V5IDkHAAAAdmFsdWUgOW51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=")
	f.Add(rawProofV1)

	// Fuzzing.
	f.Fuzz(func(_ *testing.T, data []byte) {
		var proof Proof
		err := cbor.Unmarshal(data, &proof)
		if err != nil {
			return
		}

		var verifier ProofVerifier
		_, _ = verifier.VerifyProof(context.Background(), proof.UntrustedRoot, &proof)
	})
}
