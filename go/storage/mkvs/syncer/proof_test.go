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
	rawProof, _ := base64.StdEncoding.DecodeString("omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=")

	var proof Proof
	err = cbor.Unmarshal(rawProof, &proof)
	if err != nil {
		panic(err)
	}

	// Verify the proof as a sanity check.
	var verifier ProofVerifier
	_, err = verifier.VerifyProof(context.Background(), rootHash, &proof)
	require.NoError(err)

	// Duplicate some nodes and add them to the end.
	proof.Entries = append(proof.Entries, proof.Entries[0])

	_, err = verifier.VerifyProof(context.Background(), rootHash, &proof)
	require.Error(err, "proof with extra data should fail to validate")
}

func FuzzProof(f *testing.F) {
	// Seed corpus.
	rawProof, _ := base64.StdEncoding.DecodeString("omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=")
	f.Add(rawProof)

	// Fuzzing.
	f.Fuzz(func(t *testing.T, data []byte) {
		var proof Proof
		err := cbor.Unmarshal(data, &proof)
		if err != nil {
			return
		}

		var verifier ProofVerifier
		_, _ = verifier.VerifyProof(context.Background(), proof.UntrustedRoot, &proof)
	})
}
