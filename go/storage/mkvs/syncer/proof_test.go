package syncer

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

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
