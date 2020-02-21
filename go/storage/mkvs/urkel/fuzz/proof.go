// +build gofuzz

package fuzz

import (
    "context"

    commonFuzz "github.com/oasislabs/oasis-core/go/common/fuzz"
    "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
)

var proofFuzzer *commonFuzz.InterfaceFuzzer

// ProofFuzz is a wrapper for fuzzing syncer proof decoding.
type ProofFuzz struct {}

func (p *ProofFuzz) DecodeProof(ctx context.Context, entries [][]byte) {
    var proof syncer.Proof
    proof.Entries = entries

    var verifier syncer.ProofVerifier
    _, _ = verifier.VerifyProof(ctx, proof.UntrustedRoot, &proof)
}

func NewProofFuzz() (*ProofFuzz, *commonFuzz.InterfaceFuzzer) {
    pf := &ProofFuzz{}
    fz := commonFuzz.NewInterfaceFuzzer(pf)
    return pf, fz
}

func init() {
    _, proofFuzzer = NewProofFuzz()
}

func FuzzProof(data []byte) int {
    _, result := proofFuzzer.DispatchBlob(data)
    if !result {
        return -1
    }

    return 0
}
