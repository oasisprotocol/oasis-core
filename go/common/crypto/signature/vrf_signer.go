package signature

import (
	"encoding/base64"
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/ecvrf"
)

const (
	// ProofSize is the size of a VRF proof in bytes.
	ProofSize = ecvrf.ProofSize

	// BetaSize is the size of a VRF output in bytes.
	BetaSize = ecvrf.OutputSize
)

// VRFSigner is a Signer that also supports generating VRF proofs,
// using the semantics from v10 of the IETF Verifiable Random Functions
// draft.
type VRFSigner interface {
	Signer

	// Prove generates a VRF proof with the private key over the alpha.
	Prove(alphaString []byte) ([]byte, error)
}

// Prove generates a VRF proof with the private key over the alpha.
func Prove(signer Signer, alphaString []byte) (*Proof, error) {
	vrfSigner, ok := signer.(VRFSigner)
	if !ok {
		return nil, fmt.Errorf("signature: invalid signer for VRF proofs")
	}

	proof, err := vrfSigner.Prove(alphaString)
	if err != nil {
		return nil, err
	}

	p := &Proof{
		PublicKey: signer.Public(),
	}
	if err = p.Proof.UnmarshalBinary(proof); err != nil {
		return nil, err
	}
	return p, nil
}

// Proof is a VRF proof, bundled with the signing public key.
type Proof struct {
	// PublicKey is the public key that produced the proof.
	PublicKey PublicKey `json:"public_key"`

	// Proof is the actual raw proof.
	Proof RawProof `json:"proof"`
}

// Verify verifies a VRP proof over the alpha, and returns true iff the proof
// is valid.  Iff the proof is valid, beta is also returned.
func (p *Proof) Verify(alphaString []byte) (bool, []byte) {
	return p.PublicKey.VerifyVRF(alphaString, p.Proof[:])
}

// UnsafeToHash extracts the hash (beta) from a VRF proof.  This MUST only
// be called for proofs that are known to be valid.
func (p *Proof) UnsafeToHash() []byte {
	beta, err := ecvrf.ProofToHash(p.Proof[:])
	if err != nil {
		panic("signature/ecvrf: failed to extract beta: " + err.Error())
	}

	return beta
}

// VerifyVRF returns true iff the VRF proof is valid for the public key over
// alpha.  Iff the proof is valid, beta is also returned.
func (k PublicKey) VerifyVRF(alphaString, piString []byte) (bool, []byte) {
	if len(piString) != ProofSize {
		return false, nil
	}
	if k.IsBlacklisted() {
		return false, nil
	}

	return ecvrf.Verify_v10(k[:], piString, alphaString)
}

// RawProof is a raw VRF proof.
type RawProof [ProofSize]byte

// String returns a string representation of the raw VRF proof.
func (r RawProof) String() string {
	data, _ := r.MarshalText()
	return string(data)
}

// MarshalBinary encodes a VRF proof into binary form.
func (r RawProof) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, r[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled VRF proof.
func (r *RawProof) UnmarshalBinary(data []byte) error {
	if len(data) != ProofSize {
		return ErrMalformedSignature
	}

	copy(r[:], data)

	return nil
}

// MarshalText encodes a VRF proof into text form.
func (r RawProof) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(r[:])), nil
}

// UnmarshalText decodes a text marshaled VRF proof.
func (r *RawProof) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return r.UnmarshalBinary(b)
}
