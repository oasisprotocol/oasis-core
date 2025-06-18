package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

const (
	// LocalRPCEndpointAttestation is the name of the local RPC endpoint for attestation functions.
	LocalRPCEndpointAttestation = "attestation"

	// MethodAttestLabels is the name of the AttestLabels method.
	MethodAttestLabels = "AttestLabels"

	// MaxAttestLabels is the maximum number of labels on can request attestation for.
	MaxAttestLabels = 10
)

// AttestLabelsRequest is a request to host to attest to specific component labels.
type AttestLabelsRequest struct {
	// Labels are the labels to attest to.
	Labels []string `json:"labels"`
}

// AttestLabelsResponse is the response from the AttestLabels method.
type AttestLabelsResponse struct {
	// Attestation is the label attestation.
	Attestation LabelAttestation `json:"attstation"`
	// NodeID is the public key of the node attesting to the labels.
	NodeID signature.PublicKey `json:"node_id"`
	// Signature is the signature of the attested labels.
	Signature signature.RawSignature `json:"signature"`
}

// AttestLabelsSignatureContext is the signature context used for label attestation.
var AttestLabelsSignatureContext = signature.NewContext("oasis-core/node: attest component labels")

// LabelAttestation is an attestation of component labels.
type LabelAttestation struct {
	// Labels are the attested labels.
	Labels map[string]string `json:"labels"`
	// RAK is the component RAK.
	RAK signature.PublicKey `json:"rak"`
}

// AttestLabels signs the given label attestation and returns the signature.
func AttestLabels(signer signature.Signer, la LabelAttestation) (*signature.RawSignature, error) {
	return signature.SignRaw(signer, AttestLabelsSignatureContext, cbor.Marshal(la))
}
