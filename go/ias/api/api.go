// Package api defines the IAS interfaces.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

// Endpoint is an attestation validation endpoint, likely remote.
type Endpoint interface {
	// VerifyEvidence takes the provided quote, (optional) PSE manifest, and
	// (optional) nonce, and returns the corresponding AVR, signature, and
	// certificate chain respectively.
	VerifyEvidence(ctx context.Context, evidence *Evidence) (*ias.AVRBundle, error)

	// GetSPID returns the SPID and associated info used by the endpoint.
	GetSPIDInfo(ctx context.Context) (*SPIDInfo, error)

	// GetSigRL returns the Signature Revocation List for a given EPID group.
	GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error)

	// Cleanup performs post-termination service cleanup.
	Cleanup()
}

// SPIDInfo contains information about the SPID associated with the client certificate.
type SPIDInfo struct {
	SPID               ias.SPID          `json:"spid"`
	QuoteSignatureType ias.SignatureType `json:"quote_signature_type"`
}

// Evidence is attestation evidence.
type Evidence struct {
	RuntimeID   common.Namespace `json:"runtime_id"`
	Quote       []byte           `json:"quote"`
	PSEManifest []byte           `json:"pse_manifest"`
	Nonce       string           `json:"nonce"`
}
