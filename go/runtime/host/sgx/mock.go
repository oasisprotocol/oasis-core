package sgx

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type teeStateMock struct{}

func (ec *teeStateMock) Init(ctx context.Context, sp *sgxProvisioner, _ common.Namespace, _ version.Version) ([]byte, error) {
	// Check whether the consensus layer even supports ECDSA attestations.
	regParams, err := sp.consensus.Registry().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("unable to determine registry consensus parameters: %w", err)
	}
	if regParams.TEEFeatures == nil || !regParams.TEEFeatures.SGX.PCS {
		return nil, fmt.Errorf("ECDSA not supported by the registry")
	}

	// Generate mock QE target info.
	var targetInfo [512]byte

	return targetInfo[:], nil
}

func (ec *teeStateMock) Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, _ string) ([]byte, error) {
	rawQuote, err := pcs.NewMockQuote(report)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	var quote pcs.Quote
	if err = quote.UnmarshalBinary(rawQuote); err != nil {
		return nil, fmt.Errorf("failed to parse quote: %w", err)
	}

	// Check what information we need to retrieve based on what is in the quote.
	qs, ok := quote.Signature.(*pcs.QuoteSignatureECDSA_P256)
	if !ok {
		return nil, fmt.Errorf("unsupported attestation key type: %s", quote.Signature.AttestationKeyType())
	}

	// Verify PCK certificate and extract the information required to get the TCB bundle.
	pckInfo, err := qs.VerifyPCK(time.Now())
	if err != nil {
		return nil, fmt.Errorf("PCK verification failed: %w", err)
	}

	tcbBundle, err := sp.pcs.GetTCBBundle(ctx, pckInfo.FMSPC, pcs.UpdateStandard)
	if err != nil {
		return nil, err
	}

	// Prepare quote structure.
	q := sgxQuote.Quote{
		PCS: &pcs.QuoteBundle{
			Quote: rawQuote,
			TCB:   *tcbBundle,
		},
	}

	// Call the runtime with the quote and TCB bundle.
	rspBody, err := conn.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakQuoteRequest: &protocol.RuntimeCapabilityTEERakQuoteRequest{
				Quote: q,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error while configuring quote: %w", err)
	}
	rsp := rspBody.RuntimeCapabilityTEERakQuoteResponse
	if rsp == nil {
		return nil, fmt.Errorf("unexpected response from runtime")
	}

	return cbor.Marshal(node.SGXAttestation{
		Versioned: cbor.NewVersioned(node.LatestSGXAttestationVersion),
		Quote:     q,
		Height:    rsp.Height,
		Signature: rsp.Signature,
	}), nil
}
