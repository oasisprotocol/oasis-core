package sgx

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmnIAS "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type teeStateEPID struct {
	teeStateImplCommon

	epidGID uint32
}

func (ep *teeStateEPID) Init(ctx context.Context, sp *sgxProvisioner, runtimeID common.Namespace, version version.Version) ([]byte, error) {
	qi, err := sp.aesm.InitQuote(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting quote info from AESMD: %w", err)
	}

	ep.runtimeID = runtimeID
	ep.version = version
	ep.epidGID = binary.LittleEndian.Uint32(qi.GID[:])

	return qi.TargetInfo, nil
}

func (ep *teeStateEPID) Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error) {
	spidInfo, err := sp.ias.GetSPIDInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while requesting SPID info: %w", err)
	}

	// Check if new format of attestations is supported in the consensus layer and use it.
	regParams, err := sp.consensus.Registry().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("unable to determine registry consensus parameters: %w", err)
	}
	supportsAttestationV1 := (regParams.TEEFeatures != nil && regParams.TEEFeatures.SGX.PCS)

	// Update the SigRL (Not cached, knowing if revoked is important).
	sigRL, err := sp.ias.GetSigRL(ctx, ep.epidGID)
	if err != nil {
		return nil, fmt.Errorf("error while requesting SigRL: %w", err)
	}

	quote, err := sp.aesm.GetQuote(
		ctx,
		report,
		spidInfo.QuoteSignatureType,
		spidInfo.SPID,
		make([]byte, 16),
		sigRL,
	)
	if err != nil {
		return nil, fmt.Errorf("error while getting quote: %w", err)
	}

	// Get current quote policy from the consensus layer.
	var quotePolicy *cmnIAS.QuotePolicy
	var policies *sgxQuote.Policy
	policies, err = ep.getQuotePolicies(ctx, sp)
	if err != nil {
		return nil, err
	}
	if policies != nil {
		quotePolicy = policies.IAS
	}

	evidence := ias.Evidence{
		RuntimeID:                  ep.runtimeID,
		Quote:                      quote,
		Nonce:                      nonce,
		MinTCBEvaluationDataNumber: quotePolicy.MinTCBEvaluationDataNumber,
	}

	avrBundle, err := sp.ias.VerifyEvidence(ctx, &evidence)
	if err != nil {
		return nil, fmt.Errorf("error while verifying attestation evidence: %w", err)
	}

	// Decode the AVR so we can do further checks.
	avr, decErr := cmnIAS.UnsafeDecodeAVR(avrBundle.Body)
	if decErr == nil && avr.TCBEvaluationDataNumber < quotePolicy.MinTCBEvaluationDataNumber {
		// Retry again with early updating.
		evidence.EarlyTCBUpdate = true
		avrBundle, err = sp.ias.VerifyEvidence(ctx, &evidence)
		if err != nil {
			return nil, fmt.Errorf("error while verifying attestation evidence with early update: %w", err)
		}
		avr, decErr = cmnIAS.UnsafeDecodeAVR(avrBundle.Body)
	}
	if decErr != nil {
		return nil, fmt.Errorf("unable to decode AVR: %w", decErr)
	}
	if avr.TCBEvaluationDataNumber < quotePolicy.MinTCBEvaluationDataNumber {
		return nil, fmt.Errorf(
			"AVR TCB data evaluation number invalid (%v < %v)",
			avr.TCBEvaluationDataNumber,
			quotePolicy.MinTCBEvaluationDataNumber,
		)
	}

	// Prepare quote structure.
	q := sgxQuote.Quote{
		IAS: avrBundle,
	}

	rspBody, err := conn.Call(
		ctx,
		&protocol.Body{
			// TODO: Use RuntimeCapabilityTEERakQuoteRequest once all runtimes support it.
			RuntimeCapabilityTEERakAvrRequest: &protocol.RuntimeCapabilityTEERakAvrRequest{
				AVR: *avrBundle,
			},
		},
	)
	if err != nil {
		// If we are here, presumably the AVR is well-formed (VerifyEvidence
		// succeeded).  Since this is more than likely the AVR indicating
		// rejection, deserialize it and log some pertinent details.
		switch avr.ISVEnclaveQuoteStatus {
		case cmnIAS.QuoteOK, cmnIAS.QuoteSwHardeningNeeded:
			// That's odd, the quote checks out as ok.  Can't
			// really get further information.
		default:
			// This probably has to do with the never-ending series of
			// speculative execution trashfires, so log the vulns and
			// quote status.
			sp.logger.Error("attestation likely rejected by IAS",
				"quote_status", avr.ISVEnclaveQuoteStatus.String(),
				"advisory_ids", avr.AdvisoryIDs,
			)
		}

		return nil, fmt.Errorf("error while configuring AVR: %w", err)
	}

	var attestation []byte
	if supportsAttestationV1 {
		// Use V1 attestation format.
		rsp := rspBody.RuntimeCapabilityTEERakQuoteResponse
		if rsp == nil {
			return nil, fmt.Errorf("unexpected response from runtime")
		}

		attestation = cbor.Marshal(node.SGXAttestation{
			Versioned: cbor.NewVersioned(node.LatestSGXAttestationVersion),
			Quote:     q,
			Height:    rsp.Height,
			Signature: rsp.Signature,
		})
	} else {
		// Use V0 attestation format.
		attestation = cbor.Marshal(avrBundle)
	}

	return attestation, nil
}
