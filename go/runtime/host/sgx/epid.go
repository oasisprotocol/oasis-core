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
	runtimeID common.Namespace
	epidGID   uint32
	spid      cmnIAS.SPID
	quoteType *cmnIAS.SignatureType
}

func (ep *teeStateEPID) Init(ctx context.Context, sp *sgxProvisioner, runtimeID common.Namespace, version version.Version) ([]byte, error) {
	qi, err := sp.aesm.InitQuote(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting quote info from AESMD: %w", err)
	}

	spidInfo, err := sp.ias.GetSPIDInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting IAS SPID information: %w", err)
	}

	ep.runtimeID = runtimeID
	ep.epidGID = binary.LittleEndian.Uint32(qi.GID[:])
	ep.spid = spidInfo.SPID
	ep.quoteType = &spidInfo.QuoteSignatureType

	return qi.TargetInfo, nil
}

func (ep *teeStateEPID) Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error) {
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
	sigRL = cbor.FixSliceForSerde(sigRL)

	quote, err := sp.aesm.GetQuote(
		ctx,
		report,
		*ep.quoteType,
		ep.spid,
		make([]byte, 16),
		sigRL,
	)
	if err != nil {
		return nil, fmt.Errorf("error while getting quote: %w", err)
	}

	evidence := ias.Evidence{
		RuntimeID: ep.runtimeID,
		Quote:     quote,
		Nonce:     nonce,
	}

	avrBundle, err := sp.ias.VerifyEvidence(ctx, &evidence)
	if err != nil {
		return nil, fmt.Errorf("error while verifying attestation evidence: %w", err)
	}

	avrBundle.Body = cbor.FixSliceForSerde(avrBundle.Body)
	avrBundle.CertificateChain = cbor.FixSliceForSerde(avrBundle.CertificateChain)
	avrBundle.Signature = cbor.FixSliceForSerde(avrBundle.Signature)

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
		avr, decErr := cmnIAS.UnsafeDecodeAVR(avrBundle.Body)
		if decErr == nil {
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
