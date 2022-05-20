package sgx

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type teeStateECDSA struct {
	key *aesm.AttestationKeyID
}

func (ec *teeStateECDSA) Init(ctx context.Context, sp *sgxProvisioner, runtimeID common.Namespace) ([]byte, error) {
	akeys, err := sp.aesm.GetAttestationKeyIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch attestation key IDs: %w", err)
	}

	// Find the first suitable ECDSA-capable key.
	var key *aesm.AttestationKeyID
	for _, akey := range akeys {
		if akey.Type == aesm.AttestationKeyECDSA_P256 {
			key = akey
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("no suitable ECDSA attestation keys found")
	}

	// Retrieve the target info for QE.
	targetInfo, err := sp.aesm.GetTargetInfo(ctx, key)
	if err != nil {
		return nil, err
	}

	ec.key = key

	return targetInfo, nil
}

func (ec *teeStateECDSA) Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error) {
	rawQuote, err := sp.aesm.GetQuoteEx(ctx, ec.key, report)
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

	switch qs.CertificationData.(type) {
	case *pcs.CertificationData_PCKCertificateChain:
		// We have a PCK certificate chain and so are good to go.
	case *pcs.CertificationData_PPID:
		// We have a PPID, need to retrieve PCK certificate first.
		// TODO: Fetch PCK certificate based on PPID and include it in the quote, replacing the
		//       PPID certification data with the PCK certificate chain certification data.
		return nil, fmt.Errorf("PPID certification data not yet supported")
	default:
		return nil, fmt.Errorf("unsupported certification data type: %s", qs.CertificationData.CertificationDataType())
	}

	// Verify PCK certificate and extract the information required to get the TCB bundle.
	pckInfo, err := qs.VerifyPCK(time.Now())
	if err != nil {
		return nil, fmt.Errorf("PCK verification failed: %w", err)
	}
	// Fetch the TCB bundle from Intel PCS.
	tcbBundle, err := sp.pcs.GetTCBBundle(ctx, pckInfo.FMSPC)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TCB bundle: %w", err)
	}

	// Verify the quote so we can catch errors early (the runtime and later consensus layer will
	// also do their own verification).
	tcbLevel, err := quote.Verify(time.Now(), tcbBundle)
	if err != nil {
		return nil, fmt.Errorf("quote verification failed: %w", err)
	}

	// Validate TCB level.
	switch tcbLevel.Status {
	case pcs.StatusUpToDate, pcs.StatusSWHardeningNeeded:
		// These are ok.
	default:
		sp.logger.Error("current TCB is not up to date",
			"tcb_status", tcbLevel.Status.String(),
			"advisory_ids", tcbLevel.AdvisoryIDs,
		)
		return nil, fmt.Errorf("TCB is not up to date (likely needs upgrade): %s", tcbLevel.Status)
	}

	// TODO: Call the runtime with the quote and TCB bundle.

	return nil, fmt.Errorf("ECDSA attestation not yet implemented (quote: %X)", rawQuote)
}
