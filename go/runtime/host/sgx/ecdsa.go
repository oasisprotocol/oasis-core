package sgx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type teeStateECDSA struct {
	runtimeID common.Namespace
	version   version.Version

	key *aesm.AttestationKeyID
}

func (ec *teeStateECDSA) Init(ctx context.Context, sp *sgxProvisioner, runtimeID common.Namespace, version version.Version) ([]byte, error) {
	// Check whether the consensus layer even supports ECDSA attestations.
	regParams, err := sp.consensus.Registry().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("unable to determine registry consensus parameters: %w", err)
	}
	if regParams.TEEFeatures == nil || !regParams.TEEFeatures.SGX.PCS {
		return nil, fmt.Errorf("ECDSA not supported by the registry")
	}

	// Fetch supported attestation keys.
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

	ec.runtimeID = runtimeID
	ec.version = version
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

	// Get current quote policy from the consensus layer.
	var quotePolicy *pcs.QuotePolicy
	rt, err := sp.consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height:           consensus.HeightLatest,
		ID:               ec.runtimeID,
		IncludeSuspended: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query runtime descriptor: %w", err)
	}
	if d := rt.DeploymentForVersion(ec.version); d != nil {
		var sc node.SGXConstraints
		if err = cbor.Unmarshal(d.TEE, &sc); err != nil {
			return nil, fmt.Errorf("malformed runtime SGX constraints: %w", err)
		}

		if sc.Policy != nil {
			quotePolicy = sc.Policy.PCS
		}
	}

	// Verify the quote so we can catch errors early (the runtime and later consensus layer will
	// also do their own verification).
	_, err = quote.Verify(quotePolicy, time.Now(), tcbBundle)
	var tcbErr *pcs.TCBOutOfDateError
	switch {
	case err == nil:
	case errors.As(err, &tcbErr):
		sp.logger.Error("current TCB is not up to date",
			"kind", tcbErr.Kind,
			"tcb_status", tcbErr.Status.String(),
			"advisory_ids", tcbErr.AdvisoryIDs,
		)
		return nil, tcbErr
	default:
		return nil, fmt.Errorf("quote verification failed: %w", err)
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
