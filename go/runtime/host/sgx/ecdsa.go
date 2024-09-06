package sgx

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	sgxCommon "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx/common"
)

type teeStateECDSA struct {
	key *aesm.AttestationKeyID
	cfg *host.Config
}

func (ec *teeStateECDSA) Init(ctx context.Context, sp *sgxProvisioner, cfg *host.Config) ([]byte, error) {
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

	ec.key = key
	ec.cfg = cfg

	return targetInfo, nil
}

func (ec *teeStateECDSA) Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, _ string) ([]byte, error) {
	rawQuote, err := sp.aesm.GetQuoteEx(ctx, ec.key, report)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	quotePolicy, err := sgxCommon.GetQuotePolicy(ctx, ec.cfg, sp.consensus, nil)
	if err != nil {
		return nil, err
	}
	var pcsQuotePolicy *pcs.QuotePolicy
	if quotePolicy != nil {
		pcsQuotePolicy = quotePolicy.PCS
	}

	quoteBundle, err := sp.pcs.ResolveQuote(ctx, rawQuote, pcsQuotePolicy)
	if err != nil {
		return nil, err
	}
	return sgxCommon.UpdateRuntimeQuote(ctx, conn, quoteBundle)
}
