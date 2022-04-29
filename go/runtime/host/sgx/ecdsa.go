package sgx

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
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
	quote, err := sp.aesm.GetQuoteEx(ctx, ec.key, report)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	// TODO: Retrieve corresponding PCK certificate.
	// TODO: Retrieve corresponding TCB info.
	// TODO: Retrieve corresponding QE identity.
	// TODO: Call the runtime to configure an ECDSA attestation.

	return nil, fmt.Errorf("ECDSA attestation not yet implemented (quote: %X)", quote)
}
