package sgx

import (
	"context"
	"fmt"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sgx/common"
)

type teeStateImpl interface {
	// Init initializes the TEE state and returns the QE target info.
	Init(ctx context.Context, sp *sgxProvisioner, cfg *host.Config) ([]byte, error)

	// Update updates the TEE state and returns a new attestation.
	Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error)
}

type teeState struct {
	cfg          *host.Config
	insecureMock bool

	impl teeStateImpl
}

func (ts *teeState) init(ctx context.Context, sp *sgxProvisioner) ([]byte, error) {
	if ts.impl != nil {
		return nil, fmt.Errorf("already initialized")
	}

	// Check whether the consensus layer even supports ECDSA attestations.
	regParams, err := sp.consensus.Registry().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("unable to determine registry consensus parameters: %w", err)
	}
	if regParams.TEEFeatures == nil || !regParams.TEEFeatures.SGX.PCS {
		return nil, fmt.Errorf("ECDSA not supported by the registry")
	}

	// When insecure mock SGX is enabled, use mock implementation.
	if ts.insecureMock {
		ts.impl = &teeStateMock{}
		return ts.impl.Init(ctx, sp, ts.cfg)
	}

	implECDSA := &teeStateECDSA{}
	targetInfo, err := implECDSA.Init(ctx, sp, ts.cfg)
	if err != nil {
		return nil, fmt.Errorf("ECDSA attestation initialization failed: %w", err)
	}
	ts.impl = implECDSA

	return targetInfo, nil
}

func (ts *teeState) updateTargetInfo(ctx context.Context, sp *sgxProvisioner) ([]byte, error) {
	if ts.impl == nil {
		return nil, fmt.Errorf("not initialized")
	}
	return ts.impl.Init(ctx, sp, ts.cfg)
}

func (ts *teeState) update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error) {
	if ts.impl == nil {
		return nil, fmt.Errorf("not initialized")
	}

	attestation, err := ts.impl.Update(ctx, sp, conn, report, nonce)

	common.UpdateAttestationMetrics(ts.cfg.ID, component.TEEKindSGX, err)

	return attestation, err
}
