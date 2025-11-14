package sgx

import (
	"context"
	"fmt"

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

	metricsEnabled bool
}

func (ts *teeState) init(ctx context.Context, sp *sgxProvisioner, metricsEnabled bool) ([]byte, error) {
	if ts.impl != nil {
		return nil, fmt.Errorf("already initialized")
	}
	ts.metricsEnabled = metricsEnabled // TODO are you sure?!

	var (
		targetInfo []byte
		err        error
	)

	// When insecure mock SGX is enabled, use mock implementation.
	if ts.insecureMock {
		ts.impl = &teeStateMock{}
		return ts.impl.Init(ctx, sp, ts.cfg)
	}

	// Try ECDSA first. If it fails, try EPID.
	implECDSA := &teeStateECDSA{}
	if targetInfo, err = implECDSA.Init(ctx, sp, ts.cfg); err != nil {
		sp.logger.Debug("ECDSA attestation initialization failed, trying EPID",
			"err", err,
		)

		implEPID := &teeStateEPID{}
		if targetInfo, err = implEPID.Init(ctx, sp, ts.cfg); err != nil {
			return nil, err
		}
		ts.impl = implEPID
	} else {
		ts.impl = implECDSA
	}

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

	if ts.metricsEnabled {
		common.UpdateAttestationMetrics(ts.cfg.ID, component.TEEKindSGX, err)
	}

	return attestation, err
}
