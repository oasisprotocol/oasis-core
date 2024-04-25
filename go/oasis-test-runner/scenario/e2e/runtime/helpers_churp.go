package runtime

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

// createChurp creates a new CHURP scheme with the given parameters.
func (sc *Scenario) createChurp(ctx context.Context, id uint8, threshold uint8, handoffInterval beacon.EpochTime, nonce uint64) error {
	identity := churp.Identity{
		ID:        id,
		RuntimeID: KeyManagerRuntimeID,
	}
	req := churp.CreateRequest{
		Identity:        identity,
		SuiteID:         churp.NistP384Sha3_384,
		Threshold:       threshold,
		ExtraShares:     0,
		HandoffInterval: handoffInterval,
		Policy: churp.SignedPolicySGX{
			Policy: churp.PolicySGX{
				Identity: identity,
			},
		},
	}

	if enclaveID := sc.Net.Runtimes()[0].GetEnclaveIdentity(0); enclaveID != nil {
		req.Policy.Policy.MayJoin = []sgx.EnclaveIdentity{*enclaveID}
		req.Policy.Policy.MayShare = []sgx.EnclaveIdentity{*enclaveID}
	}

	if err := req.Policy.Sign(api.TestSigners); err != nil {
		return err
	}

	tx := churp.NewCreateTx(nonce, &transaction.Fee{Gas: 10000}, &req)
	entSigner := sc.Net.Entities()[0].Signer()
	sigTx, err := transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed signing create churp transaction: %w", err)
	}

	err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return fmt.Errorf("failed submitting create churp transaction: %w", err)
	}

	return nil
}

// updateChurp updates the CHURP scheme with the given parameters.
func (sc *Scenario) updateChurp(ctx context.Context, id uint8, handoffInterval beacon.EpochTime, nonce uint64) error {
	identity := churp.Identity{
		ID:        id,
		RuntimeID: KeyManagerRuntimeID,
	}
	req := churp.UpdateRequest{
		Identity:        identity,
		ExtraShares:     nil,
		HandoffInterval: &handoffInterval,
		Policy:          nil,
	}

	tx := churp.NewUpdateTx(nonce, &transaction.Fee{Gas: 10000}, &req)
	entSigner := sc.Net.Entities()[0].Signer()
	sigTx, err := transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed signing update churp transaction: %w", err)
	}

	err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return fmt.Errorf("failed submitting update churp transaction: %w", err)
	}

	return nil
}

// nextChurpStatus waits for and returns the next CHURP status.
func (sc *Scenario) nextChurpStatus(ctx context.Context, stCh <-chan *churp.Status) (*churp.Status, error) {
	select {
	case status := <-stCh:
		sc.Logger.Info("status updated",
			"status", fmt.Sprintf("%+v", status),
		)
		return status, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
