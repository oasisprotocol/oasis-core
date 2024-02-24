package runtime

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerChurp is the key manager CHURP scenario.
var KeymanagerChurp scenario.Scenario = newKmChurpImpl()

type kmChurpImpl struct {
	Scenario
}

func newKmChurpImpl() scenario.Scenario {
	return &kmChurpImpl{
		Scenario: *NewScenario(
			"keymanager-churp",
			NewTestClient(),
		),
	}
}

func (sc *kmChurpImpl) Clone() scenario.Scenario {
	return &kmChurpImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmChurpImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// We don't need compute workers.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}

	// Ensure that the key manager workers participate in the CHURP scheme.
	f.Keymanagers[0].ChurpIDs = []uint8{0}

	// Enable CHURP extension.
	f.Network.EnableKeyManagerCHURP = true

	return f, nil
}

func (sc *kmChurpImpl) Run(ctx context.Context, _ *env.Env) error {
	var nonce uint64

	if err := sc.Net.Start(); err != nil {
		return err
	}

	if err := sc.Net.ClientController().WaitReady(ctx); err != nil {
		return err
	}

	stCh, stSub, err := sc.Net.ClientController().Keymanager.Churp().WatchStatuses(ctx)
	if err != nil {
		return err
	}
	defer stSub.Close()

	// Create a new CHURP instance.
	identity := churp.Identity{
		ID:        0,
		RuntimeID: KeyManagerRuntimeID,
	}
	req := churp.CreateRequest{
		Identity:        identity,
		GroupID:         churp.EccNistP384,
		Threshold:       2,
		HandoffInterval: 1,
		Policy: churp.SignedPolicySGX{
			Policy: churp.PolicySGX{
				Identity: identity,
			},
		},
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

	// Test wether the key manager node submits an application every round.
	var st *churp.Status
	for i := range 4 {
		select {
		case st = <-stCh:
		case <-ctx.Done():
			return ctx.Err()
		}

		round := uint64(i / 2)
		if st.Round != round {
			return fmt.Errorf("expected round %d, not round %d", round, st.Round)
		}

		// New round started or node just submitted an application.
		if appSize := i % 2; len(st.Applications) != appSize {
			return fmt.Errorf("status should have %d applications", appSize)
		}
	}

	return nil
}
