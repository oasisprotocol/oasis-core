package runtime

import (
	"context"
	"crypto/rand"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
)

func (sc *Scenario) initialEpochTransitions(ctx context.Context, fixture *oasis.NetworkFixture) (beacon.EpochTime, error) {
	return sc.initialEpochTransitionsWith(ctx, fixture, 0)
}

func (sc *Scenario) initialEpochTransitionsWith(ctx context.Context, fixture *oasis.NetworkFixture, baseEpoch beacon.EpochTime) (beacon.EpochTime, error) {
	epoch := baseEpoch + 1
	advanceEpoch := func() error {
		sc.Logger.Info("triggering epoch transition",
			"epoch", epoch,
		)
		if err := sc.Net.Controller().SetEpoch(ctx, epoch); err != nil {
			return fmt.Errorf("failed to set epoch: %w", err)
		}
		sc.Logger.Info("epoch transition done",
			"epoch", epoch,
		)

		epoch++

		return nil
	}

	if len(sc.Net.Keymanagers()) > 0 {
		// First wait for validator and key manager nodes to register. Then perform an epoch
		// transition which will cause the compute and storage nodes to register.
		sc.Logger.Info("waiting for validators to initialize",
			"num_validators", len(sc.Net.Validators()),
		)
		for i, n := range sc.Net.Validators() {
			if fixture.Validators[i].NoAutoStart {
				// Skip nodes that don't auto start.
				continue
			}
			if err := n.WaitReady(ctx); err != nil {
				return epoch, fmt.Errorf("failed to wait for a validator: %w", err)
			}
		}
		sc.Logger.Info("waiting for key managers to initialize",
			"num_keymanagers", len(sc.Net.Keymanagers()),
		)
		for i, n := range sc.Net.Keymanagers() {
			if fixture.Keymanagers[i].NoAutoStart {
				// Skip nodes that don't auto start.
				continue
			}
			if err := n.WaitReady(ctx); err != nil {
				return epoch, fmt.Errorf("failed to wait for a key manager: %w", err)
			}
		}
	}

	if err := advanceEpoch(); err != nil { // Epoch 1
		return epoch, err
	}

	// Wait for compute workers to become ready.
	sc.Logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.Net.ComputeWorkers()),
	)
	for i, n := range sc.Net.ComputeWorkers() {
		if fixture.ComputeWorkers[i].NoAutoStart {
			// Skip nodes that don't auto start.
			continue
		}
		if err := n.WaitReady(ctx); err != nil {
			return epoch, fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Byzantine nodes can only registered. If defined, since we cannot control them directly, wait
	// for all nodes to become registered.
	if len(sc.Net.Byzantine()) > 0 {
		sc.Logger.Info("waiting for (all) nodes to register",
			"num_nodes", sc.Net.NumRegisterNodes(),
		)
		if err := sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()); err != nil {
			return epoch, fmt.Errorf("failed to wait for nodes: %w", err)
		}
	}

	// Then perform epoch transition(s) to elect the committees.
	if err := advanceEpoch(); err != nil { // Epoch 2
		return epoch, err
	}
	switch sc.Net.Config().Beacon.Backend {
	case "", beacon.BackendVRF:
		// The byzantine node gets jammed into a committee first thing, which
		// breaks everything because our test case failure detection log watcher
		// can't cope with expected failures.  So once we elect, if the byzantine
		// node is active, we need to immediately transition into doing interesting
		// things.
		if !sc.debugWeakAlphaOk {
			// Committee elections won't happen the first round.
			if err := advanceEpoch(); err != nil { // Epoch 3
				return epoch, err
			}
			// And nodes are ineligible to be elected till their registration
			// epoch + 2.
			if err := advanceEpoch(); err != nil { // Epoch 4 (or 3 if byzantine test)
				return epoch, err
			}
		}
		if !sc.debugNoRandomInitialEpoch {
			// To prevent people from writing tests that depend on very precise
			// timekeeping by epoch, randomize the start epoch slightly.
			//
			// If this causes your test to fail, it is not this code that is
			// wrong, it is the test that is wrong.
			var randByte [1]byte
			_, _ = rand.Read(randByte[:])
			numSkips := (int)(randByte[0]&3) + 1
			sc.Logger.Info("advancing the epoch to prevent hardcoding time assumptions in tests",
				"num_advances", numSkips,
			)
			for i := 0; i < numSkips; i++ {
				if err := advanceEpoch(); err != nil {
					return epoch, err
				}
			}
		}
	}

	return epoch, nil
}
