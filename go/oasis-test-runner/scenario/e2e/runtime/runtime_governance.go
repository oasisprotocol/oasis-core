package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// RuntimeGovernance is a scenario which tests runtime governance.
//
// Two runtimes with the runtime governance model are created at genesis time.
// We submit an update_runtime runtime transaction with a slightly modified
// runtime descriptor to the first runtime.  This transaction triggers the
// runtime to emit an update_runtime message, which in turn causes the runtime
// to be re-registered with the updated descriptor specified in the message.
// After an epoch transition, we fetch the runtime descriptor from the registry
// and check if the modification took place or not.
//
// Additionally, we test that a runtime cannot update another runtime by passing
// a modified other runtime's descriptor to the update_runtime call of another
// runtime.
var RuntimeGovernance = func() scenario.Scenario {
	sc := &runtimeGovernanceImpl{
		runtimeImpl: *newRuntimeImpl("runtime-governance", nil),
	}
	return sc
}()

type runtimeGovernanceImpl struct {
	runtimeImpl
}

func (sc *runtimeGovernanceImpl) Clone() scenario.Scenario {
	return &runtimeGovernanceImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *runtimeGovernanceImpl) Fixture() (*oasis.NetworkFixture, error) {
	// Start with the default fixture and make some modifications below.
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use deterministic identities as we need to allocate funds to nodes.
	f.Network.DeterministicIdentities = true

	// Remove existing compute runtimes from fixture, remember RuntimeID and
	// binary from the first one.
	var id common.Namespace
	var runtimeBinaries map[node.TEEHardware]string
	var rts []oasis.RuntimeFixture
	for _, rt := range f.Runtimes {
		if rt.Kind == registry.KindCompute {
			if runtimeBinaries == nil {
				copy(id[:], rt.ID[:])
				runtimeBinaries = rt.Deployments[0].Binaries
			}
		} else {
			rts = append(rts, rt)
		}
	}
	f.Runtimes = rts

	// Avoid unexpected blocks.
	f.Network.SetMockEpoch()

	// Add our two test runtimes with the runtime governance model set.
	for i := 1; i <= 2; i++ {
		// Increase LSB by 1.
		id[len(id)-1]++
		newRtFixture := oasis.RuntimeFixture{
			ID:         id,
			Kind:       registry.KindCompute,
			Entity:     0,
			Keymanager: 0,
			Executor: registry.ExecutorParameters{
				GroupSize:       2,
				GroupBackupSize: 0,
				RoundTimeout:    20,
				MaxMessages:     128,
			},
			TxnScheduler: registry.TxnSchedulerParameters{
				MaxBatchSize:      100,
				MaxBatchSizeBytes: 1024 * 1024,
				BatchFlushTimeout: 1 * time.Second,
				ProposerTimeout:   10,
			},
			AdmissionPolicy: registry.RuntimeAdmissionPolicy{
				AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
			},
			GovernanceModel: registry.GovernanceRuntime,
			Deployments: []oasis.DeploymentCfg{
				{
					Binaries: runtimeBinaries,
				},
			},
		}

		f.Runtimes = append(f.Runtimes, newRtFixture)
	}

	var computeRuntimes []int
	for id, rt := range f.Runtimes {
		if rt.Kind == registry.KindCompute {
			computeRuntimes = append(computeRuntimes, id)
		}
	}

	// Set up compute worker fixtures.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}
	for i := 0; i < 2; i++ {
		f.ComputeWorkers = append(f.ComputeWorkers,
			oasis.ComputeWorkerFixture{
				Entity:   1,
				Runtimes: computeRuntimes,
			},
		)
	}
	f.Clients[0].Runtimes = computeRuntimes

	// Set up staking.
	f.Network.StakingGenesis = &staking.Genesis{
		TotalSupply: *quantity.NewFromUint64(9*10_000_000_000 + 2*1_000_000 + 10_000_000),
		Ledger: map[staking.Address]*staking.Account{
			e2e.DeterministicValidator0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicValidator1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicValidator2: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicValidator3: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicCompute0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicCompute1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicStorage0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicStorage1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicKeyManager0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10_000_000_000),
				},
			},
			e2e.DeterministicEntity1: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(10_000_000),
						TotalShares: *quantity.NewFromUint64(10_000_000),
					},
				},
			},
			staking.NewRuntimeAddress(f.Runtimes[0].ID): {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(1_000_000),
						TotalShares: *quantity.NewFromUint64(1_000_000),
					},
				},
			},
			staking.NewRuntimeAddress(f.Runtimes[1].ID): {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(1_000_000),
						TotalShares: *quantity.NewFromUint64(1_000_000),
					},
				},
			},
		},
		Delegations: map[staking.Address]map[staking.Address]*staking.Delegation{
			e2e.DeterministicEntity1: {
				e2e.DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(10_000_000),
				},
			},
			staking.NewRuntimeAddress(f.Runtimes[0].ID): {
				e2e.DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(1_000_000),
				},
			},
			staking.NewRuntimeAddress(f.Runtimes[1].ID): {
				e2e.DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(1_000_000),
				},
			},
		},
	}

	return f, nil
}

func (sc *runtimeGovernanceImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Wait for all nodes to start.
	if _, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	ctx := context.Background()
	var rtNonce uint64

	// Filter compute runtimes.
	var crt []*registry.Runtime
	for _, r := range sc.Net.Runtimes() {
		rt := r.ToRuntimeDescriptor()
		if rt.Kind == registry.KindCompute {
			crt = append(crt, &rt)
		}
	}

	// Submit transactions.
	c := sc.Net.ClientController().RuntimeClient

	rt := crt[0]

	blkCh, sub, err := c.WatchBlocks(ctx, rt.ID)
	if err != nil {
		return err
	}
	defer sub.Close()

	sc.Logger.Info("submitting update transaction to runtime",
		"runtime_id", rt.ID,
	)

	// Change something in the runtime descriptor & trigger update_runtime.
	newRT := *rt
	newRT.Executor.MaxMessages = 64
	newRT.Genesis.StateRoot.Empty()

	meta, err := sc.submitRuntimeTxMeta(ctx, rt.ID, rtNonce, "update_runtime", struct {
		UpdateRuntime registry.Runtime `json:"update_runtime"`
	}{
		UpdateRuntime: newRT,
	})
	if err != nil {
		return err
	}
	if _, err = unpackRawTxResp(meta.Output); err != nil {
		return err
	}
	rtNonce++

	// Wait for next round.
	for {
		select {
		case blk := <-blkCh:
			sc.Logger.Debug("round transition", "round", blk.Block.Header.Round)
			if blk.Block.Header.Round <= meta.Round {
				continue
			}
		case <-time.After(waitTimeout):
			return fmt.Errorf("timed out waiting for runtime rounds")
		}

		break
	}

	// Verify that the descriptor was updated.
	sc.Logger.Info("checking that the runtime descriptor was updated")
	fetchedRT, err := sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     rt.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch runtime: %w", err)
	}
	if fetchedRT.Executor.MaxMessages != 64 {
		sc.Logger.Error("runtime descriptor wasn't updated",
			"runtime_id", rt.ID,
			"max_messages", fetchedRT.Executor.MaxMessages,
		)
		return fmt.Errorf("update_runtime didn't work")
	}
	sc.Logger.Info("runtime descriptor was successfully updated",
		"runtime_id", rt.ID,
	)

	// Updating another runtime should fail.
	otherRT := crt[1]
	newRT = *rt
	newRT.ID = otherRT.ID
	newRT.Executor.MaxMessages = 32
	newRT.Genesis.StateRoot.Empty()

	sc.Logger.Info("submitting bogus update to runtime",
		"src_runtime", rt.ID,
		"target_runtime", otherRT.ID,
	)
	meta, err = sc.submitRuntimeTxMeta(ctx, rt.ID, rtNonce, "update_runtime", struct {
		UpdateRuntime registry.Runtime `json:"update_runtime"`
	}{
		UpdateRuntime: newRT,
	})
	if err != nil {
		return err
	}
	if _, err = unpackRawTxResp(meta.Output); err != nil {
		return err
	}

	// Wait for next round.
	for {
		select {
		case blk := <-blkCh:
			sc.Logger.Debug("round transition", "round", blk.Block.Header.Round)
			if blk.Block.Header.Round <= meta.Round {
				continue
			}
		case <-time.After(waitTimeout):
			return fmt.Errorf("timed out waiting for runtime rounds")
		}

		break
	}

	sc.Logger.Info("checking that the update didn't succeed")
	// Check target runtime.
	fetchedRT, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     otherRT.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch runtime: %w", err)
	}
	if fetchedRT.Executor.MaxMessages == 32 {
		sc.Logger.Error("target runtime descriptor was updated when it shouldn't be")
		return fmt.Errorf("update_runtime also worked for another runtime when it shouldn't")
	}
	// Check source runtime.
	fetchedRT, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     rt.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch runtime: %w", err)
	}
	if fetchedRT.Executor.MaxMessages == 32 {
		sc.Logger.Error("source runtime descriptor was updated when it shouldn't be")
		return fmt.Errorf("update_runtime also worked for another runtime when it shouldn't")
	}

	sc.Logger.Info("bogus update test passed")

	return nil
}
