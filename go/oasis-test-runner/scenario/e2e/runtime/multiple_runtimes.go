package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	// cfgNumComputeRuntimes is the number of runtimes, all with common runtimeBinary registered.
	cfgNumComputeRuntimes = "num_compute_runtimes"
	// cfgNumComputeRuntimeTxns is the number of insert test transactions sent to each runtime.
	cfgNumComputeRuntimeTxns = "num_compute_runtime_txns" // #nosec G101
	// cfgNumComputeWorkers is the number of compute workers.
	cfgNumComputeWorkers = "num_compute_workers"
	// cfgExecutorGroupSize is the number of executor nodes.
	cfgExecutorGroupSize = "executor_group_size"
)

// MultipleRuntimes is a scenario which tests running multiple runtimes on one node.
var MultipleRuntimes = func() scenario.Scenario {
	sc := &multipleRuntimesImpl{
		Scenario: *NewScenario("multiple-runtimes", nil),
	}
	sc.Flags.Int(cfgNumComputeRuntimes, 2, "number of compute runtimes per worker")
	sc.Flags.Int(cfgNumComputeRuntimeTxns, 2, "number of transactions to perform")
	sc.Flags.Int(cfgNumComputeWorkers, 2, "number of workers to initiate")
	sc.Flags.Uint16(cfgExecutorGroupSize, 2, "number of executor workers in committee")

	return sc
}()

type multipleRuntimesImpl struct {
	Scenario
}

func (sc *multipleRuntimesImpl) Clone() scenario.Scenario {
	return &multipleRuntimesImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *multipleRuntimesImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Remove existing compute runtimes from fixture, remember runtime ID and primary deployment
	// from the first one.
	var (
		runtimeID         common.Namespace
		runtimeDeployment *oasis.DeploymentCfg
		rts               []oasis.RuntimeFixture
	)
	for _, rt := range f.Runtimes {
		if rt.Kind == registry.KindCompute {
			if len(rt.Deployments) == 0 {
				continue
			}
			if runtimeDeployment != nil {
				continue
			}

			copy(runtimeID[:], rt.ID[:])
			runtimeDeployment = &rt.Deployments[0]
		} else {
			rts = append(rts, rt)
		}
	}
	f.Runtimes = rts

	// Add some more consecutive runtime IDs with the same binary.
	numComputeRuntimes, _ := sc.Flags.GetInt(cfgNumComputeRuntimes)
	executorGroupSize, _ := sc.Flags.GetUint16(cfgExecutorGroupSize)
	for i := 1; i <= numComputeRuntimes; i++ {
		// Increase LSB by 1.
		runtimeID[len(runtimeID)-1]++

		newRtFixture := oasis.RuntimeFixture{
			ID:         runtimeID,
			Kind:       registry.KindCompute,
			Entity:     0,
			Keymanager: 0,
			Executor: registry.ExecutorParameters{
				GroupSize:       executorGroupSize,
				GroupBackupSize: 0,
				RoundTimeout:    20,
			},
			TxnScheduler: registry.TxnSchedulerParameters{
				MaxBatchSize:      100,
				MaxBatchSizeBytes: 1024 * 1024,
				BatchFlushTimeout: time.Second,
				ProposerTimeout:   2 * time.Second,
			},
			AdmissionPolicy: registry.RuntimeAdmissionPolicy{
				AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
			},
			Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
				scheduler.KindComputeExecutor: {
					scheduler.RoleWorker: {
						MinPoolSize: &registry.MinPoolSizeConstraint{
							Limit: executorGroupSize,
						},
					},
				},
			},
			GovernanceModel: registry.GovernanceEntity,
			Deployments:     []oasis.DeploymentCfg{*runtimeDeployment}, // Copy deployment.
		}

		f.Runtimes = append(f.Runtimes, newRtFixture)
	}

	var computeRuntimes []int
	for id, rt := range f.Runtimes {
		if rt.Kind != registry.KindCompute {
			continue
		}
		computeRuntimes = append(computeRuntimes, id)
	}
	// Use numComputeWorkers compute worker fixtures.
	numComputeWorkers, _ := sc.Flags.GetInt(cfgNumComputeWorkers)
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}
	for i := 0; i < numComputeWorkers; i++ {
		f.ComputeWorkers = append(f.ComputeWorkers,
			oasis.ComputeWorkerFixture{
				Entity:   1,
				Runtimes: computeRuntimes,
			},
		)
	}

	f.Clients[0].Runtimes = computeRuntimes

	return f, nil
}

func (sc *multipleRuntimesImpl) Run(ctx context.Context, _ *env.Env) error {
	// Start the network.
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Submit transactions.
	numComputeRuntimeTxns, _ := sc.Flags.GetInt(cfgNumComputeRuntimeTxns)
	for _, r := range sc.Net.Runtimes() {
		rt := r.ToRuntimeDescriptor()
		if rt.Kind != registry.KindCompute {
			continue
		}

		for i := 0; i < numComputeRuntimeTxns; i++ {
			sc.Logger.Info("submitting transaction to runtime",
				"seq", i,
				"runtime_id", rt.ID,
			)

			if _, err := sc.submitKeyValueRuntimeInsertTx(ctx, rt.ID, uint64(i), "hello", fmt.Sprintf("world at iteration %d from %s", i, rt.ID), false, 0); err != nil {
				return err
			}
		}
	}

	return nil
}
