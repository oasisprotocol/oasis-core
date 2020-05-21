package e2e

import (
	"context"
	"fmt"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	// MultipleRuntimes is a scenario which tests running multiple runtimes on one node.
	MultipleRuntimes scenario.Scenario = &multipleRuntimesImpl{
		runtimeImpl: *newRuntimeImpl("multiple-runtimes", "simple-keyvalue-client", nil),
		logger:      logging.GetLogger("scenario/e2e/multiple_runtimes"),

		numComputeRuntimes:    2,
		numComputeRuntimeTxns: 2,
		numComputeWorkers:     2,
		executorGroupSize:     2,
	}
)

type multipleRuntimesImpl struct {
	runtimeImpl

	logger *logging.Logger

	// numComputeRuntimes is the number of runtimes, all with common runtimeBinary registered.
	numComputeRuntimes int

	// numComputeRuntimeTxns is the number of insert test transactions sent to each runtime.
	numComputeRuntimeTxns int

	// numComputeWorkers is the number of compute workers.
	numComputeWorkers int

	// executorGroupSize is the number of executor nodes.
	executorGroupSize int
}

func (mr *multipleRuntimesImpl) Clone() scenario.Scenario {
	return &multipleRuntimesImpl{
		runtimeImpl: *mr.runtimeImpl.Clone().(*runtimeImpl),
		logger:      mr.logger,

		numComputeRuntimes:    mr.numComputeRuntimes,
		numComputeRuntimeTxns: mr.numComputeRuntimeTxns,
		numComputeWorkers:     mr.numComputeWorkers,
		executorGroupSize:     mr.executorGroupSize,
	}
}

func (mr *multipleRuntimesImpl) Parameters() *flag.FlagSet {
	fs := mr.runtimeImpl.Parameters()
	fs.IntVar(&mr.numComputeRuntimes, "num_compute_runtimes", mr.numComputeRuntimes, "number of compute runtimes per worker")
	fs.IntVar(&mr.numComputeRuntimeTxns, "num_compute_runtime_txns", mr.numComputeRuntimeTxns, "number of transactions to perform")
	fs.IntVar(&mr.numComputeWorkers, "num_compute_workers", mr.numComputeWorkers, "number of workers to initiate")
	fs.IntVar(&mr.executorGroupSize, "executor_group_size", mr.executorGroupSize, "number of executor workers in committee")

	return fs
}

func (mr *multipleRuntimesImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := mr.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Remove existing compute runtimes from fixture, remember RuntimeID and
	// binary from the first one.
	var id common.Namespace
	var runtimeBinary string
	var rts []oasis.RuntimeFixture
	for _, rt := range f.Runtimes {
		if rt.Kind == registry.KindCompute {
			if runtimeBinary == "" {
				copy(id[:], rt.ID[:])
				runtimeBinary = rt.Binaries[0]
			}
		} else {
			rts = append(rts, rt)
		}
	}
	f.Runtimes = rts

	// Avoid unexpected blocks.
	f.Network.EpochtimeMock = true

	// Add some more consecutive runtime IDs with the same binary.
	for i := 1; i <= mr.numComputeRuntimes; i++ {
		// Increase LSB by 1.
		id[len(id)-1]++

		newRtFixture := oasis.RuntimeFixture{
			ID:         id,
			Kind:       registry.KindCompute,
			Entity:     0,
			Keymanager: 0,
			Binaries:   []string{runtimeBinary},
			Executor: registry.ExecutorParameters{
				GroupSize:       uint64(mr.executorGroupSize),
				GroupBackupSize: 0,
				RoundTimeout:    10 * time.Second,
			},
			Merge: registry.MergeParameters{
				GroupSize:       1,
				GroupBackupSize: 0,
				RoundTimeout:    10 * time.Second,
			},
			TxnScheduler: registry.TxnSchedulerParameters{
				Algorithm:         registry.TxnSchedulerAlgorithmBatching,
				GroupSize:         1,
				MaxBatchSize:      1,
				MaxBatchSizeBytes: 1000,
				BatchFlushTimeout: 1 * time.Second,
			},
			Storage: registry.StorageParameters{
				GroupSize:               1,
				MaxApplyWriteLogEntries: 100_000,
				MaxApplyOps:             2,
				MaxMergeRoots:           8,
				MaxMergeOps:             2,
			},
			AdmissionPolicy: registry.RuntimeAdmissionPolicy{
				AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
			},
		}

		f.Runtimes = append(f.Runtimes, newRtFixture)
	}

	// Use numComputeWorkers compute worker fixtures.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}
	for i := 0; i < mr.numComputeWorkers; i++ {
		f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{Entity: 1})
	}

	return f, nil
}

func (mr *multipleRuntimesImpl) Run(childEnv *env.Env) error {
	if err := mr.net.Start(); err != nil {
		return err
	}

	// Wait for the nodes.
	if err := mr.initialEpochTransitions(); err != nil {
		return err
	}

	ctx := context.Background()

	// Submit transactions.
	epoch := epochtime.EpochTime(3)
	for _, r := range mr.net.Runtimes() {
		rt := r.ToRuntimeDescriptor()
		if rt.Kind == registry.KindCompute {
			for i := 0; i < mr.numComputeRuntimeTxns; i++ {
				mr.logger.Info("submitting transaction to runtime",
					"seq", i,
					"runtime_id", rt.ID,
				)

				if err := mr.submitKeyValueRuntimeInsertTx(ctx, rt.ID, "hello", fmt.Sprintf("world at iteration %d from %s", i, rt.ID)); err != nil {
					return err
				}

				mr.logger.Info("triggering epoch transition",
					"epoch", epoch,
				)
				if err := mr.net.Controller().SetEpoch(context.Background(), epoch); err != nil {
					return fmt.Errorf("failed to set epoch: %w", err)
				}
				mr.logger.Info("epoch transition done")
				epoch++
			}
		}
	}

	return nil
}
