package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const (
	// computeRuntimesCount is the number of runtimes with shared runtimeBinary registered.
	computeRuntimesCount = 2

	// computeRuntimeTxnCount is the number of insert transactions sent to each runtime.
	computeRuntimeTxnCount = 3
)

var (
	// MultipleRuntimes is a scenario which tests running multiple runtimes on one node.
	MultipleRuntimes scenario.Scenario = &multipleRuntimesImpl{
		basicImpl: *newBasicImpl("multiple-runtimes", "simple-keyvalue-client", nil),
		logger:    logging.GetLogger("scenario/e2e/multiple_runtimes"),
	}
)

type multipleRuntimesImpl struct {
	basicImpl

	logger *logging.Logger
}

func (mr *multipleRuntimesImpl) Name() string {
	return "multiple-runtimes"
}

func (mr *multipleRuntimesImpl) Fixture() (*oasis.NetworkFixture, error) {
	fixtures, err := mr.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Take the RuntimeID and binary from the existing compute runtime.
	var id common.Namespace
	var runtimeBinary string
	for _, rt := range fixtures.Runtimes {
		if rt.Kind == registry.KindCompute {
			copy(id[:], rt.ID[:])
			runtimeBinary = rt.Binary
			break
		}
	}

	// Add some more consecutive runtime IDs with the same binary.
	for i := 1; i <= computeRuntimesCount-1; i++ {
		// Increase LSB by 1.
		id[len(id)-1]++

		newRtFixture := oasis.RuntimeFixture{
			ID:         id,
			Kind:       registry.KindCompute,
			Entity:     0,
			Keymanager: 0,
			Binary:     runtimeBinary,
			Compute: registry.ComputeParameters{
				GroupSize:       2,
				GroupBackupSize: 1,
				RoundTimeout:    10 * time.Second,
			},
			Merge: registry.MergeParameters{
				GroupSize:       2,
				GroupBackupSize: 1,
				RoundTimeout:    10 * time.Second,
			},
			TxnScheduler: registry.TxnSchedulerParameters{
				Algorithm:         registry.TxnSchedulerAlgorithmBatching,
				GroupSize:         1,
				MaxBatchSize:      1,
				MaxBatchSizeBytes: 1000,
				BatchFlushTimeout: 1 * time.Second,
			},
			Storage: registry.StorageParameters{GroupSize: 2},
		}

		fixtures.Runtimes = append(fixtures.Runtimes, newRtFixture)
	}

	return fixtures, nil
}

func (mr *multipleRuntimesImpl) Run(childEnv *env.Env) error {
	if err := mr.net.Start(); err != nil {
		return err
	}

	// Wait for all nodes to be synced before we proceed.
	if err := mr.waitNodesSynced(); err != nil {
		return err
	}

	mr.logger.Info("waiting for (some) nodes to register",
		"num_nodes", mr.net.NumRegisterNodes(),
	)
	if err := mr.net.Controller().WaitNodesRegistered(context.Background(), mr.net.NumRegisterNodes()); err != nil {
		return err
	}

	ctx := context.Background()

	// Submit transactions.
	for _, r := range mr.net.Runtimes() {
		rt := r.ToRuntimeDescriptor()
		if rt.Kind == registry.KindCompute {
			for i := 0; i < computeRuntimeTxnCount; i++ {
				mr.logger.Info("submitting transaction to runtime",
					"seq", i,
					"runtime_id", rt.ID,
				)

				if err := mr.submitRuntimeTx(ctx, rt.ID, "hello", fmt.Sprintf("world %d from %s", i, rt.ID)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
