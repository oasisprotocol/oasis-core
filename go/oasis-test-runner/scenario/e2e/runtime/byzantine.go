package runtime

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// Permutations generated in the epoch 2 election are
	// executor worker:            1 (w+s), 3 (w), 0 (-), 2 (-)
	// executor backup worker:     0   (b), 3 (-), 2 (-), 1 (-)
	// storage worker:             0   (w), 1 (w)
	// w = worker and not scheduler in first round
	// w+s = worker and scheduler in first round
	// b = backup
	// - = not elected for this role
	//
	//
	// For executor scripts, it suffices to be index 3.
	// For executor and scheduler scripts, it suffices to be index 1.
	// For storage worker scripts suffices to be index 0.

	// ByzantineExecutorHonest is the byzantine executor honest scenario.
	ByzantineExecutorHonest scenario.Scenario = newByzantineImpl(
		"executor-honest",
		"executor",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		nil,
	)
	// ByzantineExecutorSchedulerHonest is the byzantine executor scheduler honest scenario.
	ByzantineExecutorSchedulerHonest scenario.Scenario = newByzantineImpl(
		"executor-scheduler-honest",
		"executor",
		nil,
		oasis.ByzantineSlot1IdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgSchedulerRoleExpected},
		},
	)
	// ByzantineExecutorWrong is the byzantine executor wrong scenario.
	ByzantineExecutorWrong scenario.Scenario = newByzantineImpl(
		"executor-wrong",
		"executor",
		[]log.WatcherHandlerFactory{
			// Wrong commitment should trigger discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertNoTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for submitting incorrect commitment.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeIncorrectResults: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorWrong.String()}},
		},
	)
	// ByzantineExecutorSchedulerWrong is the byzantine executor wrong scheduler scenario.
	ByzantineExecutorSchedulerWrong scenario.Scenario = newByzantineImpl(
		"executor-scheduler-wrong",
		"executor",
		[]log.WatcherHandlerFactory{
			// Invalid proposed batch should trigger round failure in first round (proposer timeout).
			// In round two timeout and discrepancy detection should be triggered.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot1IdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgSchedulerRoleExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorWrong.String()}},
		},
	)
	// ByzantineExecutorStraggler is the byzantine executor straggler scenario.
	ByzantineExecutorStraggler scenario.Scenario = newByzantineImpl(
		"executor-straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Straggler should trigger timeout and discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
	)
	// ByzantineExecutorSchedulerStraggler is the byzantine executor scheduler straggler scenario.
	ByzantineExecutorSchedulerStraggler scenario.Scenario = newByzantineImpl(
		"executor-scheduler-straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Scheduler straggler should trigger round failure in first round (proposer timeout).
			// In round two timeout and discrepancy detection should be triggered.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot1IdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgSchedulerRoleExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
	)
	// ByzantineExecutorFailureIndicating is the byzantine executor that submits failure indicating
	// commitments scenario.
	ByzantineExecutorFailureIndicating scenario.Scenario = newByzantineImpl(
		"executor-failure-indicating",
		"executor",
		[]log.WatcherHandlerFactory{
			// Failure indicating executor should trigger discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertNoTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorFailureIndicating.String()}},
		},
	)
	// ByzantineExecutorSchedulerFailureIndicating is the byzantine executor scheduler failure indicating scenario.
	ByzantineExecutorSchedulerFailureIndicating scenario.Scenario = newByzantineImpl(
		"executor-scheduler-failure-indicating",
		"executor",
		[]log.WatcherHandlerFactory{
			// Failure indicating scheduler submitts a failure indicating commitment and doesn't propagate the batch.
			// This triggers a timeout, discrepancy detection and results in round failure.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot1IdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgSchedulerRoleExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorFailureIndicating.String()}},
		},
	)
	// ByzantineStorageHonest is the byzantine storage honest scenario.
	ByzantineStorageHonest scenario.Scenario = newByzantineImpl(
		"storage-honest",
		"storage",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		nil,
	)
	// ByzantineStorageFailApply is the byzantine storage scenario where storage node fails
	// first 5 Apply requests.
	ByzantineStorageFailApply scenario.Scenario = newByzantineImpl(
		"storage-fail-apply",
		"storage",
		// Failing first 5 apply requests should result in no round failures. As the proposer
		// should keep retrying proposing a batch until it succeeds.
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			// Fail first 5 ApplyBatch requests.
			{Name: byzantine.CfgNumStorageFailApply, Values: []string{strconv.Itoa(5)}},
		},
	)
	// ByzantineStorageFailApplyBatch is the byzantine storage scenario where storage node fails
	// first 3 ApplyBatch requests.
	ByzantineStorageFailApplyBatch scenario.Scenario = newByzantineImpl(
		"storage-fail-applybatch",
		"storage",
		[]log.WatcherHandlerFactory{
			// There should be a discrepancy. Discrepancy resolution should fail with majority failure.
			oasis.LogAssertExecutionDiscrepancyDetected(),
			oasis.LogAssertDiscrepancyMajorityFailure(),
			oasis.LogAssertRoundFailures(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			// Fail first 3 ApplyBatch requests - from the 2 executor workers and 1 backup node.
			{Name: byzantine.CfgNumStorageFailApplyBatch, Values: []string{strconv.Itoa(3)}},
		},
	)
	// ByzantineStorageFailRead is the byzantine storage node scenario that fails all read requests.
	ByzantineStorageFailRead scenario.Scenario = newByzantineImpl(
		"storage-fail-read",
		"storage",
		// There should be no discrepancy or round failures.
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		// Hack to work around the way the storage client selects nodes.
		// It can happen that for this test, the client will keep selecting the byzantine
		// node instead of the other storage nodes and so would never be able to fully sync.
		// It can take up to two minutes for storage-0 to sync in this scenario with the
		// current shuffling method in the storage client. See also #1815.
		true,
		nil,
		[]oasis.Argument{
			// Fail all read requests.
			{Name: byzantine.CfgFailReadRequests},
		},
	)
	// ByzantineStorageCorruptGetDiff is the byzantine storage node scenario that corrupts GetDiff
	// responses.
	ByzantineStorageCorruptGetDiff scenario.Scenario = newByzantineImpl(
		"storage-corrupt-getdiff",
		"storage",
		// There should be no discrepancy or round failures.
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			// Corrupt all GetDiff responses.
			{Name: byzantine.CfgCorruptGetDiff},
		},
	)
)

type byzantineImpl struct {
	runtimeImpl

	script    string
	extraArgs []oasis.Argument

	skipStorageSyncWait        bool
	identitySeed               string
	logWatcherHandlerFactories []log.WatcherHandlerFactory

	// expectedSlashes are the expected slashes of the byzantine entity. Value
	// is the number of times the entity is expected to be slashed for the specific
	// reason.
	expectedSlashes map[staking.SlashReason]uint64
}

func newByzantineImpl(
	name string,
	script string,
	logWatcherHandlerFactories []log.WatcherHandlerFactory,
	identitySeed string,
	skipStorageWait bool,
	expectedSlashes map[staking.SlashReason]uint64,
	extraArgs []oasis.Argument,
) scenario.Scenario {
	return &byzantineImpl{
		runtimeImpl:                *newRuntimeImpl("byzantine/"+name, nil),
		script:                     script,
		extraArgs:                  extraArgs,
		skipStorageSyncWait:        skipStorageWait,
		identitySeed:               identitySeed,
		logWatcherHandlerFactories: logWatcherHandlerFactories,
		expectedSlashes:            expectedSlashes,
	}
}

func (sc *byzantineImpl) Clone() scenario.Scenario {
	return &byzantineImpl{
		runtimeImpl:                *sc.runtimeImpl.Clone().(*runtimeImpl),
		script:                     sc.script,
		extraArgs:                  sc.extraArgs,
		skipStorageSyncWait:        sc.skipStorageSyncWait,
		identitySeed:               sc.identitySeed,
		logWatcherHandlerFactories: sc.logWatcherHandlerFactories,
		expectedSlashes:            sc.expectedSlashes,
	}
}

func (sc *byzantineImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Add another entity (DeterministicEntity2) that will get slashed.
	f.Entities = append(f.Entities, oasis.EntityCfg{})

	f.Runtimes[1].Staking = registry.RuntimeStakingParameters{
		Slashing: map[staking.SlashReason]staking.Slash{
			staking.SlashRuntimeIncorrectResults: {
				Amount: *quantity.NewFromUint64(50),
			},
			staking.SlashRuntimeEquivocation: {
				Amount: *quantity.NewFromUint64(50),
			},
		},
	}
	f.Network.StakingGenesis = &staking.Genesis{
		TotalSupply: *quantity.NewFromUint64(100),
		Ledger: map[staking.Address]*staking.Account{
			// Entity account needs escrow so that the byzantine node can get
			// slashed.
			e2e.DeterministicEntity2: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
				},
			},
		},
		Delegations: map[staking.Address]map[staking.Address]*staking.Delegation{
			e2e.DeterministicEntity2: {
				e2e.DeterministicEntity2: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
		},
	}

	// The byzantine node requires deterministic identities.
	f.Network.DeterministicIdentities = true
	// The byzantine scenario requires mock epochtime as the byzantine node
	// doesn't know how to handle epochs in which it is not scheduled.
	f.Network.SetMockEpoch()
	// Change the default network log watcher handler factories if configured.
	if sc.logWatcherHandlerFactories != nil {
		f.Network.DefaultLogWatcherHandlerFactories = sc.logWatcherHandlerFactories
	}
	// Provision a Byzantine node.
	f.ByzantineNodes = []oasis.ByzantineFixture{
		{
			Script:          sc.script,
			ExtraArgs:       sc.extraArgs,
			IdentitySeed:    sc.identitySeed,
			Entity:          2,
			ActivationEpoch: 1,
			Runtime:         1,
		},
	}
	return f, nil
}

func (sc *byzantineImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()

	if err := sc.Net.Start(); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Start watching for runtime blocks.
	blkCh, blkSub, err := sc.Net.ClientController().RuntimeClient.WatchBlocks(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to watch blocks: %w", err)
	}
	defer blkSub.Close()

	if err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	genesisBlk, err := sc.Net.ClientController().RuntimeClient.GetGenesisBlock(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to get genesis block: %w", err)
	}

	// NOTE: There is no need to submit any transactions as the nodes are proposing a block
	//       immediately after genesis. We just wait for a successful round.
WatchBlocksLoop:
	for {
		select {
		case blk := <-blkCh:
			if blk.Block.Header.HeaderType != block.Normal || blk.Block.Header.Round <= genesisBlk.Header.Round {
				continue
			}

			break WatchBlocksLoop
		case <-time.After(120 * time.Second):
			return fmt.Errorf("timeout while waiting for successful round")
		}
	}

	if err = sc.Net.CheckLogWatchers(); err != nil {
		return err
	}

	// Ensure entity has expected stake.
	acc, err := sc.Net.ClientController().Staking.Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  e2e.DeterministicEntity2,
	})
	if err != nil {
		return err
	}

	// Calculate expected stake by going through expected slashes.
	expectedStake := fixture.Network.StakingGenesis.Ledger[e2e.DeterministicEntity2].Escrow.Active.Balance.Clone()
	for reason, times := range sc.expectedSlashes {
		slashAmount := fixture.Runtimes[1].Staking.Slashing[reason].Amount
		for i := uint64(0); i < times; i++ {
			if err = expectedStake.Sub(&slashAmount); err != nil {
				return fmt.Errorf("expectedStake.Sub(slashAmount): %w", err)
			}
		}
	}
	if expectedStake.Cmp(&acc.Escrow.Active.Balance) != 0 {
		return fmt.Errorf("expected entity stake: %v got: %v", expectedStake, acc.General.Balance)
	}

	if sc.skipStorageSyncWait {
		return nil
	}

	// Wait for all storage nodes to be synced.
	blk, err := sc.Net.ClientController().RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: runtimeID,
		Round:     runtimeClient.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest block: %w", err)
	}

	sc.Logger.Info("waiting for storage nodes to be synced",
		"target_round", blk.Header.Round,
	)

	syncedNodes := make(map[string]bool)
	storageCtx, cancelFn := context.WithTimeout(ctx, 60*time.Second)
	defer cancelFn()
StorageWorkerSyncLoop:
	for {
		if storageCtx.Err() != nil {
			return fmt.Errorf("failed to wait for storage nodes to be synced: %w", storageCtx.Err())
		}

		for _, n := range sc.Net.StorageWorkers() {
			if syncedNodes[n.Name] {
				continue
			}

			ctrl, err := oasis.NewController(n.SocketPath())
			if err != nil {
				return fmt.Errorf("failed to create storage node controller: %w", err)
			}

			// Iterate over the roots to confirm they have been synced.
			for _, root := range blk.Header.StorageRoots() {
				state := mkvs.NewWithRoot(ctrl.Storage, nil, root)
				it := state.NewIterator(storageCtx)

				for it.Rewind(); it.Valid(); it.Next() {
				}
				err = it.Err()
				it.Close()
				state.Close()

				if err != nil {
					// Failed to iterate over the root.
					sc.Logger.Warn("storage node is still not synced",
						"node", n.Name,
						"root", root,
						"err", err,
					)
					time.Sleep(1 * time.Second)
					continue StorageWorkerSyncLoop
				}
			}

			sc.Logger.Warn("storage node is synced",
				"node", n.Name,
			)
			syncedNodes[n.Name] = true
		}
		break
	}

	return nil
}
