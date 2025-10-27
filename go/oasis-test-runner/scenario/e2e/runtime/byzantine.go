package runtime

import (
	"context"
	"fmt"
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
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// primarySchedulerIndex is the index of the highest-ranked scheduler in round 3
	// when the committee consists of 2 workers.
	//
	// Formula: `rank = (round + idx) % num_workers`.
	primarySchedulerIndex uint64 = 1
	// backupSchedulerIndex in the index of the second-ranked scheduler in round 3
	// when the committee consists of 2 workers.
	//
	// Formula: `rank = (round + idx) % num_workers`.
	backupSchedulerIndex uint64
)

var (
	// We force the result of each election such that the byzantine node will be elected
	// as primary/backup worker, primary/backup scheduler, storage worker, or combination
	// of these roles.

	// ByzantineExecutorHonest is a scenario in which the Byzantine node acts
	// as the primary worker, backup scheduler, and is honest.
	ByzantineExecutorHonest scenario.Scenario = newByzantineImpl(
		"primary-worker/backup-scheduler/honest",
		"executor",
		nil,
		oasis.ByzantineSlot1IdentitySeed,
		false,
		nil,
		nil,
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: backupSchedulerIndex,
		},
	)
	// ByzantineExecutorSchedulerHonest is a scenario in which the Byzantine node acts
	// as the primary worker, primary scheduler, and is honest.
	ByzantineExecutorSchedulerHonest scenario.Scenario = newByzantineImpl(
		"primary-worker/primary-scheduler/honest",
		"executor",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			{Name: byzantine.CfgPrimarySchedulerExpected},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: primarySchedulerIndex,
		},
	)
	// ByzantineExecutorDishonest is a scenario in which the Byzantine node acts
	// as the primary worker, backup scheduler, and is dishonest.
	ByzantineExecutorDishonest scenario.Scenario = newByzantineImpl(
		"primary-worker/backup-scheduler/dishonest",
		"executor",
		[]log.WatcherHandlerFactory{
			// Wrong commitment should trigger discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertNoTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for submitting incorrect commitment and
		// again for not being live enough.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeIncorrectResults: 1,
			staking.SlashRuntimeLiveness:         1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorDishonest.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: backupSchedulerIndex,
		},
	)
	// ByzantineExecutorSchedulerRunaway is a scenario in which the Byzantine node acts
	// as the primary worker, primary scheduler, and runs away after publishes a proposal.
	ByzantineExecutorSchedulerRunaway scenario.Scenario = newByzantineImpl(
		"primary-worker/primary-scheduler/runaway",
		"executor",
		[]log.WatcherHandlerFactory{
			// The Byzantine node will publish a proposal but won't submit a commitment.
			// The backup schedulers should recognize this and submit their own proposals.
			// Since stragglers are not permitted, the round timeout will elapse, triggering
			// discrepancy detection, but the round itself shouldn't fail.
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness (not participating in second
		// round).
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgPrimarySchedulerExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorRunaway.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: primarySchedulerIndex,
		},
	)
	// ByzantineExecutorSchedulerBogus is a scenario in which the Byzantine node acts
	// as the primary worker, primary scheduler, and schedules bogus transactions.
	ByzantineExecutorSchedulerBogus scenario.Scenario = newByzantineImpl(
		"primary-worker/primary-scheduler/bogus",
		"executor",
		[]log.WatcherHandlerFactory{
			// The Byzantine node will publish a bogus proposal and submit a commitment.
			// Other workers will see the proposal but won't have all transactions to commit
			// to it. This will trigger the first round timeout, leading to a discrepancy
			// resolution that will time out and fail, ultimately causing the round to fail.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot1IdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness (not participating in second
		// round).
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgPrimarySchedulerExpected},
			{Name: byzantine.CfgExecutorProposeBogusTx},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: primarySchedulerIndex,
		},
	)
	// ByzantineExecutorStraggler is a scenario in which the Byzantine node acts
	// as the primary worker, backup scheduler, and a straggler.
	ByzantineExecutorStraggler scenario.Scenario = newByzantineImpl(
		"primary-worker/backup-scheduler/straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Straggler should trigger timeout and discrepancy detection, but the round shouldn't
			// fail.
			oasis.LogAssertTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: backupSchedulerIndex,
		},
	)
	// ByzantineExecutorSchedulerStraggler is a scenario in which the Byzantine node acts
	// as the primary worker, primary scheduler, and a straggler.
	ByzantineExecutorSchedulerStraggler scenario.Scenario = newByzantineImpl(
		"primary-worker/primary-scheduler/straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Straggler should trigger timeout and discrepancy detection, but the round shouldn't
			// fail.
			oasis.LogAssertTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgPrimarySchedulerExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: primarySchedulerIndex,
		},
	)
	// ByzantineExecutorStragglerAllowed is a scenario in which the Byzantine node acts
	// as the primary worker, backup scheduler, and a straggler. One straggler is allowed.
	ByzantineExecutorStragglerAllowed scenario.Scenario = newByzantineImpl(
		"primary-worker/backup-scheduler/straggler-allowed",
		"executor",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: backupSchedulerIndex,
		},
		withCustomRuntimeConfig(func(rt *oasis.RuntimeFixture) {
			rt.Executor.AllowedStragglers = 1
		}),
	)
	// ByzantineExecutorSchedulerStragglerAllowed is a scenario in which the Byzantine node acts
	// as the primary worker, primary scheduler, and a straggler. One straggler is allowed.
	ByzantineExecutorSchedulerStragglerAllowed scenario.Scenario = newByzantineImpl(
		"primary-worker/primary-scheduler/straggler-allowed",
		"executor",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgPrimarySchedulerExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: primarySchedulerIndex,
		},
		withCustomRuntimeConfig(func(rt *oasis.RuntimeFixture) {
			// One straggler is allowed.
			rt.Executor.AllowedStragglers = 1
		}),
	)
	// ByzantineExecutorBackupStraggler is a scenario in which the Byzantine node acts
	// as the primary and backup worker, backup scheduler, and a straggler.
	ByzantineExecutorBackupStraggler scenario.Scenario = newByzantineImpl(
		"primary-backup-worker/backup-scheduler/straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Straggler should trigger timeout, but no discrepancies or round failures.
			oasis.LogAssertTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker, scheduler.RoleBackupWorker},
			Index: backupSchedulerIndex,
		},
		withCustomRuntimeConfig(func(rt *oasis.RuntimeFixture) {
			// One byzantine node is in the backup committee so we need more to not fail.
			rt.Executor.GroupBackupSize = 3
		}),
	)
	// ByzantineExecutorBackupSchedulerStraggler is a scenario in which the Byzantine node acts
	// as the primary and backup worker, primary scheduler, and a straggler.
	ByzantineExecutorBackupSchedulerStraggler scenario.Scenario = newByzantineImpl(
		"primary-backup-worker/primary-scheduler/straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Straggler should trigger timeout, but no discrepancies or round failures.
			oasis.LogAssertTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorStraggler.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker, scheduler.RoleBackupWorker},
			Index: primarySchedulerIndex,
		},
		withCustomRuntimeConfig(func(rt *oasis.RuntimeFixture) {
			// One byzantine node is in the backup committee so we need more to not fail.
			rt.Executor.GroupBackupSize = 3
		}),
	)
	// ByzantineExecutorFailureIndicating is a scenario in which the Byzantine node acts
	// as the primary worker, backup scheduler, and submits failure indicating commitment.
	ByzantineExecutorFailureIndicating scenario.Scenario = newByzantineImpl(
		"primary-worker/backup-scheduler/failure-indicating",
		"executor",
		[]log.WatcherHandlerFactory{
			// Failure indicating executor should trigger discrepancy detection, but the round
			// shouldn't fail.
			oasis.LogAssertNoTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness.
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorFailureIndicating.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: backupSchedulerIndex,
		},
	)
	// ByzantineExecutorSchedulerFailureIndicating is a scenario in which the Byzantine node acts
	// as the primary worker, primary scheduler, and submits failure indicating commitment.
	ByzantineExecutorSchedulerFailureIndicating scenario.Scenario = newByzantineImpl(
		"primary-worker/primary-scheduler/failure-indicating",
		"executor",
		[]log.WatcherHandlerFactory{
			// Proposal from failure indicating scheduler will be rejected. The round will not fail
			// as the backup scheduler's proposal will be accepted after discrepancy resolution.
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot1IdentitySeed,
		false,
		// Byzantine node entity should be slashed once for liveness (not participating in second
		// round).
		map[staking.SlashReason]uint64{
			staking.SlashRuntimeLiveness: 1,
		},
		[]oasis.Argument{
			{Name: byzantine.CfgPrimarySchedulerExpected},
			{Name: byzantine.CfgExecutorMode, Values: []string{byzantine.ModeExecutorFailureIndicating.String()}},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: primarySchedulerIndex,
		},
	)
	// ByzantineExecutorCorruptGetDiff is the byzantine executor node scenario that corrupts GetDiff
	// responses.
	ByzantineExecutorCorruptGetDiff scenario.Scenario = newByzantineImpl(
		"primary-worker/backup-scheduler/corrupt-getdiff",
		"executor",
		// There should be no discrepancy or round failures.
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		false,
		nil,
		[]oasis.Argument{
			// Corrupt all GetDiff responses.
			{Name: byzantine.CfgCorruptGetDiff},
		},
		scheduler.ForceElectCommitteeRole{
			Kind:  scheduler.KindComputeExecutor,
			Roles: []scheduler.Role{scheduler.RoleWorker},
			Index: backupSchedulerIndex,
		},
	)
)

type byzantineOption func(opts *byzantineImpl)

func withCustomRuntimeConfig(cfgFn func(rt *oasis.RuntimeFixture)) byzantineOption {
	return func(opts *byzantineImpl) {
		opts.configureRuntimeFn = cfgFn
	}
}

type byzantineImpl struct {
	Scenario

	schedParams        scheduler.ForceElectCommitteeRole
	configureRuntimeFn func(*oasis.RuntimeFixture)

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
	schedParams scheduler.ForceElectCommitteeRole,
	opts ...byzantineOption,
) scenario.Scenario {
	sc := &byzantineImpl{
		Scenario:                   *NewScenario("byzantine/"+name, nil),
		script:                     script,
		extraArgs:                  extraArgs,
		skipStorageSyncWait:        skipStorageWait,
		identitySeed:               identitySeed,
		logWatcherHandlerFactories: logWatcherHandlerFactories,
		expectedSlashes:            expectedSlashes,
		schedParams:                schedParams,
	}

	for _, opt := range opts {
		opt(sc)
	}

	// The byzantine node code and our tests are extremely sensitive
	// to timekeeping being exactly how it was when the tests were
	// written.
	sc.debugNoRandomInitialEpoch = true
	sc.debugWeakAlphaOk = true
	return sc
}

func (sc *byzantineImpl) Clone() scenario.Scenario {
	return &byzantineImpl{
		Scenario:                   *sc.Scenario.Clone().(*Scenario),
		script:                     sc.script,
		extraArgs:                  sc.extraArgs,
		skipStorageSyncWait:        sc.skipStorageSyncWait,
		identitySeed:               sc.identitySeed,
		logWatcherHandlerFactories: sc.logWatcherHandlerFactories,
		expectedSlashes:            sc.expectedSlashes,
		schedParams:                sc.schedParams,
		configureRuntimeFn:         sc.configureRuntimeFn,
	}
}

func (sc *byzantineImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Add another entity (DeterministicEntity2) that will get slashed.
	f.Entities = append(f.Entities, oasis.EntityCfg{})

	f.Runtimes[1].Executor.MinLiveRoundsPercent = 100 // To test slashing.
	f.Runtimes[1].Executor.MaxLivenessFailures = 1
	f.Runtimes[1].Staking = registry.RuntimeStakingParameters{
		Slashing: map[staking.SlashReason]staking.Slash{
			staking.SlashRuntimeIncorrectResults: {
				Amount: *quantity.NewFromUint64(50),
			},
			staking.SlashRuntimeEquivocation: {
				Amount: *quantity.NewFromUint64(40),
			},
			staking.SlashRuntimeLiveness: {
				Amount: *quantity.NewFromUint64(30),
			},
		},
	}

	if sc.configureRuntimeFn != nil {
		sc.configureRuntimeFn(&f.Runtimes[1])
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
	// The byzantine node requires allowing weak alphas.
	f.Network.SchedulerWeakAlphaOk = true
	// Change the default network log watcher handler factories if configured.
	if sc.logWatcherHandlerFactories != nil {
		f.Network.DefaultLogWatcherHandlerFactories = sc.logWatcherHandlerFactories
	}
	// Provision a Byzantine node.
	schedParams := sc.schedParams // Copy
	f.ByzantineNodes = []oasis.ByzantineFixture{
		{
			Script:           sc.script,
			ExtraArgs:        sc.extraArgs,
			IdentitySeed:     sc.identitySeed,
			Entity:           2,
			ActivationEpoch:  1,
			Runtime:          1,
			ForceElectParams: &schedParams,
		},
	}
	return f, nil
}

func (sc *byzantineImpl) Run(ctx context.Context, _ *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Start watching for runtime blocks.
	blkCh, blkSub, err := sc.Net.ClientController().RuntimeClient.WatchBlocks(ctx, KeyValueRuntimeID)
	if err != nil {
		return fmt.Errorf("failed to watch blocks: %w", err)
	}
	defer blkSub.Close()

	epoch, err := sc.initialEpochTransitions(ctx, fixture)
	if err != nil {
		return err
	}

	sc.Logger.Info("getting genesis block")

	genesisBlk, err := sc.Net.ClientController().RuntimeClient.GetGenesisBlock(ctx, KeyValueRuntimeID)
	if err != nil {
		return fmt.Errorf("failed to get genesis block: %w", err)
	}

	sc.Logger.Info("waiting for a successful round")

	// NOTE: There is no need to submit any transactions as the nodes are proposing a block
	//       immediately after genesis. We just wait for a successful round.
WatchBlocksLoop:
	for {
		select {
		case blk := <-blkCh:
			if blk.Block.Header.HeaderType != block.Normal || blk.Block.Header.Round <= genesisBlk.Header.Round {
				continue
			}
			sc.Logger.Info("successful round",
				"round", blk.Block.Header.Round,
			)

			break WatchBlocksLoop
		case <-time.After(120 * time.Second):
			return fmt.Errorf("timeout while waiting for successful round")
		}
	}

	sc.Logger.Info("checking log watchers")

	if err = sc.Net.CheckLogWatchers(); err != nil {
		return err
	}

	// Advance epoch to trigger any liveness slashing/suspension.
	if err = sc.Net.Controller().SetEpoch(ctx, epoch); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	epoch++
	if err = sc.Net.Controller().SetEpoch(ctx, epoch); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}

	// Ensure entity has expected stake.
	sc.Logger.Info("ensuring entity has sufficient stake")
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
		return fmt.Errorf("expected entity stake: %v got: %v", expectedStake, acc.Escrow.Active.Balance)
	}

	if sc.skipStorageSyncWait {
		sc.Logger.Info("storage sync wait set, bailing")
		return nil
	}

	// Wait for all compute nodes to be synced.
	blk, err := sc.Net.ClientController().RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     runtimeClient.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest block: %w", err)
	}

	sc.Logger.Info("waiting for compute nodes to be synced",
		"target_round", blk.Header.Round,
	)

	syncedNodes := make(map[string]bool)
	storageCtx, cancelFn := context.WithTimeout(ctx, 60*time.Second)
	defer cancelFn()
ComputeWorkerSyncLoop:
	for {
		if storageCtx.Err() != nil {
			return fmt.Errorf("failed to wait for compute nodes to be synced: %w", storageCtx.Err())
		}

		for _, n := range sc.Net.ComputeWorkers() {
			if syncedNodes[n.Name] {
				continue
			}

			ctrl, err := oasis.NewController(n.SocketPath())
			if err != nil {
				return fmt.Errorf("failed to create compute node controller: %w", err)
			}

			// Iterate over the roots to confirm they have been synced.
			for _, root := range blk.Header.StorageRoots() {
				state := mkvs.NewWithRoot(ctrl.Storage, nil, root)
				it := state.NewIterator(storageCtx)

				for it.Rewind(); it.Valid(); it.Next() { //nolint:revive
				}
				err = it.Err()
				it.Close()
				state.Close()

				if err != nil {
					// Failed to iterate over the root.
					sc.Logger.Warn("compute node is still not synced",
						"node", n.Name,
						"root", root,
						"err", err,
					)
					time.Sleep(1 * time.Second)
					continue ComputeWorkerSyncLoop
				}
			}

			sc.Logger.Warn("compute node is synced",
				"node", n.Name,
			)
			syncedNodes[n.Name] = true
		}
		break
	}

	return nil
}
