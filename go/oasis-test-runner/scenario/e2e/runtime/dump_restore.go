package runtime

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

var (
	// DumpRestore is the dump and restore scenario.
	DumpRestore scenario.Scenario = newDumpRestoreImpl("dump-restore", nil)

	// DumpRestoreRuntimeRoundAdvance is the scenario where additional rounds are simulated after
	// the runtime stopped in the old network (so storage node state is behind).
	DumpRestoreRuntimeRoundAdvance scenario.Scenario = newDumpRestoreImpl(
		"dump-restore/runtime-round-advance",
		func(doc *genesis.Document) {
			// Make it look like there were additional rounds (e.g. from epoch transitions) after the
			// runtime stopped in the old network.
			for _, st := range doc.RootHash.RuntimeStates {
				st.Round += 10
			}
		},
	)
)

type dumpRestoreImpl struct {
	runtimeImpl

	mapGenesisDocumentFn func(*genesis.Document)
}

func newDumpRestoreImpl(
	name string,
	mapGenesisDocumentFn func(*genesis.Document),
) scenario.Scenario {
	// Use -nomsg variant as this test also compares with the database dump which cannot
	// reconstruct the emitted messages as those are not available in the state dump alone.
	sc := &dumpRestoreImpl{
		runtimeImpl: *newRuntimeImpl(
			name,
			NewLongTermTestClient().WithMode(ModePart1NoMsg),
		),
		mapGenesisDocumentFn: mapGenesisDocumentFn,
	}
	return sc
}

func (sc *dumpRestoreImpl) Clone() scenario.Scenario {
	return &dumpRestoreImpl{
		runtimeImpl:          *sc.runtimeImpl.Clone().(*runtimeImpl),
		mapGenesisDocumentFn: sc.mapGenesisDocumentFn,
	}
}

func (sc *dumpRestoreImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Set up governance for proposals.
	f.Network.DeterministicIdentities = true
	f.Network.RestoreIdentities = true
	f.Network.GovernanceParameters = &governance.ConsensusParameters{
		MinProposalDeposit:        *quantity.NewFromUint64(100),
		VotingPeriod:              20,
		StakeThreshold:            100,
		UpgradeMinEpochDiff:       50,
		UpgradeCancelMinEpochDiff: 40,
	}
	f.Network.StakingGenesis = &staking.Genesis{
		TotalSupply: *quantity.NewFromUint64(1200),
		CommonPool:  *quantity.NewFromUint64(100),
		Ledger: map[staking.Address]*staking.Account{
			// Fund entity account so we'll be able to submit the proposal.
			e2e.DeterministicEntity1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(1000),
				},
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
				},
			},
		},
		Delegations: map[staking.Address]map[staking.Address]*staking.Delegation{
			e2e.DeterministicEntity1: {
				e2e.DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
		},
	}

	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 1
	f.Runtimes[1].Storage.CheckpointChunkSize = 1 * 1024

	return f, nil
}

func (sc *dumpRestoreImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Try submitting a proposal so that deposits are made.
	entityAcc, err := sc.Net.Controller().Staking.Account(ctx,
		&staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  e2e.DeterministicEntity1,
		},
	)
	if err != nil {
		return fmt.Errorf("failed querying account: %w", err)
	}
	content := &governance.ProposalContent{
		Upgrade: &governance.UpgradeProposal{
			Descriptor: upgrade.Descriptor{
				Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
				Handler:   migrations.DummyUpgradeHandler,
				Target:    version.Versions,
				Epoch:     200,
			},
		},
	}
	tx := governance.NewSubmitProposalTx(entityAcc.General.Nonce, &transaction.Fee{Gas: 2000}, content)
	sigTx, err := transaction.Sign(sc.Net.Entities()[0].Signer(), tx)
	if err != nil {
		return fmt.Errorf("failed signing submit proposal transaction: %w", err)
	}
	err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return fmt.Errorf("failed submitting proposal transaction: %w", err)
	}

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	// Dump restore network.
	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if err = sc.DumpRestoreNetwork(childEnv, fixture, true, sc.mapGenesisDocumentFn, nil); err != nil {
		return err
	}

	// Completely reset state for one of the compute nodes so we can test initial sync.
	sc.Logger.Info("completely resetting state for one of the compute nodes")
	cli := cli.New(childEnv, sc.Net, sc.Logger)
	if err = cli.UnsafeReset(sc.Net.ComputeWorkers()[1].DataDir(), false, false, true); err != nil {
		return fmt.Errorf("failed to reset state for compute worker: %w", err)
	}

	if err = sc.Net.Start(); err != nil {
		return fmt.Errorf("failed to start restored network: %w", err)
	}

	// Wait for all compute nodes to be ready.
	sc.Logger.Info("waiting for all compute nodes to be ready")
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Check that everything works with restored state.
	newTestClient := sc.testClient.Clone().(*LongTermTestClient)
	sc.runtimeImpl.testClient = newTestClient.WithMode(ModePart2).WithSeed("second_seed")
	return sc.runtimeImpl.Run(childEnv)
}
