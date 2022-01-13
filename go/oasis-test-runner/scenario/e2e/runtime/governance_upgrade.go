package runtime

import (
	"context"
	"fmt"
	"sync"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

var (
	// GovernanceConsensusUpgrade is the governance consensus upgrade scenario.
	GovernanceConsensusUpgrade scenario.Scenario = newGovernanceConsensusUpgradeImpl(true, false)
	// GovernanceConsensusFailUpgrade is the governance consensus upgrade scenario
	// where node should fail the upgrade.
	GovernanceConsensusFailUpgrade scenario.Scenario = newGovernanceConsensusUpgradeImpl(false, false)
	// GovernanceConsensusCancelUpgrade is the governance consensus upgrade scenario
	// where the pending upgrade is canceled.
	GovernanceConsensusCancelUpgrade scenario.Scenario = newGovernanceConsensusUpgradeImpl(true, true)
)

type governanceConsensusUpgradeImpl struct {
	runtimeImpl

	currentEpoch beacon.EpochTime
	entityNonce  uint64

	correctUpgradeVersion bool
	shouldCancelUpgrade   bool

	entity *oasis.Entity

	ctx context.Context
}

func newGovernanceConsensusUpgradeImpl(correctUpgradeVersion, cancelUpgrade bool) scenario.Scenario {
	var name string
	switch correctUpgradeVersion {
	case true:
		name = "governance-upgrade"
	case false:
		name = "governance-fail-upgrade"
	}
	if cancelUpgrade {
		name += "-cancel"
	}

	sc := &governanceConsensusUpgradeImpl{
		runtimeImpl: *newRuntimeImpl(
			name,
			NewLongTermTestClient().WithMode(ModePart1),
		),
		correctUpgradeVersion: correctUpgradeVersion,
		shouldCancelUpgrade:   cancelUpgrade,
		ctx:                   context.Background(),
	}
	return sc
}

func (sc *governanceConsensusUpgradeImpl) Clone() scenario.Scenario {
	return &governanceConsensusUpgradeImpl{
		runtimeImpl:           *sc.runtimeImpl.Clone().(*runtimeImpl),
		currentEpoch:          sc.currentEpoch,
		entityNonce:           sc.entityNonce,
		correctUpgradeVersion: sc.correctUpgradeVersion,
		shouldCancelUpgrade:   sc.shouldCancelUpgrade,
		ctx:                   context.Background(),
	}
}

func (sc *governanceConsensusUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Needed so we can fast-forward to upgrade epoch.
	f.Network.SetMockEpoch()
	// Needed as we will vote as validators.
	f.Network.DeterministicIdentities = true
	f.Network.DefaultLogWatcherHandlerFactories = []log.WatcherHandlerFactory{}

	f.Network.GovernanceParameters = &api.ConsensusParameters{
		MinProposalDeposit:        *quantity.NewFromUint64(100),
		VotingPeriod:              5,
		StakeThreshold:            100,
		UpgradeMinEpochDiff:       20,
		UpgradeCancelMinEpochDiff: 8,
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
	f.Entities = []oasis.EntityCfg{
		{IsDebugTestEntity: true},
		{},
	}

	f.Validators = []oasis.ValidatorFixture{
		{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true, SupplementarySanityInterval: 1}, AllowErrorTermination: true},
		{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}, AllowErrorTermination: true},
		{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}, AllowErrorTermination: true},
	}
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1, AllowErrorTermination: true},
	}
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{
		{Entity: 1, Runtimes: []int{1}, AllowErrorTermination: true},
		{Entity: 1, Runtimes: []int{1}, AllowErrorTermination: true},
		{Entity: 1, Runtimes: []int{1}, AllowErrorTermination: true},
	}
	f.Clients = []oasis.ClientFixture{
		{AllowErrorTermination: true, Runtimes: []int{1}},
	}

	switch {
	case sc.correctUpgradeVersion && !sc.shouldCancelUpgrade:
		f.Network.DefaultLogWatcherHandlerFactories = append(
			f.Network.DefaultLogWatcherHandlerFactories,
			oasis.LogAssertUpgradeStartup(),
			oasis.LogAssertUpgradeConsensus(),
		)
	case !sc.correctUpgradeVersion:
		f.Network.DefaultLogWatcherHandlerFactories = append(
			f.Network.DefaultLogWatcherHandlerFactories,
			oasis.LogAssertUpgradeIncompatibleBinary(),
		)
		fallthrough
	default:
		f.Network.DefaultLogWatcherHandlerFactories = append(
			f.Network.DefaultLogWatcherHandlerFactories,
			oasis.LogAssertNoUpgradeStartup(),
			oasis.LogAssertNoUpgradeConsensus(),
		)
	}
	return f, nil
}

func (sc *governanceConsensusUpgradeImpl) nextEpoch(ctx context.Context) error {
	sc.currentEpoch++
	if err := sc.Net.Controller().SetEpoch(ctx, sc.currentEpoch); err != nil {
		// Errors can happen because an upgrade happens exactly during an epoch transition. So
		// make sure to ignore them.
		sc.Logger.Warn("failed to set epoch",
			"epoch", sc.currentEpoch,
			"err", err,
		)
	}
	return nil
}

// Submits a proposal, votes for it and ensures the proposal is finalized.
func (sc *governanceConsensusUpgradeImpl) ensureProposalFinalized(content *api.ProposalContent) (*api.Proposal, error) {
	// Submit proposal.
	tx := api.NewSubmitProposalTx(sc.entityNonce, &transaction.Fee{Gas: 2000}, content)
	sc.entityNonce++
	sigTx, err := transaction.Sign(sc.entity.Signer(), tx)
	if err != nil {
		return nil, fmt.Errorf("failed signing submit proposal transaction: %w", err)
	}
	sc.Logger.Info("submitting proposal", "content", content)
	err = sc.Net.Controller().Consensus.SubmitTx(sc.ctx, sigTx)
	if err != nil {
		return nil, fmt.Errorf("failed submitting proposal transaction: %w", err)
	}

	// Ensure proposal created.
	aps, err := sc.Net.Controller().Governance.ActiveProposals(sc.ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("failed querying active proposals: %w", err)
	}
	var proposal *api.Proposal
	for _, p := range aps {
		if p.Content.Equals(content) {
			proposal = p
			break
		}
	}
	if proposal == nil {
		return nil, fmt.Errorf("submitted proposal %v not found", content)
	}

	// Vote for the proposal.
	vote := api.ProposalVote{
		ID:   proposal.ID,
		Vote: api.VoteYes,
	}
	tx = api.NewCastVoteTx(sc.entityNonce, &transaction.Fee{Gas: 2000}, &vote)
	sc.entityNonce++
	sigTx, err = transaction.Sign(sc.entity.Signer(), tx)
	if err != nil {
		return nil, fmt.Errorf("failed signing cast vote transaction: %w", err)
	}
	sc.Logger.Info("submitting vote for proposal", "proposal", proposal, "vote", vote)
	err = sc.Net.Controller().Consensus.SubmitTx(sc.ctx, sigTx)
	if err != nil {
		return nil, fmt.Errorf("failed submitting cast vote transaction: %w", err)
	}

	// Ensure vote was cast.
	votes, err := sc.Net.Controller().Governance.Votes(sc.ctx,
		&api.ProposalQuery{
			Height:     consensus.HeightLatest,
			ProposalID: aps[0].ID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed queying votes: %w", err)
	}
	if l := len(votes); l != 1 {
		return nil, fmt.Errorf("expected one vote, got: %v", l)
	}
	if vote := votes[0].Vote; vote != api.VoteYes {
		return nil, fmt.Errorf("expected vote Yes, got: %s", string(vote))
	}

	// Transition to the epoch when proposal finalizes.
	for ep := sc.currentEpoch + 1; ep < aps[0].ClosesAt+1; ep++ {
		sc.Logger.Info("transitioning to epoch", "epoch", ep)
		if err = sc.nextEpoch(sc.ctx); err != nil {
			return nil, err
		}
	}

	p, err := sc.Net.Controller().Governance.Proposal(sc.ctx,
		&api.ProposalQuery{
			Height:     consensus.HeightLatest,
			ProposalID: proposal.ID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query proposal: %w", err)
	}
	sc.Logger.Info("got proposal",
		"state", p.State.String(),
		"results", p.Results,
		"len", len(p.Results),
		"invalid", p.InvalidVotes,
	)
	// Ensure proposal finalized.
	if p.State == api.StateActive || p.State == api.StateFailed {
		return nil, fmt.Errorf("expected finalized proposal, proposal state: %v", p.State)
	}

	return p, nil
}

func (sc *governanceConsensusUpgradeImpl) cancelUpgrade(proposalID uint64) error {
	_, err := sc.ensureProposalFinalized(
		&api.ProposalContent{CancelUpgrade: &api.CancelUpgradeProposal{
			ProposalID: proposalID,
		}})
	if err != nil {
		return err
	}

	// Ensure pending upgrade was canceled.
	pendingUpgrades, err := sc.Net.Controller().Governance.PendingUpgrades(sc.ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to query pending upgrades: %w", err)
	}
	if l := len(pendingUpgrades); l != 0 {
		return fmt.Errorf("expected no pending upgrade, got: %v", l)
	}

	return nil
}

func (sc *governanceConsensusUpgradeImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	if err := sc.startNetworkAndTestClient(sc.ctx, childEnv); err != nil {
		return err
	}

	sc.entity = sc.Net.Entities()[1]

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Wait for the nodes.
	if sc.currentEpoch, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	entityAcc, err := sc.Net.Controller().Staking.Account(sc.ctx,
		&staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  e2e.DeterministicEntity1,
		},
	)
	if err != nil {
		return fmt.Errorf("failed querying account: %w", err)
	}
	sc.entityNonce = entityAcc.General.Nonce

	// Prepare upgrade proposal.
	upgradeEpoch := sc.currentEpoch + sc.Net.Config().GovernanceParameters.UpgradeMinEpochDiff
	var target version.ProtocolVersions
	switch sc.correctUpgradeVersion {
	case true:
		target = version.Versions
	default:
		target = version.ProtocolVersions{
			ConsensusProtocol: version.FromU64(192),
			RuntimeHostProtocol: version.Version{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			RuntimeCommitteeProtocol: version.Version{
				Major: 4,
				Minor: 5,
				Patch: 6,
			},
		}
	}

	content := &api.ProposalContent{
		Upgrade: &api.UpgradeProposal{
			Descriptor: upgrade.Descriptor{
				Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
				Handler:   migrations.DummyUpgradeHandler,
				Target:    target,
				Epoch:     upgradeEpoch,
			},
		},
	}
	// Submit upgrade proposal.
	proposal, err := sc.ensureProposalFinalized(content)
	if err != nil {
		return fmt.Errorf("upgrade proposal error: %w", err)
	}

	// Ensure pending upgrade exists.
	pendingUpgrades, err := sc.Net.Controller().Governance.PendingUpgrades(sc.ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to query pending upgrades: %w", err)
	}
	if l := len(pendingUpgrades); l != 1 {
		return fmt.Errorf("expected one pending upgrade, got: %v", l)
	}

	// Cancel upgrade if configured so.
	if sc.shouldCancelUpgrade {
		if err = sc.cancelUpgrade(proposal.ID); err != nil {
			return fmt.Errorf("cancel upgrade failure: %w", err)
		}
	}

	// Make sure all nodes will restart once the upgrade epoch is reached.
	var group sync.WaitGroup
	errCh := make(chan error, len(sc.Net.Nodes()))
	if !sc.shouldCancelUpgrade {
		for i, nd := range sc.Net.Nodes() {
			group.Add(1)
			go func(i int, nd *oasis.Node) {
				defer group.Done()
				sc.Logger.Info("waiting for node to exit", "node", nd.Name)
				<-nd.Exit()
				sc.Logger.Info("restarting node", "node", nd.Name)
				if err = nd.Restart(sc.ctx); err != nil {
					errCh <- err
				}
			}(i, nd)
		}
	}

	// Transition to upgrade epoch.
	for ep := sc.currentEpoch + 1; ep <= upgradeEpoch; ep++ {
		sc.Logger.Info("transitioning to epoch", "epoch", ep)

		if err = sc.nextEpoch(sc.ctx); err != nil {
			return err
		}
	}

	if !sc.shouldCancelUpgrade {
		// Nodes should restart.
		sc.Logger.Info("waiting for all nodes to get restarted")
		group.Wait()
		select {
		case err = <-errCh:
			return fmt.Errorf("can't restart node for consensus upgrade test: %w", err)
		default:
		}

		if !sc.correctUpgradeVersion {
			// In case the upgrade descriptor binary doesn't match the upgraded version, all of the
			// nodes should halt even after being restarted.
			for _, nd := range sc.Net.Nodes() {
				sc.Logger.Info("waiting for node to exit", "node", nd.Name)
				<-nd.Exit()
			}
			sc.Logger.Info("all nodes have exited after restart")
			return sc.Net.CheckLogWatchers()
		}

		// Ensure genesis was exported and matches on all nodes.
		sc.Logger.Info("gathering exported genesis files")
		_, err = sc.GetExportedGenesisFiles(false)
		if err != nil {
			return fmt.Errorf("failure getting exported genesis files: %w", err)
		}

		// Upgrade binary matches node binary, upgrade should work.
		sc.Logger.Info("waiting for nodes to sync")
		if err = sc.Net.Controller().WaitSync(sc.ctx); err != nil {
			return fmt.Errorf("wait sync error: %w", err)
		}

		// Check the consensus migration was run (test migration creates a new entity).
		idQuery := &registry.IDQuery{
			Height: consensus.HeightLatest,
			ID:     migrations.TestEntity.ID,
		}
		_, err = sc.Net.Controller().Registry.GetEntity(sc.ctx, idQuery)
		if err != nil {
			return fmt.Errorf("can't get registered test entity: %w", err)
		}

		// Wait for compute nodes to be ready.
		sc.Logger.Info("waiting for compute nodes to be ready")
		for _, n := range sc.Net.ComputeWorkers() {
			if err = n.WaitReady(sc.ctx); err != nil {
				return fmt.Errorf("failed to wait for a compute node: %w", err)
			}
		}
	}

	sc.Logger.Info("final epoch transition")
	if err = sc.nextEpoch(sc.ctx); err != nil {
		return err
	}

	// Check that runtime still works after the upgrade.
	newTestClient := sc.testClient.Clone().(*LongTermTestClient)
	sc.runtimeImpl.testClient = newTestClient.WithMode(ModePart2).WithSeed("second_seed")
	return sc.runtimeImpl.Run(childEnv)
}
