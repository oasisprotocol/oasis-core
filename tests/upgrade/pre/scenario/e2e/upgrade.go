package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

// DumpRestoreUpgradeNetwork prepares, submits, and votes on a new network upgrade proposal,
// waits for the network to halt and then wipes the consensus state.
func DumpRestoreUpgradeNetwork(ctx context.Context, childEnv *env.Env, sc *e2e.Scenario) error {
	// Upgrade the network and wait for it to halt.
	if err := UpgradeNetwork(ctx, childEnv, sc); err != nil {
		return err
	}

	// Prepare state for post-upgrade scenario.
	sc.Logger.Info("wiping consensus state")

	resetFlags := map[uint8]bool{
		e2e.PreserveComputeWorkerLocalStorage:   true,
		e2e.PreserveComputeWorkerRuntimeStorage: true, // default, needed
		e2e.PreserveKeymanagerLocalStorage:      true, // default, needed
	}
	if err := sc.ResetConsensusState(childEnv, resetFlags); err != nil {
		return fmt.Errorf("failed to wipe storage: %w", err)
	}

	return nil
}

// UpgradeNetwork prepares, submits, and votes on a new network upgrade proposal,
// and then waits for the network to halt.
func UpgradeNetwork(ctx context.Context, childEnv *env.Env, sc *e2e.Scenario) error {
	// Wait for client sync.
	if len(sc.Net.Clients()) == 0 {
		return fmt.Errorf("network upgrade requires at least one client node")
	}
	if err := sc.Net.ClientController().WaitSync(ctx); err != nil {
		return err
	}

	// Remember current epoch.
	epoch, err := sc.Net.ClientController().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Select an entity that will submit a network upgrade proposal.
	if len(sc.Net.Entities()) == 0 {
		return fmt.Errorf("network upgrade requires at least one entity")
	}
	entity := sc.Net.Entities()[0]

	account, err := sc.Net.ClientController().Staking.Account(ctx, &api.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  staking.NewAddress(entity.ID()),
	})
	if err != nil {
		return fmt.Errorf("failed to query entity account: %w", err)
	}

	// Load governance parameters.
	govParams, err := sc.Net.ClientController().Governance.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to load governance consensus parameters: %w", err)
	}

	// Prepare and submit a proposal.
	versions, err := protocolVersions()
	if err != nil {
		return err
	}

	proposal := governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
		Descriptor: upgrade.Descriptor{
			Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
			Handler:   migrations.EmptyHandler,
			Target:    versions, // TODO: This should be the next version.
			Epoch:     epoch + govParams.UpgradeMinEpochDiff + 1,
		},
	}}

	sc.Logger.Info("submitting network upgrade proposal", "proposal", proposal)

	tx := governance.NewSubmitProposalTx(account.General.Nonce, &transaction.Fee{
		Amount: *quantity.NewFromUint64(0),
		Gas:    10_000,
	}, &proposal)

	sigTx, err := transaction.Sign(entity.Signer(), tx)
	if err != nil {
		return fmt.Errorf("failed to sign network upgrade proposal transaction: %w", err)
	}

	if err = sc.Net.ClientController().Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to submit network upgrade proposal transaction: %w", err)
	}

	// Ensure proposal created.
	aps, err := sc.Net.ClientController().Governance.ActiveProposals(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to query active proposals: %w", err)
	}
	idx := slices.IndexFunc(aps, func(p *governance.Proposal) bool {
		return p.Content.Equals(&proposal)
	})
	if idx < 0 {
		return fmt.Errorf("submitted network upgrade proposal not found")
	}
	activeProposal := aps[idx]

	sc.Logger.Info("network upgrade proposal is active")

	// Vote on the proposal.
	for _, entity := range sc.Net.Entities() {
		if err = voteForProposal(ctx, sc, entity, activeProposal.ID); err != nil {
			return fmt.Errorf("failed to vote on proposal: %w", err)
		}
	}

	// Wait for the network to halt.
	sc.Logger.Info("waiting for network to halt")

	for _, v := range sc.Net.Nodes() {
		<-v.Exit()
	}

	return nil
}

func voteForProposal(ctx context.Context, sc *e2e.Scenario, entity *oasis.Entity, proposalID uint64) error {
	// Query entity nonce.
	account, err := sc.Net.ClientController().Staking.Account(ctx, &api.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  staking.NewAddress(entity.ID()),
	})
	if err != nil {
		return fmt.Errorf("failed to query entity account: %w", err)
	}

	nonce := account.General.Nonce

	// Ensure entity has some stake.
	if account.Escrow.Active.Balance.IsZero() {
		// Self-delegate some stake.
		tx := staking.NewAddEscrowTx(nonce, &transaction.Fee{Gas: 2000}, &staking.Escrow{
			Account: staking.NewAddress(entity.ID()),
			Amount:  *quantity.NewFromUint64(10),
		})
		nonce++

		sigTx, err := transaction.Sign(entity.Signer(), tx)
		if err != nil {
			return fmt.Errorf("failed to sign add escrow transaction: %w", err)
		}
		if err = sc.Net.ClientController().Consensus.SubmitTx(ctx, sigTx); err != nil {
			return fmt.Errorf("failed to submit add escrow transaction: %w", err)
		}
	}

	// Vote for proposal.
	vote := governance.ProposalVote{
		ID:   proposalID,
		Vote: governance.VoteYes,
	}
	tx := governance.NewCastVoteTx(nonce, &transaction.Fee{Gas: 2000}, &vote)
	sigTx, err := transaction.Sign(entity.Signer(), tx)
	if err != nil {
		return fmt.Errorf("failed to sign cast vote transaction: %w", err)
	}

	err = sc.Net.ClientController().Consensus.SubmitTx(ctx, sigTx)
	switch {
	case errors.Is(err, governance.ErrNotEligible):
		// Entity is not eligible to vote.
	case err == nil:
		// Vote cast.
	default:
		// Unexpected error.
		return fmt.Errorf("failed to submit cast vote transaction: %w", err)
	}

	return nil
}

func protocolVersions() (version.ProtocolVersions, error) {
	var versions version.ProtocolVersions
	versionsStr, _ := upgradeFlags.GetString(cfgUpgradeProtocolVersions)
	versionsSlice := strings.Split(versionsStr, ",")

	for i, s := range versionsSlice {
		v, err := version.FromString(s)
		if err != nil {
			return versions, err
		}

		switch i {
		case 0:
			versions.ConsensusProtocol = v
		case 1:
			versions.RuntimeHostProtocol = v
		default:
			versions.RuntimeCommitteeProtocol = v
		}
	}

	return versions, nil
}
