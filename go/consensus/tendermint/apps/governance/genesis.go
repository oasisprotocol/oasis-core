package governance

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
)

func (app *governanceApplication) InitChain(ctx *abciAPI.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Governance

	epoch, err := app.state.GetCurrentEpoch(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/governance: couldn't get current epoch: %w", err)
	}

	state := governanceState.NewMutableState(ctx.State())
	if err = state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("tendermint/governance: failed to set consensus parameters: %w", err)
	}

	// Insert proposals.
	var largestProposalID uint64
	for _, proposal := range st.Proposals {
		if proposal.ID > largestProposalID {
			largestProposalID = proposal.ID
		}
		switch proposal.State {
		case governance.StateActive:
			if err = state.SetActiveProposal(ctx, proposal); err != nil {
				return fmt.Errorf("tendermint/governance: failed to set active proposal: %w", err)
			}
		default:
			if err = state.SetProposal(ctx, proposal); err != nil {
				return fmt.Errorf("tendermint/governance: failed to set proposal: %w", err)
			}
		}
		// Insert votes for the proposal.
		for _, vote := range st.VoteEntries[proposal.ID] {
			if err = state.SetVote(ctx, proposal.ID, vote.Voter, vote.Vote); err != nil {
				return fmt.Errorf("tendermint/governance: failed to set vote: %w", err)
			}
		}
	}

	// Compute pending upgrades from proposals.
	upgrades, ids := governance.PendingUpgradesFromProposals(st.Proposals, epoch)
	for i, up := range upgrades {
		if err = state.SetPendingUpgrade(ctx, ids[i], up); err != nil {
			return fmt.Errorf("tendermint/governance: failed to set pending upgrade: %w", err)
		}
	}

	if err := state.SetNextProposalIdentifier(ctx, largestProposalID+1); err != nil {
		return fmt.Errorf("tendermint/governance: failed to set next proposal identifier: %w", err)
	}

	return nil
}

// Genesis exports current state in genesis format.
func (gq *governanceQuerier) Genesis(ctx context.Context) (*governance.Genesis, error) {
	params, err := gq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	proposals, err := gq.state.Proposals(ctx)
	if err != nil {
		return nil, err
	}

	voteEntries := make(map[uint64][]*governance.VoteEntry)
	for _, proposal := range proposals {
		var votes []*governance.VoteEntry
		votes, err = gq.state.Votes(ctx, proposal.ID)
		if err != nil {
			return nil, err
		}
		voteEntries[proposal.ID] = votes
	}

	return &governance.Genesis{
		Parameters:  *params,
		Proposals:   proposals,
		VoteEntries: voteEntries,
	}, nil
}
