package api

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// ProposalState is the state of the proposal.
type ProposalState uint8

// Proposal state kinds.
const (
	StateActive   ProposalState = 1
	StatePassed   ProposalState = 2
	StateRejected ProposalState = 3
	StateFailed   ProposalState = 4

	StateActiveName   = "active"
	StatePassedName   = "passed"
	StateRejectedName = "rejected"
	StateFailedName   = "failed"
)

// String returns a string representation of a ProposalState.
func (p ProposalState) String() string {
	switch p {
	case StateActive:
		return StateActiveName
	case StatePassed:
		return StatePassedName
	case StateRejected:
		return StateRejectedName
	case StateFailed:
		return StateFailedName
	default:
		return fmt.Sprintf("[unknown state: %d]", p)
	}
}

// MarshalText encodes a ProposalState into text form.
func (p ProposalState) MarshalText() ([]byte, error) {
	switch p {
	case StateActive:
		return []byte(StateActiveName), nil
	case StatePassed:
		return []byte(StatePassedName), nil
	case StateRejected:
		return []byte(StateRejectedName), nil
	case StateFailed:
		return []byte(StateFailedName), nil
	default:
		return nil, fmt.Errorf("invalid state: %d", p)
	}
}

// UnmarshalText decodes a text slice into a ProposalState.
func (p *ProposalState) UnmarshalText(text []byte) error {
	switch string(text) {
	case StateActiveName:
		*p = StateActive
	case StatePassedName:
		*p = StatePassed
	case StateRejectedName:
		*p = StateRejected
	case StateFailedName:
		*p = StateFailed
	default:
		return fmt.Errorf("invalid state: %s", string(text))
	}
	return nil
}

var errInvalidProposalState = fmt.Errorf("invalid closing proposal state")

// Proposal is a consensus upgrade proposal.
type Proposal struct {
	// ID is the unique identifier of the proposal.
	ID uint64 `json:"id"`
	// Submitter is the address of the proposal submitter.
	Submitter staking.Address `json:"submitter"`
	// State is the state of the proposal.
	State ProposalState `json:"state"`
	// Deposit is the deposit attached to the proposal.
	Deposit quantity.Quantity `json:"deposit"`

	// Content is the content of the proposal.
	Content ProposalContent `json:"content"`

	// CreatedAt is the epoch at which the proposal was created.
	CreatedAt beacon.EpochTime `json:"created_at"`
	// ClosesAt is the epoch at which the proposal will close and votes will
	// be tallied.
	ClosesAt beacon.EpochTime `json:"closes_at"`
	// Results are the final tallied results after the voting period has
	// ended.
	Results map[Vote]quantity.Quantity `json:"results,omitempty"`
	// InvalidVotes is the number of invalid votes after tallying.
	InvalidVotes uint64 `json:"invalid_votes,omitempty"`
}

// VotedSum returns the sum of all votes.
func (p *Proposal) VotedSum() (*quantity.Quantity, error) {
	votedSum := quantity.NewQuantity()
	for _, q := range p.Results {
		if err := votedSum.Add(q.Clone()); err != nil {
			return nil, fmt.Errorf("failed to add votes to vote sum: %w", err)
		}
	}
	return votedSum, nil
}

// CloseProposal closes an active proposal based on the vote results and
// specified voting parameters.
//
// The proposal is accepted iff the percentage of yes votes relative to
// total voting power is at least `stakeThreshold`.  Otherwise the proposal
// is rejected.
func (p *Proposal) CloseProposal(totalVotingStake quantity.Quantity, stakeThreshold uint8) error {
	if p.State != StateActive {
		return fmt.Errorf("%w: expected: %v, got: %v", errInvalidProposalState, StateActive, p.State)
	}
	if p.Results == nil {
		return fmt.Errorf("%w: results not initialized", errInvalidProposalState)
	}
	if totalVotingStake.IsZero() {
		return fmt.Errorf("%w: total voting stake is zero", errInvalidProposalState)
	}

	votedStake, err := p.VotedSum()
	if err != nil {
		return err
	}
	// Ensure Voted is not more than the total possible voting stake.
	if votedStake.Cmp(&totalVotingStake) > 0 {
		return fmt.Errorf("%w: voted stake (%v) greater than total possbile voting stake (%v)", errInvalidProposalState, votedStake, totalVotingStake)
	}

	votedYesStake := p.Results[VoteYes]
	if votedYesStake.IsZero() {
		// If there's no yes votes, we can early reject the vote.
		p.State = StateRejected
		return nil
	}

	// Calculate percentage of yes votes vs the sum of validator stake.
	votedYesPercentage := votedYesStake.Clone()
	if err := votedYesPercentage.Mul(quantity.NewFromUint64(100)); err != nil {
		return fmt.Errorf("failed to multiply votedYesPercentage: %w", err)
	}
	if err := votedYesPercentage.Quo(&totalVotingStake); err != nil {
		return fmt.Errorf("failed to divide multiply votedYesPercentage: %w", err)
	}

	// In case the percentage of yes votes (by stake) relative to the total
	// voting power is less than the stake threshold, the proposal is rejected.
	if votedYesPercentage.Cmp(quantity.NewFromUint64(uint64(stakeThreshold))) < 0 {
		// Reject proposal.
		p.State = StateRejected
		return nil
	}

	p.State = StatePassed

	return nil
}

// Vote is a governance vote.
type Vote uint8

// Vote kinds.
const (
	VoteYes     Vote = 1
	VoteNo      Vote = 2
	VoteAbstain Vote = 3

	VoteYesName     = "yes"
	VoteNoName      = "no"
	VoteAbstainName = "abstain"
)

// String returns a string representation of a Vote.
func (v Vote) String() string {
	switch v {
	case VoteYes:
		return VoteYesName
	case VoteNo:
		return VoteNoName
	case VoteAbstain:
		return VoteAbstainName
	default:
		return fmt.Sprintf("[unknown vote: %d]", v)
	}
}

// MarshalText encodes a Vote into text form.
func (v Vote) MarshalText() ([]byte, error) {
	switch v {
	case VoteYes:
		return []byte(VoteYesName), nil
	case VoteNo:
		return []byte(VoteNoName), nil
	case VoteAbstain:
		return []byte(VoteAbstainName), nil
	default:
		return nil, fmt.Errorf("invalid vote: %d", v)
	}
}

// UnmarshalText decodes a text slice into a Vote.
func (v *Vote) UnmarshalText(text []byte) error {
	switch string(text) {
	case VoteYesName:
		*v = VoteYes
	case VoteNoName:
		*v = VoteNo
	case VoteAbstainName:
		*v = VoteAbstain
	default:
		return fmt.Errorf("invalid vote: %s", string(text))
	}
	return nil
}

// PendingUpgradesFromProposals computes pending upgrades proposals state.
//
// Returns pending upgrades and corresponding proposal IDs.
// This is useful for initialzing genesis state which doesn't include pending upgrades,
// as these can always be computed from accepted proposals.
func PendingUpgradesFromProposals(proposals []*Proposal, epoch beacon.EpochTime) ([]*upgrade.Descriptor, []uint64) {
	var acceptedProposals []*Proposal

	// Go over all proposals and find accepted proposals.
	for _, proposal := range proposals {
		// Unless this is a passed proposal, there's nothing to do.
		if proposal.State != StatePassed {
			continue
		}
		// Cancel upgrade proposals are handled separately.
		if proposal.Content.Upgrade == nil {
			continue
		}
		// If the upgrade is for an old epoch, skip it as it isn't relevant anymore.
		if proposal.Content.Upgrade.Epoch < epoch {
			continue
		}
		// Set the pending upgrade.
		acceptedProposals = append(acceptedProposals, proposal)
	}
	// Cancel any accepted proposals.
	for _, proposal := range proposals {
		if proposal.State != StatePassed {
			continue
		}
		if proposal.Content.CancelUpgrade == nil {
			continue
		}
		for i, p := range acceptedProposals {
			if p.ID == proposal.Content.CancelUpgrade.ProposalID {
				// It's fine to mutate acceptedProposals here, as we'll break out of the loop.
				acceptedProposals = append(acceptedProposals[:i], acceptedProposals[i+1:]...)
				break
			}
		}
	}

	// Return accepted and not canceled upgrade descriptors.
	var pendingUpgrades []*upgrade.Descriptor
	var proposalIDs []uint64
	for _, p := range acceptedProposals {
		pendingUpgrades = append(pendingUpgrades, &p.Content.Upgrade.Descriptor)
		proposalIDs = append(proposalIDs, p.ID)
	}
	return pendingUpgrades, proposalIDs
}
