// Package api implements the governance APIs.
package api

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// ModuleName is a unique module name for the governance backend.
const ModuleName = "governance"

var (
	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New(ModuleName, 1, "governance: invalid argument")
	// ErrUpgradeTooSoon is the error returned when an upgrade is not enough in the future.
	ErrUpgradeTooSoon = errors.New(ModuleName, 2, "governance: upgrade too soon")
	// ErrUpgradeAlreadyPending is the error returned when an upgrade is already pending.
	ErrUpgradeAlreadyPending = errors.New(ModuleName, 3, "governance: upgrade already pending")
	// ErrNoSuchUpgrade is the error returned when an upgrade does not exist.
	ErrNoSuchUpgrade = errors.New(ModuleName, 4, "governance: no such upgrade")
	// ErrNoSuchProposal is the error retrued when a proposal does not exist.
	ErrNoSuchProposal = errors.New(ModuleName, 5, "governance: no such proposal")
	// ErrNotEligible is the error returned when a vote caster is not eligible for a vote.
	ErrNotEligible = errors.New(ModuleName, 6, "governance: not eligible")
	// ErrVotingIsClosed is the error returned when a vote is cast for a non-active proposal.
	ErrVotingIsClosed = errors.New(ModuleName, 7, "governance: voting is closed")

	// MethodSubmitProposal submits a new consensus layer governance proposal.
	MethodSubmitProposal = transaction.NewMethodName(ModuleName, "SubmitProposal", ProposalContent{})
	// MethodCastVote casts a vote for a consensus layer governance proposal.
	MethodCastVote = transaction.NewMethodName(ModuleName, "CastVote", ProposalVote{})

	// Methods is the list of all methods supported by the governance backend.
	Methods = []transaction.MethodName{
		MethodSubmitProposal,
		MethodCastVote,
	}
)

// ProposalContent is a consensus layer governance proposal content.
type ProposalContent struct {
	Upgrade       *UpgradeProposal       `json:"upgrade,omitempty"`
	CancelUpgrade *CancelUpgradeProposal `json:"cancel_upgrade,omitempty"`
}

// ValidateBasic performs basic proposal content validity checks.
func (p *ProposalContent) ValidateBasic() error {
	switch {
	case p.Upgrade != nil && p.CancelUpgrade != nil:
		return fmt.Errorf("proposal content has multiple fields set")
	case p.Upgrade != nil:
		return p.Upgrade.ValidateBasic()
	case p.CancelUpgrade != nil:
		// No validation at this time.
		return nil
	default:
		return fmt.Errorf("proposal content has no fields set")
	}
}

// Equals checks if proposal contents are equal.
//
// Note: this assumes valid proposals where each proposals will have
// exactly one field set.
func (p *ProposalContent) Equals(other *ProposalContent) bool {
	switch {
	case p.CancelUpgrade != nil && other.CancelUpgrade != nil:
		return p.CancelUpgrade.ProposalID == other.CancelUpgrade.ProposalID
	case p.Upgrade != nil && other.Upgrade != nil:
		return p.Upgrade.Descriptor.Equals(&other.Upgrade.Descriptor)
	default:
		return false
	}
}

// UpgradeProposal is an upgrade proposal.
type UpgradeProposal struct {
	upgrade.Descriptor
}

// CancelUpgradeProposal is an upgrade cancellation proposal.
type CancelUpgradeProposal struct {
	// ProposalID is the identifier of the pending upgrade proposal.
	ProposalID uint64 `json:"proposal_id"`
}

// ProposalVote is a vote for a proposal.
type ProposalVote struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Vote is the vote.
	Vote Vote `json:"vote"`
}

// Backend is a governance implementation.
type Backend interface {
	// ActiveProposals returns a list of all proposals that have not yet closed.
	ActiveProposals(ctx context.Context, height int64) ([]*Proposal, error)

	// Proposal looks up a specific proposal.
	Proposal(ctx context.Context, query *ProposalQuery) (*Proposal, error)

	// Votes looks up votes for a specific proposal.
	Votes(ctx context.Context, query *ProposalQuery) ([]*VoteEntry, error)

	// PendingUpgrades returns a list of all pending upgrades.
	PendingUpgrades(ctx context.Context, height int64) ([]*upgrade.Descriptor, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// ConsensusParameters returns the governance consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]*Event, error)

	// WatchEvents returns a channel that produces a stream of Events.
	WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error)

	// Cleanup cleans up the backend.
	Cleanup()
}

// ProposalQuery is a proposal query.
type ProposalQuery struct {
	Height     int64  `json:"height"`
	ProposalID uint64 `json:"id"`
}

// VoteEntry contains data about a cast vote.
type VoteEntry struct {
	Voter staking.Address `json:"voter"`
	Vote  Vote            `json:"vote"`
}

// Genesis is the initial governance state for use in the genesis block.
//
// Note: PendingProposalUpgrades are not included in genesis, but are instead
// computed at InitChain from accepted proposals.
type Genesis struct {
	// Parameters are the genesis consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// Proposals are the governance proposals.
	Proposals []*Proposal `json:"proposals,omitempty"`

	// VoteEntries are the governance proposal vote entries.
	VoteEntries map[uint64][]*VoteEntry `json:"vote_entries,omitempty"`
}

// ConsensusParameters are the governance consensus parameters.
type ConsensusParameters struct {
	// GasCosts are the governance transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MinProposalDeposit is the number of base units that are deposited when
	// creating a new proposal.
	MinProposalDeposit quantity.Quantity `json:"min_proposal_deposit,omitempty"`

	// VotingPeriod is the number of epochs after which the voting for a proposal
	// is closed and the votes are tallied.
	VotingPeriod epochtime.EpochTime `json:"voting_period,omitempty"`

	// Quorum is he minimum percentage of voting power that needs to be cast on
	// a proposal for the result to be valid.
	Quorum uint8 `json:"quorum,omitempty"`

	// Threshold is the minimum percentage of VoteYes votes in order for a
	// proposal to be accepted.
	Threshold uint8 `json:"threshold,omitempty"`

	// UpgradeMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade proposal to be valid.
	// This is also the minimum number of epochs between two pending upgrades.
	UpgradeMinEpochDiff epochtime.EpochTime `json:"upgrade_min_epoch_diff,omitempty"`

	// UpgradeCancelMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade cancellation proposal to be valid.
	UpgradeCancelMinEpochDiff epochtime.EpochTime `json:"upgrade_cancel_min_epoch_diff,omitempty"`
}

// Event signifies a governance event, returned via GetEvents.
type Event struct {
	Height int64     `json:"height,omitempty"`
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	ProposalSubmitted *ProposalSubmittedEvent `json:"proposal_submitted,omitempty"`
	ProposalExecuted  *ProposalExecutedEvent  `json:"proposal_executed,omitempty"`
	ProposalFinalized *ProposalFinalizedEvent `json:"proposal_finalized,omitempty"`
	Vote              *VoteEvent              `json:"vote,omitempty"`
}

// ProposalSubmittedEvent is the event emitted when a new proposal is submitted.
type ProposalSubmittedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Submitter is the staking account address of the submitter.
	Submitter staking.Address `json:"submitter"`
}

// ProposalExecutedEvent is emitted when a proposal is executed.
type ProposalExecutedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
}

// ProposalFinalizedEvent is the event emitted when a proposal is finalized.
type ProposalFinalizedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// State is the new proposal state.
	State ProposalState `json:"state"`
}

// VoteEvent is the event emitted when a vote is cast.
type VoteEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Submitter is the staking account address of the vote submitter.
	Submitter staking.Address `json:"submitter"`
	// Vote is the cast vote.
	Vote Vote `json:"vote"`
}

// NewSubmitProposalTx creates a new submit proposal transaction.
func NewSubmitProposalTx(nonce uint64, fee *transaction.Fee, proposal *ProposalContent) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodSubmitProposal, proposal)
}

// NewCastVoteTx creates a new cast vote transaction.
func NewCastVoteTx(nonce uint64, fee *transaction.Fee, vote *ProposalVote) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodCastVote, vote)
}

const (
	// GasOpSubmitProposal is the gas operation identifier for submitting proposal.
	GasOpSubmitProposal transaction.Op = "submit_proposal"
	// GasOpCastVote is the gas operation identifier for casting vote.
	GasOpCastVote transaction.Op = "cast_vote"
)

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpSubmitProposal: 1000,
	GasOpCastVote:       1000,
}
