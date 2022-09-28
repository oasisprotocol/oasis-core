// Package api implements the governance APIs.
package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// ModuleName is a unique module name for the governance backend.
const ModuleName = "governance"

// ProposalContentInvalidText is the textual representation of an invalid
// ProposalContent.
const ProposalContentInvalidText = "(invalid)"

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

	_ prettyprint.PrettyPrinter = (*ProposalContent)(nil)
	_ prettyprint.PrettyPrinter = (*UpgradeProposal)(nil)
	_ prettyprint.PrettyPrinter = (*CancelUpgradeProposal)(nil)
	_ prettyprint.PrettyPrinter = (*ChangeParametersProposal)(nil)
	_ prettyprint.PrettyPrinter = (*ProposalVote)(nil)
)

// ProposalContent is a consensus layer governance proposal content.
type ProposalContent struct {
	Upgrade          *UpgradeProposal          `json:"upgrade,omitempty"`
	CancelUpgrade    *CancelUpgradeProposal    `json:"cancel_upgrade,omitempty"`
	ChangeParameters *ChangeParametersProposal `json:"change_parameters,omitempty"`
}

// ValidateBasic performs basic proposal content validity checks.
func (p *ProposalContent) ValidateBasic() error {
	numProposals := 0
	values := reflect.ValueOf(*p)
	for i := 0; i < values.NumField(); i++ {
		if !values.Field(i).IsNil() {
			numProposals++
		}
	}

	switch {
	case numProposals > 1:
		return fmt.Errorf("proposal content has multiple fields set")
	case p.Upgrade != nil:
		if err := p.Upgrade.ValidateBasic(); err != nil {
			return fmt.Errorf("upgrade proposal validation failed: %w", err)
		}
	case p.CancelUpgrade != nil:
		// No validation at this time.
	case p.ChangeParameters != nil:
		if err := p.ChangeParameters.ValidateBasic(); err != nil {
			return fmt.Errorf("change parameters proposal validation failed: %w", err)
		}
	default:
		return fmt.Errorf("proposal content has no fields set")
	}

	return nil
}

// Equals checks if proposal contents are equal.
//
// Note: this assumes valid proposals where each proposals will have
// exactly one field set.
func (p *ProposalContent) Equals(other *ProposalContent) bool {
	if p == other {
		return true
	}
	if p == nil || other == nil {
		return false
	}
	if !p.Upgrade.Equals(other.Upgrade) {
		return false
	}
	if !p.CancelUpgrade.Equals(other.CancelUpgrade) {
		return false
	}
	if !p.ChangeParameters.Equals(other.ChangeParameters) {
		return false
	}
	return true
}

// PrettyPrint writes a pretty-printed representation of ProposalContent to the
// given writer.
func (p ProposalContent) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	switch {
	case p.Upgrade != nil && p.CancelUpgrade == nil:
		fmt.Fprintf(w, "%sUpgrade:\n", prefix)
		p.Upgrade.PrettyPrint(ctx, prefix+"  ", w)
	case p.CancelUpgrade != nil && p.Upgrade == nil:
		fmt.Fprintf(w, "%sCancel Upgrade:\n", prefix)
		p.CancelUpgrade.PrettyPrint(ctx, prefix+"  ", w)
	default:
		fmt.Fprintf(w, "%s%s\n", prefix, ProposalContentInvalidText)
	}
}

// PrettyType returns a representation of ProposalContent that can be used for
// pretty printing.
func (p ProposalContent) PrettyType() (interface{}, error) {
	return p, nil
}

// UpgradeProposal is an upgrade proposal.
type UpgradeProposal struct {
	upgrade.Descriptor
}

// Equals checks if upgrade proposals are equal.
func (u *UpgradeProposal) Equals(other *UpgradeProposal) bool {
	if u == other {
		return true
	}
	if u == nil || other == nil {
		return false
	}
	if !u.Descriptor.Equals(&other.Descriptor) {
		return false
	}
	return true
}

// PrettyPrint writes a pretty-printed representation of UpgradeProposal to the
// given writer.
func (u UpgradeProposal) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	u.Descriptor.PrettyPrint(ctx, prefix, w)
}

// PrettyType returns a representation of UpgradeProposal that can be used for
// pretty printing.
func (u UpgradeProposal) PrettyType() (interface{}, error) {
	return u, nil
}

// CancelUpgradeProposal is an upgrade cancellation proposal.
type CancelUpgradeProposal struct {
	// ProposalID is the identifier of the pending upgrade proposal.
	ProposalID uint64 `json:"proposal_id"`
}

// Equals checks if cancel upgrade proposals are equal.
func (cu *CancelUpgradeProposal) Equals(other *CancelUpgradeProposal) bool {
	if cu == other {
		return true
	}
	if cu == nil || other == nil {
		return false
	}
	if cu.ProposalID != other.ProposalID {
		return false
	}
	return true
}

// PrettyPrint writes a pretty-printed representation of CancelUpgradeProposal
// to the given writer.
func (cu CancelUpgradeProposal) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sProposal ID: %d\n", prefix, cu.ProposalID)
}

// PrettyType returns a representation of CancelUpgradeProposal that can be used
// for pretty printing.
func (cu CancelUpgradeProposal) PrettyType() (interface{}, error) {
	return cu, nil
}

// ChangeParametersProposal is a consensus change parameters proposal.
type ChangeParametersProposal struct {
	// Module identifies the consensus backend module to which changes should be applied.
	Module string `json:"module"`
	// Changes are consensus parameter changes that should be applied to the module.
	Changes cbor.RawMessage `json:"changes"`
}

// Equals checks if change parameters proposals are equal.
func (p *ChangeParametersProposal) Equals(other *ChangeParametersProposal) bool {
	if p == other {
		return true
	}
	if p == nil || other == nil {
		return false
	}
	if p.Module != other.Module {
		return false
	}
	if !bytes.Equal(p.Changes, other.Changes) {
		return false
	}
	return true
}

// PrettyPrint writes a pretty-printed representation of ChangeParametersProposal to the given
// writer.
func (p *ChangeParametersProposal) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sModule: %s\n", prefix, p.Module)
	fmt.Fprintf(w, "%sChanges: %v\n", prefix, p.Changes)
}

// PrettyType returns a representation of ChangeParametersProposal that can be used for pretty
// printing.
func (p *ChangeParametersProposal) PrettyType() (interface{}, error) {
	return p, nil
}

// ValidateBasic performs a basic validation on the change parameters proposal.
func (p *ChangeParametersProposal) ValidateBasic() error {
	if len(p.Module) == 0 {
		return fmt.Errorf("invalid module name: name should not be empty")
	}
	if len(p.Changes) == 0 {
		return fmt.Errorf("invalid parameter changes: changes should not be empty")
	}
	return nil
}

// ProposalVote is a vote for a proposal.
type ProposalVote struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Vote is the vote.
	Vote Vote `json:"vote"`
}

// PrettyPrint writes a pretty-printed representation of ProposalVote to the
// given writer.
func (pv ProposalVote) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sProposal ID: %d\n", prefix, pv.ID)
	fmt.Fprintf(w, "%sVote:        %s\n", prefix, pv.Vote)
}

// PrettyType returns a representation of ProposalVote that can be used for
// pretty printing.
func (pv ProposalVote) PrettyType() (interface{}, error) {
	return pv, nil
}

// Backend is a governance implementation.
type Backend interface {
	// ActiveProposals returns a list of all proposals that have not yet closed.
	ActiveProposals(ctx context.Context, height int64) ([]*Proposal, error)

	// Proposals returns a list of all proposals.
	Proposals(ctx context.Context, height int64) ([]*Proposal, error)

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
	VotingPeriod beacon.EpochTime `json:"voting_period,omitempty"`

	// StakeThreshold is the minimum percentage of VoteYes votes in terms
	// of total voting power when the proposal expires in order for a
	// proposal to be accepted.  This value has a lower bound of 67.
	StakeThreshold uint8 `json:"stake_threshold,omitempty"`

	// UpgradeMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade proposal to be valid.
	// This is also the minimum number of epochs between two pending upgrades.
	UpgradeMinEpochDiff beacon.EpochTime `json:"upgrade_min_epoch_diff,omitempty"`

	// UpgradeCancelMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade cancellation proposal to be valid.
	UpgradeCancelMinEpochDiff beacon.EpochTime `json:"upgrade_cancel_min_epoch_diff,omitempty"`

	// EnableChangeParametersProposal is true iff change parameters proposals are allowed.
	EnableChangeParametersProposal bool `json:"enable_change_parameters_proposal,omitempty"`
}

// ConsensusParameterChanges are allowed governance consensus parameter changes.
type ConsensusParameterChanges struct {
	// GasCosts are the new gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MinProposalDeposit is the new minimal proposal deposit.
	MinProposalDeposit *quantity.Quantity `json:"min_proposal_deposit,omitempty"`

	// VotingPeriod is the new voting period.
	VotingPeriod *beacon.EpochTime `json:"voting_period,omitempty"`

	// StakeThreshold is the new stake threshold.
	StakeThreshold *uint8 `json:"stake_threshold,omitempty"`

	// UpgradeMinEpochDiff is the new minimal epoch difference between two pending upgrades.
	UpgradeMinEpochDiff *beacon.EpochTime `json:"upgrade_min_epoch_diff,omitempty"`

	// UpgradeCancelMinEpochDiff is the new minimal epoch difference for the upgrade cancellation
	// proposal to be valid.
	UpgradeCancelMinEpochDiff *beacon.EpochTime `json:"upgrade_cancel_min_epoch_diff,omitempty"`

	// EnableChangeParametersProposal is the new enable change parameters proposal flag.
	EnableChangeParametersProposal *bool `json:"enable_change_parameters_proposal,omitempty"`
}

// Apply applies changes to the given consensus parameters.
func (c *ConsensusParameterChanges) Apply(params *ConsensusParameters) error {
	if c.GasCosts != nil {
		params.GasCosts = c.GasCosts
	}
	if c.MinProposalDeposit != nil {
		params.MinProposalDeposit = *c.MinProposalDeposit
	}
	if c.VotingPeriod != nil {
		params.VotingPeriod = *c.VotingPeriod
	}
	if c.StakeThreshold != nil {
		params.StakeThreshold = *c.StakeThreshold
	}
	if c.UpgradeMinEpochDiff != nil {
		params.UpgradeMinEpochDiff = *c.UpgradeMinEpochDiff
	}
	if c.UpgradeCancelMinEpochDiff != nil {
		params.UpgradeCancelMinEpochDiff = *c.UpgradeCancelMinEpochDiff
	}
	if c.EnableChangeParametersProposal != nil {
		params.EnableChangeParametersProposal = *c.EnableChangeParametersProposal
	}
	return nil
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

// EventKind returns a string representation of this event's kind.
func (e *ProposalSubmittedEvent) EventKind() string {
	return "proposal_submitted"
}

// ProposalExecutedEvent is emitted when a proposal is executed.
type ProposalExecutedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
}

// EventKind returns a string representation of this event's kind.
func (e *ProposalExecutedEvent) EventKind() string {
	return "proposal_executed"
}

// ProposalFinalizedEvent is the event emitted when a proposal is finalized.
type ProposalFinalizedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// State is the new proposal state.
	State ProposalState `json:"state"`
}

// EventKind returns a string representation of this event's kind.
func (e *ProposalFinalizedEvent) EventKind() string {
	return "proposal_finalized"
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

// EventKind returns a string representation of this event's kind.
func (e *VoteEvent) EventKind() string {
	return "vote"
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
