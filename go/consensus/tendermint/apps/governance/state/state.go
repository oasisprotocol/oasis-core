package state

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

var (
	// nextProposalIdentifierKeyFmt is the key format used for the storing the next proposal identifier.
	//
	// Value is a CBOR-serialized uint64.
	nextProposalIdentifierKeyFmt = keyformat.New(0x80)

	// proposalsKeyFmt is the key format used for the storing existing proposals.
	//
	// Key format is: 0x81 <proposal-id (uint64)>.
	// Value is a CBOR-serialized governance.Proposal.
	proposalsKeyFmt = keyformat.New(0x81, uint64(0))

	// activeProposalsKeyFmt is the key format used for the storing active proposals.
	//
	// Key format is: 0x82 <closes-at-epoch (uint64)> <proposal-id (uint64)>.
	activeProposalsKeyFmt = keyformat.New(0x82, uint64(0), uint64(0))

	// votesKeyFmt is the key format used for the storing existing votes for proposals.
	//
	// Key format is: 0x83 <proposal-id (uint64)> <voter-address (staking.Address)>.
	// Value is a CBOR-serialized governance.Vote.
	votesKeyFmt = keyformat.New(0x83, uint64(0), &staking.Address{})

	// pendingUpgradesKeyFmt is the key format used for the storing pending upgrades.
	//
	// Key format is: 0x84 <upgrade-epoch (uint64)> <proposal-id (uint64)>.
	pendingUpgradesKeyFmt = keyformat.New(0x84, uint64(0), uint64(0))

	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Key format is: 0x85.
	// Value is CBOR-serialized governance.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x85)
)

// ImmutableState is the immutable consensus state wrapper.
type ImmutableState struct {
	is *api.ImmutableState
}

// NewImmutableState returns immutable governance state.
func NewImmutableState(ctx context.Context, state api.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := api.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// NextProposalIdentifier looks up the next proposal identifier.
func (s *ImmutableState) NextProposalIdentifier(ctx context.Context) (uint64, error) {
	keyRaw, err := s.is.Get(ctx, nextProposalIdentifierKeyFmt.Encode())
	if err != nil {
		return 0, api.UnavailableStateError(err)
	}
	if keyRaw == nil {
		return 0, nil
	}

	var key uint64
	if err := cbor.Unmarshal(keyRaw, &key); err != nil {
		return 0, api.UnavailableStateError(err)
	}
	return key, nil
}

// Proposals looks up all proposals.
func (s *ImmutableState) Proposals(ctx context.Context) ([]*governance.Proposal, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var proposals []*governance.Proposal
	for it.Seek(proposalsKeyFmt.Encode()); it.Valid(); it.Next() {
		var proposalID uint64
		if !proposalsKeyFmt.Decode(it.Key(), &proposalID) {
			break
		}
		// Load the proposal.
		proposal, err := s.Proposal(ctx, proposalID)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}

// ActiveProposals looks up all active proposals.
func (s *ImmutableState) ActiveProposals(ctx context.Context) ([]*governance.Proposal, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var proposals []*governance.Proposal
	for it.Seek(activeProposalsKeyFmt.Encode()); it.Valid(); it.Next() {
		var epoch uint64
		var proposalID uint64
		if !activeProposalsKeyFmt.Decode(it.Key(), &epoch, &proposalID) {
			break
		}
		// Load the proposal.
		proposal, err := s.Proposal(ctx, proposalID)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}

func (s *ImmutableState) getProposalRaw(ctx context.Context, id uint64) ([]byte, error) {
	data, err := s.is.Get(ctx, proposalsKeyFmt.Encode(&id))
	return data, api.UnavailableStateError(err)
}

// Proposal looks up a proposal by its identifier.
func (s *ImmutableState) Proposal(ctx context.Context, id uint64) (*governance.Proposal, error) {
	proposalRaw, err := s.getProposalRaw(ctx, id)
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if proposalRaw == nil {
		return nil, governance.ErrNoSuchProposal
	}
	var proposal governance.Proposal
	if err = cbor.Unmarshal(proposalRaw, &proposal); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &proposal, nil
}

// Votes looks up all votes for a proposal.
func (s *ImmutableState) Votes(ctx context.Context, id uint64) ([]*governance.VoteEntry, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var voteEntries []*governance.VoteEntry
	for it.Seek(votesKeyFmt.Encode(id)); it.Valid(); it.Next() {
		var proposalID uint64
		var voter staking.Address
		if !votesKeyFmt.Decode(it.Key(), &proposalID, &voter) {
			break
		}
		if proposalID != id {
			break
		}
		var vote governance.Vote
		if err := cbor.Unmarshal(it.Value(), &vote); err != nil {
			return nil, api.UnavailableStateError(err)
		}
		voteEntries = append(voteEntries, &governance.VoteEntry{
			Voter: voter,
			Vote:  vote,
		})

	}

	return voteEntries, nil
}

func (s *ImmutableState) isProposalPendingUpgrade(ctx context.Context, proposal *governance.Proposal) (bool, error) {
	if proposal.Content.Upgrade == nil {
		return false, nil
	}
	data, err := s.is.Get(ctx, pendingUpgradesKeyFmt.Encode(uint64(proposal.Content.Upgrade.Epoch), proposal.ID))
	return data != nil, err
}

// PendingUpgradeProposal looks up a pending upgrade proposal by its identifier.
func (s *ImmutableState) PendingUpgradeProposal(ctx context.Context, id uint64) (*governance.UpgradeProposal, error) {
	proposalRaw, err := s.getProposalRaw(ctx, id)
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if proposalRaw == nil {
		return nil, governance.ErrNoSuchProposal
	}
	var proposal governance.Proposal
	if err = cbor.Unmarshal(proposalRaw, &proposal); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	b, err := s.isProposalPendingUpgrade(ctx, &proposal)
	if err != nil {
		return nil, err
	}
	if !b {
		return nil, governance.ErrNoSuchUpgrade
	}

	return proposal.Content.Upgrade, nil
}

// PendingUpgrades looks up all pending upgrades.
func (s *ImmutableState) PendingUpgrades(ctx context.Context) ([]*upgrade.Descriptor, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var pendingUpgrades []*upgrade.Descriptor
	for it.Seek(pendingUpgradesKeyFmt.Encode()); it.Valid(); it.Next() {
		var epoch uint64
		var proposalID uint64
		if !pendingUpgradesKeyFmt.Decode(it.Key(), &epoch, &proposalID) {
			break
		}
		// Load the proposal.
		proposal, err := s.Proposal(ctx, proposalID)
		if err != nil {
			return nil, err
		}
		if proposal.Content.Upgrade == nil {
			return nil, api.UnavailableStateError(fmt.Errorf("tendermint/governance: pending upgrade with missing upgrade descriptor"))
		}
		pendingUpgrades = append(pendingUpgrades, &proposal.Content.Upgrade.Descriptor)
	}

	return pendingUpgrades, nil
}

// ConsensusParameters returns the governance consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*governance.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("tendermint/governance: expected consensus parameters to be present in app state")
	}

	var params governance.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &params, nil
}

// MutableState is a mutable consensus state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// NewMutableState creates a new mutable governance state.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&api.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}

// SetNextProposalIdentifier sets the next proposal identifier.
func (s *MutableState) SetNextProposalIdentifier(ctx context.Context, id uint64) error {
	err := s.ms.Insert(ctx, nextProposalIdentifierKeyFmt.Encode(), cbor.Marshal(id))
	return api.UnavailableStateError(err)
}

// SetActiveProposal sets active proposal.
func (s *MutableState) SetActiveProposal(ctx context.Context, proposal *governance.Proposal) error {
	// Save the proposal.
	if err := s.ms.Insert(ctx, proposalsKeyFmt.Encode(proposal.ID), cbor.Marshal(proposal)); err != nil {
		return api.UnavailableStateError(err)
	}
	// Add proposal to the active proposals list.
	err := s.ms.Insert(ctx, activeProposalsKeyFmt.Encode(uint64(proposal.ClosesAt), proposal.ID), []byte(""))
	return api.UnavailableStateError(err)
}

// RemoveActiveProposal removes an active proposal.
func (s *MutableState) RemoveActiveProposal(ctx context.Context, proposal *governance.Proposal) error {
	// Remove proposal from the active proposals list.
	err := s.ms.Remove(ctx, activeProposalsKeyFmt.Encode(uint64(proposal.ClosesAt), proposal.ID))
	return api.UnavailableStateError(err)
}

// SetProposal sets a proposal.
func (s *MutableState) SetProposal(ctx context.Context, proposal *governance.Proposal) error {
	// Save the proposal.
	err := s.ms.Insert(ctx, proposalsKeyFmt.Encode(proposal.ID), cbor.Marshal(proposal))
	return api.UnavailableStateError(err)
}

// SetPendingUpgrade sets a pending upgrade.
func (s *MutableState) SetPendingUpgrade(ctx context.Context, proposalID uint64, upgrade *upgrade.Descriptor) error {
	// Save the upgrade descriptor.
	err := s.ms.Insert(ctx, pendingUpgradesKeyFmt.Encode(uint64(upgrade.Epoch), proposalID), []byte(""))
	return api.UnavailableStateError(err)
}

// RemovePendingUpgrade removes a pending upgrade.
func (s *MutableState) RemovePendingUpgrade(ctx context.Context, epoch beacon.EpochTime, proposalID uint64) error {
	// Remove proposal from the active proposals list.
	err := s.ms.Remove(ctx, pendingUpgradesKeyFmt.Encode(uint64(epoch), proposalID))
	return api.UnavailableStateError(err)
}

// RemovePendingUpgradesForEpoch removes pending upgrades for epoch.
func (s *MutableState) RemovePendingUpgradesForEpoch(ctx context.Context, epoch beacon.EpochTime) error {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var upgradeProposalIDs []uint64
	for it.Seek(pendingUpgradesKeyFmt.Encode(uint64(epoch))); it.Valid(); it.Next() {
		var epocht uint64
		var proposalID uint64
		if !pendingUpgradesKeyFmt.Decode(it.Key(), &epocht, &proposalID) {
			break
		}
		if epocht != uint64(epoch) {
			break
		}
		upgradeProposalIDs = append(upgradeProposalIDs, proposalID)
	}

	for _, proposalID := range upgradeProposalIDs {
		if err := s.ms.Remove(ctx, pendingUpgradesKeyFmt.Encode(uint64(epoch), proposalID)); err != nil {
			return api.UnavailableStateError(err)
		}
	}

	return nil
}

// SetVote sets a vote for a proposal.
func (s *MutableState) SetVote(
	ctx context.Context,
	proposalID uint64,
	voter staking.Address,
	vote governance.Vote,
) error {
	err := s.ms.Insert(ctx, votesKeyFmt.Encode(proposalID, voter), cbor.Marshal(vote))
	return api.UnavailableStateError(err)
}

// SetConsensusParameters sets governance consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *governance.ConsensusParameters) error {
	if err := s.is.CheckContextMode(ctx, []api.ContextMode{api.ContextInitChain, api.ContextEndBlock}); err != nil {
		return err
	}
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return api.UnavailableStateError(err)
}
