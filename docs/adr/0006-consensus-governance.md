# ADR 0006: Consensus Governance

## Changelog

- 2021-03-30: Update name of the CastVote method's body
- 2021-01-06: Update API to include Proposals() method
- 2020-12-08: Updates to match the actual implementation
- 2020-10-27: Voting period in epochs, min upgrade cancellation difference,
  failed proposal state
- 2020-10-16: Initial draft

## Status

Accepted

## Context

Currently the consensus layer does not contain any on-chain governance
mechanism so any network upgrades need to be carefully coordinated off-chain.
An on-chain governance mechanism would allow upgrades to be handled in a more
controlled (and automatable) manner without introducing the risk of corrupting
state.

## Decision

This proposal introduces a minimal on-chain governance mechanism where anyone
can submit governance proposals and the validators can vote where one base unit
of delegated stake counts as one vote.

The high-level overview is as follows:

- **A new governance API** is added to the consensus layer and its Tendermint
  based implementation. It supports transactions for submitting proposals and
  voting on proposals. It supports queries for listing current proposals and
  votes for any given proposal.

- **Two governance proposal kinds are supported**, a consensus layer upgrade
  proposal (where the content is basically the existing upgrade descriptor) and
  the cancellation of a pending upgrade.

A proposal is created through a _submit proposal_ transaction and requires a
minimum deposit (which is later refunded in case the proposal passes). Once a
proposal is successfully submitted the voting period starts. Entities that are
part of the validator set may cast votes for the proposal. After the voting
period completes, the votes are tallied and the proposal either passes or is
rejected.

In case the proposal passes, the actions specified in the content of the propsal
are executed. Currently the only actions are scheduling of an upgrade by
publishing an upgrade descriptor or cancelling a previously passed upgrade.

### State

#### Staking

This proposal adds the following consensus layer state in the staking module:

- **Governance deposits account balance (`0x59`)**, similar to the common pool.

#### Governance

This proposal adds the following consensus layer state in the governance module:

- **Next proposal identifier (`0x80`)**

  The next proposal identifier is stored as a CBOR-serialized `uint64`.

- **List of proposals (`0x81`)**

  Each proposal is stored under a separate storage key with the following key
  format:

  ```
  0x81 <proposal-id (uint64)>
  ```

  And CBOR-serialized value:

  ```golang
  // ProposalState is the state of the proposal.
  type ProposalState uint8

  const (
      StateActive   ProposalState = 1
      StatePassed   ProposalState = 2
      StateRejected ProposalState = 3
      StateFailed   ProposalState = 4
  )

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
  ```

- **List of active proposals (`0x82`)**

  Each active proposal (one that has not yet closed) is stored under a separate
  storage key with the following key format:

  ```
  0x82 <closes-at-epoch (uint64)> <proposal-id (uint64)>
  ```

  The value is empty as the proposal ID can be inferred from the key.

- **List of votes (`0x83`)**

  Each vote is stored under a separate storage key with the following key
  format:

  ```
  0x83 <proposal-id (uint64)> <voter-address (staking.Address)>
  ```

  And CBOR-serialized value:

  ```golang
  // Vote is a governance vote.
  type Vote uint8

  const (
      VoteYes     Vote = 1
      VoteNo      Vote = 2
      VoteAbstain Vote = 3
  )
  ```

- **List of pending upgrades (`0x84`)**

  Each pending upgrade is stored under a separate storage key with the following
  key format:

  ```
  0x84 <upgrade-epoch (uint64)> <proposal-id (uint64)>
  ```

  The value is empty as the proposal upgrade descriptor can be obtained via
  proposal that can be inferred from the key.

- **Parameters (`0x85`)**

  Governance consensus parameters.

  With CBOR-serialized value:

  ```golang
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

      // Quorum is he minimum percentage of voting power that needs to be cast on
      // a proposal for the result to be valid.
      Quorum uint8 `json:"quorum,omitempty"`

      // Threshold is the minimum percentage of VoteYes votes in order for a
      // proposal to be accepted.
      Threshold uint8 `json:"threshold,omitempty"`

      // UpgradeMinEpochDiff is the minimum number of epochs between the current
      // epoch and the proposed upgrade epoch for the upgrade proposal to be valid.
      // This is also the minimum number of epochs between two pending upgrades.
      UpgradeMinEpochDiff beacon.EpochTime `json:"upgrade_min_epoch_diff,omitempty"`

      // UpgradeCancelMinEpochDiff is the minimum number of epochs between the current
      // epoch and the proposed upgrade epoch for the upgrade cancellation proposal to be valid.
      UpgradeCancelMinEpochDiff beacon.EpochTime `json:"upgrade_cancel_min_epoch_diff,omitempty"`
  }
  ```

### Genesis Document

The genesis document needs to be updated to include a `governance` field with
any initial state (see [_State_]) and consensus parameters (see [_Consensus
Parameters_]) for the governance service.

[_State_]: #state
[_Consensus Parameters_]: #consensus-parameters

### Transaction Methods

This proposal adds the following transaction methods in the governance module:

#### Submit Proposal

Proposal submission enables a new consensus layer governance proposal to be
created.

**Method name:**

```
governance.SubmitProposal
```

**Body:**

```golang
// ProposalContent is a consensus layer governance proposal content.
type ProposalContent struct {
    Upgrade       *UpgradeProposal       `json:"upgrade,omitempty"`
    CancelUpgrade *CancelUpgradeProposal `json:"cancel_upgrade,omitempty"`
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
```

**Fields:**

- `upgrade` (optional) specifies an upgrade proposal.
- `cancel_upgrade` (optional) specifies an upgrade cancellation proposal.

Exactly one of the proposal kind fields needs to be non-nil, otherwise the
proposal is considered malformed.

Upon processing any proposal the following steps are first performed:

- The account indicated by the signer is loaded.

- If the account balance is less than `min_proposal_deposit`, the method call
  fails with `ErrInsufficientBalance`.

Upon processing an **`UpgradeProposal`** the following steps are then performed:

- The upgrade descriptor is checked for basic internal validity. If the check
  fails, the method call fails with `ErrInvalidArgument`.

- The upgrade descriptor's `epoch` field is compared with the current epoch. If
  the specified epoch is not at least `upgrade_min_epoch_diff` epochs ahead of
  the current epoch, the method call fails with `ErrUpgradeTooSoon`.

- The set of pending upgrades is checked to make sure that no upgrades are
  currently pending within `upgrade_min_epoch_diff` epochs of the upgrade
  descriptor's `epoch` field. If there is such an existing upgrade pending, the
  method call fails with `ErrUpgradeAlreadyPending`.

Upon processing a **`CancelUpgradeProposal`** the following steps are then
performed:

- The set of pending upgrades is checked to make sure that the given upgrade
  proposal is currently pending to be executed. If there is no such upgrade, the
  method call fails with `ErrNoSuchUpgrade`.

- The upgrade descriptor's `epoch` field is compared with the current epoch. If
  the specified epoch is not at least `upgrade_cancel_min_epoch_diff` epochs
  ahead of the current epoch, the method call fails with `ErrUpgradeTooSoon`.

Upon processing any proposal the following steps are then performed:

- The `min_proposal_deposit` base units are transferred from the signer's
  account to the governance service's _proposal deposit account_.

- The signer's account is saved.

- A new proposal is created and assigned an identifier.

- The corresponding `ProposalSubmittedEvent` is emitted with the following
  structure:

  ```golang
  type ProposalSubmittedEvent struct {
      // ID is the unique identifier of a proposal.
      ID uint64 `json:"id"`
      // Submitter is the staking account address of the submitter.
      Submitter staking.Address `json:"submitter"`
  }
  ```

- The corresponding `staking.TransferEvent` is emitted, indicating transfer from
  the submitter's account to the _proposal deposit account_.

#### Vote

Voting for submitted consensus layer governance proposals.

**Method name:**

```
governance.CastVote
```

**Body:**

```golang
type ProposalVote struct {
    // ID is the unique identifier of a proposal.
    ID uint64 `json:"id"`
    // Vote is the vote.
    Vote Vote `json:"vote"`
}
```

Upon processing a vote the following steps are performed:

- The entity descriptor corresponding to the transaction signer is fetched. In
  case no such entity exists, the method call fails with `ErrNotEligible`.

- It is checked whether any entity's nodes are in the current validator set. In
  case they are not, the method call fails with `ErrNotEligible`.

- The proposal identified by `id` is loaded. If the proposal does not exist,
  the method call fails with `ErrNoSuchProposal`.

- If the proposal's state is not `StateActive`, the method call fails with
  `ErrVotingIsClosed`.

- The vote is added to the list of votes. If the vote already exists, it is
  overwritten.

- The corresponding `VoteEvent` is emitted with the following structure:

  ```golang
  type VoteEvent struct {
      // ID is the unique identifier of a proposal.
      ID uint64 `json:"id"`
      // Submitter is the staking account address of the submitter.
      Submitter staking.Address `json:"submitter"`
      // Vote is the cast vote.
      Vote Vote `json:"vote"`
  }
  ```

### Queries

This proposal introduces the following query methods in the governance module:

```golang
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
}

// ProposalQuery is a proposal query.
type ProposalQuery struct {
    Height int64  `json:"height"`
    ID     uint64 `json:"id"`
}

// VoteEntry contains data about a cast vote.
type VoteEntry struct {
    Voter staking.Address `json:"voter"`
    Vote  Vote            `json:"vote"`
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
```

### Tallying

In `EndBlock` the list of active proposals is checked to see if there was an
epoch transition in this block. If there was, the following steps are performed
for each proposal that should be closed at the current epoch:

- A mapping of current validator entity addresses to their respective active
  escrow balances is prepared.

- A results mapping from `Vote` to number of votes is initialized in the
  proposal's `results` field.

- Votes from the list of votes for the given proposal are iterated and the
  address of each vote is looked up in the prepared entity address mapping. The
  corresponding number of votes (on the principle of 1 base unit equals one
  vote) are added to the results mapping based on the voted option. Any votes
  that are not from the current validator set are ignored and the
  `invalid_votes` field is incremented for each such vote.

- In case the percentage of votes relative to the total voting power is less
  than `quorum`, the proposal is rejected.

- In case the percentage of `VoteYes` votes relative to all valid votes is less
  than `threshold`, the proposal is rejected.

- Otherwise the proposal is passed.

- The proposal's status is changed to either `StatePassed` or `StateRejected`
  and the proposal is saved.

- The proposal is removed from the list of active proposals.

- In case the proposal has been passed, the proposal content is executed. If
  proposal execution fails, the proposal's state is changed to `StateFailed`.

- The corresponding `ProposalFinalizedEvent` is emitted with the following
  structure:

  ```golang
  type ProposalFinalizedEvent struct {
      // ID is the unique identifier of a proposal.
      ID uint64 `json:"id"`
      // State is the new proposal state.
      State ProposalState `json:"state"`
  }
  ```

- In case the proposal has been passed, the deposit is transferred back to the
  proposal submitter and a corresponding `staking.TransferEvent` is emitted,
  indicating transfer from the _proposal deposit account_ to the submitter's
  account.

- In case the proposal has been rejected, the deposit is transferred to the
  common pool and a corresponding `staking.TransferEvent` is emitted,
  indicating transfer from the _proposal deposit account_ to the common pool
  account.

### Proposal Content Execution

After any proposal is successfully executed the corresponding
`ProposalExecutedEvent` is emitted with the following structure:

```golang
type ProposalExecutedEvent struct {
    // ID is the unique identifier of a proposal.
    ID uint64 `json:"id"`
}
```

#### Upgrade Proposal

The set of pending upgrades is checked to make sure that no upgrades are
currently pending within `upgrade_min_epoch_diff` of the upgrade descriptor's
`epoch` field. If there is such an existing pending upgrade the upgrade proposal
execution fails.

When an upgrade proposal is executed, a new entry is added to the list of
pending upgrades using `epoch` as `<upgrade-epoch>`.

On each epoch transition (as part of `BeginBlock`) it is checked whether a
pending upgrade is scheduled for that epoch. In case it is and we are not
running the new version, the consensus layer will panic. Otherwise, the pending
upgrade proposal is removed.

#### Cancel Upgrade Proposal

When a cancel upgrade proposal is executed, the proposal identified by
`proposal_id` is looked up and removed from the list of pending upgrades. In
case the pending upgrade does not exist anymore, no action is performed.

### Consensus Parameters

This proposal introduces the following new consensus parameters in the
governance module:

- `gas_costs` (transaction.Costs) are the governance transaction gas costs.

- `min_proposal_deposit` (base units) specifies the number of base units that
  are deposited when creating a new proposal.

- `voting_period` (epochs) specifies the number of epochs after which the voting
  for a proposal is closed and the votes are tallied.

- `quorum` (uint8: \[0,100\]) specifies the minimum percentage of voting power
  that needs to be cast on a proposal for the result to be valid.

- `threshold` (uint8: \[0,100\]) specifies the minimum percentage of `VoteYes`
  votes in order for a proposal to be accepted.

- `upgrade_min_epoch_diff` (epochs) specifies the minimum number of epochs
  between the current epoch and the proposed upgrade epoch for the upgrade
  proposal to be valid. Additionally specifies the minimum number of epochs
  between two consecutive pending upgrades.

- `upgrade_cancel_min_epoch_diff` (epochs) specifies the minimum number of
  epochs between the current epoch and the proposed upgrade epoch for the
  upgrade cancellation proposal to be valid.

The following parameter sanity checks are introduced:

- Product of `quorum` and `threshold` must be 2/3+.

- `voting_period` must be less than `upgrade_min_epoch_diff` and
  `upgrade_cancel_min_epoch_diff`.

## Consequences

### Positive

- The consensus layer can coordinate on upgrades.

### Negative

### Neutral

## References
