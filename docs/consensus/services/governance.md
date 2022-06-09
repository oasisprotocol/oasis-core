# Governance

The governance service is responsible for providing an on-chain governance
mechanism.

The service interface definition lives in [`go/governance/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation] and the [governance ADR
specification].

<!-- markdownlint-disable line-length -->
[`go/governance/api`]:
  https://github.com/oasisprotocol/oasis-core/tree/master/go/governance/api
[consensus service API documentation]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/governance/api?tab=doc
[governance ADR specification]:
  https://github.com/oasisprotocol/adrs/blob/main/0006-consensus-governance.md
<!-- markdownlint-enable line-length -->

## Methods

The following sections describe the methods supported by the consensus
governance service.

### Submit Proposal

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

### Vote

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

## Events

### Proposal Submitted Event

**Body:**

```golang
type ProposalSubmittedEvent {
    // ID is the unique identifier of a proposal.
    ID uint64 `json:"id"`
    // Submitter is the staking account address of the submitter.
    Submitter staking.Address `json:"submitter"`
}
```

Emitted for every submitted proposal.

### Proposal Finalized Event

**Body:**

```golang
type ProposalFinalizedEvent struct {
    // ID is the unique identifier of a proposal.
    ID uint64 `json:"id"`
    // State is the new proposal state.
   State ProposalState `json:"state"`
}
```

Emitted when a proposal is finalized.

### Proposal Executed Event

**Body:**

```golang
type ProposalExecutedEvent {
    // ID is the unique identifier of a proposal.
    ID uint64 `json:"id"`
}
```

Emitted when a passed proposal is executed.

### Vote Event

**Body:**

```golang
type VoteEvent {
    // ID is the unique identifier of a proposal.
    ID uint64 `json:"id"`
    // Submitter is the staking account address of the vote submitter.
    Submitter staking.Address `json:"submitter"`
    // Vote is the cast vote.
    Vote Vote `json:"vote"`
}
```

Emitted when a vote is cast.

## Consensus Parameters

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

## Test Vectors

To generate test vectors for various governance [transactions], run:

```bash
make -C go governance/gen_vectors
```

For more information about the structure of the test vectors see the section
on [Transaction Test Vectors].

[transactions]: ../transactions.md
[Transaction Test Vectors]: ../test-vectors.md
