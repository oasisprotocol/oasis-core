# ADR 0007: Improved Random Beacon

## Changelog

- 2020-10-22: Initial version

## Status

Proposed

## Context

> Any one who considers arithmetical methods of producing random digits
> is, of course, in a state of sin.
>
> --Dr. John von  Neumann

The existing random beacon used by Oasis Core, is largely a placeholder
implementation that naively uses the previous block's commit hash as the
entropy input.  As such it is clearly insecure as it is subject to
manipulation.

A better random beacon which is harder for an adversary to manipulate
is required to provide entropy for secure committee elections.

## Decision

At a high level, this ADR proposes implementing an on-chain random beacon
based on "SCRAPE: Scalabe Randomness Attested by Public Entities" by
Cascudo and David.  The new random beacon will use a commit-reveal scheme
backed by a PVSS scheme so that as long as the threshold of participants
is met, and one participant is honest, secure entropy will be generated.

Note: This document assumes the reader understands SCRAPE. Details
regarding the underlying SCRAPE implementation are omitted for brevity.

### Node Descriptor

The node descriptor of each node will be extended to include the following
datastructure.

```golang
type Node struct {
  // ... existing fields omitted ...

  // Beacon contains information for this node's participation
  // in the random beacon protocol.
  //
  // TODO: This is optional for now, make mandatory once enough
  // nodes provide this field.
  Beacon *BeaconInfo `json:"beacon,omitempty"`
}

// BeaconInfo contains information for this node's participation in
// the random beacon protocol.
type BeaconInfo struct {
  // Point is the elliptic curve point used for the PVSS algorithm.
  Point scrape.Point `json:"point"`
}
```

Each node will generate and maintain a long term elliptic curve point
and scalar pair (public/private key pair), the point (public key) of
which will be included in the node descriptor.

For the purposes of the initial implementation, the curve will be P-256.

### Consensus Parameters

The beacon module will have the following consensus parameters that
control behavior.

```golang
type SCRAPEParameters struct {
  Participants  uint64 `json:"participants"`
  Threshold     uint64 `json:"threshold"`
  PVSSThreshold uint64 `json:"pvss_threshold"`

  CommitInterval  int64 `json:"commit_interval"`
  RevealInterval  int64 `json:"reveal_interval"`
  TransitionDelay int64 `json:"transition_delay"`
}
```

Fields:

- `Participants` - The number of participants to be selected for each
  beacon generation protocol round.

- `Threshold` - The minimum number of participants which must
  successfully contribute entropy for the final output to be
  considered valid.

- `PVSSThreshold` - The minimum number of participants that are
  required to reconstruct a PVSS secret from the corresponding
  decrypted shares (Note: This usually should just be set to
  `Threshold`).

- `CommitInterval` - The duration of the Commit phase, in blocks.

- `RevealInterval` - The duration of the Reveal phase, in blocks.

- `TransitionDelay` - The duration of the post Reveal phase delay, in blocks.

### Consensus State and Events

The on-chain beacon will maintain and make available the following consensus
state.

```golang
// RoundState is a SCRAPE round state.
type RoundState uint8

const (
  StateInvalid  RoundState = 0
  StateCommit   RoundState = 1
  StateReveal   RoundState = 2
  StateComplete RoundState = 3
)

// SCRAPEState is the SCRAPE backend state.
type SCRAPEState struct {
  Height int64 `json:"height,omitempty"`

  Epoch EpochTime  `json:"epoch,omitempty"`
  Round uint64     `json:"round,omitempty"`
  State RoundState `json:"state,omitempty"`

  Instance     *scrape.Instance      `json:"instance,omitempty"`
  Participants []signature.PublicKey `json:"participants,omitempty"`
  Entropy      []byte                `json:"entropy,omitempty"`

  BadParticipants map[signature.PublicKey]bool `json:"bad_participants,omitempty"`

  CommitDeadline   int64 `json:"commit_deadline,omitempty"`
  RevealDeadline   int64 `json:"reveal_deadline,omitempty"`
  TransitionHeight int64 `json:"transition_height,omitempty"`

  RuntimeDisableHeight int64 `json:"runtime_disable_height,omitempty"`
}
```

Fields:

- `Height` - The block height at which the last event was emitted.

- `Epoch` - The epoch in which this beacon is being generated.

- `Round` - The epoch beacon generation round.

- `State` - The beacon generation step (commit/reveal/complete).

- `Instance` - The SCRAPE protocol state (encrypted/decrypted shares of
  all participants).

- `Participants` - The node IDs of the nodes selected to participate
  in this beacon generation round.

- `Entropy` - The final raw entropy, if any.

- `BadParticipants` - A map of nodes that were selected, but have failed
  to execute the protocol correctly.

- `CommitDeadline` - The height in blocks by which participants must
  submit their encrypted shares.

- `RevealDeadline` - The height in blocks by which participants must
  submit their decrypted shares.

- `TransitionHeight` - The height at which the epoch will transition
  assuming this round completes successfully.

- `RuntimeDisableHeight` - The height at which, upon protocol failure,
  runtime transactions will be disabled.  This height will be set to
  the transition height of the 0th round.

Upon transition to a next step of the protocol, the on-chain beacon will
emit the following event.

```golang
// SCRAPEEvent is a SCRAPE backend event.
type SCRAPEEvent struct {
  Height int64 `json:"height,omitempty"`

  Epoch EpochTime  `json:"epoch,omitempty"`
  Round uint64     `json:"round,omitempty"`
  State RoundState `json:"state,omitempty"`

  Participants []signature.PublicKey `json:"participants,omitempty"`
}
```

Field definitions are identical to that of those in the `SCRAPEState`
datastructure.

## Transactions

Participating nodes will submit the following transactions when required,
signed by the node identity key.

```golang
var (
  // MethodSCRAPECommit is the method name for a SCRAPE commitment.
  MethodSCRAPECommit = transaction.NewMethodName(ModuleName, "SCRAPECommit", SCRAPECommit{})

  // MethodSCRAPEReveal is the method name for a SCRAPE reveal.
  MethodSCRAPEReveal = transaction.NewMethodName(ModuleName, "SCRAPEReveal", SCRAPEReveal{})
)

// SCRAPECommit is a SCRAPE commitment transaction payload.
type SCRAPECommit struct {
  Epoch EpochTime `json:"epoch"`
  Round uint64    `json:"round"`

  Commit *scrape.Commit `json:"commit,omitempty"`
}

// SCRAPEReveal is a SCRAPE reveal transaction payload.
type SCRAPEReveal struct {
  Epoch EpochTime `json:"epoch"`
  Round uint64    `json:"round"`

  Reveal *scrape.Reveal `json:"reveal,omitempty"`
}
```

Fields:

- `Epoch` - The epoch in which the transaction is applicable.

- `Round` - The epoch beacon generation round for the transaction.

- `Commit` - The SCRAPE commit consisting of PVSS shares encrypted to
  every participant.

- `Reveal` - The SCRAPE reveal consisting of the decrypted result of
  PVSS shares received from every participant.

### Beacon Generation

The beacon generation process is split into three sequential stages,
roughly corresponding to the steps in the SCRAPE protocol.  Any failures
in the Commit and Reveal phases result in a failed protocol round, and
the generation process will restart after disqualifying participants who
have induced the failure.

#### Commit Phase

Upon epoch transition or a prior failed round the commit phase is initiated
the consensus application will select  `Particpants` nodes from the current
validator set (in order of decending stake) to serve as entropy contributors.

The `SCRAPEState` structure is (re)-initialized, and a `SCRAPEEvent` is
broadcast to signal to the participants that they should generate and
submit their encrypted shares via a `SCRAPECommit` transaction.

Each commit phase lasts exactly `CommitInterval` blocks, at the end of which,
the round will be closed to further commits.

At the end of the commit phase, the SCRAPE protocol state is evaluated
to ensure that `Threshold`/`PVSSThreshold` nodes have published encrypted
shares, and if an insufficient number of nodes have published in either
case, the round is considered to have failed.

The following behaviors are currently candidates for a node being marked
as malicious/non-particpatory (`BadParticipant`) and subject to exclusion
from future rounds and slashing.

- Not submitting a commitment.

- Malformed commitments (corrupted/fails to validate/etc).

- Attempting to alter an existing commitment for a given Epoch/Round.

#### Reveal Phase

When the `CommitInterval` has passed, assuming that a sufficient number of
commits have been received, the consensus application transitions into the
reveal phase by updating the `SCRAPEState` structure and broadcasting a
`SCRAPEEvent` to signal to the participants that they should reveal the
decrypted values of the encrypted shares received from other participants
via a `SCRAPEReveal` transaction.

Each reveal phase lasts exactly `RevealInterval` blocks, at the end of which,
the round will be closed to further reveals.

At the end of the reveal phase, the SCRAPE protocol state is evaluated to
ensure that `Threshold`/`PVSSThreshold` nodes have published decrypted
shares, and if an insufficient number of nodes have published in either
case, the round is considered to have failed.

The following behaviors are currently candidates for a node being marked
as malicious/non-participatory (`BadParticipant`) and subject to exclusion
from future rounds and slashing.

- Not submitting a reveal.

- Malformed commitments (corrupted/fails to validate/etc).

- Attempting to alter an existing reveal for a given Epoch/Round.

Note: It is possible for anybody who can observe consensus state to derive
the entropy the moment a threshold number of `SCRAPEReveal` transactions
have been processed.  Therefore the reveal phase should be a small fraction
of the desired epoch as it is possible to derive the results of the
committee elections for the next epoch mid-reveal phase.

#### Complete (Transition Wait) Phase

When the `RevealInterval` has passed, assuming that a sufficient number
of reveals have been received, the consensus application recovers the
final entropy output (the hash of the secret shared by each participant)
and transitions into the complete (transition wait) phase by updating the
`SCRAPEState` structure and broadcasting a `SCRAPEEvent` to signal to
participants the completion of the round.

No meaningful protocol activity happens one a round has successfully
completed, beyond the scheduling of the next epoch transition.

### Misc. Changes/Notes

Nodes MUST not be slashed for non-participation if they have not had
the opportunity to propose any blocks during the relevant interval.

Processing commitments and reveals is currently rather CPU intensive
and thus each block SHOULD only contain one of each to prevent the
consesus from stalling.

To thwart attempts to manipulate committee placement by virute of the
fact that it is possible to observe the entropy used for elections early
nodes that register between the completion of the final commit phase and
the epoch transition in any given epoch MUST be excluded from committee
eligibility.

## Consequences

### Positive

- The random beacon output is unbaised, provided that at least one
  participant is honest.

- The amount of consensus state required is relatively small.

- All protocol messages and steps can be verified on-chain, and misbehavior
  can be attributed.

- The final output can be generated on-chain.

### Negative

- Epoch intervals are theoretically variable under this proposal, as the
  beacon generation needs to be re-ran with new participants upon failure.

- A new failure mode is introduced at the consensus layer, where the
  beacon generation protocol exhausts eligible participants.

- Without using pairing based cryptography, the number of participants
  in the beacon generation is limited to a small subset of the anticipated
  active validator set.

- There is a time window where the next beacon can be derived by anyone
  with access to the consensus state before the epoch transition actually
  happens.  This should be mitigated by having a relatively short reveal
  period.

- The commit and reveal steps of the protocol are rather slow, especially
  as the number of participants increases.

### Neutral

- Due to performance reasons, the curve used by the PVSS scheme will
  be P-256 instead of Ed25519.  The point and scalar pairs that each
  node generates on this curve are exclusively for use in the random
  beacon protocol and are not used anywhere else.

## References

<!-- markdownlint-disable line-length -->
- [SCRAPE: SCalabe Randomness Attested by Public Entities](https://eprint.iacr.org/2017/216.pdf)
- [oasis-core#3180](https://github.com/oasisprotocol/oasis-core/pull/3180)
<!-- markdownlint-enable line-length -->