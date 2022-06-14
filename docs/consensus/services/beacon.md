# Random Beacon

The random beacon service is responsible for providing a source of unbiased
randomness on each epoch. It uses a commit-reveal scheme backed by a PVSS scheme
such that as long as the threshold of participants is met, and one participant
is honest, secure entropy will be generated.

The service interface definition lives in [`go/beacon/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation] and the [beacon ADR specification].

<!-- markdownlint-disable line-length -->
[`go/beacon/api`]:
  https://github.com/oasisprotocol/oasis-core/tree/master/go/beacon/api
[consensus service API documentation]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/beacon/api?tab=doc
[beacon ADR specification]:
  https://github.com/oasisprotocol/adrs/blob/main/0007-improved-random-beacon.md
<!-- markdownlint-enable line-length -->

## Operation

Each node generates and maintains a long term elliptic curve point and scalar
pair (public/private key pair), the point (public key) of which is included in
the node descriptor stored by the [registry service]. In the initial
implementation, the curve is P-256.

The beacon generation process is split into three sequential stages.  Any
failures in the _Commit_ and _Reveal_ phases result in a failed protocol round,
and the generation process will restart after disqualifying participants who
have induced the failure.

[registry service]: registry.md

### Commit Phase

Upon epoch transition or a prior failed round the commit phase is initiated and
the consensus service will select `particpants` nodes from the current validator
set (in order of descending stake) to serve as entropy contributors.

The beacon state is (re)-initialized, and an event is broadcast to signal to the
participants that they should generate and submit their encrypted shares via a
`beacon.SCRAPECommit` transaction.

Each commit phase lasts exactly `commit_interval` blocks, at the end of which,
the round will be closed to further commits.

At the end of the commit phase, the protocol state is evaluated to ensure that
`threshold` of nodes have published encrypted shares, and if an insufficient
number of nodes have published them, the round is considered to have failed.

The following behaviors are currently candidates for a node being marked as
malicious/non-particpatory and subject to exclusion from future rounds and
slashing:

- Not submitting a commitment.

- Malformed commitments (corrupted/fails to validate/etc).

- Attempting to alter an existing commitment for a given epoch/round.

### Reveal Phase

When the `commit_interval` has passed, assuming that a sufficient number of
commits have been received, the consensus service transitions into the reveal
phase and broadcasts an event to signal to the participants that they should
reveal the decrypted values of the encrypted shares received from other
participants via a `beacon.PVSSReveal` transaction.

Each reveal phase lasts exactly `reveal_interval` blocks, at the end of which,
the round will be closed to further reveals.

At the end of the reveal phase, the protocol state is evaluated to ensure that
`threshold` nodes have published decrypted shares, and if an insufficient number
of nodes have published in either case, the round is considered to have failed.

The following behaviors are currently candidates for a node being marked as
malicious/non-participatory and subject to exclusion from future rounds and
slashing:

- Not submitting a reveal.

- Malformed commitments (corrupted/fails to validate/etc).

- Attempting to alter an existing reveal for a given Epoch/Round.

### Complete (Transition Wait) Phase

When the `reveal_interval` has passed, assuming that a sufficient number of
reveals have been received, the beacon service recovers the final entropy output
(the hash of the secret shared by each participant) and transitions into the
complete (transition wait) phase and broadcasting an event to signal to
participants the completion of the round.

No meaningful protocol activity happens once a round has successfully completed,
beyond the scheduling of the next epoch transition.

## Methods

The following sections describe the methods supported by the consensus beacon
service. Note that the methods can only be called by validators and only when
they are the block proposer.

### PVSS Commit

Submits a PVSS commit.

**Method name:**

```
beacon.PVSSCommit
```

**Body:**

```golang
type PVSSCommit struct {
    Epoch EpochTime `json:"epoch"`
    Round uint64    `json:"round"`

    Commit *pvss.Commit `json:"commit,omitempty"`
}
```

### PVSS Reveal

Submits a PVSS reveal.

**Method name:**

```
beacon.PVSSReveal
```

**Body:**

```golang
type PVSSReveal struct {
    Epoch EpochTime `json:"epoch"`
    Round uint64    `json:"round"`

    Reveal *pvss.Reveal `json:"reveal,omitempty"`
}
```

## Consensus Parameters

- `participants` is the number of participants to be selected for each beacon
  generation protocol round.

- `threshold` is the minimum number of participants which must successfully
  contribute entropy for the final output to be considered valid. This is also
  the minimum number of participants that are required to reconstruct a PVSS
  secret from the corresponding decrypted shares.

- `commit_interval` is the duration of the _Commit_ phase, in blocks.

- `reveal_interval` is the duration of the _Reveal_ phase, in blocks.

- `transition_delay` is the duration of the post _Reveal_ phase delay, in
  blocks.
