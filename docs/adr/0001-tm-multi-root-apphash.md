# ADR 0001: Multiple Roots Under the Tendermint Application Hash

## Changelog

- 2020-08-06: Added consequence for state checkpoints
- 2020-07-28: Initial version

## Status

Accepted

## Context

Currently the Tendermint ABCI application hash is equal to the consensus state
root for a specific height. In order to allow additional uses, like proving to
light clients that specific events have been emitted in a block, we should make
the application hash be derivable from potentially different kinds of roots.

## Decision

The proposed design is to derive the Tendermint ABCI application hash by hashing
all the different roots as follows:

```
AppHash := H(Context || Root_0 || ... || Root_n)
```

Where:

- `H` is the SHA-512/256 hash function.
- `Context` is the string `oasis-core/tendermint: roots`.
- `Root_i` is the fixed-size SHA-512/256 root hash of the specified root.

Currently, the only root would be the existing consensus state root at index 0.

To implement this change the following modifications would be required:

- Update the ABCI multiplexer's `Commit` method to calculate and return the
  application hash using the scheme specified above.

- Update the consensus API `SignedHeader` response to include the
  `UntrustedStateRoot` (the untrusted prefix denotes that the user must verify
  that the state root corresponds to `AppHash` provided in the signed header in
  `Meta`).

  When new roots will be added in the future, both `Block` and `SignedHeader`
  will need to include them all.

## Alternatives

The proposed design is simple and assumes that the number of additional roots is
small and thus can always be included in signed headers. An alternative scheme
would be to Merkelize the roots in a binary Merkle tree (like the one used for
our MKVS), but this would add complexity and likely require more round trips for
common use cases.

## Consequences

### Positive

- This would open the path to including different kinds of provable data (e.g.,
  in addition to state) as part of any consensus-layer block.

### Negative

- As this changes the application hash, this would be a breaking change for the
  consensus layer.

- Since we are simply hashing all the roots together, all of them need to be
  included in the signed headers returned to light clients.

### Neutral

- Consensus state checkpoints will need to contain data for multiple roots.

## References

- [tendermint#5134](https://github.com/tendermint/tendermint/pull/5134)
