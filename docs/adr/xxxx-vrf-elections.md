# ADR {ADR-NUMBER}: VRF-based Committee Elections

## Changelog

- {date}: {changelog}

## Status

Proposed

## Context

While functional, the current PVSS-based random beacon is neither all that
performant, nor all that scalable.  To address both concerns, this ADR
proposes transitioning the election procedure to one that is based on
cryptographic sortition of Verifiable Random Function (VRF) outputs.

## Decision

### Cryptographic Primitives

Let the VRF to be used across the system be ECVRF-EDWARDS25519-SHA512-ELL2
from the [Verifiable Random Functions (VRFs) draft (v09)][1], with the
following additions and extra clarifications:

- All public keys MUST be validated via the "ECVRF Validate Key" procedure
  as specified in section 5.6.1 (Small order public keys MUST be
  rejected).

- The string_to_point routine MUST reject non-canonically encoded points
  as specified in RFC 8032.  Many ed25519 implementations are lax about
  enforcing this when decoding.

- When decoding s in the ECVRF_verify routine, the s scalar MUST fall
  within the range 0 <= i < L.  This change will make proofs
  non-malleable.  Note that this check is unneeded for the c scalar
  as it is 128-bits, and thus will always lie within the valid range.

- Implementations MAY choose to incorporate additional randomness into
  the ECVRF_nonce_generation_RFC8032 function.  Note that proofs (pi_string)
  are not guaranteed to be unique or deterministic even without this
  extension (the signer can use any arbitrary value for the nonce and
  produce a valid proof, without altering beta_string).

Let the tuple oriented cryptographic hash function be TupleHash256 from
[NIST SP 800-185][2].

### Node Descriptor Changes

The node descriptor of each node will be extended to include the following
datastructure.

```golang
type Node struct {
  // ... existing fields omitted ...

  // VRF is the public key used by the node to generate VRF proofs.
  VRF signature.PublicKey `json:"vrf"`
}
```

The VRF public key shall be a long-term Ed25519 public key, that is distinct
from every other key used by the node.  The key MUST not be small order.

The existing `Beacon` member of the node descriptor is considered deprecated
and will first be ignored by the consensus layer, and then removed in a
subsequent version following a transitionary period.

### Consensus Parameters

The scheduler module will have the following additional consensus parameters
that control behavior.

```golang
type ConsensusParameters struct {
  // ... existing fields omitted ...

  // VRFParameters is the paramenters for the VRF-based cryptographic
  // sortition based election system.
  VRFParameters *VRFParameters `json:"vrf_params"`
}

// VRFParameters are the VRF scheduler parameters.
type VRFParameters struct {
  // GenesisEpoch is the first epoch which the VRF based elections will occur.
  GenesisEpoch epochtime.EpochTime `json:"genesis_epoch"`

  // ProofSubmissionDelay is the wait period in blocks after an epoch
  // transition that nodes MUST wait before attempting to submit a
  // VRF output for the next epoch.
  ProofSubmissionDelay uint64 `json:"proof_delay"`
}
```

### Consensus State, Events, and Transactions

The scheduler component will maintain and make available the following additonal
consensus state.

```golang
// VRFState is the VRF scheduler state.
type VRFState struct {
  // Alpha is the current epoch's VRF alpha_string input.
  Alpha []byte `json:"alpha"`

  // Pi is the current epoch's accumulated pi_string outputs.
  Pi map[signature.PublicKey][]byte `json:"pi"`
}
```

Implementations MAY cache the beta_string values that are generated from valid
pi_strings for performance reasons, however as this is trivial to recalculate,
it does not need to be explicitly exposed.

Upon epoch transition, the scheduler will emit the following event.

```golang
// VRFEvent is the VRF scheduler event.
type VRFEvent struct {
  // Alpha is the new epoch's VRF alpha_string input.
  Alpha []byte `json:"alpha"`
}

```

```golang
type VRFProve struct {
  // Epoch is the epoch that this VRF proof is for.
  Epoch epochtime.EpochTime `json:"epoch"`

  // VRFKey is the key used to generate pi.
  VRFKey signature.PublicKey `json:"key"`
  // Pi is the VRF proof for the current epoch.
  Pi     []byte              `json:"pi"`
}
```

### VRF Operation

For the genesis epoch, let the VRF alpha_string input be derived as:

  `TupleHash256((chain_context, I2OSP(epoch,8)), 256, "oasis-core:vrf/alpha")`

For every subsequent epoch, let alpha_string be derived as:

  `TupleHash256((chain_context, I2OSP(epoch, 8), beta_0, ... beta_n), 256, "oasis-core:vrf/alpha")`

where beta_0 through beta_n are the beta_string outputs gathered from
all valid pi_strings submitted during the previous epoch (after the
on-transition culling is complete), in ascending lexographic order by
VRF key.

Upon receiving a VRFEvent, all eligible nodes MUST wait a minimum of
ProofSubmissionDelay blocks, and then submit a VRFProve transaction,
with the Proof field set to the output of `ECVRF_prove(VRFKey_private, alpha_string)`.

Upon receiving a VRFProve transaction, the scheduler does the following:

  1. Rejects the transaction if less than ProofSubmissionDelay blocks
     have elapsed since the transition into the current epoch.

  2. Checks to see if the node tentatively eligible to be included in
     the next election according to the following criteria:

      * Not frozen.

      * Has registered the VRFKey used to generate the proof prior to
        the transition into the current epoch (May slash).

      * Has not already submitted a proof for the current epoch
        (May slash if proof is different).

  3. Validates the proof, and if valid, stores the VRFKey + pi_string
     in the consensus state.

### VRF Committee Elections

The following changes are made to the committee election process.

On epoch transition, re-validate node eligibility for all nodes that
submitted a VRF proof (Not frozen, VRFKey has not changed), and cull
proofs from nodes that are now ineligible.

For each committee:

 1. Filter the node list based on the current stake/eligibility criteria,
    and additionally filter out nodes that have not submitted a valid
    VRF proof.

 2. For each eligible (node, commitee kind, committe role) tuple, derive
    a sortition string as:

    `s_n = TupleHash256((chain_context, I2OSP(epoch, 8), runtime_id, I2OSP(kind, 1), I2OSP(role, 1), beta_n), 256, "oasis-core:vrf/committee")`

 3. Sort s_0 ... s_n in ascending lexographical order.

 4. Select the requisite nodes that produced the sortition strings
    starting from the head of the sorted list as the committee.

Committee elections MUST be skipped for the genesis and subsequent epoch,
as the genesis epoch has no VRF proofs, and proofs submitted during the
genesis epoch are based on the bootstrap alpha_string.

### VRF Validator Elections

The only place where the beacon is currently used in the validator selection
process is to pick a single node out of multiple eligible nodes controlled by
the same entity to become a validator.

When this situation occurs the validator is selected as follows:

  1. For all validator-eligible nodes controlled by the given entity,
     derive a sortition string as:

     `s_n = TupleHash256((chain_context, I2OSP(epoch, 8), beta_n), 256, "oasis-core:vrf/validator")`

  2. Sort s_0 ... s_n, in ascending lexographic order.

  3. Select the node that produced the 0th sortition string in the sorted
     list as the validator.

This is safe to do with beta values generated via the bootstrap alpha string
as it is up to the entity running the nodes in question as to which ones
are a validator anyway.

### Timekeeping Changes

Timekeeping will go back to a fixed-interval epoch transition mechanism, with
all of the beacon related facilities removed.  As this is primarily a module
rename and code removal, the exact details are left unspecified.

## Consequences

### Positive

- This is significantly simpler from a design standpoint.

- This is significantly faster and scales significantly better.

- It is possible to go back to fixed-length epochs again.

### Negative

- The system loses a way to generate entropy at the consensus layer.

- The simple design involves an additional 1-epoch period after network
  initialization where elections are not available.

### Neutral

- I need to implement TupleHash256.

## References

- [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/
- [2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf