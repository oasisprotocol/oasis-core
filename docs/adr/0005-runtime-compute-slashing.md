# ADR 0005: Runtime Compute Node Slashing

## Changelog

- 2020-10-14: Evidence expiry, duplicate evidence detection
- 2020-09-28: Initial draft

## Status

Accepted

## Context

The runtime compute nodes make updates to the runtime state by submitting
commitment messages to the roothash service in the consensus layer where
discrepancy detection and resolution are performed.

Currently, the compute nodes are never slashed even if they commit incorrect
results. While integrity is guarded by discrepancy detection and resolution,
compute nodes should be disincentivized to behave incorrectly.

## Decision

This proposal introduces a slashing mechanism for punishing misbehaving compute
nodes as follows:

- **Per-runtime configurable slashing parameters** are added to the runtime
  descriptor similar to the global slashing configuration that currently exists
  in the staking service.

- **New runtime-specific slashing reasons** are introduced: (i) submitting
  incorrect compute results and (ii) signing two different executor commits or
  proposed batches for the same round.

- **Failure-indicating executor commits** are introduced in order to give the
  compute nodes a possibility to vote for failure when they cannot execute the
  given batch (e.g., due to unavailability of storage or key manager) without
  getting slashed. Such commits will always trigger a discrepancy during
  discrepancy detection and will vote for failing the round in discrepancy
  resolution phase.

### Runtime Descriptor

This proposal updates the runtime staking parameters (stored under the `staking`
field of the runtime descriptor) as follows:

```golang
type RuntimeStakingParameters struct {
    // ... existing fields omitted ...

    // Slashing are the per-runtime misbehavior slashing parameters.
    Slashing map[staking.SlashReason]staking.Slash `json:"slashing,omitempty"`
}
```

### Slashing Parameters

The slash reason type in the staking module is changed from `int` to `uint8`.

The slash reason definitions are updated as follows:

```golang
const (
    // SlashConsensusEquivocation is slashing due to equivocation in the
    // consensus layer.
    SlashConsensusEquivocation SlashReason = 0x00

    // SlashRuntimeIncorrectResults is slashing due to submission of incorrect
    // results in runtime executor commitments.
    SlashRuntimeIncorrectResults SlashReason = 0x80
    // SlashRuntimeEquivocation is slashing due to signing two different
    // executor commits or proposed batches for the same round.
    SlashRuntimeEquivocation SlashReason = 0x81
)
```

### Executor Commitments

The executor commitment body structures are updated to make certain fields
optional and to introduce the `failure` field as follows:

```golang
type ExecutorCommitmentFailure uint8

const (
    // FailureNone indicates that no failure has occurred.
    FailureNone ExecutorCommitmentFailure = 0
    // FailureUnknown indicates a generic failure.
    FailureUnknown ExecutorCommitmentFailure = 1
    // FailureStorageUnavailable indicates that batch processing failed due to
    // storage being unavailable.
    FailureStorageUnavailable ExecutorCommitmentFailure = 2
    // FailureKeyManagerUnavailable indicates that batch processing failed due
    // to key manager being unavailable.
    FailureKeyManagerUnavailable ExecutorCommitmentFailure = 3
)

type ExecutorCommitmentHeader struct {
    // Required fields.

    Round        uint64    `json:"round"`
    PreviousHash hash.Hash `json:"previous_hash"`

    // Optional fields (may be absent for failure indication).

    IORoot       *hash.Hash `json:"io_root,omitempty"`
    StateRoot    *hash.Hash `json:"state_root,omitempty"`
    MessageHash  *hash.Hash `json:"messages_hash,omitempty"`
}

type ExecutorCommitmentBody struct {
  Header  ExecutorCommitmentHeader  `json:"header"`
  Failure ExecutorCommitmentFailure `json:"failure,omitempty"`

  TxnSchedSig      signature.Signature   `json:"txn_sched_sig"`
  InputRoot        hash.Hash             `json:"input_root"`
  InputStorageSigs []signature.Signature `json:"input_storage_sigs"`

  // Optional fields (may be absent for failure indication).

  StorageSignatures []signature.Signature   `json:"storage_signatures,omitempty"`
  RakSig            *signature.RawSignature `json:"rak_sig,omitempty"`
}
```

The notion of an _failure-indicating_ executor commitment is introduced as being
an executor commitment with the following field values:

- The `failure` field must be present and non-zero. The code can indicate a
  reason for the failure but currently the reason is ignored during processing.

- `header.round`, `header.previous_hash`, `txn_sched_sig`, `input_root` and
  `input_storage_sigs` are set as for usual commitments (e.g., they must be
  valid).

- All other fields must be omitted or set to nil.

### Root Hash Commitment Processing

The processing of executor commitments by the commitment pool is modified as
follows:

- **Adding new commitments (`AddExecutorCommitment`)**

  - If a commitment for a node already exists the existing commitment is
    checked for evidence of equivocation. Any evidence of misbehavior is
    processed as described in the _Evidence_ subsection below.

- **Discrepancy detection (`DetectDiscrepancy`)**

  - If any executor commitment indicates failure, the discrepancy detection
    process signals a discrepancy (which implies that discrepancy resolution is
    triggered).

- **Discrepancy resolution (`ResolveDiscrepancy`)**

  - When tallying votes, any executor commitments indicating failure are tallied
    into its own bucket. If the failure bucket receives 1/2+ votes, the round
    fails.

  - If after discrepancy resolution a non-failure option receives 1/2+ votes,
    this is considered the correct result. Executor commitments for any other
    result (excluding failure indication) are considered incorrect and are
    subject to slashing (based on the configured slashing instructions for the
    `SlashRuntimeIncorrectResults` reason).

A portion of slashed funds is disbursed equally to the compute nodes which
participated in discrepancy resolution for the round. The remainder of slashed
funds is transferred to the runtime account.

Any slashing instructions related to freezing nodes are currently ignored.

### State

This proposal introduces/updates the following consensus state in the roothash
module:

- **List of past valid evidence (`0x23`)**

  A hash uniquely identifying the evidence is stored for each successfully
  processed evidence that has not yet expired using the following key format:

  ```
  0x23 <H(runtime-id) (hash.Hash)> <round (uint64)> <evidence-hash (hash.Hash)>
  ```

  The value is empty as we only need to detect duplicate evidence.

### Transaction Methods

This proposal updates the following transaction methods in the roothash module:

#### Evidence

The evidence method allows anyone to submit evidence of runtime node
misbehavior.

**Method name:**

```
roothash.Evidence
```

**Body:**

```golang
type EvidenceKind uint8

const (
    // EvidenceKindEquivocation is the evidence kind for equivocation.
    EvidenceKindEquivocation = 1
)

type Evidence struct {
    ID   common.Namespace `json:"id"`

    EquivocationExecutor *EquivocationExecutorEvidence `json:"equivocation_executor,omitempty"`
    EquivocationBatch    *EquivocationBatchEvidence    `json:"equivocation_batch,omitempty"`
}

type EquivocationExecutorEvidence struct {
    CommitA commitment.ExecutorCommitment `json:"commit_a"`
    CommitB commitment.ExecutorCommitment `json:"commit_b"`
}

type EquivocationBatchEvidence struct {
    BatchA commitment.SignedProposedBatch `json:"batch_a"`
    BatchB commitment.SignedProposedBatch `json:"batch_b"`
}
```

**Fields:**

- `id` specifies the runtime identifier of a runtime this evidence is for.
- `equivocation_executor` (optional) specifies evidence of an executor node
  equivocating when signing commitments.
- `equivocation_batch` (optional) specifies evidence of an executor node
  equivocating when signing proposed batches.

If no evidence is specified (e.g., all evidence fields are `nil`) the method
call is invalid and must fail with `ErrInvalidArgument`.

For all kinds of evidence, the following steps are performed to verify evidence
validity:

- Current state for the runtime identified by `id` is fetched. If the runtime
  does not exist, the evidence is invalid.

- If no slashing instructions for `SlashRuntimeEquivocation` are configured for
  the given runtime, there is no point in collecting evidence so the method call
  must fail with `ErrRuntimeDoesNotSlash`.

When processing **`EquivocationExecutor`** evidence, the following steps are
performed to verify evidence validity:

- `header.round` fields of both commitments are compared. If they are not the
  same, the evidence is invalid.

- Both executor commitments are checked for basic validity. If either is
  invalid, the evidence is invalid.

- The `header.previous_hash`, `header.io_root`, `header.state_root` and
  `header.messages_hash` fields of both commitments are compared. If they are
  the same, the evidence is invalid.

- The failure indication fields of both commitments are compared. If they are
  the same, the evidence is invalid.

- `header.round` field is compared with the runtime's current state. If it is
  more than `max_evidence_age` (consensus parameter) rounds behind, the evidence
  is invalid.

- Public keys of signers of both commitments are compared. If they are not the
  same, the evidence is invalid.

- Signatures of both commitments are verified. If either is invalid, the
  evidence is invalid.

- Otherwise the evidence is valid.

When processing **`EquivocationBatch`** evidence, the following steps are
performed to verify evidence validity:

- The `header.round` fields of both proposed batches are compared. If they are
  not the same, the evidence is invalid.

- The `header` fields of both proposed batches are checked for basic validity.
  If any is invalid, the evidence is invalid.

- The `io_root` fields of both proposed batches are compared. If they are the
  same, the evidence is invalid.

- Public keys of signers of both commitments are compared. If they are not the
  same, the evidence is invalid.

- Signatures of both proposed batches are compared. If either is invalid, the
  evidence is invalid.

- Otherwise the evidence is valid.

For all kinds of valid evidence, the following steps are performed after
validation:

- The evidence hash is derived by hashing the evidence kind and the public key
  of the signer and the evidence is looked up in the _list of past valid
  evidence_. If evidence already exists there, the method fails with
  `ErrDuplicateEvidence`.

- The valid evidence hash is stored in the _list of past valid evidence_.

If the evidence is deemed valid by the above procedure, the misbehaving compute
node is slashed based on the runtime slashing parameters for the
`SlashRuntimeEquivocation` reason.

Any slashing instructions related to freezing nodes are currently ignored.

The node submitting the evidence may be rewarded from part of the slashed
amount to incentivize evidence submission. The remainder of slashed funds is
transferred to the runtime account.

### Evidence Expiry

On each epoch transition, for each runtime, expired evidence (as defined by the
`max_evidence_age` and the current runtime's round) must be pruned from the
_list of past valid evidence_.

### Evidence Collection

Nodes collect commitment messages distributed via the P2P gossip network and
check for any signs of misbehavior. In case valid evidence can be constructed,
it is submitted to the consensus layer. Any evidence parts that have expired
should be discarded.

### Consensus Parameters

#### Roothash

This proposal introduces the following new consensus parameters in the roothash
module:

- `max_evidence_age` (uint64) specifies the maximum age of submitted evidence in
  the number of rounds.

## Consequences

### Positive

- Compute nodes can be disincentivized to submit incorrect results by runtimes
  configuring slashing parameters.

### Negative

- Checking for duplicate evidence requires additional state in the consensus
  layer to store the evidence hashes (73 bytes per evidence).

- Expiring old evidence requires additional per-runtime state lookups and
  updates that happen on each epoch transition.

- If a runtime exhibits non-determinism, this can result in a compute node being
  slashed. While we specify that runtimes should be deterministic, for non-SGX
  runtimes we have no way determining whether a discrepancy is due to runtime
  non-determinism or a faulty compute node.

### Neutral

- This proposal does not introduce any kind of slashing for liveness.

- This proposal does not introduce freezing misbehaving nodes.

## References

- [oasis-core#2078](https://github.com/oasisprotocol/oasis-core/issues/2078)
