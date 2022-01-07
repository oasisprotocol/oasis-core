# ADR 0011: Incoming Runtime Messages

## Changelog

- 2022-01-07: Update based on insights from implementation
- 2021-12-09: Introduce an explicit fee field, clarify token transfers
- 2021-10-26: Initial draft

## Status

Accepted

## Context

There is currently a single mechanism through which the consensus layer and a
runtime may interact in a consistent and secure manner. This is the mechanism
of runtime messages that can be emitted by runtimes (see [ADR 3]) and allows
the consensus layer to act on a runtime's behalf. This mechanism is currently
used for _pulling_ tokens from consensus layer accounts that have previously
set proper allowances and for updating the runtime descriptor when the runtime
governance model (see [ADR 4]) is in effect.

This ADR proposes to implement the reverse mechanism where anyone issuing a
transaction at the consensus layer can queue arbitrary messages for processing
by the runtime in its next round.

[ADR 3]: 0003-consensus-runtime-token-transfer.md
[ADR 4]: 0004-runtime-governance.md

## Decision

On a high level this proposal affects the following components:

- A new transaction method `roothash.SubmitMsg` is added to the roothash
  consensus service to queue a new message for the specific runtime.

- Additional per-runtime state is added to the roothash service containing the
  currently queued messages, sorted by arrival time.

- During processing of a round the proposer may propose to pop any number of
  messages and process them by pushing them to the runtime, similar as it does
  for transaction batches. This is of course subject to discrepancy detection.

- The runtime host protocol is updated to allow the host to push arbitrary
  incoming messages in addition to the transaction batch.

- The runtime descriptor is updated to include a field that specifies the
  maximum size of the incoming message queue.

### Incoming Message

Each incoming message is represented as follows:

```golang
type IncomingMessage struct {
    // ID is the unique identifier of the message.
    ID uint64 `json:"id"`

    // Caller is the address of the caller authenticated by the consensus layer.
    Caller staking.Address `json:"caller"`

    // Tag is an optional tag provided by the caller which is ignored and can be used to match
    // processed incoming message events later.
    Tag uint64 `json:"tag,omitempty"`

    // Fee is the fee sent into the runtime as part of the message being sent.
    // The fee is transferred before the message is processed by the runtime.
    Fee quantity.Quantity `json:"fee,omitempty"`

    // Tokens are any tokens sent into the runtime as part of the message being
    // sent. The tokens are transferred before the message is processed by the
    // runtime.
    Tokens quantity.Quantity `json:"tokens,omitempty"`

    // Data is arbitrary runtime-dependent data.
    Data []byte `json:"data,omitempty"`
}
```

### Executor Commitments

The compute results header structure is updated to include two fields that
specify the number and hash of incoming messages included in a batch as follows:

```golang
type ComputeResultsHeader struct {
    // ... existing fields omitted ...

    // InMessagesHash is the hash of processed incoming messages.
    InMessagesHash *hash.Hash `json:"in_msgs_hash,omitempty"`
    // InMessagesCount is the number of processed incoming messages.
    InMessagesCount uint32 `json:"in_msgs_count,omitempty"`
}
```

Where the hash of included incoming messages is computed as follows:

```golang
// InMessagesHash returns a hash of provided incoming runtime messages.
func InMessagesHash(msgs []IncomingMessage) (h hash.Hash) {
    if len(msgs) == 0 {
        // Special case if there are no messages.
        h.Empty()
        return
    }
    return hash.NewFrom(msgs)
}
```

Note that this also requires the enclave RAK signature (for runtimes requiring
the use of TEEs) to be computed over this updated new header.

### Runtime Block Header

The runtime block header is updated to include the `InMessagesHash` field as
follows:

```golang
type Header struct {
    // ... existing fields omitted ...

    // InMessagesHash is the hash of processed incoming messages.
    InMessagesHash hash.Hash `json:"in_msgs_hash"`
}
```

### Runtime Descriptor

This proposal updates the runtime transaction scheduler parameters (stored under
the `txn_scheduler` field of the runtime descriptor) as follows:

```golang
type TxnSchedulerParameters struct {
    // ... existing fields omitted ...

    // MaxInMessages specifies the maximum size of the incoming message queue
    // for this runtime.
    MaxInMessages uint32 `json:"max_in_messages,omitempty"`
}
```

It also updates the runtime staking parameters (stored under the `staking` field
of the runtime descriptor) as follows:

```golang
type RuntimeStakingParameters struct {
    // ... existing fields omitted ...

    // MinInMessageFee specifies the minimum fee that the incoming message must
    // include for the message to be queued.
    MinInMessageFee quantity.Quantity `json:"min_in_msg_fee,omitempty"`
}
```

### State

This proposal introduces/updates the following consensus state in the roothash
module:

- **Incoming message queue metadata (`0x28`)**

  Metadata for the incoming message queue.

  ```
  0x28 <H(runtime-id) (hash.Hash)>
  ```

  The value is the following CBOR-serialized structure:

  ```golang
  type IncomingMessageQueue struct {
      // Size contains the current size of the queue.
      Size uint32 `json:"size,omitempty"`

      // NextSequenceNumber contains the sequence number that should be used for
      // the next queued message.
      NextSequenceNumber uint64 `json:"next_sequence_number,omitempty"`
  }
  ```

- **Incoming message queue item (`0x29`)**

  A queue of incoming messages pending to be delivered to the runtime in the
  next round.

  ```
  0x29 <H(runtime-id) (hash.Hash)> <sequence-no (uint64)>
  ```

  The value is a CBOR-serialized `IncomingMessage` structure.

### Transaction Methods

This proposal updates the following transaction methods in the roothash module:

#### Submit Message

The submit message method allows anyone to submit incoming runtime messages to
be queued for delivery to the given runtime.

**Method name:**

```
roothash.SubmitMsg
```

**Body:**

```golang
type SubmitMsg struct {
    ID     common.Namespace  `json:"id"`
    Fee    quantity.Quantity `json:"fee,omitempty"`
    Tokens quantity.Quantity `json:"tokens,omitempty"`
    Data   []byte            `json:"data,omitempty"`
}
```

**Fields:**

- `id` specifies the destination runtime's identifier.
- `fee` specifies the fee that should be sent into the runtime as part of the
  message being sent. The fee is transferred before the message is processed by
  the runtime.
- `tokens` specifies any tokens to be sent into the runtime as part of the
  message being sent. The tokens are transferred before the message is processed
  by the runtime.
- `data` arbitrary data to be sent to the runtime for processing.

The transaction signer implicitly specifies the caller. Upon executing the
submit message method the following actions are performed:

- Gas is accounted for (new `submitmsg` gas operation).

- The runtime descriptor for runtime `id` is retrieved. If the runtime does not
  exist or is currently suspended the method fails with `ErrInvalidRuntime`.

- The `txn_scheduler.max_in_messages` field in the runtime descriptor is
  checked. If it is equal to zero the method fails with
  `ErrIncomingMessageQueueFull`.

- If the value of the `fee` field is smaller than the value of the
  `staking.min_in_msg_fee` field in the runtime descriptor the method fails with
  `ErrIncomingMessageInsufficientFee`.

- The number of tokens corresponding to `fee + tokens` are moved from the
  caller's account into the runtime account. If there is insufficient balance to
  do so the method fails with `ErrInsufficientBalance`.

- The incoming queue metadata structure is fetched. If it doesn't yet exist it
  is populated with zero values.

- If the value of the `size` field in the metadata structure is equal to or
  larger than the value of the `txn_scheduler.max_in_messages` field in the
  runtime descriptor the method fails with `ErrIncomingMessageQueueFull`.

- An `IncomingMessage` structure is generated based on the caller and method
  body and the value of the `next_sequence_number` metadata field is used to
  generate a proper key for storing it in the queue. The structure is inserted
  into the queue.

- The `size` and `next_sequence_number` fields are incremented and the updated
  metadata is saved.

### Queries

This proposal adds the following new query methods in the roothash module by
updating the `roothash.Backend` interface as follows:

<!-- markdownlint-disable line-length -->
```golang
type Backend interface {
    // ... existing methods omitted ...

    // GetIncomingMessageQueueMeta returns the given runtime's incoming message queue metadata.
    GetIncomingMessageQueueMeta(ctx context.Context, request *RuntimeRequest) (*message.IncomingMessageQueueMeta, error)

    // GetIncomingMessageQueue returns the given runtime's queued incoming messages.
    GetIncomingMessageQueue(ctx context.Context, request *InMessageQueueRequest) ([]*message.IncomingMessage, error)
}

// IncomingMessageQueueMeta is the incoming message queue metadata.
type IncomingMessageQueueMeta struct {
    // Size contains the current size of the queue.
    Size uint32 `json:"size,omitempty"`

    // NextSequenceNumber contains the sequence number that should be used for the next queued
    // message.
    NextSequenceNumber uint64 `json:"next_sequence_number,omitempty"`
}

// InMessageQueueRequest is a request for queued incoming messages.
type InMessageQueueRequest struct {
    RuntimeID common.Namespace `json:"runtime_id"`
    Height    int64            `json:"height"`

    Offset uint64 `json:"offset,omitempty"`
    Limit  uint32 `json:"limit,omitempty"`
}
```
<!-- markdownlint-enable line-length -->

### Runtime Host Protocol

This proposal updates the existing host to runtime requests in the runtime host
protocol as follows:

```golang
type RuntimeExecuteTxBatchRequest struct {
    // ... existing fields omitted ...

    // IncomingMessages are the incoming messages from the consensus layer that
    // should be processed by the runtime in this round.
    IncomingMessages []*IncomingMessage `json:"in_messages,omitempty"`
}
```

### Rust Runtime Support Library

This proposal updates the `transaction::Dispatcher` trait as follows:

```rust
pub trait Dispatcher: Send + Sync {
    // ... existing unchanged methods omitted ...

    /// Execute the transactions in the given batch.
    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: Vec<IncomingMessage>, // Added argument.
    ) -> Result<ExecuteBatchResult, RuntimeError>;
}
```

### Executor Processing

The executor processing pipeline is changed such that pending incoming messages
are queried before the next round starts and are then passed to the runtime via
the runtime host protocol.

The executor may perform checks to estimate resource use early, similarly to how
checks are performed for transactions as they arrive.

### Runtime Processing

The proposal requires that messages are processed by the runtime in queue order
(e.g. on each round `InMessagesCount` messages are poped from the queue). This
simplifies the design but the runtimes need to carefully consider how much
resources to allocate for executing messages (vs. regular transactions) in a
round.

The runtime has full autonomy in choosing how many messages to execute as it
is given the complete message batch. It should first compute how many messages
to process by running them in "check" mode and computing how much gas (or other
resources) they take and then choosing as many as fits.

Specifying these details is left to the runtime implementation although the SDK
is expected to adopt an approach with separate `max_inmsg_gas` and
`max_inmsg_slots` parameters which limits how resources are allocated for
incoming message processing in each round. If a single message exceeds either of
these limits it will result in execution failure of that message.

### Root Hash Commitment Processing

The processing of executor commitments is modified as follows:

- No changes are made to the discrepancy detection and resolution protocols
  besides the newly added fields being taken into account in discrepancy
  determination.

- After a successful round, the `InMessagesCount` field of the compute body is
  checked and the corresponding number of messages are popped from the queue in
  increasing order of their sequence numbers. The queue metadata is updated
  accoordingly by decrementing the value of the `size` field and the
  `InMessagesHash` is added to the newly emitted block header.

## Consequences

### Positive

- Consensus layer transactions can trigger actions in the runtime without
  additional runtime transactions. This would also allow pushing tokens into
  the runtime via a consensus layer transaction or even invoking smart contracts
  that result in consensus layer actions to happen (via emitted messages).

- Each runtime can define the format of incoming messages. The SDK would likely
  use something that contains a transaction (either signed to support
  non-Ed25519 callers or unsigned for smaller Ed25519-based transactions) so
  arbitrary invocations would be possible.

### Negative

- Storing the queue will increase the size of consensus layer state.

- This could lead to incoming messages being used exclusively to interact with a
  runtime leading to the consensus layer getting clogged with incoming message
  submission transactions. Posting such messages would be more expensive though
  as it would require paying per transaction consensus layer fees in addition to
  the runtime fees. If clogging does eventually happen the fees can be adjusted
  to encourage transaction submission to runtimes directly.

### Neutral

- Allows rollup-like constructions where all transactions are posted to the
  consensus layer first and the runtime is just executing those.

- Retrieving the result of processing an incoming message is more involved.
