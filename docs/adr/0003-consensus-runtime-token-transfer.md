# ADR 0003: Consensus/Runtime Token Transfer

## Changelog

- 2020-09-16: Beneficiary allowance, add message results
- 2020-09-08: Initial draft

## Status

Accepted

## Context

Currently each runtime can define its own token (or none at all) and there is no
mechanism that would support transfer of consensus layer tokens into a runtime
and back out.

Introducing such a mechanism would allow the consensus layer tokens to be used
inside runtimes for various functions. This ADR proposes such a mechanism.

## Decision

On a high level, this proposal adds support for consensus/runtime token
transfers as follows:

- **Each staking account can set an allowance for beneficiaries.** Each staking
  account can set an allowance, a maximum amount a beneficiary can withdraw from
  the given account. Beneficiaries are identified by their address. This is
  similar to approve/transferFrom calls defined by the [ERC-20 Token Standard].
  Previously such functionality was already present but was removed in
  [oasis-core#2021].

- **Each runtime itself has an account in the consensus layer.** This account
  contains the balance of tokens which are managed exclusively by the runtime
  and do not belong to any specific regular account in the consensus layer.

  It is not possible to transfer directly into a runtime account and doing so
  may result in funds to be locked without a way to reclaim them.

  The only way to perform any operations on runtime accounts is through the use
  of messages emitted by the runtime during each round. These messages are
  subject to discrepancy detection and instruct the consensus layer what to do.

Combined, the two mechanisms enable account holders to set an allowance in the
benefit of runtimes so that the runtimes can withdraw up to the allowed amount
from the account holder's address.

### Addresses

This proposal introduces the following new address context for the runtime
accounts:

```
oasis-core/address: runtime
```

Initial version for the address context is `0`. To derive the address, the
standard address derivation scheme is used, with the runtime's 32-byte
identifier used as the `data` part.

### State

This proposal introduces/updates the following consensus state in the staking
module:

#### General Accounts

The general account data structure is modified to include an additional field
storing the allowances as follows:

```golang
type GeneralAccount struct {
    // ... existing fields omitted ...

    Allowances map[Address]quantity.Quantity `json:"allowances,omitempty"`
}
```

### Transaction Methods

This proposal adds the following new transaction methods in the staking module:

#### Allow

Allow enables an account holder to set an allowance for a beneficiary.

**Method name:**

```
staking.Allow
```

**Body:**

```golang
type Allow struct {
    Beneficiary  Address           `json:"beneficiary"`
    Negative     bool              `json:"negative,omitempty"`
    AmountChange quantity.Quantity `json:"amount_change"`
}
```

**Fields:**

- `beneficiary` specifies the beneficiary account address.
- `amount_change` specifies the absolute value of the amount of base units to
  change the allowance for.
- `negative` specifies whether the `amount_change` should be subtracted instead
  of added.

The transaction signer implicitly specifies the general account. Upon executing
the allow the following actions are performed:

- If either the `disable_transfers` staking consensus parameter is set to `true`
  or the `max_allowances` staking consensus parameter is set to zero, the method
  fails with `ErrForbidden`.

- It is checked whether either the transaction signer address or the
  `beneficiary` address are reserved. If any are reserved, the method fails with
  `ErrForbidden`.

- Address specified by `beneficiary` is compared with the transaction signer
  address. If the addresses are the same, the method fails with
  `ErrInvalidArgument`.

- The account indicated by the signer is loaded.

- If the allow would create a new allowance and the maximum number of allowances
  for an account has been reached, the method fails with `ErrTooManyAllowances`.

- The set of allowances is updated so that the allowance is updated as specified
  by `amount_change`/`negative`. In case the change would cause the allowance to
  be equal to zero or negative, the allowance is removed.

- The account is saved.

- The corresponding `AllowanceChangeEvent` is emitted with the following
  structure:

  ```golang
  type AllowanceChangeEvent struct {
      Owner        Address           `json:"owner"`
      Beneficiary  Address           `json:"beneficiary"`
      Allowance    quantity.Quantity `json:"allowance"`
      Negative     bool              `json:"negative,omitempty"`
      AmountChange quantity.Quantity `json:"amount_change"`
  }
  ```

  Where `allowance` contains the new total allowance, the `amount_change`
  contains the absolute amount the allowance has changed for and `negative`
  specifies whether the allowance has been reduced rather than increased. The
  event is emitted even if the new allowance is zero.

#### Withdraw

Withdraw enables a beneficiary to withdraw from the given account.

**Method name:**

```
staking.Withdraw
```

**Body:**

```golang
type Withdraw struct {
    From   Address           `json:"from"`
    Amount quantity.Quantity `json:"amount"`
}
```

**Fields:**

- `from` specifies the account address to withdraw from.
- `amount` specifies the amount of base units to withdraw.

The transaction signer implicitly specifies the destination general account.
Upon executing the withdrawal the following actions are performed:

- If either the `disable_transfers` staking consensus parameter is set to `true`
  or the `max_allowances` staking consensus parameter is set to zero, the method
  fails with `ErrForbidden`.

- It is checked whether either the transaction signer address or the
  `from` address are reserved. If any are reserved, the method fails with
  `ErrForbidden`.

- Address specified by `from` is compared with the transaction signer address.
  If the addresses are the same, the method fails with `ErrInvalidArgument`.

- The source account indicated by `from` is loaded.

- The destination account indicated by the transaction signer is loaded.

- `amount` is deducted from the corresponding allowance in the source account.
  If this would cause the allowance to go negative, the method fails with
  `ErrForbidden`.

- `amount` is deducted from the source general account balance. If this would
  cause the balance to go negative, the method fails with
  `ErrInsufficientBalance`.

- `amount` is added to the destination general account balance.

- Both source and destination accounts are saved.

- The corresponding `TransferEvent` is emitted.

- The corresponding `AllowanceChangeEvent` is emitted with the updated
  allowance.

### Queries

This proposal adds the following new query methods in the staking module by
updating the `staking.Backend` interface as follows:

```golang
type Backend interface {
    // ... existing methods omitted ...

    // Allowance looks up the allowance for the given owner/beneficiary combination.
    Allowance(ctx context.Context, query *AllowanceQuery) (*quantity.Quantity, error)
}

// AllowanceQuery is an allowance query.
type AllowanceQuery struct {
    Height      int64   `json:"height"`
    Owner       Address `json:"owner"`
    Beneficiary Address `json:"beneficiary"`
}
```

### Messages

Since this is the first proposal that introduces a new runtime message type that
can be emitted from a runtime during a round, it also defines some general
properties of runtime messages and the dispatch mechanism:

- Each message has an associated gas cost that needs to be paid by the
  submitter (e.g. as part of the `roothash.ExecutorCommit` method call). The gas
  cost is split among the committee members.

- There is a maximum number of messages that can be emitted by a runtime during
  a given round. The limit is defined both globally (e.g. a roothash consensus
  parameter) and per-runtime (which needs to be equal to or lower than the
  global limit).

- Messages are serialized using a sum type describing all possible messages,
  where each message type is assigned a _field name_:

  ```golang
  type Message struct {
      Message1 *Message1 `json:"message1,omitempty"`
      Message2 *Message2 `json:"message2,omitempty"`
      // ...
  }
  ```

- All messages are versioned by embeding the `cbor.Versioned` structure which
  provides a single `uint16` field `v`.

- A change is made to how messages are included in commitments, to reduce the
  size of submitted transactions.

  The `ComputeResultsHeader` is changed so that the `Messages` field is replaced
  with a `MessagesHash` field containing a hash of the CBOR-encoded messages
  emitted by the runtime.

  At the same time `ComputeBody` is changed to include an additional field
  `Messages` as follows:

  ```golang
  type ComputeBody struct {
      // ... existing fields omitted ...
      Messages []*block.Message `json:"messages,omitempty"`
  }
  ```

  The `Messages` field must only be populated in the commitment by the
  transaction scheduler and must match the `MessagesHash`.

- If any of the included messages is deemed _malformed_, the round fails and the
  runtime state is not updated.

- In order to support messages that fail to execute, a new roothash event is
  emitted for each executed message:

  ```golang
  type MessageEvent struct {
      Index  uint32 `json:"index,omitempty"`
      Module string `json:"module,omitempty"`
      Code   uint32 `json:"code,omitempty"`
  }
  ```

  Where the `index` specifies the index of the executed message and the `module`
  and `code` specify the module and error code accoording to Oasis Core error
  encoding convention (note that the usual human readable message field is not
  included).

This proposal introduces the following runtime messages:

#### Staking Method Call

The staking method call message enables a runtime to call one of the supported
staking module methods.

**Field name:**

```
staking
```

**Body:**

```golang
type StakingMessage struct {
    cbor.Versioned

    Transfer *staking.Transfer `json:"transfer,omitempty"`
    Withdraw *staking.Withdraw `json:"withdraw,omitempty"`
}
```

**Fields:**

- `v` must be set to `0`.
- `transfer` indicates that the `staking.Transfer` method should be executed.
- `withdraw` indicates that the `staking.Withdraw` method should be executed.

Exactly one of the supported method fields needs to be non-nil, otherwise the
message is considered malformed.

### Consensus Parameters

#### Staking

This proposal introduces the following new consensus parameters in the staking
module:

- `max_allowances` (uint32) specifies the maximum number of allowances an
  account can store. Zero means that allowance functionality is disabled.

#### Roothash

This proposal introduces the following new consensus parameters in the roothash
module:

- `max_runtime_messages` (uint32) specifies the global limit on the number of
  messages that can be emitted in each round by the runtime. The default value
  of `0` disables the use of runtime messages.

### Runtime Host Protocol

This proposal modifies the runtime host protocol as follows:

#### Host to Runtime: Initialization

The existing `RuntimeInfoRequest` message body is updated to contain a field
denoting the consensus backend used by the host and its consensus protocol
version as follows:

```golang
type RuntimeInfoRequest struct {
    ConsensusBackend         string `json:"consensus_backend"`
    ConsensusProtocolVersion uint64 `json:"consensus_protocol_version"`

    // ... existing fields omitted ...
}
```

This information can be used by the runtime to ensure that it supports the
consensus layer used by the host. In case the backend and/or protocol version is
not supported, the runtime should return an error and terminate. In case the
runtime does not interact with the consensus layer it may ignore the consensus
layer information.

#### Host to Runtime: Transaction Batch Dispatch

The existing `RuntimeExecuteTxBatchRequest` and `RuntimeCheckTxBatchRequest`
message bodies are updated to include the consensus layer light block at the
last finalized round height (specified in `.Block.Header.Round`) and the list of
`MessageEvent`s emitted while processing the runtime messages emitted in the
previous round as follows:

```golang
type RuntimeExecuteTxBatchRequest struct {
    // ConsensusBlock is the consensus light block at the last finalized round
    // height (e.g., corresponding to .Block.Header.Round).
    ConsensusBlock consensus.LightBlock `json:"consensus_block"`

    // MessageResults are the results of executing messages emitted by the
    // runtime in the previous round (sorted by .Index).
    MessageResults []roothash.MessageEvent `json:"message_results,omitempty"`

    // ... existing fields omitted ...
}

type RuntimeCheckTxBatchRequest struct {
    // ConsensusBlock is the consensus light block at the last finalized round
    // height (e.g., corresponding to .Block.Header.Round).
    ConsensusBlock consensus.LightBlock `json:"consensus_block"`

    // ... existing fields omitted ...
}
```

The information from the light block can be used to access consensus layer
state.

#### Runtime to Host: Read-only Storage Access

The existing `HostStorageSyncRequest` message body is updated to include an
endpoint identifier as follows:

```golang
type HostStorageSyncRequest struct {
    // Endpoint is the storage endpoint to which this request should be routed.
    Endpoint string `json:"endpoint,omitempty"`

    // ... existing fields omitted ...
}
```

The newly introduced `endpoint` field can take the following values:

- `runtime` (or empty string) denotes the runtime state endpoint. The empty
  value is allowed for backwards compatibility as this was the only endpoint
  available before this proposal.

- `consensus` denotes the consensus state endpoint, providing access to
  consensus state.

### Rust Runtime Support Library

The Rust runtime support library (`oasis-core-runtime`) must be updated to
support the updated message structures. Additionally, there needs to be basic
support for interpreting the data from the Tendermint consensus layer backend:

- Decoding light blocks.

- Decoding staking-related state structures.

The Tendermint-specific functionality should be part of a separate crate.

### Expected User/Consensus/Runtime Flow

**Scenario:**

Account holder has 100 tokens in her account in the consensus layer staking
ledger and would like to spend 50 tokens to execute an action in runtime X.

**Flow:**

- Account holder sets an allowance of 50 tokens for runtime X by submitting an
  allow transaction to the consensus layer.

- Account holder submits a runtime transaction that performs some action costing
  50 tokens.

- Account holder's runtime transaction is executed in runtime X round R:

  - Runtime X emits a message to transfer 50 tokens from the user's account to
    the runtime's own account.

    _As an optimization runtime X can verify current consensus layer state and
    reject the transaction early to prevent paying for needless consensus layer
    message processing._

  - Runtime X updates its state to indicate a pending transfer of 50 tokens from
    the user. It uses the index of the emitted message to be able to match the
    message execution result once it arrives.

  - Runtime X submits commitments to the consensus layer.

- When finalizing round R for runtime X, the consensus layer transfers 50 tokens
  from the account holder's account to the runtime X account.

- Corresponding message result event is emitted, indicating success.

- When runtime X processes round R+1, the runtime receives the set of emitted
  message result events.

- Runtime X processes message result events, using the index field to match the
  corresponding pending action and executes whatever action it queued.

  - In case the message result event would indicate failure, the pending action
    can be pruned.

## Consequences

### Positive

- Consensus layer tokens can be transferred into and out of runtimes, enabling
  more use cases.

- Any tokens must be explicitly made available to the runtime which limits the
  damage from badly written or malicious runtimes.

- Account holders can change the allowance at any time.

### Negative

- A badly written or malicious runtime could steal the tokens explicitly
  deposited into the runtime. This includes any actions by the runtime owner
  which would modify the runtime's security parameters.

- A badly written, malicious or forever suspended runtime can lock tokens in
  the runtime account forever. This could be mitigated via an unspecified
  consensus layer governance mechanism.

- Account holders may mistakenly transfer tokens directly into a runtime account
  which may cause such tokens to be locked forever.

- Account holders may change the allowance or reduce their account balance right
  before the runtime round is finalized, causing the emitted messages to fail
  while the runtime still needs to pay for gas to execute the messages.

### Neutral

- The runtime must handle all message results in the next round as otherwise it
  cannot easily get past messages.

## References

- [ERC-20 Token Standard]
- [oasis-core#2021]

[ERC-20 Token Standard]: https://eips.ethereum.org/EIPS/eip-20
[oasis-core#2021]: https://github.com/oasisprotocol/oasis-core/issues/2021
