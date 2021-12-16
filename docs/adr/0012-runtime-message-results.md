# ADR 0012: Runtime Message Results

## Changelog

- 2021-12-04: Initial version

- 2021-12-10: Extend the implementation section

## Status

Accepted

## Context

Currently, the results of emitted runtime messages are `MessageEvent`s, which
only provide information whether the message execution was successful or not.
For various use-cases additional information about message results would be
useful.

One of such is supporting staking by runtimes. Currently, a runtime can emit an
`AddEscrow` message, but is unaware of the actual amount of shares it obtained
as a result of the added escrow. For some use-cases (e.g. runtime staking user
deposited funds) this information is crucial for accounting.

Similarly, for `ReclaimEscrow`, the runtime doesn't have the direct information
at which epoch the stake gets debonded.

The only way to currently obtain this data is to subscribe to consensus events,
something which runtime doesn't have access to.

Adding results to `MessageEvent` solves both of the mentioned use cases:

- for `AddEscrow` the result should contain amount of shares obtained with the
  escrow

- for `ReclaimEscrow` the result should contain the amount of shares and epoch
  at which the stake gets debonded

## Decision

Implement support for arbitrary result data in `MessageEvent` runtime message
results.

## Implementation

- Result field is added to `roothash.MessageEvent` struct:

```golang
// MessageEvent is a runtime message processed event.
type MessageEvent struct {
        Module string `json:"module,omitempty"`
        Code   uint32 `json:"code,omitempty"`
        Index  uint32 `json:"index,omitempty"`

        // Result contains message execution results for successfully executed messages.
        Result cbor.RawMessage `json:"result,omitempty"
}
```

The `Result` field is runtime message specific and is present only when the
message execution was successful (`Code` is `errors.CodeNoError`).

- `ExecuteMessage` method in `MessageSubscriber` interface is updated to include
  a response:

```golang
// MessageSubscriber is a message subscriber interface.
type MessageSubscriber interface {
        // ExecuteMessage executes a given message.
        ExecuteMessage(ctx *Context, kind, msg interface{}) (interface{}, error)
}
```

- `Publish` method of the `MessageDispatcher` interface is updated to include
  the response:

```golang
// MessageDispatcher is a message dispatcher interface.
type MessageDispatcher interface {
        // Publish publishes a message of a given kind by dispatching to all subscribers.
        //
        // In case there are no subscribers ErrNoSubscribers is returned.
        Publish(ctx *Context, kind, msg interface{}) ([]interface{}, error)
}
```

In case the `Publish` `error` is `nil` the Roothash backend propagates the first
result to the emitted `MessageEvent`.

With these changes the runtime is able to obtain message execution results via
`MessageEvents` in `RoundResults`.

### Escrow events

Already existing staking consensus events are leveraged and used as result types
to runtime message execution messages.

- `AddEscrow` message execution result is the `AddEscrowEvent`:

```golang
type AddEscrowEvent struct {
        Owner     Address           `json:"owner"`
        Escrow    Address           `json:"escrow"`
        Amount    quantity.Quantity `json:"amount"`
        NewShares quantity.Quantity `json:"new_shares"`
}
```

- `ReclaimEscrow` message execution result is the (updated)
  `DebondingStartEscrowEvent`:

```golang
type DebondingStartEscrowEvent struct {
        Owner           Address           `json:"owner"`
        Escrow          Address           `json:"escrow"`
        Amount          quantity.Quantity `json:"amount"`
        ActiveShares    quantity.Quantity `json:"active_shares"`
        DebondingShares quantity.Quantity `json:"debonding_shares"`

        // Added.
        DebondEndTime   beacon.EpochTime `json:"debond_end_time"`
}
```

`DebondEndTime` field is added to the `DebondingStartEscrowEvent`.

For completeness, other staking messages also return corresponding events in
message results:

- `Transfer` message execution result is the `TransferEvent`:

```golang
type TransferEvent struct {
        From   Address           `json:"from"`
        To     Address           `json:"to"`
        Amount quantity.Quantity `json:"amount"`
}
```

- `Withdraw` message execution results in `AllowanceChangeEvent`:

```golang
type AllowanceChangeEvent struct {
        Owner        Address           `json:"owner"`
        Beneficiary  Address           `json:"beneficiary"`
        Allowance    quantity.Quantity `json:"allowance"`
        Negative     bool              `json:"negative,omitempty"`
        AmountChange quantity.Quantity `json:"amount_change"`
}
```

## Consequences

### Positive

All the functionality for runtimes to support staking is implemented.

### Negative

Requires breaking changes.

### Neutral

### Alternatives considered

Add support to runtimes for subscribing to consensus events. A more heavyweight
solution, that can still be implemented in future if desired. Decided against it
due to simplicity of the message events solution for the present use cases.
