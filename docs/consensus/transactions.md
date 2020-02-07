# Transactions

The consensus layer uses a common transaction format for all transactions.

## Format

Each (unsigned) transaction is represented by the following [encoded] structure:

```golang
type Transaction struct {
    Nonce uint64 `json:"nonce"`
    Fee   *Fee   `json:"fee,omitempty"`

    Method string      `json:"method"`
    Body   interface{} `json:"body,omitempty"`
}
```

Fields:

* `nonce` is the current caller's nonce to prevent replays.
* `fee` is an optional fee that the caller commits to paying to execute the
  transaction.
* `method` is the called method name. Method names are composed of two parts,
  the component name and the method name, joined by a separator (`.`).
  For example, `staking.Transfer` is the method name of the staking component's
  `Transfer` method.
* `body` is the method-specific body.

The actual transaction that is submitted to the consensus layer must be signed
which means that it is wrapped into a [signed envelope].

Domain separation context (+ [chain domain separation]):

```
oasis-core/consensus: tx
```

[encoded]: ../encoding.md
[signed envelope]: ../crypto.md#signed-envelope
[chain domain separation]: ../crypto.md#chain-domain-separation

## Fees

As the consensus operations require resources to process, the consensus layer
charges fees to perform operations.

### Gas

Gas is an unsigned 64-bit integer denominated in _gas units_.

Different operations cost different amounts of gas as defined by the consensus
parameters of the consensus component that implements the operation.

Transactions that require fees to process will include a `fee` field to declare
how much the caller is willing to pay for fees.
Specifying an `amount` (in tokens) and `gas` (in gas units) implicitly defines a
_gas price_ (price of one gas unit) as `amount / gas`.
Consensus validators may refuse to process operations with a gas price that is
too low.

The `gas` field defines the maximum amount of gas that can be used by an
operation for which the fee has been included. In case an operation uses more
gas, processing will be aborted and no state changes will take place.

Signing a transaction which includes a fee structure implicitly grants
permission to withdraw the given amount of tokens from the signer's account.
In case there is not enough balance in the account, the operation will fail.

```golang
type Fee struct {
    Amount quantity.Quantity `json:"amount"`
    Gas    Gas               `json:"gas"`
}
```

Fees are not refunded.

Fields:

* `amount` is the total fee amount to be paid.
* `gas` is the maximum gas that an operation can use.
