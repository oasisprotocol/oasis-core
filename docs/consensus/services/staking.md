# Staking

The staking service is responsible for managing the staking ledger in the
consensus layer. It enables operations like transferring stake between accounts
and escrowing stake for specific needs (e.g., operating nodes).

The service interface definition lives in [`go/staking/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[`go/staking/api`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/staking/api/api.go
[consensus service API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc
<!-- markdownlint-enable line-length -->

## Tokens and Base Units

Stake amounts can be denominated in tokens and base units.

Tokens are used in user-facing scenarios (e.g. CLI commands) where the token
amount is prefixed with the token's ticker symbol as defined by the [`Genesis`'
`TokenSymbol` field][pkggodev-genesis].

Another [`Genesis`' field, `TokenValueExponent`][pkggodev-genesis], defines the
token's value base-10 exponent.
For example, if `TokenValueExponent` is 6, then 1 token equals 10^6 (i.e. one
million) base units.

Internally, base units are used for all stake calculation and processing.

<!-- markdownlint-disable line-length -->
[pkggodev-genesis]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#Genesis
<!-- markdownlint-enable line-length -->

## Accounts

A staking account is an entry in the staking ledger. It can hold both general
and escrow accounts.

Each staking account has an address which is derived from the corresponding
public key as follows:

<!-- markdownlint-disable line-length -->
```
[ 1 byte <ctx-version> ][ first 20 bytes of SHA512-256(<ctx-identifier> || <ctx-version> || <data>) ]
```
<!-- markdownlint-disable line-length -->

Where `<ctx-version>` and `<ctx-identifier>` represent the staking account
address' context version and identifier and `<data>` represents the data
specific to the address kind.

There are two kinds of accounts:

* User accounts linked to a specific public key.
* Runtime accounts linked to a specific [runtime identifier].

Addresses use [Bech32 encoding] for text serialization with `oasis` as its human
readable part (HRP) prefix (for both kinds of accounts).

### User Accounts

In case of user accounts, the `<ctx-version>` and `<ctx-identifier>` are as
defined by the [`AddressV0Context` variable], and `<data>` represents the
account signer's public key (e.g. entity id).

For more details, see the [`NewAddress` function].

:::info

When generating an account's private/public key pair, follow [ADR 0008:
Standard Account Key Generation][ADR 0008].

:::

### Runtime Accounts

In case of runtime accounts, the `<ctx-version>` and `<ctx-identifier>` are as
defined by the [`AddressRuntimeV0Context` variable], and `<data>` represents the
[runtime identifier].

For more details, see the [`NewRuntimeAddress` function].

The runtime accounts belong to runtimes and can only be manipulated by the
runtime by [emitting messages] to the consensus layer.

### Reserved Addresses

Some staking account addresses are reserved to prevent them from being
accidentally used in the actual ledger.

Currently, they are:

* `oasis1qrmufhkkyyf79s5za2r8yga9gnk4t446dcy3a5zm`: common pool address
  (defined by [`CommonPoolAddress` variable]).
* `oasis1qqnv3peudzvekhulf8v3ht29z4cthkhy7gkxmph5`: per-block fee accumulator
  address (defined by [`FeeAccumulatorAddress` variable]).
* `oasis1qp65laz8zsa9a305wxeslpnkh9x4dv2h2qhjz0ec`: governance deposits address
  (defined by the [`GovernanceDeposits` variable]).

<!-- markdownlint-disable line-length -->
[runtime identifier]: ../../runtime/identifiers.md
[`AddressV0Context` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[`NewAddress` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAddress
[`AddressRuntimeV0Context` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[`NewRuntimeAddress` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewRuntimeAddress
[emitting messages]: ../../runtime/messages.md
[Bech32 encoding]:
  https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32
[`CommonPoolAddress` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[`FeeAccumulatorAddress` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[`GovernanceDeposits` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[ADR 0008]:
  https://github.com/oasisprotocol/adrs/blob/main/0008-standard-account-key-generation.md
<!-- markdownlint-enable line-length -->

### General

General accounts store account's general balance and nonce.
Nonce is the incremental number that must be unique for each account's
transaction.

### Escrow

Escrow accounts are used to hold stake delegated for specific consensus-layer
operations (e.g., registering and running nodes).
Their balance is subject to special delegation provisions and a debonding
period.

Delegation provisions, also called commissions, are specified by the
[`CommissionSchedule` field].

An escrow account also has a corresponding stake accumulator.
It stores stake claims for an escrow account and ensures all claims are
satisfied at any given point.
Adding a new claim is only possible if all of the existing claims plus the new
claim can be satisfied.

<!-- markdownlint-disable line-length -->
[`CommissionSchedule` field]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#CommissionSchedule
<!-- markdownlint-enable line-length -->

#### Delegation

When a delegator wants to delegate some of amount of stake to a staking account,
he needs to escrow stake using [Add Escrow method].

Similarly, when a delegator wants to reclaim some amount of escrowed stake back
to his general account, he needs to reclaim stake using [Reclaim Escrow method].

To simplify accounting, each escrow results in the delegator account being
issued shares which can be converted back to stake during the reclaim escrow
operation.

When a delegator delegates some amount of stake to an escrow account, the
delegator receives the number of shares proportional to the current
_share price_ (in base units) calculated from the total number of stake
delegated to an escrow account so far and the number of shares issued so far:

```
shares_per_base_unit = account_issued_shares / account_delegated_base_units
```

For example, if an escrow account has the following state:

```json
"escrow": {
    "active": {
        "balance": "250",
        "total_shares": "1000"
    },
    ...
}
```

then the current share price (i.e. `shares_per_base_unit`) is 1000 / 250 = 4.

Delegating 500 base units to this escrow account would result in 500 * 4 = 2000
newly issued shares.

Thus, the escrow account would have the following state afterwards:

```json
"escrow": {
    "active": {
        "balance": "750",
        "total_shares": "3000"
    },
    ...
}
```

When a delegator wants to reclaim a certain number of escrowed stake, the
_base unit price_ (in shares) must be calculated based on the escrow account's
current active balance and the number of issued shares:

```text
base_units_per_share = account_delegated_base_units / account_issued_shares
```

Returning to our example escrow account, the current base unit price (i.e.
`base_units_per_share`) is 750 / 3000 = 0.25.

Reclaiming 1200 shares would result in 1200 * 0.25 = 300 base units being
reclaimed.

The escrow account would have the following state afterwards:

```json
"escrow": {
    "active": {
        "balance": "450",
        "total_shares": "1800"
    },
    ...
}
```

Reclaiming escrow does not complete immediately, but may be subject to a
debonding period during in which the stake still remains escrowed.

[Add Escrow method]: #add-escrow
[Reclaim Escrow method]: #reclaim-escrow

#### Commission Schedule

A staking account can be configured to take a commission on staking rewards
given to its node(s). They are defined by the [`CommissionRateStep` type].

The commission rate must be within bounds, which the staking account can also
specify using the [`CommissionRateBoundStep` type].

The commission rates and rate bounds can change over time which is defined
by the [`CommissionSchedule` type][`CommissionSchedule` field].

To prevent unexpected changes in commission rates and rate bounds, they must
be specified a number of epochs in the future, controlled by the
[`CommissionScheduleRules` consensus parameter].

<!-- markdownlint-disable line-length -->
[`CommissionRateStep` type]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#CommissionRateStep
[`CommissionRateBoundStep` type]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#CommissionRateBoundStep
[`CommissionScheduleRules` consensus parameter]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#CommissionScheduleRules
<!-- markdownlint-enable line-length -->

## Methods

The following sections describe the methods supported by the consensus staking
service.

### Transfer

Transfer enables stake transfer between different accounts in the staking
ledger. A new transfer transaction can be generated using
[`NewTransferTx` function].

**Method name:**

```
staking.Transfer
```

**Body:**

```golang
type Transfer struct {
    To     Address           `json:"to"`
    Amount quantity.Quantity `json:"amount"`
}
```

**Fields:**

* `to` specifies the destination account's address.
* `amount` specifies the amount of base units to transfer.

The transaction signer implicitly specifies the source account.

<!-- markdownlint-disable line-length -->
[`NewTransferTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewTransferTx
<!-- markdownlint-enable line-length -->

### Burn

Burn destroys some stake in the caller's account. A new burn transaction can be
generated using [`NewBurnTx` function].

**Method name:**

```
staking.Burn
```

**Body:**

```golang
type Burn struct {
    Amount quantity.Quantity `json:"amount"`
}
```

**Fields:**

* `amount` specifies the amount of base units to burn.

The transaction signer implicitly specifies the caller's account.

<!-- markdownlint-disable line-length -->
[`NewBurnTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewBurnTx
<!-- markdownlint-enable line-length -->

### Add Escrow

Escrow transfers stake into an escrow account.
For more details, see the [Delegation section] of this document.
A new add escrow transaction can be generated using [`NewAddEscrowTx` function].

**Method name:**

```
staking.AddEscrow
```

**Body:**

```golang
type Escrow struct {
    Account Address           `json:"account"`
    Amount  quantity.Quantity `json:"amount"`
}
```

**Fields:**

* `account` specifies the destination escrow account's address.
* `amount` specifies the amount of base units to transfer.

The transaction signer implicitly specifies the source account.

<!-- markdownlint-disable line-length -->
[Delegation section]: #delegation
[`NewAddEscrowTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAddEscrowTx
<!-- markdownlint-enable line-length -->

### Reclaim Escrow

Reclaim escrow starts the escrow reclamation process.
For more details, see the [Delegation section] of this document.
A new reclaim escrow transaction can be generated using
[`NewReclaimEscrowTx` function].

**Method name:**

```
staking.ReclaimEscrow
```

**Body:**

```golang
type ReclaimEscrow struct {
    Account Address           `json:"account"`
    Shares  quantity.Quantity `json:"shares"`
}
```

**Fields:**

* `account` specifies the source escrow account's address.
* `shares` specifies the number of shares to reclaim.

The transaction signer implicitly specifies the destination account.

<!-- markdownlint-disable line-length -->
[`NewReclaimEscrowTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewReclaimEscrowTx
<!-- markdownlint-enable line-length -->

### Amend Commission Schedule

Amend commission schedule updates the commission schedule specified for the
given escrow account.
For more details, see the [Commission Schedule section] of this document.
A new amend commission schedule transaction can be
generated using [`NewAmendCommissionScheduleTx` function].

**Method name:**

```
staking.AmendCommissionSchedule
```

**Body:**

```golang
type AmendCommissionSchedule struct {
    Amendment CommissionSchedule `json:"amendment"`
}
```

**Fields:**

* `amendment` defines the amended commission schedule.

The transaction signer implicitly specifies the escrow account.

<!-- markdownlint-disable line-length -->
[Commission Schedule section]: #commission-schedule
[`NewAmendCommissionScheduleTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAmendCommissionScheduleTx
<!-- markdownlint-enable line-length -->

### Allow

Allow enables an account holder to set an allowance for a beneficiary. A new
allow transaction can be generated using [`NewAllowTx` function].

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

* `beneficiary` specifies the beneficiary account address.
* `amount_change` specifies the absolute value of the amount of base units to
  change the allowance for.
* `negative` specifies whether the `amount_change` should be subtracted instead
  of added.

The transaction signer implicitly specifies the general account. Upon executing
the allow the following actions are performed:

* If either the `disable_transfers` staking consensus parameter is set to `true`
  or the `max_allowances` staking consensus parameter is set to zero, the method
  fails with `ErrForbidden`.

* It is checked whether either the transaction signer address or the
  `beneficiary` address are reserved. If any are reserved, the method fails with
  `ErrForbidden`.

* Address specified by `beneficiary` is compared with the transaction signer
  address. If the addresses are the same, the method fails with
  `ErrInvalidArgument`.

* The account indicated by the signer is loaded.

* If the allow would create a new allowance and the maximum number of allowances
  for an account has been reached, the method fails with `ErrTooManyAllowances`.

* The set of allowances is updated so that the allowance is updated as specified
  by `amount_change`/`negative`. In case the change would cause the allowance to
  be equal to zero or negative, the allowance is removed.

* The account is saved.

* The corresponding [`AllowanceChangeEvent`] is emitted.

<!-- markdownlint-disable line-length -->
[`NewAllowTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAllowTx
[`AllowanceChangeEvent`]: #allowance-change-event
<!-- markdownlint-enable line-length -->

### Withdraw

Withdraw enables a beneficiary to withdraw from the given account. A new
withdraw transaction can be generated using [`NewWithdrawTx` function].

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

* `from` specifies the account address to withdraw from.
* `amount` specifies the amount of base units to withdraw.

The transaction signer implicitly specifies the destination general account.
Upon executing the withdrawal the following actions are performed:

* If either the `disable_transfers` staking consensus parameter is set to `true`
  or the `max_allowances` staking consensus parameter is set to zero, the method
  fails with `ErrForbidden`.

* It is checked whether either the transaction signer address or the
  `from` address are reserved. If any are reserved, the method fails with
  `ErrForbidden`.

* Address specified by `from` is compared with the transaction signer address.
  If the addresses are the same, the method fails with `ErrInvalidArgument`.

* The source account indicated by `from` is loaded.

* The destination account indicated by the transaction signer is loaded.

* `amount` is deducted from the corresponding allowance in the source account.
  If this would cause the allowance to go negative, the method fails with
  `ErrForbidden`.

* `amount` is deducted from the source general account balance. If this would
  cause the balance to go negative, the method fails with
  `ErrInsufficientBalance`.

* `amount` is added to the destination general account balance.

* Both source and destination accounts are saved.

* The corresponding [`TransferEvent`] is emitted.

* The corresponding [`AllowanceChangeEvent`] is emitted with the updated
  allowance.

<!-- markdownlint-disable line-length -->
[`NewWithdrawTx` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewWithdrawTx
[`TransferEvent`]: #transfer-event
<!-- markdownlint-enable line-length -->

## Events

### Transfer Event

The transfer event is emitted when tokens are transferred from a source account
to a destination account.

**Body:**

```golang
type TransferEvent struct {
  From   Address           `json:"from"`
  To     Address           `json:"to"`
  Amount quantity.Quantity `json:"amount"`
}
```

**Fields:**

* `from` contains the address of the source account.
* `to` contains the address of the destination account.
* `amount` contains the amount (in base units) transferred.

### Burn Event

The burn event is emitted when tokens are burned.

**Body:**

```golang
type BurnEvent struct {
  Owner  Address           `json:"owner"`
  Amount quantity.Quantity `json:"amount"`
}
```

**Fields:**

* `owner` contains the address of the account that burned tokens.
* `amount` contains the amount (in base units) burned.

### Escrow Event

Escrow events are emitted when tokens are escrowed, taken from escrow by the
protocol or reclaimed from escrow by the account owner.

**Body:**

```golang
type EscrowEvent struct {
  Add     *AddEscrowEvent     `json:"add,omitempty"`
  Take    *TakeEscrowEvent    `json:"take,omitempty"`
  Reclaim *ReclaimEscrowEvent `json:"reclaim,omitempty"`
}
```

**Fields:**

* `add` is set if the emitted event is an _Add Escrow_ event.
* `take` is set if the emitted event is a _Take Escrow_ event.
* `reclaim` is set if the emitted event is a _Reclaim Escrow_ event.

#### Add Escrow Event

The add escrow event is emitted when funds are escrowed.

**Body:**

```golang
type AddEscrowEvent struct {
  Owner     Address           `json:"owner"`
  Escrow    Address           `json:"escrow"`
  Amount    quantity.Quantity `json:"amount"`
  NewShares quantity.Quantity `json:"new_shares"`
}
```

**Fields:**

* `owner` contains the address of the source account.
* `escrow` contains the address of the destination account the tokens are being
  escrowed to.
* `amount` contains the amount (in base units) escrowed.
* `new_shares` contains the amount of shares created as a result of the added
  escrow event. Can be zero in case of (non-commissioned) rewards, where stake
  is added without new shares to increase share price.

#### Take Escrow Event

The take escrow event is emitted by the protocol when escrowed funds are
slashed for whatever reason.

**Body:**

```golang
type TakeEscrowEvent struct {
  Owner  Address           `json:"owner"`
  Amount quantity.Quantity `json:"amount"`
}
```

**Fields:**

* `owner` contains the address of the account escrow has been taken from.
* `amount` contains the amount (in base units) taken.

#### Reclaim Escrow Event

The reclaim escrow event is emitted when a reclaim escrow operation completes
successfully (after the debonding period has passed).

**Body:**

```golang
type ReclaimEscrowEvent struct {
  Owner  Address           `json:"owner"`
  Escrow Address           `json:"escrow"`
  Amount quantity.Quantity `json:"amount"`
  Shares quantity.Quantity `json:"shares"`
}
```

**Fields:**

* `owner` contains the address of the account that reclaimed tokens from escrow.
* `escrow` contains the address of the account escrow has been reclaimed from.
* `amount` contains the amount (in base units) reclaimed.
* `shares` contains the amount of shares reclaimed.

### Allowance Change Event

**Body:**

```golang
type AllowanceChangeEvent struct {
    Owner        Address           `json:"owner"`
    Beneficiary  Address           `json:"beneficiary"`
    Allowance    quantity.Quantity `json:"allowance"`
    Negative     bool              `json:"negative,omitempty"`
    AmountChange quantity.Quantity `json:"amount_change"`
}
```

**Fields:**

* `owner` contains the address of the account owner where allowance has been
  changed.
* `beneficiary` contains the address of the beneficiary.
* `allowance` contains the new total allowance.
* `amount_change` contains the absolute amount the allowance has changed for.
* `negative` specifies whether the allowance has been reduced rather than
  increased.

The event is emitted even if the new allowance is zero.

## Consensus Parameters

* `max_allowances` (uint32) specifies the maximum number of [allowances] an
  account can store. Zero means that allowance functionality is disabled.

[allowances]: #allow

## Test Vectors

To generate test vectors for various staking [transactions], run:

```bash
make -C go staking/gen_vectors
```

For more information about the structure of the test vectors see the section
on [Transaction Test Vectors].

[transactions]: ../transactions.md
[Transaction Test Vectors]: ../test-vectors.md
