# Staking

The staking service is responsible for managing the staking ledger in the
consensus layer. It enables operations like transferring stake between accounts
and escrowing stake for specific needs (e.g., operating nodes).

The service interface definition lives in [`go/staking/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[`go/staking/api`]: ../../go/staking/api
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
[ 1 byte <ctx-version> ][ first 20 bytes of SHA512-256(<ctx-identifier> || <ctx-version> || <pubkey>) ]
```
<!-- markdownlint-disable line-length -->

where `<ctx-version>` and `<ctx-identifier>` represent the staking account
address' context version and identifier as defined by the
[`AddressV0Context` variable],
and `<pubkey>` represents the account signer's public key (e.g. entity id).

For more details, see the [`NewAddress` function].

Addresses use [Bech32 encoding] for text serialization with `oasis` as its human
readable part (HRP) prefix.

### Reserved addresses

Some staking account addresses are reserved to prevent them from being
accidentally used in the actual ledger.

Currently, they are:

* `oasis1qrmufhkkyyf79s5za2r8yga9gnk4t446dcy3a5zm`: common pool address
  (defined by [`CommonPoolAddress` variable]).
* `oasis1qqnv3peudzvekhulf8v3ht29z4cthkhy7gkxmph5`: per-block fee accumulator
  address (defined by [`FeeAccumulatorAddress` variable]).

<!-- markdownlint-disable line-length -->
[`AddressV0Context` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[`NewAddress` function]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAddress
[Bech32 encoding]:
  https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32
[`CommonPoolAddress` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
[`FeeAccumulatorAddress` variable]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#pkg-variables
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

## Events

## Test Vectors

To generate test vectors for various staking [transactions], run:

```bash
make -C go staking/gen_vectors
```

For more information about the structure of the test vectors see the section
on [Transaction Test Vectors].

[transactions]: transactions.md
[Transaction Test Vectors]: test-vectors.md
