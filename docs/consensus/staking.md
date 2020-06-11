# Staking

The staking service is responsible for managing the staking ledger in the
consensus layer. It enables operations like transfering tokens between accounts
and escrowing tokens for specific needs (e.g., operating nodes).

The service interface definition lives in [`go/staking/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[`go/staking/api`]: ../../go/staking/api
[consensus service API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc
<!-- markdownlint-enable line-length -->

## Test Vectors

To generate test vectors for various staking [transactions], run:

```bash
make -C go test-vectors/staking
```

[transactions]: transactions.md

## Accounts

### General

### Escrow

### Commission Schedule

## Delegation

## Methods

### Transfer

Transfer enables token transfer between different accounts in the staking
ledger. A new transfer transaction can be generated using [`NewTransferTx`].

**Method name:**

```
staking.Transfer
```

**Body:**

```golang
type Transfer struct {
    To     Address           `json:"xfer_to"`
    Tokens quantity.Quantity `json:"xfer_tokens"`
}
```

**Fields:**

* `xfer_to` specifies the destination account's address.
* `xfer_tokens` specifies the amount of tokens to transfer.

The transaction signer implicitly specifies the source account.

<!-- markdownlint-disable line-length -->
[`NewTransferTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewTransferTx
<!-- markdownlint-enable line-length -->

### Burn

Burn destroys some tokens in the caller's account. A new burn transaction can be
generated using [`NewBurnTx`].

**Method name:**

```
staking.Burn
```

**Body:**

```golang
type Burn struct {
    Tokens quantity.Quantity `json:"burn_tokens"`
}
```

**Fields:**

* `burn_tokens` specifies the amount of tokens to burn.

The transaction signer implicitly specifies the caller's account.

<!-- markdownlint-disable line-length -->
[`NewBurnTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewBurnTx
<!-- markdownlint-enable line-length -->

### Add Escrow

Escrow transfers tokens into an escrow account. Escrow accounts are used to keep
the funds needed for specific consensus-layer operations (e.g., registering and
running nodes). To simplify accounting, each escrow results in the source
account being issued shares which can be converted back into staking tokens
during the reclaim escrow operation. A new add escrow transaction can be
generated using [`NewAddEscrowTx`].

**Method name:**

```
staking.AddEscrow
```

**Body:**

```golang
type Escrow struct {
    Account Address           `json:"escrow_account"`
    Tokens  quantity.Quantity `json:"escrow_tokens"`
}
```

**Fields:**

* `escrow_account` specifies the destination escrow account's address.
* `escrow_tokens` specifies the amount of tokens to transfer.

The transaction signer implicitly specifies the source account.

<!-- markdownlint-disable line-length -->
[`NewAddEscrowTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAddEscrowTx
<!-- markdownlint-enable line-length -->

### Reclaim Escrow

Reclaim escrow starts the escrow reclamation process. The process does not
complete immediately but may be subject to a debonding period during which the
tokens still remain escrowed. A new reclaim escrow transaction can be generated
using [`NewReclaimEscrowTx`].

**Method name:**

```
staking.ReclaimEscrow
```

**Body:**

```golang
type ReclaimEscrow struct {
    Account Address           `json:"escrow_account"`
    Shares  quantity.Quantity `json:"reclaim_shares"`
}
```

**Fields:**

* `escrow_account` specifies the source escrow account's address.
* `reclaim_shares` specifies the amount of shares to reclaim.

The transaction signer implicitly specifies the destination account.

<!-- markdownlint-disable line-length -->
[`NewReclaimEscrowTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewReclaimEscrowTx
<!-- markdownlint-enable line-length -->

### Amend Commission Schedule

Amend commission schedule updates the commission schedule specified for the
given escrow account. A new amend commission schedule transaction can be
generated using [`NewAmendCommissionScheduleTx`].

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
[`NewAmendCommissionScheduleTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#NewAmendCommissionScheduleTx
<!-- markdownlint-enable line-length -->

## Events
