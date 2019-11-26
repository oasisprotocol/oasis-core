# Staking

The staking component is responsible for managing the staking ledger in the consensus layer. It
enables operations like transfering tokens between accounts and escrowing tokens for specific
needs (e.g., operating nodes).

Links:
* [API definition](../../go/staking/api).

### Test Vectors

To generate test vectors for various staking transactions, run:
```bash
$ make -C go test-vectors/staking
```

## Accounts

_TODO: Say something about our accounts._

### General

### Escrow

### Commission Schedule

## Delegation

_TODO: Say something about how delegation works._

## Methods

Each staking method takes a method-specific body as an argument.

### Transfer

Transfer enables token transfer between different accounts in the staking ledger.

Method name:
```
staking.Transfer
```

Body:
```golang
type Transfer struct {
    To     signature.PublicKey `json:"xfer_to"`
    Tokens quantity.Quantity   `json:"xfer_tokens"`
}
```

The transaction signer implicitly specifies the source account.

Fields:
* `xfer_to` specifies the destination account.
* `xfer_tokens` specifies the amount of tokens to transfer.

### Burn

Burn destroys some tokens in the caller's account.

Method name:
```
staking.Burn
```

Body:
```golang
type Burn struct {
    Tokens quantity.Quantity `json:"burn_tokens"`
}
```

The transaction signer implicitly specifies the caller's account.

Fields:
* `burn_tokens` specifies the amount of tokens to burn.

### Add Escrow

Escrow transfers tokens into an escrow account. Escrow accounts are used to keep the funds needed
for specific consensus-layer operations (e.g., registering and running nodes). To simplify
accounting, each escrow results in the source account being issued shares which can be converted
back into staking tokens during the reclaim escrow operation.

Method name:
```
staking.AddEscrow
```

Body:
```golang
type Escrow struct {
    Account signature.PublicKey `json:"escrow_account"`
    Tokens  quantity.Quantity   `json:"escrow_tokens"`
}
```

The transaction signer implicitly specifies the source account.

Fields:
* `escrow_account` specifies the destination escrow account.
* `escrow_tokens` specifies the amount of tokens to transfer.

### Reclaim Escrow

Reclaim escrow starts the escrow reclamation process. The process does not complete immediately but
may be subject to a debonding period during which the tokens still remain escrowed.

Method name:
```
staking.ReclaimEscrow
```

Body:
```golang
type ReclaimEscrow struct {
    Account signature.PublicKey `json:"escrow_account"`
    Shares  quantity.Quantity   `json:"reclaim_shares"`
}
```

The transaction signer implicitly specifies the destination account.

Fields:
* `escrow_account` specifies the source escrow account.
* `reclaim_shares` specifies the amount of shares to reclaim.

### Amend Commission Schedule

Method name:
```
staking.AmendCommissionSchedule
```

Body:
```golang
type AmendCommissionSchedule struct {
    Amendment CommissionSchedule `json:"amendment"`
}
```

The transaction signer implicitly specifies the escrow account.

Fields:
* `amendment` defines the amended commission schedule.

## Events

_TODO_
