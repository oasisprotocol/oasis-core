// Package memory implements the memory backed staking token backend.
package memory

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/staking/api"
)

// BackendName is the name of this implementation.
const BackendName = "memory"

var (
	_ api.Backend       = (*memoryBackend)(nil)
	_ api.EscrowBackend = (*memoryBackend)(nil)
)

type ledgerEntry struct {
	id signature.PublicKey

	generalBalance *api.Quantity
	escrowBalance  *api.Quantity
	nonce          uint64

	approvals map[signature.MapKey]*api.Quantity
}

func (ent *ledgerEntry) getAllowance(id signature.PublicKey) *api.Quantity {
	n, ok := ent.approvals[id.ToMapKey()]
	if !ok {
		return api.NewQuantity()
	}
	return n.Clone()
}

func (ent *ledgerEntry) setAllowance(id signature.PublicKey, n *api.Quantity) {
	if n.IsZero() {
		delete(ent.approvals, id.ToMapKey())
	} else {
		ent.approvals[id.ToMapKey()] = n.Clone()
	}
}

func newLedgerEntry(id signature.PublicKey) *ledgerEntry {
	return &ledgerEntry{
		id:             id,
		generalBalance: api.NewQuantity(),
		escrowBalance:  api.NewQuantity(),
		approvals:      make(map[signature.MapKey]*api.Quantity),
	}
}

type memoryBackend struct {
	sync.RWMutex

	logger *logging.Logger

	totalSupply *api.Quantity
	ledger      map[signature.MapKey]*ledgerEntry

	transferNotifier *pubsub.Broker
	approvalNotifier *pubsub.Broker
	burnNotifier     *pubsub.Broker
	escrowNotifier   *pubsub.Broker
}

func (b *memoryBackend) Name() string {
	return "Debug Stake Pls Ignore"
}

func (b *memoryBackend) Symbol() string {
	return "DBG"
}

func (b *memoryBackend) TotalSupply(ctx context.Context) (*api.Quantity, error) {
	b.RLock()
	defer b.RUnlock()

	return b.totalSupply, nil
}

func (b *memoryBackend) Accounts(ctx context.Context) ([]signature.PublicKey, error) {
	b.RLock()
	defer b.RUnlock()

	ret := make([]signature.PublicKey, 0, len(b.ledger))
	for _, v := range b.ledger {
		if !v.generalBalance.IsZero() || !v.escrowBalance.IsZero() {
			ret = append(ret, v.id)
		}
	}

	return ret, nil
}

func (b *memoryBackend) AccountInfo(ctx context.Context, owner signature.PublicKey) (*api.Quantity, *api.Quantity, uint64, error) {
	b.RLock()
	defer b.RUnlock()

	v, ok := b.ledger[owner.ToMapKey()]
	if !ok {
		// No such thing as a non-existent account.  All accounts are valid,
		// most are just empty.  So just return the default uninitialized
		// values for everything.
		return api.NewQuantity(), api.NewQuantity(), 0, nil
	}

	return v.generalBalance.Clone(), v.escrowBalance.Clone(), v.nonce, nil
}

func (b *memoryBackend) Transfer(ctx context.Context, signedXfer *api.SignedTransfer) error {
	var xfer api.Transfer
	if signedXfer == nil {
		return api.ErrInvalidArgument
	}

	if err := signedXfer.Open(api.TransferSignatureContext, &xfer); err != nil {
		b.logger.Error("Transfer: invalid signature",
			"signed_xfer", signedXfer,
		)
		return api.ErrInvalidSignature
	}

	b.Lock()
	defer b.Unlock()

	from := b.getLedgerEntryLocked(signedXfer.Signature.PublicKey)
	if from.nonce != xfer.Nonce {
		b.logger.Error("Transfer: invalid account nonce",
			"id", from.id,
			"account_nonce", from.nonce,
			"xfer_nonce", xfer.Nonce,
		)
		return api.ErrInvalidNonce
	}

	to := b.getLedgerEntryLocked(xfer.To)

	if err := api.Move(to.generalBalance, from.generalBalance, &xfer.Tokens); err != nil {
		b.logger.Error("Transfer: failed to move balance",
			"err", err,
			"from", from.id,
			"to", to.id,
			"amount", xfer.Tokens,
		)
		return err
	}

	from.nonce++
	b.setLedgerEntryLocked(from)
	b.setLedgerEntryLocked(to)

	b.logger.Debug("Transfer: executed transfer",
		"from", from.id,
		"to", to.id,
		"amount", xfer.Tokens,
	)

	b.transferNotifier.Broadcast(&api.TransferEvent{
		From:   signedXfer.Signature.PublicKey,
		To:     xfer.To,
		Tokens: xfer.Tokens,
	})

	return nil
}

func (b *memoryBackend) Allowance(ctx context.Context, owner, spender signature.PublicKey) (*api.Quantity, error) {
	b.RLock()
	defer b.RUnlock()

	from, ok := b.ledger[owner.ToMapKey()]
	if !ok {
		return api.NewQuantity(), nil
	}

	qty, ok := from.approvals[spender.ToMapKey()]
	if !ok {
		return api.NewQuantity(), nil
	}

	return qty, nil
}

func (b *memoryBackend) Approve(ctx context.Context, signedApproval *api.SignedApproval) error {
	var approval api.Approval
	if signedApproval == nil {
		return api.ErrInvalidArgument
	}

	if err := signedApproval.Open(api.ApproveSignatureContext, &approval); err != nil {
		b.logger.Error("Approve: invalid signature",
			"signed_approval", signedApproval,
		)
		return api.ErrInvalidSignature
	}

	if !approval.Tokens.IsValid() {
		b.logger.Error("Approve: invalid approval quantity",
			"id", signedApproval.Signature.PublicKey,
			"spender", approval.Spender,
			"amount", approval.Tokens,
		)
		return api.ErrInvalidArgument
	}

	b.Lock()
	defer b.Unlock()

	from := b.getLedgerEntryLocked(signedApproval.Signature.PublicKey)
	if from.nonce != approval.Nonce {
		b.logger.Error("Approve: invalid account nonce",
			"id", from.id,
			"account_nonce", from.nonce,
			"approval_nonce", approval.Nonce,
		)
		return api.ErrInvalidNonce
	}

	from.nonce++
	from.setAllowance(approval.Spender, &approval.Tokens)
	b.setLedgerEntryLocked(from)

	b.logger.Debug("Approve: executed approval",
		"from", from.id,
		"spender", approval.Spender,
		"amount", approval.Tokens,
	)

	b.approvalNotifier.Broadcast(&api.ApprovalEvent{
		Owner:   signedApproval.Signature.PublicKey,
		Spender: approval.Spender,
		Tokens:  approval.Tokens,
	})

	return nil
}

func (b *memoryBackend) Withdraw(ctx context.Context, signedWithdrawal *api.SignedWithdrawal) error {
	var withdrawal api.Withdrawal
	if signedWithdrawal == nil {
		return api.ErrInvalidArgument
	}

	if err := signedWithdrawal.Open(api.WithdrawSignatureContext, &withdrawal); err != nil {
		b.logger.Error("Withdraw: invalid signature",
			"signed_withdrawal", signedWithdrawal,
		)
		return api.ErrInvalidSignature
	}

	b.Lock()
	defer b.Unlock()

	from := b.getLedgerEntryLocked(withdrawal.From)
	if from.nonce != withdrawal.Nonce {
		b.logger.Error("Withdraw: invalid account nonce",
			"id", from.id,
			"account_nonce", from.nonce,
			"withdrawal_nonce", withdrawal.Nonce,
		)
		return api.ErrInvalidNonce
	}

	to := b.getLedgerEntryLocked(signedWithdrawal.Signature.PublicKey)

	// Ensure there is sufficient allowance.
	allowance := from.getAllowance(to.id)
	if err := allowance.Sub(&withdrawal.Tokens); err != nil {
		b.logger.Error("Withdraw: insufficent allowance",
			"id", from.id,
			"spender", to.id,
			"amount", withdrawal.Tokens,
		)
		return api.ErrInsufficientAllowance
	}

	if err := api.Move(to.generalBalance, from.generalBalance, &withdrawal.Tokens); err != nil {
		b.logger.Error("Withdraw: failed to move balance",
			"err", err,
			"from", from.id,
			"to", to.id,
			"amount", withdrawal.Tokens,
		)
		return err
	}

	from.nonce++
	from.setAllowance(to.id, allowance)
	b.setLedgerEntryLocked(from)
	b.setLedgerEntryLocked(to)

	b.logger.Debug("Withdraw: executed withdrawal",
		"from", from.id,
		"to", to.id,
		"amount", withdrawal.Tokens,
	)

	b.transferNotifier.Broadcast(&api.TransferEvent{
		From:   withdrawal.From,
		To:     signedWithdrawal.Signature.PublicKey,
		Tokens: withdrawal.Tokens,
	})

	return nil
}

func (b *memoryBackend) Burn(ctx context.Context, signedBurn *api.SignedBurn) error {
	var burn api.Burn
	if signedBurn == nil {
		return api.ErrInvalidArgument
	}

	if err := signedBurn.Open(api.BurnSignatureContext, &burn); err != nil {
		b.logger.Error("Burn: invalid signature",
			"signed_burn", signedBurn,
		)
		return api.ErrInvalidSignature
	}

	b.Lock()
	defer b.Unlock()

	from := b.getLedgerEntryLocked(signedBurn.Signature.PublicKey)
	if from.nonce != burn.Nonce {
		b.logger.Error("Burn: invalid account nonce",
			"id", from.id,
			"account_nonce", from.nonce,
			"burn_nonce", burn.Nonce,
		)
		return api.ErrInvalidNonce
	}

	if err := from.generalBalance.Sub(&burn.Tokens); err != nil {
		b.logger.Error("Burn: failed to burn tokens",
			"err", err,
			"from", from.id,
			"amount", burn.Tokens,
		)
		return err
	}

	from.nonce++
	b.setLedgerEntryLocked(from)
	_ = b.totalSupply.Sub(&burn.Tokens)

	b.logger.Debug("Burn: burnt tokens",
		"from", from.id,
		"amount", burn.Tokens,
	)

	b.burnNotifier.Broadcast(&api.BurnEvent{
		Owner:  signedBurn.Signature.PublicKey,
		Tokens: burn.Tokens,
	})

	return nil
}

func (b *memoryBackend) AddEscrow(ctx context.Context, signedEscrow *api.SignedEscrow) error {
	var escrow api.Escrow
	if signedEscrow == nil {
		return api.ErrInvalidArgument
	}

	if err := signedEscrow.Open(api.EscrowSignatureContext, &escrow); err != nil {
		b.logger.Error("AddEscrow: invalid signature",
			"signed_escrow", signedEscrow,
		)
		return api.ErrInvalidSignature
	}

	b.Lock()
	defer b.Unlock()

	from := b.getLedgerEntryLocked(signedEscrow.Signature.PublicKey)
	if from.nonce != escrow.Nonce {
		b.logger.Error("AddEscrow: invalid account nonce",
			"id", from.id,
			"account_nonce", from.nonce,
			"escrow_nonce", escrow.Nonce,
		)
		return api.ErrInvalidNonce
	}

	if err := api.Move(from.escrowBalance, from.generalBalance, &escrow.Tokens); err != nil {
		b.logger.Error("AddEscrow: failed to escrow tokens",
			"err", err,
			"from", from.id,
			"amount", escrow.Tokens,
		)
		return err
	}

	from.nonce++
	b.setLedgerEntryLocked(from)

	b.logger.Debug("AddEscrow: escrowed tokens",
		"from", from.id,
		"amount", escrow.Tokens,
	)

	b.escrowNotifier.Broadcast(&api.EscrowEvent{
		Owner:  signedEscrow.Signature.PublicKey,
		Tokens: escrow.Tokens,
	})

	return nil
}

func (b *memoryBackend) TakeEscrow(ctx context.Context, owner signature.PublicKey, tokens *api.Quantity) error {
	b.Lock()
	defer b.Unlock()

	from, ok := b.ledger[owner.ToMapKey()]
	if !ok {
		b.logger.Error("TakeEscrow: invalid owner",
			"id", owner,
		)
		return api.ErrInvalidAccount
	}

	var discard api.Quantity // Just do a burn for now.
	moved, err := api.MoveUpTo(&discard, from.escrowBalance, tokens)
	if err != nil {
		b.logger.Error("TakeEscrow: failed to take escrow",
			"err", err,
			"id", from.id,
		)
		return err
	}

	b.setLedgerEntryLocked(from)
	_ = b.totalSupply.Sub(moved)

	b.logger.Debug("TakeEscrow: took escrow",
		"from", from.id,
		"amount", moved,
	)

	b.escrowNotifier.Broadcast(&api.TakeEscrowEvent{
		Owner:  owner,
		Tokens: *moved,
	})

	return nil
}

func (b *memoryBackend) ReleaseEscrow(ctx context.Context, owner signature.PublicKey) error {
	b.Lock()
	defer b.Unlock()

	from, ok := b.ledger[owner.ToMapKey()]
	if !ok {
		b.logger.Error("ReleaseEscrow: invalid owner",
			"id", owner,
		)
		return api.ErrInvalidAccount
	}

	balance := from.escrowBalance.Clone()
	if err := api.Move(from.generalBalance, from.escrowBalance, balance); err != nil {
		b.logger.Error("ReleaseEscrow: failed to shift balance",
			"err", err,
			"id", from.id,
		)
		return err
	}

	b.setLedgerEntryLocked(from)

	b.logger.Debug("ReleaseEscrow: released escrow",
		"from", from.id,
		"amount", balance,
	)

	b.escrowNotifier.Broadcast(&api.ReleaseEscrowEvent{
		Owner:  owner,
		Tokens: *balance,
	})

	return nil
}

func (b *memoryBackend) WatchTransfers() (<-chan *api.TransferEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.TransferEvent)
	sub := b.transferNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (b *memoryBackend) WatchApprovals() (<-chan *api.ApprovalEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.ApprovalEvent)
	sub := b.approvalNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (b *memoryBackend) WatchBurns() (<-chan *api.BurnEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.BurnEvent)
	sub := b.burnNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (b *memoryBackend) WatchEscrows() (<-chan interface{}, *pubsub.Subscription) {
	sub := b.escrowNotifier.Subscribe()
	return sub.Untyped(), sub
}

func (b *memoryBackend) Cleanup() {
	// No cleanup required.
}

func (b *memoryBackend) getLedgerEntryLocked(id signature.PublicKey) *ledgerEntry {
	mapKey := id.ToMapKey()
	ent, ok := b.ledger[mapKey]
	if !ok {
		ent = newLedgerEntry(id)
	}

	return ent
}

func (b *memoryBackend) setLedgerEntryLocked(ent *ledgerEntry) {
	b.ledger[ent.id.ToMapKey()] = ent
}

// New constructs a new mmeory backed staking Backend instance.
func New(debugGenesisState *api.GenesisState) (api.Backend, error) {
	b := &memoryBackend{
		logger:           logging.GetLogger("staking/memory"),
		totalSupply:      api.NewQuantity(),
		ledger:           make(map[signature.MapKey]*ledgerEntry),
		transferNotifier: pubsub.NewBroker(false),
		approvalNotifier: pubsub.NewBroker(false),
		burnNotifier:     pubsub.NewBroker(false),
		escrowNotifier:   pubsub.NewBroker(false),
	}

	if debugGenesisState != nil {
		// Populate initial entries.
		var totalSupply api.Quantity
		for k, v := range debugGenesisState.Ledger {
			var id signature.PublicKey
			if err := id.UnmarshalBinary(k[:]); err != nil {
				return nil, errors.Wrap(err, "staking/memory: malformed genesis entry ID")
			}

			ent := newLedgerEntry(id)
			ent.generalBalance = v

			b.ledger[k] = ent

			if err := totalSupply.Add(v); err != nil {
				return nil, errors.Wrap(err, "staking/memory: malformed genesis entry balance")
			}
		}

		// And set the total supply.
		b.totalSupply = &totalSupply
	}

	return b, nil
}
