// Package api implements the staking backend API.
package api

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

const (
	// ModuleName is a unique module name for the staking module.
	ModuleName = "staking"

	// TokenName is the name of the staking token.
	TokenName = "Buffycoin"

	// TokenSymbol is the symbol of the staking token.
	TokenSymbol = "BUF"

	// LogEventGeneralAdjustment is a log event value that signals adjustment
	// of an account's general balance due to a roothash message.
	LogEventGeneralAdjustment = "staking/general_adjustment"
)

var (
	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New(ModuleName, 1, "staking: invalid argument")

	// ErrInvalidSignature is the error returned on invalid signature.
	ErrInvalidSignature = errors.New(ModuleName, 2, "staking: invalid signature")

	// ErrInsufficientBalance is the error returned when an operation
	// fails due to insufficient balance.
	ErrInsufficientBalance = errors.New(ModuleName, 3, "staking: insufficient balance")

	// ErrInsufficientStake is the error returned when an operation fails
	// due to insufficient stake.
	ErrInsufficientStake = errors.New(ModuleName, 4, "staking: insufficient stake")

	// MethodTransfer is the method name for transfers.
	MethodTransfer = transaction.NewMethodName(ModuleName, "Transfer", Transfer{})
	// MethodBurn is the method name for burns.
	MethodBurn = transaction.NewMethodName(ModuleName, "Burn", Burn{})
	// MethodAddEscrow is the method name for escrows.
	MethodAddEscrow = transaction.NewMethodName(ModuleName, "AddEscrow", Escrow{})
	// MethodReclaimEscrow is the method name for escrow reclamations.
	MethodReclaimEscrow = transaction.NewMethodName(ModuleName, "ReclaimEscrow", ReclaimEscrow{})
	// MethodAmendCommissionSchedule is the method name for amending commission schedules.
	MethodAmendCommissionSchedule = transaction.NewMethodName(ModuleName, "AmendCommissionSchedule", AmendCommissionSchedule{})

	// Methods is the list of all methods supported by the staking backend.
	Methods = []transaction.MethodName{
		MethodTransfer,
		MethodBurn,
		MethodAddEscrow,
		MethodReclaimEscrow,
		MethodAmendCommissionSchedule,
	}
)

// Backend is a staking token implementation.
type Backend interface {
	// Name is the name of the token.
	Name() string

	// Symbol is the symbol of the token.
	Symbol() string

	// TotalSupply returns the total number of tokens.
	TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error)

	// CommonPool returns the common pool balance.
	CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error)

	// Threshold returns the specific staking threshold by kind.
	Threshold(ctx context.Context, kind ThresholdKind, height int64) (*quantity.Quantity, error)

	// Accounts returns the IDs of all accounts with a non-zero general
	// or escrow balance.
	Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error)

	// AccountInfo returns the account descriptor for the given account.
	AccountInfo(ctx context.Context, owner signature.PublicKey, height int64) (*Account, error)

	// DebondingDelegations returns the list of debonding delegations for
	// the given owner (delegator).
	DebondingDelegations(ctx context.Context, owner signature.PublicKey, height int64) (map[signature.PublicKey][]*DebondingDelegation, error)

	// WatchTransfers returns a channel that produces a stream of TranserEvent
	// on all balance transfers.
	WatchTransfers(ctx context.Context) (<-chan *TransferEvent, pubsub.ClosableSubscription, error)

	// WatchBurns returns a channel of BurnEvent on token destruction.
	WatchBurns(ctx context.Context) (<-chan *BurnEvent, pubsub.ClosableSubscription, error)

	// WatchEscrows returns a channel that produces a stream of `*EscrowEvent`,
	// `*TakeEscrowEvent`, and `*ReleaseEscrowEvent` when entities add to their
	// escrow balance, get tokens deducted from their escrow balance, and
	// have their escrow balance released into their general balance
	// respectively.
	WatchEscrows(ctx context.Context) (<-chan interface{}, pubsub.ClosableSubscription, error)

	// ToGenesis returns the genesis state at specified block height.
	ToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// Cleanup cleans up the backend.
	Cleanup()
}

// TransferEvent is the event emitted when a balance is transfered, either by
// a call to Transfer or Withdraw.
type TransferEvent struct {
	From   signature.PublicKey `json:"from"`
	To     signature.PublicKey `json:"to"`
	Tokens quantity.Quantity   `json:"tokens"`
}

// BurnEvent is the event emitted when tokens are destroyed via a call to Burn.
type BurnEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Tokens quantity.Quantity   `json:"tokens"`
}

// EscrowEvent is the event emitted when a balance is transfered into a escrow
// balance.
type EscrowEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Escrow signature.PublicKey `json:"escrow"`
	Tokens quantity.Quantity   `json:"tokens"`
}

// TakeEscrowEvent is the event emitted when balanace is deducted from a escrow
// balance (stake is slashed).
type TakeEscrowEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Tokens quantity.Quantity   `json:"tokens"`
}

// ReclaimEscrowEvent is the event emitted when tokens are relaimed from a
// escrow balance back into the entitie's general balance.
type ReclaimEscrowEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Escrow signature.PublicKey `json:"escrow"`
	Tokens quantity.Quantity   `json:"tokens"`
}

// Transfer is a token transfer.
type Transfer struct {
	To     signature.PublicKey `json:"xfer_to"`
	Tokens quantity.Quantity   `json:"xfer_tokens"`
}

// NewTransferTx creates a new transfer transaction.
func NewTransferTx(nonce uint64, fee *transaction.Fee, xfer *Transfer) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodTransfer, xfer)
}

// Burn is a token burn (destruction).
type Burn struct {
	Tokens quantity.Quantity `json:"burn_tokens"`
}

// NewBurnTx creates a new burn transaction.
func NewBurnTx(nonce uint64, fee *transaction.Fee, burn *Burn) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodBurn, burn)
}

// Escrow is a token escrow.
type Escrow struct {
	Account signature.PublicKey `json:"escrow_account"`
	Tokens  quantity.Quantity   `json:"escrow_tokens"`
}

// NewAddEscrowTx creates a new add escrow transaction.
func NewAddEscrowTx(nonce uint64, fee *transaction.Fee, escrow *Escrow) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAddEscrow, escrow)
}

// ReclaimEscrow is a token escrow reclimation.
type ReclaimEscrow struct {
	Account signature.PublicKey `json:"escrow_account"`
	Shares  quantity.Quantity   `json:"reclaim_shares"`
}

// NewReclaimEscrowTx creates a new reclaim escrow transaction.
func NewReclaimEscrowTx(nonce uint64, fee *transaction.Fee, reclaim *ReclaimEscrow) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodReclaimEscrow, reclaim)
}

// AmendCommissionSchedule is an amendment to a commission schedule.
type AmendCommissionSchedule struct {
	Amendment CommissionSchedule `json:"amendment"`
}

// NewAmendCommissionScheduleTx creates a new amend commission schedule transaction.
func NewAmendCommissionScheduleTx(nonce uint64, fee *transaction.Fee, amend *AmendCommissionSchedule) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAmendCommissionSchedule, amend)
}

// SharePool is a combined balance of several entries, the relative sizes
// of which are tracked through shares.
type SharePool struct {
	Balance     quantity.Quantity `json:"balance"`
	TotalShares quantity.Quantity `json:"total_shares"`
}

// sharesForTokens computes the amount of shares for the given amount of tokens.
func (p *SharePool) sharesForTokens(amount *quantity.Quantity) (*quantity.Quantity, error) {
	if p.TotalShares.IsZero() {
		// No existing shares, exchange rate is 1:1.
		return amount.Clone(), nil
	}
	if p.Balance.IsZero() {
		// This can happen if the pool has no balance due to
		// losing everything through slashing. In this case there is no
		// way to create more shares.
		return nil, ErrInvalidArgument
	}

	// Exchange rate is based on issued shares and the total balance as:
	//
	//     shares = amount * total_shares / balance
	//
	q := amount.Clone()
	// Multiply first.
	if err := q.Mul(&p.TotalShares); err != nil {
		return nil, err
	}
	if err := q.Quo(&p.Balance); err != nil {
		return nil, err
	}

	return q, nil
}

// Deposit moves tokens into the combined balance, raising the shares.
// If an error occurs, the pool and affected accounts are left in an invalid state.
func (p *SharePool) Deposit(shareDst, tokenSrc, tokenAmount *quantity.Quantity) error {
	shares, err := p.sharesForTokens(tokenAmount)
	if err != nil {
		return err
	}

	if err = quantity.Move(&p.Balance, tokenSrc, tokenAmount); err != nil {
		return err
	}

	if err = p.TotalShares.Add(shares); err != nil {
		return err
	}

	if err = shareDst.Add(shares); err != nil {
		return err
	}

	return nil
}

// tokensForShares computes the amount of tokens for the given amount of shares.
func (p *SharePool) tokensForShares(amount *quantity.Quantity) (*quantity.Quantity, error) {
	if amount.IsZero() || p.Balance.IsZero() || p.TotalShares.IsZero() {
		// No existing shares or no balance means no tokens.
		return quantity.NewQuantity(), nil
	}

	// Exchange rate is based on issued shares and the total balance as:
	//
	//     tokens = shares * balance / total_shares
	//
	q := amount.Clone()
	// Multiply first.
	if err := q.Mul(&p.Balance); err != nil {
		return nil, err
	}
	if err := q.Quo(&p.TotalShares); err != nil {
		return nil, err
	}

	return q, nil
}

// Withdraw moves tokens out of the combined balance, reducing the shares.
// If an error occurs, the pool and affected accounts are left in an invalid state.
func (p *SharePool) Withdraw(tokenDst, shareSrc, shareAmount *quantity.Quantity) error {
	tokens, err := p.tokensForShares(shareAmount)
	if err != nil {
		return err
	}

	if err = shareSrc.Sub(shareAmount); err != nil {
		return err
	}

	if err = p.TotalShares.Sub(shareAmount); err != nil {
		return err
	}

	if err = quantity.Move(tokenDst, &p.Balance, tokens); err != nil {
		return err
	}

	return nil
}

// ThresholdKind is the kind of staking threshold.
type ThresholdKind int

const (
	KindEntity    ThresholdKind = 0
	KindValidator ThresholdKind = 1
	KindCompute   ThresholdKind = 2
	KindStorage   ThresholdKind = 3

	KindMax = KindStorage
)

// String returns the string representation of a ThresholdKind.
func (k ThresholdKind) String() string {
	switch k {
	case KindEntity:
		return "entity"
	case KindValidator:
		return "validator"
	case KindCompute:
		return "compute"
	case KindStorage:
		return "storage"
	default:
		return "[unknown threshold kind]"
	}
}

// GeneralAccount is a general-purpose account.
type GeneralAccount struct {
	Balance quantity.Quantity `json:"balance"`
	Nonce   uint64            `json:"nonce"`
}

// EscrowAccount is an escrow account the balance of which is subject to
// special delegation provisions and a debonding period.
type EscrowAccount struct {
	Active             SharePool          `json:"active"`
	Debonding          SharePool          `json:"debonding"`
	CommissionSchedule CommissionSchedule `json:"commission_schedule"`
}

// Account is an entry in the staking ledger.
//
// The same ledger entry can hold both general and escrow accounts. Escrow
// acounts are used to hold funds delegated for staking.
type Account struct {
	General GeneralAccount `json:"general"`
	Escrow  EscrowAccount  `json:"escrow"`
}

// Delegation is a delegation descriptor.
type Delegation struct {
	Shares quantity.Quantity `json:"shares"`
}

// DebondingDelegation is a debonding delegation descriptor.
type DebondingDelegation struct {
	Shares        quantity.Quantity   `json:"shares"`
	DebondEndTime epochtime.EpochTime `json:"debond_end"`
}

// Genesis is the initial ledger balances at genesis for use in the genesis
// block and test cases.
type Genesis struct {
	Parameters ConsensusParameters `json:"params"`

	TotalSupply quantity.Quantity `json:"total_supply"`
	CommonPool  quantity.Quantity `json:"common_pool"`

	Ledger map[signature.PublicKey]*Account `json:"ledger,omitempty"`

	Delegations          map[signature.PublicKey]map[signature.PublicKey]*Delegation            `json:"delegations,omitempty"`
	DebondingDelegations map[signature.PublicKey]map[signature.PublicKey][]*DebondingDelegation `json:"debonding_delegations,omitempty"`
}

// ConsensusParameters are the staking consensus parameters.
type ConsensusParameters struct {
	Thresholds              map[ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
	DebondingInterval       epochtime.EpochTime                 `json:"debonding_interval,omitempty"`
	RewardSchedule          []RewardStep                        `json:"reward_schedule,omitempty"`
	CommissionScheduleRules CommissionScheduleRules             `json:"commission_schedule_rules,omitempty"`
	AcceptableTransferPeers map[signature.PublicKey]bool        `json:"acceptable_transfer_peers,omitempty"`
	Slashing                map[SlashReason]Slash               `json:"slashing,omitempty"`
	GasCosts                transaction.Costs                   `json:"gas_costs,omitempty"`
	MinDelegationAmount     quantity.Quantity                   `json:"min_delegation,omitempty"`
}

const (
	// GasOpTransfer is the gas operation identifier for transfer.
	GasOpTransfer transaction.Op = "transfer"
	// GasOpBurn is the gas operation identifier for burn.
	GasOpBurn transaction.Op = "burn"
	// GasOpAddEscrow is the gas operation identifier for add escrow.
	GasOpAddEscrow transaction.Op = "add_escrow"
	// GasOpReclaimEscrow is the gas operation identifier for reclaim escrow.
	GasOpReclaimEscrow transaction.Op = "reclaim_escrow"
	// GasOpAmendCommissionSchedule is the gas operation identifier for amend commission schedule.
	GasOpAmendCommissionSchedule transaction.Op = "amend_commission_schedule"
)

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	// Thresholds.
	if p.Thresholds != nil {
		for k, v := range p.Thresholds {
			if !v.IsValid() {
				return fmt.Errorf("invalid value for threshold: %s", k)
			}
		}
	}

	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(now epochtime.EpochTime) error { // nolint: gocyclo
	for thr, val := range g.Parameters.Thresholds {
		if !val.IsValid() {
			return fmt.Errorf("staking: sanity check failed: threshold '%s' has invalid value", thr.String())
		}
	}

	if !g.TotalSupply.IsValid() {
		return fmt.Errorf("staking: sanity check failed: total supply is invalid")
	}

	if !g.CommonPool.IsValid() {
		return fmt.Errorf("staking: sanity check failed: common pool is invalid")
	}

	// Check if the total supply adds up (common pool + all balances in the ledger).
	// Check all commission schedules.
	var total quantity.Quantity
	for id, acct := range g.Ledger {
		if !acct.General.Balance.IsValid() {
			return fmt.Errorf("staking: sanity check failed: account balance is invalid")
		}
		if !acct.Escrow.Active.Balance.IsValid() {
			return fmt.Errorf("staking: sanity check failed: escrow account active balance is invalid")
		}
		if !acct.Escrow.Debonding.Balance.IsValid() {
			return fmt.Errorf("staking: sanity check failed: escrow account debonding balance is invalid")
		}

		_ = total.Add(&acct.General.Balance)
		_ = total.Add(&acct.Escrow.Active.Balance)
		_ = total.Add(&acct.Escrow.Debonding.Balance)

		commissionStateShallowCopy := acct.Escrow.CommissionSchedule
		if err := commissionStateShallowCopy.PruneAndValidateForGenesis(&g.Parameters.CommissionScheduleRules, now); err != nil {
			return fmt.Errorf("staking: sanity check failed: commission schedule for %s is invalid: %+v", id, err)
		}
	}
	_ = total.Add(&g.CommonPool)
	if total.Cmp(&g.TotalSupply) != 0 {
		return fmt.Errorf("staking: sanity check failed: balances in accounts plus common pool (%s) does not add up to total supply (%s)", total.String(), g.TotalSupply.String())
	}

	// All shares of all delegations for a given account must add up to account's Escrow.Active.TotalShares.
	for acct, delegations := range g.Delegations {
		var shares quantity.Quantity
		var numDelegations uint64
		for _, d := range delegations {
			_ = shares.Add(&d.Shares)
			numDelegations++
		}

		sharesExpected := g.Ledger[acct].Escrow.Active.TotalShares

		if shares.Cmp(&sharesExpected) != 0 {
			return fmt.Errorf("staking: sanity check failed: all shares of all delegations for account don't add up to account's total active shares in escrow")
		}

		// Account's Escrow.Active.Balance must be 0 if account has no delegations.
		if numDelegations == 0 {
			if !g.Ledger[acct].Escrow.Active.Balance.IsZero() {
				return fmt.Errorf("staking: sanity check failed: account has no delegations, but non-zero active escrow balance")
			}
		}
	}

	// All shares of all debonding delegations for a given account must add up to account's Escrow.Debonding.TotalShares.
	for acct, delegations := range g.DebondingDelegations {
		var shares quantity.Quantity
		var numDebondingDelegations uint64
		for _, dels := range delegations {
			for _, d := range dels {
				_ = shares.Add(&d.Shares)
				numDebondingDelegations++
			}
		}

		sharesExpected := g.Ledger[acct].Escrow.Debonding.TotalShares

		if shares.Cmp(&sharesExpected) != 0 {
			return fmt.Errorf("staking: sanity check failed: all shares of all debonding delegations for account don't add up to account's total debonding shares in escrow")
		}

		// Account's Escrow.Debonding.Balance must be 0 if account has no debonding delegations.
		if numDebondingDelegations == 0 {
			if !g.Ledger[acct].Escrow.Debonding.Balance.IsZero() {
				return fmt.Errorf("staking: sanity check failed: account has no debonding delegations, but non-zero debonding escrow balance")
			}
		}
	}

	// Check the above two invariants for each account as well.
	for id, acct := range g.Ledger {
		// Count the delegations for this account and add up the total shares.
		var shares quantity.Quantity
		var numDelegations uint64
		for _, d := range g.Delegations[id] {
			_ = shares.Add(&d.Shares)
			numDelegations++
		}
		// Account's total active shares in escrow should match delegations.
		if shares.Cmp(&acct.Escrow.Active.TotalShares) != 0 {
			return fmt.Errorf("staking: sanity check failed: delegations don't match account's total active shares in escrow")
		}
		// If there are no delegations, the active escrow balance should be 0.
		if numDelegations == 0 {
			if !acct.Escrow.Active.Balance.IsZero() {
				return fmt.Errorf("staking: sanity check failed: account has no delegations, but non-zero active escrow balance")
			}
		}

		// Count the debonding delegations for this account and add up the total shares.
		var debondingShares quantity.Quantity
		var numDebondingDelegations uint64
		for _, dels := range g.DebondingDelegations[id] {
			for _, d := range dels {
				_ = debondingShares.Add(&d.Shares)
				numDebondingDelegations++
			}
		}
		// Account's total debonding shares in escrow should match debonding delegations.
		if debondingShares.Cmp(&acct.Escrow.Debonding.TotalShares) != 0 {
			return fmt.Errorf("staking: sanity check failed: debonding delegations don't match account's total debonding shares in escrow")
		}
		// If there are no debonding delegations, the debonding escrow balance should be 0.
		if numDebondingDelegations == 0 {
			if !acct.Escrow.Debonding.Balance.IsZero() {
				return fmt.Errorf("staking: sanity check failed: account has no debonding delegations, but non-zero debonding escrow balance")
			}
		}
	}

	return nil
}
