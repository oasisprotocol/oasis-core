// Package api implements the staking backend API.
package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/gas"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

const (
	// TokenName is the name of the staking token.
	TokenName = "Buffycoin"

	// TokenSymbol is the symbol of the staking token.
	TokenSymbol = "BUF"

	// LogEventGeneralAdjustment is a log event value that signals adjustment
	// of an account's general balance due to a roothash message.
	LogEventGeneralAdjustment = "staking/general_adjustment"
)

var (
	// TransferSignatureContext is the context used for transfers.
	TransferSignatureContext = signature.NewContext("oasis-core/staking: transfer", signature.WithChainSeparation())

	// BurnSignatureContext is the context used for burns.
	BurnSignatureContext = signature.NewContext("oasis-core/staking: burn", signature.WithChainSeparation())

	// EscrowSignatureContext is the context used for escrows.
	EscrowSignatureContext = signature.NewContext("oasis-core/staking: escrow", signature.WithChainSeparation())

	// ReclaimEscrowSignatureContext is the context used for escrow reclimation.
	ReclaimEscrowSignatureContext = signature.NewContext("oasis-core/staking: reclaim escrow", signature.WithChainSeparation())

	// AmendCommissionScheduleSignatureContext is the context used for escrow reclimation.
	AmendCommissionScheduleSignatureContext = signature.NewContext("oasis-core/staking: amend commission schedule")

	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New("staking: invalid argument")

	// ErrInvalidSignature is the error returned on invalid signature.
	ErrInvalidSignature = errors.New("staking: invalid signature")

	// ErrInsufficientBalance is the error returned when an operation
	// fails due to insufficient balance.
	ErrInsufficientBalance = errors.New("staking: insufficient balance")

	// ErrInvalidNonce is the error returned when a nonce is invalid.
	ErrInvalidNonce = errors.New("staking: invalid nonce")

	// ErrInsufficientStake is the error returned when an operation fails
	// due to insufficient stake.
	ErrInsufficientStake = errors.New("staking: insufficient stake")
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

	// Transfer executes a SignedTransfer.
	Transfer(ctx context.Context, signedXfer *SignedTransfer) error

	// Burn destroys tokens in the signing entity's balance.
	Burn(ctx context.Context, signedBurn *SignedBurn) error

	// AddEscrow escrows the amount of tokens from the signer's balance.
	AddEscrow(ctx context.Context, signedEscrow *SignedEscrow) error

	// ReclaimEscrow releases the quantity of the owner's escrow balance
	// back into the owner's general balance.
	ReclaimEscrow(ctx context.Context, signedReclaim *SignedReclaimEscrow) error

	// SubmitEvidence submits evidence of misbehavior.
	SubmitEvidence(ctx context.Context, evidence Evidence) error

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
	Nonce uint64  `json:"nonce"`
	Fee   gas.Fee `json:"fee"`

	To     signature.PublicKey `json:"xfer_to"`
	Tokens quantity.Quantity   `json:"xfer_tokens"`
}

// Burn is a token burn (destruction).
type Burn struct {
	Nonce uint64  `json:"nonce"`
	Fee   gas.Fee `json:"fee"`

	Tokens quantity.Quantity `json:"burn_tokens"`
}

// Escrow is a token escrow.
type Escrow struct {
	Nonce uint64  `json:"nonce"`
	Fee   gas.Fee `json:"fee"`

	Account signature.PublicKey `json:"escrow_account"`
	Tokens  quantity.Quantity   `json:"escrow_tokens"`
}

// ReclaimEscrow is a token escrow reclimation.
type ReclaimEscrow struct {
	Nonce uint64  `json:"nonce"`
	Fee   gas.Fee `json:"fee"`

	Account signature.PublicKey `json:"escrow_account"`
	Shares  quantity.Quantity   `json:"reclaim_shares"`
}

// AmendCommissionSchedule is an amendment to a commission schedule.
type AmendCommissionSchedule struct {
	Nonce uint64  `json:"nonce"`
	Fee   gas.Fee `json:"fee"`

	Amendment CommissionSchedule `json:"amendment"`
}

// SignedTransfer is a Transfer, signed by the owner (source) entity.
type SignedTransfer struct {
	signature.Signed
}

// SignTransfer serializes the Transfer and signs the result.
func SignTransfer(signer signature.Signer, xfer *Transfer) (*SignedTransfer, error) {
	signed, err := signature.SignSigned(signer, TransferSignatureContext, xfer)
	if err != nil {
		return nil, err
	}

	return &SignedTransfer{
		Signed: *signed,
	}, nil
}

// SignedBurn is a Burn, signed by the owner entity.
type SignedBurn struct {
	signature.Signed
}

// SignBurn serializes the Burn and signs the result.
func SignBurn(signer signature.Signer, burn *Burn) (*SignedBurn, error) {
	signed, err := signature.SignSigned(signer, BurnSignatureContext, burn)
	if err != nil {
		return nil, err
	}

	return &SignedBurn{
		Signed: *signed,
	}, nil
}

// SignedEscrow is a Escrow, signed by the owner entity.
type SignedEscrow struct {
	signature.Signed
}

// SignEscrow serializes the Escrow and signs the result.
func SignEscrow(signer signature.Signer, escrow *Escrow) (*SignedEscrow, error) {
	signed, err := signature.SignSigned(signer, EscrowSignatureContext, escrow)
	if err != nil {
		return nil, err
	}

	return &SignedEscrow{
		Signed: *signed,
	}, nil
}

// SignedReclaimEscrow is a ReclaimEscrow, signed by the owner entity.
type SignedReclaimEscrow struct {
	signature.Signed
}

// SignReclaimEscrow serializes the Reclaim and signs the result.
func SignReclaimEscrow(signer signature.Signer, reclaim *ReclaimEscrow) (*SignedReclaimEscrow, error) {
	signed, err := signature.SignSigned(signer, ReclaimEscrowSignatureContext, reclaim)
	if err != nil {
		return nil, err
	}

	return &SignedReclaimEscrow{
		Signed: *signed,
	}, nil
}

// SignedAmendCommissionSchedule is a ReclaimEscrow, signed by the owner entity.
type SignedAmendCommissionSchedule struct {
	signature.Signed
}

// SignReclaimEscrow serializes the Reclaim and signs the result.
func SignAmendCommissionSchedule(signer signature.Signer, amendCommissionSchedule *AmendCommissionSchedule) (*SignedAmendCommissionSchedule, error) {
	signed, err := signature.SignSigned(signer, AmendCommissionScheduleSignatureContext, amendCommissionSchedule)
	if err != nil {
		return nil, err
	}

	return &SignedAmendCommissionSchedule{
		Signed: *signed,
	}, nil
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
	Thresholds                   map[ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
	DebondingInterval            epochtime.EpochTime                 `json:"debonding_interval,omitempty"`
	RewardSchedule               []RewardStep                        `json:"reward_schedule,omitempty"`
	CommissionRateChangeInterval epochtime.EpochTime                 `json:"commission_rate_change_interval,omitempty"`
	CommissionRateBoundLead      epochtime.EpochTime                 `json:"commission_rate_bound_lead,omitempty"`
	AcceptableTransferPeers      map[signature.PublicKey]bool        `json:"acceptable_transfer_peers,omitempty"`
	Slashing                     map[SlashReason]Slash               `json:"slashing,omitempty"`
	GasCosts                     gas.Costs                           `json:"gas_costs,omitempty"`
	MinDelegationAmount          quantity.Quantity                   `json:"min_delegation,omitempty"`
}

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
func (g *Genesis) SanityCheck() error {
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
	var total quantity.Quantity
	for _, acct := range g.Ledger {
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

	return nil
}

const (
	// GasOpTransfer is the gas operation identifier for transfer.
	GasOpTransfer gas.Op = "transfer"
	// GasOpBurn is the gas operation identifier for burn.
	GasOpBurn gas.Op = "burn"
	// GasOpAddEscrow is the gas operation identifier for add escrow.
	GasOpAddEscrow gas.Op = "add_escrow"
	// GasOpReclaimEscrow is the gas operation identifier for reclaim escrow.
	GasOpReclaimEscrow gas.Op = "reclaim_escrow"
	// GasOpAmendCommissionSchedule is the gas operation identifier for amend commission schedule.
	GasOpAmendCommissionSchedule gas.Op = "amend_commission_schedule"
)
