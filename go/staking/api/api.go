// Package api implements the staking backend API.
package api

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

const (
	// ModuleName is a unique module name for the staking module.
	ModuleName = "staking"

	// LogEventGeneralAdjustment is a log event value that signals adjustment
	// of an account's general balance due to a roothash message.
	LogEventGeneralAdjustment = "staking/general_adjustment"
)

var (
	// CommonPoolAddress is the common pool address.
	// The address is reserved to prevent it being accidentally used in the actual ledger.
	CommonPoolAddress = NewReservedAddress(
		signature.NewPublicKey("1abe11edc001ffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

	// FeeAccumulatorAddress is the per-block fee accumulator address.
	// It holds all fees from txs in a block which are later disbursed to validators appropriately.
	// The address is reserved to prevent it being accidentally used in the actual ledger.
	FeeAccumulatorAddress = NewReservedAddress(
		signature.NewPublicKey("1abe11edfeeaccffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

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

	// ErrForbidden is the error returned when an operation is forbidden by
	// policy.
	ErrForbidden = errors.New(ModuleName, 5, "staking: forbidden by policy")

	// ErrInvalidThreshold is the error returned when an invalid threshold kind
	// is specified in a query.
	ErrInvalidThreshold = errors.New(ModuleName, 6, "staking: invalid threshold")

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

	_ prettyprint.PrettyPrinter = (*Transfer)(nil)
	_ prettyprint.PrettyPrinter = (*Burn)(nil)
	_ prettyprint.PrettyPrinter = (*Escrow)(nil)
	_ prettyprint.PrettyPrinter = (*ReclaimEscrow)(nil)
	_ prettyprint.PrettyPrinter = (*AmendCommissionSchedule)(nil)
	_ prettyprint.PrettyPrinter = (*SharePool)(nil)
	_ prettyprint.PrettyPrinter = (*StakeThreshold)(nil)
	_ prettyprint.PrettyPrinter = (*StakeAccumulator)(nil)
	_ prettyprint.PrettyPrinter = (*GeneralAccount)(nil)
	_ prettyprint.PrettyPrinter = (*EscrowAccount)(nil)
	_ prettyprint.PrettyPrinter = (*Account)(nil)
)

// Backend is a staking implementation.
type Backend interface {
	// TokenSymbol returns the token's ticker symbol.
	TokenSymbol(ctx context.Context) (string, error)

	// TokenValueExponent is the token's value base-10 exponent, i.e.
	// 1 token = 10**TokenValueExponent base units.
	TokenValueExponent(ctx context.Context) (uint8, error)

	// TotalSupply returns the total number of base units.
	TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error)

	// CommonPool returns the common pool balance.
	CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error)

	// LastBlockFees returns the collected fees for previous block.
	LastBlockFees(ctx context.Context, height int64) (*quantity.Quantity, error)

	// Threshold returns the specific staking threshold by kind.
	Threshold(ctx context.Context, query *ThresholdQuery) (*quantity.Quantity, error)

	// Addresses returns the addresses of all accounts with a non-zero general
	// or escrow balance.
	Addresses(ctx context.Context, height int64) ([]Address, error)

	// Account returns the account descriptor for the given account.
	Account(ctx context.Context, query *OwnerQuery) (*Account, error)

	// Delegations returns the list of delegations for the given owner
	// (delegator).
	Delegations(ctx context.Context, query *OwnerQuery) (map[Address]*Delegation, error)

	// DebondingDelegations returns the list of debonding delegations for
	// the given owner (delegator).
	DebondingDelegations(ctx context.Context, query *OwnerQuery) (map[Address][]*DebondingDelegation, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// Paremeters returns the staking consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]*Event, error)

	// WatchEvents returns a channel that produces a stream of Events.
	WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error)

	// Cleanup cleans up the backend.
	Cleanup()
}

// ThresholdQuery is a treshold query.
type ThresholdQuery struct {
	Height int64         `json:"height"`
	Kind   ThresholdKind `json:"kind"`
}

// OwnerQuery is an owner query.
type OwnerQuery struct {
	Height int64   `json:"height"`
	Owner  Address `json:"owner"`
}

// TransferEvent is the event emitted when stake is transferred, either by a
// call to Transfer or Withdraw.
type TransferEvent struct {
	From   Address           `json:"from"`
	To     Address           `json:"to"`
	Amount quantity.Quantity `json:"amount"`
}

// BurnEvent is the event emitted when stake is destroyed via a call to Burn.
type BurnEvent struct {
	Owner  Address           `json:"owner"`
	Amount quantity.Quantity `json:"amount"`
}

// EscrowEvent is an escrow event.
type EscrowEvent struct {
	Add     *AddEscrowEvent     `json:"add,omitempty"`
	Take    *TakeEscrowEvent    `json:"take,omitempty"`
	Reclaim *ReclaimEscrowEvent `json:"reclaim,omitempty"`
}

// Event signifies a staking event, returned via GetEvents.
type Event struct {
	Height int64     `json:"height,omitempty"`
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	Transfer *TransferEvent `json:"transfer,omitempty"`
	Burn     *BurnEvent     `json:"burn,omitempty"`
	Escrow   *EscrowEvent   `json:"escrow,omitempty"`
}

// AddEscrowEvent is the event emitted when stake is transferred into an escrow
// account.
type AddEscrowEvent struct {
	Owner  Address           `json:"owner"`
	Escrow Address           `json:"escrow"`
	Amount quantity.Quantity `json:"amount"`
}

// TakeEscrowEvent is the event emitted when stake is taken from an escrow
// account (i.e. stake is slashed).
type TakeEscrowEvent struct {
	Owner  Address           `json:"owner"`
	Amount quantity.Quantity `json:"amount"`
}

// ReclaimEscrowEvent is the event emitted when stake is reclaimed from an
// escrow account back into owner's general account.
type ReclaimEscrowEvent struct {
	Owner  Address           `json:"owner"`
	Escrow Address           `json:"escrow"`
	Amount quantity.Quantity `json:"amount"`
}

// Transfer is a stake transfer.
type Transfer struct {
	To     Address           `json:"to"`
	Amount quantity.Quantity `json:"amount"`
}

// PrettyPrint writes a pretty-printed representation of Transfer to the given
// writer.
func (t Transfer) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sTo:     %s\n", prefix, t.To)

	fmt.Fprintf(w, "%sAmount: ", prefix)
	token.PrettyPrintAmount(ctx, t.Amount, w)
	fmt.Fprintln(w)
}

// PrettyType returns a representation of Transfer that can be used for pretty
// printing.
func (t Transfer) PrettyType() (interface{}, error) {
	return t, nil
}

// NewTransferTx creates a new transfer transaction.
func NewTransferTx(nonce uint64, fee *transaction.Fee, xfer *Transfer) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodTransfer, xfer)
}

// Burn is a stake burn (destruction).
type Burn struct {
	Amount quantity.Quantity `json:"amount"`
}

// PrettyPrint writes a pretty-printed representation of Burn to the given
// writer.
func (b Burn) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAmount: ", prefix)
	token.PrettyPrintAmount(ctx, b.Amount, w)
	fmt.Fprintln(w)
}

// PrettyType returns a representation of Burn that can be used for pretty
// printing.
func (b Burn) PrettyType() (interface{}, error) {
	return b, nil
}

// NewBurnTx creates a new burn transaction.
func NewBurnTx(nonce uint64, fee *transaction.Fee, burn *Burn) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodBurn, burn)
}

// Escrow is a stake escrow.
type Escrow struct {
	Account Address           `json:"account"`
	Amount  quantity.Quantity `json:"amount"`
}

// PrettyPrint writes a pretty-printed representation of Escrow to the given
// writer.
func (e Escrow) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAccount: %s\n", prefix, e.Account)

	fmt.Fprintf(w, "%sAmount:  ", prefix)
	token.PrettyPrintAmount(ctx, e.Amount, w)
	fmt.Fprintln(w)
}

// PrettyType returns a representation of Escrow that can be used for pretty
// printing.
func (e Escrow) PrettyType() (interface{}, error) {
	return e, nil
}

// NewAddEscrowTx creates a new add escrow transaction.
func NewAddEscrowTx(nonce uint64, fee *transaction.Fee, escrow *Escrow) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAddEscrow, escrow)
}

// ReclaimEscrow is a reclamation of stake from an escrow.
type ReclaimEscrow struct {
	Account Address           `json:"account"`
	Shares  quantity.Quantity `json:"shares"`
}

// PrettyPrint writes a pretty-printed representation of ReclaimEscrow to the
// given writer.
func (re ReclaimEscrow) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAccount: %s\n", prefix, re.Account)

	fmt.Fprintf(w, "%sShares:  %s\n", prefix, re.Shares)
}

// PrettyType returns a representation of Transfer that can be used for pretty
// printing.
func (re ReclaimEscrow) PrettyType() (interface{}, error) {
	return re, nil
}

// NewReclaimEscrowTx creates a new reclaim escrow transaction.
func NewReclaimEscrowTx(nonce uint64, fee *transaction.Fee, reclaim *ReclaimEscrow) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodReclaimEscrow, reclaim)
}

// AmendCommissionSchedule is an amendment to a commission schedule.
type AmendCommissionSchedule struct {
	Amendment CommissionSchedule `json:"amendment"`
}

// PrettyPrint writes a pretty-printed representation of AmendCommissionSchedule
// to the given writer.
func (acs AmendCommissionSchedule) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAmendment:\n", prefix)
	acs.Amendment.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of AmendCommissionSchedule that can be
// used for pretty printing.
func (acs AmendCommissionSchedule) PrettyType() (interface{}, error) {
	return acs, nil
}

// NewAmendCommissionScheduleTx creates a new amend commission schedule transaction.
func NewAmendCommissionScheduleTx(nonce uint64, fee *transaction.Fee, amend *AmendCommissionSchedule) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAmendCommissionSchedule, amend)
}

// SharePool is a combined balance of several entries, the relative sizes
// of which are tracked through shares.
type SharePool struct {
	Balance     quantity.Quantity `json:"balance,omitempty"`
	TotalShares quantity.Quantity `json:"total_shares,omitempty"`
}

// PrettyPrint writes a pretty-printed representation of SharePool to the given
// writer.
func (p SharePool) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sBalance:      ", prefix)
	token.PrettyPrintAmount(ctx, p.Balance, w)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%sTotal Shares: %s\n", prefix, p.TotalShares)
}

// PrettyType returns a representation of SharePool that can be used for pretty
// printing.
func (p SharePool) PrettyType() (interface{}, error) {
	return p, nil
}

// sharesForStake computes the amount of shares for the given amount of base units.
func (p *SharePool) sharesForStake(amount *quantity.Quantity) (*quantity.Quantity, error) {
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

// Deposit moves stake into the combined balance, raising the shares.
// If an error occurs, the pool and affected accounts are left in an invalid state.
func (p *SharePool) Deposit(shareDst, stakeSrc, baseUnitsAmount *quantity.Quantity) error {
	shares, err := p.sharesForStake(baseUnitsAmount)
	if err != nil {
		return err
	}

	if err = quantity.Move(&p.Balance, stakeSrc, baseUnitsAmount); err != nil {
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

// stakeForShares computes the amount of base units for the given amount of shares.
func (p *SharePool) stakeForShares(amount *quantity.Quantity) (*quantity.Quantity, error) {
	if amount.IsZero() || p.Balance.IsZero() || p.TotalShares.IsZero() {
		// No existing shares or no balance means no base units.
		return quantity.NewQuantity(), nil
	}

	// Exchange rate is based on issued shares and the total balance as:
	//
	//     base_units = shares * balance / total_shares
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

// Withdraw moves stake out of the combined balance, reducing the shares.
// If an error occurs, the pool and affected accounts are left in an invalid state.
func (p *SharePool) Withdraw(stakeDst, shareSrc, shareAmount *quantity.Quantity) error {
	baseUnits, err := p.stakeForShares(shareAmount)
	if err != nil {
		return err
	}

	if err = shareSrc.Sub(shareAmount); err != nil {
		return err
	}

	if err = p.TotalShares.Sub(shareAmount); err != nil {
		return err
	}

	if err = quantity.Move(stakeDst, &p.Balance, baseUnits); err != nil {
		return err
	}

	return nil
}

// ThresholdKind is the kind of staking threshold.
type ThresholdKind int

const (
	KindEntity            ThresholdKind = 0
	KindNodeValidator     ThresholdKind = 1
	KindNodeCompute       ThresholdKind = 2
	KindNodeStorage       ThresholdKind = 3
	KindNodeKeyManager    ThresholdKind = 4
	KindRuntimeCompute    ThresholdKind = 5
	KindRuntimeKeyManager ThresholdKind = 6

	KindMax = KindRuntimeKeyManager

	KindEntityName            = "entity"
	KindNodeValidatorName     = "node-validator"
	KindNodeComputeName       = "node-compute"
	KindNodeStorageName       = "node-storage"
	KindNodeKeyManagerName    = "node-keymanager"
	KindRuntimeComputeName    = "runtime-compute"
	KindRuntimeKeyManagerName = "runtime-keymanager"
)

// String returns the string representation of a ThresholdKind.
func (k ThresholdKind) String() string {
	switch k {
	case KindEntity:
		return KindEntityName
	case KindNodeValidator:
		return KindNodeValidatorName
	case KindNodeCompute:
		return KindNodeComputeName
	case KindNodeStorage:
		return KindNodeStorageName
	case KindNodeKeyManager:
		return KindNodeKeyManagerName
	case KindRuntimeCompute:
		return KindRuntimeComputeName
	case KindRuntimeKeyManager:
		return KindRuntimeKeyManagerName
	default:
		return "[unknown threshold kind]"
	}
}

// MarshalText encodes a ThresholdKind into text form.
func (k ThresholdKind) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText decodes a text slice into a ThresholdKind.
func (k *ThresholdKind) UnmarshalText(text []byte) error {
	switch string(text) {
	case KindEntityName:
		*k = KindEntity
	case KindNodeValidatorName:
		*k = KindNodeValidator
	case KindNodeComputeName:
		*k = KindNodeCompute
	case KindNodeStorageName:
		*k = KindNodeStorage
	case KindNodeKeyManagerName:
		*k = KindNodeKeyManager
	case KindRuntimeComputeName:
		*k = KindRuntimeCompute
	case KindRuntimeKeyManagerName:
		*k = KindRuntimeKeyManager
	default:
		return fmt.Errorf("%w: %s", ErrInvalidThreshold, string(text))
	}
	return nil
}

// StakeClaim is a unique stake claim identifier.
type StakeClaim string

// StakeThreshold is a stake threshold as used in the stake accumulator.
type StakeThreshold struct {
	// Global is a reference to a global stake threshold.
	Global *ThresholdKind `json:"global,omitempty"`
	// Constant is the value for a specific threshold.
	Constant *quantity.Quantity `json:"const,omitempty"`
}

// String returns a string representation of a stake threshold.
func (st StakeThreshold) String() string {
	switch {
	case st.Global != nil:
		return fmt.Sprintf("<global: %s>", *st.Global)
	case st.Constant != nil:
		return fmt.Sprintf("<constant: %s>", st.Constant)
	default:
		return "<malformed>"
	}
}

// PrettyPrint writes a pretty-printed representation of StakeThreshold to the
// given writer.
func (st StakeThreshold) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	switch {
	case st.Global != nil:
		fmt.Fprintf(w, "%s- Global: %s\n", prefix, *st.Global)
	case st.Constant != nil:
		fmt.Fprintf(w, "%s- Constant: %s\n", prefix, st.Constant)
	default:
		fmt.Fprintf(w, "%s- (malformed)\n", prefix)
	}
}

// PrettyType returns a representation of StakeThreshold that can be used for
// pretty printing.
func (st StakeThreshold) PrettyType() (interface{}, error) {
	return st, nil
}

// Equal compares vs another stake threshold for equality.
func (st *StakeThreshold) Equal(cmp *StakeThreshold) bool {
	if cmp == nil {
		return false
	}
	switch {
	case st.Global != nil:
		return cmp.Global != nil && *st.Global == *cmp.Global
	case st.Constant != nil:
		return cmp.Constant != nil && st.Constant.Cmp(cmp.Constant) == 0
	default:
		return false
	}
}

// Value returns the value of the stake threshold.
func (st *StakeThreshold) Value(tm map[ThresholdKind]quantity.Quantity) (*quantity.Quantity, error) {
	switch {
	case st.Global != nil:
		// Reference to a global threshold.
		q := tm[*st.Global]
		return &q, nil
	case st.Constant != nil:
		// Direct constant threshold.
		return st.Constant, nil
	default:
		return nil, fmt.Errorf("staking: invalid claim threshold: %+v", st)
	}
}

// GlobalStakeTreshold creates a new global StakeThreshold.
func GlobalStakeThreshold(kind ThresholdKind) StakeThreshold {
	return StakeThreshold{Global: &kind}
}

// GlobalStakeTresholds creates a new list of global StakeThresholds.
func GlobalStakeThresholds(kinds ...ThresholdKind) (sts []StakeThreshold) {
	for _, k := range kinds {
		sts = append(sts, GlobalStakeThreshold(k))
	}
	return
}

// StakeAccumulator is a per-escrow-account stake accumulator.
type StakeAccumulator struct {
	// Claims are the stake claims that must be satisfied at any given point. Adding a new claim is
	// only possible if all of the existing claims plus the new claim is satisfied.
	Claims map[StakeClaim][]StakeThreshold `json:"claims,omitempty"`
}

// PrettyPrint writes a pretty-printed representation of StakeAccumulator to the
// given writer.
func (sa StakeAccumulator) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	if sa.Claims == nil {
		fmt.Fprintf(w, "%sClaims: (none)\n", prefix)
	} else {
		fmt.Fprintf(w, "%sClaims:\n", prefix)
		for claim, thresholds := range sa.Claims {
			fmt.Fprintf(w, "%s  - Name: %s\n", prefix, claim)
			for _, threshold := range thresholds {
				fmt.Fprintf(w, "%s    Staking Thresholds:\n", prefix)
				threshold.PrettyPrint(ctx, prefix+"      ", w)
			}
		}
	}
}

// PrettyType returns a representation of StakeAccumulator that can be used for
// pretty printing.
func (sa StakeAccumulator) PrettyType() (interface{}, error) {
	return sa, nil
}

// AddClaimUnchecked adds a new claim without checking its validity.
func (sa *StakeAccumulator) AddClaimUnchecked(claim StakeClaim, thresholds []StakeThreshold) {
	if sa.Claims == nil {
		sa.Claims = make(map[StakeClaim][]StakeThreshold)
	}

	sa.Claims[claim] = thresholds
}

// RemoveClaim removes a given stake claim.
//
// It is an error if the stake claim does not exist.
func (sa *StakeAccumulator) RemoveClaim(claim StakeClaim) error {
	if sa.Claims == nil || sa.Claims[claim] == nil {
		return fmt.Errorf("staking: claim does not exist: %s", claim)
	}

	delete(sa.Claims, claim)
	return nil
}

// TotalClaims computes the total amount of stake claims in the accumulator.
func (sa *StakeAccumulator) TotalClaims(thresholds map[ThresholdKind]quantity.Quantity, exclude *StakeClaim) (*quantity.Quantity, error) {
	if sa == nil || sa.Claims == nil {
		return quantity.NewQuantity(), nil
	}

	var total quantity.Quantity
	for id, claim := range sa.Claims {
		if exclude != nil && id == *exclude {
			continue
		}

		for _, t := range claim {
			q, err := t.Value(thresholds)
			if err != nil {
				return nil, err
			}

			if err = total.Add(q); err != nil {
				return nil, fmt.Errorf("staking: failed to accumulate threshold: %w", err)
			}
		}
	}
	return &total, nil
}

// GeneralAccount is a general-purpose account.
type GeneralAccount struct {
	Balance quantity.Quantity `json:"balance,omitempty"`
	Nonce   uint64            `json:"nonce,omitempty"`
}

// PrettyPrint writes a pretty-printed representation of GeneralAccount to the
// given writer.
func (ga GeneralAccount) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sBalance: ", prefix)
	token.PrettyPrintAmount(ctx, ga.Balance, w)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%sNonce:   %d\n", prefix, ga.Nonce)
}

// PrettyType returns a representation of GeneralAccount that can be used for
// pretty printing.
func (ga GeneralAccount) PrettyType() (interface{}, error) {
	return ga, nil
}

// EscrowAccount is an escrow account the balance of which is subject to
// special delegation provisions and a debonding period.
type EscrowAccount struct {
	Active             SharePool          `json:"active,omitempty"`
	Debonding          SharePool          `json:"debonding,omitempty"`
	CommissionSchedule CommissionSchedule `json:"commission_schedule,omitempty"`
	StakeAccumulator   StakeAccumulator   `json:"stake_accumulator,omitempty"`
}

// PrettyPrint writes a pretty-printed representation of EscrowAccount to the
// given writer.
func (e EscrowAccount) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sActive:\n", prefix)
	e.Active.PrettyPrint(ctx, prefix+"  ", w)

	fmt.Fprintf(w, "%sDebonding:\n", prefix)
	e.Debonding.PrettyPrint(ctx, prefix+"  ", w)

	fmt.Fprintf(w, "%sCommission Schedule:\n", prefix)
	e.CommissionSchedule.PrettyPrint(ctx, prefix+"  ", w)

	fmt.Fprintf(w, "%sStake Accumulator:\n", prefix)
	e.StakeAccumulator.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of EscrowAccount that can be used for
// pretty printing.
func (e EscrowAccount) PrettyType() (interface{}, error) {
	return e, nil
}

// CheckStakeClaims checks whether the escrow account balance satisfies all the stake claims.
func (e *EscrowAccount) CheckStakeClaims(tm map[ThresholdKind]quantity.Quantity) error {
	totalClaims, err := e.StakeAccumulator.TotalClaims(tm, nil)
	if err != nil {
		return err
	}
	if e.Active.Balance.Cmp(totalClaims) < 0 {
		return ErrInsufficientStake
	}
	return nil
}

// AddStakeClaim attempts to add a stake claim to the given escrow account.
//
// In case there is insufficient stake to cover the claim or an error occurrs, no modifications are
// made to the stake accumulator.
func (e *EscrowAccount) AddStakeClaim(tm map[ThresholdKind]quantity.Quantity, claim StakeClaim, thresholds []StakeThreshold) error {
	// Compute total amount of claims excluding the claim that we are just adding. This is needed
	// in case the claim is being updated to avoid counting it twice.
	totalClaims, err := e.StakeAccumulator.TotalClaims(tm, &claim)
	if err != nil {
		return err
	}

	for _, t := range thresholds {
		q, err := t.Value(tm)
		if err != nil {
			return err
		}

		if err = totalClaims.Add(q); err != nil {
			return fmt.Errorf("staking: failed to accumulate threshold: %w", err)
		}
	}

	// Make sure there is sufficient stake to satisfy the claim.
	if e.Active.Balance.Cmp(totalClaims) < 0 {
		return ErrInsufficientStake
	}

	e.StakeAccumulator.AddClaimUnchecked(claim, thresholds)
	return nil
}

// RemoveStakeClaim removes a given stake claim.
//
// It is an error if the stake claim does not exist.
func (e *EscrowAccount) RemoveStakeClaim(claim StakeClaim) error {
	return e.StakeAccumulator.RemoveClaim(claim)
}

// Account is an entry in the staking ledger.
//
// The same ledger entry can hold both general and escrow accounts. Escrow
// accounts are used to hold funds delegated for staking.
type Account struct {
	General GeneralAccount `json:"general,omitempty"`
	Escrow  EscrowAccount  `json:"escrow,omitempty"`
}

// PrettyPrint writes a pretty-printed representation of Account to the given
// writer.
func (a Account) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sGeneral Account:\n", prefix)
	a.General.PrettyPrint(ctx, prefix+"  ", w)
	fmt.Fprintf(w, "%sEscrow Account:\n", prefix)
	a.Escrow.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of Account that can be used for pretty
// printing.
func (a Account) PrettyType() (interface{}, error) {
	return a, nil
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

// Genesis is the initial staking state for use in the genesis block.
type Genesis struct {
	// Parameters are the staking consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// TokenSymbol is the token's ticker symbol.
	// Only upper case A-Z characters are allowed.
	TokenSymbol string `json:"token_symbol"`
	// TokenValueExponent is the token's value base-10 exponent, i.e.
	// 1 token = 10**TokenValueExponent base units.
	TokenValueExponent uint8 `json:"token_value_exponent"`

	// TokenSupply is the network's total amount of stake in base units.
	TotalSupply quantity.Quantity `json:"total_supply"`
	// CommonPool is the network's common stake pool.
	CommonPool quantity.Quantity `json:"common_pool"`
	// LastBlockFees are the collected fees for previous block.
	LastBlockFees quantity.Quantity `json:"last_block_fees"`

	// Ledger is a map of staking accounts.
	Ledger map[Address]*Account `json:"ledger,omitempty"`

	// Delegations is a nested map of staking delegations of the form:
	// DELEGATEE-ACCOUNT-ADDRESS: DELEGATOR-ACCOUNT-ADDRESS: DELEGATION.
	Delegations map[Address]map[Address]*Delegation `json:"delegations,omitempty"`
	// DebondingDelegations is a nested map of staking delegations of the form:
	// DEBONDING-DELEGATEE-ACCOUNT-ADDRESS: DEBONDING-DELEGATOR-ACCOUNT-ADDRESS: list of DEBONDING-DELEGATIONs.
	DebondingDelegations map[Address]map[Address][]*DebondingDelegation `json:"debonding_delegations,omitempty"`
}

// ConsensusParameters are the staking consensus parameters.
type ConsensusParameters struct {
	Thresholds                        map[ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
	DebondingInterval                 epochtime.EpochTime                 `json:"debonding_interval,omitempty"`
	RewardSchedule                    []RewardStep                        `json:"reward_schedule,omitempty"`
	SigningRewardThresholdNumerator   uint64                              `json:"signing_reward_threshold_numerator,omitempty"`
	SigningRewardThresholdDenominator uint64                              `json:"signing_reward_threshold_denominator,omitempty"`
	CommissionScheduleRules           CommissionScheduleRules             `json:"commission_schedule_rules,omitempty"`
	Slashing                          map[SlashReason]Slash               `json:"slashing,omitempty"`
	GasCosts                          transaction.Costs                   `json:"gas_costs,omitempty"`
	MinDelegationAmount               quantity.Quantity                   `json:"min_delegation"`

	DisableTransfers       bool             `json:"disable_transfers,omitempty"`
	DisableDelegation      bool             `json:"disable_delegation,omitempty"`
	UndisableTransfersFrom map[Address]bool `json:"undisable_transfers_from,omitempty"`

	// FeeSplitWeightPropose is the proportion of block fee portions that go to the proposer.
	FeeSplitWeightPropose quantity.Quantity `json:"fee_split_weight_propose"`
	// FeeSplitWeightVote is the proportion of block fee portions that go to the validator that votes.
	FeeSplitWeightVote quantity.Quantity `json:"fee_split_weight_vote"`
	// FeeSplitWeightNextPropose is the proportion of block fee portions that go to the next block's proposer.
	FeeSplitWeightNextPropose quantity.Quantity `json:"fee_split_weight_next_propose"`

	// RewardFactorEpochSigned is the factor for a reward distributed per epoch to
	// entities that have signed at least a threshold fraction of the blocks.
	RewardFactorEpochSigned quantity.Quantity `json:"reward_factor_epoch_signed"`
	// RewardFactorBlockProposed is the factor for a reward distributed per block
	// to the entity that proposed the block.
	RewardFactorBlockProposed quantity.Quantity `json:"reward_factor_block_proposed"`
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
