// Package api implements the staking backend API.
package api

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
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
	TransferSignatureContext = []byte("EkStaXfr")

	// BurnSignatureContext is the context used for burns.
	BurnSignatureContext = []byte("EkStaBur")

	// EscrowSignatureContext is the context used for escrows.
	EscrowSignatureContext = []byte("EkStaEsc")

	// ReclaimEscrowSignatureContext is the context used for escrow reclimation.
	ReclaimEscrowSignatureContext = []byte("EkStaRec")

	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New("staking: invalid argument")

	// ErrInvalidSignature is the error returned on invalid signature.
	ErrInvalidSignature = errors.New("staking: invalid signature")

	// ErrInsufficientBalance is the error returned when an operation
	// fails due to insufficient balance.
	ErrInsufficientBalance = errors.New("staking: insufficient balance")

	// ErrInvalidAccount is the error returned when an operation fails
	// due to a missing account.
	ErrInvalidAccount = errors.New("staking: invalid account")

	// ErrInvalidNonce is the error returned when a nonce is invalid.
	ErrInvalidNonce = errors.New("staking: invalid nonce")

	// ErrInsufficientStake is the error returned when an operation fails
	// due to insufficient stake.
	ErrInsufficientStake = errors.New("staking: insufficient stake")

	_ cbor.Marshaler   = (*Transfer)(nil)
	_ cbor.Unmarshaler = (*Transfer)(nil)
	_ cbor.Marshaler   = (*Burn)(nil)
	_ cbor.Unmarshaler = (*Burn)(nil)
	_ cbor.Marshaler   = (*Escrow)(nil)
	_ cbor.Unmarshaler = (*Escrow)(nil)
)

// Backend is a staking token implementation.
type Backend interface {
	// Name is the name of the token.
	Name() string

	// Symbol is the symbol of the token.
	Symbol() string

	// TotalSupply returns the total nmber of tokens.
	TotalSupply(ctx context.Context, height int64) (*Quantity, error)

	// CommonPool returns the common pool balance.
	CommonPool(ctx context.Context, height int64) (*Quantity, error)

	// Threshold returns the specific staking threshold by kind.
	Threshold(ctx context.Context, kind ThresholdKind, height int64) (*Quantity, error)

	// Accounts returns the IDs of all accounts with a non-zero general
	// or escrow balance.
	Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error)

	// AccountInfo returns the account descriptor for the given account.
	AccountInfo(ctx context.Context, owner signature.PublicKey, height int64) (*Account, error)

	// DebondingDelegations returns the list of debonding delegations for
	// the given owner (delegator).
	DebondingDelegations(ctx context.Context, owner signature.PublicKey, height int64) (map[signature.MapKey][]*DebondingDelegation, error)

	// Transfer executes a SignedTransfer.
	Transfer(ctx context.Context, signedXfer *SignedTransfer) error

	// Burn destroys tokens in the signing entity's balance.
	Burn(ctx context.Context, signedBurn *SignedBurn) error

	// AddEscrow escrows the amount of tokens from the signer's balance.
	AddEscrow(ctx context.Context, signedEscrow *SignedEscrow) error

	// ReclaimEscrow releases the quantity of the owner's escrow balance
	// back into the owner's general balance.
	ReclaimEscrow(ctx context.Context, signedReclaim *SignedReclaimEscrow) error

	// WatchTransfers returns a channel that produces a stream of TranserEvent
	// on all balance transfers.
	WatchTransfers() (<-chan *TransferEvent, *pubsub.Subscription)

	// WatchBurns returns a channel of BurnEvent on token destruction.
	WatchBurns() (<-chan *BurnEvent, *pubsub.Subscription)

	// WatchEscrows returns a channel that produces a stream of `*EscrowEvent`,
	// `*TakeEscrowEvent`, and `*ReleaseEscrowEvent` when entities add to their
	// escrow balance, get tokens deducted from their escrow balance, and
	// have their escrow balance released into their general balance
	// respectively.
	WatchEscrows() (<-chan interface{}, *pubsub.Subscription)

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
	Tokens Quantity            `json:"tokens"`
}

// BurnEvent is the event emitted when tokens are destroyed via a call to Burn.
type BurnEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Tokens Quantity            `json:"tokens"`
}

// EscrowEvent is the event emitted when a balance is transfered into a escrow
// balance.
type EscrowEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Escrow signature.PublicKey `json:"escrow"`
	Tokens Quantity            `json:"tokens"`
}

// TakeEscrowEvent is the event emitted when balanace is deducted from a escrow
// balance (stake is slashed).
type TakeEscrowEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Tokens Quantity            `json:"tokens"`
}

// ReclaimEscrowEvent is the event emitted when tokens are relaimed from a
// escrow balance back into the entitie's general balance.
type ReclaimEscrowEvent struct {
	Owner  signature.PublicKey `json:"owner"`
	Escrow signature.PublicKey `json:"escrow"`
	Tokens Quantity            `json:"tokens"`
}

// Transfer is a token transfer.
type Transfer struct {
	Nonce uint64 `json:"nonce"`

	To     signature.PublicKey `json:"xfer_to"`
	Tokens Quantity            `json:"xfer_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (x *Transfer) MarshalCBOR() []byte {
	return cbor.Marshal(x)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (x *Transfer) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, x)
}

// Burn is a token burn (destruction).
type Burn struct {
	Nonce uint64 `json:"nonce"`

	Tokens Quantity `json:"burn_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (b *Burn) MarshalCBOR() []byte {
	return cbor.Marshal(b)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (b *Burn) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, b)
}

// Escrow is a token escrow.
type Escrow struct {
	Nonce uint64 `json:"nonce"`

	Account signature.PublicKey `json:"escrow_account"`
	Tokens  Quantity            `json:"escrow_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *Escrow) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (e *Escrow) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

// ReclaimEscrow is a token escrow reclimation.
type ReclaimEscrow struct {
	Nonce uint64 `json:"nonce"`

	Account signature.PublicKey `json:"escrow_account"`
	Shares  Quantity            `json:"reclaim_shares"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *ReclaimEscrow) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (r *ReclaimEscrow) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
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

// Move moves exactly n from src to dst.  On failures neither src nor dst
// are altered.
func Move(dst, src, n *Quantity) error {
	if dst == nil || src == nil {
		return ErrInvalidAccount
	}
	if err := src.Sub(n); err != nil {
		return err
	}
	_ = dst.Add(n)

	return nil
}

// MoveUpTo moves up to n from src to dst, and returns the amount moved.
// On failures neither src nor dst are altered.
func MoveUpTo(dst, src, n *Quantity) (*Quantity, error) {
	if dst == nil || src == nil {
		return nil, ErrInvalidAccount
	}
	amount, err := src.SubUpTo(n)
	if err != nil {
		return nil, err
	}
	_ = dst.Add(amount)

	return amount, nil
}

// IssueShares tries to issue shares for the given amount of delegated tokens.
// On failures, dst and dsc are not modified.
func IssueShares(dst *EscrowAccount, amount *Quantity, dsc *Delegation) (*Quantity, error) {
	var issuedShares *Quantity
	if dst.TotalShares.IsZero() {
		// No existing shares, exchange rate is 1:1.
		issuedShares = amount.Clone()
	} else {
		// Exchange rate is based on issued shares and the total balance as:
		//
		//     shares = amount * total_shares / balance
		//
		q := amount.Clone()
		// Multiply first.
		if err := q.Mul(&dst.TotalShares); err != nil {
			return nil, err
		}
		// NOTE: This currently assumes that the slashing code will make sure
		//       that the exchange rate is maintained such that no tokens are
		//       lost due to loss of precision.
		if err := q.Quo(&dst.Balance); err != nil {
			// This can happen if the escrow account has no balance due to
			// losing everything through slashing. In this case there is no
			// way to delegate more.
			return nil, err
		}

		issuedShares = q
	}
	if err := dst.TotalShares.Add(issuedShares); err != nil {
		return nil, err
	}
	// We can skip the error check as we checked the exact same quantity above.
	_ = dsc.Shares.Add(issuedShares)

	return issuedShares, nil
}

// TokensForShares computes the amount of tokens to be received for shares in the
// given escrow account.
func TokensForShares(acc *EscrowAccount, amount *Quantity) (*Quantity, error) {
	if amount.IsZero() || acc.Balance.IsZero() || acc.TotalShares.IsZero() {
		// No existing shares or no balance means no tokens.
		return NewQuantity(), nil
	}

	// Exchange rate is based on issued shares and the total balance as:
	//
	//     tokens = shares * balance / total_shares
	//
	q := amount.Clone()
	// Multiply first.
	if err := q.Mul(&acc.Balance); err != nil {
		return nil, err
	}
	// NOTE: This currently assumes that the slashing code will make sure
	//       that the exchange rate is maintained such that no tokens are
	//       lost due to loss of precision.
	if err := q.Quo(&acc.TotalShares); err != nil {
		return nil, err
	}

	return q, nil
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
		return "[unknown]"
	}
}

// GeneralAccount is a general-purpose account.
type GeneralAccount struct {
	Balance Quantity `json:"balance"`
	Nonce   uint64   `json:"nonce"`
}

// EscrowAccount is an escrow account the balance of which is subject to
// special delegation provisions and a debonding period.
type EscrowAccount struct {
	Balance         Quantity `json:"balance"`
	TotalShares     Quantity `json:"total_shares"`
	DebondingShares Quantity `json:"debonding_shares"`
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
	Shares Quantity `json:"shares"`
}

// DebondingDelegation is a debonding delegation descriptor.
type DebondingDelegation struct {
	Shares        Quantity            `json:"shares"`
	DebondEndTime epochtime.EpochTime `json:"debond_end"`
}

// Genesis is the initial ledger balances at genesis for use in the genesis
// block and test cases.
type Genesis struct {
	TotalSupply             Quantity                   `json:"total_supply"`
	CommonPool              Quantity                   `json:"common_pool"`
	Thresholds              map[ThresholdKind]Quantity `json:"thresholds,omitempty"`
	DebondingInterval       epochtime.EpochTime        `json:"debonding_interval,omitempty"`
	AcceptableTransferPeers map[signature.MapKey]bool  `json:"acceptable_transfer_peers,omitempty"`

	Ledger map[signature.MapKey]*Account `json:"ledger,omitempty"`

	Delegations          map[signature.MapKey]map[signature.MapKey]*Delegation            `json:"delegations,omitempty"`
	DebondingDelegations map[signature.MapKey]map[signature.MapKey][]*DebondingDelegation `json:"debonding_delegations,omitempty"`
}
