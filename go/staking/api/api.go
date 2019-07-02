// Package api implements the staking backend API.
package api

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
)

var (
	// TransferSignatureContext is the context used for transfers.
	TransferSignatureContext = []byte("EkStaXfr")

	// ApproveSignatureContext is the context used for approvals.
	ApproveSignatureContext = []byte("EkStaApr")

	// WithdrawSignatureContext is the context used for withdrawals.
	WithdrawSignatureContext = []byte("EkStaWit")

	// BurnSignatureContext is the context used for burns.
	BurnSignatureContext = []byte("EkStaBur")

	// EscrowSignatureContext is the context used for escrows.
	EscrowSignatureContext = []byte("EkStaEsc")

	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New("staking: invalid argument")

	// ErrInvalidSignature is the error returned on invalid signature.
	ErrInvalidSignature = errors.New("staking: invalid signature")

	// ErrInsufficientBalance is the error returned when an operation
	// fails due to insufficient balance.
	ErrInsufficientBalance = errors.New("staking: insufficient balance")

	// ErrInsufficientAllowance is the error returned when a withdrawal
	// fails due to insufficient allowance.
	ErrInsufficientAllowance = errors.New("staking: insufficient allowance")

	// ErrInvalidAccount is the error returned when an operation fails
	// due to a missing account.
	ErrInvalidAccount = errors.New("staking: invalid account")

	// ErrInvalidNonce is the error returned when a nonce is invalid.
	ErrInvalidNonce = errors.New("staking: invalid nonce")

	_ cbor.Marshaler   = (*Transfer)(nil)
	_ cbor.Unmarshaler = (*Transfer)(nil)
	_ cbor.Marshaler   = (*Approval)(nil)
	_ cbor.Unmarshaler = (*Approval)(nil)
	_ cbor.Marshaler   = (*Withdrawal)(nil)
	_ cbor.Unmarshaler = (*Withdrawal)(nil)
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
	TotalSupply(ctx context.Context) (*Quantity, error)

	// CommonPool returns the common pool balance.
	CommonPool(ctx context.Context) (*Quantity, error)

	// Threshold returns the specific staking threshold by kind.
	Threshold(ctx context.Context, kind ThresholdKind) (*Quantity, error)

	// Accounts returns the IDs of all accounts with a non-zero general
	// or escrow balance.
	Accounts(ctx context.Context) ([]signature.PublicKey, error)

	// AccountInfo returns the general balance, escrow balance and account nonce
	// for the specified account.
	AccountInfo(ctx context.Context, owner signature.PublicKey) (*Quantity, *Quantity, uint64, error)

	// Transfer executes a SignedTransfer.
	Transfer(ctx context.Context, signedXfer *SignedTransfer) error

	// Allowance returns the number of tokens the spender can
	// withdraw from the owner entity's balance.
	Allowance(ctx context.Context, owner, spender signature.PublicKey) (*Quantity, error)

	// Approve executes a SignedApproval, approving the spender to
	// withdraw up to the specified amount of tokens from the signer's
	// balance.
	//
	// If the call is called repeatedly with the same spender, the
	// most recent allowance value is used.
	Approve(ctx context.Context, signedApproval *SignedApproval) error

	// Withdraw execues a SignedWithdrawal, withdrawing tokens from the
	// specified entity's balance into the signer's balance.
	//
	// This is analagous to ERC20's `transferFrom` call.
	Withdraw(ctx context.Context, signedWithdrawal *SignedWithdrawal) error

	// Burn destroys tokens in the signing entity's balance.
	Burn(ctx context.Context, signedBurn *SignedBurn) error

	// AddEscrow escrows the amount of tokens from the signer's balance.
	AddEscrow(ctx context.Context, signedEscrow *SignedEscrow) error

	// WatchTransfers returns a channel that produces a stream of TranserEvent
	// on all balance transfers.
	WatchTransfers() (<-chan *TransferEvent, *pubsub.Subscription)

	// WatchApprovals returns a channel that produces a stream of ApprovalEvent
	// on all approvals.
	WatchApprovals() (<-chan *ApprovalEvent, *pubsub.Subscription)

	// WatchBurns returns a channel of BurnEvent on token destruction.
	WatchBurns() (<-chan *BurnEvent, *pubsub.Subscription)

	// WatchEscrows returns a channel that produces a stream of `*EscrowEvent`,
	// `*TakeEscrowEvent`, and `*ReleaseEscrowEvent` when entities add to their
	// escrow balance, get tokens deducted from their escrow balance, and
	// have their escrow balance released into their general balance
	// respectively.
	WatchEscrows() (<-chan interface{}, *pubsub.Subscription)

	// Cleanup cleans up the backend.
	Cleanup()
}

// EscrowBackend is the interface implemented by implementations that have a
// Take/ReleaseEscrow implementation that are not tightly coupled with the BFT
// consensus.
type EscrowBackend interface {
	// TakeEscrow deducts up to the amount of tokens from the owner's escrow
	// balance.
	//
	// This should only be called by the roothash (?) committee to penalize
	// a misbehaving entity.
	TakeEscrow(ctx context.Context, owner signature.PublicKey, tokens *Quantity) error

	// ReleaseEscrow releases the entirity of the owner's escrow balance
	// back into the owner's general balance.
	//
	// This should only be called by the registry committee (?) when
	// de-bonding an entity.
	ReleaseEscrow(ctx context.Context, owner signature.PublicKey) error
}

// TransferEvent is the event emitted when a balance is transfered, either by
// a call to Transfer or Withdraw.
type TransferEvent struct {
	From   signature.PublicKey `codec:"from"`
	To     signature.PublicKey `codec:"to"`
	Tokens Quantity            `codec:"tokens"`
}

// ApprovalEvent is the event emitted when a withdraw is approved via a call
// to Allowance.
type ApprovalEvent struct {
	Owner   signature.PublicKey `codec:"owner"`
	Spender signature.PublicKey `codec:"spender"`
	Tokens  Quantity            `codec:"tokens"`
}

// BurnEvent is the event emitted when tokens are destroyed via a call to Burn.
type BurnEvent struct {
	Owner  signature.PublicKey `codec:"owner"`
	Tokens Quantity            `codec:"tokens"`
}

// EscrowEvent is the event emitted when a balance is transfered into a escrow
// balance.
type EscrowEvent struct {
	Owner  signature.PublicKey `codec:"owner"`
	Tokens Quantity            `codec:"tokens"`
}

// TakeEscrowEvent is the event emitted when balanace is deducted from a escrow
// balance (stake is slashed).
type TakeEscrowEvent struct {
	Owner  signature.PublicKey `codec:"owner"`
	Tokens Quantity            `codec:"tokens"`
}

// ReleaseEscrowEvent is the event emitted when tokens are released from a
// escrow balance back into the entitie's general balance.
type ReleaseEscrowEvent struct {
	Owner  signature.PublicKey `codec:"owner"`
	Tokens Quantity            `codec:"tokens"`
}

// Transfer is a token transfer.
type Transfer struct {
	Nonce uint64 `codec:"nonce"`

	To     signature.PublicKey `codec:"xfer_to"`
	Tokens Quantity            `codec:"xfer_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (x *Transfer) MarshalCBOR() []byte {
	return cbor.Marshal(x)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (x *Transfer) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, x)
}

// Approval is a token transfer approval.
type Approval struct {
	Nonce uint64 `codec:"nonce"`

	Spender signature.PublicKey `codec:"approve_spender"`
	Tokens  Quantity            `codec:"approve_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (a *Approval) MarshalCBOR() []byte {
	return cbor.Marshal(a)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (a *Approval) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, a)
}

// Withdrawal is a token withdrawal.
type Withdrawal struct {
	Nonce uint64 `codec:"nonce"`

	From   signature.PublicKey `codec:"withdraw_from"`
	Tokens Quantity            `codec:"withdraw_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (w *Withdrawal) MarshalCBOR() []byte {
	return cbor.Marshal(w)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (w *Withdrawal) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, w)
}

// Burn is a token burn (destruction).
type Burn struct {
	Nonce uint64 `codec:"nonce"`

	Tokens Quantity `codec:"burn_tokens"`
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
	Nonce uint64 `codec:"nonce"`

	Tokens Quantity `codec:"escrow_tokens"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *Escrow) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (e *Escrow) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

// SignedTransfer is a Transfer, signed by the owner (source) entity.
type SignedTransfer struct {
	signature.Signed
}

// SignTransfer serializes the Transfer and signs the result.
func SignTransfer(privateKey signature.PrivateKey, xfer *Transfer) (*SignedTransfer, error) {
	signed, err := signature.SignSigned(privateKey, TransferSignatureContext, xfer)
	if err != nil {
		return nil, err
	}

	return &SignedTransfer{
		Signed: *signed,
	}, nil
}

// SignedApproval is an Approval, signed by the owner entity.
type SignedApproval struct {
	signature.Signed
}

// SignApproval serializes the Approval and signs the result.
func SignApproval(privateKey signature.PrivateKey, approval *Approval) (*SignedApproval, error) {
	signed, err := signature.SignSigned(privateKey, ApproveSignatureContext, approval)
	if err != nil {
		return nil, err
	}

	return &SignedApproval{
		Signed: *signed,
	}, nil
}

// SignedWithdrawal is a Withdrawal, signed by the destination entity.
type SignedWithdrawal struct {
	signature.Signed
}

// SignWithdrawal serializes the Withdrawal and signs the result.
func SignWithdrawal(privateKey signature.PrivateKey, withdrawal *Withdrawal) (*SignedWithdrawal, error) {
	signed, err := signature.SignSigned(privateKey, WithdrawSignatureContext, withdrawal)
	if err != nil {
		return nil, err
	}

	return &SignedWithdrawal{
		Signed: *signed,
	}, nil
}

// SignedBurn is a Burn, signed by the owner entity.
type SignedBurn struct {
	signature.Signed
}

// SignBurn serializes the Burn and signs the result.
func SignBurn(privateKey signature.PrivateKey, burn *Burn) (*SignedBurn, error) {
	signed, err := signature.SignSigned(privateKey, BurnSignatureContext, burn)
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
func SignEscrow(privateKey signature.PrivateKey, escrow *Escrow) (*SignedEscrow, error) {
	signed, err := signature.SignSigned(privateKey, EscrowSignatureContext, escrow)
	if err != nil {
		return nil, err
	}

	return &SignedEscrow{
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

// Genesis is the initial ledger balances at genesis for use in the genesis
// block and test cases.
type Genesis struct {
	TotalSupply Quantity                   `codec:"total_supply"`
	CommonPool  Quantity                   `codec:"common_pool"`
	Thresholds  map[ThresholdKind]Quantity `codec:"thresholds,omitempty"`

	Ledger map[signature.MapKey]*GenesisLedgerEntry `codec:"ledger"`
}

// GenesisLedgerEntry is the per-account ledger entry for the genesis block.
type GenesisLedgerEntry struct {
	GeneralBalance Quantity                       `codec:"general_balance"`
	EscrowBalance  Quantity                       `codec:"escrow_balance"`
	Nonce          uint64                         `codec:"nonce"`
	Allowances     map[signature.MapKey]*Quantity `codec:"allowances,omitempty"`
}
