package api

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	// MethodCreate is the method name for creating vaults.
	MethodCreate = transaction.NewMethodName(ModuleName, "Create", Create{})
	// MethodAuthorizeAction is the method name for authorizing actions.
	MethodAuthorizeAction = transaction.NewMethodName(ModuleName, "AuthorizeAction", AuthorizeAction{})
	// MethodCancelAction is the method name for canceling actions.
	MethodCancelAction = transaction.NewMethodName(ModuleName, "CancelAction", CancelAction{})

	// Methods is the list of all methods supported by the vault backend.
	Methods = []transaction.MethodName{
		MethodCreate,
		MethodAuthorizeAction,
		MethodCancelAction,
	}

	_ prettyprint.PrettyPrinter = (*Create)(nil)
	_ prettyprint.PrettyPrinter = (*AuthorizeAction)(nil)
	_ prettyprint.PrettyPrinter = (*CancelAction)(nil)
)

// Create is a create call body.
type Create struct {
	// AdminAuthority specifies the vault's admin authority.
	AdminAuthority Authority `json:"admin_authority"`
	// SuspendAuthority specifies the vault's suspend authority.
	SuspendAuthority Authority `json:"suspend_authority"`
}

// Validate validates the create call.
func (c *Create) Validate(params *ConsensusParameters) error {
	if err := c.AdminAuthority.Validate(params); err != nil {
		return err
	}
	if err := c.SuspendAuthority.Validate(params); err != nil {
		return err
	}
	return nil
}

// PrettyPrint writes a pretty-printed representation of Create to the given writer.
func (c Create) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAdmin authority:\n", prefix)
	c.AdminAuthority.PrettyPrint(ctx, prefix+"  ", w)
	fmt.Fprintf(w, "%sSuspend authority:\n", prefix)
	c.SuspendAuthority.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of Create that can be used for pretty printing.
func (c Create) PrettyType() (interface{}, error) {
	return c, nil
}

// AuthorizeAction is an action authorization call body.
type AuthorizeAction struct {
	// Vault is the address of the target vault.
	Vault staking.Address `json:"vault"`
	// Nonce is the action nonce.
	Nonce uint64 `json:"nonce"`
	// Action is the action that should be authorized.
	Action Action `json:"action"`
}

// Validate validates the action authorization call.
func (a *AuthorizeAction) Validate(params *ConsensusParameters) error {
	if !a.Vault.IsValid() {
		return fmt.Errorf("invalid vault address")
	}
	err := a.Action.Validate(params)
	if err != nil {
		return fmt.Errorf("invalid action: %w", err)
	}
	return nil
}

// PrettyPrint writes a pretty-printed representation of AuthorizeAction to the given writer.
func (a AuthorizeAction) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sVault:  %s\n", prefix, a.Vault)
	fmt.Fprintf(w, "%sNonce:  %d\n", prefix, a.Nonce)
	fmt.Fprintf(w, "%sAction:\n", prefix)
	a.Action.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of AuthorizeAction that can be used for pretty printing.
func (a AuthorizeAction) PrettyType() (interface{}, error) {
	return a, nil
}

// CancelAction is an action cancelation call body.
type CancelAction struct {
	// Vault is the address of the target vault.
	Vault staking.Address `json:"vault"`
	// Nonce is the action nonce.
	Nonce uint64 `json:"nonce"`
}

// Validate validates the action cancelation call.
func (a *CancelAction) Validate() error {
	if !a.Vault.IsValid() {
		return fmt.Errorf("invalid vault address")
	}
	return nil
}

// PrettyPrint writes a pretty-printed representation of CancelAction to the given writer.
func (a CancelAction) PrettyPrint(_ context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sVault:  %s\n", prefix, a.Vault)
	fmt.Fprintf(w, "%sNonce:  %d\n", prefix, a.Nonce)
}

// PrettyType returns a representation of CancelAction that can be used for pretty printing.
func (a CancelAction) PrettyType() (interface{}, error) {
	return a, nil
}

// NewCreateTx creates a new vault creation transaction.
func NewCreateTx(nonce uint64, fee *transaction.Fee, create *Create) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodCreate, create)
}

// NewAuthorizeActionTx creates a new authorize action transaction.
func NewAuthorizeActionTx(nonce uint64, fee *transaction.Fee, action *AuthorizeAction) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAuthorizeAction, action)
}

// NewCancelActionTx creates a new cancel action transaction.
func NewCancelActionTx(nonce uint64, fee *transaction.Fee, action *CancelAction) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodCancelAction, action)
}

const (
	// GasOpCreate is the gas operation identifier for creating a vault.
	GasOpCreate transaction.Op = "create"
	// GasOpAuthorizeAction is the gas operation identifier for authorizing an action.
	GasOpAuthorizeAction transaction.Op = "authorize_action"
	// GasOpCancelAction is the gas operation identifier for canceling an action.
	GasOpCancelAction transaction.Op = "cancel_action"
)

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpCreate:          10000,
	GasOpAuthorizeAction: 5000,
	GasOpCancelAction:    5000,
}
